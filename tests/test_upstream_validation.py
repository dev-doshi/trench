"""Upstream response validation (RFC 5452).

Two defects motivated this file:

  * the client's own transaction id was forwarded upstream verbatim. A LAN
    client can choose its id, so it could hand an off-path spoofer the exact
    value needed — 16 bits of entropy given away for free;
  * nothing checked the id or the question on the way back, so the first
    datagram to arrive from the upstream's address was believed. Winning the
    race was the entire attack.

The tests drive a real UDP socket acting as the upstream, so they exercise the
socket path rather than a mock.
"""
from __future__ import annotations

import asyncio
import socket

import pytest

from dnsguard.errors import UpstreamError
from dnsguard.transport.upstream import Upstream, parse_upstream
from dnsguard.wire import Class, Message, Question
from dnsguard.wire.name import Name
from dnsguard.wire.rdata import A
from dnsguard.wire.rrtypes import Flags, Type


def query(name="example.com.", rtype=Type.A) -> Message:
    q = Message(id=0x1234)
    q.set_flag(Flags.RD, True)
    q.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    return q


def answer(for_msg: Message, *, msg_id=None, name=None, rtype=None,
           ip="1.2.3.4", with_question=True) -> bytes:
    q = for_msg.question
    r = Message(id=for_msg.id if msg_id is None else msg_id)
    r.set_flag(Flags.QR, True)
    nm = Name.from_text(name) if name else q.name
    rt = q.rtype if rtype is None else rtype
    if with_question:
        r.questions.append(Question(nm, rt, Class.IN))
    if rt == Type.A:
        from dnsguard.wire.message import RR
        r.answers.append(RR(nm, Type.A, Class.IN, 300, A(ip)))
    return r.to_wire()


class FakeUpstream:
    """A UDP server that replies with whatever bytes it is told to."""

    def __init__(self, make_reply):
        self.make_reply = make_reply
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.setblocking(False)
        self.received: list[Message] = []
        self._task: asyncio.Task | None = None

    @property
    def port(self) -> int:
        return self.sock.getsockname()[1]

    async def _serve(self):
        loop = asyncio.get_running_loop()
        while True:
            data, addr = await loop.sock_recvfrom(self.sock, 4096)
            got = Message.parse(data)
            self.received.append(got)
            reply = self.make_reply(got)
            if reply is not None:
                await loop.sock_sendto(self.sock, reply, addr)

    async def __aenter__(self):
        self._task = asyncio.ensure_future(self._serve())
        return self

    async def __aexit__(self, *exc):
        if self._task:
            self._task.cancel()
        self.sock.close()


def upstream_to(port: int) -> Upstream:
    return Upstream(parse_upstream(f"127.0.0.1:{port}"), timeout=1.0)


@pytest.mark.asyncio
async def test_client_id_is_not_forwarded_upstream():
    """The id on the wire to the upstream must not be the one the client chose."""
    async with FakeUpstream(lambda got: answer(got)) as srv:
        up = upstream_to(srv.port)
        q = query()
        resp = await up.query(q)
        assert srv.received, "upstream saw no query"
        assert srv.received[0].id != q.id, (
            "the client's transaction id was forwarded verbatim")
        # the client still gets its own id back, as it must
        assert resp.id == q.id


@pytest.mark.asyncio
async def test_valid_response_is_accepted():
    async with FakeUpstream(lambda got: answer(got)) as srv:
        resp = await upstream_to(srv.port).query(query())
        assert resp.answers[0].rdata.to_text() == "1.2.3.4"


@pytest.mark.asyncio
async def test_wrong_id_is_never_accepted():
    """The spoofer's job: arrive first from the right address. Without an id
    check that alone was enough.

    A reply bearing the wrong id is now *discarded* rather than reported —
    upstream sockets dispatch replies by transaction id, so a mismatched one
    belongs to no waiting query and is simply not read. That is the stronger
    behaviour: raising on the first wrong id would let one spoofed packet
    cancel a query the genuine answer was still on its way to satisfy. The
    query times out instead, and the wrong answer is never returned.
    """
    async with FakeUpstream(lambda got: answer(got, msg_id=(got.id + 1) & 0xFFFF)) as srv:
        with pytest.raises((UpstreamError, asyncio.TimeoutError, TimeoutError)):
            await upstream_to(srv.port).query(query())


@pytest.mark.asyncio
async def test_answer_for_a_different_name_is_rejected():
    """Classic cache-poisoning shape: a valid-looking reply that answers for
    someone else's domain."""
    async with FakeUpstream(lambda got: answer(got, name="evil.example.", ip="6.6.6.6")) as srv:
        with pytest.raises(UpstreamError, match="different question"):
            await upstream_to(srv.port).query(query())


@pytest.mark.asyncio
async def test_answer_for_a_different_type_is_rejected():
    async with FakeUpstream(lambda got: answer(got, rtype=Type.TXT)) as srv:
        with pytest.raises(UpstreamError, match="different question"):
            await upstream_to(srv.port).query(query())


@pytest.mark.asyncio
async def test_response_without_the_qr_bit_is_rejected():
    def reply(got):
        r = Message.parse(answer(got))
        r.set_flag(Flags.QR, False)
        return r.to_wire()
    async with FakeUpstream(reply) as srv:
        with pytest.raises(UpstreamError, match="not a response"):
            await upstream_to(srv.port).query(query())


@pytest.mark.asyncio
async def test_answers_without_a_question_are_rejected():
    """Answers that cannot be attributed to a question must not be trusted."""
    async with FakeUpstream(lambda got: answer(got, with_question=False)) as srv:
        with pytest.raises(UpstreamError, match="no question"):
            await upstream_to(srv.port).query(query())


@pytest.mark.asyncio
async def test_empty_error_reply_without_a_question_is_tolerated():
    """A bare FORMERR legitimately carries no question and no answers; treating
    that as an attack would break interoperability."""
    def reply(got):
        r = Message(id=got.id)
        r.set_flag(Flags.QR, True)
        r.set_rcode(1)   # FORMERR
        return r.to_wire()
    async with FakeUpstream(reply) as srv:
        resp = await upstream_to(srv.port).query(query())
        assert resp.rcode == 1


@pytest.mark.asyncio
async def test_case_differences_from_the_upstream_are_tolerated():
    """Some resolvers normalise case. Strict 0x20 checking happens further up
    where the original casing is known; here it must not break resolution."""
    async with FakeUpstream(lambda got: answer(got, name="EXAMPLE.COM.")) as srv:
        resp = await upstream_to(srv.port).query(query())
        assert resp.answers[0].rdata.to_text() == "1.2.3.4"


@pytest.mark.asyncio
async def test_forwarded_ids_vary_between_queries():
    """A fixed or sequential id would be as guessable as the client's."""
    async with FakeUpstream(lambda got: answer(got)) as srv:
        up = upstream_to(srv.port)
        for _ in range(12):
            await up.query(query())
        ids = {m.id for m in srv.received}
        assert len(ids) >= 10, f"upstream ids barely varied: {sorted(ids)}"


# --- the AD bit: a claim, not a fact ---
def ad_reply(got, ad=True):
    r = Message.parse(answer(got))
    r.set_flag(Flags.AD, ad)
    return r.to_wire()


@pytest.mark.asyncio
async def test_ad_is_cleared_from_a_plaintext_upstream():
    """AD says "I validated DNSSEC". Over plain UDP anyone can set it, so
    relaying it would let a spoofer mark a forged answer as verified."""
    async with FakeUpstream(ad_reply) as srv:
        resp = await upstream_to(srv.port).query(query())
        assert not resp.ad, "a forgeable AD claim was relayed to the client"


@pytest.mark.asyncio
async def test_ad_can_be_relayed_deliberately():
    """Operators who trust their plaintext path (dnsmasq's `proxy-dnssec`) must
    still be able to opt in."""
    async with FakeUpstream(ad_reply) as srv:
        up = Upstream(parse_upstream(f"127.0.0.1:{srv.port}"), timeout=1.0,
                      trust_ad="always")
        assert (await up.query(query())).ad


@pytest.mark.asyncio
async def test_ad_never_mode_strips_even_authenticated_transports():
    up = Upstream(parse_upstream("tls://9.9.9.9"), timeout=1.0, trust_ad="never")
    assert not up._ad_trusted()


def test_authenticated_transports_are_trusted_under_auto():
    """DoT/DoH/DoQ authenticate the peer, so its claim comes from who we think."""
    for scheme, trusted in (("tls", True), ("https", True), ("quic", True),
                            ("udp", False), ("tcp", False)):
        up = Upstream(parse_upstream(f"{scheme}://9.9.9.9" if scheme != "udp" else "9.9.9.9"),
                      trust_ad="auto")
        assert up._ad_trusted() is trusted, f"{scheme} should be trusted={trusted}"
