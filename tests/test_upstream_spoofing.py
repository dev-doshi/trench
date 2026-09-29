"""Off-path spoofing resistance of plain-UDP upstream queries (audit H2).

Against a blind spoofer, a plain-UDP forwarder has the transaction id and the
source port, about 26 bits with the default pool. These tests hold the three
things added on top: 0x20 case randomisation on every plain-UDP upstream,
learned per upstream so one that folds case is not broken by it; a CSPRNG
behind every guessable choice; and a socket pool that rotates, so a port an
attacker has learned stops being useful.
"""
from __future__ import annotations

import asyncio
import random
import socket

import pytest

from trench.engine import zerox20
from trench.errors import UpstreamError
from trench.transport.upstream import UdpPool, Upstream, parse_upstream
from trench.wire import Class, Message, Question, Type
from trench.wire.name import Name

NAME = "www.example.com."


def _query(name=NAME, qid=0x1234) -> Message:
    q = Message(id=qid)
    q.set_flag(0x0100, True)
    q.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return q


class CaseServer:
    """A UDP upstream whose treatment of query-name case is chosen per reply:
    `echo` (RFC-conforming), `lower` (folds case) or `flip` (a spoofer that
    guessed id and port but not the case)."""

    def __init__(self, mode="echo"):
        self.mode = mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.setblocking(False)
        self.seen: list[Name] = []
        self._task = None

    @property
    def port(self):
        return self.sock.getsockname()[1]

    async def _serve(self):
        loop = asyncio.get_running_loop()
        while True:
            data, addr = await loop.sock_recvfrom(self.sock, 4096)
            got = Message.parse(data)
            q = got.question
            self.seen.append(q.name)
            if self.mode == "lower":
                name = Name(tuple(label.lower() for label in q.name.labels))
            elif self.mode == "flip":
                name = Name(tuple(label.swapcase() for label in q.name.labels))
            else:
                name = q.name
            r = Message(id=got.id)
            r.set_flag(0x8000, True)
            r.questions = [Question(name, q.rtype, q.rclass)]
            await loop.sock_sendto(self.sock, r.to_wire(), addr)

    async def __aenter__(self):
        self._task = asyncio.ensure_future(self._serve())
        return self

    async def __aexit__(self, *exc):
        self._task.cancel()
        self.sock.close()


def _upstream(port):
    return Upstream(parse_upstream(f"127.0.0.1:{port}"), timeout=2.0)


def test_case_randomisation_does_not_use_mersenne_twister(monkeypatch):
    def predictable(*_a, **_k):
        raise AssertionError("0x20 bits must come from the CSPRNG")
    monkeypatch.setattr(random, "getrandbits", predictable)
    name = Name.from_text("abcdefghijklmnopqrstuvwxyz.example.")
    seen = {zerox20.randomize_name(name).labels for _ in range(20)}
    assert len(seen) > 1
    assert all(Name(labels) == name for labels in seen)   # same name, new case


@pytest.mark.asyncio
async def test_plain_udp_queries_carry_randomised_case_and_answers_keep_the_callers():
    async with CaseServer() as srv:
        up = _upstream(srv.port)
        try:
            for i in range(10):
                resp = await up.query(_query(qid=i + 1))
                assert resp.question.name.labels == Name.from_text(NAME).labels
        finally:
            await up.close()
    assert len({n.labels for n in srv.seen}) > 1        # the case moved about
    assert up._case_echo is True


@pytest.mark.asyncio
async def test_once_an_upstream_is_known_to_echo_a_wrong_case_is_refused():
    async with CaseServer() as srv:
        up = _upstream(srv.port)
        try:
            while up._case_echo is not True:
                await up.query(_query())
            srv.mode = "flip"                     # a spoofer that won id + port
            with pytest.raises(UpstreamError, match="0x20"):
                await up.query(_query())
        finally:
            await up.close()


@pytest.mark.asyncio
async def test_an_upstream_that_folds_case_keeps_working():
    """Learned, not assumed: a case-folding upstream is not failed for it."""
    async with CaseServer("lower") as srv:
        up = _upstream(srv.port)
        try:
            for i in range(10):
                resp = await up.query(_query(qid=i + 1))
                assert resp.question.name.labels == Name.from_text(NAME).labels
        finally:
            await up.close()
    assert up._case_echo is False
    # once it is known, the randomising stops rather than failing on and on
    assert srv.seen[-1].labels == Name.from_text(NAME).labels


@pytest.mark.asyncio
async def test_the_pool_rotates_its_ports(monkeypatch):
    """A fixed pool let an attacker keep a learned port for the life of the
    process. Each socket now carries a bounded, random number of queries."""
    monkeypatch.setattr(UdpPool, "LIFETIME", (2, 4))
    async with CaseServer() as srv:
        up = Upstream(parse_upstream(f"127.0.0.1:{srv.port}"), timeout=2.0,
                      udp_source_ports=2)
        ports = set()
        try:
            for i in range(40):
                await up.query(_query(qid=i + 1))
                ports |= {s.transport.get_extra_info("sockname")[1]
                          for s in up._pool._socks}
                assert len(up._pool._socks) <= 2
        finally:
            await up.close()
    assert len(ports) > 4, ports


@pytest.mark.asyncio
async def test_a_retired_socket_is_closed_only_after_its_queries_finish(monkeypatch):
    monkeypatch.setattr(UdpPool, "LIFETIME", (1, 2))    # every socket used once
    async with CaseServer() as srv:
        pool = UdpPool("127.0.0.1", srv.port, size=1)
        try:
            a, b = await asyncio.gather(
                pool.query(_query(qid=1).to_wire(), 2),
                pool.query(_query(qid=2).to_wire(), 2))
            assert {Message.parse(a).id, Message.parse(b).id} == {1, 2}
        finally:
            pool.close()


@pytest.mark.asyncio
async def test_pool_selection_does_not_use_mersenne_twister(monkeypatch):
    def predictable(*_a, **_k):
        raise AssertionError("socket choice must come from the CSPRNG")
    for fn in ("choice", "sample", "getrandbits", "randrange"):
        monkeypatch.setattr(random, fn, predictable)
    async with CaseServer() as srv:
        pool = UdpPool("127.0.0.1", srv.port, size=4)
        try:
            await pool._ensure()
            loop = asyncio.get_running_loop()
            for sock in pool._socks[:3]:
                sock.pending[7] = loop.create_future()   # force the fallback
            await pool.query(_query(qid=7).to_wire(), 2)
        finally:
            for sock in pool._socks:
                sock.pending.clear()
            pool.close()
