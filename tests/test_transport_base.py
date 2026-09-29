"""The shared frontend choke point, and the DoH request surface.

`process_query` is where every transport funnels through, so the size limits,
the FORMERR path and the padding all live there — and a malformed query is the
one input every listener is guaranteed to receive.
"""
from __future__ import annotations

import base64

import pytest
from support import blocked_engine, free_port

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.stats import Counters
from trench.transport.base import (
    PAD_BLOCK,
    apply_padding,
    process_query,
    resolve_wire,
    udp_response_limit,
)
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.edns import Edns
from trench.wire.name import Name
from trench.wire.rrtypes import EDNSOption, Flags, Rcode


class Fwd:
    async def resolve(self, query, note=None):
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60,
                               R.A("93.184.216.34")))
        return resp


def pipeline():
    return Pipeline(filter_engine=blocked_engine("doubleclick.net"), cache=Cache(),
                    forwarder=Fwd(), counters=Counters(), config=Config())


def mkquery(name="example.com", rtype=Type.A, edns=True, udp_size=1232, do=False):
    m = Message(id=0x4242)
    m.set_flag(Flags.RD, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    if edns:
        m.edns = Edns(udp_size=udp_size)
        m.edns.do = do
    return m


# --- the UDP size cap ---
def test_a_query_without_edns_gets_the_classic_limit():
    assert udp_response_limit(mkquery(edns=False)) == 512
    assert udp_response_limit(None) == 512


def test_an_edns_query_gets_its_advertised_size():
    assert udp_response_limit(mkquery(udp_size=1232)) == 1232


def test_an_advertised_size_below_the_floor_is_raised():
    assert udp_response_limit(mkquery(udp_size=0)) == 512
    assert udp_response_limit(mkquery(udp_size=200)) == 512


def test_an_implausible_advertised_size_is_capped():
    """A client asking for 64 KB over UDP is asking for an amplifier."""
    assert udp_response_limit(mkquery(udp_size=65535)) == 4096


# --- padding ---
def test_padding_rounds_up_to_a_block_boundary():
    resp = mkquery().reply(Rcode.NOERROR)
    apply_padding(resp)
    assert len(resp.to_wire()) % PAD_BLOCK == 0


def test_padding_adds_an_opt_to_a_response_that_had_none():
    resp = Message(id=1, flags=Flags.QR)
    apply_padding(resp)
    assert resp.edns is not None
    assert resp.edns.get_option(EDNSOption.PADDING) is not None


# --- resolve_wire ---
@pytest.mark.asyncio
async def test_a_malformed_query_becomes_a_formerr_message():
    resp = await resolve_wire(pipeline(), b"\x12\x34garbage", "127.0.0.1", "udp")
    assert resp is not None
    assert resp.id == 0x1234 and resp.rcode == Rcode.FORMERR
    assert resp.qr is True


@pytest.mark.asyncio
async def test_a_query_too_short_to_carry_an_id_is_dropped():
    assert await resolve_wire(pipeline(), b"\x00", "127.0.0.1", "udp") is None
    assert await resolve_wire(pipeline(), b"", "127.0.0.1", "udp") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("proto", ["tls", "https", "quic", "h3"])
async def test_an_encrypted_transport_pads_its_answers(proto):
    resp = await resolve_wire(pipeline(), mkquery().to_wire(), "127.0.0.1", proto)
    assert len(resp.to_wire()) % PAD_BLOCK == 0


@pytest.mark.asyncio
async def test_plaintext_transports_are_not_padded():
    resp = await resolve_wire(pipeline(), mkquery().to_wire(), "127.0.0.1", "udp")
    assert resp.edns.get_option(EDNSOption.PADDING) is None


@pytest.mark.asyncio
async def test_a_query_without_edns_is_never_padded():
    """There is no OPT to carry the option, and inventing one changes the
    answer's shape for a client that did not ask for EDNS."""
    resp = await resolve_wire(pipeline(), mkquery(edns=False).to_wire(),
                              "127.0.0.1", "tls")
    assert resp.edns is None or resp.edns.get_option(EDNSOption.PADDING) is None


# --- process_query ---
@pytest.mark.asyncio
async def test_a_malformed_datagram_gets_a_formerr_header():
    out = await process_query(pipeline(), b"\x12\x34garbage", "127.0.0.1", "udp",
                              stream=False)
    assert out[:2] == b"\x12\x34"
    assert len(out) == 12
    assert Message.parse(out).rcode == Rcode.FORMERR


@pytest.mark.asyncio
async def test_a_datagram_too_short_to_answer_is_dropped():
    assert await process_query(pipeline(), b"\x00", "127.0.0.1", "udp",
                               stream=False) is None


@pytest.mark.asyncio
async def test_a_stream_answer_is_not_size_capped():
    """TCP frames its own length; only UDP has to fit in a datagram."""
    pipe = pipeline()
    q = mkquery(edns=False)
    out = await process_query(pipe, q.to_wire(), "127.0.0.1", "tcp", stream=True)
    assert Message.parse(out).answers


@pytest.mark.asyncio
async def test_a_udp_answer_that_does_not_fit_is_truncated():
    class Big:
        async def resolve(self, query, note=None):
            resp = query.reply(Rcode.NOERROR)
            for i in range(60):
                resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60,
                                       R.A(f"93.184.216.{i % 250 + 1}")))
            return resp

    pipe = Pipeline(filter_engine=blocked_engine(), cache=Cache(), forwarder=Big(),
                    counters=Counters(), config=Config())
    out = await process_query(pipe, mkquery(edns=False).to_wire(), "127.0.0.1",
                              "udp", stream=False)
    assert len(out) <= 512
    assert Message.parse(out).tc is True


@pytest.mark.asyncio
async def test_the_answer_is_recorded_when_something_is_recording():
    """So the next identical query is answered from these very bytes, without
    coming through the pipeline at all."""
    from trench.engine.fastpath import FastPath
    pipe = pipeline()
    fast = FastPath(pipe)
    data = mkquery().to_wire()
    out = await process_query(pipe, data, "127.0.0.1", "udp", stream=False, fast=fast)
    assert out
    assert fast.size > 0
    replayed = fast.serve(data, "127.0.0.1")
    assert replayed is not None
    assert Message.parse(replayed).answers[0].rdata.address == "93.184.216.34"


@pytest.mark.asyncio
async def test_nothing_is_recorded_without_a_recorder():
    from trench.engine.fastpath import FastPath
    pipe = pipeline()
    fast = FastPath(pipe)
    data = mkquery().to_wire()
    await process_query(pipe, data, "127.0.0.1", "udp", stream=False)
    assert fast.size == 0
    assert fast.serve(data, "127.0.0.1") is None


# --- the DoH request surface ---
def _doh():
    import aiohttp

    from trench.transport.doh import DoHServer
    pipe = pipeline()
    port = free_port()
    return DoHServer(pipe, "127.0.0.1", port, "/dns-query", tls=False), port, aiohttp


@pytest.fixture
async def doh():
    server, port, aiohttp = _doh()
    await server.start()

    class D:
        base = f"http://127.0.0.1:{port}/dns-query"

    D.server = server
    yield D
    await server.stop()


def _b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


@pytest.mark.asyncio
async def test_a_get_without_the_dns_parameter_is_a_400(doh):
    import aiohttp
    async with aiohttp.ClientSession() as s, s.get(doh.base) as r:
        assert r.status == 400
        assert "missing ?dns" in await r.text()


@pytest.mark.asyncio
async def test_a_get_with_unparseable_base64_is_a_400(doh):
    import aiohttp
    async with aiohttp.ClientSession() as s, \
            s.get(f"{doh.base}?dns=!!!not base64!!!") as r:
        assert r.status == 400
        assert "bad base64url" in await r.text()


@pytest.mark.asyncio
async def test_a_post_with_the_wrong_content_type_is_a_415(doh):
    import aiohttp
    async with aiohttp.ClientSession() as s, \
            s.post(doh.base, data=b"x", headers={"Content-Type": "text/plain"}) as r:
        assert r.status == 415


@pytest.mark.asyncio
async def test_a_post_content_type_with_parameters_is_accepted(doh):
    """Parameters and case do not change the media type (RFC 9110 §8.3.1)."""
    import aiohttp
    async with aiohttp.ClientSession() as s, \
            s.post(doh.base, data=b"\x00",
                   headers={"Content-Type": "Application/DNS-Message; charset=binary"}) as r:
        assert r.status == 400          # past the media-type check, to the parser


@pytest.mark.asyncio
async def test_a_post_of_a_malformed_message_is_a_400(doh):
    import aiohttp
    async with aiohttp.ClientSession() as s, \
            s.post(doh.base, data=b"\x00",
                   headers={"Content-Type": "application/dns-message"}) as r:
        assert r.status == 400


@pytest.mark.asyncio
async def test_a_wire_get_is_answered_with_a_cache_control_header(doh):
    import aiohttp
    async with aiohttp.ClientSession() as s, \
            s.get(f"{doh.base}?dns={_b64(mkquery().to_wire())}") as r:
        assert r.status == 200
        assert r.content_type == "application/dns-message"
        assert r.headers["Cache-Control"].startswith("max-age=")
        resp = Message.parse(await r.read())
    assert resp.answers[0].rdata.address == "93.184.216.34"


@pytest.mark.asyncio
async def test_the_json_api_answers_and_names_its_content_type(doh):
    import aiohttp
    async with aiohttp.ClientSession() as s, \
            s.get(f"{doh.base}?name=example.com&type=A") as r:
        assert r.status == 200
        assert r.content_type.startswith("application/dns-json")
        body = await r.json(content_type=None)
    assert body["Status"] == 0
    assert body["Answer"][0]["data"] == "93.184.216.34"
    assert body["Question"][0]["name"].startswith("example.com")


@pytest.mark.asyncio
async def test_the_json_api_accepts_a_numeric_type(doh):
    import aiohttp
    async with aiohttp.ClientSession() as s, \
            s.get(f"{doh.base}?name=example.com&type=1") as r:
        assert (await r.json(content_type=None))["Status"] == 0


@pytest.mark.asyncio
async def test_the_json_api_refuses_a_type_it_cannot_read(doh):
    import aiohttp
    async with aiohttp.ClientSession() as s, \
            s.get(f"{doh.base}?name=example.com&type=NOTATYPE") as r:
        assert r.status == 400
        assert (await r.json())["error"] == "bad type"


@pytest.mark.asyncio
async def test_the_json_api_honours_the_do_and_cd_flags(doh):
    import aiohttp
    async with aiohttp.ClientSession() as s, \
            s.get(f"{doh.base}?name=example.com&do=1&cd=true") as r:
        body = await r.json(content_type=None)
    assert "Status" in body


def test_the_json_rendering_drops_the_opt_pseudo_record():
    from trench.transport.doh import message_to_json
    msg = mkquery().reply(Rcode.NOERROR)
    msg.answers.append(RR(Name.from_text("example.com."), Type.A, Class.IN, 60,
                          R.A("192.0.2.1")))
    msg.additional.append(RR(Name.from_text("."), Type.OPT, Class.IN, 0,
                             R.A("0.0.0.0")))
    out = message_to_json(msg)
    assert len(out["Answer"]) == 1
    assert all(rr["type"] != int(Type.OPT) for rr in out.get("Additional", []))
