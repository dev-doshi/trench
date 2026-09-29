"""Header and OPT validation on the query path (RFC 1035, 6891, 8906, 9619)."""
from __future__ import annotations

import struct

import pytest
from support import blocked_engine

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.errors import WireError
from trench.stats import Counters
from trench.transport.base import not_a_query, process_query, udp_response_limit
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.edns import Edns
from trench.wire.name import Name
from trench.wire.rrtypes import EDNSOption, Flags, Opcode, Rcode


class Fwd:
    async def resolve(self, query, note=None):
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60,
                               R.A("93.184.216.34")))
        return resp


def pipeline(config=None):
    return Pipeline(filter_engine=blocked_engine("doubleclick.net"), cache=Cache(),
                    forwarder=Fwd(), counters=Counters(), config=config or Config())


def mkquery(*names, edns=True, version=0, opcode=Opcode.QUERY):
    m = Message(id=0x1234)
    m.set_flag(Flags.RD, True)
    m.flags |= opcode << Flags.OPCODE_SHIFT
    for name in names:
        m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    if edns:
        m.edns = Edns(udp_size=4096)
        m.edns.version = version
    return m


async def ask(query, **kw):
    out = await process_query(pipeline(**kw), query.to_wire(), "192.0.2.1", "udp",
                              stream=False)
    return None if out is None else Message.parse(out)


@pytest.mark.asyncio
async def test_a_response_is_never_answered():
    """Answering a QR=1 message lets a spoofed response set two servers
    bouncing replies off each other indefinitely."""
    q = mkquery("example.com")
    q.set_flag(Flags.QR, True)
    assert not_a_query(q.to_wire())
    assert await ask(q) is None


@pytest.mark.asyncio
async def test_an_unknown_opcode_is_notimp():
    resp = await ask(mkquery("example.com", opcode=Opcode.STATUS))
    assert resp.rcode == Rcode.NOTIMP


@pytest.mark.asyncio
async def test_an_unknown_edns_version_is_badvers_with_version_zero():
    resp = await ask(mkquery("example.com", version=1))
    assert resp.rcode == Rcode.BADVERS
    assert resp.edns is not None and resp.edns.version == 0
    assert resp.answers == []


@pytest.mark.asyncio
async def test_more_than_one_question_is_formerr():
    resp = await ask(mkquery("example.com", "example.org"))
    assert resp.rcode == Rcode.FORMERR


@pytest.mark.asyncio
async def test_no_question_without_a_cookie_is_formerr():
    resp = await ask(mkquery())
    assert resp.rcode == Rcode.FORMERR


@pytest.mark.asyncio
async def test_a_cookie_probe_with_no_question_is_answered():
    q = mkquery()
    q.edns.set_option(EDNSOption.COOKIE, b"\x01" * 8)
    resp = await ask(q)
    assert resp.rcode == Rcode.NOERROR


@pytest.mark.asyncio
async def test_the_response_advertises_our_udp_size_not_the_clients():
    cfg = Config()
    cfg.server.edns_udp_size = 1232
    resp = await ask(mkquery("example.com"), config=cfg)
    assert resp.edns is not None and resp.edns.udp_size == 1232


def test_the_udp_limit_is_the_smaller_of_both_sizes():
    q = mkquery("example.com")
    assert udp_response_limit(q, 1232) == 1232
    q.edns.udp_size = 800
    assert udp_response_limit(q, 1232) == 800


def _with_opts(count: int, owner: bytes = b"\x00") -> bytes:
    wire = bytearray(mkquery("example.com", edns=False).to_wire())
    opt = owner + struct.pack(">HHIH", Type.OPT, 4096, 0, 0)
    wire[10:12] = struct.pack(">H", count)
    return bytes(wire) + opt * count


def test_two_opt_records_are_rejected():
    Message.parse(_with_opts(1))
    with pytest.raises(WireError):
        Message.parse(_with_opts(2))


def test_an_opt_not_owned_by_the_root_is_rejected():
    with pytest.raises(WireError):
        Message.parse(_with_opts(1, owner=b"\x01a\x00"))


@pytest.mark.asyncio
async def test_a_rejected_header_says_why():
    """A Fritz!Box repeater's DNS UPDATEs sat in the log 2,600 times as
    'refused' with nothing to say which check turned them away."""
    ctx = await pipeline().resolve_ctx(mkquery("myfritz.net", opcode=Opcode.UPDATE),
                                       "192.0.2.1")
    assert ctx.response.rcode == Rcode.NOTIMP
    assert ctx.reason == "opcode not supported"
