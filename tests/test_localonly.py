"""Names answered locally and never forwarded (RFC 6303 / 6761 / 8375 / 9462)."""
from __future__ import annotations

import asyncio

import pytest
from support import open_resolver

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.engine.localonly import is_local_only
from trench.filter import FilterEngine, compile_rules
from trench.filter.rule import operator_rules
from trench.stats import Counters
from trench.transport.upstream import Router
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


@pytest.mark.parametrize("qname", [
    "1.178.168.192.in-addr.arpa", "5.0.20.172.in-addr.arpa", "9.9.10.in-addr.arpa",
    "1.2.64.100.in-addr.arpa",
    "a.b.d.f.ip6.arpa", "health-check.trench.invalid", "printer.local",
    "nas.home.arpa", "_dns.resolver.arpa", "localhost", "WPAD.LAN.",
])
def test_local_only_names(qname):
    assert is_local_only(qname, ("lan",))


@pytest.mark.parametrize("qname", [
    "8.8.8.8.in-addr.arpa", "1.0.32.172.in-addr.arpa", "example.com",
    "invalid.example.com", "local.example", "fritz.box",
])
def test_ordinary_names(qname):
    assert not is_local_only(qname, ("lan",))


class Upstream:
    def __init__(self, routes=None):
        self.asked: list[str] = []
        self.router = Router(routes=routes or {})

    async def resolve(self, query: Message, note=None) -> Message:
        self.asked.append(str(query.question.name))
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def _query(name, rtype=Type.A):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    return m


def _pipe(fwd, rules=(), **security):
    cfg = Config.model_validate({"security": security})
    return Pipeline(filter_engine=FilterEngine.compile(list(rules)), cache=Cache(),
                    forwarder=fwd, counters=Counters(), config=open_resolver(cfg))


def test_a_private_ptr_is_answered_without_asking_upstream():
    fwd = Upstream()
    r = asyncio.run(_pipe(fwd).resolve(_query("1.178.168.192.in-addr.arpa", Type.PTR),
                                       "192.168.178.20"))
    assert r.rcode == Rcode.NXDOMAIN and fwd.asked == []


def test_a_list_cannot_block_a_special_use_name():
    """`resolver.arpa` sits on a public blocklist; a sinkhole answer to the
    DDR probe is still an answer the name was never meant to get upstream."""
    fwd = Upstream()
    pipe = _pipe(fwd, compile_rules("||resolver.arpa^", "list"))
    r = asyncio.run(pipe.resolve(_query("_dns.resolver.arpa", Type.SVCB), "10.0.0.2"))
    assert r.rcode == Rcode.NXDOMAIN and not r.answers and fwd.asked == []


def test_a_configured_route_still_wins():
    fwd = Upstream(routes={"178.168.192.in-addr.arpa": [object()]})
    r = asyncio.run(_pipe(fwd).resolve(_query("1.178.168.192.in-addr.arpa", Type.PTR),
                                       "192.168.178.20"))
    assert r.rcode == Rcode.NOERROR and len(fwd.asked) == 1


def test_an_allowed_name_is_not_second_guessed_by_the_detectors():
    name = "a8f3b2c9d4e5f6a7b8c9d0e1f2a3b4c5a8f3b2c9.exfil.example.com"
    blocked = _pipe(Upstream(), tunnel_detection=True, tunnel_block=True)
    assert asyncio.run(blocked.resolve_ctx(_query(name, Type.TXT), "10.0.0.2")).source == "tunnel"
    allowed = _pipe(Upstream(), operator_rules(["example.com"], []),
                    tunnel_detection=True, tunnel_block=True)
    assert asyncio.run(allowed.resolve_ctx(_query(name, Type.TXT), "10.0.0.2")).source != "tunnel"


class _Spec:
    def __init__(self, host):
        self.host = host


class _Dead:
    """An upstream that fails every question, as a looping router does."""
    def __init__(self, host):
        self.spec = _Spec(host)

    def __repr__(self):
        return f"udp://{self.spec.host}:53"

    async def query(self, msg):
        from trench.errors import UpstreamError
        raise UpstreamError("timed out")


def _forwarder(routes=None, default=()):
    from trench.resolver.forwarder import Forwarder
    fwd = Forwarder([])
    fwd.router = Router(default=list(default), routes=routes or {})
    return fwd


ROUTER = "192.168.178.1"


def test_the_route_s_own_server_is_not_sent_its_question_back():
    """A router whose upstream is this resolver passes on the reverse lookups
    it cannot answer; routing them back to it is a loop that ends in a SERVFAIL
    seconds later."""
    fwd = Upstream(routes={"178.168.192.in-addr.arpa": [_Dead(ROUTER)]})
    pipe = _pipe(fwd)
    for client in (ROUTER, "::ffff:" + ROUTER):
        r = asyncio.run(pipe.resolve(_query("26.178.168.192.in-addr.arpa", Type.PTR), client))
        assert r.rcode == Rcode.NXDOMAIN
    assert fwd.asked == []
    # Any other device still gets the route.
    asyncio.run(pipe.resolve(_query("26.178.168.192.in-addr.arpa", Type.PTR), "192.168.178.20"))
    assert len(fwd.asked) == 1


def test_a_failed_route_for_a_private_name_is_nxdomain_and_names_the_server():
    fwd = _forwarder(routes={"178.168.192.in-addr.arpa": [_Dead(ROUTER)]})
    pipe = _pipe(fwd)
    ctx = asyncio.run(pipe.resolve_ctx(_query("26.178.168.192.in-addr.arpa", Type.PTR),
                                       "192.168.178.20"))
    assert ctx.response.rcode == Rcode.NXDOMAIN
    assert ctx.action == "failed" and ctx.upstream == f"udp://{ROUTER}:53"


def test_a_failed_public_name_is_servfail_and_names_the_servers_tried():
    fwd = _forwarder(default=[_Dead("9.9.9.9"), _Dead("1.1.1.1")])
    pipe = _pipe(fwd)
    ctx = asyncio.run(pipe.resolve_ctx(_query("example.com"), "192.168.178.20"))
    assert ctx.response.rcode == Rcode.SERVFAIL and ctx.action == "failed"
    assert ctx.upstream == "udp://9.9.9.9:53, udp://1.1.1.1:53"
    # Named in the log, but not counted as having answered anything.
    assert not pipe.counters.upstreams.most_common(10)
