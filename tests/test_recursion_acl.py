"""Who may recurse over plain DNS (audit M4).

A listener bound to a LAN address answered anyone who reached it: with a port
forward or an unfirewalled IPv6 address, an open resolver and a reflector for
spoofed-source floods.
"""
from __future__ import annotations

import ipaddress

import pytest
from support import blocked_engine

from trench.cache import Cache
from trench.config import Config
from trench.engine import access
from trench.engine.access import RecursionAcl, connected_networks
from trench.engine.pipeline import Pipeline
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


def _nets(*cidrs):
    return lambda: [ipaddress.ip_network(c) for c in cidrs]


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "172.20.0.5", "192.168.1.9",
                                "100.100.100.100", "::1", "fd00::5", "fe80::1%eth0",
                                "::ffff:192.168.1.9"])
def test_local_addresses_may_recurse_by_default(ip):
    assert RecursionAcl(routes=list).allows(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "2001:db8::1", "::ffff:8.8.8.8", "garbage"])
def test_outsiders_may_not(ip):
    assert not RecursionAcl(routes=list).allows(ip)


def test_attached_networks_count_as_local():
    """A home LAN on IPv6 uses global addresses no fixed list contains."""
    acl = RecursionAcl(routes=_nets("2001:db8:1:2::/64", "198.51.100.0/24"))
    assert acl.allows("2001:db8:1:2::abcd") and acl.allows("198.51.100.7")
    assert not acl.allows("2001:db8:1:3::1")


def test_attached_networks_are_reread(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(access.time, "monotonic", lambda: now[0])
    routes = ["198.51.100.0/24"]
    acl = RecursionAcl(routes=lambda: [ipaddress.ip_network(c) for c in routes])
    assert acl.allows("198.51.100.7")
    routes[:] = []
    now[0] += access.REFRESH + 1
    assert not acl.allows("198.51.100.7")        # the remembered yes expired


def test_explicit_entries_replace_or_extend_the_default():
    only = RecursionAcl(["203.0.113.0/24"], routes=list)
    assert only.allows("203.0.113.9") and not only.allows("192.168.1.1")
    both = RecursionAcl(["local", "203.0.113.0/24"], routes=list)
    assert both.allows("203.0.113.9") and both.allows("192.168.1.1")
    everyone = RecursionAcl(["0.0.0.0/0", "::/0"], routes=list)
    assert everyone.open and everyone.allows("8.8.8.8")
    # blank lines from a settings form are the default, not "nobody"
    assert RecursionAcl(["", "  "], routes=list).allows("192.168.1.1")


def test_refusals_are_not_remembered():
    acl = RecursionAcl(routes=list)
    for n in range(1000):
        acl.allows(f"8.8.{n // 256}.{n % 256}")
    assert acl._memo == {} and acl.refused == 1000


def test_route_table_parsing(monkeypatch, tmp_path):
    v4 = tmp_path / "route"
    v4.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n"     # default via gw
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"     # 192.168.1.0/24
        "tun0\t00000000\t00000000\t0001\t0\t0\t0\t00000080\n")    # 0.0.0.0/1 on-link
    v6 = tmp_path / "ipv6_route"
    zero = "0" * 32
    v6.write_text(
        f"20010db8000100020000000000000000 40 {zero} 00 {zero} 100 1 0 1 eth0\n"
        f"{zero} 00 {zero} 00 {zero} ffffffff 1 0 200 lo\n"
        f"ff000000000000000000000000000000 08 {zero} 00 {zero} 100 1 0 1 eth0\n"
        f"20010db8000900000000000000000000 30 {zero} 00 "
        f"fe800000000000000000000000000001 400 1 0 3 eth0\n")
    real = open
    paths = {"/proc/net/route": v4, "/proc/net/ipv6_route": v6}
    monkeypatch.setattr("builtins.open", lambda p, *a, **k: real(paths.get(p, p), *a, **k))
    assert [str(n) for n in connected_networks()] == ["192.168.1.0/24", "2001:db8:1:2::/64"]


class _Forwarder:
    def __init__(self):
        self.calls = 0

    async def resolve(self, query, note=None):
        self.calls += 1
        a = query.reply(Rcode.NOERROR)
        a.answers.append(RR(query.question.name, Type.A, Class.IN, 60,
                            R.A("93.184.216.34")))
        return a


class _Zones:
    empty = False

    def resolve(self, query):
        if query.question.name.to_text() == "zone.example.":
            return query.reply(Rcode.NOERROR)
        return None


def _pipeline():
    fwd = _Forwarder()
    p = Pipeline(filter_engine=blocked_engine("ads.example"), cache=Cache(),
                 forwarder=fwd, counters=Counters(), config=Config())
    p.recursion_acl = RecursionAcl(routes=list)
    return p, fwd


def _q(name="example.com"):
    m = Message(id=1)
    m.set_flag(0x0100, True)  # RD
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


@pytest.mark.asyncio
async def test_pipeline_refuses_outsiders_over_plain_dns_only():
    p, fwd = _pipeline()
    for proto in ("udp", "tcp"):
        ctx = await p.resolve_ctx(_q(), "8.8.8.8", proto)
        assert ctx.response.rcode == Rcode.REFUSED and ctx.action == "refused"
    assert fwd.calls == 0
    for proto in ("tls", "https"):
        ctx = await p.resolve_ctx(_q(), "8.8.8.8", proto)
        assert ctx.response.rcode == Rcode.NOERROR
    ctx = await p.resolve_ctx(_q("other.example"), "192.168.1.5", "udp")
    assert ctx.response.rcode == Rcode.NOERROR


@pytest.mark.asyncio
async def test_authoritative_zones_stay_open_to_everyone():
    """An ACME CA checking a dns-01 challenge asks from the internet."""
    p, fwd = _pipeline()
    p.zones = _Zones()
    ctx = await p.resolve_ctx(_q("zone.example"), "8.8.8.8", "udp")
    assert ctx.action == "authoritative"


@pytest.mark.asyncio
async def test_the_fast_path_does_not_replay_to_outsiders():
    from trench.engine.fastpath import FastPath
    from trench.transport.base import process_query
    p, fwd = _pipeline()
    p.fast = fast = FastPath(p)
    wire = _q().to_wire()
    await process_query(p, wire, "192.168.1.5", "udp", stream=False, fast=fast)
    assert fast.serve(wire, "192.168.1.5") is not None      # recorded and replayed
    assert fast.serve(wire, "8.8.8.8") is None               # but not to outsiders
    out = await process_query(p, wire, "8.8.8.8", "udp", stream=False, fast=fast)
    assert Message.parse(out).rcode == Rcode.REFUSED
