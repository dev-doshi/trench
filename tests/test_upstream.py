"""Upstream transports (DoT/DoH/DoQ) + spec parsing + per-domain routing.

We point the upstream client at our own encrypted frontends to prove the full
encrypted forwarding path end to end.
"""
from __future__ import annotations

import socket
from pathlib import Path

import pytest
from support import blocked_engine

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.resolver.forwarder import Forwarder
from dnsguard.stats import Counters
from dnsguard.transport.upstream import Router, parse_upstream
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode

CERT_DIR = Path("./data")


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_parse_upstream_forms():
    assert parse_upstream("1.1.1.1").scheme == "udp"
    assert parse_upstream("1.1.1.1:5353").port == 5353
    u = parse_upstream("tls://9.9.9.9#dns.quad9.net")
    assert u.scheme == "tls" and u.port == 853 and u.sni == "dns.quad9.net"
    u = parse_upstream("https://dns.google/dns-query")
    assert u.scheme == "https" and u.port == 443 and u.path == "/dns-query"
    u = parse_upstream("quic://dns.adguard.com")
    assert u.scheme == "quic" and u.port == 853
    u = parse_upstream("[/internal.lan/]192.168.1.1")
    assert u.domains == ("internal.lan",) and u.host == "192.168.1.1"


def test_router_per_domain():
    r = Router.build(["1.1.1.1", "[/corp.example/]10.0.0.1", "[/corp.example/]10.0.0.2"])
    assert [u.spec.host for u in r.group_for("www.corp.example")] == ["10.0.0.1", "10.0.0.2"]
    assert [u.spec.host for u in r.group_for("google.com")] == ["1.1.1.1"]


class FakeForwarder:
    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("93.184.216.34")))
        return resp


def server_pipeline() -> Pipeline:
    return Pipeline(filter_engine=blocked_engine(), cache=Cache(), forwarder=FakeForwarder(),
                    counters=Counters(), config=Config())


def mkquery(name="example.com"):
    m = Message(id=9)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


@pytest.mark.asyncio
async def test_upstream_dot():
    from dnsguard.transport.dot import DoTServer
    port = free_port()
    srv = DoTServer(server_pipeline(), "127.0.0.1", port, None, None, CERT_DIR)
    await srv.start()
    try:
        fwd = Forwarder([f"tls://127.0.0.1:{port}"], strategy="sequential", verify=False)
        resp = await fwd.resolve(mkquery())
        assert resp.answers[0].rdata.to_text() == "93.184.216.34"
        await fwd.close()
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_upstream_doh():
    from dnsguard.transport.doh import DoHServer
    port = free_port()
    srv = DoHServer(server_pipeline(), "127.0.0.1", port, "/dns-query", tls=True,
                    data_dir=CERT_DIR)
    await srv.start()
    try:
        fwd = Forwarder([f"https://127.0.0.1:{port}/dns-query"], strategy="sequential",
                        verify=False)
        resp = await fwd.resolve(mkquery())
        assert resp.answers[0].rdata.to_text() == "93.184.216.34"
        await fwd.close()
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_upstream_doq():
    from dnsguard.transport.doq import DoQServer
    port = free_port()
    srv = DoQServer(server_pipeline(), "127.0.0.1", port, None, None, CERT_DIR)
    await srv.start()
    try:
        fwd = Forwarder([f"quic://127.0.0.1:{port}"], strategy="sequential", verify=False)
        resp = await fwd.resolve(mkquery())
        assert resp.answers[0].rdata.to_text() == "93.184.216.34"
        await fwd.close()
    finally:
        await srv.stop()
