"""Upstream transports (DoT/DoH/DoQ) + spec parsing + per-domain routing.

We point the upstream client at our own encrypted frontends to prove the full
encrypted forwarding path end to end.
"""
from __future__ import annotations

import socket
from pathlib import Path

import pytest
from support import blocked_engine

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.resolver.forwarder import Forwarder
from trench.stats import Counters
from trench.transport.upstream import Router, parse_upstream
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode

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
    from trench.transport.dot import DoTServer
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
    from trench.transport.doh import DoHServer
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
    from trench.transport.doq import DoQServer
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


@pytest.mark.asyncio
async def test_upstream_doq_needs_no_ipv6(monkeypatch):
    """A v4 DoQ upstream must work on a kernel with IPv6 disabled.

    aioquic's own `connect` always opens an AF_INET6 dual-stack socket, which
    fails with EAFNOSUPPORT there; the forwarder must not depend on it.
    """
    import errno
    import socket as socketmod

    from trench.transport.doq import DoQServer
    port = free_port()
    srv = DoQServer(server_pipeline(), "127.0.0.1", port, None, None, CERT_DIR)
    await srv.start()

    real = socketmod.socket

    class _NoV6(real):
        def __init__(self, family=-1, *a, **k):
            if family == socketmod.AF_INET6:
                raise OSError(errno.EAFNOSUPPORT, "Address family not supported")
            super().__init__(family, *a, **k)

    monkeypatch.setattr(socketmod, "socket", _NoV6)
    try:
        fwd = Forwarder([f"quic://127.0.0.1:{port}"], strategy="sequential", verify=False)
        resp = await fwd.resolve(mkquery())
        assert resp.answers[0].rdata.to_text() == "93.184.216.34"
        await fwd.close()
    finally:
        monkeypatch.undo()
        await srv.stop()


# --- stream reconnect behaviour ---------------------------------------------
class _FlakyConn:
    """Stands in for `_StreamConn`, failing the first `fail_first` attempts.

    `_stream` owns the reconnect loop; the connection object only reports what
    the peer did. Each failure must be followed by a close, or the next attempt
    reuses a socket the peer has already dropped.
    """

    def __init__(self, fail_first: int, exc: BaseException | None = None):
        self.fail_first = fail_first
        self.exc = exc or ConnectionResetError(104, "Connection reset by peer")
        self.attempts = 0
        self.closes = 0

    async def query(self, wire: bytes) -> bytes:
        self.attempts += 1
        if self.attempts <= self.fail_first:
            raise self.exc
        return b"answer"

    async def close(self) -> None:
        self.closes += 1


def _upstream(spec: str = "tls://9.9.9.9#dns.quad9.net"):
    from trench.transport.upstream import Upstream
    return Upstream(parse_upstream(spec), timeout=4.0)


@pytest.mark.asyncio
async def test_a_reset_handshake_is_retried_rather_than_failing_the_query():
    """Quad9 measured a 33-67% TLS accept rate from one deployment, resetting
    during the handshake. A single retry is a coin flip, and with both
    configured upstreams at one provider the pair lost the toss together often
    enough to SERVFAIL real clients."""
    up = _upstream()
    up._conn = _FlakyConn(fail_first=2)
    assert await up._stream(b"q") == b"answer"
    assert up._conn.attempts == 3
    assert up._conn.closes == 2, "each failed attempt must drop the dead connection"


@pytest.mark.asyncio
async def test_a_peer_that_never_accepts_reports_its_own_error():
    up = _upstream()
    up._conn = _FlakyConn(fail_first=99)
    with pytest.raises(ConnectionResetError):
        await up._stream(b"q")
    assert up._conn.attempts == up._STREAM_ATTEMPTS


@pytest.mark.asyncio
async def test_a_timeout_is_not_retried():
    """`upstream.timeout` is the budget for answering the query, not for each
    attempt at it. TimeoutError subclasses OSError, so it used to fall into the
    reconnect branch and a merely slow upstream cost two full timeouts."""
    up = _upstream()
    up._conn = _FlakyConn(fail_first=99, exc=TimeoutError())
    with pytest.raises(TimeoutError):
        await up._stream(b"q")
    assert up._conn.attempts == 1
    assert up._conn.closes == 0, "a timeout says nothing about the connection"


@pytest.mark.asyncio
async def test_a_silent_doq_upstream_fails_within_its_timeout():
    """A black-holed DoQ upstream used to hold the query for aioquic's 60 s idle
    timeout, and the close afterwards waited out the draining period on top."""
    import asyncio
    import time

    from trench.transport.upstream import Upstream, parse_upstream
    hole = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # bound, never answers
    hole.bind(("127.0.0.1", 0))
    try:
        up = Upstream(parse_upstream(f"quic://127.0.0.1:{hole.getsockname()[1]}"),
                      timeout=0.5, verify=False)
        t = time.monotonic()
        with pytest.raises((asyncio.TimeoutError, TimeoutError, OSError)):
            await up._doq(mkquery().to_wire())
        assert time.monotonic() - t < 1.5
    finally:
        hole.close()
