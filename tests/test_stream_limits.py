"""Stream (TCP/DoT) frontend bounds and pipelining, RFC 7766.

Three defects, all verified against a running server before being fixed:

  * a read with no deadline — 300 connections opened and abandoned stayed open
    indefinitely, having sent no DNS at all;
  * no cap on connections, so the limit was whatever the file-descriptor ceiling
    happened to be, and one peer could take all of it;
  * queries answered strictly in arrival order (§6.2.1.1), so 20 pipelined
    queries took 568 ms in series where the slowest one alone took 114 ms.

The tests drive real sockets through `asyncio.start_server`, because the defects
were in how the connection is read, not in what the resolver does with it.
"""
from __future__ import annotations

import asyncio
import struct

import pytest

from dnsguard.transport.stream import (
    ConnectionTracker,
    StreamLimits,
    serve_stream,
)


class Server:
    """A `serve_stream` listener on a loopback port."""

    def __init__(self, respond, **limit_kw):
        self.limits = StreamLimits(**limit_kw)
        self.tracker = ConnectionTracker(self.limits)
        self.respond = respond
        self.srv: asyncio.AbstractServer | None = None

    async def __aenter__(self):
        self.srv = await asyncio.start_server(
            lambda r, w: serve_stream(r, w, self.respond, proto="tcp",
                                      limits=self.limits, tracker=self.tracker),
            "127.0.0.1", 0)
        return self

    async def __aexit__(self, *exc):
        self.srv.close()
        await self.srv.wait_closed()

    @property
    def port(self) -> int:
        return self.srv.sockets[0].getsockname()[1]

    async def connect(self):
        return await asyncio.open_connection("127.0.0.1", self.port)


def framed(payload: bytes) -> bytes:
    return struct.pack(">H", len(payload)) + payload


async def read_frame(reader, timeout=5.0):
    hdr = await asyncio.wait_for(reader.readexactly(2), timeout)
    n = int.from_bytes(hdr, "big")
    return await asyncio.wait_for(reader.readexactly(n), timeout)


def echo(delays=None):
    """Responder that echoes the payload, optionally after a per-payload delay."""
    async def respond(data: bytes, client_ip: str) -> list[bytes]:
        if delays:
            await asyncio.sleep(delays.get(data, 0.0))
        return [data]
    return respond


# --- idle connections are reclaimed ---
@pytest.mark.asyncio
async def test_a_connection_that_sends_nothing_is_closed():
    """The whole slow-loris shape: connect, send no bytes, hold a slot."""
    async with Server(echo(), idle_timeout=0.15) as srv:
        reader, writer = await srv.connect()
        assert await asyncio.wait_for(reader.read(1), 2.0) == b"", (
            "the server held an idle connection open")
        writer.close()


@pytest.mark.asyncio
async def test_a_connection_that_stops_mid_message_is_closed():
    """A length prefix promising bytes that never arrive is the same attack with
    two bytes of effort."""
    async with Server(echo(), idle_timeout=0.15) as srv:
        reader, writer = await srv.connect()
        writer.write(struct.pack(">H", 500))   # promise 500, send none
        await writer.drain()
        assert await asyncio.wait_for(reader.read(1), 2.0) == b""
        writer.close()


@pytest.mark.asyncio
async def test_the_idle_clock_restarts_after_each_query():
    """A connection in use must not be cut off for having been open a while."""
    async with Server(echo(), idle_timeout=0.3) as srv:
        reader, writer = await srv.connect()
        for i in range(4):
            writer.write(framed(f"q{i}".encode()))
            await writer.drain()
            assert await read_frame(reader) == f"q{i}".encode()
            await asyncio.sleep(0.2)           # under the timeout each time
        writer.close()


@pytest.mark.asyncio
async def test_the_timeout_can_be_disabled():
    async with Server(echo(), idle_timeout=0) as srv:
        reader, writer = await srv.connect()
        await asyncio.sleep(0.3)
        writer.write(framed(b"late"))
        await writer.drain()
        assert await read_frame(reader) == b"late"
        writer.close()


# --- connections are capped ---
@pytest.mark.asyncio
async def test_connections_beyond_the_global_cap_are_refused():
    async with Server(echo(), max_connections=3, idle_timeout=5) as srv:
        held = [await srv.connect() for _ in range(3)]
        for reader, writer in held:            # the first three work
            writer.write(framed(b"x"))
            await writer.drain()
            assert await read_frame(reader) == b"x"
        reader, writer = await srv.connect()   # the fourth is refused
        assert await asyncio.wait_for(reader.read(1), 2.0) == b""
        assert srv.tracker.rejected == 1
        for _, w in held:
            w.close()


@pytest.mark.asyncio
async def test_a_closed_connection_frees_its_slot():
    async with Server(echo(), max_connections=1, idle_timeout=5) as srv:
        reader, writer = await srv.connect()
        writer.write(framed(b"first"))
        await writer.drain()
        assert await read_frame(reader) == b"first"
        writer.close()
        await writer.wait_closed()
        for _ in range(50):                    # let the server notice
            await asyncio.sleep(0)
        reader2, writer2 = await srv.connect()
        writer2.write(framed(b"second"))
        await writer2.drain()
        assert await read_frame(reader2) == b"second", "the slot was never released"
        writer2.close()


@pytest.mark.asyncio
async def test_one_client_cannot_take_every_slot():
    """The per-client cap is what stops a single peer from filling the server."""
    async with Server(echo(), max_connections=10, max_per_client=2,
                      idle_timeout=5) as srv:
        held = [await srv.connect() for _ in range(2)]
        reader, writer = await srv.connect()
        assert await asyncio.wait_for(reader.read(1), 2.0) == b""
        assert srv.tracker.rejected == 1
        assert srv.tracker.total == 2
        for _, w in held:
            w.close()


def test_the_tracker_does_not_leak_client_entries():
    t = ConnectionTracker(StreamLimits())
    for _ in range(3):
        assert t.admit("10.0.0.1")
    for _ in range(3):
        t.release("10.0.0.1")
    assert t.total == 0 and t.per_client == {}


# --- pipelining: answers come as they finish ---
@pytest.mark.asyncio
async def test_a_slow_query_does_not_block_the_ones_behind_it():
    """RFC 7766 §6.2.1.1. In arrival order, `fast` waits out `slow`."""
    delays = {b"slow": 0.3, b"fast": 0.0}
    async with Server(echo(delays), idle_timeout=5) as srv:
        reader, writer = await srv.connect()
        writer.write(framed(b"slow") + framed(b"fast"))
        await writer.drain()
        first = await read_frame(reader)
        assert first == b"fast", "answers were serialised behind the slow query"
        assert await read_frame(reader) == b"slow"
        writer.close()


@pytest.mark.asyncio
async def test_a_burst_of_pipelined_queries_is_answered_concurrently():
    n = 12
    delays = {f"q{i}".encode(): 0.1 for i in range(n)}
    async with Server(echo(delays), idle_timeout=5, max_inflight=n) as srv:
        reader, writer = await srv.connect()
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        for i in range(n):
            writer.write(framed(f"q{i}".encode()))
        await writer.drain()
        got = [await read_frame(reader) for _ in range(n)]
        elapsed = loop.time() - t0
        assert sorted(got) == sorted(f"q{i}".encode() for i in range(n))
        assert elapsed < n * 0.1 / 2, (
            f"{n} queries of 100ms took {elapsed*1000:.0f}ms — still serialised")
        writer.close()


@pytest.mark.asyncio
async def test_answers_are_never_interleaved_on_the_wire():
    """Out of order is fine; a half-written frame is not. Each response goes out
    as a single write, so nothing can land between a prefix and its body."""
    big = {f"q{i}".encode(): 0.0 for i in range(8)}
    payloads = {f"q{i}".encode(): bytes([65 + i]) * 4000 for i in range(8)}

    async def respond(data, client_ip):
        await asyncio.sleep(big[data])
        return [payloads[data]]

    async with Server(respond, idle_timeout=5, max_inflight=8) as srv:
        reader, writer = await srv.connect()
        for i in range(8):
            writer.write(framed(f"q{i}".encode()))
        await writer.drain()
        for _ in range(8):
            body = await read_frame(reader)
            assert len(set(body)) == 1 and len(body) == 4000, "frames interleaved"
        writer.close()


@pytest.mark.asyncio
async def test_a_multi_message_response_stays_together():
    """A zone transfer answers with several messages, which must arrive in order
    and consecutively — another query's answer must not land among them."""
    async def respond(data, client_ip):
        if data == b"axfr":
            await asyncio.sleep(0.05)
            return [b"axfr-1", b"axfr-2", b"axfr-3"]
        return [data]

    async with Server(respond, idle_timeout=5) as srv:
        reader, writer = await srv.connect()
        writer.write(framed(b"axfr") + framed(b"other"))
        await writer.drain()
        frames = [await read_frame(reader) for _ in range(4)]
        i = frames.index(b"axfr-1")
        assert frames[i:i + 3] == [b"axfr-1", b"axfr-2", b"axfr-3"]
        writer.close()


@pytest.mark.asyncio
async def test_reading_pauses_while_the_inflight_limit_is_reached():
    """Out-of-order answering without back-pressure is its own denial of service:
    one connection could queue unbounded work."""
    started = []
    release = asyncio.Event()

    async def respond(data, client_ip):
        started.append(data)
        await release.wait()
        return [data]

    async with Server(respond, idle_timeout=5, max_inflight=2) as srv:
        reader, writer = await srv.connect()
        for i in range(6):
            writer.write(framed(f"q{i}".encode()))
        await writer.drain()
        for _ in range(80):
            await asyncio.sleep(0)
        assert len(started) == 2, f"read ahead past the limit: {len(started)} started"
        release.set()
        got = [await read_frame(reader) for _ in range(6)]
        assert sorted(got) == sorted(f"q{i}".encode() for i in range(6))
        writer.close()


@pytest.mark.asyncio
async def test_a_stalled_connection_is_dropped_rather_than_held():
    """A client that stops reading never frees a slot. Waiting on it forever is
    the same leak the idle timeout exists to prevent."""
    release = asyncio.Event()

    async def respond(data, client_ip):
        await release.wait()
        return [data]

    async with Server(respond, idle_timeout=0.15, max_inflight=1) as srv:
        reader, writer = await srv.connect()
        writer.write(framed(b"a") + framed(b"b"))
        await writer.drain()
        assert await asyncio.wait_for(reader.read(1), 3.0) == b""
        assert srv.tracker.total == 0, "the stalled connection kept its slot"
        release.set()
        writer.close()


# --- a responder that fails must not take the connection with it ---
@pytest.mark.asyncio
async def test_a_failing_query_does_not_kill_the_connection():
    async def respond(data, client_ip):
        if data == b"boom":
            raise RuntimeError("handler blew up")
        return [data]

    async with Server(respond, idle_timeout=5) as srv:
        reader, writer = await srv.connect()
        writer.write(framed(b"boom"))
        await writer.drain()
        writer.write(framed(b"still-here"))
        await writer.drain()
        assert await read_frame(reader) == b"still-here"
        writer.close()


# --- UDP: work is bounded before the rate limiter can be reached ---
@pytest.mark.asyncio
async def test_udp_drops_datagrams_once_saturated():
    """Rate limiting lives inside the pipeline, so without a bound here a flood
    pays for a task and a parse before anything can refuse it."""
    from dnsguard.transport.do53 import _UDPProtocol

    release = asyncio.Event()
    handled = []

    class Slow:
        async def resolve(self, query, client_ip, proto="udp", client_id=""):
            handled.append(client_ip)
            await release.wait()
            return query.reply(0)

    proto = _UDPProtocol(Slow(), None, max_inflight=3)
    proto.transport = None            # nothing to send to; we only count work
    wire = (struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            + b"\x01a\x07example\x00" + struct.pack(">HH", 1, 1))
    for _ in range(10):
        proto.datagram_received(wire, ("10.0.0.1", 5353))
    for _ in range(50):
        await asyncio.sleep(0)
    assert len(handled) == 3, f"read past the bound: {len(handled)} in flight"
    assert proto.dropped == 7
    release.set()
    for _ in range(50):
        await asyncio.sleep(0)
    assert proto.inflight == 0, "in-flight count leaked"


@pytest.mark.asyncio
async def test_udp_inflight_is_released_even_when_a_query_fails():
    from dnsguard.transport.do53 import _UDPProtocol

    class Broken:
        async def resolve(self, *a, **k):
            raise RuntimeError("boom")

    proto = _UDPProtocol(Broken(), None, max_inflight=2)
    wire = (struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            + b"\x01a\x07example\x00" + struct.pack(">HH", 1, 1))
    for _ in range(6):
        proto.datagram_received(wire, ("10.0.0.1", 5353))
        for _ in range(10):
            await asyncio.sleep(0)
    assert proto.inflight == 0 and proto.dropped == 0, (
        "a failing query held its slot")


@pytest.mark.asyncio
async def test_a_zero_length_message_ends_the_connection():
    async with Server(echo(), idle_timeout=5) as srv:
        reader, writer = await srv.connect()
        writer.write(struct.pack(">H", 0))
        await writer.drain()
        assert await asyncio.wait_for(reader.read(1), 2.0) == b""
        writer.close()


# --- QUIC frontends carry the same caps -----------------------------------

def test_the_quic_frontends_admit_and_release_through_the_tracker():
    """DoQ and DoH3 were built without limits at all, so the number of
    established QUIC connections one worker held was whatever peers asked for —
    while the config described these caps as covering every connection-oriented
    frontend."""
    from aioquic.quic import events

    from dnsguard.transport.quiclimits import LimitedQuicProtocol
    from dnsguard.transport.stream import ConnectionTracker, StreamLimits

    class Fake(LimitedQuicProtocol):
        def __init__(self, tracker, peer):
            self.tracker = tracker
            self._admitted = None
            self._peer = peer
            self.closed = False

        def peer_ip(self):
            return self._peer

        def close(self):
            self.closed = True

        def transmit(self):
            pass

    tracker = ConnectionTracker(StreamLimits(max_connections=2, max_per_client=2))
    done = events.ConnectionTerminated(error_code=0, frame_type=None, reason_phrase="")
    hello = events.HandshakeCompleted(alpn_protocol="doq", early_data_accepted=False,
                                      session_resumed=False)

    a, b, c = (Fake(tracker, "10.0.0.1") for _ in range(3))
    assert a.note_quic_event(hello) is True
    assert b.note_quic_event(hello) is True
    assert tracker.total == 2

    # third is over the cap: refused, and told so rather than left hanging
    assert c.note_quic_event(hello) is False
    assert c.closed is True
    assert tracker.total == 2 and tracker.rejected == 1

    # a closed connection frees its slot
    a.note_quic_event(done)
    assert tracker.total == 1
    assert c.note_quic_event(hello) is True

    # releasing twice must not drive the count negative
    b.note_quic_event(done)
    b.note_quic_event(done)
    assert tracker.total == 1
