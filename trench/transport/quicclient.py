"""A QUIC client connect that works on a host without IPv6.

aioquic's `connect` always opens an AF_INET6 socket and reaches IPv4 peers
through v4-mapped addresses. On a kernel booted with `ipv6.disable=1`, or in a
container given no IPv6 at all — both common for a small home resolver — that
socket cannot be created, and every DoQ upstream query failed with EAFNOSUPPORT
before a packet was sent, however reachable the upstream was over IPv4.

This is the same connect with one change: the socket's family is the family of
the address the upstream resolved to. Everything else — configuration, protocol
construction, the wait for the handshake and the close — follows aioquic's.
"""
from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from typing import TypeVar

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

#: Longest a close waits for the peer before the socket is simply dropped.
CLOSE_WAIT = 0.5

P = TypeVar("P", bound=QuicConnectionProtocol)


@asynccontextmanager
async def quic_connect(host: str, port: int, *, configuration: QuicConfiguration,
                       create_protocol: Callable[..., P]) -> AsyncIterator[P]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    family, _, _, _, addr = infos[0]
    if configuration.server_name is None:
        configuration.server_name = host
    connection = QuicConnection(configuration=configuration)

    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.bind(("::", 0, 0, 0) if family == socket.AF_INET6 else ("0.0.0.0", 0))
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: create_protocol(connection), sock=sock)
    except BaseException:
        sock.close()
        raise
    try:
        protocol.connect(addr, transmit=True)
        await protocol.wait_connected()
        yield protocol
    finally:
        protocol.close()
        # Bounded, unlike aioquic's: closing a connection whose peer never
        # answered waits out the draining period, and this runs inside the
        # caller's deadline — a `wait_for` that has already fired still waits
        # for the cleanup to finish.
        try:
            await asyncio.wait_for(protocol.wait_closed(), CLOSE_WAIT)
        except TimeoutError:
            pass
        transport.close()


class _DoQProtocol(QuicConnectionProtocol):
    """Pairs each DoQ stream with the query that opened it."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.pending: dict[int, tuple[bytearray, asyncio.Future]] = {}
        self.dead = False
        self.last_rx = 0.0      # loop time of the latest stream data received

    def quic_event_received(self, event) -> None:
        from aioquic.quic.events import (
            ConnectionTerminated,
            StreamDataReceived,
            StreamReset,
        )
        if isinstance(event, StreamDataReceived):
            self.last_rx = asyncio.get_running_loop().time()
            slot = self.pending.get(event.stream_id)
            if slot is None or slot[1].done():
                return
            buf, fut = slot
            buf += event.data
            # One length-prefixed message, never more: a peer streaming without
            # end is cut off at the largest a DNS message can be.
            if len(buf) > 2 + 65535:
                fut.set_exception(ConnectionError("DoQ response too long"))
            elif event.end_stream:
                fut.set_result(bytes(buf))
        elif isinstance(event, StreamReset):
            slot = self.pending.get(event.stream_id)
            if slot is not None and not slot[1].done():
                slot[1].set_exception(ConnectionError("DoQ stream reset by the upstream"))
        elif isinstance(event, ConnectionTerminated):
            self.dead = True
            for _, fut in self.pending.values():
                if not fut.done():
                    fut.set_exception(ConnectionError("DoQ connection closed"))


class DoQClient:
    """One QUIC connection to a DoQ upstream, with a fresh stream per query.

    RFC 9250 §5.5 expects a client to reuse its connection. Opening one per
    query paid a full TLS 1.3 handshake — two round trips — on every lookup.
    The connection is replaced when the peer closes it, or when a query is given
    up on and nothing at all arrived on the connection while it waited — so an
    upstream that went away costs one round of timed-out queries rather than
    every query until QUIC's own idle timeout notices.
    """

    def __init__(self, host: str, port: int, configuration: QuicConfiguration):
        self.host, self.port = host, port
        self.configuration = configuration
        self._proto: _DoQProtocol | None = None
        self._stack: AsyncExitStack | None = None
        self._lock = asyncio.Lock()

    async def _connection(self) -> _DoQProtocol:
        async with self._lock:
            if self._proto is None or self._proto.dead:
                await self.close()
                stack = AsyncExitStack()
                proto = await stack.enter_async_context(quic_connect(
                    self.host, self.port, configuration=self.configuration,
                    create_protocol=_DoQProtocol))
                self._stack, self._proto = stack, proto
            return self._proto

    async def query(self, wire: bytes) -> bytes:
        """Send one query; return the response without its length prefix.

        The caller bounds this with its own deadline.
        """
        proto = await self._connection()
        loop = asyncio.get_running_loop()
        sent_at = loop.time()
        sid = proto._quic.get_next_available_stream_id()
        fut: asyncio.Future = loop.create_future()
        proto.pending[sid] = (bytearray(), fut)
        try:
            proto._quic.send_stream_data(sid, len(wire).to_bytes(2, "big") + wire,
                                         end_stream=True)
            proto.transmit()
            data = await fut
        except BaseException:
            # Usually the caller's deadline. If the connection carried nothing
            # at all while this query waited, the peer is gone and the next
            # query starts a new one. Otherwise it is alive and shared: only
            # this query was slow, and tearing the connection down would fail
            # every other query in flight on it.
            if proto.last_rx < sent_at:
                proto.dead = True
            raise
        finally:
            proto.pending.pop(sid, None)
        n = int.from_bytes(data[:2], "big") if len(data) >= 2 else -1
        if n != len(data) - 2:
            raise ConnectionError("DoQ response length prefix does not match")
        return data[2:]

    async def close(self) -> None:
        stack, self._stack, self._proto = self._stack, None, None
        if stack is not None:
            await stack.aclose()
