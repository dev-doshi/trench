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
from contextlib import asynccontextmanager
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
