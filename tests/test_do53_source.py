"""A wildcard UDP listener answers from the address the query was sent to."""
from __future__ import annotations

import asyncio
import socket
import sys

import pytest
from test_transports import build_pipeline, mkquery

from trench.transport.do53 import Do53Server
from trench.wire import Message


async def _serve(host):
    srv = Do53Server(build_pipeline(), host, 0, udp=True, tcp=False)
    await srv.start()
    return srv, srv._udp_transport.get_extra_info("socket").getsockname()[1]


async def _ask_connected(family, dst, port) -> Message:
    """Query like glibc's resolver: a connected socket, which the kernel lets
    receive only from the address it sent to."""
    loop = asyncio.get_running_loop()
    with socket.socket(family, socket.SOCK_DGRAM) as cs:
        cs.setblocking(False)
        await loop.sock_connect(cs, (dst, port))
        await loop.sock_sendall(cs, mkquery().to_wire())
        return Message.parse(await asyncio.wait_for(loop.sock_recv(cs, 2048), 2))


@pytest.mark.asyncio
async def test_a_wildcard_listener_answers():
    srv, port = await _serve("0.0.0.0")
    try:
        assert (await _ask_connected(socket.AF_INET, "127.0.0.1", port)).answers
    finally:
        await srv.stop()


@pytest.mark.skipif(sys.platform != "linux", reason="all of 127/8 is local only on Linux")
@pytest.mark.asyncio
async def test_the_answer_comes_from_the_address_that_was_asked():
    """Asked on 127.0.0.2, the kernel's own choice for the way back is
    127.0.0.1 — the same thing that sent a Docker container's answers from the
    bridge address when it had asked the host's LAN address."""
    srv, port = await _serve("0.0.0.0")
    try:
        assert (await _ask_connected(socket.AF_INET, "127.0.0.2", port)).answers
    finally:
        await srv.stop()


@pytest.mark.skipif(not socket.has_ipv6, reason="no IPv6")
@pytest.mark.asyncio
async def test_a_dual_stack_listener_answers_both_families():
    try:
        srv, port = await _serve("::")
    except OSError:
        pytest.skip("cannot bind ::")
    try:
        assert (await _ask_connected(socket.AF_INET6, "::1", port)).answers
        assert (await _ask_connected(socket.AF_INET, "127.0.0.1", port)).answers
    finally:
        await srv.stop()
