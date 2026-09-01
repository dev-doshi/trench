"""The explainer page served on the sinkhole address."""
from __future__ import annotations

import socket

import pytest


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.mark.asyncio
async def test_block_page_serves():
    import aiohttp

    from dnsguard.web.blockpage import BlockPageServer
    port = free_port()
    srv = BlockPageServer("127.0.0.1", port)
    await srv.start()
    try:
        async with aiohttp.ClientSession() as s, s.get(f"http://127.0.0.1:{port}/anything") as r:
            assert r.status == 200
            body = await r.text()
            assert "blocked" in body.lower() and "DNSGuard" in body
    finally:
        await srv.stop()
