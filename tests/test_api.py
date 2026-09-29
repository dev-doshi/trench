"""API server: auth gate, login, rules CRUD, toggle, metrics, websocket."""
from __future__ import annotations

import asyncio
import socket

import aiohttp
import pytest

from trench.api import APIServer
from trench.app import App
from trench.config import Config


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def make_app(tmp_path):
    cfg = Config.model_validate({
        "data_dir": str(tmp_path),
        "server": {"do53": {"enabled": False}},
        "web": {"enabled": True, "admin_password": "secret123"},
    })
    app = App(cfg)
    await app.setup_storage()
    port = free_port()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    return app, port


@pytest.mark.asyncio
async def test_api_auth_and_rules(tmp_path):
    app, port = await make_app(tmp_path)
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            # public health
            async with s.get(f"{base}/healthz") as r:
                assert r.status == 200
            # protected without auth -> 401
            async with s.get(f"{base}/api/v1/stats") as r:
                assert r.status == 401
            # bad login
            async with s.post(f"{base}/api/v1/auth/login",
                              json={"name": "admin", "password": "nope"}) as r:
                assert r.status == 401
            # good login
            async with s.post(f"{base}/api/v1/auth/login",
                              json={"name": "admin", "password": "secret123"}) as r:
                assert r.status == 200
            # now stats works
            async with s.get(f"{base}/api/v1/stats") as r:
                assert r.status == 200
                data = await r.json()
                assert "total" in data and data["enabled"] is True
            # add a deny rule
            async with s.post(f"{base}/api/v1/rules",
                              json={"action": "deny", "domain": "doubleclick.net"}) as r:
                assert r.status == 200
            assert app.filter.match("doubleclick.net").blocked
            async with s.get(f"{base}/api/v1/rules") as r:
                rules = await r.json()
                assert "doubleclick.net" in rules["deny"]
            # toggle blocking off
            async with s.post(f"{base}/api/v1/toggle") as r:
                assert (await r.json())["enabled"] is False
            # metrics public
            async with s.get(f"{base}/metrics") as r:
                text = await r.text()
                assert "trench_queries_total" in text
    finally:
        await app.api.stop()
        await app.db.close()


@pytest.mark.asyncio
async def test_api_lockout(tmp_path):
    app, port = await make_app(tmp_path)
    base = f"http://127.0.0.1:{port}"
    try:
        async with aiohttp.ClientSession() as s:
            for _ in range(6):  # exceed LOCKOUT_THRESHOLD
                async with s.post(f"{base}/api/v1/auth/login",
                                  json={"name": "admin", "password": "x"}) as r:
                    assert r.status == 401
            # now locked: even the correct password is rejected during backoff
            async with s.post(f"{base}/api/v1/auth/login",
                              json={"name": "admin", "password": "secret123"}) as r:
                assert r.status == 401
    finally:
        await app.api.stop()
        await app.db.close()


@pytest.mark.asyncio
async def test_api_websocket(tmp_path):
    app, port = await make_app(tmp_path)
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            async with s.post(f"{base}/api/v1/auth/login",
                              json={"name": "admin", "password": "secret123"}) as r:
                assert r.status == 200
            async with s.ws_connect(f"{base}/api/v1/ws") as ws:
                msg = await ws.receive(timeout=3)
                import json
                payload = json.loads(msg.data)
                # first frame hydrates the client with a snapshot
                assert payload["type"] == "hello"
                assert "total" in payload["data"]["stats"]
    finally:
        await app.api.stop()
        await app.db.close()


@pytest.mark.asyncio
async def test_api_websocket_keeps_up_with_a_burst(tmp_path):
    """A burst that fits the per-socket queue arrives whole and promptly.

    The send loop used to poll `receive()` with a 1 ms timeout after every
    event, capping a socket at roughly 740 events/s; anything beyond that
    overflowed the queue and was dropped without trace. 1500 events fit the
    queue, so all 1500 must arrive, well inside the time the old loop needed."""
    import json
    app, port = await make_app(tmp_path)
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            await s.post(f"{base}/api/v1/auth/login",
                         json={"name": "admin", "password": "secret123"})
            async with s.ws_connect(f"{base}/api/v1/ws") as ws:
                assert json.loads((await ws.receive(timeout=3)).data)["type"] == "hello"
                for i in range(1500):
                    app.counters.record(client="10.0.0.2", qname=f"n{i}.example",
                                        qtype="A", action="allowed")
                got, dropped = 0, None
                loop = asyncio.get_running_loop()
                deadline = loop.time() + 1.2
                while got < 1500 and loop.time() < deadline:
                    frame = json.loads((await ws.receive(timeout=2)).data)
                    if frame["type"] == "query":
                        got += 1
                assert got == 1500
                while dropped is None:      # and the stats frame owns up to no gaps
                    frame = json.loads((await ws.receive(timeout=3)).data)
                    if frame["type"] == "stats":
                        dropped = frame["dropped"]
                assert dropped == 0
            # and a closed socket gives up its subscription on the resolve path
            for _ in range(40):
                if not app.counters._listeners:
                    break
                await asyncio.sleep(0.05)
            assert not app.counters._listeners
    finally:
        await app.api.stop()
        await app.db.close()

@pytest.mark.asyncio
async def test_api_websocket_requires_a_session(tmp_path):
    """The live feed carries client IPs and queried domains. It was the one
    data route with no role check, so any host on the LAN could open it and
    receive the recent-query ring plus every subsequent lookup."""
    app, port = await make_app(tmp_path)
    base = f"http://127.0.0.1:{port}"
    try:
        async with aiohttp.ClientSession() as s:
            with pytest.raises(aiohttp.WSServerHandshakeError) as excinfo:
                await s.ws_connect(f"{base}/api/v1/ws")
            assert excinfo.value.status == 401
    finally:
        await app.api.stop()
        await app.db.close()
