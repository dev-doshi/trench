"""State-changing requests and the live feed refuse other origins.

SameSite=Strict keeps a cross-site page from riding the session cookie, not a
same-site one: another service on the same domain could POST `text/plain` to
any mutating route, or open `/ws` and stream every client's queries.
"""
from __future__ import annotations

import aiohttp
import pytest
from support import free_port

from trench.api import APIServer
from trench.app import App
from trench.config import Config


@pytest.fixture
async def api(tmp_path):
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "web": {"enabled": True, "admin_password": "pw"}})
    app = App(cfg)
    await app.setup_storage()
    port = free_port()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    base = f"http://127.0.0.1:{port}"
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        async with s.post(f"{base}/api/v1/auth/login",
                          json={"name": "admin", "password": "pw"}) as r:
            assert r.status == 200
        yield s, base
    await app.api.stop()
    await app.db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("hdr", [
    {"Origin": "http://evil.lan"},
    {"Sec-Fetch-Site": "same-site"},
    {"Sec-Fetch-Site": "cross-site"},
    {"Origin": "null"},
])
async def test_a_foreign_origin_cannot_mutate(api, hdr):
    s, base = api
    async with s.post(f"{base}/api/v1/gravity/refresh", headers=hdr,
                      data="{}", ) as r:
        assert r.status == 403
        assert r.headers.get("X-Frame-Options")      # refusals carry headers too


@pytest.mark.asyncio
async def test_a_foreign_origin_cannot_open_the_live_feed(api):
    s, base = api
    with pytest.raises(aiohttp.WSServerHandshakeError) as e:
        await s.ws_connect(f"{base}/api/v1/ws", origin="http://evil.lan")
    assert e.value.status == 403


@pytest.mark.asyncio
async def test_the_console_own_origin_still_works(api):
    s, base = api
    hdr = {"Origin": base, "Sec-Fetch-Site": "same-origin"}
    async with s.post(f"{base}/api/v1/auth/logout", headers=hdr) as r:
        assert r.status != 403
    async with s.get(f"{base}/api/v1/settings", headers={"Origin": "http://evil.lan"}) as r:
        assert r.status != 403          # reads are not state changes
