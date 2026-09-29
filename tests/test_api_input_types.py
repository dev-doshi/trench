"""JSON bodies whose fields have the wrong type are a 400, never a 500.

JSON lets the sender pick every field's type. Handlers `.strip()`ed, bound into
SQLite or hashed whatever arrived, so a number or a list where a string belongs
— or a body that was an array rather than an object — escaped as an
AttributeError, a binding error or an unhashable-type error, and aiohttp turned
each into a 500.
"""
from __future__ import annotations

import aiohttp
import pytest
from support import free_port

from trench.api import APIServer
from trench.app import App
from trench.config import Config


async def _app_with_api(tmp_path):
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "web": {"enabled": True, "admin_password": "pw"}})
    app = App(cfg)
    await app.setup_storage()
    port = free_port()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    return app, port


BAD = [
    ("POST", "/auth/login", {"json": {"name": 1, "password": "pw"}}),
    ("POST", "/auth/login", {"data": "[1]", "headers": {"Content-Type": "application/json"}}),
    ("POST", "/rules", {"json": ["example.com"]}),
    ("POST", "/rules", {"json": {"domain": 5, "action": "deny"}}),
    ("POST", "/auth/tokens", {"json": {"name": 5}}),
    ("POST", "/auth/tokens", {"json": {"name": "ci", "scope": ["admin"]}}),
    ("PUT", "/settings", {"data": "not json"}),
    ("PUT", "/settings", {"json": [1]}),
    ("POST", "/clients/manage", {"json": {"ident": 5}}),
    ("POST", "/clients/manage", {"json": {"ident": "10.0.0.9", "name": ["x"]}}),
    ("POST", "/whatif", {"json": {"deny": "example.com"}}),
    ("POST", "/whatif", {"json": {"deny": [5]}}),
    ("POST", "/pause", {"json": {"seconds": 10, "client": ["10.0.0.9"]}}),
]


@pytest.mark.asyncio
async def test_wrongly_typed_bodies_are_refused_not_crashed_on(tmp_path):
    app, port = await _app_with_api(tmp_path)
    base = f"http://127.0.0.1:{port}/api/v1"
    try:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
            r = await s.post(f"{base}/auth/login", json={"name": "admin", "password": "pw"})
            assert r.status == 200
            for method, path, kw in BAD:
                r = await s.request(method, base + path, **kw)
                assert r.status in (400, 401), f"{method} {path} {kw}: {r.status}"
            # the list-typed client must not have become a pause key either
            assert not app.pipeline.pause_state()["clients"]
    finally:
        await app.api.stop(); await app.db.close()


@pytest.mark.asyncio
async def test_missing_ids_are_404(tmp_path):
    app, port = await _app_with_api(tmp_path)
    base = f"http://127.0.0.1:{port}/api/v1"
    try:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
            await s.post(f"{base}/auth/login", json={"name": "admin", "password": "pw"})
            assert (await s.delete(f"{base}/auth/tokens/abc")).status == 404
            assert (await s.delete(f"{base}/auth/tokens/²")).status == 404
            assert (await s.delete(f"{base}/clients/manage/999")).status == 404
    finally:
        await app.api.stop(); await app.db.close()


@pytest.mark.asyncio
async def test_client_update_cannot_null_the_ident_type_or_blank_the_ident(tmp_path):
    app, port = await _app_with_api(tmp_path)
    base = f"http://127.0.0.1:{port}/api/v1"
    try:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
            await s.post(f"{base}/auth/login", json={"name": "admin", "password": "pw"})
            await s.post(f"{base}/clients/manage", json={"ident": "10.0.0.5"})
            cid = (await (await s.get(f"{base}/clients/manage")).json())["clients"][0]["id"]
            for body in ({"ident_type": None}, {"ident": "  "}, {"name": 3}):
                r = await s.put(f"{base}/clients/manage/{cid}", json=body)
                assert r.status == 400, body
            row = (await (await s.get(f"{base}/clients/manage")).json())["clients"][0]
            assert row["ident"] == "10.0.0.5" and row["ident_type"] == "ip"
    finally:
        await app.api.stop(); await app.db.close()
