"""Clients + groups CRUD API, with live registry rebuild on mutation."""
from __future__ import annotations

import socket

import aiohttp
import pytest

from dnsguard.api import APIServer
from dnsguard.app import App
from dnsguard.config import Config


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


async def _app_with_api(tmp_path):
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "web": {"enabled": True, "admin_password": "pw"}})
    app = App(cfg)
    await app.setup_storage()
    port = _free_port()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    return app, port


async def _login(s, base):
    await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})


@pytest.mark.asyncio
async def test_client_crud_lifecycle(tmp_path):
    app, port = await _app_with_api(tmp_path)
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            await _login(s, base)
            # create
            r = await s.post(f"{base}/api/v1/clients/manage",
                             json={"ident": "10.0.0.5", "ident_type": "ip", "name": "kid",
                                   "policy": {"safe_search": True, "block": True}})
            assert (await r.json())["ok"]
            # the live registry now applies the policy
            pol = app.clients.identify("10.0.0.5")
            assert pol.safe_search and pol.name == "kid"
            # list
            r = await s.get(f"{base}/api/v1/clients/manage")
            data = await r.json()
            assert len(data["clients"]) == 1
            cid = data["clients"][0]["id"]
            # update
            await s.put(f"{base}/api/v1/clients/manage/{cid}",
                        json={"policy": {"safe_search": False, "parental": True}})
            app.clients.invalidate()
            pol = app.clients.identify("10.0.0.5")
            assert pol.parental and not pol.safe_search
            # delete -> falls back to default policy
            await s.delete(f"{base}/api/v1/clients/manage/{cid}")
            app.clients.invalidate()
            assert app.clients.identify("10.0.0.5").name == "default"
    finally:
        await app.api.stop(); await app.db.close()


@pytest.mark.asyncio
async def test_client_create_validation(tmp_path):
    app, port = await _app_with_api(tmp_path)
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            await _login(s, base)
            r = await s.post(f"{base}/api/v1/clients/manage",
                             json={"ident": "", "ident_type": "bogus"})
            assert r.status == 400
    finally:
        await app.api.stop(); await app.db.close()


@pytest.mark.asyncio
async def test_group_crud(tmp_path):
    app, port = await _app_with_api(tmp_path)
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            await _login(s, base)
            groups = (await (await s.get(f"{base}/api/v1/groups")).json())["groups"]
            # Groups are declared in the config and enforced by the pipeline;
            # this endpoint reports what is in force, and creates nothing.
            assert groups == []
            assert (await s.post(f"{base}/api/v1/groups", json={"name": "kids"})).status == 405
    finally:
        await app.api.stop(); await app.db.close()


@pytest.mark.asyncio
async def test_managed_client_survives_reload(tmp_path):
    app, port = await _app_with_api(tmp_path)
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            await _login(s, base)
            await s.post(f"{base}/api/v1/clients/manage",
                         json={"ident": "10.0.0.9", "name": "persisted"})
        # a fresh registry load (as on SIGHUP) still sees the DB client
        await app.reload_clients()
        assert app.clients.identify("10.0.0.9").name == "persisted"
        # the FULL reload path (SIGHUP handler) must not drop DB clients either
        await app.reload()
        assert app.clients.identify("10.0.0.9").name == "persisted"
    finally:
        await app.api.stop(); await app.db.close()
