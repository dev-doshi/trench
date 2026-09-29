"""Secrets are not readable below admin.

`GET /api/v1/settings` needs only viewer, which is also the default scope of an
API token. It used to return every collection verbatim: TSIG secrets (enough to
sign zone updates) and the ids DoH/DoT clients present (enough to be that
client, with its policy). The same ids went into the query log in the clear.
"""
from __future__ import annotations

import aiohttp
import pytest
from support import free_port

from trench.api import APIServer
from trench.api import settings as st
from trench.app import App
from trench.clients.model import mask_client_id, mask_ident
from trench.config import Config
from trench.store.querylog import record_from_ctx

TSIG_SECRET = "c2VjcmV0c2VjcmV0c2VjcmV0"
TOKEN = "s3cr3t-doh-token-abcd"

_CFG = {
    "tsig_keys": [{"name": "upd.", "algorithm": "hmac-sha256.", "secret": TSIG_SECRET}],
    "clients": [{"ident": TOKEN, "type": "token", "name": "phone"},
                {"ident": "192.0.2.7", "type": "ip", "name": "tv"}],
}


def test_describe_redacts_unless_revealed():
    cfg = Config.model_validate(_CFG)
    hidden = str(st.describe(cfg)["collection_values"])
    assert TSIG_SECRET not in hidden and TOKEN not in hidden
    assert "192.0.2.7" in hidden                 # ordinary idents stay readable
    assert TOKEN[-4:] in hidden                  # enough to tell devices apart
    shown = str(st.describe(cfg, reveal=True)["collection_values"])
    assert TSIG_SECRET in shown and TOKEN in shown


def test_masking_rules():
    assert mask_ident("10.0.0.1", "ip") == "10.0.0.1"
    for kind in ("token", "clientid"):
        assert TOKEN not in mask_ident(TOKEN, kind)
    assert mask_client_id("") == ""
    assert "short" not in mask_client_id("short")   # too short to keep a tail


def test_query_log_never_records_the_client_id_in_full():
    class Ctx:
        client_ip, client_id, proto = "192.0.2.9", TOKEN, "https"
        action = reason = rule = source = upstream = ""

        def elapsed_us(self):
            return 0
    rec = record_from_ctx("example.com", "A", Ctx(), "NOERROR", [])
    assert TOKEN not in rec.client_id and rec.client_id.endswith(TOKEN[-4:])


@pytest.mark.asyncio
async def test_a_viewer_token_cannot_read_secrets_over_http(tmp_path):
    cfg = Config.model_validate({**_CFG, "data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "web": {"enabled": True, "admin_password": "pw"}})
    app = App(cfg)
    await app.setup_storage()
    port = free_port()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    base = f"http://127.0.0.1:{port}"
    try:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
            await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
            async with s.post(f"{base}/api/v1/auth/tokens",
                              json={"name": "ro", "scope": "viewer"}) as r:
                viewer = (await r.json())["token"]
            await s.post(f"{base}/api/v1/clients/manage",
                         json={"ident": TOKEN, "ident_type": "token", "name": "db-phone"})
            async with s.get(f"{base}/api/v1/settings") as r:
                assert TSIG_SECRET in await r.text()   # admin still sees them
        hdr = {"Authorization": f"Bearer {viewer}"}
        async with aiohttp.ClientSession(headers=hdr) as s:
            for path in ("/api/v1/settings", "/api/v1/clients/manage", "/api/v1/groups"):
                async with s.get(base + path) as r:
                    assert r.status == 200, path
                    body = await r.text()
                assert TSIG_SECRET not in body and TOKEN not in body, path
    finally:
        await app.api.stop()
        await app.db.close()
