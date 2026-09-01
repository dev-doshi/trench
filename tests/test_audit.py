"""The audit trail: who changed what, through the API."""
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
async def test_audit_written_on_rule_change(tmp_path):
    import aiohttp

    from dnsguard.api import APIServer
    from dnsguard.app import App
    from dnsguard.config import Config
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "web": {"enabled": True, "admin_password": "pw"}})
    app = App(cfg)
    await app.setup_storage()
    port = free_port()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
            await s.post(f"{base}/api/v1/rules", json={"action": "deny", "domain": "ads.test"})
            async with s.get(f"{base}/api/v1/audit") as r:
                data = await r.json()
                assert any(a["action"] == "rule.deny" and a["target"] == "ads.test"
                           for a in data["audit"])
    finally:
        await app.api.stop()
        await app.db.close()


@pytest.mark.asyncio
async def test_the_process_records_its_own_actions(tmp_path):
    """Both of these used to name a `user` column the table does not have, so
    every write raised and was swallowed by its own except."""
    from dnsguard.app import App
    from dnsguard.config import Config
    from dnsguard.filter import FilterEngine
    from dnsguard.filter.contract import check, parse_all
    from dnsguard.filter.parser import parse_line

    app = App(Config.load_dict({"data_dir": str(tmp_path)}))
    await app.setup_storage()
    try:
        engine = FilterEngine.compile([parse_line("||bank.example^", "list")])
        await app._record_contract_failure(
            check(engine, parse_all(["bank.example must resolve"])))
        await app._audit("notary", "bank.example", "upstreams disagree")
        rows = await app.db.fetchall(
            "SELECT actor, action, target, detail FROM audit ORDER BY id")
        actions = [r["action"] for r in rows]
        assert "blocklist refresh rejected" in actions
        assert "notary" in actions
        assert all(r["actor"] == "system" for r in rows)
        assert any("bank.example" in (r["detail"] or "") for r in rows)
    finally:
        await app.db.close()
