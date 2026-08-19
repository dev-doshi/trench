"""W1 batch: cache persistence, block page, audit log."""
from __future__ import annotations

import socket

import pytest

from dnsguard.cache import Cache
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _answer(name="example.com", ip="1.2.3.4", ttl=300):
    q = Message(id=1)
    q.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    resp = q.reply(Rcode.NOERROR)
    resp.answers.append(RR(q.question.name, Type.A, Class.IN, ttl, R.A(ip)))
    return q, resp


def test_cache_persistence_roundtrip(tmp_path):
    c = Cache()
    for i in range(5):
        q, resp = _answer(f"site{i}.com", f"10.0.0.{i}")
        c.put(c.key_for(q), resp)
    path = tmp_path / "cache.json"
    assert c.dump(path) == 5
    # fresh cache restores them
    c2 = Cache()
    assert c2.load(path) == 5
    q, _ = _answer("site3.com")
    hit = c2.get(c2.key_for(q))
    assert hit is not None and hit[0].answers[0].rdata.to_text() == "10.0.0.3"


def test_cache_load_missing_file(tmp_path):
    assert Cache().load(tmp_path / "nope.json") == 0


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
