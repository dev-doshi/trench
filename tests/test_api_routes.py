"""Every REST route the console calls, end to end against a live server.

Roughly a third of `api/server.py` was reached by no test: the settings write
path (which rewrites the config file the resolver restarts from), the update
endpoints, the analysis reports, the clients/groups/services catalogue, and the
security headers that stop the console being framed. Each is exercised here for
its success shape, its refusal shape, and its permission gate.
"""
from __future__ import annotations

import asyncio
import json
import time

import aiohttp
import pytest
from support import api_app, needs_unprivileged, shutdown_api

from trench.api.server import _config_writable, _write_config


@pytest.fixture
async def api(tmp_path):
    app, base = await api_app(tmp_path)
    sess = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    await sess.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})

    class Api:
        pass

    Api.app, Api.base, Api.s = app, base, sess
    yield Api
    await sess.close()
    await shutdown_api(app)


async def _json(resp):
    return await resp.json()


# --- security headers ---
@pytest.mark.asyncio
async def test_every_response_carries_the_anti_framing_headers(api):
    """An admin visiting an attacker page could otherwise have the console
    framed and the filtering toggle clicked through an overlay."""
    async with api.s.get(f"{api.base}/healthz") as r:
        assert r.headers["X-Frame-Options"] == "DENY"
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["Referrer-Policy"] == "same-origin"
        csp = r.headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in csp
        # Bare ws:/wss: would permit a socket to any host, not just this origin.
        assert "connect-src 'self'" in csp and "ws:" not in csp


@pytest.mark.asyncio
@pytest.mark.parametrize("path,status", [("/api/v1/stats", 401),
                                         ("/api/v1/audit", 401)])
async def test_headers_are_present_on_an_error_response(api, path, status):
    """`_require` signals refusal by raising, which does not pass through the
    middleware's return path — so every 401/403/404 used to go out bare."""
    async with aiohttp.ClientSession() as anon, anon.get(f"{api.base}{path}") as r:
        assert r.status == status
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


# --- public endpoints ---
@pytest.mark.asyncio
async def test_healthz_readyz_metrics_and_openapi_are_public(api):
    async with aiohttp.ClientSession() as anon:
        async with anon.get(f"{api.base}/healthz") as r:
            assert r.status == 200 and (await r.json())["status"] == "ok"
        async with anon.get(f"{api.base}/readyz") as r:
            assert r.status == 200 and (await r.json())["ready"] is True
        async with anon.get(f"{api.base}/metrics") as r:
            assert r.status == 200
            assert r.content_type == "text/plain"
            assert "trench_" in await r.text()
        async with anon.get(f"{api.base}/api/v1/openapi.json") as r:
            doc = await r.json()
            assert doc["openapi"].startswith("3.")
            assert doc["info"]["title"] == "Trench API"


@pytest.mark.asyncio
async def test_readyz_reports_not_ready_without_a_filter(api):
    api.app.filter = None
    async with aiohttp.ClientSession() as anon, anon.get(f"{api.base}/readyz") as r:
        assert r.status == 503
        assert (await r.json())["ready"] is False


# --- session lifecycle ---
@pytest.mark.asyncio
async def test_me_reports_the_user_and_whether_totp_is_on(api):
    async with api.s.get(f"{api.base}/api/v1/auth/me") as r:
        body = await r.json()
    assert body["user"]["name"] == "admin"
    assert body["totp"] is False


@pytest.mark.asyncio
async def test_me_without_a_session_reports_no_user(api):
    async with aiohttp.ClientSession() as anon, anon.get(f"{api.base}/api/v1/auth/me") as r:
        assert (await r.json()) == {"user": None, "totp": False}


@pytest.mark.asyncio
async def test_logout_invalidates_the_session(api):
    async with api.s.post(f"{api.base}/api/v1/auth/logout") as r:
        assert r.status == 200
    async with api.s.get(f"{api.base}/api/v1/stats") as r:
        assert r.status == 401


@pytest.mark.asyncio
async def test_the_session_cookie_is_httponly_and_samesite_strict(api):
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s, \
            s.post(f"{api.base}/api/v1/auth/login",
                   json={"name": "admin", "password": "pw"}) as r:
        cookie = r.cookies["dgsession"]
    assert cookie["httponly"]
    assert cookie["samesite"].lower() == "strict"
    # Plaintext listener: Secure would make the cookie unusable.
    assert not cookie["secure"]


@pytest.mark.asyncio
async def test_a_login_body_that_is_not_json_is_rejected_not_crashed(api):
    async with aiohttp.ClientSession() as anon, \
            anon.post(f"{api.base}/api/v1/auth/login", data=b"not json") as r:
        assert r.status == 401


# --- stats / system / clients ---
@pytest.mark.asyncio
async def test_stats_payload_shape(api):
    async with api.s.get(f"{api.base}/api/v1/stats") as r:
        body = await r.json()
    for key in ("enabled", "blocklist_size", "cache_size", "cache_stats", "version"):
        assert key in body


@pytest.mark.asyncio
async def test_system_reports_version_uptime_and_upstream(api):
    async with api.s.get(f"{api.base}/api/v1/system") as r:
        body = await r.json()
    assert body["version"] and body["uptime"] >= 0
    assert body["upstream"] == api.app.config.upstream.servers
    assert body["mode"] == api.app.config.upstream.mode


@pytest.mark.asyncio
async def test_top_clients_reflect_the_counters(api):
    api.app.counters.record(client="10.0.0.7", qname="a.example.com", qtype="A",
                            action="forwarded")
    api.app.counters.record(client="10.0.0.7", qname="b.example.com", qtype="A",
                            action="blocked")
    async with api.s.get(f"{api.base}/api/v1/clients") as r:
        top = (await r.json())["top_clients"]
    assert top[0][0] == "10.0.0.7" and top[0][1] == 2


# --- rules ---
@pytest.mark.asyncio
async def test_rules_round_trip_and_persist(api):
    async with api.s.post(f"{api.base}/api/v1/rules",
                          json={"domain": "Bad.Example.COM", "action": "deny"}) as r:
        assert r.status == 200
    async with api.s.get(f"{api.base}/api/v1/rules") as r:
        body = await r.json()
    assert "bad.example.com" in body["deny"]           # normalised to lower case
    rows = await api.app.db.fetchall("SELECT raw, kind FROM custom_rule")
    assert [dict(r) for r in rows] == [{"raw": "bad.example.com", "kind": "block"}]

    async with api.s.post(f"{api.base}/api/v1/rules",
                          json={"domain": "bad.example.com", "action": "remove"}) as r:
        assert r.status == 200
    assert await api.app.db.fetchall("SELECT raw FROM custom_rule") == []


@pytest.mark.asyncio
async def test_an_allow_rule_is_recorded_as_allow(api):
    await api.s.post(f"{api.base}/api/v1/rules",
                     json={"domain": "ok.example.com", "action": "allow"})
    rows = await api.app.db.fetchall("SELECT kind FROM custom_rule")
    assert rows[0]["kind"] == "allow"
    async with api.s.get(f"{api.base}/api/v1/rules") as r:
        assert "ok.example.com" in (await r.json())["allow"]


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{}, {"domain": "x.com"}, {"action": "deny"},
                                  {"domain": "", "action": "deny"},
                                  {"domain": "x.com", "action": "nonsense"}])
async def test_a_malformed_rule_change_is_a_400(api, body):
    async with api.s.post(f"{api.base}/api/v1/rules", json=body) as r:
        assert r.status == 400


def _fill_cache(cache, *names):
    from trench.cache.cache import CacheKey
    from trench.wire import RR, Class, Message, Question, Type
    from trench.wire import rdata as R
    from trench.wire.name import Name
    from trench.wire.rrtypes import Rcode
    for name in names:
        n = Name.from_text(name)
        q = Message()
        q.questions.append(Question(n, Type.A, Class.IN))
        resp = q.reply(Rcode.NOERROR)
        resp.answers.append(RR(n, Type.A, Class.IN, 300, R.A("192.0.2.1")))
        cache.put(CacheKey(n.key, int(Type.A), int(Class.IN), False), resp)


@pytest.mark.asyncio
async def test_changing_a_rule_flushes_the_cache(api):
    _fill_cache(api.app.cache, "cached.example.com")
    assert api.app.cache.size == 1
    await api.s.post(f"{api.base}/api/v1/rules",
                     json={"domain": "new.example.com", "action": "deny"})
    assert api.app.cache.size == 0


# --- toggle / pause ---
@pytest.mark.asyncio
async def test_toggle_flips_and_reports(api):
    start = api.app.pipeline.enabled
    async with api.s.post(f"{api.base}/api/v1/toggle") as r:
        assert (await r.json())["enabled"] is (not start)
    async with api.s.post(f"{api.base}/api/v1/toggle") as r:
        assert (await r.json())["enabled"] is start


@pytest.mark.asyncio
async def test_pause_and_resume_globally(api):
    async with api.s.post(f"{api.base}/api/v1/pause", json={"seconds": 60}) as r:
        assert r.status == 200
        assert (await r.json())["paused_until"] > time.time()
    async with api.s.get(f"{api.base}/api/v1/pause") as r:
        assert (await r.json())["paused_until"] > time.time()
    async with api.s.post(f"{api.base}/api/v1/pause", json={"seconds": 0}) as r:
        assert (await r.json())["paused_until"] == 0
    rows = await api.app.db.fetchall(
        "SELECT action, target FROM audit WHERE action IN ('pause','resume') ORDER BY id")
    assert [r["action"] for r in rows] == ["pause", "resume"]
    assert rows[1]["target"] == "all"


@pytest.mark.asyncio
async def test_pause_for_one_client_only(api):
    """Unlike the toggle this expires by itself — the difference between letting
    one download through and leaving the network unfiltered until someone
    notices."""
    async with api.s.post(f"{api.base}/api/v1/pause",
                          json={"seconds": 60, "client": "10.0.0.5"}) as r:
        state = await r.json()
    assert state["paused_until"] == 0             # everyone else stays filtered
    assert "10.0.0.5" in state["clients"]
    async with api.s.post(f"{api.base}/api/v1/pause",
                          json={"seconds": 0, "client": "10.0.0.5"}) as r:
        assert (await r.json())["clients"] == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("seconds", [-1, 86_401])
async def test_pause_outside_the_allowed_window_is_refused(api, seconds):
    async with api.s.post(f"{api.base}/api/v1/pause", json={"seconds": seconds}) as r:
        assert r.status == 400
        assert "0..86400" in (await r.json())["error"]


@pytest.mark.asyncio
async def test_pause_with_a_non_numeric_duration_is_refused(api):
    async with api.s.post(f"{api.base}/api/v1/pause", json={"seconds": "soon"}) as r:
        assert r.status == 400
        assert "number" in (await r.json())["error"]


# --- explain / history ---
@pytest.mark.asyncio
async def test_explain_requires_a_name(api):
    async with api.s.get(f"{api.base}/api/v1/explain") as r:
        assert r.status == 400
        assert "name is required" in (await r.json())["error"]


@pytest.mark.asyncio
async def test_explain_reports_a_verdict(api):
    await api.s.post(f"{api.base}/api/v1/rules",
                     json={"domain": "ads.example.com", "action": "deny"})
    async with api.s.get(f"{api.base}/api/v1/explain?name=ads.example.com") as r:
        body = await r.json()
    assert body["findings"]
    assert any(f["verdict"] for f in body["findings"])


@pytest.mark.asyncio
async def test_history_requires_a_name(api):
    async with api.s.get(f"{api.base}/api/v1/history") as r:
        assert r.status == 400


@pytest.mark.asyncio
async def test_history_is_empty_without_a_query_log(api):
    api.app.querylog = None
    async with api.s.get(f"{api.base}/api/v1/history?name=example.com") as r:
        assert (await r.json()) == {"name": "example.com", "history": []}


@pytest.mark.asyncio
async def test_history_tolerates_a_non_numeric_days(tmp_path):
    app, base = await api_app(tmp_path, querylog={"enabled": True})
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
        async with s.get(f"{base}/api/v1/history?name=example.com&days=lots") as r:
            assert r.status == 200
            assert (await r.json())["name"] == "example.com"
    await shutdown_api(app)


# --- notary / silence, which are optional subsystems ---
@pytest.mark.asyncio
async def test_notary_reports_disabled_when_it_is_not_running(api):
    api.app.notary = None
    async with api.s.get(f"{api.base}/api/v1/notary") as r:
        assert (await r.json()) == {"enabled": False, "findings": []}


@pytest.mark.asyncio
async def test_notary_reports_its_findings(api):
    class FakeFinding:
        def to_json(self):
            return {"name": "bank.example.com", "why": "answers disagreed"}

    class FakeNotary:
        names = ["bank.example.com"]
        findings = [FakeFinding()]

    api.app.notary = FakeNotary()
    async with api.s.get(f"{api.base}/api/v1/notary") as r:
        body = await r.json()
    assert body["enabled"] is True
    assert body["names"] == ["bank.example.com"]
    assert body["findings"][0]["why"] == "answers disagreed"


@pytest.mark.asyncio
async def test_silence_reports_disabled_when_there_is_no_ledger(api):
    api.app.ledger = None
    async with api.s.get(f"{api.base}/api/v1/silence") as r:
        assert (await r.json()) == {"enabled": False, "devices": []}


@pytest.mark.asyncio
async def test_silence_filters_by_status(api):
    class FakeLedger:
        def report(self):
            return [{"client": "a", "status": "quiet"}, {"client": "b", "status": "gone"}]

    api.app.ledger = FakeLedger()
    async with api.s.get(f"{api.base}/api/v1/silence") as r:
        assert len((await r.json())["devices"]) == 2
    async with api.s.get(f"{api.base}/api/v1/silence?status=gone") as r:
        devices = (await r.json())["devices"]
    assert [d["client"] for d in devices] == ["b"]


# --- services / groups ---
@pytest.mark.asyncio
async def test_services_lists_the_catalogue_with_categories(api):
    async with api.s.get(f"{api.base}/api/v1/services") as r:
        rows = (await r.json())["services"]
    assert rows, "the shipped catalogue should not be empty"
    row = rows[0]
    assert set(row) == {"id", "category", "domains"}
    assert row["domains"] > 0


@pytest.mark.asyncio
async def test_services_is_empty_when_the_catalogue_is_not_loaded(api):
    api.app.services = None
    async with api.s.get(f"{api.base}/api/v1/services") as r:
        assert (await r.json())["services"] == []


@pytest.mark.asyncio
async def test_groups_are_derived_from_what_the_pipeline_runs(tmp_path):
    """The old shape was CRUD over a table no verdict consulted, so a group made
    in the console changed nothing."""
    app, base = await api_app(
        tmp_path,
        filtering={"groups": {"kids": {"sources": [], "inherit": True}}},
        clients=[{"ident": "10.0.0.9", "name": "tablet", "group": "kids"}])
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
        async with s.get(f"{base}/api/v1/groups") as r:
            groups = (await r.json())["groups"]
    await shutdown_api(app)
    assert len(groups) == 1
    g = groups[0]
    assert g["name"] == "kids" and g["inherit"] is True
    assert g["clients"] == ["tablet"]
    assert "compiled" in g and "rules" in g


@pytest.mark.asyncio
async def test_groups_is_empty_when_none_are_configured(api):
    async with api.s.get(f"{api.base}/api/v1/groups") as r:
        assert (await r.json())["groups"] == []


# --- analysis reports ---
@pytest.mark.asyncio
async def test_collateral_says_why_it_has_nothing_without_a_log(api):
    api.app.querylog = None
    async with api.s.get(f"{api.base}/api/v1/collateral") as r:
        body = await r.json()
    assert body["findings"] == [] and body["reason"] == "query log disabled"


@pytest.mark.asyncio
async def test_collateral_reports_over_a_live_log(tmp_path):
    app, base = await api_app(tmp_path, querylog={"enabled": True})
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
        async with s.get(f"{base}/api/v1/collateral?hours=6&limit=5") as r:
            body = await r.json()
    await shutdown_api(app)
    assert body["hours"] == 6 and isinstance(body["findings"], list)
    assert body["high"] == 0


@pytest.mark.asyncio
async def test_collateral_clamps_its_window_and_limit(tmp_path):
    app, base = await api_app(tmp_path, querylog={"enabled": True})
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
        async with s.get(f"{base}/api/v1/collateral?hours=99999&limit=99999") as r:
            body = await r.json()
    await shutdown_api(app)
    assert body["hours"] == 24 * 30


@pytest.mark.asyncio
async def test_lists_roi_without_a_query_log(api):
    api.app.querylog = None
    async with api.s.get(f"{api.base}/api/v1/lists") as r:
        body = await r.json()
    assert body["observed_hours"] == 0.0
    assert body["total_domains"] == api.app.filter.size
    for key in ("est_total_mb", "dead_weight_mb", "protective_mb"):
        assert isinstance(body[key], float)


@pytest.mark.asyncio
async def test_lists_roi_with_a_query_log(tmp_path):
    app, base = await api_app(tmp_path, querylog={"enabled": True})
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
        async with s.get(f"{base}/api/v1/lists?hours=3") as r:
            body = await r.json()
    await shutdown_api(app)
    assert body["hours"] == 3 and isinstance(body["lists"], list)


@pytest.mark.asyncio
async def test_list_reviews_returns_what_the_last_updates_changed(api):
    detail = {"added": 3, "removed": 1, "summary": "one list refreshed"}
    await api.app.db.execute(
        "INSERT INTO list_review(ts, domains_before, domains_after, high_risk, detail)"
        " VALUES(?,?,?,?,?)", (int(time.time()), 10, 12, 0, json.dumps(detail)))
    async with api.s.get(f"{api.base}/api/v1/list-reviews") as r:
        reviews = (await r.json())["reviews"]
    assert reviews[0]["added"] == 3 and "ts" in reviews[0]


@pytest.mark.asyncio
async def test_an_unreadable_review_row_is_skipped_not_fatal(api):
    now = int(time.time())
    await api.app.db.execute(
        "INSERT INTO list_review(ts, domains_before, domains_after, high_risk, detail)"
        " VALUES(?,?,?,?,?)", (now, 1, 1, 0, "{not json"))
    await api.app.db.execute(
        "INSERT INTO list_review(ts, domains_before, domains_after, high_risk, detail)"
        " VALUES(?,?,?,?,?)", (now + 1, 1, 2, 0, json.dumps({"added": 1})))
    async with api.s.get(f"{api.base}/api/v1/list-reviews") as r:
        reviews = (await r.json())["reviews"]
    assert len(reviews) == 1 and reviews[0]["added"] == 1


@pytest.mark.asyncio
async def test_list_reviews_clamps_its_limit(api):
    async with api.s.get(f"{api.base}/api/v1/list-reviews?limit=100000") as r:
        assert r.status == 200


@pytest.mark.asyncio
async def test_whatif_needs_a_query_log(api):
    # Put the database back afterwards: teardown closes it, and an unclosed
    # aiosqlite connection is a non-daemon thread that keeps pytest from exiting.
    db, api.app.db = api.app.db, None
    try:
        async with api.s.post(f"{api.base}/api/v1/whatif", json={"deny": ["x.com"]}) as r:
            assert r.status == 503
    finally:
        api.app.db = db


@pytest.mark.asyncio
async def test_whatif_dry_runs_a_proposed_rule(tmp_path):
    app, base = await api_app(tmp_path, querylog={"enabled": True})
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
        async with s.post(f"{base}/api/v1/whatif",
                          json={"deny": ["ads.example.com"], "hours": 1}) as r:
            assert r.status == 200
            body = await r.json()
    await shutdown_api(app)
    assert isinstance(body, dict)
    # Nothing was applied: the proposal must not have become policy.
    assert "ads.example.com" not in app.filter.custom_rules()[0]


# --- audit ---
@pytest.mark.asyncio
async def test_audit_lists_recorded_actions_for_admins(api):
    await api.s.post(f"{api.base}/api/v1/toggle")
    async with api.s.get(f"{api.base}/api/v1/audit") as r:
        rows = (await r.json())["audit"]
    assert any(row["action"] == "toggle" for row in rows)
    assert rows[0]["actor"] == "admin"


@pytest.mark.asyncio
async def test_an_audit_write_failure_does_not_fail_the_request(api, monkeypatch):
    async def boom(*a, **kw):
        raise RuntimeError("disk full")

    monkeypatch.setattr(api.app.db, "execute", boom)
    async with api.s.post(f"{api.base}/api/v1/toggle") as r:
        assert r.status == 200


# --- cache / gravity ---
@pytest.mark.asyncio
async def test_cache_flush_reports_how_many_entries_went(api):
    _fill_cache(api.app.cache, "a.example.com", "b.example.com")
    async with api.s.post(f"{api.base}/api/v1/cache/flush") as r:
        assert (await r.json())["flushed"] == 2


@pytest.mark.asyncio
async def test_gravity_refresh_is_accepted_and_scheduled(api, monkeypatch):
    called = asyncio.Event()

    async def fake_refresh():
        called.set()

    monkeypatch.setattr(api.app, "refresh_blocklists", fake_refresh)
    async with api.s.post(f"{api.base}/api/v1/gravity/refresh") as r:
        assert (await r.json()) == {"ok": True}
    await asyncio.wait_for(called.wait(), timeout=5)


# --- updates ---
@pytest.mark.asyncio
async def test_update_status_explains_that_checking_is_off(api):
    api.app.updater = None
    async with api.s.get(f"{api.base}/api/v1/update") as r:
        body = await r.json()
    assert body["update_available"] is False
    assert body["why_not"] == "update checking is off"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v1/update/check", "/api/v1/update/apply",
                                  "/api/v1/update/rollback"])
async def test_update_actions_are_409_when_checking_is_off(api, path):
    api.app.updater = None
    async with api.s.post(f"{api.base}{path}", json={}) as r:
        assert r.status == 409
        assert (await r.json())["error"] == "update checking is off"


class FakeUpdater:
    def __init__(self, *, fail=None):
        self.state = type("S", (), {"latest_version": "9.9.9"})()
        self.checked = False
        self.applied = None
        self.rolled_back = False
        self._fail = fail

    def status(self):
        return {"current_version": "1.0.0", "latest_version": "9.9.9",
                "update_available": True, "applied_version": "9.9.9",
                "previous_version": "1.0.0"}

    async def check(self):
        self.checked = True

    async def apply(self, version=None):
        from trench.ops.update import UpdateError
        if self._fail:
            raise UpdateError(self._fail)
        self.applied = version
        return self.status()

    async def rollback(self):
        from trench.ops.update import UpdateError
        if self._fail:
            raise UpdateError(self._fail)
        self.rolled_back = True
        return self.status()


@pytest.mark.asyncio
async def test_update_status_check_apply_and_rollback(api):
    up = FakeUpdater()
    api.app.updater = up
    async with api.s.get(f"{api.base}/api/v1/update") as r:
        assert (await r.json())["latest_version"] == "9.9.9"
    async with api.s.post(f"{api.base}/api/v1/update/check") as r:
        assert r.status == 200
    assert up.checked is True
    async with api.s.post(f"{api.base}/api/v1/update/apply",
                          json={"version": "9.9.9"}) as r:
        assert r.status == 200
    assert up.applied == "9.9.9"
    async with api.s.post(f"{api.base}/api/v1/update/rollback") as r:
        assert r.status == 200
    assert up.rolled_back is True


@pytest.mark.asyncio
async def test_apply_without_a_version_installs_the_newest(api):
    up = FakeUpdater()
    api.app.updater = up
    await api.s.post(f"{api.base}/api/v1/update/apply", json={})
    assert up.applied is None


@pytest.mark.asyncio
async def test_a_refused_install_comes_back_as_409_with_the_reason(api):
    api.app.updater = FakeUpdater(fail="this installation is managed by apt")
    async with api.s.post(f"{api.base}/api/v1/update/apply", json={}) as r:
        assert r.status == 409
        assert "managed by apt" in (await r.json())["error"]
    rows = await api.app.db.fetchall(
        "SELECT action FROM audit WHERE action='update.apply.failed'")
    assert rows, "a refused install should still be audited"


@pytest.mark.asyncio
async def test_a_refused_rollback_comes_back_as_409(api):
    api.app.updater = FakeUpdater(fail="nothing to roll back to")
    async with api.s.post(f"{api.base}/api/v1/update/rollback") as r:
        assert r.status == 409


# --- settings ---
@pytest.mark.asyncio
async def test_settings_get_describes_the_config_and_its_writability(api):
    async with api.s.get(f"{api.base}/api/v1/settings") as r:
        body = await r.json()
    assert body["config_path"] == ""
    assert body["writable"] is False
    assert "started without a config file" in body["why"]


@pytest.mark.asyncio
async def test_settings_put_is_refused_when_there_is_nowhere_to_save(api):
    async with api.s.put(f"{api.base}/api/v1/settings",
                         json={"changes": {"log.level": "debug"}}) as r:
        assert r.status == 400
        assert "nowhere to save" in await r.text()


@pytest.mark.asyncio
async def test_settings_put_rejects_an_empty_change_set(api):
    async with api.s.put(f"{api.base}/api/v1/settings", json={"changes": {}}) as r:
        assert r.status == 400
        assert "no changes" in await r.text()
    async with api.s.put(f"{api.base}/api/v1/settings", json={"changes": []}) as r:
        assert r.status == 400


async def _api_with_config(tmp_path, text="log:\n  level: info\n"):
    cfg_file = tmp_path / "trench.yaml"
    cfg_file.write_text(text)
    app, base = await api_app(tmp_path)
    app._config_path = str(cfg_file)
    s = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
    return app, base, s, cfg_file


@pytest.mark.asyncio
async def test_settings_put_writes_the_file_and_applies_it(tmp_path):
    import yaml
    app, base, s, cfg_file = await _api_with_config(tmp_path)
    try:
        async with s.put(f"{base}/api/v1/settings",
                         json={"changes": {"log.level": "debug"}}) as r:
            assert r.status == 200
            body = await r.json()
        assert body["ok"] is True and body["reloaded"] is True
        assert yaml.safe_load(cfg_file.read_text())["log"]["level"] == "debug"
        assert app.config.log.level == "debug"
        rows = await app.db.fetchall("SELECT target FROM audit WHERE action='settings.write'")
        assert rows[0]["target"] == "log.level"
    finally:
        await s.close()
        await shutdown_api(app)


@pytest.mark.asyncio
async def test_settings_put_preserves_keys_the_form_does_not_cover(tmp_path):
    import yaml
    app, base, s, cfg_file = await _api_with_config(
        tmp_path, "log:\n  level: info\nsome_future_key: keep-me\n")
    try:
        await s.put(f"{base}/api/v1/settings", json={"changes": {"log.level": "warning"}})
        tree = yaml.safe_load(cfg_file.read_text())
        assert tree["some_future_key"] == "keep-me"
    finally:
        await s.close()
        await shutdown_api(app)


@pytest.mark.asyncio
async def test_settings_put_rejects_an_unknown_setting(tmp_path):
    app, base, s, cfg_file = await _api_with_config(tmp_path)
    try:
        before = cfg_file.read_text()
        async with s.put(f"{base}/api/v1/settings",
                         json={"changes": {"log.colour": "purple"}}) as r:
            assert r.status == 400
            assert "unknown setting" in await r.text()
        assert cfg_file.read_text() == before
    finally:
        await s.close()
        await shutdown_api(app)


@pytest.mark.asyncio
async def test_settings_put_rejects_a_value_of_the_wrong_type(tmp_path):
    app, base, s, cfg_file = await _api_with_config(tmp_path)
    try:
        async with s.put(f"{base}/api/v1/settings",
                         json={"changes": {"server.do53.port": "not-a-port"}}) as r:
            assert r.status == 400
    finally:
        await s.close()
        await shutdown_api(app)


@pytest.mark.asyncio
async def test_settings_put_refuses_an_unreadable_config_file(tmp_path):
    app, base, s, cfg_file = await _api_with_config(tmp_path, "log:\n  level: info\n")
    try:
        cfg_file.write_text("this: [is not: valid yaml\n")
        async with s.put(f"{base}/api/v1/settings",
                         json={"changes": {"log.level": "debug"}}) as r:
            assert r.status == 400
            assert "could not be read" in await r.text()
    finally:
        await s.close()
        await shutdown_api(app)


@pytest.mark.asyncio
async def test_a_settings_change_that_cannot_be_applied_is_still_saved(tmp_path,
                                                                      monkeypatch):
    import yaml
    app, base, s, cfg_file = await _api_with_config(tmp_path)
    try:
        async def boom(keys):
            raise RuntimeError("applier exploded")

        monkeypatch.setattr(app, "apply_config", boom)
        async with s.put(f"{base}/api/v1/settings",
                         json={"changes": {"log.level": "error"}}) as r:
            body = await r.json()
        assert body["ok"] is True and body["reloaded"] is False
        assert yaml.safe_load(cfg_file.read_text())["log"]["level"] == "error"
    finally:
        await s.close()
        await shutdown_api(app)


@pytest.mark.asyncio
async def test_settings_put_reports_a_write_failure(tmp_path, monkeypatch):
    app, base, s, cfg_file = await _api_with_config(tmp_path)
    try:
        import trench.api.server as srv

        def boom(src, text):
            raise OSError("read-only filesystem")

        monkeypatch.setattr(srv, "_write_config", boom)
        async with s.put(f"{base}/api/v1/settings",
                         json={"changes": {"log.level": "debug"}}) as r:
            assert r.status == 400
            assert "could not be written" in await r.text()
    finally:
        await s.close()
        await shutdown_api(app)


# --- the config-writability probe, directly ---
def test_config_writable_without_a_path():
    ok, why = _config_writable(None)
    assert ok is False and "without a config file" in why
    assert _config_writable("")[0] is False


def test_config_writable_for_a_new_file_in_a_writable_dir(tmp_path):
    ok, why = _config_writable(tmp_path / "new.yaml")
    assert ok is True and why == ""


@needs_unprivileged
def test_config_writable_for_a_new_file_in_an_unwritable_dir(tmp_path):
    d = tmp_path / "locked"
    d.mkdir()
    d.chmod(0o500)
    try:
        ok, why = _config_writable(d / "new.yaml")
        assert ok is False and "not writable" in why
    finally:
        d.chmod(0o700)


@needs_unprivileged
def test_config_writable_for_a_read_only_file(tmp_path):
    """The shipped container bind-mounts this file `:ro`, so the honest answer
    on a default install is no."""
    p = tmp_path / "trench.yaml"
    p.write_text("log:\n  level: info\n")
    p.chmod(0o400)
    try:
        ok, why = _config_writable(p)
        assert ok is False and ":ro" in why
    finally:
        p.chmod(0o600)


def test_config_writable_for_a_writable_file(tmp_path):
    p = tmp_path / "trench.yaml"
    p.write_text("x: 1\n")
    assert _config_writable(p) == (True, "")


def test_write_config_replaces_atomically(tmp_path):
    p = tmp_path / "trench.yaml"
    p.write_text("old\n")
    _write_config(p, "new\n")
    assert p.read_text() == "new\n"
    assert not list(tmp_path.glob("*.tmp"))


def test_write_config_falls_back_to_an_in_place_write(tmp_path, monkeypatch):
    """A rename cannot cross a bind mount, and the container mounts this file
    individually — `os.replace` fails with EBUSY there."""
    from pathlib import Path
    p = tmp_path / "trench.yaml"
    p.write_text("old\n")
    real_replace = Path.replace

    def refuse(self, target):
        raise OSError("EBUSY")

    monkeypatch.setattr(Path, "replace", refuse)
    _write_config(p, "new\n")
    assert p.read_text() == "new\n"
    assert not list(tmp_path.glob("*.tmp")), "the temp file must be cleaned up"
    monkeypatch.setattr(Path, "replace", real_replace)


# --- the SPA fallback ---
@pytest.mark.asyncio
async def test_unknown_paths_fall_through_to_the_console(api):
    """The console is a single-page app: a deep link like /clients has to be
    answered with index.html, not a 404."""
    async with aiohttp.ClientSession() as anon:
        async with anon.get(f"{api.base}/clients") as r:
            assert r.status == 200
            assert r.content_type == "text/html"
            assert r.headers["X-Frame-Options"] == "DENY"
        async with anon.get(f"{api.base}/") as r:
            assert r.status == 200 and r.content_type == "text/html"


# --- role gates ---
async def _login_as(base, name, password):
    s = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    r = await s.post(f"{base}/api/v1/auth/login", json={"name": name, "password": password})
    assert r.status == 200
    r.close()
    return s


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,role", [
    ("GET", "/api/v1/stats", "viewer"),
    ("POST", "/api/v1/toggle", "editor"),
    ("POST", "/api/v1/cache/flush", "editor"),
    ("POST", "/api/v1/gravity/refresh", "editor"),
    ("POST", "/api/v1/querylog/purge", "editor"),
    ("PUT", "/api/v1/settings", "admin"),
    ("GET", "/api/v1/audit", "admin"),
    ("GET", "/api/v1/auth/tokens", "admin"),
    ("POST", "/api/v1/update/apply", "admin"),
])
async def test_every_route_is_gated_at_the_role_it_claims(api, method, path, role):
    """A viewer must not be able to disable network-wide filtering, and an
    editor must not be able to install code on the box."""
    from trench.api.auth import AuthManager
    auth = AuthManager(api.app.db)
    await auth.create_user("v", "pw", "viewer")
    await auth.create_user("e", "pw", "editor")

    allowed = {"viewer": ["v", "e", "admin"], "editor": ["e", "admin"],
               "admin": ["admin"]}[role]
    for who in ("v", "e"):
        s = await _login_as(api.base, who, "pw")
        try:
            async with s.request(method, f"{api.base}{path}", json={}) as r:
                if who in allowed:
                    assert r.status != 403, f"{who} should reach {path}"
                else:
                    assert r.status == 403, f"{who} must not reach {path}"
        finally:
            await s.close()


@pytest.mark.asyncio
async def test_a_forbidden_response_still_carries_the_security_headers(api):
    from trench.api.auth import AuthManager
    await AuthManager(api.app.db).create_user("v", "pw", "viewer")
    s = await _login_as(api.base, "v", "pw")
    try:
        async with s.get(f"{api.base}/api/v1/audit") as r:
            assert r.status == 403
            assert r.headers["X-Frame-Options"] == "DENY"
    finally:
        await s.close()


# --- managed clients ---
@pytest.mark.asyncio
async def test_a_client_can_be_created_listed_updated_and_deleted(api):
    async with api.s.post(f"{api.base}/api/v1/clients/manage",
                          json={"ident": "10.0.0.5", "ident_type": "ip",
                                "name": "laptop", "comment": "desk",
                                "policy": {"block": False}}) as r:
        assert r.status == 200
    async with api.s.get(f"{api.base}/api/v1/clients/manage") as r:
        rows = (await r.json())["clients"]
    assert len(rows) == 1 and rows[0]["name"] == "laptop"
    cid = rows[0]["id"]

    async with api.s.put(f"{api.base}/api/v1/clients/manage/{cid}",
                         json={"name": "renamed", "policy": {"block": True}}) as r:
        assert r.status == 200
    async with api.s.get(f"{api.base}/api/v1/clients/manage") as r:
        assert (await r.json())["clients"][0]["name"] == "renamed"

    async with api.s.delete(f"{api.base}/api/v1/clients/manage/{cid}") as r:
        assert r.status == 200
    async with api.s.get(f"{api.base}/api/v1/clients/manage") as r:
        assert (await r.json())["clients"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{}, {"ident": ""},
                                  {"ident": "10.0.0.5", "ident_type": "carrier-pigeon"}])
async def test_a_malformed_client_is_refused(api, body):
    async with api.s.post(f"{api.base}/api/v1/clients/manage", json=body) as r:
        assert r.status == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", [["a"], "a string", 5])
async def test_a_non_object_policy_is_refused_at_the_door(api, policy):
    """Stored, it raises inside `reload_clients`' one try/except — disabling
    every database-managed client at once."""
    async with api.s.post(f"{api.base}/api/v1/clients/manage",
                          json={"ident": "10.0.0.5", "policy": policy}) as r:
        assert r.status == 400
        assert "object" in (await r.json())["error"]
    assert await api.app.db.fetchall("SELECT id FROM client") == []


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", [None, {}, [], "", 0])
async def test_an_empty_policy_of_any_falsy_shape_means_no_policy(api, policy):
    """`policy: null` and `policy: {}` are the console's own "no overrides"."""
    async with api.s.post(f"{api.base}/api/v1/clients/manage",
                          json={"ident": "10.0.0.5", "policy": policy}) as r:
        assert r.status == 200
    rows = await api.app.db.fetchall("SELECT policy FROM client")
    assert rows[0]["policy"] == "{}"


@pytest.mark.asyncio
async def test_a_non_object_policy_is_refused_on_update(api):
    await api.s.post(f"{api.base}/api/v1/clients/manage",
                     json={"ident": "10.0.0.5", "policy": {}})
    rows = await api.app.db.fetchall("SELECT id FROM client")
    async with api.s.put(f"{api.base}/api/v1/clients/manage/{rows[0]['id']}",
                         json={"policy": ["nope"]}) as r:
        assert r.status == 400


@pytest.mark.asyncio
async def test_updating_a_client_that_does_not_exist_is_a_404(api):
    async with api.s.put(f"{api.base}/api/v1/clients/manage/999",
                         json={"name": "ghost"}) as r:
        assert r.status == 404


@pytest.mark.asyncio
async def test_an_invalid_ident_type_on_update_is_refused(api):
    await api.s.post(f"{api.base}/api/v1/clients/manage", json={"ident": "10.0.0.5"})
    rows = await api.app.db.fetchall("SELECT id FROM client")
    async with api.s.put(f"{api.base}/api/v1/clients/manage/{rows[0]['id']}",
                         json={"ident_type": "carrier-pigeon"}) as r:
        assert r.status == 400


@pytest.mark.asyncio
async def test_an_update_with_no_recognised_fields_touches_nothing(api):
    await api.s.post(f"{api.base}/api/v1/clients/manage",
                     json={"ident": "10.0.0.5", "name": "laptop"})
    rows = await api.app.db.fetchall("SELECT id FROM client")
    async with api.s.put(f"{api.base}/api/v1/clients/manage/{rows[0]['id']}",
                         json={"unrelated": 1}) as r:
        assert r.status == 200
    after = await api.app.db.fetchall("SELECT name FROM client")
    assert after[0]["name"] == "laptop"


@pytest.mark.asyncio
async def test_a_managed_client_reaches_the_running_registry(api):
    await api.s.post(f"{api.base}/api/v1/clients/manage",
                     json={"ident": "10.0.0.5", "name": "laptop",
                           "policy": {"block": False}})
    assert api.app.clients.identify("10.0.0.5").block is False


# --- the query log routes, with a log switched on ---
@pytest.fixture
async def logged(tmp_path):
    """An API server whose query log is on and already holds rows."""
    from trench.store.querylog import QueryRecord
    app, base = await api_app(tmp_path, querylog={"enabled": True})
    now = int(time.time() * 1_000_000)
    for i in range(6):
        app.querylog.enqueue(QueryRecord(
            ts=now - i * 1_000_000, client_ip=f"10.0.0.{i % 2}", client_id="",
            qname=f"host{i}.example.com", qtype="A", proto="udp",
            action="blocked" if i % 2 else "forwarded", reason="", rule="",
            source="", upstream="1.1.1.1:53", rcode="NOERROR",
            answers=["192.0.2.1"], elapsed_us=1000 + i))
    await app.querylog._flush()
    sess = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    await sess.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})

    class Api:
        pass

    Api.app, Api.base, Api.s, Api.now = app, base, sess, now
    yield Api
    await sess.close()
    await shutdown_api(app)


@pytest.mark.asyncio
async def test_the_query_log_lists_rows_with_a_total(logged):
    async with logged.s.get(f"{logged.base}/api/v1/querylog") as r:
        body = await r.json()
    assert body["total"] == 6 and len(body["rows"]) == 6


@pytest.mark.asyncio
async def test_the_query_log_filters_on_every_column(logged):
    for query, expect in [("qname=host1", 1), ("client=10.0.0.0", 3),
                          ("action=blocked", 3), ("rcode=NOERROR", 6),
                          ("upstream=1.1.1.1:53", 6)]:
        async with logged.s.get(f"{logged.base}/api/v1/querylog?{query}") as r:
            body = await r.json()
        assert body["total"] == expect, query


@pytest.mark.asyncio
async def test_the_query_log_windows_by_time(logged):
    since = logged.now - 2 * 1_000_000
    async with logged.s.get(f"{logged.base}/api/v1/querylog?since={since}") as r:
        assert (await r.json())["total"] == 3
    until = logged.now - 3 * 1_000_000
    async with logged.s.get(f"{logged.base}/api/v1/querylog?until={until}") as r:
        assert (await r.json())["total"] == 3


@pytest.mark.asyncio
async def test_the_query_log_pages_and_clamps_its_limit(logged):
    async with logged.s.get(f"{logged.base}/api/v1/querylog?limit=2&offset=2") as r:
        body = await r.json()
    assert len(body["rows"]) == 2 and body["total"] == 6
    async with logged.s.get(f"{logged.base}/api/v1/querylog?limit=100000") as r:
        assert r.status == 200


@pytest.mark.asyncio
async def test_the_facets_populate_the_filter_menus(logged):
    async with logged.s.get(f"{logged.base}/api/v1/querylog/facets") as r:
        facets = await r.json()
    assert {f["value"] for f in facets["clients"]} == {"10.0.0.0", "10.0.0.1"}
    assert {f["value"] for f in facets["actions"]} == {"blocked", "forwarded"}


@pytest.mark.asyncio
async def test_the_purge_empties_the_log(logged):
    async with logged.s.post(f"{logged.base}/api/v1/querylog/purge") as r:
        assert (await r.json())["purged"] == 6
    async with logged.s.get(f"{logged.base}/api/v1/querylog") as r:
        assert (await r.json())["total"] == 0


@pytest.mark.asyncio
async def test_the_export_streams_one_json_object_per_line(logged):
    async with logged.s.get(f"{logged.base}/api/v1/querylog/export") as r:
        assert r.status == 200
        assert r.content_type == "application/x-ndjson"
        assert "attachment" in r.headers["Content-Disposition"]
        body = await r.text()
    lines = [json.loads(x) for x in body.strip().splitlines()]
    assert len(lines) == 6
    assert {row["qname"] for row in lines} == {f"host{i}.example.com" for i in range(6)}


@pytest.mark.asyncio
async def test_the_export_is_empty_without_a_log(api):
    api.app.querylog = None
    async with api.s.get(f"{api.base}/api/v1/querylog/export") as r:
        assert r.status == 200 and (await r.text()) == ""


@pytest.mark.asyncio
async def test_the_query_log_routes_are_empty_without_a_log(api):
    api.app.querylog = None
    async with api.s.get(f"{api.base}/api/v1/querylog") as r:
        assert (await r.json()) == {"rows": [], "total": 0}
    async with api.s.get(f"{api.base}/api/v1/querylog/facets") as r:
        assert (await r.json())["clients"] == []
    async with api.s.post(f"{api.base}/api/v1/querylog/purge") as r:
        assert (await r.json()) == {"purged": 0}


# --- analytics ---
@pytest.mark.asyncio
async def test_analytics_is_refused_without_a_query_log(api):
    api.app.querylog = None
    async with api.s.get(f"{api.base}/api/v1/analytics") as r:
        assert r.status == 400
        assert (await r.json())["error"] == "query log disabled"


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["metric=median", "bucket=fortnight",
                                   "group=; DROP TABLE querylog"])
async def test_analytics_refuses_anything_outside_its_whitelists(logged, query):
    """User input never reaches the SQL beyond these fixed fragments."""
    async with logged.s.get(f"{logged.base}/api/v1/analytics?{query}") as r:
        assert r.status == 400
        assert "invalid bucket/group/metric" in (await r.json())["error"]


@pytest.mark.asyncio
async def test_analytics_totals_everything_by_default(logged):
    async with logged.s.get(f"{logged.base}/api/v1/analytics") as r:
        body = await r.json()
    assert body["rows"] == [["all", 6]]


@pytest.mark.asyncio
async def test_analytics_groups_without_bucketing(logged):
    async with logged.s.get(f"{logged.base}/api/v1/analytics?group=action") as r:
        rows = dict((await r.json())["rows"])
    assert rows == {"blocked": 3, "forwarded": 3}


@pytest.mark.asyncio
async def test_analytics_buckets_over_time(logged):
    async with logged.s.get(f"{logged.base}/api/v1/analytics?bucket=hour") as r:
        series = (await r.json())["series"]
    assert len(series) == 1 and series[0]["group"] == "all"
    assert sum(v for _, v in series[0]["points"]) == 6


@pytest.mark.asyncio
async def test_analytics_buckets_per_group(logged):
    async with logged.s.get(
            f"{logged.base}/api/v1/analytics?bucket=hour&group=action") as r:
        series = {s["group"]: s["points"] for s in (await r.json())["series"]}
    assert set(series) == {"blocked", "forwarded"}


@pytest.mark.asyncio
async def test_analytics_renders_a_day_hour_heatmap(logged):
    async with logged.s.get(f"{logged.base}/api/v1/analytics?bucket=dow_hour") as r:
        cells = (await r.json())["cells"]
    assert cells and all(len(c) == 3 for c in cells)
    assert sum(c[2] for c in cells) == 6


@pytest.mark.asyncio
@pytest.mark.parametrize("metric", ["count", "avg_latency", "max_latency"])
async def test_every_whitelisted_metric_computes(logged, metric):
    async with logged.s.get(f"{logged.base}/api/v1/analytics?metric={metric}") as r:
        assert r.status == 200
        assert (await r.json())["rows"][0][1] is not None


@pytest.mark.asyncio
async def test_analytics_filters_narrow_the_result(logged):
    async with logged.s.get(
            f"{logged.base}/api/v1/analytics?action=blocked&client=10.0.0.1"
            f"&qname=host&since={logged.now - 10_000_000}&until={logged.now}") as r:
        assert (await r.json())["rows"] == [["all", 3]]


@pytest.mark.asyncio
async def test_analytics_returns_empty_shapes_when_a_group_matches_nothing(logged):
    async with logged.s.get(
            f"{logged.base}/api/v1/analytics?group=action&action=nonexistent") as r:
        body = await r.json()
    assert body == {"series": [], "rows": [], "cells": []}


@pytest.mark.asyncio
async def test_analytics_clamps_the_number_of_groups(logged):
    async with logged.s.get(
            f"{logged.base}/api/v1/analytics?group=qname&top=10000") as r:
        assert r.status == 200
        assert len((await r.json())["rows"]) <= 12


# --- privacy ---
@pytest.mark.asyncio
async def test_privacy_describes_what_is_stored(logged):
    async with logged.s.get(f"{logged.base}/api/v1/privacy") as r:
        body = await r.json()
    assert body["enabled"] is True
    assert body["level"] == 0 and body["level_name"] == "Full logging"
    assert body["stored_count"] == 6
    assert body["survives_reboot"] is True
    assert len(body["levels"]) == 4


@pytest.mark.asyncio
async def test_privacy_reports_no_logging_when_the_log_is_off(api):
    api.app.querylog = None
    async with api.s.get(f"{api.base}/api/v1/privacy") as r:
        body = await r.json()
    assert body["enabled"] is False
    assert body["level"] == 3 and body["survives_reboot"] is False
    assert body["stored_count"] == 0


@pytest.mark.asyncio
async def test_privacy_describes_an_unknown_level_as_no_logging(logged):
    logged.app.querylog.privacy_level = 99
    async with logged.s.get(f"{logged.base}/api/v1/privacy") as r:
        body = await r.json()
    assert body["level_name"] == "No logging"


# --- token minting edge cases ---
@pytest.mark.asyncio
async def test_a_token_without_a_name_is_refused(api):
    async with api.s.post(f"{api.base}/api/v1/auth/tokens", json={"scope": "viewer"}) as r:
        assert r.status == 400
        assert (await r.json())["error"] == "name required"


@pytest.mark.asyncio
async def test_a_token_with_an_unknown_scope_is_refused(api):
    async with api.s.post(f"{api.base}/api/v1/auth/tokens",
                          json={"name": "t", "scope": "wizard"}) as r:
        assert r.status == 400
        assert "unknown scope" in (await r.json())["error"]


@pytest.mark.asyncio
async def test_a_token_can_be_given_an_expiry(api):
    async with api.s.post(f"{api.base}/api/v1/auth/tokens",
                          json={"name": "t", "scope": "viewer", "expires_days": 7}) as r:
        body = await r.json()
    assert body["expires"] > time.time()
    async with api.s.post(f"{api.base}/api/v1/auth/tokens",
                          json={"name": "forever", "scope": "viewer"}) as r:
        assert (await r.json())["expires"] == 0


@pytest.mark.asyncio
async def test_revoking_a_token_that_does_not_exist_is_a_404(api):
    async with api.s.delete(f"{api.base}/api/v1/auth/tokens/999") as r:
        assert r.status == 404


@pytest.mark.asyncio
async def test_disabling_totp_that_was_never_enabled_is_harmless(api):
    async with api.s.delete(f"{api.base}/api/v1/auth/totp") as r:
        assert r.status == 200
    async with api.s.get(f"{api.base}/api/v1/auth/me") as r:
        assert (await r.json())["totp"] is False


# --- shutdown ---
@pytest.mark.asyncio
async def test_stopping_the_server_closes_open_websockets(tmp_path):
    app, base = await api_app(tmp_path)
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
        ws = await s.ws_connect(f"{base}/api/v1/ws")
        await ws.receive()                       # the hello frame
        assert app.api._ws
        await shutdown_api(app)
        assert ws.closed or (await ws.receive()).type in (
            aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED,
            aiohttp.WSMsgType.CLOSING)


@pytest.mark.asyncio
async def test_a_plaintext_console_on_a_lan_address_warns(tmp_path, caplog):
    """The cookie and the password cross the network in the clear."""
    from support import free_port

    from trench.api import APIServer
    app, base = await api_app(tmp_path)
    try:
        app.api.host = "192.168.1.10"            # as if bound to the LAN
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
            await s.post(f"{base}/api/v1/auth/login",
                         json={"name": "admin", "password": "pw"})
        assert any("plaintext" in r.getMessage() for r in caplog.records)
        assert APIServer is not None and free_port is not None
    finally:
        await shutdown_api(app)
