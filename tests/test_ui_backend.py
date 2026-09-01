"""Backend for the live UI: time-series buckets, live event subscription,
query-log filters/facets/purge, privacy summary, and the multiplexed WS."""
from __future__ import annotations

import json
import socket
import time

import aiohttp
import pytest

from trench.stats import Counters


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


# --- counters: series + live listeners ---
def test_series_buckets_and_gapfill():
    c = Counters()
    for _ in range(3):
        c.record(client="1.1.1.1", qname="a.com", qtype="A", action="forwarded", elapsed_us=1000)
    c.record(client="1.1.1.1", qname="ad.com", qtype="A", action="blocked")
    s = c.series(5)
    assert len(s) == 5                       # gap-filled to exactly `minutes`
    assert s[-1]["total"] == 4 and s[-1]["blocked"] == 1 and s[-1]["forwarded"] == 3
    assert s[-1]["latency_ms"] == 1.0
    assert all(s[i]["t"] < s[i + 1]["t"] for i in range(len(s) - 1))   # ascending time


def test_series_pruned_when_a_new_minute_starts():
    """Pruning happens when a bucket is created, which is the only way the
    series can grow. It used to run on every query instead — meaning every
    query sorted the whole series once the process had been up three hours."""
    c = Counters()
    base = int(time.time()) // 60 * 60
    for i in range(Counters.SERIES_BUCKETS + 50):
        c._series[base - i * 60] = {"total": 1, "blocked": 0, "cached": 0,
                                    "forwarded": 1, "failed": 0, "lat_sum": 0, "lat_n": 0}
    # a query inside a minute that already has a bucket adds nothing to prune
    c._bucket("forwarded", 0, base + 1)
    assert len(c._series) == Counters.SERIES_BUCKETS + 50
    # the next minute creates one, and that is when the cap is applied
    c._bucket("forwarded", 0, base + 61)
    assert len(c._series) <= Counters.SERIES_BUCKETS
    assert base + 60 in c._series, "the newest bucket must survive its own prune"


def test_live_subscribe_receives_events():
    c = Counters()
    seen = []
    c.subscribe(seen.append)
    c.record(client="10.0.0.1", qname="live.com", qtype="A", action="forwarded")
    assert seen and seen[0]["domain"] == "live.com"
    c.unsubscribe(seen.append.__self__.append if False else seen.append)  # no-op safety


def test_listener_exception_does_not_break_record():
    c = Counters()
    c.subscribe(lambda ev: 1 / 0)            # hostile listener
    c.record(client="x", qname="ok.com", qtype="A", action="cached")
    assert c.total == 1                      # record still completed


def test_latency_percentiles():
    c = Counters()
    for us in range(1000, 101000, 1000):     # 1ms..100ms, uniform
        c.record(client="x", qname="a.com", qtype="A", action="forwarded", elapsed_us=us)
    snap = c.snapshot()
    assert snap["latency_p50_ms"] == pytest.approx(50, abs=2)
    assert snap["latency_p95_ms"] == pytest.approx(95, abs=2)
    assert snap["latency_p99_ms"] == pytest.approx(99, abs=2)
    assert snap["latency_p50_ms"] <= snap["latency_p95_ms"] <= snap["latency_p99_ms"]


def test_latency_percentiles_empty_and_single():
    c = Counters()
    assert c.snapshot()["latency_p99_ms"] == 0.0          # no samples -> 0, no crash
    c.record(client="x", qname="a.com", qtype="A", action="forwarded", elapsed_us=7000)
    snap = c.snapshot()
    assert snap["latency_p50_ms"] == snap["latency_p99_ms"] == 7.0


# --- query log: filters, count, facets, purge ---
@pytest.mark.asyncio
async def test_querylog_filters_count_facets_purge(tmp_path):
    from trench.store import Database
    from trench.store.querylog import QueryLog
    db = Database(tmp_path / "q.db")
    await db.connect()
    ql = QueryLog(db)
    try:
        now = int(time.time() * 1_000_000)
        recs = [
            ("a.com", "10.0.0.1", "forwarded", "NOERROR", "1.1.1.1"),
            ("ad.com", "10.0.0.2", "blocked", "NXDOMAIN", ""),
            ("b.com", "10.0.0.1", "cached", "NOERROR", ""),
        ]
        for qname, ip, action, rcode, up in recs:
            await db.execute(
                "INSERT INTO querylog(ts,client_ip,qname,qtype,action,rcode,upstream) "
                "VALUES(?,?,?,?,?,?,?)", (now, ip, qname, "A", action, rcode, up))
        assert await ql.search_count(action="blocked") == 1
        assert await ql.search_count(client="10.0.0.1") == 2
        assert await ql.search_count(rcode="NOERROR") == 2
        rows = await ql.search(client="10.0.0.1", limit=10)
        assert {r["qname"] for r in rows} == {"a.com", "b.com"}
        facets = await ql.facets()
        assert {f["value"] for f in facets["actions"]} == {"forwarded", "blocked", "cached"}
        assert any(f["value"] == "10.0.0.1" and f["count"] == 2 for f in facets["clients"])
        purged = await ql.purge()
        assert purged == 3 and await ql.count() == 0
    finally:
        await db.close()


# --- full API surface incl. websocket live stream ---
async def _api(tmp_path):
    from trench.api import APIServer
    from trench.app import App
    from trench.config import Config
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "querylog": {"enabled": True, "privacy_level": 0},
                                 "web": {"enabled": True, "admin_password": "pw"}})
    app = App(cfg)
    await app.setup_storage()
    port = _free_port()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    return app, port


@pytest.mark.asyncio
async def test_privacy_and_timeseries_endpoints(tmp_path):
    app, port = await _api(tmp_path)
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
            p = await (await s.get(f"{base}/api/v1/privacy")).json()
            assert p["level"] == 0 and p["survives_reboot"] and "Full" in p["level_name"]
            assert len(p["levels"]) == 4
            ts = await (await s.get(f"{base}/api/v1/timeseries?minutes=30")).json()
            assert len(ts["series"]) == 30
    finally:
        await app.api.stop(); await app.db.close()


@pytest.mark.asyncio
async def test_analytics_endpoint(tmp_path):
    app, port = await _api(tmp_path)
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    hour_us = 3_600 * 1_000_000
    now = int(time.time() * 1_000_000)
    try:
        # two clients, two actions, spread across two hours
        for qname, ip, action, lat, ts in [
            ("a.com", "10.0.0.1", "forwarded", 2000, now),
            ("a.com", "10.0.0.1", "forwarded", 4000, now),
            ("ad.com", "10.0.0.2", "blocked", 0, now),
            ("b.com", "10.0.0.2", "cached", 100, now - hour_us),
        ]:
            await app.db.execute(
                "INSERT INTO querylog(ts,client_ip,qname,qtype,action,rcode,elapsed_us) "
                "VALUES(?,?,?,?,?,?,?)", (ts, ip, qname, "A", action, "NOERROR", lat))
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
            u = f"{base}/api/v1/analytics"
            # plain group-by
            r = await (await s.get(f"{u}?group=action&bucket=none")).json()
            assert dict(map(tuple, r["rows"]))["forwarded"] == 2
            # bucketed by hour, grouped by client -> two clients, ascending buckets
            r = await (await s.get(f"{u}?bucket=hour&group=client_ip")).json()
            assert {x["group"] for x in r["series"]} == {"10.0.0.1", "10.0.0.2"}
            pts = [p for x in r["series"] for p in x["points"]]
            assert all(isinstance(p[0], int) and p[1] >= 1 for p in pts)
            # avg latency metric
            r = await (await s.get(f"{u}?bucket=none&metric=avg_latency&client=10.0.0.1")).json()
            assert r["rows"][0][1] == 3.0                      # (2ms+4ms)/2
            # since filter excludes the older row
            r = await (await s.get(f"{u}?group=action&bucket=none&since={now - hour_us // 2}")).json()
            assert "cached" not in dict(map(tuple, r["rows"]))
            # punchcard shape
            r = await (await s.get(f"{u}?bucket=dow_hour")).json()
            assert r["cells"] and all(len(c) == 3 for c in r["cells"])
            # invalid params rejected
            assert (await s.get(f"{u}?group=evil")).status == 400
            assert (await s.get(f"{u}?metric=drop_table")).status == 400
    finally:
        await app.api.stop(); await app.db.close()


@pytest.mark.asyncio
async def test_websocket_live_query_stream(tmp_path):
    app, port = await _api(tmp_path)
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
            async with s.ws_connect(f"{base}/api/v1/ws") as ws:
                hello = json.loads((await ws.receive()).data)
                assert hello["type"] == "hello" and "stats" in hello["data"]
                # a query happening now must arrive as a live 'query' frame
                app.counters.record(client="10.0.0.9", qname="stream.test", qtype="A",
                                    action="blocked", reason="gravity")
                got = None
                for _ in range(10):
                    frame = json.loads((await ws.receive()).data)
                    if frame["type"] == "query":
                        got = frame["data"]; break
                assert got is not None and got["domain"] == "stream.test"
                assert got["action"] == "blocked"
    finally:
        await app.api.stop(); await app.db.close()
