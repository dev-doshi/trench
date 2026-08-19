"""SQLite persistence: migrations, query log writer/search/retention/privacy."""
from __future__ import annotations

import time

import pytest

from dnsguard.store import Database, QueryLog
from dnsguard.store.querylog import ANON_CLIENT_DOMAIN, HIDE_CLIENT, NO_LOG, QueryRecord


def mkrec(qname="example.com", client="10.0.0.5", action="forwarded", ts=None):
    return QueryRecord(
        ts=ts if ts is not None else int(time.time() * 1_000_000),
        client_ip=client, client_id="", qname=qname, qtype="A", proto="udp",
        action=action, reason="", rule="", source="", upstream="1.1.1.1:53",
        rcode="NOERROR", answers="[]", elapsed_us=1200)


@pytest.mark.asyncio
async def test_migrations_idempotent(tmp_path):
    db = Database(tmp_path / "t.db")
    await db.connect()
    await db.apply_migrations()  # run twice, must not error
    rows = await db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    names = {r["name"] for r in rows}
    assert {"adlist", "querylog", "app_user", "ts_stat", "_migrations"} <= names
    ver = await db.fetchone("SELECT MAX(version) AS v FROM _migrations")
    assert ver["v"] >= 4
    await db.close()


@pytest.mark.asyncio
async def test_querylog_write_and_search(tmp_path):
    db = Database(tmp_path / "q.db")
    await db.connect()
    ql = QueryLog(db)
    for i in range(5):
        ql.enqueue(mkrec(qname=f"site{i}.com"))
    ql.enqueue(mkrec(qname="doubleclick.net", action="blocked"))
    await ql._flush()
    assert await ql.count() == 6
    blocked = await ql.search(action="blocked")
    assert len(blocked) == 1 and blocked[0]["qname"] == "doubleclick.net"
    one = await ql.search(qname="site3")
    assert len(one) == 1
    await db.close()


@pytest.mark.asyncio
async def test_querylog_privacy(tmp_path):
    db = Database(tmp_path / "p.db")
    await db.connect()
    # HIDE_CLIENT strips client ip
    ql = QueryLog(db, privacy_level=HIDE_CLIENT)
    ql.enqueue(mkrec(client="10.0.0.9"))
    await ql._flush()
    r = (await ql.search())[0]
    assert r["client_ip"] == ""
    # ANON also hides domain
    ql2 = QueryLog(db, privacy_level=ANON_CLIENT_DOMAIN)
    ql2.enqueue(mkrec(qname="secret.com"))
    await ql2._flush()
    assert (await ql2.search(action="forwarded"))[0]["qname"] in ("hidden", "secret.com")
    # NO_LOG drops everything
    ql3 = QueryLog(db, privacy_level=NO_LOG)
    before = await ql3.count()
    ql3.enqueue(mkrec())
    await ql3._flush()
    assert await ql3.count() == before
    await db.close()


@pytest.mark.asyncio
async def test_retention(tmp_path):
    db = Database(tmp_path / "r.db")
    await db.connect()
    ql = QueryLog(db, retention_days=1)
    old_ts = int((time.time() - 5 * 86400) * 1_000_000)
    ql.enqueue(mkrec(ts=old_ts))
    ql.enqueue(mkrec())  # fresh
    await ql._flush()
    assert await ql.count() == 2
    pruned = await ql.retention_sweep()
    assert pruned == 1
    assert await ql.count() == 1
    await db.close()


@pytest.mark.asyncio
async def test_gravity_persists_adlist(tmp_path):
    from dnsguard.gravity import Gravity
    db = Database(tmp_path / "g.db")
    await db.connect()
    listfile = tmp_path / "list.txt"
    listfile.write_text("||ads.example^\n0.0.0.0 tracker.test\n")
    g = Gravity([str(listfile)], db=db)
    engine = await g.build()
    assert engine.match("ads.example").blocked
    row = await db.fetchone("SELECT * FROM adlist WHERE url=?", (str(listfile),))
    assert row is not None and row["status"] == "ok" and row["rule_count"] == 2
    await db.close()
