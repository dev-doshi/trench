"""SQLite persistence: migrations, query log writer/search/retention/privacy."""
from __future__ import annotations

import collections
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
    assert {"adlist", "querylog", "app_user", "list_review", "_migrations"} <= names
    # Migration 6 removes two tables that nothing ever read or wrote.
    assert not ({"ts_stat", "group"} & names)
    ver = await db.fetchone("SELECT MAX(version) AS v FROM _migrations")
    assert ver["v"] >= 6
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
    # ANON hashes the client and the domain, rather than blanking them: the
    # console and the settings help both promise "hashed", and a constant string
    # would keep the row's full write cost while carrying nothing at all.
    salt = b"\x11" * 32
    ql2 = QueryLog(db, privacy_level=ANON_CLIENT_DOMAIN, salt=salt)
    ql2.enqueue(mkrec(qname="secret.com", client="10.0.0.9", action="anon"))
    ql2.enqueue(mkrec(qname="secret.com", client="10.0.0.9", action="anon"))
    ql2.enqueue(mkrec(qname="other.com", client="10.0.0.9", action="anon"))
    await ql2._flush()
    rows = await ql2.search(action="anon")
    names = [r["qname"] for r in rows]
    assert "secret.com" not in names and "10.0.0.9" not in [r["client_ip"] for r in rows]
    # the same name still reads as the same name, so a count is still a count
    assert sorted(collections.Counter(names).values()) == [1, 2]
    assert all(len(n) == 32 for n in names)
    # nothing is left that points back at the name
    assert all(r["answers"] == "[]" for r in rows)
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


@pytest.mark.asyncio
async def test_history_groups_answer_sets_over_time(tmp_path):
    """Passive DNS for one household, out of the log that already holds it."""
    db = Database(tmp_path / "h.db")
    await db.connect()
    ql = QueryLog(db)
    base = int(time.time() * 1_000_000)
    for i, (answers, client) in enumerate([
            (["1.1.1.1"], "10.0.0.5"), (["1.1.1.1"], "10.0.0.6"),
            (["9.9.9.9"], "10.0.0.5")]):
        rec = mkrec(qname="bank.example", client=client, ts=base + i)
        rec.answers = answers
        ql.enqueue(rec)
    noise = mkrec(qname="other.example", ts=base + 9)
    noise.answers = ["8.8.8.8"]
    ql.enqueue(noise)
    await ql._flush()

    hist = await ql.history("bank.example")
    assert [h["answers"] for h in hist] == [["9.9.9.9"], ["1.1.1.1"]]   # newest first
    assert hist[1]["hits"] == 2 and hist[1]["clients"] == 2
    assert await ql.history("never-asked.example") == []
    await db.close()
