"""The hourly rollups behind /analytics.

They exist only to make the answer cheap, so the property that matters is that
the answer does not change: every question is asked twice, once with the
rollups trusted and once with them ignored (read raw), and must come out equal.
"""
from __future__ import annotations

import random
import time

import pytest

from trench.store import querylog as qlmod
from trench.store.db import Database

HOUR = 3_600_000_000
NOW = int(time.time() * 1_000_000)

QUESTIONS = [
    {"bucket": "none", "group": None, "metric": "count"},
    {"bucket": "none", "group": None, "metric": "avg_latency"},
    {"bucket": "none", "group": None, "metric": "max_latency"},
    {"bucket": "hour", "group": "action", "metric": "count"},
    {"bucket": "hour", "group": None, "metric": "avg_latency"},
    {"bucket": "day", "group": "client_ip", "metric": "count"},
    {"bucket": "dow_hour", "group": None, "metric": "count"},
    {"bucket": "none", "group": "qtype", "metric": "count"},
    {"bucket": "none", "group": "upstream", "metric": "count"},
    {"bucket": "none", "group": "qname", "metric": "count"},
    {"bucket": "none", "group": "qname", "metric": "count", "action": "blocked"},
    {"bucket": "hour", "group": "client_ip", "metric": "count", "action": "forwarded"},
    {"bucket": "none", "group": "action", "metric": "count", "client": "10.0.0.2"},
]


def _rows(n: int, seed: int = 7) -> list[tuple]:
    rnd = random.Random(seed)
    return [(NOW - rnd.randrange(30 * HOUR), rnd.choice(["10.0.0.1", "10.0.0.2", "10.0.0.3"]),
             rnd.choice(["a.com", "b.com", "ads.com", "c.org"]), rnd.choice(["A", "AAAA", "HTTPS"]),
             rnd.choice(["forwarded", "cached", "blocked"]), rnd.choice(["", "tls://9.9.9.9"]),
             "NOERROR", rnd.randrange(50, 90_000)) for _ in range(n)]


async def _log(tmp_path, rows) -> tuple[Database, qlmod.QueryLog]:
    db = Database(tmp_path / "t.db")
    await db.connect()
    await db.executemany(
        "INSERT INTO querylog(ts, client_ip, qname, qtype, action, upstream, rcode, elapsed_us)"
        " VALUES (?,?,?,?,?,?,?,?)", rows)
    return db, qlmod.QueryLog(db)


async def _both(db, ql, q: dict, since: int, until: int):
    args = dict(since=since, until=until, top=12, **q)
    rolled = await ql.aggregate(**args)
    kept = await ql.rollup_from()
    await db.execute("UPDATE querylog_rollup SET complete_from = ?", (1 << 62,))
    raw = await ql.aggregate(**args)
    await db.execute("UPDATE querylog_rollup SET complete_from = ?", (kept,))
    return rolled, raw


@pytest.mark.asyncio
@pytest.mark.parametrize("q", QUESTIONS, ids=lambda q: "-".join(str(v) for v in q.values()))
async def test_the_rollups_give_the_same_answer_as_the_raw_log(tmp_path, q):
    db, ql = await _log(tmp_path, _rows(3000))
    try:
        # an unaligned window, so both edges are partial hours read raw
        rolled, raw = await _both(db, ql, q, NOW - 26 * HOUR - 123_456, NOW - 777)
        assert rolled == raw
        assert await ql.rollup_from() == 0, "a fresh log is whole from the start"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_the_window_edges_are_not_counted_twice(tmp_path):
    db, ql = await _log(tmp_path, _rows(2000))
    try:
        since, until = NOW - 20 * HOUR - 1, NOW - 3 * HOUR + 1
        got = await ql.aggregate(since=since, until=until, bucket="none", group=None,
                                 metric="count", top=8)
        n = (await db.fetchone("SELECT COUNT(*) FROM querylog WHERE ts >= ? AND ts <= ?",
                               (since, until)))[0]
        assert got["rows"] == [["all", n]]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_a_log_from_before_the_rollups_is_backfilled(tmp_path):
    db, ql = await _log(tmp_path, [])
    try:
        # rows the trigger never saw, as if logged before the migration
        await db.executescript("BEGIN; DROP TRIGGER querylog_rollup_ins; COMMIT;")
        await db.executemany(
            "INSERT INTO querylog(ts, client_ip, qname, qtype, action, upstream, rcode,"
            " elapsed_us) VALUES (?,?,?,?,?,?,?,?)", _rows(1500))
        await db.execute("UPDATE querylog_rollup SET complete_from = ?",
                         (NOW // HOUR * 3600 + 3600,))
        q = {"bucket": "hour", "group": "action", "metric": "count"}
        before = await ql.aggregate(since=NOW - 40 * HOUR, until=NOW, top=8, **q)
        assert (await db.fetchone("SELECT COUNT(*) FROM querylog_hour"))[0] == 0
        assert await ql.backfill_rollup(pause=0) > 0
        oldest = (await db.fetchone("SELECT MIN(ts) FROM querylog"))[0]
        assert await ql.rollup_from() == oldest // HOUR * 3600
        assert await ql.aggregate(since=NOW - 40 * HOUR, until=NOW, top=8, **q) == before
        total = (await db.fetchone("SELECT SUM(n) FROM querylog_hour"))[0]
        assert total == 1500
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_the_backfill_steps_over_empty_years(tmp_path):
    """A stray old row must cost one hour of work, not one per empty hour."""
    db, ql = await _log(tmp_path, [(1_000_000, "10.0.0.1", "old.com", "A", "cached", "",
                                    "NOERROR", 10)])
    try:
        await db.execute("DELETE FROM querylog_hour")
        await db.execute("DELETE FROM querylog_hour_name")
        await db.execute("UPDATE querylog_rollup SET complete_from = ?", (NOW // HOUR * 3600,))
        assert await ql.backfill_rollup(pause=0) == 1
        assert await ql.rollup_from() == 0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_retention_leaves_the_rollups_answering_what_is_left(tmp_path):
    db, ql = await _log(tmp_path, _rows(2000))
    try:
        ql.retention_days = 1                 # cuts the 30 hours of rows mid-hour
        assert await ql.retention_sweep() > 0
        await ql.backfill_rollup(pause=0)
        for q in QUESTIONS[:6]:
            rolled, raw = await _both(db, ql, q, 0, NOW)
            assert rolled == raw
        cutoff_hour = (NOW - 86400 * 1_000_000) // HOUR * 3600
        assert (await db.fetchone("SELECT MIN(hour) FROM querylog_hour"))[0] >= cutoff_hour
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_the_purge_takes_the_rollups_with_it(tmp_path):
    db, ql = await _log(tmp_path, _rows(200))
    try:
        await ql.purge()
        for table in ("querylog", "querylog_hour", "querylog_hour_name"):
            assert (await db.fetchone(f"SELECT COUNT(*) FROM {table}"))[0] == 0
        assert await ql.rollup_from() == 0
    finally:
        await db.close()
