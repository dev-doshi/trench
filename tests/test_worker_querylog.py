"""Every worker's queries reach the query log, not just the primary's.

Do53 runs in all workers and the kernel spreads a client's datagrams across
them, so the primary — the only process allowed to write SQLite — used to see
roughly `1/nworkers` of the traffic. The log, the breakage report, the
blocklist ROI figures and the what-if replay all read that share as if it were
the whole, and nothing anywhere said otherwise.
"""
from __future__ import annotations

import json

import pytest

from trench.store import Database, QueryLog
from trench.store.querylog import ANON_CLIENT_DOMAIN, QueryRecord
from trench.store.ringlog import RecordRing


def mkrec(qname="example.com", client="10.0.0.5", action="forwarded"):
    import time
    return QueryRecord(
        ts=int(time.time() * 1_000_000),
        client_ip=client, client_id="", qname=qname, qtype="A", proto="udp",
        action=action, reason="", rule="", source="", upstream="1.1.1.1:53",
        rcode="NOERROR", answers=["1.2.3.4"], elapsed_us=1200)


def test_a_row_survives_the_round_trip():
    ring = RecordRing.create(lanes=2)
    worker = ring.for_lane(1)
    assert worker.push(["a", 1, "[]"]) is True
    assert ring.for_lane(0).drain() == [["a", 1, "[]"]]


def test_a_full_lane_sheds_rather_than_blocks():
    ring = RecordRing.create(lanes=1, slots=4, slot_bytes=128)
    for i in range(4):
        assert ring.push([i]) is True
    assert ring.push([99]) is False          # full: dropped, not blocked
    assert ring.dropped() == 1
    # draining makes room again
    reader = RecordRing(ring.mm, ring.locks, 1, 4, 128, lane=0)
    assert len(reader._drain_lane(0, 10)) == 4
    assert ring.push([100]) is True


def test_an_oversize_row_keeps_the_row_and_drops_the_answers():
    ring = RecordRing.create(lanes=1, slots=4, slot_bytes=256)
    answers = json.dumps(["1.2.3.4"] * 200)
    assert len(answers) > 256
    assert ring.push(["big.example", answers]) is True
    got = RecordRing(ring.mm, ring.locks, 1, 4, 256, lane=0)._drain_lane(0, 10)
    assert got == [["big.example", "[]"]]    # the question survived; the context did not


@pytest.mark.asyncio
async def test_the_primary_writes_what_the_siblings_publish(tmp_path):
    db = Database(tmp_path / "q.db")
    await db.connect()
    ring = RecordRing.create(lanes=3)

    primary = QueryLog(db, ring=ring.for_lane(0), salt=b"s" * 32)
    workers = [QueryLog(ring=ring.for_lane(i), salt=b"s" * 32) for i in (1, 2)]

    primary.enqueue(mkrec(qname="from-primary.test"))
    workers[0].enqueue(mkrec(qname="from-worker-1.test"))
    workers[1].enqueue(mkrec(qname="from-worker-2.test"))
    workers[1].enqueue(mkrec(qname="also-worker-2.test"))

    for w in workers:
        await w._flush()          # each publishes into its own lane
    await primary._flush()        # the primary drains them, then writes

    names = sorted(r["qname"] for r in await db.fetchall(
        "SELECT qname FROM querylog ORDER BY qname"))
    assert names == ["also-worker-2.test", "from-primary.test",
                     "from-worker-1.test", "from-worker-2.test"]
    await db.close()


@pytest.mark.asyncio
async def test_a_worker_log_never_touches_the_database():
    """It has none to touch — which is the point, and why `stop()` and the
    retention sweep must not assume one."""
    ring = RecordRing.create(lanes=2)
    worker = QueryLog(ring=ring.for_lane(1), salt=b"s" * 32)
    await worker.start()
    assert worker.db is None
    # Retention belongs to whoever owns the table, and is armed by
    # `App._adopt_querylog` rather than by the log itself.
    assert not hasattr(worker, "_sweeper_task")
    worker.enqueue(mkrec(qname="w.test"))
    await worker.stop()                       # must drain, not raise on a missing db
    rows = ring.for_lane(0).drain()
    assert any("w.test" in json.dumps(r) for r in rows)


@pytest.mark.asyncio
async def test_privacy_is_applied_before_anything_crosses_the_boundary(tmp_path):
    """Redaction happens in `enqueue`, so a name the operator asked not to keep
    is never written into memory another process can read."""
    salt = b"p" * 32
    ring = RecordRing.create(lanes=2)
    worker = QueryLog(ring=ring.for_lane(1), privacy_level=ANON_CLIENT_DOMAIN,
                      salt=salt)
    worker.enqueue(mkrec(qname="secret.test", client="10.0.0.9"))
    await worker._flush()

    published = json.dumps(ring.for_lane(0).drain())
    assert "secret.test" not in published and "10.0.0.9" not in published

    # and the primary, hashing with the same salt, agrees on what it is
    from trench.security.hashutil import hash_identifier
    assert hash_identifier("secret.test", salt) in published
