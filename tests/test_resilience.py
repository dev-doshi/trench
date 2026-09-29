"""Behaviour under upstream degradation, a partial write, and a bad restore.

Each test here is a reproduction of a defect found by a reliability audit:

  * a SERVFAIL or REFUSED from one upstream ended the resolution — the next
    upstream was never asked, and a retained stale answer was not served;
  * a DoQ upstream that never completed its handshake held a query for aioquic's
    60 s idle timeout rather than `upstream.timeout`;
  * a migration that failed partway left its first statements applied and
    nothing recorded, and a failed write batch was committed in part by the next
    unrelated write;
  * a restored cache file ignored `max_entries`, and a hand-edited TTL made every
    later lookup of that name raise.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import time

import pytest
from test_cache_freshness import _good, build, query
from test_forwarder_strategies import FakeUpstream, _forwarder, _query

from trench.cache import Cache
from trench.errors import UpstreamError
from trench.store import db as dbmod
from trench.transport.upstream import Upstream, parse_upstream
from trench.wire.rrtypes import Rcode


class FailingRcode(FakeUpstream):
    """Answers promptly, with a failure rcode."""

    def __init__(self, label, rcode=Rcode.SERVFAIL, **kw):
        super().__init__(label, **kw)
        self.rcode = rcode

    async def query(self, q):
        self.asked += 1
        return q.reply(self.rcode)


# --- a failure rcode fails over ---
@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", ["sequential", "fastest", "parallel"])
@pytest.mark.parametrize("rcode", [Rcode.SERVFAIL, Rcode.REFUSED])
async def test_a_failure_rcode_falls_through_to_the_next_upstream(strategy, rcode):
    bad = FailingRcode("bad", rcode)
    good = FakeUpstream("good", delay=0.01, rtt=1.0)   # slower, ranked second
    seen: list[str] = []
    resp = await _forwarder([bad, good], strategy).resolve(_query(), seen.append)
    assert resp.rcode == Rcode.NOERROR, f"{strategy} served the {rcode!r}"
    assert seen == ["good"]
    assert bad.failures == 1, "a refusing upstream kept its fastest ranking"


@pytest.mark.asyncio
async def test_every_upstream_failing_is_an_upstream_error():
    fwd = _forwarder([FailingRcode("a"), FailingRcode("b")], "sequential")
    with pytest.raises(UpstreamError):
        await fwd.resolve(_query())


@pytest.mark.asyncio
async def test_nxdomain_is_an_answer_not_a_failure():
    nx = FailingRcode("nx", Rcode.NXDOMAIN)
    other = FakeUpstream("other")
    resp = await _forwarder([nx, other], "sequential").resolve(_query())
    assert resp.rcode == Rcode.NXDOMAIN and other.asked == 0


# --- a SERVFAIL refresh falls back to stale ---
class ServfailResolver:
    """Stands in for a resolver that returns SERVFAIL rather than raising (the
    recursive resolver does)."""

    def __init__(self):
        self.servfail = False
        self.calls = 0

    async def resolve(self, q, note=None):
        self.calls += 1
        if self.servfail:
            return q.reply(Rcode.SERVFAIL)
        r = _good(ttl=1)
        r.id = q.id
        return r


@pytest.mark.asyncio
async def test_stale_is_served_when_the_refresh_is_a_servfail():
    up = ServfailResolver()
    p = build(up)
    await p.resolve(query(), "10.0.0.1")
    await asyncio.sleep(1.05)
    up.servfail = True
    resp = await p.resolve(query(), "10.0.0.1")
    assert resp.rcode == Rcode.NOERROR and resp.answers, "SERVFAIL beat the stale copy"
    assert up.calls == 2, "stale was served without attempting a refresh"


@pytest.mark.asyncio
async def test_a_servfail_with_nothing_retained_is_still_a_servfail():
    up = ServfailResolver()
    up.servfail = True
    resp = await build(up).resolve(query(), "10.0.0.1")
    assert resp.rcode == Rcode.SERVFAIL


# --- DoQ: the handshake is inside the timeout ---
@pytest.mark.asyncio
async def test_a_doq_handshake_that_never_completes_is_bounded(monkeypatch):
    import aioquic.asyncio as aq

    @contextlib.asynccontextmanager
    async def black_hole(*_a, **_k):
        await asyncio.sleep(3600)
        yield None

    monkeypatch.setattr(aq, "connect", black_hole)
    up = Upstream(parse_upstream("quic://192.0.2.1"), timeout=0.2)
    t0 = time.monotonic()
    with pytest.raises(TimeoutError):
        await up.query(_query())
    assert time.monotonic() - t0 < 2, "the DoQ handshake ignored upstream.timeout"


# --- SQLite: all or nothing ---
@pytest.mark.asyncio
async def test_a_failed_migration_leaves_nothing_behind(tmp_path, monkeypatch):
    path = tmp_path / "t.db"
    monkeypatch.setattr(dbmod, "MIGRATIONS", [
        (1, "it's broken", "CREATE TABLE a(x); SELECT nope FROM missing;")])
    d = dbmod.Database(path)
    with pytest.raises(Exception, match="missing"):
        await d.connect()
    names = {r[0] for r in await d.fetchall(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "a" not in names, "half a migration was applied"
    assert not await d.fetchall("SELECT * FROM _migrations")
    await d.close()

    # fixed and re-run: applies once, recorded with its description intact
    monkeypatch.setattr(dbmod, "MIGRATIONS", [
        (1, "it's fixed", "CREATE TABLE a(x);")])
    d = dbmod.Database(path)
    await d.connect()
    rows = await d.fetchall("SELECT version, descr FROM _migrations")
    assert [tuple(r) for r in rows] == [(1, "it's fixed")]
    await d.close()


@pytest.mark.asyncio
async def test_a_failed_batch_is_not_committed_by_the_next_write(tmp_path):
    d = dbmod.Database(tmp_path / "t.db")
    await d.connect()
    sql = "INSERT INTO querylog(ts, qname) VALUES (?, ?)"
    with pytest.raises(Exception, match="NOT NULL"):
        await d.executemany(sql, [(1, "a"), (None, "bad"), (3, "c")])
    assert not d.conn._conn.in_transaction, "the failed batch still holds the write lock"
    await d.executemany(sql, [(4, "d")])
    rows = await d.fetchall("SELECT qname FROM querylog")
    assert [r[0] for r in rows] == ["d"], "part of a failed batch was committed"
    await d.close()


# --- cache restore ---
def _dump(tmp_path, n):
    big = Cache(max_entries=n)
    for i in range(n):
        name = f"n{i}.example."
        big.put(big.key_for(query(name)), _good(name))
    path = tmp_path / "cache.json"
    big.dump(path)
    return path


def test_a_restore_respects_max_entries(tmp_path):
    path = _dump(tmp_path, 50)
    c = Cache(max_entries=10)
    assert c.load(path) == 10
    assert c.size == 10
    newest = Cache.key_for(query("n49.example."))
    assert c.get(newest) is not None, "kept the oldest entries, not the newest"


def test_a_bad_ttl_in_the_restore_file_is_skipped(tmp_path):
    path = _dump(tmp_path, 3)
    items = json.loads(path.read_text())
    items[0][2] = "300"
    items[1][2] = -5
    path.write_text(json.dumps(items))
    c = Cache()
    assert c.load(path) == 1
    for key in list(c._store):
        assert c.get(key) is not None


def test_the_dump_leaves_no_partial_file(tmp_path):
    path = _dump(tmp_path, 3)
    assert not (tmp_path / "cache.json.tmp").exists()
    assert len(json.loads(path.read_text())) == 3


# --- fastest: a failure is forgotten ---
@pytest.mark.asyncio
async def test_an_old_failure_no_longer_demotes_the_faster_upstream():
    from trench.resolver import forwarder as fwdmod

    now = asyncio.get_running_loop().time()
    quick = FakeUpstream("quick", failures=1, rtt=0.001)
    quick.failed_at = now - fwdmod._FAILURE_MEMORY - 1
    slow = FakeUpstream("slow", rtt=0.5)
    seen: list[str] = []
    await _forwarder([slow, quick], "fastest").resolve(_query(), seen.append)
    assert seen == ["quick"], "one old failure demoted the faster upstream for good"

    quick.failed_at = now
    seen.clear()
    await _forwarder([slow, quick], "fastest").resolve(_query(), seen.append)
    assert seen == ["slow"], "a recent failure did not demote"


# --- TCP / DoT: bounded, and a silent connection is dropped ---
async def _silent_server():
    """Accepts, reads, never answers."""
    held = []

    async def handle(reader, writer):
        held.append(writer)
        with contextlib.suppress(Exception):
            while await reader.read(4096):
                pass

    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1], held


@pytest.mark.asyncio
async def test_a_silent_stream_connection_is_closed_and_reopened():
    srv, port, held = await _silent_server()
    up = Upstream(parse_upstream(f"tcp://127.0.0.1:{port}"), timeout=0.2)
    try:
        with pytest.raises(TimeoutError):
            await up.query(_query())
        assert up._conn is not None and up._conn.closed, "silent connection kept"
        with pytest.raises(TimeoutError):
            await up.query(_query())
        await asyncio.sleep(0.05)
        assert len(held) == 2, "the second query did not reconnect"
    finally:
        await up.close()
        srv.close()


@pytest.mark.asyncio
async def test_the_truncation_fallback_has_one_budget():
    async def trickle(reader, writer):
        await reader.read(4096)
        # each step inside one timeout, the whole well past it
        for b in (b"\x00\x40", b"\x00"):       # length prefix, then part of the body
            await asyncio.sleep(0.15)
            writer.write(b)
            await writer.drain()
        await asyncio.sleep(3600)

    srv = await asyncio.start_server(trickle, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    up = Upstream(parse_upstream(f"127.0.0.1:{port}"), timeout=0.2)
    t0 = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            await up._tcp(_query().to_wire())
        assert time.monotonic() - t0 < 0.3, "each read got its own timeout"
    finally:
        srv.close()


# --- retention: chunked ---
@pytest.mark.asyncio
async def test_retention_prunes_a_backlog_in_chunks(tmp_path, monkeypatch):
    from trench.store import querylog as qlmod

    monkeypatch.setattr(qlmod, "_PRUNE_CHUNK", 7)
    d = dbmod.Database(tmp_path / "t.db")
    await d.connect()
    old = int((time.time() - 5 * 86400) * 1_000_000)
    now = int(time.time() * 1_000_000)
    await d.executemany("INSERT INTO querylog(ts, qname) VALUES (?, ?)",
                        [(old + i, "old") for i in range(30)] + [(now, "new")])
    statements: list[str] = []
    real = d.execute

    async def spy(sql, params=()):
        statements.append(sql)
        return await real(sql, params)

    monkeypatch.setattr(d, "execute", spy)
    ql = qlmod.QueryLog(d, retention_days=1)
    assert await ql.retention_sweep() == 30
    assert len(statements) == 5, "the backlog was not deleted in chunks"
    rows = await d.fetchall("SELECT qname FROM querylog")
    assert [r[0] for r in rows] == ["new"]
    assert not d.conn._conn.in_transaction
    await d.close()


# --- shared cache: a worker dying with a stripe lock held ---
def test_a_dead_lock_holder_does_not_freeze_the_shared_cache():
    import multiprocessing
    import os
    import signal

    from trench.cache.shared import SharedCache

    sc = SharedCache.create(slots=128, payload=64)
    k = 5
    sc.put(k, b"answer", 60)
    stripe = sc._slot(k)[1]

    ctx = multiprocessing.get_context("fork")
    ready = ctx.Event()

    def hold(lock, ev):
        lock.acquire()
        ev.set()
        time.sleep(3600)

    child = ctx.Process(target=hold, args=(sc.locks[stripe], ready))
    child.start()
    try:
        assert ready.wait(5)
        os.kill(child.pid, signal.SIGKILL)
        child.join(5)
        t0 = time.monotonic()
        assert sc.get(k) is None             # a miss, not a hang
        sc.put(k, b"other", 60)
        sc.delete(k)
        sc.clear()
        assert time.monotonic() - t0 < 1, "a dead holder stalled the cache"
        other = next(i for i in range(128) if sc._slot(i)[1] != stripe)
        sc.put(other, b"fine", 60)
        assert sc.get(other)[0] == b"fine", "healthy stripes stopped working"
    finally:
        if child.is_alive():
            child.kill()


def test_a_wedged_lock_is_skipped_at_no_cost_and_re_probed():
    import threading

    from trench import shmlock

    now = [0.0]
    lock = threading.Lock()
    guard = shmlock.BoundedLocks([lock], "test lock", clock=lambda: now[0])
    lock.acquire()                                    # the dead holder
    t0 = time.monotonic()
    with guard.hold(0) as held:
        assert not held
    first = time.monotonic() - t0
    t0 = time.monotonic()
    for _ in range(100):
        with guard.hold(0) as held:
            assert not held
    assert time.monotonic() - t0 < first, "every access waited out the timeout"

    lock.release()
    with guard.hold(0) as held:
        assert not held, "re-probed before the retry interval"
    now[0] += shmlock.RETRY
    with guard.hold(0) as held:
        assert held, "a freed lock was never taken again"
    assert not lock.locked()


def test_a_worker_dying_mid_push_does_not_freeze_the_primary():
    import multiprocessing
    import os
    import signal

    from trench.store.ringlog import RecordRing

    ring = RecordRing.create(lanes=3, slots=8, slot_bytes=128)
    primary, healthy = ring.for_lane(0), ring.for_lane(2)
    assert healthy.push([1, "ok"])

    ctx = multiprocessing.get_context("fork")
    ready = ctx.Event()

    def die_holding(lock, ev):
        lock.acquire()
        ev.set()
        time.sleep(3600)

    child = ctx.Process(target=die_holding, args=(ring.locks[1], ready))
    child.start()
    try:
        assert ready.wait(5)
        os.kill(child.pid, signal.SIGKILL)
        child.join(5)
        t0 = time.monotonic()
        assert primary.drain() == [[1, "ok"]], "the healthy lane was not drained"
        assert primary.dropped() == 0
        assert time.monotonic() - t0 < 1, "a dead worker froze the primary"
    finally:
        if child.is_alive():
            child.kill()
