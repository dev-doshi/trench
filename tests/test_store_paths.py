"""The storage layer's error and maintenance paths.

Every one of these exists because a failure here must not stop DNS: the private
mode on the database file, the flush loop that used to end query logging for the
life of the process on one bad tick, the shutdown drain that left a gap in the
log around every restart, and the purge whose VACUUM raised after the rows were
already gone.
"""
from __future__ import annotations

import asyncio
import json
import stat
import time

import pytest

from trench.store import Database, QueryLog
from trench.store.export import ExportDisabled, JsonLinesExport
from trench.store.querylog import _COLUMNS, QueryRecord


def mkrec(qname="example.com", client="10.0.0.5", action="forwarded", ts=None,
          answers=None):
    return QueryRecord(
        ts=ts if ts is not None else int(time.time() * 1_000_000),
        client_ip=client, client_id="", qname=qname, qtype="A", proto="udp",
        action=action, reason="", rule="", source="", upstream="1.1.1.1:53",
        rcode="NOERROR", answers=answers if answers is not None else [],
        elapsed_us=1200)


async def _db(tmp_path, name="t.db"):
    db = Database(tmp_path / name)
    await db.connect()
    return db


# --- the database file ---
@pytest.mark.asyncio
async def test_the_database_is_created_private(tmp_path):
    """It holds the session secrets and the query log."""
    db = await _db(tmp_path)
    try:
        assert stat.S_IMODE((tmp_path / "t.db").stat().st_mode) == 0o600
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_a_loose_existing_database_is_tightened(tmp_path):
    path = tmp_path / "loose.db"
    path.touch()
    path.chmod(0o644)
    db = Database(path)
    await db.connect()
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_a_database_that_cannot_be_tightened_still_starts(tmp_path, caplog,
                                                                monkeypatch):
    """Someone else owning the file must not stop the daemon."""
    path = tmp_path / "owned.db"
    path.touch()
    path.chmod(0o644)
    import os

    def refuse(p, mode):
        raise PermissionError("not yours")

    monkeypatch.setattr(os, "chmod", refuse)
    db = Database(path)
    await db.connect()
    try:
        assert any("could not tighten" in r.getMessage() for r in caplog.records)
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_the_connection_is_required_before_use(tmp_path):
    db = Database(tmp_path / "unopened.db")
    with pytest.raises(RuntimeError, match="not connected"):
        _ = db.conn


@pytest.mark.asyncio
async def test_a_secret_is_generated_once_and_persisted(tmp_path):
    db = await _db(tmp_path)
    try:
        first = await db.secret("querylog_salt")
        assert first and await db.secret("querylog_salt") == first
    finally:
        await db.close()
    again = await _db(tmp_path)
    try:
        assert await again.secret("querylog_salt") == first
    finally:
        await again.close()


@pytest.mark.asyncio
async def test_vacuum_runs_outside_the_shared_connection(tmp_path):
    """Issuing it on the shared connection raised `cannot VACUUM from within a
    transaction`."""
    db = await _db(tmp_path)
    try:
        await db.execute("INSERT INTO adlist(url, enabled) VALUES(?,1)",
                         ("https://example.invalid/list.txt",))
        await db.vacuum()
        rows = await db.fetchall("SELECT url FROM adlist")
        assert len(rows) == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_vacuum_succeeds_after_reads_and_writes(tmp_path):
    """Regression: an unfinalised cursor is a statement in progress, and the
    dedicated connection left one open with its own `busy_timeout` pragma — so
    every VACUUM Trench ever issued failed and was swallowed by the caller's
    best-effort `except`."""
    db = await _db(tmp_path)
    try:
        await db.execute("INSERT INTO adlist(url, enabled) VALUES(?,1)",
                         ("https://example.invalid/a.txt",))
        await db.fetchall("SELECT url FROM adlist")
        await db.fetchone("SELECT COUNT(*) AS n FROM adlist")
        await db.vacuum()          # must not raise
        await db.vacuum()          # and must still not raise the second time
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_a_purge_actually_reclaims_the_file(tmp_path):
    """A privacy purge that leaves every name legible in the file's free pages
    has not done the thing it exists to do."""
    db = await _db(tmp_path, "purge.db")
    path = tmp_path / "purge.db"
    ql = QueryLog(db)
    try:
        for i in range(20_000):
            ql.enqueue(mkrec(qname=f"host{i}.example.invalid"))
        while not ql._queue.empty():
            await ql._flush()
        await db.vacuum()                       # fold the WAL into the file
        before = path.stat().st_size
        assert b"host19999.example.invalid" in path.read_bytes()

        assert await ql.purge() == 20_000
        assert path.stat().st_size < before
        assert b"host19999.example.invalid" not in path.read_bytes()
    finally:
        await db.close()


# --- the query log writer ---
@pytest.mark.asyncio
async def test_a_bad_flush_does_not_end_query_logging(tmp_path, caplog):
    """One escaped exception used to end query logging for the life of the
    process, unretrieved and with nothing in the log to say so."""
    db = await _db(tmp_path)
    ql = QueryLog(db, batch_ms=10)
    calls = []
    real = ql._flush

    async def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("disk hiccup")
        await real()

    ql._flush = flaky
    await ql.start()
    try:
        ql.enqueue(mkrec())
        for _ in range(100):
            await asyncio.sleep(0.02)
            if len(calls) >= 3:
                break
        assert len(calls) >= 3, "the writer stopped after one failure"
        assert any("continuing" in r.getMessage() for r in caplog.records)
    finally:
        await ql.stop()
        await db.close()


@pytest.mark.asyncio
async def test_shutdown_drains_more_than_one_batch(tmp_path):
    """`_flush` writes at most `max_batch` records and the queue holds 50,000,
    so a single call silently dropped everything above the first batch."""
    db = await _db(tmp_path)
    ql = QueryLog(db, batch_ms=10_000)      # never ticks on its own
    ql.max_batch = 10
    await ql.start()
    for i in range(35):
        ql.enqueue(mkrec(qname=f"host{i}.example.com"))
    await ql.stop()
    try:
        row = await db.fetchone("SELECT COUNT(*) AS n FROM querylog")
        assert row["n"] == 35
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_a_queue_that_will_not_drain_stops_rather_than_spinning(tmp_path):
    db = await _db(tmp_path)
    ql = QueryLog(db, batch_ms=10_000)
    await ql.start()
    ql.enqueue(mkrec())

    async def never_drains():
        return None

    ql._flush = never_drains
    await asyncio.wait_for(ql.stop(), timeout=5)
    await db.close()


@pytest.mark.asyncio
async def test_a_full_queue_sheds_load_rather_than_blocking_dns(tmp_path):
    db = await _db(tmp_path)
    ql = QueryLog(db)
    ql._queue = asyncio.Queue(maxsize=2)
    for i in range(10):
        ql.enqueue(mkrec(qname=f"h{i}.example.com"))    # must not raise or block
    assert ql._queue.qsize() == 2
    await db.close()


@pytest.mark.asyncio
async def test_a_flush_failure_is_logged_not_raised(tmp_path, caplog):
    db = await _db(tmp_path)
    ql = QueryLog(db)
    ql.enqueue(mkrec())

    async def boom(sql, rows):
        raise RuntimeError("table is locked")

    db.executemany = boom
    await ql._flush()                       # must not raise
    assert any("querylog flush failed" in r.getMessage() for r in caplog.records)
    await db.close()


# --- reads that need a database ---
@pytest.mark.asyncio
async def test_a_workers_log_refuses_the_read_paths(tmp_path):
    """A sibling's log publishes into the shared ring; only the primary's has a
    database."""
    ql = QueryLog(None)
    with pytest.raises(RuntimeError, match="no database"):
        _ = ql.store


@pytest.mark.asyncio
async def test_facets_group_the_columns_a_filter_menu_offers(tmp_path):
    db = await _db(tmp_path)
    ql = QueryLog(db)
    for _ in range(3):
        ql.enqueue(mkrec(client="10.0.0.1", action="blocked"))
    ql.enqueue(mkrec(client="10.0.0.2", action="forwarded"))
    await ql._flush()
    try:
        facets = await ql.facets()
        clients = {f["value"]: f["count"] for f in facets["clients"]}
        assert clients == {"10.0.0.1": 3, "10.0.0.2": 1}
        assert {f["value"] for f in facets["actions"]} == {"blocked", "forwarded"}
        assert facets["upstreams"][0]["value"] == "1.1.1.1:53"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_purge_removes_everything_and_reports_the_count(tmp_path):
    db = await _db(tmp_path)
    ql = QueryLog(db)
    for i in range(4):
        ql.enqueue(mkrec(qname=f"h{i}.example.com"))
    await ql._flush()
    try:
        assert await ql.count() == 4
        assert await ql.purge() == 4
        assert await ql.count() == 0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_a_failed_vacuum_does_not_fail_the_purge(tmp_path, caplog):
    """It reliably raised *after* the rows were gone, so the operator saw a 500
    for a purge that had in fact succeeded."""
    db = await _db(tmp_path)
    ql = QueryLog(db)
    ql.enqueue(mkrec())
    await ql._flush()

    async def boom():
        raise RuntimeError("cannot VACUUM from within a transaction")

    db.vacuum = boom
    try:
        assert await ql.purge() == 1
        assert await ql.count() == 0
        assert any("reclaiming disk space failed" in r.getMessage()
                   for r in caplog.records)
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_the_ndjson_export_pages_through_the_table(tmp_path):
    db = await _db(tmp_path)
    ql = QueryLog(db)
    for i in range(7):
        ql.enqueue(mkrec(qname=f"h{i}.example.com"))
    await ql._flush()
    try:
        lines = [json.loads(line) async for line in ql.iter_ndjson(batch=2)]
        assert len(lines) == 7
        assert {row["qname"] for row in lines} == {f"h{i}.example.com" for i in range(7)}
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_the_ndjson_export_honours_its_limit(tmp_path):
    db = await _db(tmp_path)
    ql = QueryLog(db)
    for i in range(10):
        ql.enqueue(mkrec(qname=f"h{i}.example.com"))
    await ql._flush()
    try:
        lines = [line async for line in ql.iter_ndjson(batch=3, limit=5)]
        assert len(lines) == 5
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_the_ndjson_export_of_an_empty_table_yields_nothing(tmp_path):
    db = await _db(tmp_path)
    ql = QueryLog(db)
    try:
        assert [line async for line in ql.iter_ndjson()] == []
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_history_skips_rows_whose_answers_are_unreadable(tmp_path):
    db = await _db(tmp_path)
    ql = QueryLog(db)
    ql.enqueue(mkrec(qname="moved.example.com", answers=["192.0.2.1"]))
    await ql._flush()
    await db.execute("INSERT INTO querylog(ts, client_ip, client_id, qname, qtype,"
                     " proto, action, reason, rule, source, upstream, rcode,"
                     " answers, elapsed_us, dnssec)"
                     " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (int(time.time() * 1_000_000), "10.0.0.1", "",
                      "moved.example.com", "A", "udp", "forwarded", "", "", "",
                      "1.1.1.1:53", "NOERROR", "{not json", 1, ""))
    try:
        rows = await ql.history("moved.example.com")
        assert any(r["answers"] == ["192.0.2.1"] for r in rows)
        assert any(r["answers"] == [] for r in rows)
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_history_can_be_windowed(tmp_path):
    db = await _db(tmp_path)
    ql = QueryLog(db)
    now = int(time.time() * 1_000_000)
    ql.enqueue(mkrec(qname="x.example.com", answers=["192.0.2.1"],
                     ts=now - 10 * 86400 * 1_000_000))
    ql.enqueue(mkrec(qname="x.example.com", answers=["198.51.100.1"], ts=now))
    await ql._flush()
    try:
        recent = await ql.history("x.example.com", since=now - 86400 * 1_000_000)
        assert [r["answers"] for r in recent] == [["198.51.100.1"]]
    finally:
        await db.close()


# --- the JSON-lines export ---
def test_the_export_writes_to_stdout_when_asked(capsys):
    exp = JsonLinesExport("-", _COLUMNS)
    exp.write([tuple(getattr(mkrec(), c) if c != "answers" else "[]"
                     for c in _COLUMNS)])
    assert "example.com" in capsys.readouterr().out
    exp.close()             # closing stdout would be a very bad idea


def test_stdout_is_never_rotated(capsys):
    exp = JsonLinesExport("-", _COLUMNS, max_bytes=1)
    exp.write([tuple(getattr(mkrec(), c) if c != "answers" else "[]"
                     for c in _COLUMNS)])
    exp._rotate_if_needed()
    exp.write([tuple(getattr(mkrec(), c) if c != "answers" else "[]"
                     for c in _COLUMNS)])
    assert capsys.readouterr().out.count("\n") == 2


def test_writing_no_rows_opens_nothing(tmp_path):
    out = tmp_path / "deep" / "querylog.ndjson"
    exp = JsonLinesExport(str(out), _COLUMNS)
    exp.write([])
    assert not out.exists()


def test_the_parent_directory_is_created(tmp_path):
    out = tmp_path / "deep" / "nested" / "querylog.ndjson"
    exp = JsonLinesExport(str(out), _COLUMNS)
    exp.write([tuple(getattr(mkrec(), c) if c != "answers" else '["192.0.2.1"]'
                     for c in _COLUMNS)])
    exp.close()
    assert json.loads(out.read_text().strip())["answers"] == ["192.0.2.1"]


def test_an_unparseable_answers_column_is_left_as_written(tmp_path):
    out = tmp_path / "querylog.ndjson"
    exp = JsonLinesExport(str(out), _COLUMNS)
    exp.write([tuple(getattr(mkrec(), c) if c != "answers" else "{not json"
                     for c in _COLUMNS)])
    exp.close()
    assert json.loads(out.read_text().strip())["answers"] == "{not json"


def test_a_rotation_failure_is_survivable(tmp_path, caplog, monkeypatch):
    out = tmp_path / "querylog.ndjson"
    exp = JsonLinesExport(str(out), _COLUMNS, max_bytes=1)
    from pathlib import Path

    def refuse(self, target):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(Path, "replace", refuse)
    exp.write([tuple(getattr(mkrec(), c) if c != "answers" else "[]"
                     for c in _COLUMNS)])
    assert any("could not rotate" in r.getMessage() for r in caplog.records)
    assert exp._fh is None


def test_closing_an_export_that_never_opened_is_harmless(tmp_path):
    JsonLinesExport(str(tmp_path / "x.ndjson"), _COLUMNS).close()


def test_a_close_that_raises_is_swallowed(tmp_path):
    exp = JsonLinesExport(str(tmp_path / "x.ndjson"), _COLUMNS)
    exp.write([tuple(getattr(mkrec(), c) if c != "answers" else "[]"
                     for c in _COLUMNS)])

    class Stubborn:
        def close(self):
            raise OSError("already closed")

    exp._fh = Stubborn()
    exp.close()
    assert exp._fh is None


def test_a_write_failure_disables_the_export(tmp_path):
    """A full disk or a closed pipe must not stop the query log — still less
    DNS."""
    exp = JsonLinesExport(str(tmp_path / "x.ndjson"), _COLUMNS)

    class Broken:
        def write(self, data):
            raise OSError("no space left on device")

        def flush(self):
            pass

        def close(self):
            pass

    exp._fh = Broken()
    with pytest.raises(ExportDisabled):
        exp.write([tuple(getattr(mkrec(), c) if c != "answers" else "[]"
                         for c in _COLUMNS)])
    assert exp._fh is None
