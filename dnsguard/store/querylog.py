"""Query log: a non-blocking batched writer plus search / export / retention.

The pipeline calls `enqueue()` (cheap, never awaits). A background task drains
the queue in batches and writes to SQLite. Privacy levels strip fields before
they ever hit disk.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass

from ..log import get
from .db import Database

log = get("querylog")

# privacy levels (PiHole-compatible semantics)
SHOW_ALL = 0
HIDE_CLIENT = 1
ANON_CLIENT_DOMAIN = 2
NO_LOG = 3


@dataclass
class QueryRecord:
    ts: int
    client_ip: str
    client_id: str
    qname: str
    qtype: str
    proto: str
    action: str
    reason: str
    rule: str
    source: str
    upstream: str
    rcode: str
    # The answer list, not its JSON. Encoding it here would put a json.dumps
    # (0.855 us measured) on the query's own latency path for a string only the
    # writer ever reads; `_flush` encodes it in batches instead.
    answers: list
    elapsed_us: int
    dnssec: str = ""


_COLUMNS = ("ts", "client_ip", "client_id", "qname", "qtype", "proto", "action",
            "reason", "rule", "source", "upstream", "rcode", "answers",
            "elapsed_us", "dnssec")
_INSERT = (f"INSERT INTO querylog ({','.join(_COLUMNS)}) "
           f"VALUES ({','.join('?' for _ in _COLUMNS)})")


class QueryLog:
    def __init__(self, db: Database, *, retention_days: int = 90,
                 privacy_level: int = SHOW_ALL, batch_ms: int = 250,
                 max_batch: int = 500):
        self.db = db
        self.retention_days = retention_days
        self.privacy_level = privacy_level
        self.batch_ms = batch_ms
        self.max_batch = max_batch
        self._queue: asyncio.Queue[QueryRecord] = asyncio.Queue(maxsize=50_000)
        self._writer_task: asyncio.Task | None = None
        self._sweeper_task: asyncio.Task | None = None
        self._running = False

    def enqueue(self, rec: QueryRecord) -> None:
        if self.privacy_level >= NO_LOG:
            return
        if self.privacy_level >= HIDE_CLIENT:
            rec.client_ip = ""
            rec.client_id = ""
        if self.privacy_level >= ANON_CLIENT_DOMAIN:
            rec.qname = "hidden"
        try:
            self._queue.put_nowait(rec)
        except asyncio.QueueFull:  # under flood, shed log load rather than block DNS
            pass

    async def start(self) -> None:
        self._running = True
        self._writer_task = asyncio.ensure_future(self._writer())
        self._sweeper_task = asyncio.ensure_future(self._sweeper())

    async def stop(self) -> None:
        self._running = False
        for t in (self._writer_task, self._sweeper_task):
            if t is not None:
                t.cancel()
        # Loop until empty: _flush writes at most `max_batch` (500) records and
        # the queue holds up to 50,000, so a single call silently dropped
        # everything above the first batch on a busy shutdown — an unexplained
        # gap in the log around every restart.
        while not self._queue.empty():
            before = self._queue.qsize()
            await self._flush()
            if self._queue.qsize() >= before:
                break                    # not draining; stop rather than spin

    async def _writer(self) -> None:
        while self._running:
            await asyncio.sleep(self.batch_ms / 1000)
            await self._flush()

    async def _flush(self) -> None:
        batch: list[QueryRecord] = []
        while not self._queue.empty() and len(batch) < self.max_batch:
            batch.append(self._queue.get_nowait())
        if not batch:
            return
        rows = [[json.dumps(r.answers) if c == "answers" else getattr(r, c)
                 for c in _COLUMNS] for r in batch]
        try:
            await self.db.executemany(_INSERT, rows)
        except Exception:
            log.exception("querylog flush failed (%d rows)", len(rows))

    async def _sweeper(self) -> None:
        while self._running:
            await asyncio.sleep(3600)
            await self.retention_sweep()

    async def retention_sweep(self) -> int:
        cutoff = int((time.time() - self.retention_days * 86400) * 1_000_000)
        before = await self.db.fetchone("SELECT COUNT(*) AS n FROM querylog WHERE ts < ?", (cutoff,))
        await self.db.execute("DELETE FROM querylog WHERE ts < ?", (cutoff,))
        n = before["n"] if before else 0
        if n:
            log.info("retention: pruned %d query log rows", n)
        return n

    # --- read API (P6) ---
    async def distinct_names(self, *, since: int, limit: int = 20000) -> list[dict]:
        """One row per name actually asked for, with how much traffic it carries.

        A blocklist update only matters for names someone looks up, and there are
        a few thousand of those against millions of log rows — aggregating in SQL
        is what makes reviewing an update cheap enough to do on every refresh.
        """
        rows = await self.db.fetchall(
            "SELECT qname,"
            "       COUNT(*) AS hits,"
            "       COUNT(DISTINCT client_ip) AS clients,"
            "       MAX(ts) AS last_seen,"
            "       SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked_hits"
            "  FROM querylog WHERE ts >= ?"
            " GROUP BY qname ORDER BY hits DESC LIMIT ?", (since, limit))
        return [dict(r) for r in rows]

    async def search(self, *, qname: str | None = None, client: str | None = None,
                     action: str | None = None, rcode: str | None = None,
                     upstream: str | None = None, since: int | None = None,
                     until: int | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
        where, params = self._filters(qname, client, action, rcode, upstream, since, until)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        params += [limit, offset]
        rows = await self.db.fetchall(
            f"SELECT * FROM querylog {clause} ORDER BY ts DESC LIMIT ? OFFSET ?", params)
        return [dict(r) for r in rows]

    async def search_count(self, *, qname=None, client=None, action=None, rcode=None,
                           upstream=None, since=None, until=None) -> int:
        where, params = self._filters(qname, client, action, rcode, upstream, since, until)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        r = await self.db.fetchone(f"SELECT COUNT(*) AS n FROM querylog {clause}", params)
        return r["n"] if r else 0

    @staticmethod
    def _filters(qname, client, action, rcode, upstream, since, until):
        where, params = [], []
        if qname:
            where.append("qname LIKE ?"); params.append(f"%{qname}%")
        if client:
            where.append("client_ip = ?"); params.append(client)
        if action:
            where.append("action = ?"); params.append(action)
        if rcode:
            where.append("rcode = ?"); params.append(rcode)
        if upstream:
            where.append("upstream = ?"); params.append(upstream)
        if since:
            where.append("ts >= ?"); params.append(since)
        if until:
            where.append("ts <= ?"); params.append(until)
        return where, params

    async def facets(self) -> dict:
        """Distinct clients / actions / rcodes for populating filter menus."""
        async def col(name):
            rows = await self.db.fetchall(
                f"SELECT {name} AS v, COUNT(*) AS n FROM querylog WHERE {name} != '' "
                f"GROUP BY {name} ORDER BY n DESC LIMIT 50")
            return [{"value": r["v"], "count": r["n"]} for r in rows]
        return {"clients": await col("client_ip"), "actions": await col("action"),
                "rcodes": await col("rcode"), "upstreams": await col("upstream")}

    async def purge(self) -> int:
        """Delete every stored query (one-click privacy purge). Returns rows removed."""
        n = await self.count()
        await self.db.execute("DELETE FROM querylog")
        # VACUUM cannot run inside a transaction, and this connection is shared
        # with the 250 ms flush loop — so it reliably raised *after* the rows
        # were already gone, and the operator saw a 500 for a purge that had in
        # fact succeeded. Reclaiming the file is best-effort; the delete is not.
        try:
            await self.db.vacuum()
        except Exception:
            log.warning("query log purged, but reclaiming disk space failed",
                        exc_info=True)
        log.info("query log purged: %d rows removed", n)
        return n

    async def count(self) -> int:
        r = await self.db.fetchone("SELECT COUNT(*) AS n FROM querylog")
        return r["n"] if r else 0

    async def export_ndjson(self) -> str:
        """The whole export as one string. Prefer `iter_ndjson` for serving.

        Kept for callers that genuinely want it in memory; the HTTP handler no
        longer does, because this held four live copies of the same data at once
        (rows, their JSON strings, the join, and the response body).
        """
        return "\n".join([line async for line in self.iter_ndjson()])

    async def iter_ndjson(self, batch: int = 2000, limit: int = 100_000):
        """Yield the export one line at a time, a page of rows at a time."""
        offset = 0
        while offset < limit:
            rows = await self.db.fetchall(
                "SELECT * FROM querylog ORDER BY ts DESC LIMIT ? OFFSET ?",
                (min(batch, limit - offset), offset))
            if not rows:
                return
            for r in rows:
                yield json.dumps(dict(r))
            offset += len(rows)


def record_from_ctx(qname: str, qtype: str, ctx, rcode: str, answers: list[str]) -> QueryRecord:
    return QueryRecord(
        ts=int(time.time() * 1_000_000), client_ip=ctx.client_ip, client_id=ctx.client_id,
        qname=qname, qtype=qtype, proto=ctx.proto, action=ctx.action, reason=ctx.reason,
        rule=ctx.rule, source=ctx.source, upstream=ctx.upstream, rcode=rcode,
        answers=answers, elapsed_us=ctx.elapsed_us(),
    )
