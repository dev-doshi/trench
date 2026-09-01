"""Query log: a non-blocking batched writer plus search / export / retention.

The pipeline calls `enqueue()` (cheap, never awaits). A background task drains
the queue in batches and writes to SQLite. Privacy levels strip fields before
they ever hit disk.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import dataclass

from ..log import get
from ..security.hashutil import hash_identifier
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
    """The query log's writer, on either side of the worker boundary.

    With a `db` this is the primary worker's: it writes to SQLite, and — when a
    `ring` is also given — drains what the sibling workers published before
    writing its own batch, so the table holds the whole machine's traffic rather
    than the primary's share of it.

    With only a `ring` this is a sibling worker's: identical up to the point of
    the write, then it publishes instead. Same privacy handling, same batching,
    same shedding under flood; only the sink differs.
    """

    def __init__(self, db: Database | None = None, *, retention_days: int = 90,
                 privacy_level: int = SHOW_ALL, batch_ms: int = 250,
                 max_batch: int = 500, salt: bytes | None = None,
                 ring=None, export=None):
        self.db = db
        # Optional JSON-lines stream of every written row (store/export.py).
        self.export = export
        self.ring = ring
        self.retention_days = retention_days
        self.privacy_level = privacy_level
        self.batch_ms = batch_ms
        self.max_batch = max_batch
        # Per-installation once `start()` has loaded it from the database. The
        # default is random rather than empty on purpose: an unsalted digest of a
        # domain name is precomputable from any public blocklist, so a QueryLog
        # used without `start()` should degrade to "stable only within this
        # process", never to "reversible by anyone".
        self.salt = secrets.token_bytes(32) if salt is None else salt
        self._salt_is_persisted = salt is not None
        self._queue: asyncio.Queue[QueryRecord] = asyncio.Queue(maxsize=50_000)
        self._writer_task: asyncio.Task | None = None
        self._running = False

    def enqueue(self, rec: QueryRecord) -> None:
        """Queue one record, stripped to whatever the privacy level allows.

        Level 2 hashes rather than blanks, which is what the console and the
        settings help have always said it does. The difference matters: it was
        writing the literal string "hidden" into every row, so the log kept its
        full size and retention while carrying nothing at all. A salted digest
        keeps every count and every correlation — this domain was looked up 40
        times by two devices — and keeps the name itself out of the file.
        """
        if self.privacy_level >= NO_LOG:
            return
        if self.privacy_level >= ANON_CLIENT_DOMAIN:
            if rec.client_ip:
                rec.client_ip = hash_identifier(rec.client_ip, self.salt)
            if rec.client_id:
                rec.client_id = hash_identifier(rec.client_id, self.salt)
            if rec.qname:
                rec.qname = hash_identifier(rec.qname, self.salt)
            # The answer is the address the name resolved to, which identifies
            # the name as surely as the name does.
            rec.answers = []
        elif self.privacy_level >= HIDE_CLIENT:
            rec.client_ip = ""
            rec.client_id = ""
        try:
            self._queue.put_nowait(rec)
        except asyncio.QueueFull:  # under flood, shed log load rather than block DNS
            pass

    async def start(self) -> None:
        if not self._salt_is_persisted and self.db is not None:
            self.salt = await self.db.secret("querylog_salt")
            self._salt_is_persisted = True
        self._running = True
        self._writer_task = asyncio.ensure_future(self._writer())
        # Retention is *not* armed here. `App._adopt_querylog` registers
        # `retention_sweep` with the scheduler, under a name it can cancel; a
        # second loop in here meant two hourly DELETE passes over the same
        # table with different error behaviour, and the app's cancel silenced
        # only one of them.

    async def stop(self) -> None:
        self._running = False
        for t in (self._writer_task,):
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
        if self.db is not None and self.ring is not None:
            await self._flush()          # one last sweep of the siblings' lanes

    async def _writer(self) -> None:
        while self._running:
            await asyncio.sleep(self.batch_ms / 1000)
            try:
                await self._flush()
            except asyncio.CancelledError:
                raise
            except Exception:
                # One escaped exception used to end query logging for the life
                # of the process, unretrieved and with nothing in the log to say
                # so. A bad tick is not a reason to stop writing.
                log.exception("query log flush failed; continuing")

    async def _flush(self) -> None:
        batch: list[QueryRecord] = []
        while not self._queue.empty() and len(batch) < self.max_batch:
            batch.append(self._queue.get_nowait())
        rows = [[json.dumps(r.answers) if c == "answers" else getattr(r, c)
                 for c in _COLUMNS] for r in batch]
        if self.db is None:
            # A sibling worker: hand the rows to the primary and stop here.
            # Encoding happens on this tick rather than on the query path, which
            # is the whole reason `enqueue` takes an object and not a string.
            if self.ring is not None:
                for row in rows:
                    self.ring.push(row)
            return
        if self.ring is not None:
            rows += self.ring.drain()      # whatever the siblings published
        if not rows:
            return
        if self.export is not None:
            try:
                # Off the loop: this is a file write plus a flush, and at 500
                # rows every 250 ms on an SD card that is not free. Rotation
                # happens inside the same call, so it moves with it.
                await asyncio.to_thread(self.export.write, rows)
            except Exception:
                # The export disables itself and has already logged why. The
                # log — and DNS — carry on regardless.
                self.export = None
        try:
            await self.db.executemany(_INSERT, rows)
        except Exception:
            log.exception("querylog flush failed (%d rows)", len(rows))

    async def retention_sweep(self) -> int:
        cutoff = int((time.time() - self.retention_days * 86400) * 1_000_000)
        before = await self.store.fetchone("SELECT COUNT(*) AS n FROM querylog WHERE ts < ?", (cutoff,))
        await self.store.execute("DELETE FROM querylog WHERE ts < ?", (cutoff,))
        n = before["n"] if before else 0
        if n:
            log.info("retention: pruned %d query log rows", n)
        return n

    @property
    def store(self) -> Database:
        """The database this log writes to.

        Only the primary worker's log has one; a sibling's publishes into the
        shared ring instead. Everything below is a read or a maintenance
        operation on the table, reached through the API — which also runs only
        in the primary — so this asserts the invariant rather than assuming it.
        """
        if self.db is None:
            raise RuntimeError("this query log has no database: it is a worker's, "
                               "and publishes into the shared ring instead")
        return self.db

    # --- read API (P6) ---
    async def distinct_names(self, *, since: int, limit: int = 20000) -> list[dict]:
        """One row per name actually asked for, with how much traffic it carries.

        A blocklist update only matters for names someone looks up, and there are
        a few thousand of those against millions of log rows — aggregating in SQL
        is what makes reviewing an update cheap enough to do on every refresh.
        """
        rows = await self.store.fetchall(
            "SELECT qname,"
            "       COUNT(*) AS hits,"
            "       COUNT(DISTINCT client_ip) AS clients,"
            "       MAX(ts) AS last_seen,"
            "       SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked_hits"
            "  FROM querylog WHERE ts >= ?"
            " GROUP BY qname ORDER BY hits DESC LIMIT ?", (since, limit))
        return [dict(r) for r in rows]

    async def history(self, qname: str, *, since: int | None = None,
                      limit: int = 50) -> list[dict]:
        """What this name has resolved to over time, one row per answer set.

        Passive DNS — "what did this resolve to on the 3rd, and who asked?" — is
        a paid product built by collecting everyone's answers. Built from one
        household's own log it is neither paid nor collected, and it is the first
        question of any incident. No second store: the answers are already in the
        query log, so this is an aggregation over rows that exist rather than a
        parallel archive to keep, prune and get wrong.

        Rows carry the same privacy level the log was written at: at level 2 the
        names are hashed and the answers dropped, so this returns nothing for
        them, which is the point of that setting.
        """
        params: list = [qname.strip(".").lower()]
        clause = "qname = ? AND answers NOT IN ('[]', '')"
        if since is not None:
            clause += " AND ts >= ?"
            params.append(since)
        params.append(limit)
        rows = await self.store.fetchall(
            "SELECT answers,"
            "       MIN(ts) AS first_seen,"
            "       MAX(ts) AS last_seen,"
            "       COUNT(*) AS hits,"
            "       COUNT(DISTINCT client_ip) AS clients"
            f"  FROM querylog WHERE {clause}"
            " GROUP BY answers ORDER BY last_seen DESC LIMIT ?", params)
        out = []
        for r in rows:
            try:
                answers = json.loads(r["answers"])
            except (ValueError, TypeError):
                answers = []
            out.append({"answers": answers, "first_seen": r["first_seen"],
                        "last_seen": r["last_seen"], "hits": r["hits"],
                        "clients": r["clients"]})
        return out

    async def search(self, *, qname: str | None = None, client: str | None = None,
                     action: str | None = None, rcode: str | None = None,
                     upstream: str | None = None, since: int | None = None,
                     until: int | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
        where, params = self._filters(qname, client, action, rcode, upstream, since, until)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        params += [limit, offset]
        rows = await self.store.fetchall(
            f"SELECT * FROM querylog {clause} ORDER BY ts DESC LIMIT ? OFFSET ?", params)
        return [dict(r) for r in rows]

    async def search_count(self, *, qname=None, client=None, action=None, rcode=None,
                           upstream=None, since=None, until=None) -> int:
        where, params = self._filters(qname, client, action, rcode, upstream, since, until)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        r = await self.store.fetchone(f"SELECT COUNT(*) AS n FROM querylog {clause}", params)
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
            rows = await self.store.fetchall(
                f"SELECT {name} AS v, COUNT(*) AS n FROM querylog WHERE {name} != '' "
                f"GROUP BY {name} ORDER BY n DESC LIMIT 50")
            return [{"value": r["v"], "count": r["n"]} for r in rows]
        return {"clients": await col("client_ip"), "actions": await col("action"),
                "rcodes": await col("rcode"), "upstreams": await col("upstream")}

    async def purge(self) -> int:
        """Delete every stored query (one-click privacy purge). Returns rows removed."""
        n = await self.count()
        await self.store.execute("DELETE FROM querylog")
        # VACUUM cannot run inside a transaction, and this connection is shared
        # with the 250 ms flush loop — so it reliably raised *after* the rows
        # were already gone, and the operator saw a 500 for a purge that had in
        # fact succeeded. Reclaiming the file is best-effort; the delete is not.
        try:
            await self.store.vacuum()
        except Exception:
            log.warning("query log purged, but reclaiming disk space failed",
                        exc_info=True)
        log.info("query log purged: %d rows removed", n)
        return n

    async def count(self) -> int:
        r = await self.store.fetchone("SELECT COUNT(*) AS n FROM querylog")
        return r["n"] if r else 0


    async def iter_ndjson(self, batch: int = 2000, limit: int = 100_000):
        """Yield the export one line at a time, a page of rows at a time."""
        offset = 0
        while offset < limit:
            rows = await self.store.fetchall(
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
