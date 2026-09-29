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

from ..clients.model import mask_client_id
from ..log import get
from ..security.hashutil import hash_identifier
from .db import Database

log = get("querylog")

# privacy levels (PiHole-compatible semantics)
SHOW_ALL = 0
HIDE_CLIENT = 1
ANON_CLIENT_DOMAIN = 2
NO_LOG = 3


#: Rows per retention transaction; see `QueryLog.retention_sweep`.
_PRUNE_CHUNK = 5000
_PRUNE = ("DELETE FROM querylog WHERE rowid IN "
          "(SELECT rowid FROM querylog WHERE ts < ? LIMIT ?)")

_HOUR_US = 3_600_000_000

# One hour of the rollups, recomputed from the raw rows. A script, so it runs as
# one transaction on the shared connection: nothing the trigger adds for that
# hour can land between the DELETE and the INSERT and be counted twice, or be
# wiped. Every value in it is an int this module computed.
_BACKFILL = """
BEGIN IMMEDIATE;
DELETE FROM querylog_hour WHERE hour = {h};
DELETE FROM querylog_hour_name WHERE hour = {h};
INSERT INTO querylog_hour
    SELECT {h}, COALESCE(action, ''), COALESCE(client_ip, ''), COALESCE(qtype, ''),
           COALESCE(upstream, ''), COALESCE(rcode, ''), COUNT(*), COUNT(elapsed_us),
           COALESCE(SUM(elapsed_us), 0), COALESCE(MAX(elapsed_us), 0)
    FROM querylog WHERE ts >= {lo} AND ts < {hi} GROUP BY 2, 3, 4, 5, 6;
INSERT INTO querylog_hour_name
    SELECT {h}, COALESCE(qname, ''), COALESCE(action, ''), COUNT(*)
    FROM querylog WHERE ts >= {lo} AND ts < {hi} GROUP BY 2, 3;
UPDATE querylog_rollup SET complete_from = {h} WHERE id = 1 AND complete_from = {next};
COMMIT;
"""

#: What `aggregate` can be asked for. Fixed fragments only: nothing the caller
#: sends is interpolated into SQL.
GROUPS = ("client_ip", "action", "qtype", "rcode", "upstream", "qname")
BUCKETS = {"minute": 60, "hour": 3600, "day": 86400}
METRICS = ("count", "avg_latency", "max_latency")


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
        self._backfill_task: asyncio.Task | None = None
        self._running = False
        # Records shed because the queue was full. Counted, and reported by the
        # writer, so a gap in the log under load is explained rather than silent.
        self.dropped = 0
        self._dropped_reported = 0
        self._dropped_at = float("-inf")

    @property
    def recording(self) -> bool:
        """False when `enqueue` would discard everything it is handed.

        Building the record is not free — the answer section is rendered to
        text, which is a string per record — and at `NO_LOG` every bit of that
        is thrown away inside `enqueue`. Callers ask first, so the work is not
        done at all. Kept as a property rather than a flag so it cannot go stale
        when the privacy level is changed at runtime.
        """
        return self.privacy_level < NO_LOG

    @property
    def records_answers(self) -> bool:
        """False when the answer section would be stripped before it is written.

        At `ANON_CLIENT_DOMAIN` the answer is discarded by `enqueue` — it
        identifies the name as surely as the name does — so rendering it is
        wasted too.
        """
        return self.privacy_level < ANON_CLIENT_DOMAIN

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
            self.dropped += 1

    async def start(self) -> None:
        if not self._salt_is_persisted and self.db is not None:
            self.salt = await self.db.secret("querylog_salt")
            self._salt_is_persisted = True
        self._running = True
        self._writer_task = asyncio.ensure_future(self._writer())
        self._start_backfill()
        # Retention is *not* armed here. `App._adopt_querylog` registers
        # `retention_sweep` with the scheduler, under a name it can cancel; a
        # second loop in here meant two hourly DELETE passes over the same
        # table with different error behaviour, and the app's cancel silenced
        # only one of them.

    async def stop(self) -> None:
        self._running = False
        for t in (self._writer_task, self._backfill_task):
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
                # Keep writing while a full batch is waiting. One batch per tick
                # capped the log at max_batch / batch_ms — 2,000 rows a second at
                # the defaults — and anything faster than that filled the queue
                # and was shed. Each flush awaits the database, so the loop still
                # yields between batches.
                await self._flush()
                while self._running and self._queue.qsize() >= self.max_batch:
                    await self._flush()
                self._report_drops()
            except asyncio.CancelledError:
                raise
            except Exception:
                # One escaped exception used to end query logging for the life
                # of the process, unretrieved and with nothing in the log to say
                # so. A bad tick is not a reason to stop writing.
                log.exception("query log flush failed; continuing")

    def _report_drops(self) -> None:
        shed = self.dropped - self._dropped_reported
        now = time.monotonic()
        if shed and now - self._dropped_at >= 60:   # once a minute, not every tick
            self._dropped_reported, self._dropped_at = self.dropped, now
            log.warning("query log queue full: %d records dropped (%d total)",
                        shed, self.dropped)

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
        """Delete records older than `retention_days`, a chunk at a time.

        One DELETE for the whole backlog — the first sweep after retention is
        shortened, or after the process was down for a while — was one
        transaction over millions of rows: the write lock held and the WAL
        growing for its whole length, while the batched writer queued behind it
        on the same connection and shed records once its queue filled. Chunks
        commit separately and yield in between, so log writes interleave. The
        count is what was actually deleted, not a separate COUNT beforehand
        that rows arriving in between could make wrong.
        """
        cutoff = int((time.time() - self.retention_days * 86400) * 1_000_000)
        n = 0
        while True:
            done = await self.store.execute(_PRUNE, (cutoff, _PRUNE_CHUNK))
            n += max(done, 0)
            if done < _PRUNE_CHUNK:
                break
            await asyncio.sleep(0)
        if n:
            log.info("retention: pruned %d query log rows", n)
        # The rollups are not pruned row by row. Hours now wholly gone are
        # dropped; the hour the cutoff fell inside is half gone, so it is
        # marked incomplete — read raw — and the backfill recounts it.
        cut = cutoff // _HOUR_US * 3600
        await self.store.executescript(
            f"BEGIN IMMEDIATE; DELETE FROM querylog_hour WHERE hour < {cut}; "
            f"DELETE FROM querylog_hour_name WHERE hour < {cut}; "
            f"UPDATE querylog_rollup SET complete_from = {cut + 3600} "
            f"WHERE id = 1 AND complete_from < {cut + 3600}; COMMIT;")
        if self._running:
            self._start_backfill()
        return n

    # --- hourly rollups ---
    def _start_backfill(self) -> None:
        if self.db is None or (self._backfill_task and not self._backfill_task.done()):
            return
        self._backfill_task = asyncio.ensure_future(self._backfill_quietly())

    async def _backfill_quietly(self) -> None:
        try:
            n = await self.backfill_rollup()
            if n:
                log.info("query log rollups: counted %d earlier hours", n)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Charts over the missing hours stay correct, only slower: they are
            # read from the raw log until a later sweep finishes the job.
            log.warning("query log rollup backfill stopped", exc_info=True)

    async def rollup_from(self) -> int:
        """The first hour (epoch seconds) the rollup tables are whole from."""
        r = await self.store.fetchone("SELECT complete_from FROM querylog_rollup WHERE id = 1")
        return int(r[0]) if r else 1 << 62

    async def backfill_rollup(self, *, pause: float = 0.01) -> int:
        """Count the hours before `complete_from` into the rollups, newest first.

        An hour per transaction, yielding between them: after the upgrade that
        added the rollups this is the whole existing log, and it must not hold
        the connection the batched writer is waiting on. Newest first, because
        the recent past is what the console asks about.
        """
        done = 0
        while True:
            start = await self.rollup_from()
            # the newest hour below the mark that has any rows at all: the hours
            # in between are empty, so the rollups are already right for them
            row = await self.store.fetchone(
                "SELECT MAX(ts) FROM querylog WHERE ts < ?", (start * 1_000_000,))
            if row is None or row[0] is None:
                return done
            h = row[0] // _HOUR_US * 3600
            await self.store.executescript(_BACKFILL.format(
                h=h, next=start, lo=h * 1_000_000, hi=start * 1_000_000))
            done += 1
            await asyncio.sleep(pause)

    async def aggregate(self, *, since: int | None, until: int | None, bucket: str,
                        group: str | None, metric: str, top: int,
                        qname: str | None = None, client: str | None = None,
                        action: str | None = None) -> dict:
        """The console's charts: counts or latency over the log, bucketed and grouped.

        Whole hours inside the window come from the rollups when they can
        answer the question; the partial hours at either edge, and anything the
        rollups do not carry (minute buckets, a name substring, per-name
        latency), come from the raw rows. The two are summed before anything is
        ranked, so the answer is the same either way — only its cost differs.
        """
        lo = since if since is not None else 0
        # below int64 with room for the `hi + 1` bounds, whatever was asked
        hi = min(until if until is not None else int(time.time() * 1_000_000), 1 << 62)
        names = group == "qname"
        usable = (bucket != "minute" and not qname
                  and not (names and (client or metric != "count")))
        h0 = h1 = 0
        if usable:
            h0 = max(-(-lo // _HOUR_US) * 3600, await self.rollup_from())
            h1 = (hi + 1) // _HOUR_US * 3600        # hours ending at or before `hi`
        if h0 >= h1:
            h0 = h1 = 0

        async def fetch(bkt: str, grp: str | None, keep: list | None) -> dict:
            out: dict[tuple, list] = {}

            def add(rows):
                for b, g, n, ln, ls, lm in rows:
                    a = out.setdefault((b, g), [0, 0, 0, 0])
                    a[0] += n; a[1] += ln; a[2] += ls; a[3] = max(a[3], lm)

            raw_w, raw_a = ["ts >= ?", "ts < ?"], []
            if qname:
                raw_w.append("qname LIKE ?"); raw_a.append(f"%{qname}%")
            if client:
                raw_w.append("client_ip = ?"); raw_a.append(client)
            if action:
                raw_w.append("action = ?"); raw_a.append(action)
            gx = f"COALESCE({grp}, '')" if grp else "''"
            if keep is not None:
                raw_w.append(f"{gx} IN ({','.join('?' * len(keep))})"); raw_a += keep
            # `+col` keeps SQLite off the column's own index when grouping. With
            # it, the planner walks ix_querylog_qname end to end to skip one
            # sort, which reads every row ever logged instead of the requested
            # span: top names over a day took 85 s on a Pi holding two weeks.
            raw_g = f"COALESCE(+{grp}, '')" if grp else "''"
            raw_sql = (f"SELECT {_bucket_sql(bkt, 'ts / 1000000')} b, {raw_g} g, COUNT(*), "
                       "COUNT(elapsed_us), COALESCE(SUM(elapsed_us), 0), "
                       f"COALESCE(MAX(elapsed_us), 0) FROM querylog "
                       f"WHERE {' AND '.join(raw_w)} GROUP BY b, g")
            spans = [(lo, hi + 1)] if not h1 else [
                (lo, h0 * 1_000_000), (h1 * 1_000_000, hi + 1)]
            for a, z in spans:
                if a < z:
                    add(await self.store.fetchall(raw_sql, (a, z, *raw_a)))
            if h1:
                table = "querylog_hour_name" if names else "querylog_hour"
                w, args = ["hour >= ?", "hour < ?"], [h0, h1]
                if client:
                    w.append("client_ip = ?"); args.append(client)
                if action:
                    w.append("action = ?"); args.append(action)
                if keep is not None:
                    w.append(f"{grp} IN ({','.join('?' * len(keep))})"); args += keep
                lat = "0, 0, 0" if names else "SUM(lat_n), SUM(lat_sum), MAX(lat_max)"
                add(await self.store.fetchall(
                    f"SELECT {_bucket_sql(bkt, 'hour')} b, {grp or chr(39) * 2} g, "
                    f"SUM(n), {lat} FROM {table} WHERE {' AND '.join(w)} GROUP BY b, g",
                    args))
            return out

        def value(a: list):
            if metric == "count":
                return a[0]
            if metric == "avg_latency":
                return round(a[2] / a[1] / 1000.0, 2) if a[1] else None
            return round(a[3] / 1000.0, 2) if a[0] else None

        keep = None
        if group:  # keep only the busiest groups so charts stay legible
            totals = await fetch("none", group, None)
            ranked = sorted(totals.items(), key=lambda kv: -kv[1][0])[:top]
            keep = [g for (_, g), _ in ranked]
            if not keep:
                return {"series": [], "rows": [], "cells": []}

        if bucket == "none":
            got = totals if group else await fetch("none", None, None)
            if group:
                rows = sorted(([g, value(a)] for (_, g), a in got.items() if g in keep),
                              key=lambda r: -(r[1] or 0))
                return {"rows": rows}
            a = got.get((0, ""))
            return {"rows": [["all", value(a) if a else (0 if metric == "count" else None)]]}

        got = await fetch(bucket, group, keep)
        if bucket == "dow_hour":
            cells: dict[int, list] = {}
            for (b, _), a in got.items():
                c = cells.setdefault(b, [0, 0, 0, 0])
                c[0] += a[0]; c[1] += a[1]; c[2] += a[2]; c[3] = max(c[3], a[3])
            return {"cells": [[b // 24, b % 24, value(a)] for b, a in sorted(cells.items())]}
        series: dict[str, list] = {}
        for (b, g), a in sorted(got.items(), key=lambda kv: kv[0][0]):
            series.setdefault(str(g) if group else "all", []).append([b, value(a)])
        return {"series": [{"group": g, "points": p} for g, p in series.items()]}

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
            " GROUP BY +qname ORDER BY hits DESC LIMIT ?", (since, limit))  # +: see APIServer.analytics
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
            # A comma list is "any of these": the console's `blocked` means every
            # action it draws as blocked (blocked, refused, ratelimited, …), and
            # fetching them one action at a time would page the log once each.
            # No action name contains a comma, so a single value is unchanged.
            actions = [a for a in dict.fromkeys(action.split(",")) if a][:16]
            if len(actions) == 1:
                where.append("action = ?"); params.append(actions[0])
            elif actions:
                where.append(f"action IN ({','.join('?' * len(actions))})")
                params.extend(actions)
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
        # The rollups go with it — the per-name table holds every name — in the
        # same transaction, so a batch written in between cannot survive in one
        # and not the other.
        await self.store.executescript(
            "BEGIN IMMEDIATE; DELETE FROM querylog; DELETE FROM querylog_hour; "
            "DELETE FROM querylog_hour_name; "
            "UPDATE querylog_rollup SET complete_from = 0 WHERE id = 1; COMMIT;")
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


def _bucket_sql(bucket: str, secs: str) -> str:
    """A bucket key from an expression in epoch seconds. `dow_hour` packs the
    weekday and the hour into one integer, day * 24 + hour."""
    if bucket == "none":
        return "0"
    if bucket == "dow_hour":
        return (f"CAST(strftime('%w', {secs}, 'unixepoch') AS INTEGER) * 24 + "
                f"CAST(strftime('%H', {secs}, 'unixepoch') AS INTEGER)")
    step = BUCKETS[bucket]
    return f"({secs}) / {step} * {step}"


def record_from_ctx(qname: str, qtype: str, ctx, rcode: str, answers: list[str]) -> QueryRecord:
    return QueryRecord(
        ts=int(time.time() * 1_000_000), client_ip=ctx.client_ip,
        # The id a client presents is its credential (DoH path, DoT SNI);
        # the log is readable by every viewer, so only a masked form goes in.
        client_id=mask_client_id(ctx.client_id),
        qname=qname, qtype=qtype, proto=ctx.proto, action=ctx.action, reason=ctx.reason,
        rule=ctx.rule, source=ctx.source, upstream=ctx.upstream, rcode=rcode,
        answers=answers, elapsed_us=ctx.elapsed_us(),
    )
