"""Embedded, versioned SQL migrations.

Migrations are applied in order; the applied set is tracked in `_migrations`.
Kept in code (not .sql files) so the package ships self-contained.
"""
from __future__ import annotations

# (version, description, sql)
MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "core gravity/config schema", """
    CREATE TABLE IF NOT EXISTS adlist (
        id INTEGER PRIMARY KEY,
        url TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL DEFAULT 'block',     -- block | allow
        format TEXT DEFAULT 'auto',
        enabled INTEGER NOT NULL DEFAULT 1,
        comment TEXT DEFAULT '',
        group_id INTEGER,
        last_update INTEGER DEFAULT 0,
        http_etag TEXT DEFAULT '',
        http_modified TEXT DEFAULT '',
        rule_count INTEGER DEFAULT 0,
        status TEXT DEFAULT 'new',              -- new | ok | error
        error TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS custom_rule (
        id INTEGER PRIMARY KEY,
        raw TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT 'block',     -- block | allow
        enabled INTEGER NOT NULL DEFAULT 1,
        comment TEXT DEFAULT '',
        group_id INTEGER,
        created INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS "group" (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 1,
        comment TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS client (
        id INTEGER PRIMARY KEY,
        ident TEXT NOT NULL,
        ident_type TEXT NOT NULL DEFAULT 'ip',  -- ip | cidr | mac | clientid | token
        name TEXT DEFAULT '',
        comment TEXT DEFAULT '',
        policy TEXT DEFAULT '{}'                -- JSON per-client overrides
    );
    CREATE TABLE IF NOT EXISTS setting (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL                     -- JSON
    );
    """),
    (2, "query log", """
    CREATE TABLE IF NOT EXISTS querylog (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,                    -- microseconds since epoch
        client_ip TEXT,
        client_id TEXT,
        qname TEXT,
        qtype TEXT,
        proto TEXT,
        action TEXT,
        reason TEXT,
        rule TEXT,
        source TEXT,
        upstream TEXT,
        rcode TEXT,
        answers TEXT,
        elapsed_us INTEGER,
        dnssec TEXT
    );
    CREATE INDEX IF NOT EXISTS ix_querylog_ts ON querylog(ts);
    CREATE INDEX IF NOT EXISTS ix_querylog_client ON querylog(client_ip, ts);
    CREATE INDEX IF NOT EXISTS ix_querylog_qname ON querylog(qname);
    CREATE INDEX IF NOT EXISTS ix_querylog_action ON querylog(action, ts);
    """),
    (3, "users / tokens / audit (used in P6)", """
    CREATE TABLE IF NOT EXISTS app_user (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        pw_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        totp_secret TEXT DEFAULT '',
        created INTEGER DEFAULT 0,
        last_login INTEGER DEFAULT 0,
        disabled INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS api_token (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        token_hash TEXT NOT NULL,
        name TEXT DEFAULT '',
        scopes TEXT DEFAULT '',
        created INTEGER DEFAULT 0,
        last_used INTEGER DEFAULT 0,
        expires INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY,
        ts INTEGER NOT NULL,
        actor TEXT,
        action TEXT,
        target TEXT,
        detail TEXT,
        ip TEXT
    );
    """),
    (4, "stats time-series rollups", """
    CREATE TABLE IF NOT EXISTS ts_stat (
        bucket INTEGER NOT NULL,                -- unix epoch, truncated
        step TEXT NOT NULL,                     -- minute | hour | day
        metric TEXT NOT NULL,
        labels TEXT NOT NULL DEFAULT '',
        value REAL NOT NULL,
        PRIMARY KEY (step, bucket, metric, labels)
    );
    """),
    (5, "blocklist update reviews", """
    CREATE TABLE IF NOT EXISTS list_review (
        id INTEGER PRIMARY KEY,
        ts INTEGER NOT NULL,                    -- unix epoch of the refresh
        domains_before INTEGER NOT NULL,
        domains_after INTEGER NOT NULL,
        high_risk INTEGER NOT NULL DEFAULT 0,
        detail TEXT NOT NULL                    -- full review as JSON
    );
    CREATE INDEX IF NOT EXISTS idx_list_review_ts ON list_review(ts DESC);
    """),
    # Two tables that were modelled and never wired to anything. `ts_stat` was
    # written by nothing and read by nothing. The `group` table had create/list/
    # delete endpoints behind it, but no verdict ever consulted it: a group made
    # there could not change what any client resolved. Filtering groups are now
    # declared in `filtering.groups` and enforced by the pipeline, so the dead
    # copy goes rather than sitting next to the working one.
    #
    # `adlist.group_id` and `custom_rule.group_id` are left in place: dropping a
    # column rewrites the table on older SQLite, and an unused column costs a
    # few bytes where a failed migration costs the query log.
    (6, "drop the unwired group and ts_stat tables", """
    DROP TABLE IF EXISTS ts_stat;
    DROP TABLE IF EXISTS "group";
    """),
    # Hourly totals of the query log, for the console's charts. A week of raw
    # rows is ~450K on a small household; every chart over it read ~100 MB off
    # an SD card that a 1 GB Pi cannot keep in its page cache, and the Overview
    # asks nine such questions. The same week is ~20K rows here, and ~110K in
    # the per-name table.
    #
    # Kept by a trigger rather than by the writer, so every path that inserts
    # a row counts it. Deletes are not mirrored; `querylog_rollup.complete_from`
    # is the first hour the tables are known to be whole from. Hours before it
    # — the log as it was before this migration, and the hour retention is
    # halfway through — are read from `querylog` instead, and the writer
    # backfills them an hour at a time (see `QueryLog.backfill_rollup`).
    (7, "hourly rollups of the query log", """
    CREATE TABLE IF NOT EXISTS querylog_hour (
        hour INTEGER NOT NULL,                  -- unix epoch of the hour's start
        action TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        qtype TEXT NOT NULL,
        upstream TEXT NOT NULL,
        rcode TEXT NOT NULL,
        n INTEGER NOT NULL,
        lat_n INTEGER NOT NULL,                 -- rows with an elapsed_us
        lat_sum INTEGER NOT NULL,
        lat_max INTEGER NOT NULL,
        PRIMARY KEY (hour, action, client_ip, qtype, upstream, rcode)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS querylog_hour_name (
        hour INTEGER NOT NULL,
        qname TEXT NOT NULL,
        action TEXT NOT NULL,
        n INTEGER NOT NULL,
        PRIMARY KEY (hour, qname, action)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS querylog_rollup (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        complete_from INTEGER NOT NULL
    );
    -- whole from the hour after the newest row already logged; an empty log is
    -- whole from the start
    INSERT OR REPLACE INTO querylog_rollup(id, complete_from)
        SELECT 1, COALESCE(MAX(ts) / 3600000000 * 3600 + 3600, 0) FROM querylog;
    CREATE TRIGGER IF NOT EXISTS querylog_rollup_ins AFTER INSERT ON querylog BEGIN
        INSERT INTO querylog_hour VALUES (
            NEW.ts / 3600000000 * 3600, COALESCE(NEW.action, ''),
            COALESCE(NEW.client_ip, ''), COALESCE(NEW.qtype, ''),
            COALESCE(NEW.upstream, ''), COALESCE(NEW.rcode, ''),
            1, NEW.elapsed_us IS NOT NULL, COALESCE(NEW.elapsed_us, 0),
            COALESCE(NEW.elapsed_us, 0))
        ON CONFLICT (hour, action, client_ip, qtype, upstream, rcode) DO UPDATE SET n = n + 1, lat_n = lat_n + excluded.lat_n,
            lat_sum = lat_sum + excluded.lat_sum,
            lat_max = max(lat_max, excluded.lat_max);
        INSERT INTO querylog_hour_name VALUES (
            NEW.ts / 3600000000 * 3600, COALESCE(NEW.qname, ''),
            COALESCE(NEW.action, ''), 1)
        ON CONFLICT (hour, qname, action) DO UPDATE SET n = n + 1;
    END;
    """),
]
