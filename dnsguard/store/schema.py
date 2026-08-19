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
]
