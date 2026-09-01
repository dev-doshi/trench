"""Async SQLite wrapper (aiosqlite) with WAL + migrations."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import aiosqlite

from ..log import get
from .schema import MIGRATIONS

log = get("db")


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        parent = Path(self.path).parent
        parent.mkdir(parents=True, exist_ok=True)
        # This file holds scrypt password hashes, TOTP secrets, API-token
        # digests, the query-log salt and every name the household has looked
        # up. It was created at the process umask — world-readable on a default
        # 0022 — while `security/tls.py` and `api/auth.py` both take care to
        # write their secrets 0600. Created empty and private first, so there is
        # no window in which it exists and is readable.
        self._precreate_private(Path(self.path))
        self._db = await aiosqlite.connect(self.path)
        self._db.row_factory = aiosqlite.Row
        for pragma in ("PRAGMA journal_mode=WAL",
                       "PRAGMA synchronous=NORMAL",
                       "PRAGMA busy_timeout=5000",
                       "PRAGMA foreign_keys=ON"):
            await self._db.execute(pragma)
        await self.apply_migrations()

    @staticmethod
    def _precreate_private(path: Path) -> None:
        """Create the database file 0600 if it does not exist yet.

        Best effort: a filesystem that cannot represent the mode (or a file
        someone else owns) must not stop the daemon from starting, but it is
        worth a warning because the operator's secrets are what is at stake.
        """
        import os
        if path.exists():
            try:
                if path.stat().st_mode & 0o077:
                    os.chmod(path, 0o600)
            except OSError:
                log.warning("could not tighten permissions on %s", path)
            return
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        except FileExistsError:
            pass
        except OSError:
            log.warning("could not create %s privately; check its permissions",
                        path)

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("database not connected")
        return self._db

    async def apply_migrations(self) -> None:
        db = self.conn
        await db.execute("CREATE TABLE IF NOT EXISTS _migrations "
                         "(version INTEGER PRIMARY KEY, applied INTEGER, descr TEXT)")
        await db.commit()
        cur = await db.execute("SELECT version FROM _migrations")
        done = {r[0] for r in await cur.fetchall()}
        import time
        for version, descr, sql in MIGRATIONS:
            if version in done:
                continue
            await db.executescript(sql)
            await db.execute("INSERT INTO _migrations(version, applied, descr) VALUES (?,?,?)",
                             (version, int(time.time()), descr))
            await db.commit()
            log.info("applied migration %d: %s", version, descr)

    async def secret(self, name: str, *, nbytes: int = 32) -> bytes:
        """A random value created once for this installation and kept in `setting`.

        Two things need one, and both were getting it wrong in the same way by
        generating it per process: API-token digests (every stored token became
        unverifiable at the next restart) and the query-log privacy salt (level 2
        would hash the same domain to a different value after every restart,
        which destroys the only property hashing was supposed to preserve).

        Concurrent creation is safe: the INSERT is `OR IGNORE` and the value read
        back afterwards is whichever one landed, the same for every caller.
        """
        key = f"secret.{name}"
        row = await self.fetchone("SELECT value FROM setting WHERE key=?", (key,))
        if row is None:
            import secrets
            await self.execute(
                "INSERT OR IGNORE INTO setting(key, value) VALUES(?,?)",
                (key, secrets.token_hex(nbytes)))
            row = await self.fetchone("SELECT value FROM setting WHERE key=?", (key,))
        if row is None:  # pragma: no cover — the row was just written
            raise RuntimeError(f"could not store the {name} secret")
        return bytes.fromhex(row["value"])

    async def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        await self.conn.execute(sql, tuple(params))
        await self.conn.commit()

    async def vacuum(self) -> None:
        """VACUUM on a dedicated connection.

        It cannot run inside a transaction, and the shared connection nearly
        always has one open — the query-log flush loop writes every 250 ms — so
        issuing it there raised `cannot VACUUM from within a transaction`.
        """
        await self.conn.commit()
        db = await aiosqlite.connect(self.path)
        try:
            await db.execute("PRAGMA busy_timeout=30000")
            await db.execute("VACUUM")
            await db.commit()
        finally:
            await db.close()

    async def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        await self.conn.executemany(sql, [tuple(r) for r in rows])
        await self.conn.commit()

    async def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[aiosqlite.Row]:
        cur = await self.conn.execute(sql, tuple(params))
        return await cur.fetchall()

    async def fetchone(self, sql: str, params: Iterable[Any] = ()) -> aiosqlite.Row | None:
        cur = await self.conn.execute(sql, tuple(params))
        return await cur.fetchone()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None
