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
        self.readonly = False

    async def connect(self, *, readonly: bool = False) -> None:
        """Open the database. `readonly` is for the non-primary workers.

        Only the primary may write — that is what keeps SQLite to one writer —
        but the others still have to *read* the tables that carry policy, and
        having no handle at all is why per-client policy applied in one worker
        out of four. WAL lets those readers run alongside the writer, and the
        read-only open means the rule is enforced by SQLite rather than by
        remembering not to.
        """
        parent = Path(self.path).parent
        parent.mkdir(parents=True, exist_ok=True)
        if readonly:
            import aiosqlite as _a
            self.readonly = True
            self._db = await _a.connect(f"file:{self.path}?mode=ro", uri=True)
            self._db.row_factory = _a.Row
            await self._db.execute("PRAGMA busy_timeout=5000")
            return
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
            # One transaction per migration, its bookkeeping row included.
            # `executescript` commits first and then runs in autocommit, so each
            # statement used to land on its own: a failure — or a kill during
            # an upgrade — left half a migration applied and none of it
            # recorded, to be replayed on top of itself at the next start. That
            # is harmless only for as long as every migration is idempotent;
            # the first ALTER TABLE ADD COLUMN would have bricked start-up.
            # The row is inlined because a script takes no parameters; both
            # values are ours, and the quote escaping keeps a stray apostrophe
            # in a description from ending the literal.
            record = ("INSERT INTO _migrations(version, applied, descr) VALUES "
                      f"({int(version)}, {int(time.time())}, "
                      f"'{descr.replace(chr(39), chr(39) * 2)}');")
            try:
                await db.executescript(f"BEGIN IMMEDIATE;\n{sql}\n;{record}\nCOMMIT;")
            except BaseException:
                await db.rollback()
                raise
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

    async def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        """Run one statement and commit. Returns the number of rows it changed."""
        try:
            cur = await self.conn.execute(sql, tuple(params))
            n = cur.rowcount
            await cur.close()
            await self.conn.commit()
            return n
        except BaseException:
            await self._rollback()
            raise

    async def _rollback(self) -> None:
        """Abandon a write that failed partway.

        sqlite3 leaves the implicit transaction open when a statement fails. The
        rows written before the failure then stayed pending, holding the WAL
        write lock, and were committed by whichever unrelated write came next —
        so a query-log batch reported as failed was in fact half-written, and
        a VACUUM in between found the database busy.
        """
        try:
            await self.conn.rollback()
        except Exception:  # noqa: BLE001 — the original error is the one to report
            log.debug("rollback after a failed write also failed", exc_info=True)

    async def vacuum(self) -> None:
        """VACUUM on a dedicated connection.

        It cannot run inside a transaction, and the shared connection nearly
        always has one open — the query-log flush loop writes every 250 ms — so
        issuing it there raised `cannot VACUUM from within a transaction`.

        The dedicated connection is not enough on its own. `aiosqlite.execute`
        hands back a live cursor, and an unfinalised cursor is a statement in
        progress: the `busy_timeout` pragma above left one open on this very
        connection, so every VACUUM Trench has ever issued failed with `cannot
        VACUUM - SQL statements in progress` and was swallowed by the caller's
        best-effort `except`. The privacy purge deleted the rows and then left
        every one of them legible in the file's free pages.
        """
        await self.conn.commit()
        db = await aiosqlite.connect(self.path)
        try:
            cur = await db.execute("PRAGMA busy_timeout=30000")
            await cur.close()
            cur = await db.execute("VACUUM")
            await cur.close()
            await db.commit()
            # In WAL mode VACUUM rebuilds into the write-ahead log, so the main
            # file keeps its old size — and its old pages — until a checkpoint
            # folds the log back in. For a privacy purge that difference is the
            # whole point: the rows are meant to stop being on the disk.
            cur = await db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            await cur.close()
        finally:
            await db.close()

    async def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        try:
            await self.conn.executemany(sql, [tuple(r) for r in rows])
            await self.conn.commit()
        except BaseException:
            await self._rollback()
            raise

    # Both readers close their cursor. An unfinalised sqlite3 cursor holds the
    # connection's read transaction open, and SQLite refuses to VACUUM while
    # any statement is in progress — from *any* connection to the file. Since
    # every read here left one behind, `vacuum()` failed every single time it
    # was called, which is to say the privacy purge deleted the rows and never
    # reclaimed the pages they were written on.
    async def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[aiosqlite.Row]:
        cur = await self.conn.execute(sql, tuple(params))
        try:
            return await cur.fetchall()
        finally:
            await cur.close()

    async def fetchone(self, sql: str, params: Iterable[Any] = ()) -> aiosqlite.Row | None:
        cur = await self.conn.execute(sql, tuple(params))
        try:
            return await cur.fetchone()
        finally:
            await cur.close()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None
