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
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.path)
        self._db.row_factory = aiosqlite.Row
        for pragma in ("PRAGMA journal_mode=WAL",
                       "PRAGMA synchronous=NORMAL",
                       "PRAGMA busy_timeout=5000",
                       "PRAGMA foreign_keys=ON"):
            await self._db.execute(pragma)
        await self.apply_migrations()

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

    async def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        await self.conn.execute(sql, tuple(params))
        await self.conn.commit()

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
