"""Tiny periodic scheduler for background jobs (gravity refresh, retention)."""
from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable

from ..log import get

log = get("schedule")


class Scheduler:
    def __init__(self, board=None) -> None:
        # Where each tick's outcome is written (`trench.jobs.JobBoard`). Optional
        # so the scheduler still works on its own in tests and tools.
        self.board = board
        # Keyed by name, so a job can be replaced or dropped when the setting
        # behind it changes. Without that a live config change could start a
        # second copy of a job while the first kept running on the old interval.
        self._tasks: dict[str, asyncio.Task] = {}
        self._running = False

    def every(self, seconds: float, coro_factory: Callable[[], Awaitable], *,
              jitter: float = 0.1, name: str = "job", offset: float = 0.0) -> None:
        """Run coro_factory() every `seconds` (with +/- jitter), starting after
        one interval. coro_factory is called fresh each tick.

        Replaces any job already registered under `name`.

        `offset` delays the first tick — used to stagger memory-hungry jobs
        across forked workers so they never rebuild at the same moment."""
        self.cancel(name)
        self._running = True
        if self.board is not None:
            self.board.register(name, coro_factory, interval=seconds)
        self._tasks[name] = asyncio.ensure_future(
            self._loop(seconds, coro_factory, jitter, name, offset))

    def cancel(self, name: str) -> bool:
        """Stop one job. False when there was nothing under that name."""
        task = self._tasks.pop(name, None)
        if task is None:
            return False
        task.cancel()
        if self.board is not None:
            self.board.unschedule(name)
        return True

    def running(self, name: str) -> bool:
        return name in self._tasks

    async def _loop(self, seconds: float, factory, jitter: float, name: str,
                    offset: float = 0.0) -> None:
        if offset and self.board is not None:
            self.board.planned(name, time.time() + offset + seconds)
        if offset:
            await asyncio.sleep(offset)
        while self._running:
            delay = max(1.0, seconds * (1 + random.uniform(-jitter, jitter)))
            if self.board is not None:
                self.board.planned(name, time.time() + delay)
            await asyncio.sleep(delay)
            if not self._running:
                break
            if self.board is not None and self.board.busy(name):
                continue    # started by hand moments ago; this tick is redundant
            try:
                if self.board is None:
                    await factory()
                else:
                    async with self.board.track(name, "schedule"):
                        await factory()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("scheduled job %s failed", name)

    def stop(self) -> None:
        self._running = False
        for t in self._tasks.values():
            t.cancel()
        self._tasks.clear()
