"""Tiny periodic scheduler for background jobs (gravity refresh, retention)."""
from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable

from ..log import get

log = get("schedule")


class Scheduler:
    def __init__(self) -> None:
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
        self._tasks[name] = asyncio.ensure_future(
            self._loop(seconds, coro_factory, jitter, name, offset))

    def cancel(self, name: str) -> bool:
        """Stop one job. False when there was nothing under that name."""
        task = self._tasks.pop(name, None)
        if task is None:
            return False
        task.cancel()
        return True

    def running(self, name: str) -> bool:
        return name in self._tasks

    async def _loop(self, seconds: float, factory, jitter: float, name: str,
                    offset: float = 0.0) -> None:
        if offset:
            await asyncio.sleep(offset)
        while self._running:
            delay = seconds * (1 + random.uniform(-jitter, jitter))
            await asyncio.sleep(max(1.0, delay))
            if not self._running:
                break
            try:
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
