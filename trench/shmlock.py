"""Bounded acquisition of cross-process locks that a dead process may hold.

The shared cache and the query-log ring guard their mmap regions with
`multiprocessing.Lock`s — POSIX semaphores that a process killed inside its
critical section (SIGKILL, the OOM killer) never releases. A blocking acquire
then froze the event loop of every surviving worker for good.

A bounded acquire alone is not enough: waiting out the timeout on every access
stalls the loop for that long each time, forever — one query in 64 through the
shared cache, and every flush tick of the primary's query log. So a lock that
times out is written off: accesses skip it at no cost, and it is re-probed
without blocking every `RETRY` seconds, in case the holder was merely slow.
"""
from __future__ import annotations

import contextlib
import time
from collections.abc import Iterator, Sequence

from .log import get

log = get("shmlock")

#: Longest one acquire waits. Critical sections are a memcpy; contention never
#: gets near this, only a dead holder does.
LOCK_TIMEOUT = 0.05

#: How long a lock that timed out is skipped before it is probed again.
RETRY = 5.0


class BoundedLocks:
    """A set of cross-process locks, each taken with a bound."""

    def __init__(self, locks: Sequence, what: str, clock=time.monotonic):
        self.locks = locks
        self.what = what                  # for the log line, e.g. "cache stripe"
        self.clock = clock
        self._retry_at: dict[int, float] = {}   # index -> when to probe again

    @contextlib.contextmanager
    def hold(self, i: int) -> Iterator[bool]:
        """Hold lock `i` for the block; yields False (and holds nothing) when it
        cannot be had, in which case the caller treats the region as absent."""
        lock = self.locks[i]
        retry = self._retry_at.get(i)
        if retry is not None:
            now = self.clock()
            if now < retry:
                yield False
                return
            if not lock.acquire(False):       # probe: never blocks
                self._retry_at[i] = now + RETRY
                yield False
                return
            del self._retry_at[i]
            log.info("%s %d is free again", self.what, i)
        elif not lock.acquire(timeout=LOCK_TIMEOUT):
            self._retry_at[i] = self.clock() + RETRY
            log.warning("%s %d is held by a process that is not releasing it "
                        "(killed mid-write?); bypassing it", self.what, i)
            yield False
            return
        try:
            yield True
        finally:
            lock.release()
