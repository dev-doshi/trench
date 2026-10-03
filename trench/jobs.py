"""What the process is doing in the background, and how the last run went.

The scheduler used to be fire-and-forget: a job that failed logged a traceback
and nothing else knew. A blocklist build that took four minutes, a refresh that
kept the previous rules because one source was down, an assertion that turned a
refresh away — all of it was in the container log and nowhere an operator
would look. The board is the one place those outcomes are written, so the
console can show them and offer to run a job again.

Deliberately in-memory. It describes this process since it started; history
worth keeping (a refused refresh, an applied one) goes to the audit table.
"""
from __future__ import annotations

import asyncio
import contextvars
import os
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from .log import get

log = get("jobs")

_PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096


def rss_bytes() -> int | None:
    """Resident memory of this process right now, or None off Linux.

    `/proc/self/statm` rather than `ru_maxrss`: the latter is a high-water mark
    for the whole process lifetime and can never say what one job cost.
    """
    try:
        with open("/proc/self/statm", "rb") as f:
            return int(f.read().split()[1]) * _PAGE
    except (OSError, ValueError, IndexError):
        return None


def _read_int(path: str) -> int | None:
    try:
        with open(path) as f:
            raw = f.read().strip()
    except OSError:
        return None
    return int(raw) if raw.isdigit() else None


def memory() -> dict:
    """This process and its container, as far as the kernel will say.

    The container's ceiling is the number that matters on a small box — a
    build that crosses it is killed outright — so it is shown beside the
    process's own resident size rather than instead of it.
    """
    return {
        "rss": rss_bytes(),
        "cgroup_current": _read_int("/sys/fs/cgroup/memory.current"),
        "cgroup_peak": _read_int("/sys/fs/cgroup/memory.peak"),
        "cgroup_max": _read_int("/sys/fs/cgroup/memory.max"),   # "max" -> None
    }


def _cpu_usec() -> tuple[int, bool]:
    """CPU time spent so far, in microseconds, and whether it is the container's.

    The cgroup's figure when there is one: with several workers this process
    is only a share of the box, and a list build in a sibling worker is exactly
    what the number is for.
    """
    try:
        with open("/sys/fs/cgroup/cpu.stat") as f:
            for line in f:
                k, _, v = line.partition(" ")
                if k == "usage_usec":
                    return int(v), True
    except (OSError, ValueError):
        pass
    t = os.times()
    return int((t.user + t.system) * 1e6), False


def _cores() -> float:
    """How many CPUs' worth of time the container may use."""
    try:
        with open("/sys/fs/cgroup/cpu.max") as f:
            quota, _, period = f.read().partition(" ")
        if quota != "max":
            return max(int(quota) / int(period), 0.01)
    except (OSError, ValueError, ZeroDivisionError):
        pass
    try:
        return float(len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return float(os.cpu_count() or 1)


_last_cpu: tuple[float, int] = (time.monotonic(), _cpu_usec()[0])


def cpu() -> dict:
    """Share of the available CPU used since the previous call.

    Two reads of a counter and a subtraction — nothing sleeps to take a
    sample. The first call after start-up covers the whole time since import.
    """
    global _last_cpu
    now, (used, container) = time.monotonic(), _cpu_usec()
    then, before = _last_cpu
    _last_cpu = (now, used)
    cores = _cores()
    wall = now - then
    pct = None
    if wall > 0.05 and used >= before:
        pct = round(min(100.0, (used - before) / 1e6 / wall / cores * 100), 1)
    return {"percent": pct, "cores": round(cores, 2), "container": container}


@dataclass
class JobState:
    name: str
    interval: float | None = None
    next_at: float | None = None
    running: bool = False
    started: float | None = None       # of the run in progress, or the last one
    finished: float | None = None
    duration: float | None = None
    result: str = ""                   # ok | failed | kept | rejected | skipped
    detail: str = ""
    runs: int = 0
    failures: int = 0
    peak_rss: int | None = None        # bytes, sampled while the last run ran
    trigger: str = ""                  # schedule | console | startup | signal
    _factory: Callable[[], Awaitable] | None = field(default=None, repr=False)

    def to_json(self) -> dict:
        return {
            "name": self.name, "interval": self.interval, "next_at": self.next_at,
            "running": self.running, "started": self.started,
            "finished": self.finished, "duration": self.duration,
            "result": self.result, "detail": self.detail, "runs": self.runs,
            "failures": self.failures, "peak_rss": self.peak_rss,
            "trigger": self.trigger, "runnable": self._factory is not None,
        }


#: The job the current task is running under, so a job that calls into code
#: which tracks itself (the scheduled refresh calls `refresh_blocklists`, which
#: is also reachable from SIGHUP and the console) is recorded once, not twice.
_current: contextvars.ContextVar[JobState | None] = contextvars.ContextVar(
    "trench_job", default=None)

class JobBoard:
    #: How often memory is sampled while a job runs. Coarse on purpose: a build
    #: peaks over tens of seconds, and this must cost nothing on a quiet box.
    SAMPLE_EVERY = 0.5

    def __init__(self) -> None:
        self.jobs: dict[str, JobState] = {}
        self._tasks: set[asyncio.Task] = set()

    def job(self, name: str) -> JobState:
        st = self.jobs.get(name)
        if st is None:
            st = self.jobs[name] = JobState(name)
        return st

    def register(self, name: str, factory: Callable[[], Awaitable] | None = None, *,
                 interval: float | None = None) -> None:
        """Make a job known — with the callable "run now" should invoke."""
        st = self.job(name)
        if factory is not None:
            st._factory = factory
        st.interval = interval

    def unschedule(self, name: str) -> None:
        st = self.jobs.get(name)
        if st is not None:
            st.interval = None
            st.next_at = None

    def planned(self, name: str, at: float) -> None:
        self.job(name).next_at = at

    @staticmethod
    def note(detail: str, *, result: str | None = None) -> None:
        """Say how the job running in this task went, from inside it."""
        st = _current.get()
        if st is None:
            return
        st.detail = detail
        if result is not None:
            st.result = result

    def busy(self, name: str) -> bool:
        st = self.jobs.get(name)
        return bool(st and st.running)

    @asynccontextmanager
    async def track(self, name: str, trigger: str = "schedule", *, claimed: bool = False):
        outer = _current.get()
        if outer is not None and outer.name == name:
            yield outer                 # already recorded by whoever started it
            return
        st = self.job(name)
        if st.running and not claimed:
            # Another task is in the middle of this job. Recording this attempt
            # over it would overwrite the run the operator is watching with one
            # that is about to be turned away.
            yield JobState(name)
            return
        st.running, st.started, st.trigger = True, time.time(), trigger
        st.result, st.detail, st.peak_rss = "", "", rss_bytes()
        token = _current.set(st)
        sampler = asyncio.ensure_future(self._sample(st))
        try:
            yield st
        except asyncio.CancelledError:
            st.result = st.result or "cancelled"
            raise
        except Exception as e:
            st.result, st.detail = "failed", f"{type(e).__name__}: {e}"
            st.failures += 1
            raise
        else:
            if not st.result:
                st.result = "ok"
            elif st.result == "failed":
                st.failures += 1
        finally:
            _current.reset(token)
            sampler.cancel()
            st.running = False
            st.finished = time.time()
            st.duration = st.finished - (st.started or st.finished)
            st.runs += 1

    async def _sample(self, st: JobState) -> None:
        while True:
            await asyncio.sleep(self.SAMPLE_EVERY)
            now = rss_bytes()
            if now is not None and (st.peak_rss is None or now > st.peak_rss):
                st.peak_rss = now

    def run_now(self, name: str, trigger: str = "console") -> bool:
        """Start a registered job in the background. False when it has no
        runnable callable or is already running."""
        st = self.jobs.get(name)
        if st is None or st._factory is None or st.running:
            return False
        factory = st._factory
        st.running = True       # claimed now, so a double click cannot start two

        async def go() -> None:
            try:
                async with self.track(name, trigger, claimed=True):
                    await factory()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("job %s failed", name)

        task = asyncio.ensure_future(go())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return True

    def snapshot(self) -> list[dict]:
        return [st.to_json() for st in sorted(self.jobs.values(), key=lambda s: s.name)]
