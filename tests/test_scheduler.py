"""The periodic scheduler: replacement by name, cancellation, and the failure
path that must not kill a job.

Everything in `_loop` past the first `await` was uncovered, including the
`except Exception` that is the only reason a failing blocklist refresh does not
silently stop refreshing for the life of the process.
"""
from __future__ import annotations

import asyncio

import pytest

from trench.gravity.schedule import Scheduler


async def _yield():
    """One real loop turn, without going through the patched `asyncio.sleep`."""
    fut = asyncio.get_running_loop().create_future()
    asyncio.get_running_loop().call_soon(fut.set_result, None)
    await fut


@pytest.fixture
def sched():
    s = Scheduler()
    yield s
    s.stop()


def test_a_fresh_scheduler_is_running_nothing(sched):
    assert sched.running("anything") is False
    assert sched.cancel("anything") is False


@pytest.mark.asyncio
async def test_a_job_is_registered_under_its_name(sched):
    async def job():
        pass

    sched.every(60, job, name="refresh")
    assert sched.running("refresh") is True


@pytest.mark.asyncio
async def test_registering_the_same_name_replaces_rather_than_duplicates(sched):
    """Otherwise a live config change starts a second copy while the first keeps
    running on the old interval."""
    async def job():
        pass

    sched.every(60, job, name="refresh")
    first = sched._tasks["refresh"]
    sched.every(30, job, name="refresh")
    await asyncio.sleep(0)
    assert first.cancelled() or first.done()
    assert len(sched._tasks) == 1
    assert sched._tasks["refresh"] is not first


@pytest.mark.asyncio
async def test_cancelling_stops_the_job(sched):
    async def job():
        pass

    sched.every(60, job, name="refresh")
    assert sched.cancel("refresh") is True
    assert sched.running("refresh") is False
    assert sched.cancel("refresh") is False


@pytest.mark.asyncio
async def test_a_job_runs_on_its_interval(sched):
    ran = asyncio.Event()

    async def job():
        ran.set()

    # The loop floors the delay at one second, so this is the shortest a job
    # can actually be scheduled for.
    sched.every(0.1, job, jitter=0, name="quick")
    await asyncio.wait_for(ran.wait(), timeout=15)


@pytest.mark.asyncio
async def test_the_delay_is_jittered_within_its_band(sched, monkeypatch):
    """Jitter is what keeps a fleet of workers from all refreshing at once."""
    delays = []

    async def job():
        sched._running = False

    async def fake_sleep(d):
        delays.append(d)

    monkeypatch.setattr("trench.gravity.schedule.asyncio.sleep", fake_sleep)
    sched._running = True
    await sched._loop(100, job, 0.1, "j", 0.0)
    assert 90 <= delays[0] <= 110


@pytest.mark.asyncio
async def test_a_job_that_raises_keeps_its_schedule(sched, caplog, monkeypatch):
    """The only reason a failing refresh does not silently stop refreshing.

    `_loop` floors its delay at one second, so the sleep is stubbed rather than
    waited out — three real seconds of a test suite to observe two ticks is a
    flake waiting for a loaded machine.
    """
    runs = []

    async def job():
        runs.append(1)
        if len(runs) >= 3:
            sched._running = False
        raise RuntimeError("network down")

    async def no_wait(_delay):
        await _yield()

    monkeypatch.setattr("trench.gravity.schedule.asyncio.sleep", no_wait)
    sched._running = True
    await sched._loop(60, job, 0.0, "flaky", 0.0)
    assert len(runs) == 3, "the job stopped after its first failure"
    assert any("scheduled job flaky failed" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_an_offset_delays_the_first_tick(sched):
    """Used to stagger memory-hungry jobs across forked workers so they never
    rebuild at the same moment."""
    ran = []

    async def job():
        ran.append(1)

    sched.every(0.1, job, jitter=0, name="staggered", offset=3)
    await asyncio.sleep(1.3)
    assert ran == []


@pytest.mark.asyncio
async def test_stop_cancels_everything_and_clears_the_table(sched):
    async def job():
        pass

    sched.every(60, job, name="a")
    sched.every(60, job, name="b")
    sched.stop()
    await asyncio.sleep(0)
    assert sched._tasks == {}
    assert sched.running("a") is False


@pytest.mark.asyncio
async def test_a_job_cancelled_mid_run_does_not_log_a_failure(sched, caplog):
    started = asyncio.Event()

    async def job():
        started.set()
        await asyncio.sleep(60)

    sched.every(0.1, job, jitter=0, name="slow")
    await asyncio.wait_for(started.wait(), timeout=5)
    sched.stop()
    await asyncio.sleep(0.05)
    assert not any("failed" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_stopping_between_ticks_ends_the_loop(sched):
    ran = []

    async def job():
        ran.append(1)

    sched.every(0.1, job, jitter=0, name="j")
    task = sched._tasks["j"]
    sched._running = False           # the flag alone must end it at the next check
    await asyncio.sleep(1.3)
    assert ran == []
    task.cancel()
