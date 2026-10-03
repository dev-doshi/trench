"""The job board: what ran, how it went, and running it again by hand.

Before it, a scheduled job that failed left a traceback in the container log and
nothing anywhere an operator would look; a refresh that kept the old rules
because one source was down looked, from the console, like a refresh that had
worked.
"""
from __future__ import annotations

import asyncio

import aiohttp
import pytest
from support import api_app, shutdown_api

from trench.gravity.schedule import Scheduler
from trench.jobs import JobBoard


@pytest.mark.asyncio
async def test_a_run_records_its_outcome_and_what_it_said():
    board = JobBoard()
    async with board.track("sweep"):
        JobBoard.note("42 rows")
    st = board.jobs["sweep"]
    assert (st.result, st.detail, st.runs, st.running) == ("ok", "42 rows", 1, False)
    assert st.duration is not None and st.duration >= 0


@pytest.mark.asyncio
async def test_a_failure_is_counted_and_explained_and_still_raised():
    board = JobBoard()
    with pytest.raises(ValueError):
        async with board.track("sweep"):
            raise ValueError("disk full")
    st = board.jobs["sweep"]
    assert (st.result, st.failures) == ("failed", 1)
    assert "disk full" in st.detail


@pytest.mark.asyncio
async def test_a_job_that_tracks_itself_inside_a_tracked_run_is_recorded_once():
    """The scheduled refresh calls `refresh_blocklists`, which tracks itself
    because SIGHUP and the console reach it too."""
    board = JobBoard()
    async with board.track("refresh"), board.track("refresh", "request"):
        JobBoard.note("applied", result="kept")
    st = board.jobs["refresh"]
    assert (st.runs, st.result, st.trigger) == (1, "kept", "schedule")


@pytest.mark.asyncio
async def test_a_second_caller_does_not_overwrite_the_run_in_progress():
    board = JobBoard()
    release = asyncio.Event()

    async def first():
        async with board.track("refresh"):
            JobBoard.note("building")
            await release.wait()

    t = asyncio.ensure_future(first())
    await asyncio.sleep(0)
    async with board.track("refresh", "request"):
        JobBoard.note("skipped", result="skipped")
    assert board.jobs["refresh"].detail == "building"
    assert board.jobs["refresh"].running
    release.set()
    await t
    assert board.jobs["refresh"].runs == 1


@pytest.mark.asyncio
async def test_run_now_refuses_a_job_that_is_already_running():
    board = JobBoard()
    gate = asyncio.Event()
    calls = 0

    async def job():
        nonlocal calls
        calls += 1
        await gate.wait()

    board.register("refresh", job)
    assert board.run_now("refresh") is True
    assert board.run_now("refresh") is False, "a double click started two builds"
    await asyncio.sleep(0.01)
    gate.set()
    for _ in range(50):
        if not board.busy("refresh"):
            break
        await asyncio.sleep(0.01)
    assert calls == 1 and board.jobs["refresh"].trigger == "console"
    assert board.jobs["refresh"].result == "ok"


@pytest.mark.asyncio
async def test_the_scheduler_reports_ticks_and_the_next_one():
    board = JobBoard()
    sched = Scheduler(board)
    ran = asyncio.Event()

    async def job():
        JobBoard.note("swept")
        ran.set()

    sched.every(1.0, job, jitter=0.0, name="sweep")
    assert board.jobs["sweep"].interval == 1.0
    await asyncio.wait_for(ran.wait(), 5)
    await asyncio.sleep(0.01)
    st = board.jobs["sweep"]
    assert st.detail == "swept" and st.runs >= 1 and st.next_at is not None
    sched.cancel("sweep")
    assert board.jobs["sweep"].next_at is None
    assert board.jobs["sweep"].to_json()["runnable"], "cancelled jobs can still be run by hand"
    sched.stop()


@pytest.fixture
async def api(tmp_path):
    app, base = await api_app(tmp_path)
    sess = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    await sess.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
    yield app, base, sess
    await sess.close()
    await shutdown_api(app)


@pytest.mark.asyncio
async def test_the_console_can_see_and_run_the_jobs(api, monkeypatch):
    app, base, s = api
    done = asyncio.Event()

    async def fake_refresh():
        JobBoard.note("1,000 domains from 2 sources (+10)")
        done.set()

    monkeypatch.setattr(app, "refresh_blocklists", fake_refresh)
    async with s.post(f"{base}/api/v1/jobs/gravity-refresh/run") as r:
        assert r.status == 200
    await asyncio.wait_for(done.wait(), 5)
    await asyncio.sleep(0.01)
    async with s.get(f"{base}/api/v1/jobs") as r:
        body = await r.json()
    job = {j["name"]: j for j in body["jobs"]}["gravity-refresh"]
    assert job["result"] == "ok" and job["trigger"] == "console"
    assert job["detail"].startswith("1,000 domains")
    assert "memory" in body and "sources" in body
    assert set(body["cpu"]) == {"percent", "cores", "container"}
    async with s.get(f"{base}/api/v1/audit") as r:
        audit = (await r.json())["audit"]
    assert any(a["action"] == "job.run" and a["target"] == "gravity-refresh"
               and "detail" in a for a in audit)


@pytest.mark.asyncio
async def test_an_unknown_job_is_a_404_not_a_crash(api):
    _, base, s = api
    async with s.post(f"{base}/api/v1/jobs/nope/run") as r:
        assert r.status == 404


@pytest.mark.asyncio
async def test_reload_from_the_console_runs_the_sighup_path_once(api, monkeypatch):
    app, base, s = api
    gate, calls = asyncio.Event(), []

    async def fake_reload():
        calls.append(1)
        await gate.wait()

    monkeypatch.setattr(app, "_reload", fake_reload)
    async with s.post(f"{base}/api/v1/reload") as r:
        assert r.status == 200
    async with s.post(f"{base}/api/v1/reload") as r:
        assert r.status == 409
    gate.set()
    for _ in range(50):
        if not app.jobs.busy("reload"):
            break
        await asyncio.sleep(0.01)
    assert calls == [1]
    assert app.jobs.jobs["reload"].result == "ok"


@pytest.mark.asyncio
async def test_a_refresh_that_had_nothing_to_do_does_not_say_done(api):
    app, base, s = api
    app._gravity = None
    async with s.post(f"{base}/api/v1/jobs/gravity-refresh/run") as r:
        assert r.status == 200
    for _ in range(50):
        if not app.jobs.busy("gravity-refresh"):
            break
        await asyncio.sleep(0.01)
    st = app.jobs.jobs["gravity-refresh"]
    assert st.result == "skipped" and "no blocklists" in st.detail


def test_cpu_is_a_share_of_the_box_since_the_last_look(monkeypatch):
    from trench import jobs
    clock = iter([100.0, 110.0, 110.01])
    used = iter([(1_000_000, True), (6_000_000, True), (6_000_000, True)])
    monkeypatch.setattr(jobs.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(jobs, "_cpu_usec", lambda: next(used))
    monkeypatch.setattr(jobs, "_cores", lambda: 2.0)
    jobs.cpu()                                  # sets the baseline
    r = jobs.cpu()                              # 5 CPU-seconds over 10s on 2 cores
    assert r == {"percent": 25.0, "cores": 2.0, "container": True}
    assert jobs.cpu()["percent"] is None        # too soon to say anything
