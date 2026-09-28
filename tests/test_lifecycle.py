"""Startup failures must be fatal, not swallowed."""
from __future__ import annotations

import asyncio

import pytest

from trench.config import Config
from trench.errors import TrenchError


class FailingApp:
    """Stands in for App: `run()` raises the way privilege-drop refusal does."""

    def __init__(self, boom: Exception | None = None):
        self.boom = boom
        self.stopped = False
        self.config = Config()

    async def run(self) -> None:
        if self.boom is not None:
            raise self.boom
        await asyncio.sleep(3600)

    async def stop(self) -> None:
        self.stopped = True


async def drive(app, stop_after: float = 0.0) -> None:
    """The body of `_amain` after the App is built, in miniature."""
    from trench.__main__ import _await_startup_or_stop

    stop = asyncio.Event()
    if stop_after:
        asyncio.get_running_loop().call_later(stop_after, stop.set)
    await _await_startup_or_stop(app, stop, worker_idx=0)


@pytest.mark.asyncio
async def test_a_startup_failure_propagates_and_still_stops_the_app():
    """The refusal to run as root has to actually refuse: bound listeners keep
    answering otherwise, and systemd sees a healthy process."""
    app = FailingApp(TrenchError("refusing to run as root"))
    with pytest.raises(TrenchError, match="refusing to run as root"):
        await drive(app)
    assert app.stopped


@pytest.mark.asyncio
async def test_a_normal_shutdown_is_not_an_error():
    app = FailingApp()
    await drive(app, stop_after=0.01)
    assert app.stopped


@pytest.mark.asyncio
async def test_run_returning_early_is_treated_as_a_shutdown(caplog):
    """`App.run()` is not supposed to return. If it does, stop — do not sit in
    a loop with nothing listening."""
    class EarlyApp(FailingApp):
        async def run(self) -> None:
            return

    app = EarlyApp()
    await drive(app)                      # no exception
    assert app.stopped


@pytest.mark.asyncio
async def test_the_runner_is_cancelled_on_shutdown():
    """A live `run()` task left behind keeps the listeners it owns open."""
    cancelled = asyncio.Event()

    class SlowApp(FailingApp):
        async def run(self) -> None:
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                cancelled.set()
                raise

    app = SlowApp()
    await drive(app, stop_after=0.01)
    await asyncio.sleep(0)
    assert cancelled.is_set()
    assert app.stopped


# --- _amain: signal wiring around the App ---
class RecordingApp(FailingApp):
    def __init__(self):
        super().__init__()
        self.reloads = 0
        self.release = asyncio.Event()

    async def run(self) -> None:
        await asyncio.sleep(3600)

    async def reload(self) -> None:
        self.reloads += 1
        await self.release.wait()


@pytest.mark.asyncio
async def test_amain_installs_stop_and_hup_handlers(monkeypatch):
    import signal

    from trench import __main__ as M

    app = RecordingApp()
    monkeypatch.setattr("trench.app.App", lambda *a, **kw: app)
    task = asyncio.ensure_future(M._amain(Config(), config_path=None))
    await asyncio.sleep(0.05)
    loop = asyncio.get_running_loop()

    # SIGINT/SIGTERM stop the process; SIGHUP reloads it.
    handlers_ok = True
    try:
        loop.remove_signal_handler(signal.SIGHUP)
    except NotImplementedError:      # pragma: no cover
        handlers_ok = False
    assert handlers_ok

    # Signal the stop path directly rather than raising a real SIGINT at the
    # test runner.
    os_kill = __import__("os").kill
    os_kill(__import__("os").getpid(), signal.SIGTERM)
    await asyncio.wait_for(task, timeout=5)
    assert app.stopped


@pytest.mark.asyncio
async def test_a_second_hup_while_a_reload_runs_is_ignored(monkeypatch):
    """Two concurrent blocklist rebuilds peak at hundreds of MB each, on a box
    with an OOM history."""
    import os
    import signal

    from trench import __main__ as M

    app = RecordingApp()
    monkeypatch.setattr("trench.app.App", lambda *a, **kw: app)
    task = asyncio.ensure_future(M._amain(Config(), config_path=None))
    await asyncio.sleep(0.05)

    os.kill(os.getpid(), signal.SIGHUP)
    await asyncio.sleep(0.05)
    os.kill(os.getpid(), signal.SIGHUP)
    await asyncio.sleep(0.05)
    assert app.reloads == 1

    # Once it finishes, the next HUP is honoured again.
    app.release.set()
    await asyncio.sleep(0.05)
    os.kill(os.getpid(), signal.SIGHUP)
    await asyncio.sleep(0.05)
    assert app.reloads == 2

    os.kill(os.getpid(), signal.SIGINT)
    await asyncio.wait_for(task, timeout=5)
