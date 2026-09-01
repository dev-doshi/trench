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
