"""Pytest configuration.

The tests directory itself goes on `sys.path` so suites can import `support`,
which holds fixtures-free helpers shared between them.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


import logging  # noqa: E402

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _keep_the_trench_logger_capturable():
    """Undo `log.setup`'s effect on the `trench` logger after every test.

    `setup` sets `propagate = False` and installs its own stderr handler, which
    is right for a daemon and wrong for a test session: once any test calls it —
    directly, or through `__main__.main` — pytest's `caplog` silently stops
    seeing anything the package logs, and the failures land in unrelated suites
    much later in the run.
    """
    root = logging.getLogger("trench")
    handlers, level, propagate = list(root.handlers), root.level, root.propagate
    yield
    root.handlers = handlers
    root.setLevel(level)
    root.propagate = propagate


@pytest.fixture(autouse=True)
def _no_leaked_database_threads():
    """Fail the test that leaves an aiosqlite connection open.

    aiosqlite runs each connection on a worker thread that is not a daemon, so
    one unclosed connection anywhere in the suite keeps the interpreter from
    exiting after the last test: every test passes and the run hangs until the
    CI job times out, with nothing naming the culprit. Checked per test, the
    failure lands on the test that leaked.
    """
    import threading

    before = set(threading.enumerate())
    yield
    leaked = [t for t in threading.enumerate()
              if t not in before and "_connection_worker_thread" in t.name]
    for t in leaked:
        t.join(timeout=2)
    leaked = [t for t in leaked if t.is_alive()]
    if leaked:
        pytest.fail(f"{len(leaked)} aiosqlite connection(s) left open; close them "
                    "(or restore the attribute holding one) before the test ends",
                    pytrace=False)
