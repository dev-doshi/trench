"""Logging setup: the two formatters and `setup`'s handler wiring.

`log.setup` is called once per process by `__main__`, so nothing in the suite
exercised it; the formatters that decide whether a traceback reaches the
operator were entirely untested.
"""
from __future__ import annotations

import io
import json
import logging

from trench import log


def _record(msg="hello", level=logging.INFO, name="trench.test", exc_info=None,
            stack_info=None, extra_fields=None):
    rec = logging.LogRecord(name, level, "f.py", 10, msg, None, exc_info)
    rec.stack_info = stack_info
    if extra_fields is not None:
        rec.extra_fields = extra_fields
    return rec


def _exc_info():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        return sys.exc_info()


def test_json_formatter_basic_fields():
    out = json.loads(log._JsonFormatter().format(_record("hi")))
    assert out["msg"] == "hi"
    assert out["level"] == "info"
    assert out["logger"] == "trench.test"
    assert isinstance(out["ts"], float)
    assert "exc" not in out


def test_json_formatter_renders_traceback_and_extra_fields():
    rec = _record("bad", level=logging.ERROR, exc_info=_exc_info(),
                  extra_fields={"qname": "example.com", "client": "10.0.0.1"})
    out = json.loads(log._JsonFormatter().format(rec))
    assert out["level"] == "error"
    assert "ValueError: boom" in out["exc"]
    assert out["qname"] == "example.com"
    assert out["client"] == "10.0.0.1"


def test_json_formatter_serialises_unjsonable_values():
    rec = _record("x", extra_fields={"obj": object()})
    out = json.loads(log._JsonFormatter().format(rec))
    assert isinstance(out["obj"], str)


def test_json_formatter_interpolates_args():
    rec = logging.LogRecord("trench.t", logging.WARNING, "f.py", 1, "a=%s b=%d",
                            ("x", 7), None)
    assert json.loads(log._JsonFormatter().format(rec))["msg"] == "a=x b=7"


def test_human_formatter_colours_known_levels():
    line = log._HumanFormatter().format(_record("hi", level=logging.WARNING))
    assert log._HumanFormatter.COLORS["WARNING"] in line
    assert log._HumanFormatter.RESET in line
    assert "WARN" in line and "trench.test: hi" in line


def test_human_formatter_unknown_level_has_no_colour():
    rec = _record("hi", level=logging.CRITICAL)
    line = log._HumanFormatter().format(rec)
    assert not line.startswith("\033")
    assert "CRIT" in line


def test_human_formatter_renders_traceback():
    # The regression this guards: `log.exception` used to lose the traceback
    # entirely in the default (non-JSON) configuration.
    line = log._HumanFormatter().format(_record("bad", exc_info=_exc_info()))
    assert "Traceback (most recent call last)" in line
    assert "ValueError: boom" in line


def test_human_formatter_renders_stack_info():
    line = log._HumanFormatter().format(_record("bad", stack_info="Stack (most recent call last):\n  here"))
    assert "Stack (most recent call last)" in line


def test_setup_replaces_handlers_and_sets_level():
    try:
        log.setup("debug")
        root = logging.getLogger("trench")
        assert root.level == logging.DEBUG
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, log._HumanFormatter)
        assert root.propagate is False
        # Called twice, one handler — not two.
        log.setup("warning", json_logs=True)
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, log._JsonFormatter)
        assert root.level == logging.WARNING
    finally:
        logging.getLogger("trench").handlers.clear()


def test_setup_unknown_level_falls_back_to_info():
    try:
        log.setup("not-a-level")
        assert logging.getLogger("trench").level == logging.INFO
    finally:
        logging.getLogger("trench").handlers.clear()


def test_setup_emits_through_the_installed_handler():
    try:
        log.setup("info", json_logs=True)
        buf = io.StringIO()
        logging.getLogger("trench").handlers[0].stream = buf
        log.get("unit").info("through")
        assert json.loads(buf.getvalue())["msg"] == "through"
    finally:
        logging.getLogger("trench").handlers.clear()


def test_get_namespaces_under_trench():
    assert log.get("filter").name == "trench.filter"
