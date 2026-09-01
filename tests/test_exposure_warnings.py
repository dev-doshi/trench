"""Startup warnings for a listener that is open to the network.

The shipped config is loopback-only, where none of these settings matter.
Every real deployment changes `host`, and the setting that should change with
it lives elsewhere in the file — so these warnings are the only thing standing
between "serve the LAN" and an unrated open resolver.
"""
from __future__ import annotations

import logging

import pytest

from trench.app import App
from trench.config import Config


def _warnings(caplog, mutate) -> str:
    cfg = Config()
    mutate(cfg)
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        App(cfg)._warn_about_exposure()
    return "\n".join(r.getMessage() for r in caplog.records)


def test_shipped_defaults_warn_about_nothing(caplog):
    # Loopback, rate limiting off: correct, and must stay quiet or the
    # warnings become noise people learn to ignore.
    assert _warnings(caplog, lambda c: None) == ""


def test_lan_do53_without_rate_limit_warns(caplog):
    def lan(c):
        c.server.do53.host = "0.0.0.0"
        c.server.do53.port = 53
    out = _warnings(caplog, lan)
    assert "rate_limit" in out and "amplification" in out


def test_lan_do53_with_rate_limit_is_quiet(caplog):
    def lan(c):
        c.server.do53.host = "0.0.0.0"
        c.security.rate_limit = 100
    assert "rate_limit" not in _warnings(caplog, lan)


def test_exposed_console_without_tls_warns(caplog):
    def web(c):
        c.web.host = "0.0.0.0"
        c.web.tls = False
    out = _warnings(caplog, web)
    assert "TLS" in out


def test_exposed_console_with_tls_is_quiet(caplog):
    def web(c):
        c.web.host = "0.0.0.0"
        c.web.tls = True
    assert _warnings(caplog, web) == ""


def test_disabled_listeners_are_not_warned_about(caplog):
    def off(c):
        c.server.do53.enabled = False
        c.server.do53.host = "0.0.0.0"
        c.web.enabled = False
        c.web.host = "0.0.0.0"
    assert _warnings(caplog, off) == ""


@pytest.mark.parametrize("host,exposed", [
    ("127.0.0.1", False), ("localhost", False), ("::1", False),
    ("0.0.0.0", True), ("192.168.1.10", True), ("::", True),
    ("", False),
])
def test_loopback_detection(host, exposed):
    assert App._is_exposed(host) is exposed
