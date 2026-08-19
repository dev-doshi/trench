"""Startup must bind before it touches the network.

The blocklist sources are https:// URLs, and on the usual deployment this box
is the LAN's resolver. Fetching them before the listener is up means resolving
a hostname through a server that has not bound its socket yet — the whole
network waits for DNS that cannot arrive.
"""
from __future__ import annotations

import pytest

from dnsguard.app import App
from dnsguard.config import Config


def _app(tmp_path, sources):
    cfg = Config()
    cfg.data_dir = str(tmp_path)
    cfg.server.do53.enabled = False
    cfg.web.enabled = False
    cfg.filtering.sources = list(sources)
    return App(cfg)


@pytest.mark.asyncio
async def test_offline_pass_reports_a_fetch_is_still_owed(tmp_path):
    app = _app(tmp_path, ["https://example.invalid/list.txt"])
    # No cached table and no pre-forked engine: the only way to honour these
    # sources is a download, which this pass must decline to do.
    assert await app.load_blocklists(allow_fetch=False) is True


@pytest.mark.asyncio
async def test_offline_pass_does_not_reach_the_network(tmp_path, monkeypatch):
    app = _app(tmp_path, ["https://example.invalid/list.txt"])

    async def explode(*a, **k):
        raise AssertionError("startup fetched before the listener was bound")

    monkeypatch.setattr("dnsguard.gravity.manager.Gravity.build", explode)
    assert await app.load_blocklists(allow_fetch=False) is True


@pytest.mark.asyncio
async def test_no_sources_owes_nothing(tmp_path):
    app = _app(tmp_path, [])
    assert await app.load_blocklists(allow_fetch=False) is False
    assert await app.load_blocklists() is False
