"""A restart must not serve a table built from lists the config no longer names.

Startup maps the compiled table instead of re-parsing a million domains, as
long as it is younger than the refresh interval. It never asked what the table
had been built *from*: editing `filtering.sources` in the file and restarting
kept the old lists for up to a day. Found on the live box, where a new set of
22 lists sat unapplied behind "mapped cached block table ... 12.4 h old".

The table also only holds the default corpus. Address lists and filtering
groups live beside it in memory, so a restart that mapped the table silently
dropped both until the next scheduled refresh.
"""
from __future__ import annotations

import pytest

from trench.app import App
from trench.config import Config
from trench.filter import Action


def _app(tmp_path, sources, **filtering):
    return App(Config.model_validate({
        "data_dir": str(tmp_path),
        "server": {"do53": {"enabled": False}},
        "web": {"enabled": False},
        "querylog": {"enabled": False},
        "cache": {"persist": False},
        "filtering": {"sources": [str(s) for s in sources], **filtering},
    }))


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


@pytest.mark.asyncio
async def test_changing_the_sources_rebuilds_instead_of_serving_the_old_table(tmp_path):
    a = _write(tmp_path, "a.txt", "||ads.example.com^\n")
    b = _write(tmp_path, "b.txt", "||casino.example.com^\n")
    assert await _app(tmp_path, [a]).load_blocklists() is False

    app = _app(tmp_path, [a, b])
    # Offline first, as startup does: the table no longer matches, so a fetch
    # is owed rather than the old table being declared good enough.
    assert await app.load_blocklists(allow_fetch=False) is True
    assert await app.load_blocklists() is False
    assert app.filter.match("casino.example.com").action == Action.BLOCK
    assert app.filter.match("ads.example.com").action == Action.BLOCK


@pytest.mark.asyncio
async def test_the_same_sources_still_reuse_the_table(tmp_path):
    a = _write(tmp_path, "a.txt", "||ads.example.com^\n")
    assert await _app(tmp_path, [a]).load_blocklists() is False
    a.write_text("||other.example.com^\n")      # content, not configuration
    app = _app(tmp_path, [a])
    assert await app.load_blocklists(allow_fetch=False) is False
    assert app.filter.match("ads.example.com").action == Action.BLOCK


@pytest.mark.asyncio
async def test_a_table_from_before_fingerprints_is_rebuilt_once(tmp_path):
    a = _write(tmp_path, "a.txt", "||ads.example.com^\n")
    assert await _app(tmp_path, [a]).load_blocklists() is False
    (tmp_path / "gravity.table.json").unlink()   # as every table built so far
    app = _app(tmp_path, [a])
    assert await app.load_blocklists(allow_fetch=False) is True


@pytest.mark.asyncio
async def test_groups_survive_a_restart_on_the_cached_table(tmp_path):
    a = _write(tmp_path, "a.txt", "||ads.example.com^\n")
    g = _write(tmp_path, "g.txt", "||social.example.com^\n")
    groups = {"kids": {"sources": [str(g)], "inherit": True}}
    assert await _app(tmp_path, [a], groups=groups).load_blocklists() is False

    app = _app(tmp_path, [a], groups=groups)
    pending = await app.load_blocklists(allow_fetch=False)
    if pending:
        await app.load_blocklists()
    kids = app.pipeline.group_filters.get("kids")
    assert kids is not None, "the group was dropped on restart"
    assert kids.match("social.example.com").action == Action.BLOCK
    assert kids.match("ads.example.com").action == Action.BLOCK


@pytest.mark.asyncio
async def test_address_lists_survive_a_restart_on_the_cached_table(tmp_path):
    a = _write(tmp_path, "a.txt", "||ads.example.com^\n")
    ips = _write(tmp_path, "ips.txt", "203.0.113.7\n")
    assert await _app(tmp_path, [a], ip_sources=[str(ips)]).load_blocklists() is False

    app = _app(tmp_path, [a], ip_sources=[str(ips)])
    pending = await app.load_blocklists(allow_fetch=False)
    if pending:
        await app.load_blocklists()
    assert app.filter.ips.match("203.0.113.7"), "the address list was dropped on restart"
