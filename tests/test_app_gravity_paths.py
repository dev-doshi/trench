"""The blocklist load/refresh paths and the remaining applier branches.

These are the decisions that keep a resolver serving when something upstream is
wrong: the cached-table reuse, the build lock that stops two 300 MB compiles at
once, the refusal to swap in a corpus that lost a source, and the contract check
that treats a bad list update as a bad deploy.
"""
from __future__ import annotations

import asyncio

import pytest

from trench.app import App
from trench.config import Config


def _cfg(tmp_path, **over):
    data = {"data_dir": str(tmp_path),
            "server": {"do53": {"enabled": False}},
            "web": {"enabled": False},
            "querylog": {"enabled": False},
            "cache": {"persist": False}}
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(data.get(k), dict):
            data[k] = {**data[k], **v}
        else:
            data[k] = v
    return Config.model_validate(data)


def _list_app(tmp_path, text="||ads.example.com^\n", **over):
    """An App whose only blocklist source is a local file. `text=None` reuses
    whatever the file already holds, so a second App can be pointed at a list
    the first one has since rewritten."""
    src = tmp_path / "list.txt"
    if text is not None:
        src.write_text(text)
    filtering = {"sources": [str(src)]}
    filtering.update(over.pop("filtering", {}))
    return App(_cfg(tmp_path, filtering=filtering, **over)), src


# --- the cached table ---
@pytest.mark.asyncio
async def test_a_fresh_cached_table_is_mapped_rather_than_rebuilt(tmp_path):
    app, src = _list_app(tmp_path)
    assert await app.load_blocklists() is False
    assert (tmp_path / "gravity.table").exists()

    src.write_text("||different.example.com^\n")
    app2, _ = _list_app(tmp_path, text=None)
    assert await app2.load_blocklists() is False
    from trench.filter import Action
    assert app2.filter.match("ads.example.com").action == Action.BLOCK
    assert app2.filter.match("different.example.com").action == Action.NONE


@pytest.mark.asyncio
async def test_a_corrupt_cached_table_is_rebuilt_not_fatal(tmp_path, caplog):
    app, src = _list_app(tmp_path)
    await app.load_blocklists()
    (tmp_path / "gravity.table").write_bytes(b"not a block table")

    app2, _ = _list_app(tmp_path, text=None)
    await app2.load_blocklists()
    from trench.filter import Action
    assert app2.filter.match("ads.example.com").action == Action.BLOCK
    assert any("unusable" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_a_stale_table_is_rebuilt_by_the_primary(tmp_path):
    import os
    app, src = _list_app(tmp_path, gravity={"refresh_hours": 24})
    await app.load_blocklists()
    table = tmp_path / "gravity.table"
    old = os.stat(table).st_mtime - 10 * 24 * 3600
    os.utime(table, (old, old))

    src.write_text("||different.example.com^\n")
    app2, _ = _list_app(tmp_path, text=None, gravity={"refresh_hours": 24})
    assert await app2.load_blocklists() is False
    from trench.filter import Action
    assert app2.filter.match("different.example.com").action == Action.BLOCK


@pytest.mark.asyncio
async def test_a_sibling_worker_uses_a_stale_table_rather_than_rebuilding(tmp_path):
    """One worker per machine downloads and compiles; the rest map the result,
    because a compiled copy per worker is what gets a small box OOM-killed."""
    import os
    app, src = _list_app(tmp_path, gravity={"refresh_hours": 24})
    await app.load_blocklists()
    table = tmp_path / "gravity.table"
    old = os.stat(table).st_mtime - 10 * 24 * 3600
    os.utime(table, (old, old))

    src.write_text("||different.example.com^\n")
    worker = App(_cfg(tmp_path, filtering={"sources": [str(src)]},
                      gravity={"refresh_hours": 24}),
                 primary=False, worker_idx=1, nworkers=2)
    assert await worker.load_blocklists() is False
    from trench.filter import Action
    assert worker.filter.match("ads.example.com").action == Action.BLOCK


@pytest.mark.asyncio
async def test_the_offline_pass_reports_that_a_fetch_is_owed(tmp_path):
    app, _ = _list_app(tmp_path)
    assert await app.load_blocklists(allow_fetch=False) is True


# --- the build lock ---
@pytest.mark.asyncio
async def test_two_refreshes_at_once_run_one_build(tmp_path, caplog):
    """The refresh schedule, a settings change and SIGHUP are three ways in,
    none of which knew about the others; two builds at once is the OOM."""
    import logging
    caplog.set_level(logging.INFO)
    app, _ = _list_app(tmp_path)
    await app.load_blocklists()
    started = asyncio.Event()
    release = asyncio.Event()
    builds = []

    async def slow_build():
        builds.append(1)
        started.set()
        await release.wait()
        return app.filter

    app._gravity.build = slow_build
    first = asyncio.ensure_future(app.refresh_blocklists())
    await asyncio.wait_for(started.wait(), timeout=5)
    await app.refresh_blocklists()              # returns immediately
    assert builds == [1]
    assert any("already running" in r.getMessage() for r in caplog.records)
    release.set()
    await asyncio.wait_for(first, timeout=5)


@pytest.mark.asyncio
async def test_a_refresh_without_any_sources_does_nothing(tmp_path):
    app = App(_cfg(tmp_path))
    assert app._gravity is None
    await app.refresh_blocklists()              # must not raise
    await app._refresh_locked()


@pytest.mark.asyncio
async def test_a_worker_refresh_only_remaps_the_table(tmp_path):
    """Only one worker per machine downloads and compiles."""
    app, _ = _list_app(tmp_path)
    await app.load_blocklists()
    worker = App(_cfg(tmp_path, filtering={"sources": [str(tmp_path / "list.txt")]}),
                 primary=False, worker_idx=1, nworkers=2)
    await worker.load_blocklists(allow_fetch=False)
    built = []

    async def never():
        built.append(1)

    worker._gravity.build = never
    remapped = []
    worker.adopt_refreshed_table = lambda: remapped.append(1) or False
    await worker.refresh_blocklists()
    assert built == [] and remapped == [1]


# --- a refresh that would lose rules ---
@pytest.mark.asyncio
async def test_a_refresh_that_lost_a_source_keeps_the_previous_rules(tmp_path,
                                                                     caplog):
    """A transient outage used to silently unblock every domain of every failing
    list, and rewrite the table so the next restart served the gap too."""
    app, _ = _list_app(tmp_path)
    await app.load_blocklists()
    before = app.filter
    from trench.filter import FilterEngine
    empty = FilterEngine.compile([])

    async def failed_build():
        app._gravity.report = type("R", (), {"errors": ["list.txt: timed out"]})()
        return empty

    app._gravity.build = failed_build
    await app.refresh_blocklists()
    assert app.filter is before
    assert any("kept the previous rules" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_a_first_load_adopts_even_a_contract_violating_corpus(tmp_path,
                                                                    caplog):
    """At first load there is nothing to fall back to: no rules at all is worse
    than a set the operator is told about."""
    import logging
    caplog.set_level(logging.ERROR)
    app, _ = _list_app(tmp_path,
                       filtering={"assertions": ["never.blocked.example must block"]})
    await app.load_blocklists()
    assert app.filter is not None
    assert app.contract_failures
    assert any("violate this configuration" in r.getMessage() for r in caplog.records)


# --- adopt_refreshed_table ---
@pytest.mark.asyncio
async def test_adopting_is_a_no_op_when_the_table_has_not_moved(tmp_path):
    app, _ = _list_app(tmp_path)
    await app.load_blocklists()
    assert app.adopt_refreshed_table() is False


@pytest.mark.asyncio
async def test_adopting_without_a_shared_table_is_a_no_op(tmp_path):
    app = App(_cfg(tmp_path))
    assert app.adopt_refreshed_table() is False


@pytest.mark.asyncio
async def test_a_table_that_cannot_be_reopened_is_reported_not_fatal(tmp_path,
                                                                     caplog):
    app, _ = _list_app(tmp_path)
    await app.load_blocklists()
    class AlwaysStale:
        nbytes = 0

        def stale(self):
            return True

        def __len__(self):
            return 0

    app.filter.block_table = AlwaysStale()
    (tmp_path / "gravity.table").write_bytes(b"garbage")
    assert app.adopt_refreshed_table() is False
    assert any("could not adopt" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_a_replaced_table_is_adopted_and_flushes_the_cache(tmp_path):
    app, src = _list_app(tmp_path)
    await app.load_blocklists()
    flushed = []
    real_flush = app.cache.flush
    app.cache.flush = lambda: flushed.append(1) or real_flush()

    # A second App writes a new table under the same path.
    src.write_text("||other.example.com^\n")
    writer, _ = _list_app(tmp_path, text=None)
    writer._gravity = writer._make_gravity(writer.config.filtering.sources)
    await writer._gravity.build()

    class AlwaysStale:
        nbytes = 0

        def stale(self):
            return True

        def __len__(self):
            return 0

    app.filter.block_table = AlwaysStale()
    assert app.adopt_refreshed_table() is True
    assert flushed == [1]
    from trench.filter import Action
    assert app.filter.match("other.example.com").action == Action.BLOCK


# --- the list-update review ---
@pytest.mark.asyncio
async def test_a_review_failure_is_logged_not_raised(tmp_path, caplog, monkeypatch):
    """The review is a report, not a gate: it must never fail a refresh."""
    app, _ = _list_app(tmp_path, querylog={"enabled": True})
    await app.setup_storage()
    try:
        async def boom(before, after, querylog):
            raise RuntimeError("querylog unreadable")

        monkeypatch.setattr("trench.analyze.review_from_querylog", boom)
        await app._record_list_review(None, app.filter)
        assert any("could not review" in r.getMessage() for r in caplog.records)
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_no_review_is_recorded_without_a_query_log(tmp_path):
    app, _ = _list_app(tmp_path)
    app.querylog = None
    await app._record_list_review(None, app.filter)     # must not raise


# --- pipeline applier branches ---
@pytest.mark.asyncio
async def test_dns_cookies_can_be_turned_on_and_off(tmp_path):
    app = App(_cfg(tmp_path, security={"dns_cookies": True}))
    await app.setup_storage()
    try:
        await app._adopt_pipeline()
        assert app.pipeline.cookies is not None
        first = app.pipeline.cookies
        await app._adopt_pipeline()
        assert app.pipeline.cookies is first, "the jar must survive a re-apply"
        app.config.security.dns_cookies = False
        await app._adopt_pipeline()
        assert app.pipeline.cookies is None
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_the_fast_path_reaches_the_frontends_both_ways(tmp_path):
    app = App(_cfg(tmp_path, server={"fast_path": True}))
    await app.setup_storage()

    class Frontend:
        fast = None

        async def stop(self):
            pass

    fe = Frontend()
    app.frontends.append(fe)
    try:
        # Start from off, so the applier has to build it with the frontend
        # already registered.
        app.fast = None
        app.pipeline.fast = None
        await app._adopt_fastpath()
        assert app.fast is not None and fe.fast is app.fast
        assert app.cache.on_flush is not None
        app.config.server.fast_path = False
        await app._adopt_fastpath()
        assert app.fast is None and fe.fast is None
        assert app.cache.on_flush is None
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_the_export_is_rebuilt_only_when_its_path_changes(tmp_path):
    first = tmp_path / "one.ndjson"
    second = tmp_path / "two.ndjson"
    app = App(_cfg(tmp_path, querylog={"enabled": True, "export": str(first)}))
    await app.setup_storage()
    try:
        exporter = app.querylog.export
        assert exporter is not None
        await app._adopt_querylog()
        assert app.querylog.export is exporter, "an unchanged path must not churn"
        app.config.querylog.export = str(second)
        await app._adopt_querylog()
        assert app.querylog.export is not exporter
        assert app.querylog.export.path == str(second)
    finally:
        await app.stop()


# --- warnings that only fire as root ---
def test_running_as_root_without_a_target_user_warns(tmp_path, monkeypatch, caplog):
    import trench.app as appmod
    monkeypatch.setattr(appmod.os, "geteuid", lambda: 0)
    app = App(_cfg(tmp_path, server={"do53": {"enabled": True, "host": "0.0.0.0"}},
                   security={"rate_limit": 100}))
    app._warn_about_exposure()
    assert any("shed them" in r.getMessage() for r in caplog.records)


def test_dnssec_in_forward_mode_is_reported_as_inert(tmp_path, caplog):
    app = App(_cfg(tmp_path, upstream={"dnssec": True, "mode": "forward"}))
    app._warn_about_inert_settings()
    assert any("validated only when resolving from the root" in r.getMessage()
               for r in caplog.records)


def test_a_block_page_without_custom_ip_is_reported_as_inert(tmp_path, caplog):
    app = App(_cfg(tmp_path, filtering={"block_page": True, "block_mode": "nxdomain"}))
    app._warn_about_inert_settings()
    assert any("custom_ip" in r.getMessage() for r in caplog.records)


def test_a_consistent_configuration_warns_about_nothing(tmp_path, caplog):
    app = App(_cfg(tmp_path, upstream={"dnssec": True, "mode": "recursive"},
                   filtering={"block_page": True, "block_mode": "custom_ip"}))
    app._warn_about_inert_settings()
    assert [r for r in caplog.records if r.levelname == "WARNING"] == []


# --- trust anchors ---
def test_an_anchor_file_with_nothing_usable_falls_back_to_the_pins(tmp_path,
                                                                   caplog):
    anchors = tmp_path / "root.key"
    anchors.write_text("; nothing usable in here\n")
    app = App(_cfg(tmp_path, upstream={"mode": "recursive", "dnssec": True,
                                       "trust_anchors": str(anchors)}))
    assert app is not None
    assert any("built-in pins" in r.getMessage() for r in caplog.records)


# --- multi-worker shared counters ---
def test_a_worker_attaches_to_the_shared_counter_segment(tmp_path):
    from trench.stats.shared import SharedScalars
    shm = str(tmp_path / "stats.shm")
    SharedScalars.create(shm, 2)
    app = App(_cfg(tmp_path), worker_idx=1, nworkers=2, shm_path=shm)
    app.counters.record(client="10.0.0.1", qname="a.example.com", qtype="A",
                        action="forwarded")
    assert app.counters.snapshot()["total"] >= 1


# --- DHCP lease registration ---
def test_a_lease_publishes_a_name_and_drops_the_recorded_negative(tmp_path):
    """A name asked for before its lease existed was answered NXDOMAIN, and a
    recorded copy would replay that for the whole negative TTL."""
    app = App(_cfg(tmp_path, server={"fast_path": True}))
    from trench.clients.names import HostNames
    app.hostnames = HostNames(domain="lan", network="192.168.1.0/24")
    cleared = []

    class FakeFast:
        def forget(self, name):
            cleared.append(name)

        def clear(self):
            cleared.append("*")

    app.fast = FakeFast()
    app.on_lease("192.168.1.50", "laptop")
    assert app.hostnames.ip_for("laptop.lan") == "192.168.1.50"
    assert app.hostnames.name_for("192.168.1.50") == "laptop.lan"
    assert cleared


def test_a_lease_without_dns_registration_is_harmless(tmp_path):
    app = App(_cfg(tmp_path))
    app.hostnames = None
    app.on_lease("192.168.1.50", "laptop")      # must not raise
