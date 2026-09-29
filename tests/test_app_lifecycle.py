"""`App.run`/`start`/`stop`: what actually binds, in what order, and what is
torn down.

The App is the object every deployment runs and its start-up path was almost
entirely untested — which listeners come up on a worker versus the primary, the
privilege drop that happens only once the privileged ports are bound, the
scheduled jobs, and the shutdown that has to persist the cache and close the
database even when a frontend fails to stop.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket

import pytest
from support import free_port

from trench.app import App, release_free_memory
from trench.config import Config
from trench.errors import TrenchError


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


async def _run(app):
    """Start the App the way `_amain` does and wait until it is fully serving.

    The readiness signal is the ratelimit reaper: `_schedule_jobs` arms it after
    every listener is bound, so waiting on it cannot race a half-started App the
    way "are there any frontends yet" can.
    """
    task = asyncio.ensure_future(app.run())
    for _ in range(500):
        await asyncio.sleep(0.01)
        if task.done() or app.scheduler.running("ratelimit-gc"):
            break
    if task.done() and task.exception():
        raise task.exception()
    assert app.scheduler.running("ratelimit-gc"), "the App never finished starting"
    return task


async def _shutdown(app, task):
    await app.stop()
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


# --- what binds ---
@pytest.mark.asyncio
async def test_do53_comes_up_and_answers(tmp_path):
    """A blocked name, so the answer is decided locally: this is testing that
    the listener is bound and wired to the pipeline, not that the box has a
    working upstream."""
    port = free_port()
    app = App(_cfg(tmp_path,
                   server={"do53": {"enabled": True, "host": "127.0.0.1",
                                    "port": port}},
                   filtering={"deny": ["blocked.example.com"],
                              "block_mode": "nxdomain"}))
    task = await _run(app)
    try:
        from trench.transport.do53 import Do53Server
        assert any(isinstance(f, Do53Server) for f in app.frontends)
        from trench.wire import Class, Message, Question, Type
        from trench.wire.name import Name
        from trench.wire.rrtypes import Rcode
        q = Message(id=0x4242)
        q.set_flag(0x0100, True)
        q.questions.append(Question(Name.from_text("blocked.example.com"),
                                    Type.A, Class.IN))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.sendto(q.to_wire(), ("127.0.0.1", port))
            # In a thread: a blocking recv on this loop would stop the server
            # that is meant to answer it.
            data, _ = await asyncio.to_thread(sock.recvfrom, 4096)
        finally:
            sock.close()
        resp = Message.parse(data)
        assert resp.id == 0x4242 and resp.rcode == Rcode.NXDOMAIN
    finally:
        await _shutdown(app, task)


@pytest.mark.asyncio
async def test_do53_can_be_bound_tcp_only(tmp_path):
    port = free_port()
    app = App(_cfg(tmp_path, server={"do53": {"enabled": True, "port": port,
                                              "udp": False}}))
    task = await _run(app)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass                                    # the TCP half accepted
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", port))         # the UDP half was never taken
        finally:
            probe.close()
    finally:
        await _shutdown(app, task)


@pytest.mark.asyncio
async def test_the_admin_console_comes_up_when_enabled(tmp_path):
    port = free_port()
    app = App(_cfg(tmp_path, web={"enabled": True, "port": port,
                                  "admin_password": "pw"}))
    task = await _run(app)
    try:
        assert app.api is not None
        import aiohttp
        async with aiohttp.ClientSession() as s, \
                s.get(f"http://127.0.0.1:{port}/healthz") as r:
            assert r.status == 200
    finally:
        await _shutdown(app, task)


@pytest.mark.asyncio
async def test_the_console_is_not_started_without_a_database(tmp_path):
    app = App(_cfg(tmp_path, web={"enabled": True, "port": free_port()}))
    await app.setup_storage()
    db, app.db = app.db, None
    await app.start()
    try:
        assert app.api is None
    finally:
        await app.stop()
        await db.close()


@pytest.mark.asyncio
async def test_the_block_page_server_comes_up(tmp_path):
    port = free_port()
    app = App(_cfg(tmp_path, filtering={"block_page": True, "block_page_port": port,
                                        "block_mode": "custom_ip"}))
    task = await _run(app)
    try:
        from trench.web.blockpage import BlockPageServer
        assert any(isinstance(f, BlockPageServer) for f in app.frontends)
    finally:
        await _shutdown(app, task)


@pytest.mark.asyncio
async def test_dot_and_doh_come_up_with_a_self_signed_certificate(tmp_path):
    dot_port, doh_port = free_port(), free_port()
    app = App(_cfg(tmp_path, server={"do53": {"enabled": False},
                                     "dot": {"enabled": True, "port": dot_port},
                                     "doh": {"enabled": True, "port": doh_port}}))
    task = await _run(app)
    try:
        names = {type(f).__name__ for f in app.frontends}
        assert {"DoTServer", "DoHServer"} <= names
        # The certificate was minted on demand, into the data dir.
        assert (tmp_path / "certs" / "trench.crt").exists()
    finally:
        await _shutdown(app, task)


@pytest.mark.asyncio
async def test_doq_and_doh3_come_up(tmp_path):
    doq_port, doh3_port = free_port(), free_port()
    app = App(_cfg(tmp_path, server={"do53": {"enabled": False},
                                     "doq": {"enabled": True, "port": doq_port},
                                     "doh3": {"enabled": True, "port": doh3_port}}))
    task = await _run(app)
    try:
        names = {type(f).__name__ for f in app.frontends}
        assert {"DoQServer", "DoH3Server"} <= names
    finally:
        await _shutdown(app, task)


@pytest.mark.asyncio
async def test_dhcp_refuses_to_bind_without_the_explicit_flag(tmp_path):
    """Three gates guard :67; handing out leases on a real LAN by accident is
    not recoverable by restarting."""
    app = App(_cfg(tmp_path, dhcp={
        "enabled": True, "register_dns": True,
        "scope": {"network": "192.168.9.0/24", "range_start": "192.168.9.100",
                  "range_end": "192.168.9.200", "router": "192.168.9.1",
                  "domain": "lan"}}))
    await app.setup_storage()
    with pytest.raises(TrenchError, match="allow-dhcp"):
        await app.start()
    # The DNS-registration side was still wired up before the refusal.
    assert app.hostnames is not None
    await app.stop()


@pytest.mark.asyncio
async def test_dhcp_is_refused_in_dev_mode(tmp_path):
    app = App(_cfg(tmp_path, dev=True, allow_dhcp=True, dhcp={
        "enabled": True,
        "scope": {"network": "192.168.9.0/24", "range_start": "192.168.9.100",
                  "range_end": "192.168.9.200", "router": "192.168.9.1"}}))
    await app.setup_storage()
    with pytest.raises(TrenchError, match="dev mode"):
        await app.start()
    await app.stop()


# --- primary versus worker ---
@pytest.mark.asyncio
async def test_a_secondary_worker_binds_do53_and_nothing_else(tmp_path):
    """Do53 runs in every worker; the console, the encrypted transports and the
    scheduler belong to the primary alone."""
    port = free_port()
    app = App(_cfg(tmp_path, server={"do53": {"enabled": True, "port": port}},
                   web={"enabled": True, "port": free_port(), "admin_password": "pw"}),
              primary=False, worker_idx=1, nworkers=2)
    await app.setup_storage()
    await app.start()
    try:
        assert app.api is None
        assert [type(f).__name__ for f in app.frontends] == ["Do53Server"]
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_sibling_workers_poll_the_primary_for_changes(tmp_path):
    app = App(_cfg(tmp_path), primary=False, worker_idx=1, nworkers=2)
    await app.setup_storage()
    await app._schedule_jobs()
    try:
        assert app.scheduler.running("worker-sync")
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_the_primary_arms_the_ratelimit_reaper(tmp_path):
    """The limiter keys on the client address: without a reaper a spoofed-source
    flood grows the table until the box is OOM-killed."""
    app = App(_cfg(tmp_path))
    await app.setup_storage()
    await app._schedule_jobs()
    try:
        assert app.scheduler.running("ratelimit-gc")
        assert not app.scheduler.running("worker-sync")
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_reaping_the_ratelimiter_calls_gc(tmp_path):
    app = App(_cfg(tmp_path))
    await app.setup_storage()
    calls = []

    class RL:
        def gc(self):
            calls.append(1)

    app.pipeline.ratelimiter = RL()
    await app._reap_ratelimiter()
    assert calls == [1]
    app.pipeline.ratelimiter = None
    await app._reap_ratelimiter()          # must not raise
    await app.stop()


# --- the privilege drop ---
@pytest.mark.asyncio
async def test_no_privilege_target_is_a_no_op(tmp_path):
    app = App(_cfg(tmp_path))
    app._maybe_drop_privileges()           # must not raise, must not call out


@pytest.mark.asyncio
async def test_a_failed_privilege_drop_refuses_to_run(tmp_path, monkeypatch):
    """Bound listeners keep answering otherwise, and systemd sees a healthy
    process."""
    from trench.security.privdrop import PrivDropError
    app = App(_cfg(tmp_path, server={"user": "trench"}))

    def boom(user, group):
        raise PrivDropError("setgroups failed")

    monkeypatch.setattr("trench.security.privdrop.drop_privileges", boom)
    with pytest.raises(PrivDropError):
        app._maybe_drop_privileges()


@pytest.mark.asyncio
async def test_the_drop_happens_after_the_ports_are_bound(tmp_path, monkeypatch):
    """Binding :53 needs root; keeping root afterwards does not. The drop is the
    last thing `start` does for exactly that reason."""
    port = free_port()
    app = App(_cfg(tmp_path, server={"user": "trench",
                                     "do53": {"enabled": True, "port": port}}))
    bound_at_drop: list[bool] = []

    def note(user, group):
        bound_at_drop.append(bool(app.frontends))
        return True

    monkeypatch.setattr("trench.security.privdrop.drop_privileges", note)
    await app.setup_storage()
    await app.start()
    try:
        assert bound_at_drop == [True]
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_a_worker_sheds_root_too(tmp_path, monkeypatch):
    dropped = []
    monkeypatch.setattr("trench.security.privdrop.drop_privileges",
                        lambda u, g: dropped.append((u, g)) or True)
    app = App(_cfg(tmp_path, server={"user": "trench", "do53": {"enabled": False}}),
              primary=False, nworkers=2)
    await app.setup_storage()
    await app.start()
    await app.stop()
    assert dropped == [("trench", None)]


# --- TLS material selection ---
@pytest.mark.asyncio
async def test_an_explicit_certificate_pair_always_wins(tmp_path):
    app = App(_cfg(tmp_path))
    assert app._tls_material("/etc/my.crt", "/etc/my.key") == ("/etc/my.crt", "/etc/my.key")


@pytest.mark.asyncio
async def test_an_acme_certificate_is_used_when_there_is_no_explicit_one(tmp_path):
    app = App(_cfg(tmp_path))

    class FakeAcme:
        cert_file = tmp_path / "acme.crt"
        key_file = tmp_path / "acme.key"

    FakeAcme.cert_file.write_text("cert")
    FakeAcme.key_file.write_text("key")
    app.acme = FakeAcme()
    cert, key = app._tls_material(None, None)
    assert cert == str(FakeAcme.cert_file) and key == str(FakeAcme.key_file)


@pytest.mark.asyncio
async def test_without_acme_the_transports_self_sign(tmp_path):
    app = App(_cfg(tmp_path))
    app.acme = None
    assert app._tls_material(None, None) == (None, None)


@pytest.mark.asyncio
async def test_a_half_present_acme_pair_is_not_used(tmp_path):
    app = App(_cfg(tmp_path))

    class FakeAcme:
        cert_file = tmp_path / "half.crt"
        key_file = tmp_path / "half.key"

    FakeAcme.cert_file.write_text("cert")
    app.acme = FakeAcme()
    assert app._tls_material(None, None) == (None, None)


# --- stream limits ---
def test_stream_limits_come_from_the_config(tmp_path):
    app = App(_cfg(tmp_path, server={"tcp_idle_timeout": 3.5, "tcp_max_connections": 7,
                                     "tcp_max_per_client": 2, "tcp_max_inflight": 4}))
    limits = app._stream_limits()
    assert limits.idle_timeout == 3.5
    assert limits.max_connections == 7
    assert limits.max_per_client == 2
    assert limits.max_inflight == 4


# --- shutdown ---
@pytest.mark.asyncio
async def test_stop_persists_the_cache_when_configured(tmp_path):
    app = App(_cfg(tmp_path, cache={"persist": True}))
    await app.setup_storage()
    await app.stop()
    assert (tmp_path / "cache.json").exists()


@pytest.mark.asyncio
async def test_a_cache_dump_failure_does_not_break_shutdown(tmp_path, monkeypatch):
    app = App(_cfg(tmp_path, cache={"persist": True}))
    await app.setup_storage()
    monkeypatch.setattr(app.cache, "dump",
                        lambda p: (_ for _ in ()).throw(OSError("disk full")))
    await app.stop()                       # must not raise
    assert not (tmp_path / "cache.json").exists()


@pytest.mark.asyncio
async def test_a_frontend_that_fails_to_stop_does_not_skip_the_database(tmp_path):
    """SIGTERM must not become a traceback that drops 50k buffered log rows."""
    app = App(_cfg(tmp_path))
    await app.setup_storage()

    class Bad:
        async def stop(self):
            raise RuntimeError("socket already closed")

    closed = []
    real_close = app.db.close

    async def watched():
        closed.append(1)
        await real_close()

    app.db.close = watched
    app.frontends.append(Bad())
    await app.stop()
    assert closed == [1]


@pytest.mark.asyncio
async def test_a_failing_api_or_query_log_stop_still_closes_the_database(tmp_path):
    """aiosqlite's worker thread is not a daemon: a database left open by an
    exception earlier in stop() keeps the process alive after SIGTERM."""
    app = App(_cfg(tmp_path))
    await app.setup_storage()

    class Bad:
        async def stop(self):
            raise RuntimeError("boom")

    real_querylog = app.querylog
    app.api = Bad()
    app.querylog = Bad()
    await app.stop()                       # must not raise
    assert app.db._db is None
    if real_querylog is not None:
        await real_querylog.stop()


@pytest.mark.asyncio
async def test_stop_cancels_the_bootstrap_tasks(tmp_path):
    app = App(_cfg(tmp_path))
    await app.setup_storage()

    async def forever():
        await asyncio.sleep(3600)

    app._bootstrap = asyncio.ensure_future(forever())
    app._bootstrap_cert = asyncio.ensure_future(forever())
    await app.stop()
    await asyncio.sleep(0)
    assert app._bootstrap.cancelled() or app._bootstrap.done()
    assert app._bootstrap_cert.cancelled() or app._bootstrap_cert.done()


@pytest.mark.asyncio
async def test_stop_sets_the_stop_event_so_run_returns(tmp_path):
    app = App(_cfg(tmp_path))
    task = await _run(app)
    await app.stop()
    await asyncio.wait_for(task, timeout=5)


# --- run(): restore paths ---
@pytest.mark.asyncio
async def test_run_restores_a_persisted_cache(tmp_path):
    app = App(_cfg(tmp_path, cache={"persist": True}))
    await app.setup_storage()
    from trench.cache.cache import CacheKey
    from trench.wire import RR, Class, Message, Question, Type
    from trench.wire import rdata as R
    from trench.wire.name import Name
    from trench.wire.rrtypes import Rcode
    n = Name.from_text("kept.example.com")
    q = Message()
    q.questions.append(Question(n, Type.A, Class.IN))
    resp = q.reply(Rcode.NOERROR)
    resp.answers.append(RR(n, Type.A, Class.IN, 3600, R.A("192.0.2.9")))
    app.cache.put(CacheKey(n.key, int(Type.A), int(Class.IN), False), resp)
    await app.stop()

    app2 = App(_cfg(tmp_path, cache={"persist": True}))
    task = await _run(app2)
    try:
        assert app2.cache.size == 1
    finally:
        await _shutdown(app2, task)


@pytest.mark.asyncio
async def test_an_unreadable_cache_file_does_not_stop_start_up(tmp_path):
    (tmp_path / "cache.json").write_text("{not json")
    app = App(_cfg(tmp_path, cache={"persist": True}))
    task = await _run(app)
    try:
        assert app.cache.size == 0
    finally:
        await _shutdown(app, task)


@pytest.mark.asyncio
async def test_the_learned_popularity_file_round_trips(tmp_path):
    app = App(_cfg(tmp_path, cache={"prewarm": True}))
    await app.setup_storage()
    assert app.learn is not None, "cache.prewarm should build a popularity tracker"
    for _ in range(5):
        app.learn.note("popular.example.com")
    await app.stop()
    assert (tmp_path / "popularity.json").exists()
    assert json.loads((tmp_path / "popularity.json").read_text())

    # And it comes back on the next start.
    app2 = App(_cfg(tmp_path, cache={"prewarm": True}))
    task = await _run(app2)
    try:
        assert app2.learn is not None
        assert "popular.example.com" in app2.learn.scores
    finally:
        await _shutdown(app2, task)


@pytest.mark.asyncio
async def test_a_prewarm_sweep_without_a_learner_is_a_no_op(tmp_path):
    app = App(_cfg(tmp_path))
    await app.setup_storage()
    app.learn = None
    await app._prewarm_sweep()             # must not raise
    await app.stop()


# --- the cold-start blocklist fetch ---
@pytest.mark.asyncio
async def test_a_failed_cold_start_fetch_leaves_the_resolver_answering(tmp_path,
                                                                      monkeypatch):
    """Unfiltered is better than not answering at all; the scheduled refresh
    retries on its own interval."""
    app = App(_cfg(tmp_path))

    async def boom(**kw):
        raise RuntimeError("network down")

    monkeypatch.setattr(app, "load_blocklists", boom)
    await app._initial_blocklist_fetch()   # swallowed, not raised


@pytest.mark.asyncio
async def test_a_cancelled_cold_start_fetch_propagates(tmp_path, monkeypatch):
    app = App(_cfg(tmp_path))

    async def cancelled(**kw):
        raise asyncio.CancelledError

    monkeypatch.setattr(app, "load_blocklists", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await app._initial_blocklist_fetch()


@pytest.mark.asyncio
async def test_run_starts_the_background_fetch_when_a_source_is_pending(tmp_path,
                                                                       monkeypatch):
    src = tmp_path / "list.txt"
    src.write_text("||ads.example.com^\n")
    app = App(_cfg(tmp_path, filtering={"sources": [str(src)]}))
    task = await _run(app)
    try:
        assert app._bootstrap is not None
        await asyncio.wait_for(asyncio.shield(app._bootstrap), timeout=10)
        from trench.filter import Action
        assert app.filter.match("ads.example.com").action == Action.BLOCK
    finally:
        await _shutdown(app, task)


# --- ACME scheduling ---
@pytest.mark.asyncio
async def test_acme_that_cannot_run_is_reported_and_not_scheduled(tmp_path, caplog):
    app = App(_cfg(tmp_path, acme={"enabled": True, "domains": ["dns.example.org"]}))
    await app.setup_storage()
    if app.acme is None:
        pytest.skip("acme is not constructed in this configuration")
    await app._schedule_jobs()
    try:
        assert not app.scheduler.running("acme-renew")
        assert any("cannot run" in r.message for r in caplog.records)
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_renewing_without_acme_is_a_no_op(tmp_path):
    app = App(_cfg(tmp_path))
    app.acme = None
    await app._renew_certificates()


@pytest.mark.asyncio
async def test_acme_is_scheduled_and_bootstrapped_when_it_can_run(tmp_path):
    app = App(_cfg(tmp_path))
    await app.setup_storage()

    class FakeAcme:
        renewed = 0

        def reason_unavailable(self):
            return None

        def due(self):
            return True

        async def renew(self, *, force=False):
            FakeAcme.renewed += 1
            return True

    app.acme = FakeAcme()
    await app._schedule_jobs()
    try:
        assert app.scheduler.running("acme-renew")
        assert app._bootstrap_cert is not None
        await asyncio.wait_for(asyncio.shield(app._bootstrap_cert), timeout=5)
        assert FakeAcme.renewed == 1
    finally:
        await app.stop()


# --- worker sync ---
@pytest.mark.asyncio
async def test_the_first_look_at_the_config_records_rather_than_reapplies(tmp_path):
    cfg_file = tmp_path / "trench.yaml"
    cfg_file.write_text("log:\n  level: info\n")
    app = App(_cfg(tmp_path), config_path=str(cfg_file))
    await app.setup_storage()
    applied = []
    app.apply_config = lambda *a, **kw: applied.append(1)
    await app._adopt_changed_config()
    assert applied == [] and app._config_mtime is not None
    await app._adopt_changed_config()       # unchanged: still nothing
    assert applied == []
    await app.stop()


@pytest.mark.asyncio
async def test_a_rewritten_config_is_adopted_on_the_next_look(tmp_path):
    cfg_file = tmp_path / "trench.yaml"
    cfg_file.write_text("log:\n  level: info\n")
    app = App(_cfg(tmp_path), config_path=str(cfg_file))
    await app.setup_storage()
    await app._adopt_changed_config()       # records the mtime
    applied = []

    async def note(changed=None):
        applied.append(changed)

    app.apply_config = note
    os.utime(cfg_file, (0, 0))              # a different mtime is the whole signal
    await app._adopt_changed_config()
    assert applied == [None]
    await app.stop()


@pytest.mark.asyncio
async def test_a_worker_without_a_config_file_polls_nothing(tmp_path):
    app = App(_cfg(tmp_path))
    app.apply_config = lambda *a, **kw: pytest.fail("nothing to adopt")
    await app._adopt_changed_config()


@pytest.mark.asyncio
async def test_a_config_file_that_vanished_is_not_an_error(tmp_path):
    app = App(_cfg(tmp_path), config_path=str(tmp_path / "gone.yaml"))
    app.apply_config = lambda *a, **kw: pytest.fail("nothing to adopt")
    await app._adopt_changed_config()


@pytest.mark.asyncio
async def test_sync_with_primary_does_both_halves(tmp_path):
    app = App(_cfg(tmp_path), primary=False, worker_idx=1, nworkers=2)
    await app.setup_storage()
    seen = []
    app.adopt_refreshed_table = lambda: seen.append("table") or False

    async def adopt():
        seen.append("config")

    app._adopt_changed_config = adopt
    await app._sync_with_primary()
    assert seen == ["table", "config"]
    await app.stop()


# --- neighbours ---
@pytest.mark.asyncio
async def test_the_arp_refresh_is_only_armed_when_a_client_is_keyed_by_mac(tmp_path):
    app = App(_cfg(tmp_path))
    await app.setup_storage()
    await app._schedule_jobs()
    armed_without = app.scheduler.running("arp-refresh")
    await app.stop()

    app2 = App(_cfg(tmp_path, clients=[{"ident": "aa:bb:cc:dd:ee:ff",
                                        "type": "mac", "name": "phone"}]))
    await app2.setup_storage()
    await app2._schedule_jobs()
    try:
        assert not armed_without
        assert app2.scheduler.running("arp-refresh")
    finally:
        await app2.stop()


@pytest.mark.asyncio
async def test_a_neighbour_refresh_failure_is_swallowed(tmp_path, monkeypatch):
    """It shells out; a box without `ip neigh` must not raise every 30 seconds."""
    app = App(_cfg(tmp_path))
    monkeypatch.setattr("trench.clients.registry.refresh_neighbours",
                        lambda: (_ for _ in ()).throw(OSError("no such command")))
    await app._refresh_neighbours()


# --- the banner ---
@pytest.mark.asyncio
async def test_the_primary_banner_names_the_listener_and_upstream(tmp_path, caplog):
    import logging
    caplog.set_level(logging.INFO)
    app = App(_cfg(tmp_path, server={"do53": {"enabled": True, "port": 5399}}))
    await app.setup_storage()
    app._banner()
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "5399" in text and "upstream" in text and "blocked domains" in text
    await app.stop()


@pytest.mark.asyncio
async def test_a_worker_banner_names_its_index(tmp_path, caplog):
    import logging
    caplog.set_level(logging.INFO)
    app = App(_cfg(tmp_path), primary=False, worker_idx=2, nworkers=4)
    await app.setup_storage()
    app._banner()
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "worker 2/4" in text
    await app.stop()


# --- odds and ends ---
def test_release_free_memory_is_safe_to_call():
    release_free_memory()          # a no-op on platforms without malloc_trim
