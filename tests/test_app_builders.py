"""What the App builds from config, and what the appliers do when it changes.

These are the branches a settings change or a SIGHUP walks: upstream groups,
authoritative zones, local records, zone-transfer policy, the log export, the
notary, and the error paths where one of them fails and must not take the
resolver down with it.
"""
from __future__ import annotations

import asyncio

import pytest

from trench.app import App
from trench.config import Config
from trench.wire.name import Name
from trench.wire.rrtypes import Type


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


# --- upstream groups ---
def test_a_group_gets_its_own_forwarder(tmp_path):
    app = App(_cfg(tmp_path, upstream={"groups": {"kids": ["1.1.1.3", "1.0.0.3"]}}))
    assert set(app.forwarders) == {"kids"}
    assert app.forwarders["kids"] is not app.forwarder


def test_a_group_is_a_forwarder_even_in_recursive_mode(tmp_path):
    """Naming a group means "send those clients there"; going to the root
    instead would ignore the instruction."""
    app = App(_cfg(tmp_path, upstream={"mode": "recursive",
                                       "groups": {"office": ["10.0.0.1"]}}))
    from trench.resolver.forwarder import Forwarder
    assert isinstance(app.forwarders["office"], Forwarder)


def test_an_empty_group_is_ignored_with_a_warning(tmp_path, caplog):
    app = App(_cfg(tmp_path, upstream={"groups": {"broken": []}}))
    assert app.forwarders == {}
    assert any("no servers" in r.getMessage() for r in caplog.records)


def test_no_groups_means_no_group_forwarders(tmp_path):
    assert App(_cfg(tmp_path)).forwarders == {}


# --- zones and local records ---
ZONEFILE = """\
$ORIGIN example.test.
$TTL 3600
@   IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 604800 3600
@   IN NS  ns.example.test.
ns  IN A   192.0.2.1
www IN A   192.0.2.2
"""


def test_a_zone_file_is_loaded(tmp_path):
    zf = tmp_path / "example.test.zone"
    zf.write_text(ZONEFILE)
    app = App(_cfg(tmp_path, zones=[{"origin": "example.test.", "file": str(zf)}]))
    zone = app.zones.authoritative_for(Name.from_text("www.example.test."))
    assert zone is not None
    assert int(Type.A) in zone.records[Name.from_text("www.example.test.")]


def test_a_zone_without_a_file_is_created_empty(tmp_path):
    app = App(_cfg(tmp_path, zones=[{"origin": "empty.test."}]))
    assert app.zones.authoritative_for(Name.from_text("empty.test.")) is not None


def test_a_named_file_that_is_missing_still_yields_a_zone(tmp_path):
    app = App(_cfg(tmp_path, zones=[{"origin": "gone.test.",
                                     "file": str(tmp_path / "nope.zone")}]))
    assert app.zones.authoritative_for(Name.from_text("gone.test.")) is not None


def test_a_signed_zone_gets_dnssec_records(tmp_path, caplog):
    import logging
    caplog.set_level(logging.INFO)
    zf = tmp_path / "signed.zone"
    zf.write_text(ZONEFILE)
    app = App(_cfg(tmp_path, zones=[{"origin": "example.test.", "file": str(zf),
                                     "dnssec": True}]))
    zone = app.zones.authoritative_for(Name.from_text("example.test."))
    apex = zone.records[Name.from_text("example.test.")]
    assert int(Type.DNSKEY) in apex
    assert any("signed zone" in r.getMessage() for r in caplog.records)


def test_a_signed_nsec3_zone_with_a_salt(tmp_path):
    zf = tmp_path / "signed3.zone"
    zf.write_text(ZONEFILE)
    app = App(_cfg(tmp_path, zones=[{"origin": "example.test.", "file": str(zf),
                                     "dnssec": True, "nsec3": True,
                                     "nsec3_salt": "abcd", "nsec3_iterations": 1}]))
    zone = app.zones.authoritative_for(Name.from_text("example.test."))
    assert any(int(Type.NSEC3PARAM) in node for node in zone.records.values())


@pytest.mark.parametrize("rtype,answer", [
    ("A", "192.0.2.10"), ("AAAA", "2001:db8::10"),
    ("CNAME", "real.example.test."), ("TXT", "hello"),
])
def test_local_records_of_every_supported_type(tmp_path, rtype, answer):
    app = App(_cfg(tmp_path, local_records=[{"name": "pin.example.test.",
                                             "type": rtype, "answer": answer}]))
    zone = app.zones.authoritative_for(Name.from_text("pin.example.test."))
    assert zone is not None
    from trench.wire.rrtypes import type_from_text
    assert int(type_from_text(rtype)) in zone.records[Name.from_text("pin.example.test.")]


def test_a_local_record_of_an_unsupported_type_is_dropped(tmp_path):
    app = App(_cfg(tmp_path, local_records=[{"name": "srv.example.test.",
                                             "type": "SRV", "answer": "0 0 1 x."}]))
    assert app.zones.authoritative_for(Name.from_text("srv.example.test.")) is None


# --- the authoritative transaction handler ---
def test_a_pure_resolver_builds_no_auth_handler(tmp_path):
    """The hot path stays untouched when nothing enables a zone transaction."""
    app = App(_cfg(tmp_path, zones=[{"origin": "quiet.test."}]))
    assert app.auth is None


def test_allow_transfer_builds_a_handler_with_the_policy(tmp_path):
    app = App(_cfg(tmp_path,
                   tsig_keys=[{"name": "xfr-key.", "algorithm": "hmac-sha256.",
                               "secret": "c2VjcmV0LWtleS1tYXRlcmlhbC0zMi1ieXRlcyE="}],
                   zones=[{"origin": "example.test.",
                           "allow_transfer": ["192.0.2.0/24"],
                           "tsig_key": "xfr-key."}]))
    assert app.auth is not None
    assert "xfr-key." in app.auth.keyring


def test_allow_update_alone_builds_a_handler(tmp_path):
    app = App(_cfg(tmp_path, zones=[{"origin": "example.test.",
                                     "allow_update": ["127.0.0.1"]}]))
    assert app.auth is not None


def test_a_secondary_zone_builds_a_handler_and_registers_itself(tmp_path):
    app = App(_cfg(tmp_path, secondaries=[{"origin": "sec.test.",
                                           "primary": "192.0.2.53"}]))
    assert app.auth is not None
    assert app.auth.secondaries


def test_a_secondary_can_name_a_tsig_key(tmp_path):
    app = App(_cfg(tmp_path,
                   tsig_keys=[{"name": "xfr-key.", "algorithm": "hmac-sha256.",
                               "secret": "c2VjcmV0LWtleS1tYXRlcmlhbC0zMi1ieXRlcyE="}],
                   secondaries=[{"origin": "sec.test.", "primary": "192.0.2.53",
                                 "tsig_key": "xfr-key."}]))
    sec = next(iter(app.auth.secondaries.values()))
    assert sec.key is not None


# --- managed clients ---
@pytest.mark.asyncio
async def test_database_managed_clients_are_merged_with_the_config(tmp_path):
    app = App(_cfg(tmp_path, clients=[{"ident": "10.0.0.1", "name": "from-config"}]))
    await app.setup_storage()
    try:
        await app.db.execute(
            "INSERT INTO client(ident, ident_type, name, comment, policy)"
            " VALUES(?,?,?,?,?)", ("10.0.0.2", "ip", "from-db", "", "{}"))
        await app.reload_clients()
        assert "10.0.0.1" in app.clients.exact
        assert "10.0.0.2" in app.clients.exact
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_a_broken_client_table_does_not_stop_the_resolver(tmp_path, caplog):
    app = App(_cfg(tmp_path, clients=[{"ident": "10.0.0.1", "name": "from-config"}]))
    await app.setup_storage()
    try:
        async def boom(*a, **kw):
            raise RuntimeError("table is corrupt")

        app.db.fetchall = boom
        await app.reload_clients()
        assert "10.0.0.1" in app.clients.exact       # the config half survived
        assert any("managed clients" in r.getMessage() for r in caplog.records)
    finally:
        await app.stop()


# --- the log export ---
@pytest.mark.asyncio
async def test_no_export_path_means_no_exporter(tmp_path):
    app = App(_cfg(tmp_path, querylog={"enabled": True, "export": ""}))
    await app.setup_storage()
    try:
        assert app._build_log_export() is None
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_an_export_path_builds_a_json_lines_stream(tmp_path):
    out = tmp_path / "querylog.ndjson"
    app = App(_cfg(tmp_path, querylog={"enabled": True, "export": str(out)}))
    await app.setup_storage()
    try:
        exporter = app._build_log_export()
        assert exporter is not None and exporter.path == str(out)
        exporter.close()
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_a_worker_without_a_database_never_exports(tmp_path):
    """Only the process that writes the table exports; a per-worker export
    would emit the same query twice from one machine."""
    app = App(_cfg(tmp_path, querylog={"enabled": True,
                                       "export": str(tmp_path / "x.ndjson")}))
    await app.setup_storage()
    db, app.db = app.db, None
    try:
        assert app._build_log_export() is None
    finally:
        await app.stop()
        await db.close()


# --- the notary ---
@pytest.mark.asyncio
async def test_the_notary_is_off_without_pinned_names(tmp_path):
    app = App(_cfg(tmp_path))
    await app.setup_storage()
    try:
        await app._adopt_notary()
        assert app.notary is None
        assert not app.scheduler.running("notary")
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_pinned_names_arm_the_notary(tmp_path):
    app = App(_cfg(tmp_path, security={"notary": ["bank.example.com"],
                                       "notary_interval": 3600}))
    await app.setup_storage()
    try:
        await app._adopt_notary()
        assert app.notary is not None
        assert app.scheduler.running("notary")
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_a_worker_does_not_run_the_notary(tmp_path):
    app = App(_cfg(tmp_path, security={"notary": ["bank.example.com"],
                                       "notary_interval": 3600}),
              primary=False, nworkers=2)
    await app.setup_storage()
    try:
        await app._adopt_notary()
        assert app.notary is None
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_a_notary_round_follows_the_live_forwarder_and_audits(tmp_path):
    """A notary holding a retired forwarder would be asking servers nothing
    else uses."""
    app = App(_cfg(tmp_path, security={"notary": ["bank.example.com"],
                                       "notary_interval": 3600}))
    await app.setup_storage()
    try:
        await app._adopt_notary()

        class Finding:
            name = "bank.example.com"
            note = "answers disagreed"

        class FakeNotary:
            forwarder = None

            async def run_once(self):
                return [Finding()]

        app.notary = FakeNotary()
        sentinel = object()
        app.forwarder = sentinel
        await app._notary_round()
        assert app.notary.forwarder is sentinel
        rows = await app.db.fetchall("SELECT action, target FROM audit")
        assert [dict(r) for r in rows] == [{"action": "notary",
                                            "target": "bank.example.com"}]
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_a_notary_round_without_a_notary_is_a_no_op(tmp_path):
    app = App(_cfg(tmp_path))
    app.notary = None
    await app._notary_round()


# --- audit robustness ---
@pytest.mark.asyncio
async def test_an_audit_failure_is_logged_not_raised(tmp_path, caplog):
    app = App(_cfg(tmp_path))
    await app.setup_storage()
    try:
        async def boom(*a, **kw):
            raise RuntimeError("disk full")

        app.db.execute = boom
        await app._audit("test", "target", "detail")
        assert any("audit record" in r.getMessage() for r in caplog.records)
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_auditing_without_a_database_is_a_no_op(tmp_path):
    app = App(_cfg(tmp_path))
    app.db = None
    await app._audit("test", "target", "detail")


# --- the scheduled update tick ---
@pytest.mark.asyncio
async def test_an_update_check_failure_does_not_kill_the_job(tmp_path, caplog):
    app = App(_cfg(tmp_path))

    class Boom:
        async def tick(self):
            raise RuntimeError("github unreachable")

    app.updater = Boom()
    await app._update_tick()
    assert any("scheduled update check failed" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_a_cancelled_update_tick_propagates(tmp_path):
    app = App(_cfg(tmp_path))

    class Cancelled:
        async def tick(self):
            raise asyncio.CancelledError

    app.updater = Cancelled()
    with pytest.raises(asyncio.CancelledError):
        await app._update_tick()


@pytest.mark.asyncio
async def test_an_update_tick_without_an_updater_is_a_no_op(tmp_path):
    app = App(_cfg(tmp_path))
    app.updater = None
    await app._update_tick()


# --- appliers that toggle a subsystem ---
@pytest.mark.asyncio
async def test_the_prewarm_sweep_is_armed_and_disarmed(tmp_path):
    app = App(_cfg(tmp_path, cache={"prewarm": True, "prewarm_interval": 300}))
    await app.setup_storage()
    try:
        await app._adopt_prewarm()
        assert app.learn is not None and app.scheduler.running("prewarm")
        app.config.cache.prewarm = False
        await app._adopt_prewarm()
        assert app.learn is None and not app.scheduler.running("prewarm")
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_a_worker_learns_but_does_not_sweep(tmp_path):
    app = App(_cfg(tmp_path, cache={"prewarm": True}), primary=False, nworkers=2)
    await app.setup_storage()
    try:
        await app._adopt_prewarm()
        assert app.learn is not None
        assert not app.scheduler.running("prewarm")
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_adopting_the_upstream_closes_the_retired_forwarders(tmp_path):
    app = App(_cfg(tmp_path, upstream={"groups": {"kids": ["1.1.1.3"]}}))
    await app.setup_storage()
    try:
        closed = []
        for f in (app.forwarder, app.forwarders["kids"]):
            f.close = (lambda tag: (lambda: closed.append(tag)))(id(f))
        await app._adopt_upstream()
        assert len(closed) == 2
        assert app.forwarder is not None and "kids" in app.forwarders
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_a_forwarder_that_fails_to_close_does_not_break_the_swap(tmp_path,
                                                                      caplog):
    app = App(_cfg(tmp_path))
    await app.setup_storage()
    try:
        async def boom():
            raise OSError("socket already gone")

        app.forwarder.close = boom
        await app._adopt_upstream()
        assert app.forwarder is not None
        assert any("previous upstreams" in r.getMessage() for r in caplog.records)
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_an_applier_that_raises_is_logged_and_the_rest_still_run(tmp_path,
                                                                      caplog):
    app = App(_cfg(tmp_path))
    await app.setup_storage()
    try:
        ran = []

        async def boom():
            raise RuntimeError("applier exploded")

        async def ok():
            ran.append(1)

        app.adopters = lambda: {"a": boom, "b": ok}
        import trench.api.settings as st
        real = st.adopters_for
        st.adopters_for = lambda changed: ["a", "b"]
        try:
            await app.apply_config(["something"])
        finally:
            st.adopters_for = real
        assert ran == [1]
        assert any("could not adopt" in r.getMessage() for r in caplog.records)
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_a_config_file_that_stops_parsing_is_not_adopted(tmp_path, caplog):
    cfg_file = tmp_path / "trench.yaml"
    cfg_file.write_text(f"data_dir: {tmp_path}\nlog:\n  level: info\n")
    app = App(_cfg(tmp_path), config_path=str(cfg_file))
    await app.setup_storage()
    try:
        before = app.config
        cfg_file.write_text("server:\n  do53:\n    port: not-a-number\n")
        await app.apply_config()
        assert app.config is before
        assert any("keeping current" in r.getMessage() for r in caplog.records)
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_reapplying_a_config_keeps_the_runtime_only_dhcp_flag(tmp_path):
    cfg_file = tmp_path / "trench.yaml"
    cfg_file.write_text(f"data_dir: {tmp_path}\nlog:\n  level: info\n")
    app = App(_cfg(tmp_path, allow_dhcp=True), config_path=str(cfg_file))
    await app.setup_storage()
    try:
        await app.apply_config(["log.level"])
        assert app.config.allow_dhcp is True
    finally:
        await app.stop()
