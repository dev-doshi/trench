"""The contract between the settings form and the running process.

A setting the console offers has to be one of three things: read live, adopted
by a named applier, or honestly marked as needing a restart. Anything else is a
change the operator is told was saved and which the resolver then ignores —
which is what eight of the nine Resolution settings did.

The first test is the structural half (every field declares a disposition, every
disposition is backed by real code). The rest are the behavioural half: for each
applier, save a setting the way the API saves it and check the running objects
actually moved.
"""
from __future__ import annotations

import pathlib

import pytest
import yaml

from trench.api import settings as st
from trench.app import App
from trench.config import Config


def _write(path: pathlib.Path, tree: dict) -> None:
    path.write_text(yaml.safe_dump(tree, sort_keys=False))


async def _app(tmp_path, tree: dict | None = None):
    """An App backed by a real config file, with every listener disabled."""
    base = {"data_dir": str(tmp_path),
            "server": {"do53": {"enabled": False}},
            "web": {"enabled": False}}
    for key, value in (tree or {}).items():
        base.setdefault(key, {})
        if isinstance(value, dict):
            base[key].update(value)
        else:
            base[key] = value
    path = tmp_path / "trench.yaml"
    _write(path, base)
    return App(Config.load(str(path)), config_path=str(path)), path


async def _save(app, path: pathlib.Path, changes: dict):
    """Apply `changes` exactly as `APIServer.settings_put` does."""
    tree = yaml.safe_load(path.read_text()) or {}
    for key, raw in changes.items():
        st.merge(tree, key, st.coerce(key, raw))
    Config.model_validate(tree)          # the API validates before writing
    _write(path, tree)
    await app.apply_config(list(changes))


# --------------------------------------------------------------- the contract

def test_every_field_declares_how_it_is_applied():
    for f in st.FIELDS:
        assert f.applies in ("live", "adopt", "restart"), f.path
        if f.applies == "adopt":
            assert f.adopter, f"{f.path} adopts but names no adopter"
            assert f.adopter in st.ADOPTERS, f"{f.path}: unknown adopter {f.adopter}"
        else:
            assert not f.adopter, f"{f.path} is {f.applies} but names an adopter"


def test_every_adopter_is_a_method_the_app_has(tmp_path):
    app = App(Config.model_validate({"data_dir": str(tmp_path),
                                     "server": {"do53": {"enabled": False}},
                                     "web": {"enabled": False}}))
    table = app.adopters()
    assert set(table) == set(st.ADOPTERS)
    for name, fn in table.items():
        assert callable(fn), name


def test_every_adopter_is_reachable_from_some_field():
    """An applier nothing names is dead code pretending to be a guarantee."""
    named = {f.adopter for f in st.FIELDS if f.applies == "adopt"}
    assert named == set(st.ADOPTERS)


def test_restart_is_derived_from_the_disposition():
    for f in st.FIELDS:
        assert f.restart is (f.applies == "restart"), f.path
    labels = st.needs_restart(["server.workers", "upstream.servers"])
    assert labels == ["Worker processes"]


# ------------------------------------------------------------------- adopters

@pytest.mark.asyncio
async def test_changing_the_upstream_reaches_the_running_forwarder(tmp_path):
    app, path = await _app(tmp_path, {"upstream": {"servers": ["1.1.1.1:53"],
                                                   "strategy": "parallel"}})
    before = app.forwarder
    assert [repr(u) for u in before.router.default] == ["udp://1.1.1.1:53"]

    await _save(app, path, {"upstream.servers": ["9.9.9.9:53"],
                            "upstream.strategy": "sequential"})

    assert app.forwarder is not before
    assert [repr(u) for u in app.forwarder.router.default] == ["udp://9.9.9.9:53"]
    assert app.forwarder.strategy == "sequential"
    # and the pipeline resolves through the new one, not the retired one
    assert app.pipeline.forwarder is app.forwarder
    assert st.needs_restart(["upstream.servers"]) == []


@pytest.mark.asyncio
async def test_switching_to_recursive_replaces_the_resolver(tmp_path):
    app, path = await _app(tmp_path)
    await _save(app, path, {"upstream.mode": "recursive"})
    assert type(app.forwarder).__name__ == "RecursiveForwarder"
    await _save(app, path, {"upstream.mode": "forward"})
    assert type(app.forwarder).__name__ == "Forwarder"


@pytest.mark.asyncio
async def test_the_default_client_policy_is_rebuilt(tmp_path):
    app, path = await _app(tmp_path, {"filtering": {"safe_search": False}})
    assert app.clients.identify("10.0.0.9", "").safe_search is False
    await _save(app, path, {"filtering.safe_search": True})
    assert app.clients.identify("10.0.0.9", "").safe_search is True
    assert app.pipeline.clients is app.clients


@pytest.mark.asyncio
async def test_the_fast_path_can_be_turned_on_and_off(tmp_path):
    app, path = await _app(tmp_path, {"server": {"fast_path": False}})
    assert app.fast is None

    await _save(app, path, {"server.fast_path": True})
    assert app.fast is not None
    assert app.pipeline.fast is app.fast
    assert app.cache.on_flush == app.fast.clear   # bound methods: equal, not identical

    await _save(app, path, {"server.fast_path": False})
    assert app.fast is None and app.pipeline.fast is None
    assert app.cache.on_flush is None


@pytest.mark.asyncio
async def test_the_query_log_starts_and_stops(tmp_path):
    app, path = await _app(tmp_path, {"querylog": {"enabled": False}})
    await app.setup_storage()
    assert app.querylog is None

    await _save(app, path, {"querylog.enabled": True})
    assert app.querylog is not None
    assert app.pipeline.querylog is app.querylog
    assert app.scheduler.running("retention")

    await _save(app, path, {"querylog.privacy_level": 2})
    assert app.querylog.privacy_level == 2

    await _save(app, path, {"querylog.enabled": False})
    assert app.querylog is None and app.pipeline.querylog is None
    assert not app.scheduler.running("retention")
    await app.db.close()


@pytest.mark.asyncio
async def test_the_refresh_interval_is_re_armed(tmp_path):
    app, path = await _app(tmp_path, {"filtering": {"sources": ["x.txt"]},
                                      "gravity": {"refresh_hours": 24}})
    await app._schedule_jobs()
    assert app.scheduler.running("gravity-refresh")

    await _save(app, path, {"gravity.refresh_hours": 0})
    assert not app.scheduler.running("gravity-refresh")

    await _save(app, path, {"gravity.refresh_hours": 6})
    assert app.scheduler.running("gravity-refresh")
    app.scheduler.stop()


@pytest.mark.asyncio
async def test_the_detectors_and_limiter_follow_the_settings(tmp_path):
    app, path = await _app(tmp_path)
    assert app.pipeline.dga is None and app.pipeline.tunnel is None

    await _save(app, path, {"security.dga_detection": True,
                            "security.tunnel_detection": True,
                            "security.rate_limit": 50.0,
                            "security.rate_burst": 100})
    assert app.pipeline.dga is not None and app.pipeline.tunnel is not None
    assert app.pipeline.ratelimiter.enabled

    await _save(app, path, {"security.dga_detection": False,
                            "security.tunnel_detection": False})
    assert app.pipeline.dga is None and app.pipeline.tunnel is None


@pytest.mark.asyncio
async def test_the_log_level_follows_the_setting(tmp_path):
    import logging
    app, path = await _app(tmp_path)
    await _save(app, path, {"log.level": "debug"})
    assert logging.getLogger("trench").level == logging.DEBUG
    await _save(app, path, {"log.level": "info"})
    assert logging.getLogger("trench").level == logging.INFO


@pytest.mark.asyncio
async def test_trusted_proxies_are_re_parsed_in_place(tmp_path):
    from trench.security.clientaddr import TrustedProxies
    app, path = await _app(tmp_path)

    # The object is shared with the aiohttp app key, which cannot be reassigned
    # once the application is running — so identity has to survive the change.
    trusted = TrustedProxies([])
    app.frontends.append(type("Fe", (), {"trusted": trusted})())
    assert "10.0.0.7" not in trusted

    await _save(app, path, {"security.trusted_proxies": ["10.0.0.0/24"]})
    assert "10.0.0.7" in trusted
    assert app.frontends[0].trusted is trusted


@pytest.mark.asyncio
async def test_a_live_setting_needs_no_applier_at_all(tmp_path):
    """`filtering.block_mode` is read per query, so swapping the tree is enough."""
    app, path = await _app(tmp_path, {"filtering": {"block_mode": "zero_ip"}})
    await _save(app, path, {"filtering.block_mode": "nxdomain"})
    assert app.config.filtering.block_mode == "nxdomain"
    assert app.pipeline.config is app.config


# ------------------------------------------------------- propagation to workers

@pytest.mark.asyncio
async def test_a_sibling_worker_picks_up_a_rewritten_config(tmp_path):
    """The console runs in the primary; the other workers are separate processes
    and their only channel is the file the primary rewrote."""
    app, path = await _app(tmp_path, {"upstream": {"servers": ["1.1.1.1:53"]}})
    app.primary, app.nworkers = False, 4

    await app._adopt_changed_config()          # first look only records the mtime
    assert [repr(u) for u in app.forwarder.router.default] == ["udp://1.1.1.1:53"]

    tree = yaml.safe_load(path.read_text())
    tree["upstream"]["servers"] = ["9.9.9.9:53"]
    _write(path, tree)
    import os
    stamp = os.stat(path).st_mtime + 1        # same-second writes must still count
    os.utime(path, (stamp, stamp))

    await app._sync_with_primary()
    assert [repr(u) for u in app.forwarder.router.default] == ["udp://9.9.9.9:53"]


@pytest.mark.asyncio
async def test_sibling_workers_schedule_the_sync_job(tmp_path):
    app, _ = await _app(tmp_path)
    app.primary, app.nworkers = False, 4
    await app._schedule_jobs()
    assert app.scheduler.running("worker-sync")
    app.scheduler.stop()


@pytest.mark.asyncio
async def test_the_primary_does_not_poll_itself(tmp_path):
    app, _ = await _app(tmp_path)
    app.nworkers = 4
    await app._schedule_jobs()
    assert not app.scheduler.running("worker-sync")
    app.scheduler.stop()


# ------------------------------------------------- the shipped configuration

def test_every_shipped_config_loads():
    """The example template is what people copy. It spent a long time not
    loading at all: `ecs: off` unquoted is a YAML 1.1 boolean, so the file the
    documentation points at failed validation on a type nobody wrote."""
    import pathlib

    import yaml
    root = pathlib.Path(__file__).resolve().parent.parent
    for name in ("trench.example.yaml", "trench.yaml", "deploy/raspi.yaml"):
        path = root / name
        if not path.exists():          # trench.yaml is a local, gitignored file
            continue
        Config.model_validate(yaml.safe_load(path.read_text()))


def test_a_bare_yaml_off_still_means_off():
    assert Config.model_validate({"upstream": {"ecs": False}}).upstream.ecs == "off"
    assert Config.model_validate({"upstream": {"ecs": "off"}}).upstream.ecs == "off"


def test_an_unknown_setting_is_refused_rather_than_dropped(tmp_path):
    """A misspelling or a wrong indent used to become a setting that was simply
    absent, with the protection the operator configured silently off."""
    import yaml

    from trench.errors import ConfigError
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump({"server": {"rate_limit": 150}}))
    with pytest.raises(ConfigError, match="rate_limit"):
        Config.load(str(path))


@pytest.mark.asyncio
async def test_changing_the_sources_recompiles_rather_than_reusing_the_table(tmp_path):
    """The cached block table was compiled from the *old* sources.

    `load_blocklists` is the start-up path and will map that table when it is
    still inside its refresh interval — the right answer at boot, and exactly
    the wrong one here: the change would be accepted and have no effect.
    """
    first = tmp_path / "first.txt"
    first.write_text("||one.example^\n")
    second = tmp_path / "second.txt"
    second.write_text("||two.example^\n")

    app, path = await _app(tmp_path, {"filtering": {"sources": [str(first)]},
                                      "gravity": {"refresh_hours": 24}})
    await app.load_blocklists()               # writes gravity.table, brand new
    assert app.filter.match("one.example").action.name == "BLOCK"
    assert app.table_path.exists()

    await _save(app, path, {"filtering.sources": [str(second)]})
    assert app._bootstrap is not None
    await app._bootstrap                      # the rebuild runs in the background

    assert app.filter.match("two.example").action.name == "BLOCK"
    assert app.filter.match("one.example").action.name == "NONE"


@pytest.mark.asyncio
async def test_removing_every_source_drops_the_imported_rules(tmp_path):
    src = tmp_path / "list.txt"
    src.write_text("||gone.example^\n")
    app, path = await _app(tmp_path, {"filtering": {"sources": [str(src)],
                                                    "deny": ["mine.example"]}})
    await app.load_blocklists()
    assert app.filter.match("gone.example").action.name == "BLOCK"

    await _save(app, path, {"filtering.sources": []})
    assert app.filter.match("gone.example").action.name == "NONE"
    assert app.filter.match("mine.example").action.name == "BLOCK"   # hand-written stays


# --- coercion ---------------------------------------------------------------
def test_a_boolean_sent_as_a_string_can_be_turned_off():
    """`bool("false")` is True, and so is `bool("0")`.

    The console's checkbox sends a real JSON boolean, so it was never affected.
    Every other client of this API — curl, a token-authenticated script — could
    only ever turn a setting *on*: the wrong value was written and the endpoint
    reported success, because it really had saved something.
    """
    from trench.api.settings import coerce
    for off in ("false", "False", "FALSE", "no", "off", "0", "", "  false  "):
        assert coerce("filtering.enabled", off) is False, off
    for on in ("true", "True", "yes", "on", "1"):
        assert coerce("filtering.enabled", on) is True, on
    # real JSON booleans keep working
    assert coerce("filtering.enabled", True) is True
    assert coerce("filtering.enabled", False) is False


def test_a_boolean_that_is_neither_is_rejected_rather_than_guessed():
    """Silently reading 'maybe' as one or the other is how the original bug
    stayed invisible: the caller is told, instead."""
    import pytest

    from trench.api.settings import coerce
    with pytest.raises(ValueError, match="is not a boolean"):
        coerce("filtering.enabled", "maybe")


# --- adopting a change must cost only what that change is worth ---------------
@pytest.mark.asyncio
async def test_adopting_a_change_runs_only_the_appliers_that_changed(tmp_path):
    """`apply_config()` with no argument used to mean "run every applier".

    Two of them are expensive: `upstream` rebuilds the forwarders and flushes the
    cache, and `sources` re-downloads and recompiles the whole blocklist corpus.
    Both callers that adopt a change — the sibling-worker sync and the API's
    fan-out — call it with no argument, so saving *any* setting, or flipping one
    device's filtering switch, triggered a full 900k-domain rebuild.
    """
    import yaml

    from trench.app import App
    from trench.config import Config
    path = tmp_path / "t.yaml"
    base = {"data_dir": str(tmp_path), "server": {"do53": {"enabled": False}},
            "log": {"level": "info"}}
    path.write_text(yaml.safe_dump(base))
    app = App(Config.model_validate(base), config_path=str(path))

    ran: list[str] = []
    real = app.adopters()

    def spy():
        async def noop():
            pass
        return {name: (lambda n=name: (ran.append(n), noop())[1]) for name in real}

    app.adopters = spy                      # type: ignore[method-assign]

    # one cheap setting moves
    base["log"]["level"] = "debug"
    path.write_text(yaml.safe_dump(base))
    await app.apply_config()
    assert ran == ["log"], f"expected only the log applier, got {ran}"
    assert app.config.log.level == "debug", "the new value still has to be in force"

    # nothing moves at all
    ran.clear()
    await app.apply_config()
    assert ran == [], f"nothing changed, so nothing should be adopted: {ran}"

    # SIGHUP keeps its documented meaning
    ran.clear()
    await app.apply_config(full=True)
    assert "upstream" in ran and "sources" in ran, "full=True must run everything"


@pytest.mark.asyncio
async def test_a_change_outside_the_editable_surface_falls_back_to_everything(tmp_path):
    """A hand-edited file can move things the console never offers. Assuming
    those need no applier is the same mistake in the other direction."""
    import yaml

    from trench.app import App
    from trench.config import Config
    path = tmp_path / "t.yaml"
    base = {"data_dir": str(tmp_path), "server": {"do53": {"enabled": False}},
            "upstream": {"groups": {}}}
    path.write_text(yaml.safe_dump(base))
    app = App(Config.model_validate(base), config_path=str(path))
    ran: list[str] = []
    real = app.adopters()

    def spy():
        async def noop():
            pass
        return {name: (lambda n=name: (ran.append(n), noop())[1]) for name in real}

    app.adopters = spy                      # type: ignore[method-assign]
    base["upstream"]["groups"] = {"kids": ["9.9.9.9"]}   # not in FIELDS
    path.write_text(yaml.safe_dump(base))
    await app.apply_config()
    assert "upstream" in ran, "an unrecognised change must not be silently skipped"


def test_every_field_lands_in_a_group_the_form_renders():
    """The form draws one tab per entry in `GROUPS` and puts each field in its
    own. A field naming a group that is not in that list is declared, saved and
    shown by nothing — which is what three notary settings did."""
    missing = sorted({f.group for f in st.FIELDS} - set(st.GROUPS))
    assert not missing, f"these groups have fields but no tab: {missing}"


def test_a_secret_is_never_sent_to_the_browser():
    """`GET /settings` is a viewer-role endpoint. Echoing the console password
    back into it would hand the credential to anyone who can read the page."""
    from trench.config import Config
    cfg = Config.model_validate({"web": {"admin_password": "hunter2"}})
    values = st.current(cfg)
    assert "hunter2" not in repr(values)
    assert values["web.admin_password"] == ""
    assert any(f.secret for f in st.FIELDS), "the flag must actually be in use"


# --- structured collections --------------------------------------------------
def test_every_collection_declares_how_it_is_applied_and_where_it_shows():
    app_methods = set(App(Config()).adopters())
    for c in st.COLLECTIONS:
        assert c.applies in ("live", "adopt", "restart"), c.path
        assert c.group in st.GROUPS, f"{c.path} has no tab"
        assert c.shape in ("list", "map"), c.path
        assert c.columns, c.path
        if c.applies == "adopt":
            assert c.adopter in app_methods, f"{c.path} names a missing adopter"
        if not c.scalar:
            assert all(col.name for col in c.columns), c.path


def test_the_whole_config_is_reachable_from_the_console():
    """The point of the exercise: no setting that only a text editor can reach.

    `allow_dhcp` is the single exception and is declared read-only — it is a
    command-line interlock that `apply_config` restores from the running process
    on every reload, so a control for it would be ignored.
    """
    from pydantic import BaseModel
    have = {f.path for f in st.FIELDS} | {c.path for c in st.COLLECTIONS}

    def walk(model, prefix=""):
        for name, fi in model.model_fields.items():
            path = f"{prefix}{name}"
            if path in have:
                yield path
                continue
            sub = next((c for c in [fi.annotation, *getattr(fi.annotation, "__args__", ())]
                        if isinstance(c, type) and issubclass(c, BaseModel)), None)
            if sub is not None and not str(fi.annotation).startswith(("list[", "dict[")):
                yield from walk(sub, path + ".")
            else:
                yield path

    unreachable = [p for p in walk(Config) if p not in have]
    assert unreachable == [], f"only a text editor can set: {unreachable}"
    assert st._BY_PATH["allow_dhcp"].readonly


def test_a_collection_round_trips_through_the_save_path(tmp_path):
    """Written the way the API writes it, and read back as real config."""
    zones = [{"origin": "home.example.", "file": "/data/z", "dnssec": True,
              "nsec3": False, "nsec3_iterations": 0, "nsec3_salt": "",
              "allow_transfer": ["192.0.2.1"], "also_notify": [],
              "allow_update": [], "tsig_key": None}]
    tree = {"data_dir": str(tmp_path)}
    st.merge(tree, "zones", st.coerce_collection("zones", zones))
    cfg = Config.model_validate(tree)
    assert cfg.zones[0].origin == "home.example."
    assert cfg.zones[0].allow_transfer == ["192.0.2.1"]
    # …and comes back out in the shape the editor sent
    assert st.collection_values(cfg)["zones"][0]["origin"] == "home.example."


def test_a_collection_of_the_wrong_shape_is_refused():
    import pytest as _p
    with _p.raises(ValueError, match="must be a list"):
        st.coerce_collection("zones", {"origin": "x."})
    with _p.raises(ValueError, match="must be an object"):
        st.coerce_collection("filtering.groups", [])
    with _p.raises(ValueError, match="every zones entry"):
        st.coerce_collection("zones", ["home.example."])
    with _p.raises(KeyError):
        st.coerce_collection("not.a.collection", [])


def test_a_readonly_setting_is_refused_rather_than_silently_ignored():
    import pytest as _p
    with _p.raises(ValueError, match="cannot be set here"):
        st.coerce("allow_dhcp", True)


@pytest.mark.parametrize("path,value", [
    ("cache.max_entries", 1e400),           # JSON `1e400`: int(inf) overflowed to a 500
    ("cache.max_entries", 1.7),             # would have been saved as 1
    ("upstream.timeout", float("nan")),     # would have been written as `.nan`
    ("upstream.timeout", "inf"),
])
def test_coerce_refuses_numbers_that_cannot_be_saved_honestly(path, value):
    with pytest.raises(ValueError):
        st.coerce(path, value)


def test_coerce_still_takes_whole_floats_and_numeric_strings():
    assert st.coerce("cache.max_entries", 5000.0) == 5000
    assert st.coerce("cache.max_entries", "5000") == 5000
    assert st.coerce("upstream.timeout", "2.5") == 2.5
