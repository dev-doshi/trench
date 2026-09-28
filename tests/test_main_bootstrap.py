"""The process bootstrap: argument parsing, overrides, pre-fork work, supervisor.

`trench/__main__.py` is the entry point every deployment runs and almost none of
it was covered: the socket pre-bind, the pre-fork blocklist build, the fork
supervisor and its signal forwarding — including the SIGHUP handler whose
absence made `systemctl reload` kill the service — were reached by no test.
"""
from __future__ import annotations

import asyncio
import os
import signal
import socket

import pytest

from trench import __main__ as M
from trench.config import Config


# --- argument parsing ---
def test_parser_defaults_are_all_unset():
    a = M.build_parser().parse_args([])
    assert a.config is None and a.dns_host is None and a.dns_port is None
    assert a.upstream is None and a.source is None
    assert a.no_uvloop is False and a.allow_dhcp is False
    assert a.workers is None and a.log_level is None


def test_parser_repeatable_options_accumulate():
    a = M.build_parser().parse_args(
        ["--upstream", "1.1.1.1", "--upstream", "9.9.9.9:853",
         "--source", "/a.txt", "--source", "https://b/list.txt"])
    assert a.upstream == ["1.1.1.1", "9.9.9.9:853"]
    assert a.source == ["/a.txt", "https://b/list.txt"]


def test_parser_rejects_a_bad_log_level():
    with pytest.raises(SystemExit):
        M.build_parser().parse_args(["--log-level", "verbose"])


def test_parser_rejects_a_non_numeric_port():
    with pytest.raises(SystemExit):
        M.build_parser().parse_args(["--dns-port", "domain"])


def test_version_flag_prints_and_exits(capsys):
    from trench.version import __version__
    with pytest.raises(SystemExit) as e:
        M.build_parser().parse_args(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


# --- overrides ---
def test_apply_overrides_changes_only_what_was_given():
    cfg = Config.model_validate({})
    before = (cfg.server.do53.host, cfg.server.do53.port, list(cfg.upstream.servers))
    M.apply_overrides(cfg, M.build_parser().parse_args([]))
    assert (cfg.server.do53.host, cfg.server.do53.port,
            list(cfg.upstream.servers)) == before


def test_apply_overrides_sets_every_field():
    cfg = Config.model_validate({})
    args = M.build_parser().parse_args([
        "--dns-host", "127.0.0.53", "--dns-port", "5353",
        "--upstream", "1.1.1.1", "--source", "/list.txt",
        "--log-level", "debug", "--no-uvloop", "--workers", "3", "--allow-dhcp"])
    M.apply_overrides(cfg, args)
    assert cfg.server.do53.host == "127.0.0.53"
    assert cfg.server.do53.port == 5353
    assert cfg.upstream.servers == ["1.1.1.1"]
    assert cfg.filtering.sources == ["/list.txt"]
    assert cfg.log.level == "debug"
    assert cfg.uvloop is False
    assert cfg.server.workers == 3
    assert cfg.allow_dhcp is True


def test_workers_zero_is_an_override_not_a_no_op():
    """`--workers 0` means "auto"; treated as falsy it would be ignored."""
    cfg = Config.model_validate({"server": {"workers": 4}})
    M.apply_overrides(cfg, M.build_parser().parse_args(["--workers", "0"]))
    assert cfg.server.workers == 0


def test_overrides_replace_rather_than_append_to_lists():
    cfg = Config.model_validate({"upstream": {"servers": ["8.8.8.8"]}})
    M.apply_overrides(cfg, M.build_parser().parse_args(["--upstream", "1.1.1.1"]))
    assert cfg.upstream.servers == ["1.1.1.1"]


# --- pre-bound Do53 sockets ---
def _cfg(**do53):
    base = {"host": "127.0.0.1", "port": 0}
    base.update(do53)
    return Config.model_validate({"server": {"do53": base}})


def test_bind_do53_returns_nothing_when_disabled():
    assert M._bind_do53_sockets(_cfg(enabled=False)) == (None, None)


def test_bind_do53_binds_udp_and_tcp():
    u, t = M._bind_do53_sockets(_cfg())
    try:
        assert u.type == socket.SOCK_DGRAM and t.type == socket.SOCK_STREAM
        assert u.family == socket.AF_INET
        assert u.gettimeout() == 0 and t.gettimeout() == 0     # non-blocking
        assert u.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0
    finally:
        u.close(); t.close()


def test_bind_do53_honours_the_per_protocol_switches():
    u, t = M._bind_do53_sockets(_cfg(tcp=False))
    try:
        assert u is not None and t is None
    finally:
        u.close()
    u, t = M._bind_do53_sockets(_cfg(udp=False))
    try:
        assert u is None and t is not None
    finally:
        t.close()


def test_bind_do53_uses_inet6_for_a_v6_host():
    u, t = M._bind_do53_sockets(_cfg(host="::1"))
    try:
        assert u.family == socket.AF_INET6 and t.family == socket.AF_INET6
    finally:
        u.close(); t.close()


def test_bind_do53_propagates_a_bind_failure():
    """A port already in use must not be swallowed into a half-bound server."""
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind(("127.0.0.1", 0))
    port = holder.getsockname()[1]
    try:
        with pytest.raises(OSError):
            M._bind_do53_sockets(_cfg(port=port, tcp=False, udp=True))
    finally:
        holder.close()


# --- pre-fork blocklist build ---
def test_prebuild_filter_skips_when_there_are_no_sources(tmp_path):
    cfg = Config.model_validate({"data_dir": str(tmp_path), "filtering": {"sources": []}})
    assert M._prebuild_filter(cfg) is None


def test_prebuild_filter_compiles_a_local_source(tmp_path):
    src = tmp_path / "list.txt"
    src.write_text("||ads.example.com^\n||tracker.example.net^\n")
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "filtering": {"sources": [str(src)],
                                               "deny": ["extra.example.org"]}})
    engine = M._prebuild_filter(cfg)
    assert engine is not None
    from trench.filter import Action
    assert engine.match("ads.example.com").action == Action.BLOCK
    assert engine.match("extra.example.org").action == Action.BLOCK
    assert (tmp_path / "gravity.table").exists()


def test_prebuild_filter_reuses_a_fresh_cached_table(tmp_path, caplog):
    src = tmp_path / "list.txt"
    src.write_text("||ads.example.com^\n")
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "filtering": {"sources": [str(src)]}})
    assert M._prebuild_filter(cfg) is not None            # writes the table
    src.write_text("||different.example.com^\n")          # not re-read
    engine = M._prebuild_filter(cfg)
    from trench.filter import Action
    assert engine.match("ads.example.com").action == Action.BLOCK
    assert engine.match("different.example.com").action == Action.NONE


def test_prebuild_filter_rebuilds_a_stale_cached_table(tmp_path):
    src = tmp_path / "list.txt"
    src.write_text("||ads.example.com^\n")
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "filtering": {"sources": [str(src)]},
                                 "gravity": {"refresh_hours": 24}})
    assert M._prebuild_filter(cfg) is not None
    table = tmp_path / "gravity.table"
    old = os.stat(table).st_mtime - 10 * 24 * 3600
    os.utime(table, (old, old))
    src.write_text("||different.example.com^\n")
    from trench.filter import Action
    assert M._prebuild_filter(cfg).match("different.example.com").action == Action.BLOCK


def test_prebuild_filter_failure_is_not_fatal(tmp_path, monkeypatch):
    """Losing the optimisation costs CPU; it must not stop the server."""
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "filtering": {"sources": ["/does/not/exist.txt"]}})

    class Boom:
        def __init__(self, *a, **kw): pass

        async def build(self):
            raise RuntimeError("network down")

    monkeypatch.setattr("trench.gravity.Gravity", Boom)
    assert M._prebuild_filter(cfg) is None


# --- the query-log salt, settled before the fork ---
@pytest.mark.asyncio
async def test_querylog_salt_is_stable_across_reads(tmp_path):
    cfg = Config.model_validate({"data_dir": str(tmp_path)})
    first = await M._querylog_salt(cfg)
    assert isinstance(first, bytes) and first
    assert await M._querylog_salt(cfg) == first


@pytest.mark.asyncio
async def test_querylog_salt_failure_degrades_to_empty(tmp_path, monkeypatch):
    cfg = Config.model_validate({"data_dir": str(tmp_path)})

    class Boom:
        def __init__(self, *a, **kw): pass

        async def connect(self):
            raise OSError("disk gone")

        async def close(self):
            pass

    monkeypatch.setattr("trench.store.Database", Boom)
    assert await M._querylog_salt(cfg) == b""


# --- the supervisor ---
class _ForkHarness:
    """Drives `_run_workers` without actually forking."""

    def __init__(self, monkeypatch, tmp_path, *, child_idx=None):
        self.monkeypatch = monkeypatch
        self.pids: list[int] = []
        self.waited: list[int] = []
        self.killed: list[tuple[int, int]] = []
        self.handlers: dict[int, object] = {}
        self.exited: list[int] = []
        self.ran: list[dict] = []
        self._child_idx = child_idx
        self._n = 0

    def install(self):
        mp = self.monkeypatch

        def fake_fork():
            idx = self._n
            self._n += 1
            if self._child_idx is not None and idx == self._child_idx:
                return 0
            pid = 1000 + idx
            self.pids.append(pid)
            return pid

        mp.setattr(os, "fork", fake_fork)
        mp.setattr(os, "waitpid", lambda p, f: self.waited.append(p) or (p, 0))
        mp.setattr(os, "kill", lambda p, s: self.killed.append((p, s)))
        mp.setattr(os, "_exit", lambda code: self.exited.append(code))
        mp.setattr(signal, "signal",
                   lambda s, h: self.handlers.__setitem__(s, h))

        def fake_run(coro):
            # `asyncio.run` is called for the salt and for each child's _amain.
            if asyncio.iscoroutine(coro) and coro.cr_code.co_name == "_amain":
                coro.close()
                self.ran.append({})
                return None
            return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)

        mp.setattr(M.asyncio, "run", fake_run)


def _worker_cfg(tmp_path, **over):
    data = {"data_dir": str(tmp_path), "querylog": {"enabled": False},
            "cache": {"enabled": True, "shared": False},
            "server": {"do53": {"host": "127.0.0.1", "port": 0}}}
    data.update(over)
    return Config.model_validate(data)


def test_supervisor_forks_and_reaps_every_worker(tmp_path, monkeypatch):
    h = _ForkHarness(monkeypatch, tmp_path)
    h.install()
    assert M._run_workers(_worker_cfg(tmp_path), 3) == 0
    assert h.pids == [1000, 1001, 1002]
    assert h.waited == [1000, 1001, 1002]
    assert (tmp_path / "stats.shm").exists()


def test_supervisor_forwards_hup_as_well_as_int_and_term(tmp_path, monkeypatch):
    """Left uninstalled, SIGHUP's default disposition kills the supervisor, so
    `systemctl reload` tears the whole service down."""
    h = _ForkHarness(monkeypatch, tmp_path)
    h.install()
    M._run_workers(_worker_cfg(tmp_path), 2)
    assert set(h.handlers) == {signal.SIGINT, signal.SIGTERM, signal.SIGHUP,
                               signal.SIGUSR1}
    h.handlers[signal.SIGHUP](signal.SIGHUP, None)
    assert h.killed == [(1000, signal.SIGHUP), (1001, signal.SIGHUP)]


def test_supervisor_fans_a_policy_change_out_to_every_worker(tmp_path, monkeypatch):
    """The API lives in one worker. Without this, a saved setting or a managed
    client applied there and nowhere else, so it governed roughly one query in
    `workers` — which reads as flapping rather than as a change that did not
    take."""
    h = _ForkHarness(monkeypatch, tmp_path)
    h.install()
    M._run_workers(_worker_cfg(tmp_path), 2)
    h.handlers[signal.SIGUSR1](signal.SIGUSR1, None)
    assert h.killed == [(1000, signal.SIGUSR1), (1001, signal.SIGUSR1)]


def test_signal_forwarding_survives_a_worker_that_already_exited(tmp_path,
                                                                monkeypatch):
    h = _ForkHarness(monkeypatch, tmp_path)
    h.install()
    M._run_workers(_worker_cfg(tmp_path), 2)
    monkeypatch.setattr(os, "kill", lambda p, s: (_ for _ in ()).throw(ProcessLookupError))
    h.handlers[signal.SIGTERM](signal.SIGTERM, None)      # must not raise


def test_reaping_survives_a_worker_already_reaped(tmp_path, monkeypatch):
    h = _ForkHarness(monkeypatch, tmp_path)
    h.install()
    monkeypatch.setattr(os, "waitpid",
                        lambda p, f: (_ for _ in ()).throw(ChildProcessError))
    assert M._run_workers(_worker_cfg(tmp_path), 2) == 0


def test_a_worker_that_fails_to_start_exits_nonzero_and_does_not_fork(tmp_path,
                                                                     monkeypatch):
    """The child must die rather than fall through into the supervisor's code
    and start forking siblings of its own."""
    h = _ForkHarness(monkeypatch, tmp_path, child_idx=0)
    h.install()

    def blow_up(coro):
        if asyncio.iscoroutine(coro) and coro.cr_code.co_name == "_amain":
            coro.close()
            raise RuntimeError("port in use")
        return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)

    monkeypatch.setattr(M.asyncio, "run", blow_up)
    M._run_workers(_worker_cfg(tmp_path), 2)
    assert h.exited == [1]


def test_a_worker_interrupted_at_startup_exits_zero(tmp_path, monkeypatch):
    h = _ForkHarness(monkeypatch, tmp_path, child_idx=1)
    h.install()

    def interrupt(coro):
        if asyncio.iscoroutine(coro) and coro.cr_code.co_name == "_amain":
            coro.close()
            raise KeyboardInterrupt
        return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)

    monkeypatch.setattr(M.asyncio, "run", interrupt)
    M._run_workers(_worker_cfg(tmp_path), 2)
    assert h.exited == [0]


def test_supervisor_creates_the_shared_cache_when_configured(tmp_path, monkeypatch):
    h = _ForkHarness(monkeypatch, tmp_path)
    h.install()
    made = []
    monkeypatch.setattr("trench.cache.shared.SharedCache.create",
                        classmethod(lambda cls, slots, payload: made.append((slots, payload))))
    cfg = _worker_cfg(tmp_path, cache={"enabled": True, "shared": True})
    M._run_workers(cfg, 2)
    assert made and made[0][0] == cfg.cache.shared_slots


def test_supervisor_creates_a_record_ring_when_the_query_log_is_on(tmp_path,
                                                                   monkeypatch):
    h = _ForkHarness(monkeypatch, tmp_path)
    h.install()
    cfg = _worker_cfg(tmp_path, querylog={"enabled": True})
    assert M._run_workers(cfg, 2) == 0


# --- main() ---
def test_main_reports_a_missing_config_file(capsys, tmp_path):
    assert M.main(["--config", str(tmp_path / "nope.yaml")]) == 2
    assert "config error" in capsys.readouterr().err


def test_main_reports_an_invalid_config_file(capsys, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("server:\n  do53:\n    port: not-a-number\n")
    assert M.main(["--config", str(bad)]) == 2
    assert "config error" in capsys.readouterr().err


def test_main_single_worker_runs_amain(tmp_path, monkeypatch):
    ran = []
    monkeypatch.setattr(M.asyncio, "run", lambda c: ran.append(c.cr_code.co_name) or c.close())
    cfg_file = tmp_path / "t.yaml"
    cfg_file.write_text(f"data_dir: {tmp_path}\nserver:\n  workers: 1\n")
    assert M.main(["--config", str(cfg_file)]) == 0
    assert ran == ["_amain"]


def test_main_multi_worker_hands_off_to_the_supervisor(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(M, "_run_workers",
                        lambda cfg, n, config_path=None: seen.update(n=n, p=config_path) or 0)
    cfg_file = tmp_path / "t.yaml"
    cfg_file.write_text(f"data_dir: {tmp_path}\nserver:\n  workers: 4\n")
    assert M.main(["--config", str(cfg_file)]) == 0
    assert seen == {"n": 4, "p": str(cfg_file)}


def test_workers_zero_means_one_per_cpu(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(M, "_run_workers", lambda cfg, n, config_path=None: seen.update(n=n) or 0)
    monkeypatch.setattr(os, "cpu_count", lambda: 7)
    cfg_file = tmp_path / "t.yaml"
    cfg_file.write_text(f"data_dir: {tmp_path}\nserver:\n  workers: 0\n")
    M.main(["--config", str(cfg_file)])
    assert seen == {"n": 7}


def test_a_single_cpu_box_never_takes_the_fork_path(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "cpu_count", lambda: 1)
    monkeypatch.setattr(M, "_run_workers",
                        lambda *a, **kw: pytest.fail("should not fork on one CPU"))
    ran = []
    monkeypatch.setattr(M.asyncio, "run", lambda c: ran.append(1) or c.close())
    cfg_file = tmp_path / "t.yaml"
    cfg_file.write_text(f"data_dir: {tmp_path}\nserver:\n  workers: 0\n")
    assert M.main(["--config", str(cfg_file)]) == 0
    assert ran == [1]


def test_main_returns_zero_on_keyboard_interrupt(tmp_path, monkeypatch):
    def boom(c):
        c.close()
        raise KeyboardInterrupt
    monkeypatch.setattr(M.asyncio, "run", boom)
    cfg_file = tmp_path / "t.yaml"
    cfg_file.write_text(f"data_dir: {tmp_path}\nserver:\n  workers: 1\n")
    assert M.main(["--config", str(cfg_file)]) == 0


def test_main_applies_cli_overrides_to_the_loaded_config(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(M, "_run_workers",
                        lambda cfg, n, config_path=None: seen.update(host=cfg.server.do53.host) or 0)
    cfg_file = tmp_path / "t.yaml"
    cfg_file.write_text(f"data_dir: {tmp_path}\nserver:\n  workers: 2\n"
                        "  do53:\n    host: 0.0.0.0\n")
    M.main(["--config", str(cfg_file), "--dns-host", "127.0.0.53"])
    assert seen == {"host": "127.0.0.53"}


def test_main_runs_with_no_config_file_at_all(tmp_path, monkeypatch):
    ran = []
    monkeypatch.setattr(M.asyncio, "run", lambda c: ran.append(1) or c.close())
    monkeypatch.setattr(M, "_run_workers", lambda *a, **kw: 0)
    assert M.main(["--workers", "1"]) == 0
    assert ran == [1]
