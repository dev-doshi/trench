"""CLI bootstrap: parse args, set up logging + event loop, run the App."""
from __future__ import annotations

import argparse
import asyncio
import gc
import signal
import sys

from . import log as logmod
from .config import Config
from .errors import ConfigError
from .filter.rule import Rule
from .version import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dnsguard", description="DNSGuard DNS server")
    p.add_argument("--config", help="path to dnsguard.yaml")
    p.add_argument("--dns-host")
    p.add_argument("--dns-port", type=int)
    p.add_argument("--upstream", action="append", metavar="HOST[:PORT]",
                   help="upstream resolver (repeatable)")
    p.add_argument("--source", action="append", metavar="URL|PATH",
                   help="blocklist source (repeatable)")
    p.add_argument("--no-uvloop", action="store_true")
    p.add_argument("--workers", type=int, help="Do53 worker processes (0=auto/CPU count)")
    p.add_argument("--allow-dhcp", action="store_true",
                   help="permit the DHCP server to bind :67 (destructive on a live LAN)")
    p.add_argument("--log-level", choices=["debug", "info", "warning", "error"])
    p.add_argument("--version", action="version", version=f"dnsguard {__version__}")
    return p


def apply_overrides(cfg: Config, args: argparse.Namespace) -> None:
    if args.dns_host:
        cfg.server.do53.host = args.dns_host
    if args.dns_port:
        cfg.server.do53.port = args.dns_port
    if args.upstream:
        cfg.upstream.servers = args.upstream
    if args.source:
        cfg.filtering.sources = args.source
    if args.log_level:
        cfg.log.level = args.log_level
    if args.no_uvloop:
        cfg.uvloop = False
    if args.workers is not None:
        cfg.server.workers = args.workers
    if args.allow_dhcp:
        cfg.allow_dhcp = True


async def _amain(cfg: Config, *, primary: bool = True, worker_idx: int = 0,
                 nworkers: int = 1, shm_path: str | None = None, do53_socks=None,
                 cache_shared=None, config_path: str | None = None,
                 prebuilt_filter=None) -> None:
    from .app import App
    app = App(cfg, primary=primary, worker_idx=worker_idx, nworkers=nworkers,
              shm_path=shm_path, do53_socks=do53_socks, cache_shared=cache_shared,
              config_path=config_path, prebuilt_filter=prebuilt_filter)
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover (Windows)
            pass
    try:  # SIGHUP -> hot reload (config + lists), without dropping queries
        # Guarded and strongly referenced. A bare ensure_future is only weakly
        # held by the loop, and nothing stopped two HUPs (or a HUP during the
        # scheduled refresh) running two blocklist rebuilds at once — each of
        # which peaks at hundreds of MB, on a box with an OOM history.
        _reloads: set = set()

        def _on_hup() -> None:
            if _reloads:
                logmod.get("main").warning(
                    "SIGHUP ignored: a reload is already running")
                return
            task = asyncio.ensure_future(app.reload())
            _reloads.add(task)
            task.add_done_callback(_reloads.discard)

        loop.add_signal_handler(signal.SIGHUP, _on_hup)
    except (NotImplementedError, AttributeError):  # pragma: no cover
        pass
    runner = asyncio.ensure_future(app.run())
    await stop.wait()
    await app.stop()
    runner.cancel()
    logmod.get("main").info("worker %d stopped", worker_idx)


def _bind_do53_sockets(cfg: Config):
    """Pre-bind the Do53 UDP+TCP sockets once; forked workers inherit the fds and
    all read from them, so the kernel fans connections across cores (portable —
    works the same on Linux and BSD/macOS, unlike SO_REUSEPORT load-balancing)."""
    import socket
    d = cfg.server.do53
    if not d.enabled:
        return (None, None)
    fam = socket.AF_INET6 if ":" in d.host else socket.AF_INET
    usock = tsock = None
    if d.udp:
        usock = socket.socket(fam, socket.SOCK_DGRAM)
        usock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        usock.bind((d.host, d.port))
        usock.setblocking(False)
    if d.tcp:
        tsock = socket.socket(fam, socket.SOCK_STREAM)
        tsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tsock.bind((d.host, d.port))
        tsock.listen(1024)
        tsock.setblocking(False)
    return (usock, tsock)


def _prebuild_filter(cfg: Config):
    """Compile the blocklists once, in the supervisor, before any fork.

    Two things follow from doing it here rather than in each worker: the lists
    are downloaded and parsed once instead of `nworkers` times (minutes of CPU
    on a small board), and the compiled table lands in shared memory that every
    child then reads without a copy.

    A failure is not fatal — the worker falls back to loading them itself, which
    is exactly the old behaviour.
    """
    if not cfg.filtering.sources:
        return None
    import time

    from .filter import FilterEngine
    from .filter.shared import SharedBlockTable
    from .gravity import Gravity
    log = logmod.get("main")
    table_path = cfg.data_path / "gravity.table"
    try:
        age = time.time() - table_path.stat().st_mtime if table_path.exists() else None
        if age is not None and age < cfg.gravity.refresh_hours * 3600:
            # Already compiled and still within its refresh interval: map it and
            # start serving now. The workers' own schedule brings it up to date.
            table = SharedBlockTable.open(table_path)
            rules = [Rule(raw=d, block=False, important=True, suffix=d.lower(),
                          source="allowlist") for d in cfg.filtering.allow]
            rules += [Rule(raw=d, block=True, suffix=d.lower(), source="denylist")
                      for d in cfg.filtering.deny]
            engine = FilterEngine.from_table(table, rules)
            log.info("reusing cached block table: %d domains, %.1f h old",
                     engine.size, age / 3600)
        else:
            gravity = Gravity(list(cfg.filtering.sources), list(cfg.filtering.allow),
                              list(cfg.filtering.deny), table_path=table_path)
            engine = asyncio.run(gravity.build())
    except Exception as e:  # noqa: BLE001 — any failure here just costs the optimisation
        log.warning("pre-fork blocklist build failed (%s); workers will each load their own", e)
        return None
    # Everything reachable now is long-lived. Moving it to the permanent
    # generation keeps the collector from writing to object headers in the
    # children, which would fault shared pages private one by one.
    gc.freeze()
    log.info("pre-fork blocklist: %d domains, %.1f MB shared across workers",
             engine.size, engine.block_table.nbytes / 1_048_576)
    return engine


def _run_workers(cfg: Config, nworkers: int, config_path: str | None = None) -> int:
    """Fork `nworkers` processes sharing pre-bound Do53 sockets across cores."""
    import os
    from pathlib import Path

    from .stats.shared import SharedScalars
    Path(cfg.data_dir).mkdir(parents=True, exist_ok=True)
    shm = str(Path(cfg.data_dir) / "stats.shm")
    SharedScalars.create(shm, nworkers)
    # Linux: let each worker bind its own SO_REUSEPORT socket (kernel steers per
    # flow, no thundering herd). BSD/macOS: reuse_port doesn't load-balance UDP,
    # so share one pre-bound fd across workers instead.
    socks = (None, None) if sys.platform.startswith("linux") else _bind_do53_sockets(cfg)

    cache_shared = None
    if cfg.cache.enabled and cfg.cache.shared:
        from .cache.shared import SharedCache
        cache_shared = SharedCache.create(cfg.cache.shared_slots, cfg.cache.shared_payload)

    prebuilt = _prebuild_filter(cfg)

    pids = []
    for idx in range(nworkers):
        pid = os.fork()
        if pid == 0:  # child
            try:
                asyncio.run(_amain(cfg, primary=(idx == 0), worker_idx=idx,
                                   nworkers=nworkers, shm_path=shm, do53_socks=socks,
                                   cache_shared=cache_shared, config_path=config_path,
                                   prebuilt_filter=prebuilt))
            except KeyboardInterrupt:
                pass
            os._exit(0)
        pids.append(pid)

    log = logmod.get("main")
    log.info("supervisor: %d workers (pids %s)", nworkers, pids)

    def _forward(signum, _frame):
        for p in pids:
            try:
                os.kill(p, signum)
            except ProcessLookupError:
                pass
    signal.signal(signal.SIGINT, _forward)
    signal.signal(signal.SIGTERM, _forward)
    for p in pids:
        try:
            os.waitpid(p, 0)
        except ChildProcessError:
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = Config.load(args.config)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    apply_overrides(cfg, args)
    logmod.setup(cfg.log.level, cfg.log.json_logs)

    if cfg.uvloop:
        try:
            import uvloop
            uvloop.install()
        except Exception:  # pragma: no cover
            pass

    import os
    nworkers = cfg.server.workers
    if nworkers <= 0:
        nworkers = os.cpu_count() or 1
    if nworkers > 1 and hasattr(os, "fork"):
        return _run_workers(cfg, nworkers, config_path=args.config)
    try:
        asyncio.run(_amain(cfg, config_path=args.config))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
