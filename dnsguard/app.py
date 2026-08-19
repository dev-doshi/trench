"""Application orchestrator: build components from config, run frontends.

This is the composition root. Each subsystem is constructed here and wired
into the pipeline, so swapping (e.g. forwarder -> recursive) is a one-line change.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import time
from typing import TYPE_CHECKING, Any

from .cache import Cache
from .clients import ClientRegistry
from .config import Config
from .engine import Pipeline
from .filter import FilterEngine
from .filter.rule import Rule
from .filter.safebrowse import SafeBrowse
from .filter.services import Services
from .filter.shared import SharedBlockTable
from .gravity import Gravity
from .gravity.schedule import Scheduler
from .log import get
from .resolver.forwarder import Forwarder
from .stats import Counters
from .store import Database, QueryLog
from .transport.do53 import Do53Server

if TYPE_CHECKING:                       # imports kept lazy at runtime: an
    from .api import APIServer  # unused subsystem is never imported
    from .engine.fastpath import FastPath
    from .learn import PopularityTracker

log = get("app")


def release_free_memory() -> None:
    """Hand freed heap arenas back to the OS (glibc `malloc_trim`).

    Compiling a large blocklist allocates several times more than it retains.
    Python frees those objects, but glibc keeps the arenas, so resident memory
    stays near the peak and a small box looks permanently close to its limit —
    which is how it ends up OOM-killed on the next refresh. A no-op elsewhere.
    """
    try:
        import ctypes
        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except (OSError, AttributeError):
        pass  # not glibc (macOS/musl): nothing to do


class App:
    def __init__(self, config: Config, *, primary: bool = True, worker_idx: int = 0,
                 nworkers: int = 1, shm_path: str | None = None, do53_socks=None,
                 cache_shared=None, config_path: str | None = None,
                 prebuilt_filter: FilterEngine | None = None):
        self.config = config
        self._config_path = config_path
        self._prebuilt_filter = prebuilt_filter
        self.primary = primary
        self.worker_idx = worker_idx
        self.nworkers = nworkers
        self.do53_socks = do53_socks or (None, None)  # (udp_sock, tcp_sock) shared via fork
        shared = None
        if shm_path and nworkers > 1:
            from .stats.shared import SharedScalars
            shared = SharedScalars(shm_path, nworkers, worker_idx)
        self.counters = Counters(shared=shared)
        self.cache = Cache(
            enabled=config.cache.enabled, max_entries=config.cache.max_entries,
            min_ttl=config.cache.min_ttl, max_ttl=config.cache.max_ttl,
            negative_ttl=config.cache.negative_ttl, serve_stale=config.cache.serve_stale,
            serve_stale_max=config.cache.serve_stale_max, shared=cache_shared,
        )
        if config.upstream.mode == "recursive":
            from .resolver.recursive import RecursiveForwarder
            self.forwarder = RecursiveForwarder(
                timeout=config.upstream.timeout,
                validate=config.upstream.dnssec,
                qmin=config.upstream.qname_min,
                budget=config.upstream.recursion_budget,
                max_queries=config.upstream.recursion_max_queries,
                query_timeout=config.upstream.recursion_query_timeout)
        else:
            self.forwarder = Forwarder(config.upstream.servers,
                                       strategy=config.upstream.strategy,
                                       timeout=config.upstream.timeout,
                                       verify=config.upstream.verify,
                                       trust_ad=config.upstream.trust_ad,
                                       udp_source_ports=config.upstream.udp_source_ports)
        self.filter: FilterEngine = FilterEngine.compile(self._config_rules())
        self.clients = ClientRegistry.from_config(config)
        self.services = Services.load(config.data_path)
        self.safebrowse = SafeBrowse.load(config.data_path)
        self.zones = self._build_zones()
        self.auth = self._build_auth_handler()
        from .plugins import PluginManager
        self.plugins = PluginManager.from_config(self, config.plugins)
        self.db: Database | None = None
        self.querylog: QueryLog | None = None
        self.api: APIServer | None = None
        self.scheduler = Scheduler()
        self.pipeline = Pipeline(filter_engine=self.filter, cache=self.cache,
                                 forwarder=self.forwarder, counters=self.counters,
                                 config=config, clients=self.clients,
                                 services=self.services, safebrowse=self.safebrowse,
                                 zones=self.zones, plugins=self.plugins)
        # Wire-resident replay. Attached to the pipeline (which invalidates it
        # when the rules change) and to the cache (which invalidates it on a
        # flush), so there is no path that drops an answer without dropping the
        # recorded copy of it.
        self.fast: FastPath | None = None
        if config.server.fast_path:
            from .engine.fastpath import FastPath
            self.fast = FastPath(self.pipeline, max_entries=config.server.fast_path_entries)
            self.pipeline.fast = self.fast
            self.cache.on_flush = self.fast.clear
        self.learn: PopularityTracker | None = None
        if config.cache.enabled and config.cache.prewarm:
            from .learn import PopularityTracker
            self.learn = PopularityTracker()
            self.pipeline.learn = self.learn
        # Heterogeneous on purpose: DHCP and the block page are served
        # here too, and neither is a DNS Frontend.
        self.frontends: list[Any] = []
        self._stop = asyncio.Event()

    async def setup_storage(self) -> None:
        # only the primary worker owns the SQLite DB (single writer) + query log
        if not self.primary:
            return
        self.db = Database(self.config.data_path / self.config.querylog.db)
        await self.db.connect()
        if self.config.querylog.enabled:
            self.querylog = QueryLog(
                self.db, retention_days=self.config.querylog.retention_days,
                privacy_level=self.config.querylog.privacy_level)
            await self.querylog.start()
            self.pipeline.querylog = self.querylog
        await self.reload_clients()   # merge DB-managed clients over the config ones

    async def reload_clients(self) -> None:
        """Rebuild the live client registry from config + the `client` DB table."""
        extra = []
        if self.db is not None:
            try:
                rows = await self.db.fetchall(
                    "SELECT ident, ident_type, name, policy FROM client")
                extra = [self.clients.client_from_row(self.config, r) for r in rows]
            except Exception:
                log.exception("loading managed clients failed")
        self.clients = ClientRegistry.from_config(self.config, extra)
        self.pipeline.clients = self.clients

    def _build_zones(self):
        from pathlib import Path

        from .auth_zone import Zone, ZoneStore
        from .auth_zone.sign import sign_zone
        from .auth_zone.zonefile import parse_zonefile
        from .wire import rdata as R
        from .wire.name import Name
        from .wire.rrtypes import type_from_text
        store = ZoneStore()
        for zc in self.config.zones:
            if zc.file and Path(zc.file).exists():
                zone = parse_zonefile(Path(zc.file).read_text(), zc.origin)
            else:
                zone = Zone(Name.from_text(zc.origin))
            if zc.dnssec:
                salt = bytes.fromhex(zc.nsec3_salt) if zc.nsec3_salt else b""
                res = sign_zone(zone, nsec3=zc.nsec3, nsec3_salt=salt,
                                nsec3_iterations=zc.nsec3_iterations)
                log.info("signed zone %s (DS keytag %d, %s)", zc.origin, res.key_tag,
                         "NSEC3" if zc.nsec3 else "NSEC")
            store.add(zone)
        for lr in self.config.local_records:
            name = Name.from_text(lr.name)
            z = Zone(name)
            t = lr.type.upper()
            rd = (R.A(lr.answer) if t == "A" else R.AAAA(lr.answer) if t == "AAAA"
                  else R.CNAME(Name.from_text(lr.answer)) if t == "CNAME"
                  else R.TXT([lr.answer.encode()]) if t == "TXT" else None)
            if rd is not None:
                z.add(name, int(type_from_text(t)), rd)
                store.add(z)
        return store

    def _build_auth_handler(self):
        """Wire zone-transfer / NOTIFY / dynamic-update policy from config. Returns
        None when no zone enables any authoritative transaction (keeps the hot path
        untouched for pure-resolver deployments)."""
        cfg = self.config
        needs = any(zc.allow_transfer or zc.also_notify or zc.allow_update
                    for zc in cfg.zones) or bool(cfg.secondaries)
        if not needs:
            return None
        from .auth_zone.handler import AuthHandler
        from .auth_zone.tsig import TSIGKey
        from .wire.name import Name
        keyring = {k.name.lower(): TSIGKey.from_base64(k.name, k.secret, k.algorithm)
                   for k in cfg.tsig_keys}
        handler = AuthHandler(self.zones, keyring)
        for zc in cfg.zones:
            if zc.allow_transfer or zc.also_notify or zc.allow_update:
                handler.set_zone_policy(
                    Name.from_text(zc.origin), allow_transfer=zc.allow_transfer,
                    also_notify=zc.also_notify, allow_update=zc.allow_update,
                    tsig_key=zc.tsig_key)
        for sc in cfg.secondaries:
            from .auth_zone.secondary import SecondaryZone
            key = keyring.get(sc.tsig_key.lower()) if sc.tsig_key else None
            sec = SecondaryZone(Name.from_text(sc.origin), sc.primary, port=sc.port, key=key,
                                on_refresh=self.zones.replace)
            handler.register_secondary(sec)
        return handler

    def _config_rules(self) -> list[Rule]:
        rules: list[Rule] = []
        for d in self.config.filtering.allow:
            rules.append(Rule(raw=d, block=False, important=True, suffix=d.lower(),
                              source="allowlist"))
        for d in self.config.filtering.deny:
            rules.append(Rule(raw=d, block=True, suffix=d.lower(), source="denylist"))
        return rules

    @property
    def table_path(self):
        """The compiled block table on disk. Shared by every worker, and the
        reason a restart can serve queries before it has re-read any list."""
        return self.config.data_path / "gravity.table"

    def _adopt_table(self, table) -> None:
        """Swap in a block table built elsewhere, keeping local rules."""
        engine = FilterEngine.from_table(table, self._config_rules())
        self.filter = engine
        self.pipeline.filter = engine

    async def load_blocklists(self) -> None:
        sources = self.config.filtering.sources
        if not sources:
            log.info("no blocklist sources configured")
            return
        gravity = Gravity(sources, list(self.config.filtering.allow),
                          list(self.config.filtering.deny), db=self.db,
                          table_path=self.table_path)
        self._gravity = gravity

        if self._prebuilt_filter is not None:
            # The supervisor already compiled these before forking; reuse its
            # shared table rather than fetching and parsing the same lists again.
            engine = self._prebuilt_filter
            self._prebuilt_filter = None
            self.filter = engine
            self.pipeline.filter = engine
            log.info("using pre-forked blocklist (%d domains)", engine.size)
            release_free_memory()
            return

        # A resolver that cannot answer is worse than one answering from a
        # slightly old list, and re-parsing 600k domains takes a minute on small
        # hardware. So serve the last compiled table straight away and let the
        # normal refresh schedule bring it up to date in the background.
        if self.table_path.exists():
            try:
                table = SharedBlockTable.open(self.table_path)
            except Exception as e:  # noqa: BLE001 — a bad table is always recoverable
                log.warning("cached block table unusable (%s); rebuilding", e)
            else:
                self._adopt_table(table)
                age = max(0.0, time.time() - self.table_path.stat().st_mtime)
                log.info("mapped cached block table: %d domains, %.1f MB, %.1f h old",
                         len(table), table.nbytes / 1_048_576, age / 3600)
                release_free_memory()
                if age < self.config.gravity.refresh_hours * 3600 or not self.primary:
                    return   # still fresh, or a sibling worker owns the refresh
                log.info("cached table is past its refresh interval; rebuilding now")

        engine = await gravity.build()
        self.filter = engine
        self.pipeline.filter = engine
        release_free_memory()

    async def refresh_blocklists(self) -> None:
        if getattr(self, "_gravity", None) is None:
            return
        if not self.primary and self.nworkers > 1:
            # Only one worker per machine downloads and compiles. The others pick
            # the result up from the table file, so the lists are fetched once
            # and the compiled copy is shared instead of duplicated N times.
            self.adopt_refreshed_table()
            return
        previous = self.filter
        engine = await self._gravity.build()
        # Compare against what was running *before* swapping, so the operator
        # gets a diff of what this update actually changed for their network.
        await self._record_list_review(previous, engine)
        self.filter = engine
        self.pipeline.filter = engine
        self.cache.flush()  # rules changed; drop possibly-stale answers
        release_free_memory()  # the old engine is unreachable now — hand the pages back

    async def _record_list_review(self, before, after) -> None:
        """Review a refresh: which recently-queried names does it decide
        differently? Recorded rather than acted on — see analyze/listdiff.py for
        why nothing is auto-quarantined."""
        if self.querylog is None or self.db is None:
            return
        try:
            from .analyze import review_from_querylog
            review = await review_from_querylog(before, after, self.querylog)
            await self.db.execute(
                "INSERT INTO list_review(ts, domains_before, domains_after,"
                " high_risk, detail) VALUES(?,?,?,?,?)",
                (int(review.at), review.domains_before, review.domains_after,
                 review.high_risk, json.dumps(review.to_json())))
            log.info("blocklist update: %s", review.summary())
            for c in review.newly_blocked:
                if c.risk == "high":
                    log.warning("newly blocked and in active use: %s "
                                "(%d lookups from %d devices, via %s)",
                                c.qname, c.hits, c.clients, c.source or c.rule)
        except Exception:
            log.exception("could not review the blocklist update")

    def adopt_refreshed_table(self) -> bool:
        """Re-map the block table if another worker has replaced it.

        Coordination is the file itself: one `stat` to notice, an atomic rename
        on the writing side. No IPC, no knowledge of the other workers, and a
        worker that misses a round simply catches it on the next one.
        """
        table = getattr(self.filter, "block_table", None)
        if table is None or not table.stale():
            return False
        try:
            fresh = SharedBlockTable.open(self.table_path)
        except Exception as e:  # noqa: BLE001
            log.warning("could not adopt refreshed block table: %s", e)
            return False
        self._adopt_table(fresh)
        self.cache.flush()
        log.info("adopted refreshed block table: %d domains", len(fresh))
        release_free_memory()
        return True

    def apply_config(self) -> None:
        """Re-read the config file and push it into the objects already running.

        Swapping `self.config` is not enough: the query log, the cache and the
        detectors each copied what they needed at construction, so a changed
        setting was written to disk, reported as saved, and then ignored by the
        process that was supposed to obey it. This is the list of things that can
        genuinely be adopted without a restart.
        """
        if self._config_path:
            try:
                from .config import Config
                new = Config.load(self._config_path)
                new.allow_dhcp = self.config.allow_dhcp   # runtime-only flag
                self.config = new
                self.pipeline.config = new
            except Exception:
                log.exception("reload: config re-read failed; keeping current")
                return

        c = self.config
        if self.querylog is not None:
            self.querylog.privacy_level = c.querylog.privacy_level
            self.querylog.retention_days = c.querylog.retention_days
        self.cache.enabled = c.cache.enabled
        self.cache.max_entries = c.cache.max_entries
        self.cache.min_ttl = c.cache.min_ttl
        self.cache.max_ttl = c.cache.max_ttl
        self.cache.negative_ttl = c.cache.negative_ttl
        self.cache.serve_stale = c.cache.serve_stale
        self.cache.serve_stale_max = c.cache.serve_stale_max

        p = self.pipeline
        sec = c.security
        p.ede = bool(c.filtering.ede)
        p.stale_timeout = float(c.cache.serve_stale_client_timeout)
        p.rebinding = bool(sec.rebinding_protection)
        p.local_suffixes = tuple(sec.local_suffixes)
        p.use_0x20 = bool(sec.use_0x20)
        from .engine.ratelimit import RateLimiter
        p.ratelimiter = RateLimiter(sec.rate_limit, sec.rate_burst)
        if sec.dns_cookies and p.cookies is None:
            from .engine.cookies import CookieJar
            p.cookies = CookieJar()
        elif not sec.dns_cookies:
            p.cookies = None
        if sec.dga_detection:
            from .filter.dga import DGADetector
            p.dga = DGADetector(threshold=sec.dga_threshold, block=sec.dga_block)
        else:
            p.dga = None
        if sec.tunnel_detection:
            from .filter.tunnel import TunnelDetector
            p.tunnel = TunnelDetector(threshold=sec.tunnel_threshold, block=sec.tunnel_block)
        else:
            p.tunnel = None
        if p.fast is not None:
            p.fast.clear()          # gates and policy may have moved underneath it
        import logging
        logging.getLogger("dnsguard").setLevel(c.log.level.upper())

    async def reload(self) -> None:
        """Hot reload (SIGHUP): re-read config, re-apply it, and refresh the
        lists and data files — without dropping in-flight queries or rebinding
        sockets."""
        log.info("reload: re-reading config + refreshing lists")
        self.apply_config()
        self.services = Services.load(self.config.data_path)
        self.safebrowse = SafeBrowse.load(self.config.data_path)
        self.pipeline.services = self.services
        self.pipeline.safebrowse = self.safebrowse
        await self.reload_clients()   # config clients + DB-managed clients
        await self.refresh_blocklists()
        log.info("reload complete")

    async def start(self) -> None:
        s = self.config.server
        data_dir = self.config.data_path
        multi = self.nworkers > 1
        if self.primary:
            self._warn_about_exposure()
        # Do53 runs in EVERY worker. Prefer inherited pre-bound sockets (portable
        # multi-core: kernel fans datagrams out to whichever worker is idle);
        # fall back to SO_REUSEPORT when not running under the supervisor.
        if s.do53.enabled:
            usock, tsock = self.do53_socks
            fe = Do53Server(self.pipeline, s.do53.host, s.do53.port,
                            udp=s.do53.udp, tcp=s.do53.tcp, reuse_port=multi,
                            sock_udp=usock, sock_tcp=tsock, auth=self.auth,
                            limits=self._stream_limits(),
                            udp_max_inflight=s.udp_max_inflight, fast=self.fast)
            await fe.start()
            self.frontends.append(fe)
        # encrypted transports, API, DHCP, scheduler: primary worker only
        if not self.primary:
            self._maybe_drop_privileges()   # non-primary workers still shed root
            return
        if self.auth is not None:
            for sec in self.auth.secondaries.values():
                sec.start()
                log.info("secondary zone %s from %s started",
                         sec.origin.to_text(), sec.primary)
        if s.dot.enabled:
            from .transport.dot import DoTServer
            fe = DoTServer(self.pipeline, s.dot.host, s.dot.port, s.dot.cert, s.dot.key,
                           data_dir, limits=self._stream_limits())
            await fe.start()
            self.frontends.append(fe)
        if s.doh.enabled:
            from .transport.doh import DoHServer
            fe = DoHServer(self.pipeline, s.doh.host, s.doh.port, s.doh.path,
                           tls=s.doh.tls, cert=s.doh.cert, key=s.doh.key, data_dir=data_dir)
            await fe.start()
            self.frontends.append(fe)
        if s.doq.enabled:
            from .transport.doq import DoQServer
            fe = DoQServer(self.pipeline, s.doq.host, s.doq.port, s.doq.cert, s.doq.key, data_dir)
            await fe.start()
            self.frontends.append(fe)
        if s.doh3.enabled:
            from .transport.doh3 import DoH3Server
            fe = DoH3Server(self.pipeline, s.doh3.host, s.doh3.port, s.doh3.path,
                            s.doh3.cert, s.doh3.key, data_dir)
            await fe.start()
            self.frontends.append(fe)
        if self.config.dhcp.enabled and self.config.dhcp.scope is not None:
            from .dhcp.scope import Scope
            from .dhcp.server import DhcpServer
            sc = self.config.dhcp.scope
            scope = Scope(sc.network, sc.range_start, sc.range_end, router=sc.router,
                          dns=sc.dns, lease_time=sc.lease_time, domain=sc.domain,
                          reservations=dict(sc.reservations))
            self.dhcp = DhcpServer(scope, self.config.dhcp.server_ip or sc.router)
            await self.dhcp.start(enabled=True, allow_dhcp=self.config.allow_dhcp,
                                  dev=self.config.dev)
            self.frontends.append(self.dhcp)
        if self.config.filtering.block_page:
            from .web.blockpage import BlockPageServer
            bp = BlockPageServer(self.config.filtering.block_page_host,
                                 self.config.filtering.block_page_port)
            await bp.start()
            self.frontends.append(bp)
        if self.config.web.enabled and self.db is not None:
            from .api import APIServer
            ssl_ctx = None
            if self.config.web.tls:
                from .security.tls import server_ssl_context
                ssl_ctx = server_ssl_context(self.config.web.cert, self.config.web.key,
                                             data_dir=data_dir, alpn=["http/1.1"],
                                             hostnames=[self.config.web.host, "localhost"])
            self.api = APIServer(self, self.config.web.host, self.config.web.port,
                                 ssl_context=ssl_ctx)
            await self.api.start()
        # all privileged ports are bound: shed root if a target user was configured
        self._maybe_drop_privileges()

    @staticmethod
    def _is_exposed(host: str) -> bool:
        """Is this listener reachable from off the machine?"""
        if not host:
            return False
        try:
            return not ipaddress.ip_address(host).is_loopback
        except ValueError:
            return host not in ("localhost",)

    def _warn_about_exposure(self) -> None:
        """Say so, once, when a listener is open to the network but the
        protection that goes with it is off.

        The shipped defaults are loopback-only, where none of this matters.
        Every real deployment changes `host`, and the settings that should
        change with it live in a different part of the file — so the gap is
        easy to leave open and invisible until something abuses it.
        """
        s, sec = self.config.server, self.config.security
        if s.do53.enabled and self._is_exposed(s.do53.host):
            if not sec.rate_limit:
                log.warning(
                    "do53 is listening on %s with security.rate_limit disabled: "
                    "anything that can reach this port can use it for "
                    "amplification. Set security.rate_limit (100 is a sane "
                    "starting point for a home LAN).", s.do53.host)
            if os.geteuid() == 0 and not s.user:
                log.warning(
                    "running as root with server.user unset: DNSGuard will keep "
                    "full privileges after binding. Set server.user to shed them.")
        w = self.config.web
        if w.enabled and self._is_exposed(w.host) and not w.tls:
            log.warning(
                "admin console is listening on %s without TLS: the password and "
                "every API token cross the network in the clear. Set web.tls, or "
                "bind web.host to a management interface.", w.host)

    def _maybe_drop_privileges(self) -> None:
        s = self.config.server
        if not s.user and not s.group:
            return
        from .security.privdrop import PrivDropError, drop_privileges
        try:
            drop_privileges(s.user, s.group)
        except PrivDropError:
            log.exception("privilege drop failed; refusing to run as root")
            raise

    async def stop(self) -> None:
        self.scheduler.stop()
        if self.primary and self.config.cache.persist:
            try:
                self.cache.dump(self._cache_file())
            except Exception:
                log.exception("cache dump failed")
        if self.primary and self.learn is not None:
            try:
                self.learn.fold()   # capture the last window before persisting
                self.learn.dump(self._learn_file())
            except Exception:
                log.exception("popularity dump failed")
        if self.api is not None:
            await self.api.stop()
        if self.auth is not None:
            for sec in self.auth.secondaries.values():
                await sec.stop()
        for fe in self.frontends:
            await fe.stop()
        if self.querylog is not None:
            await self.querylog.stop()
        if self.db is not None:
            await self.db.close()
        self._stop.set()

    def _cache_file(self):
        return self.config.data_path / "cache.json"

    async def run(self) -> None:
        await self.setup_storage()
        if self.primary and self.config.cache.persist:
            try:
                n = self.cache.load(self._cache_file())
                if n:
                    log.info("restored %d cache entries from disk", n)
            except Exception:
                log.exception("cache restore failed")
        if self.primary and self.learn is not None:
            n = self.learn.load(self._learn_file())
            if n:
                log.info("restored %d learned popularity scores", n)
        await self.load_blocklists()
        await self.start()
        self._schedule_jobs()
        self._banner()
        await self._stop.wait()

    def _schedule_jobs(self) -> None:
        hours = self.config.gravity.refresh_hours
        if hours > 0 and self.config.filtering.sources:
            # Only the primary worker fetches and compiles (see
            # refresh_blocklists); the others map the result. That is both one
            # download instead of N and one compiled copy instead of N — with a
            # copy per worker, a small box gets OOM-killed.
            self.scheduler.every(hours * 3600, self.refresh_blocklists,
                                 name="gravity-refresh")
            if not self.primary and self.nworkers > 1:
                # Poll for the primary's rebuild. A stat every half minute is
                # free, and it bounds how long workers can disagree about policy.
                self.scheduler.every(30.0, self._poll_table, name="gravity-adopt")
        if self.querylog is not None:
            self.scheduler.every(3600, self.querylog.retention_sweep, name="retention")
        if self.learn is not None:
            self.scheduler.every(self.config.cache.prewarm_interval,
                                 self._prewarm_sweep, name="prewarm")

    def _stream_limits(self):
        """Connection bounds shared by every length-prefixed frontend. The caps
        are per worker, which is what the operator's number means on a box running
        several: each worker accepts its own share."""
        from .transport.stream import StreamLimits
        s = self.config.server
        return StreamLimits(idle_timeout=s.tcp_idle_timeout,
                            max_connections=s.tcp_max_connections,
                            max_per_client=s.tcp_max_per_client,
                            max_inflight=s.tcp_max_inflight)

    async def _poll_table(self) -> None:
        self.adopt_refreshed_table()

    async def _prewarm_sweep(self) -> None:
        """Fold the popularity window, then refresh the learned top names whose
        cache entries are missing or nearly expired."""
        from .learn import prewarm
        if self.learn is None:
            return              # only scheduled when prewarm is on; belt and braces
        self.learn.fold()
        await prewarm(self.learn, self.cache, self.pipeline.warm,
                      top=self.config.cache.prewarm_top)

    def _learn_file(self):
        return self.config.data_path / "popularity.json"

    def _banner(self) -> None:
        if not self.primary:
            log.info("worker %d/%d: Do53 on %s:%d (SO_REUSEPORT)", self.worker_idx,
                     self.nworkers, self.config.server.do53.host, self.config.server.do53.port)
            return
        s = self.config.server
        wk = f" x{self.nworkers} workers" if self.nworkers > 1 else ""
        log.info("DNS  : %s:%d (udp+tcp)%s", s.do53.host, s.do53.port, wk)
        log.info("upstream: %s [%s]", ", ".join(self.config.upstream.servers),
                 self.config.upstream.strategy)
        log.info("blocked domains: %d", self.filter.size)
