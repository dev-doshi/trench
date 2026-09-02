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
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .cache import Cache
from .clients import ClientRegistry
from .config import Config
from .engine import Pipeline
from .filter import FilterEngine, contract
from .filter.rule import Rule, operator_rules
from .filter.safebrowse import SafeBrowse
from .filter.services import Services
from .filter.shared import SharedBlockTable
from .gravity import Gravity
from .gravity.manager import cached_table_age
from .gravity.schedule import Scheduler
from .log import get
from .resolver.forwarder import Forwarder
from .stats import Counters
from .store import Database, QueryLog
from .transport.do53 import Do53Server

if TYPE_CHECKING:                       # imports kept lazy at runtime: an
    from .api import APIServer  # unused subsystem is never imported
    from .clients.activity import Ledger
    from .clients.names import HostNames
    from .engine.fastpath import FastPath
    from .learn import PopularityTracker
    from .ops.notary import Notary
    from .transport.base import Frontend

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
                 prebuilt_filter: FilterEngine | None = None,
                 record_ring=None, querylog_salt: bytes = b""):
        self.config = config
        # This worker's lane of the shared query-log ring, when running under the
        # supervisor. The primary drains it; the others fill it. See
        # store/ringlog.py for why the log needs one at all.
        self.record_ring = record_ring
        self.querylog_salt = querylog_salt
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
        self.forwarder = self._build_forwarder()
        self.forwarders = self._build_group_forwarders()
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
        self._bootstrap: asyncio.Task | None = None   # cold-start blocklist fetch
        self._bootstrap_cert: asyncio.Task | None = None  # first ACME issuance
        self._config_mtime: float | None = None   # see _adopt_changed_config
        self._gravity: Gravity | None = None
        # One blocklist build at a time; see `refresh_blocklists`.
        self._building = asyncio.Lock()
        self.pipeline = Pipeline(filter_engine=self.filter, cache=self.cache,
                                 forwarder=self.forwarder,
                                 forwarders=self.forwarders, counters=self.counters,
                                 config=config, clients=self.clients,
                                 services=self.services, safebrowse=self.safebrowse,
                                 zones=self.zones, plugins=self.plugins,
                                 workers=nworkers)
        # Wire-resident replay. Attached to the pipeline (which invalidates it
        # when the rules change) and to the cache (which invalidates it on a
        # flush), so there is no path that drops an answer without dropping the
        # recorded copy of it.
        # Quorum resolution for pinned names, armed in `_adopt_notary`.
        self.notary: Notary | None = None
        # Update checking, armed in `_adopt_updates` (primary worker only).
        self.updater: Any = None
        # Bypass evidence: who stopped talking to us, and where they went.
        self.ledger: Ledger | None = None
        if getattr(config.security, "silence_ledger", False):
            from .clients.activity import Ledger
            self.ledger = Ledger()
        # Assertions the last candidate rule set failed, if any.
        self.contract_failures: list = []
        # Set when DHCP starts with `register_dns` on (primary worker only).
        self.hostnames: HostNames | None = None
        self.pipeline.ledger = self.ledger
        # Encrypted-DNS discovery: what we tell clients about our own DoT/DoH/
        # DoQ endpoints, over DNS (DDR) and over DHCP (DNR).
        from .discovery import from_config as _discovery_from_config
        self.discovery = _discovery_from_config(config)
        self.pipeline.discovery = self.discovery
        self.fast: FastPath | None = None
        if config.server.fast_path:
            from .engine.fastpath import FastPath
            self.fast = FastPath(self.pipeline, max_entries=config.server.fast_path_entries)
            self.pipeline.fast = self.fast
            self.cache.on_flush = self.fast.clear
        # Automatic certificates. Primary only: one process renews, and the
        # others read the files it writes when they next bind a TLS listener.
        self.acme = None
        if config.acme.enabled and primary:
            from .security.certs import AcmeManager
            self.acme = AcmeManager(config, self.zones, config.data_path)
        self.learn: PopularityTracker | None = None
        if config.cache.enabled and config.cache.prewarm:
            from .learn import PopularityTracker
            self.learn = PopularityTracker()
            self.pipeline.learn = self.learn
        # Heterogeneous on purpose: DHCP and the block page are served
        # here too, and neither is a DNS Frontend.
        self.frontends: list[Any] = []
        self._stop = asyncio.Event()

    def _build_forwarder(self):
        """Construct the resolver named by `upstream.*`.

        Also the applier for those settings, so a change made in the console
        produces exactly the resolver a restart would have produced — the two
        used to be separate pieces of code, and only one of them ran.
        """
        u = self.config.upstream
        if u.mode == "recursive":
            from .resolver.recursive import RecursiveForwarder
            return RecursiveForwarder(
                timeout=u.timeout, validate=u.dnssec, qmin=u.qname_min,
                anchors=self._trust_anchors() if u.dnssec else None,
                budget=u.recursion_budget, max_queries=u.recursion_max_queries,
                query_timeout=u.recursion_query_timeout)
        return Forwarder(u.servers, strategy=u.strategy, timeout=u.timeout,
                         verify=u.verify, trust_ad=u.trust_ad,
                         udp_source_ports=u.udp_source_ports)

    def on_lease(self, ip: str, hostname: str) -> None:
        """What a granted DHCP lease changes here: the device is known to be
        present, and its name may now resolve.

        A method rather than a closure so it can be tested directly — this is
        the only path by which a lease reaches DNS.
        """
        if self.ledger is not None:
            self.ledger.note_lease(ip, hostname)
        if self.hostnames is None:
            return
        if self.hostnames.register(ip, hostname) and self.fast is not None:
            # A name asked for before its lease existed was answered NXDOMAIN,
            # and a recorded copy of that would keep being replayed for the whole
            # negative TTL — so the device that just registered would go on not
            # resolving. `register` returns "" when it declined, so a refused
            # registration drops nothing.
            self.fast.clear()

    def _static_names(self) -> set[str]:
        """Names the operator configured by hand, which a lease may not take."""
        out = {r.name.strip(".").lower() for r in self.config.local_records}
        out |= {z.origin.strip(".").lower() for z in self.config.zones}
        return out

    def _trust_anchors(self):
        """Root anchors from disk, or None to use the compiled-in pins.

        Read at build time rather than import time so a `systemctl reload` after
        a key roll picks up the new file — which is the whole reason for
        supporting the file at all.
        """
        from .resolver.dnssec.anchors import load_anchors
        configured = self.config.upstream.trust_anchors
        path = Path(configured) if configured else self.config.data_path / "root.key"
        anchors = load_anchors(path)
        if anchors:
            log.info("using %d root trust anchor(s) from %s", len(anchors), path)
            return anchors
        if configured:
            # An operator who named a file meant it. Falling back silently to the
            # pins would validate against keys they were trying to replace.
            log.warning("no usable trust anchors in %s; using the built-in pins",
                        path)
        return None

    def _build_group_forwarders(self) -> dict:
        """One forwarder per named upstream set in `upstream.groups`.

        A group is always a forwarding set, including when the default resolver
        is recursive: the reason to name a group is to send those clients to a
        particular server — a family filter, the office resolver — and going to
        the root instead would ignore the instruction.
        """
        u = self.config.upstream
        out: dict = {}
        for name, servers in (u.groups or {}).items():
            if not servers:
                log.warning("upstream group %r has no servers; ignoring", name)
                continue
            out[name] = Forwarder(servers, strategy=u.strategy, timeout=u.timeout,
                                  verify=u.verify, trust_ad=u.trust_ad,
                                  udp_source_ports=u.udp_source_ports)
        return out

    async def setup_storage(self) -> None:
        # Only the primary worker owns the SQLite database — one writer, as
        # SQLite wants. The others still keep a query log: it publishes into the
        # shared ring instead of writing, so the primary's table ends up holding
        # every worker's traffic rather than its own quarter of it.
        if not self.primary:
            await self._adopt_querylog()
            return
        self.db = Database(self.config.data_path / self.config.querylog.db)
        await self.db.connect()
        # Through the applier, so a query log brought up at boot and one brought
        # up by a settings change are the same query log, with the same retention
        # job behind it.
        await self._adopt_querylog()
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
        f = self.config.filtering
        return operator_rules(f.allow, f.deny)

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

    def _filter_groups(self) -> list:
        """Configured filtering groups as `GroupSpec`s."""
        from .filter.groups import GroupSpec
        return [GroupSpec(name=name, sources=list(g.sources), allow=list(g.allow),
                          deny=list(g.deny), inherit=g.inherit)
                for name, g in (self.config.filtering.groups or {}).items()]

    def _assertions(self):
        """The parsed contract. Re-read each time so a settings change applies
        to the very next refresh rather than the next restart."""
        return contract.parse_all(self.config.filtering.assertions)

    async def _audit(self, action: str, target: str, detail: str) -> None:
        """Record something the process itself did, in the same table the console
        writes to.

        One helper rather than an INSERT per call site: the first two of those
        named a `user` column this table does not have, so every write raised
        and was swallowed by its own `except Exception` — the failure mode the
        audit trail exists to prevent.
        """
        if self.db is None:
            return
        try:
            await self.db.execute(
                "INSERT INTO audit(ts, actor, action, target, detail, ip) "
                "VALUES(?,?,?,?,?,?)",
                (int(time.time()), "system", action, target, detail, ""))
        except Exception:
            log.exception("could not write the audit record for %s", action)

    async def _record_contract_failure(self, failures) -> None:
        """Leave the rejection where the console and the operator will find it."""
        await self._audit("blocklist refresh rejected", "gravity",
                          contract.summarise(failures))

    def _make_gravity(self, sources) -> Gravity:
        return Gravity(list(sources), list(self.config.filtering.allow),
                       list(self.config.filtering.deny), db=self.db,
                       table_path=self.table_path,
                       ip_sources=list(self.config.filtering.ip_sources),
                       groups=self._filter_groups())

    async def load_blocklists(self, *, allow_fetch: bool = True) -> bool:
        """Bring the filter up. Returns True if a network fetch is still owed.

        With `allow_fetch=False` this does only the local, offline work —
        adopting a pre-forked engine or mapping the cached table — and reports
        back rather than downloading. Startup uses that to bind the listener
        before touching the network: the sources are https:// URLs and on the
        usual deployment this box *is* the LAN's resolver, so fetching them
        first means resolving a hostname through a server that has not bound
        its socket yet, and the whole network is without DNS until it finishes.
        """
        sources = self.config.filtering.sources
        if not sources:
            log.info("no blocklist sources configured")
            return False
        self._gravity = self._make_gravity(sources)

        if self._prebuilt_filter is not None:
            # The supervisor already compiled these before forking; reuse its
            # shared table rather than fetching and parsing the same lists again.
            engine = self._prebuilt_filter
            self._prebuilt_filter = None
            self.filter = engine
            self.pipeline.filter = engine
            log.info("using pre-forked blocklist (%d domains)", engine.size)
            release_free_memory()
            return False

        # A resolver that cannot answer is worse than one answering from a
        # slightly old list, and re-parsing 600k domains takes a minute on small
        # hardware. So serve the last compiled table straight away and let the
        # normal refresh schedule bring it up to date in the background.
        age = cached_table_age(self.table_path)
        if age is not None:
            try:
                table = SharedBlockTable.open(self.table_path)
            except Exception as e:  # noqa: BLE001 — a bad table is always recoverable
                log.warning("cached block table unusable (%s); rebuilding", e)
            else:
                self._adopt_table(table)
                log.info("mapped cached block table: %d domains, %.1f MB, %.1f h old",
                         len(table), table.nbytes / 1_048_576, age / 3600)
                release_free_memory()
                if age < self.config.gravity.refresh_hours * 3600 or not self.primary:
                    return False  # still fresh, or a sibling worker owns the refresh
                log.info("cached table is past its refresh interval; rebuilding now")

        if not allow_fetch:
            return True

        engine = await self._gravity.build()
        # At first load there is nothing to fall back to: refusing here would
        # leave the resolver with no rules at all, which is worse than adopting
        # a set the operator will be told about. Reported loudly, then adopted.
        failures = contract.check(engine, self._assertions())
        if failures:
            self.contract_failures = failures
            log.error("the loaded blocklists violate this configuration's "
                      "assertions: %s", contract.summarise(failures))
        self.filter = engine
        self.pipeline.filter = engine
        self.pipeline.set_group_filters(getattr(self._gravity, "group_engines", {}))
        release_free_memory()
        return False

    async def refresh_blocklists(self) -> None:
        """Fetch and recompile the lists, one build at a time.

        The lock is not politeness. A build peaks at hundreds of megabytes on a
        box with a 700 MB ceiling and no swap, and there are three ways in — the
        refresh schedule, a settings change to `filtering.sources`, and SIGHUP —
        none of which knew about the others. Two builds at once is the OOM the
        ceiling exists to prevent.
        """
        if self._gravity is None:
            return
        if self._building.locked():
            log.info("a blocklist build is already running; skipping this one")
            return
        async with self._building:
            await self._refresh_locked()

    async def _refresh_locked(self) -> None:
        if self._gravity is None:
            return
        if not self.primary and self.nworkers > 1:
            # Only one worker per machine downloads and compiles. The others pick
            # the result up from the table file, so the lists are fetched once
            # and the compiled copy is shared instead of duplicated N times.
            self.adopt_refreshed_table()
            return
        previous = self.filter
        engine = await self._gravity.build()
        # A source that failed to fetch contributes zero rules, and the swap
        # went ahead regardless — so a transient outage at refresh time silently
        # unblocked every domain of every failing list, and the compiled table
        # was rewritten with the truncated corpus so the next restart served it
        # too. Keep what is already running instead; the schedule retries.
        report = getattr(self._gravity, "report", None)
        if report is not None and report.errors and previous is not None:
            log.warning("blocklist refresh kept the previous rules: %d of %d "
                        "sources failed (%s)", len(report.errors),
                        len(self._gravity.sources), "; ".join(report.errors[:3]))
            return
        # The operator's own contract for this network. A refresh that would
        # break a name they said must work is a bad deploy, and the answer to a
        # bad deploy is not to ship it — the lists will be fetched again on the
        # next schedule, and until then what is running is known-good.
        failures = contract.check(engine, self._assertions())
        if failures and previous is not None:
            self.contract_failures = failures
            log.error("blocklist refresh rejected: %s", contract.summarise(failures))
            await self._record_contract_failure(failures)
            return
        self.contract_failures = []
        # Compare against what was running *before* swapping, so the operator
        # gets a diff of what this update actually changed for their network.
        await self._record_list_review(previous, engine)
        self.filter = engine
        self.pipeline.filter = engine
        self.pipeline.set_group_filters(getattr(self._gravity, "group_engines", {}))
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

    def adopters(self) -> dict:
        """Every applier `api/settings.py` may name, and the method that runs it.

        The mapping is the contract. A field marked `adopt` names one of these;
        a name with nothing behind it is a setting that would be saved, badged
        as live, and then ignored — which is exactly the failure this table
        exists to make impossible. `tests/test_settings_apply.py` checks both
        directions.
        """
        return {
            "upstream": self._adopt_upstream,
            "cache": self._adopt_cache,
            "pipeline": self._adopt_pipeline,
            "clients": self._adopt_clients,
            "querylog": self._adopt_querylog,
            "fastpath": self._adopt_fastpath,
            "prewarm": self._adopt_prewarm,
            "gravity": self._adopt_gravity,
            "notary": self._adopt_notary,
            "updates": self._adopt_updates,
            "sources": self._adopt_sources,
            "log": self._adopt_log,
            "proxies": self._adopt_proxies,
        }

    async def apply_config(self, changed=None) -> None:
        """Re-read the config file and push it into the objects already running.

        Swapping `self.config` is not enough: the forwarder, the query log, the
        cache and the detectors each copied what they needed at construction, so
        a changed setting was written to disk, reported as saved, and then
        ignored by the process that was supposed to obey it.

        `changed` is the set of dotted paths the caller knows to have moved, and
        only the appliers those paths name are run — a log-level change has no
        business tearing down upstream connections. `None` means "assume
        everything moved", which is what SIGHUP means.
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

        from .api import settings as st
        names = st.ADOPTERS if changed is None else st.adopters_for(changed)
        table = self.adopters()
        for name in names:
            try:
                await table[name]()
            except Exception:
                log.exception("could not adopt %s settings", name)

    # ---- appliers ---------------------------------------------------------
    # One per group of settings that needs more than a swapped config tree.
    # Each is idempotent and safe to run when nothing in its group changed, so
    # SIGHUP can simply run all of them.

    async def _adopt_upstream(self) -> None:
        """Rebuild the forwarder from `upstream.*` and retire the old one."""
        retire = [self.forwarder, *self.forwarders.values()]
        self.forwarder = self._build_forwarder()
        self.forwarders = self._build_group_forwarders()
        self.pipeline.forwarder = self.forwarder
        self.pipeline.forwarders = self.forwarders
        self.cache.flush()   # answers came from servers we may no longer use
        for old in retire:
            close = getattr(old, "close", None)
            if close is not None:
                try:
                    await close()
                except Exception:
                    log.exception("closing the previous upstreams failed")

    async def _adopt_cache(self) -> None:
        c = self.config.cache
        self.cache.enabled = c.enabled
        self.cache.max_entries = c.max_entries
        self.cache.min_ttl = c.min_ttl
        self.cache.max_ttl = c.max_ttl
        self.cache.negative_ttl = c.negative_ttl
        self.cache.serve_stale = c.serve_stale
        self.cache.serve_stale_max = c.serve_stale_max

    async def _adopt_pipeline(self) -> None:
        c = self.config
        p = self.pipeline
        sec = c.security
        p.ede = bool(c.filtering.ede)
        p.stale_timeout = float(c.cache.serve_stale_client_timeout)
        p.rebinding = bool(sec.rebinding_protection)
        p.local_suffixes = tuple(sec.local_suffixes)
        p.use_0x20 = bool(sec.use_0x20)
        from .engine.ratelimit import RateLimiter
        p.ratelimiter = RateLimiter(sec.rate_limit, sec.rate_burst, workers=self.nworkers)
        if sec.dns_cookies and p.cookies is None:
            from .engine.cookies import CookieJar
            p.cookies = CookieJar()
        elif not sec.dns_cookies:
            p.cookies = None
        if sec.dga_detection:
            from .filter.dga import DGADetector
            p.dga = DGADetector(threshold=sec.dga_threshold, block=sec.dga_block,
                                workers=self.nworkers)
        else:
            p.dga = None
        if sec.tunnel_detection:
            from .filter.tunnel import TunnelDetector
            p.tunnel = TunnelDetector(threshold=sec.tunnel_threshold,
                                      block=sec.tunnel_block, workers=self.nworkers)
        else:
            p.tunnel = None
        if p.fast is not None:
            p.fast.clear()          # gates and policy may have moved underneath it

    async def _adopt_clients(self) -> None:
        """Rebuild the client registry, so a changed default policy takes hold.

        `filtering.safe_search` and its neighbours are the default every
        unconfigured client resolves under, and that default is baked into the
        registry at construction — not read per query.
        """
        await self.reload_clients()

    async def _adopt_querylog(self) -> None:
        c = self.config.querylog
        can_write = self.db is not None or self.record_ring is not None
        if c.enabled and self.querylog is None and can_write:
            self.querylog = QueryLog(
                self.db, retention_days=c.retention_days,
                privacy_level=c.privacy_level, ring=self.record_ring,
                # Every worker has to hash with the same salt, or level 2 makes
                # one domain look like `nworkers` different domains. The
                # supervisor settles it before the fork; the primary reads it
                # from the database itself.
                salt=self.querylog_salt or None,
                export=self._build_log_export())
            await self.querylog.start()
            self.pipeline.querylog = self.querylog
            if self.db is not None:
                self.scheduler.every(3600, self.querylog.retention_sweep,
                                     name="retention")
            log.info("query log started")
        elif not c.enabled and self.querylog is not None:
            self.scheduler.cancel("retention")
            self.pipeline.querylog = None
            await self.querylog.stop()
            self.querylog = None
            log.info("query log stopped")
        elif self.querylog is not None:
            self.querylog.privacy_level = c.privacy_level
            self.querylog.retention_days = c.retention_days
            current = getattr(self.querylog.export, "path", "")
            if current != c.export:
                if self.querylog.export is not None:
                    self.querylog.export.close()
                self.querylog.export = self._build_log_export()

    def _build_log_export(self):
        """The JSON-lines stream for the query log, if one is configured.

        Only the process that writes the table exports: the siblings hand their
        rows to it, so a per-worker export would emit the same query twice from
        one machine and miss the rest.
        """
        path = (self.config.querylog.export or "").strip()
        if not path or self.db is None:
            return None
        from .store.export import JsonLinesExport
        from .store.querylog import _COLUMNS
        log.info("exporting the query log as JSON lines to %s", path)
        return JsonLinesExport(path, _COLUMNS)

    async def _adopt_fastpath(self) -> None:
        s = self.config.server
        if s.fast_path and self.fast is None:
            from .engine.fastpath import FastPath
            self.fast = FastPath(self.pipeline, max_entries=s.fast_path_entries)
            self.pipeline.fast = self.fast
            self.cache.on_flush = self.fast.clear
            for fe in self.frontends:
                if hasattr(fe, "fast"):
                    fe.fast = self.fast
        elif not s.fast_path and self.fast is not None:
            self.fast.clear()
            self.fast = None
            self.pipeline.fast = None
            self.cache.on_flush = None
            for fe in self.frontends:
                if hasattr(fe, "fast"):
                    fe.fast = None

    async def _adopt_prewarm(self) -> None:
        c = self.config.cache
        want = bool(c.enabled and c.prewarm)
        if want and self.learn is None:
            from .learn import PopularityTracker
            self.learn = PopularityTracker()
            self.learn.load(self._learn_file())
            self.pipeline.learn = self.learn
        elif not want and self.learn is not None:
            self.pipeline.learn = None
            self.learn = None
        if want and self.primary:
            self.scheduler.every(c.prewarm_interval, self._prewarm_sweep, name="prewarm")
        else:
            self.scheduler.cancel("prewarm")

    async def _adopt_notary(self) -> None:
        """Re-arm the quorum checks for the pinned names (empty list disables)."""
        sec = self.config.security
        names = list(getattr(sec, "notary", []) or [])
        interval = int(getattr(sec, "notary_interval", 0) or 0)
        if not names or interval <= 0 or not self.primary:
            self.notary = None
            self.scheduler.cancel("notary")
            return
        from .ops.notary import Notary
        self.notary = Notary(self.forwarder, names, timeout=self.config.upstream.timeout)
        self.scheduler.every(interval, self._notary_round, name="notary")

    async def _notary_round(self) -> None:
        if self.notary is None:
            return
        # Follow the live forwarder: a settings change replaces it, and a notary
        # holding the retired one would be asking servers nothing else uses.
        self.notary.forwarder = self.forwarder
        for finding in await self.notary.run_once():
            await self._audit("notary", finding.name, finding.note)

    async def _adopt_updates(self) -> None:
        """Re-arm the update check, and rebuild the updater on the new settings.

        Primary worker only. Every worker would otherwise ask the index the
        same question on the same timer, and — far worse in `auto` mode — four
        of them would try to install into the same virtual environment at once.
        """
        cfg = self.config.updates
        if cfg.mode == "off" or not self.primary:
            self.updater = None
            self.scheduler.cancel("update-check")
            return
        from .ops.update import Updater
        self.updater = Updater(cfg, data_dir=self.config.data_path,
                               is_busy=self._building.locked, audit=self._audit)
        hours = int(cfg.check_interval_hours or 0)
        if hours > 0:
            # Offset so a fleet of Trenchs installed from the same image does
            # not arrive at the index in the same second, and so the check does
            # not land on top of the blocklist refresh at boot.
            self.scheduler.every(hours * 3600, self._update_tick,
                                 name="update-check", offset=300.0)
        else:
            self.scheduler.cancel("update-check")

    async def _update_tick(self) -> None:
        """The scheduled check. Never lets an update failure kill the job."""
        if self.updater is None:
            return
        try:
            await self.updater.tick()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("the scheduled update check failed")

    async def _adopt_gravity(self) -> None:
        """Re-arm the refresh schedule on the new interval (0 disables it)."""
        hours = self.config.gravity.refresh_hours
        if hours > 0 and self.config.filtering.sources:
            self.scheduler.every(hours * 3600, self.refresh_blocklists,
                                 name="gravity-refresh")
        else:
            self.scheduler.cancel("gravity-refresh")

    async def _adopt_sources(self) -> None:
        """The list of sources itself changed: fetch and recompile, in the background.

        `refresh_blocklists` and not `load_blocklists`: the latter is the
        start-up path and will happily map the cached table when it is still
        within its refresh interval, which is exactly the wrong answer here —
        that table was compiled from the *old* sources, so the operator's change
        would appear to have been accepted and then have no effect at all.

        Not awaited. Compiling a large corpus takes tens of seconds on the
        hardware this runs on, and the caller is an HTTP request holding the
        operator's browser open.
        """
        sources = self.config.filtering.sources
        if not sources:
            # Every source removed: nothing to compile, and the running engine
            # keeps only what the operator wrote by hand.
            self._gravity = None
            self.filter = FilterEngine.compile(self._config_rules())
            self.pipeline.filter = self.filter
            self.cache.flush()
            log.info("no blocklist sources configured; imported rules dropped")
            return
        self._gravity = self._make_gravity(sources)
        task = asyncio.ensure_future(self.refresh_blocklists())
        self._bootstrap = task
        task.add_done_callback(lambda f: not f.cancelled() and f.exception())

    async def _adopt_log(self) -> None:
        import logging
        logging.getLogger("trench").setLevel(self.config.log.level.upper())

    async def _adopt_proxies(self) -> None:
        """Re-parse `security.trusted_proxies` in place, for every holder."""
        entries = self.config.security.trusted_proxies
        if self.api is not None:
            self.api.trusted.replace(entries)
        for fe in self.frontends:
            trusted = getattr(fe, "trusted", None)
            if trusted is not None:
                trusted.replace(entries)

    async def reload(self) -> None:
        """Hot reload (SIGHUP): re-read config, re-apply it, and refresh the
        lists and data files — without dropping in-flight queries or rebinding
        sockets."""
        log.info("reload: re-reading config + refreshing lists")
        await self.apply_config()
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
            self._warn_about_inert_settings()
        # Do53 runs in EVERY worker. Prefer inherited pre-bound sockets (portable
        # multi-core: kernel fans datagrams out to whichever worker is idle);
        # fall back to SO_REUSEPORT when not running under the supervisor.
        fe: Frontend
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
            cert, key = self._tls_material(s.dot.cert, s.dot.key)
            fe = DoTServer(self.pipeline, s.dot.host, s.dot.port, cert, key,
                           data_dir, limits=self._stream_limits())
            await fe.start()
            self.frontends.append(fe)
        if s.doh.enabled:
            from .transport.doh import DoHServer
            cert, key = self._tls_material(s.doh.cert, s.doh.key)
            fe = DoHServer(self.pipeline, s.doh.host, s.doh.port, s.doh.path,
                           tls=s.doh.tls, cert=cert, key=key, data_dir=data_dir)
            await fe.start()
            self.frontends.append(fe)
        if s.doq.enabled:
            from .transport.doq import DoQServer
            cert, key = self._tls_material(s.doq.cert, s.doq.key)
            fe = DoQServer(self.pipeline, s.doq.host, s.doq.port, cert, key, data_dir,
                           limits=self._stream_limits())
            await fe.start()
            self.frontends.append(fe)
        if s.doh3.enabled:
            from .transport.doh3 import DoH3Server
            cert, key = self._tls_material(s.doh3.cert, s.doh3.key)
            fe = DoH3Server(self.pipeline, s.doh3.host, s.doh3.port, s.doh3.path,
                            cert, key, data_dir, limits=self._stream_limits())
            await fe.start()
            self.frontends.append(fe)
        if self.config.dhcp.enabled and self.config.dhcp.scope is not None:
            from .dhcp.scope import Scope
            from .dhcp.server import DhcpServer
            sc = self.config.dhcp.scope
            scope = Scope(sc.network, sc.range_start, sc.range_end, router=sc.router,
                          dns=sc.dns, lease_time=sc.lease_time, domain=sc.domain,
                          reservations=dict(sc.reservations))
            register = self.on_lease if self.ledger is not None else None
            if self.config.dhcp.register_dns:
                from .clients.names import HostNames
                self.hostnames = HostNames(
                    domain=sc.domain, network=sc.network,
                    reserved=self._static_names())
                self.pipeline.hostnames = self.hostnames
                register = self.on_lease
                log.info("DHCP leases will be published as %s names", sc.domain)
            self.dhcp = DhcpServer(scope, self.config.dhcp.server_ip or sc.router,
                                   dns_register=register,
                                   dnr_option=(self.discovery.dhcp_option()
                                               if self.discovery is not None else b""))
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
                web_cert, web_key = self._tls_material(self.config.web.cert,
                                                       self.config.web.key)
                ssl_ctx = server_ssl_context(web_cert, web_key,
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
                    "running as root with server.user unset: Trench will keep "
                    "full privileges after binding. Set server.user to shed them.")
        w = self.config.web
        if w.enabled and self._is_exposed(w.host) and not w.tls:
            log.warning(
                "admin console is listening on %s without TLS: the password and "
                "every API token cross the network in the clear. Set web.tls, or "
                "bind web.host to a management interface.", w.host)

    def _warn_about_inert_settings(self) -> None:
        """Say so when a setting is switched on in a mode that cannot honour it.

        These are not invalid combinations — the file validates, and each half is
        a legitimate value — so nothing else in the system has cause to mention
        them. The failure mode is an operator reading their own config back and
        counting a protection they do not have.
        """
        u = self.config.upstream
        if u.dnssec and u.mode != "recursive":
            log.warning(
                "upstream.dnssec is set but upstream.mode is %r: DNSSEC is "
                "validated only when resolving from the root. In forward mode "
                "the upstream validates, and the most this resolver can do is "
                "decide whether to relay its AD bit (upstream.trust_ad).", u.mode)
        f = self.config.filtering
        if f.block_page and f.block_mode != "custom_ip":
            log.warning(
                "filtering.block_page is on but filtering.block_mode is %r: a "
                "browser can only reach the explainer page if blocked names "
                "resolve to this host, which is what custom_ip does.", f.block_mode)

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
        for task in (self._bootstrap, self._bootstrap_cert):
            if task is not None and not task.done():
                task.cancel()
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
            # One frontend failing to close must not skip the query log (up to
            # 50k buffered rows) or the database (an unchecked-pointed WAL), and
            # must not turn SIGTERM into a traceback.
            try:
                await fe.stop()
            except Exception:
                log.exception("stopping %s failed", type(fe).__name__)
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
        # Local work only, then bind. Anything needing the network happens after
        # the listener is up, because on this deployment we are that network's
        # resolver — see load_blocklists.
        pending = await self.load_blocklists(allow_fetch=False)
        await self.start()
        if pending:
            log.info("serving now; fetching blocklists in the background")
            self._bootstrap = asyncio.create_task(self._initial_blocklist_fetch())
        await self._schedule_jobs()
        self._banner(pending)
        await self._stop.wait()

    async def _initial_blocklist_fetch(self) -> None:
        """Cold-start fetch, off the critical path. A failure here leaves the
        resolver answering unfiltered rather than not answering at all; the
        scheduled refresh retries on its own interval."""
        try:
            await self.load_blocklists()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("initial blocklist load failed; serving unfiltered")

    async def _schedule_jobs(self) -> None:
        # The blocklist refresh interval and the prewarm sweep are armed by the
        # same appliers a live settings change runs, so a schedule set at boot
        # and one set from the console cannot come out different.
        #
        # Only the primary worker fetches and compiles (see refresh_blocklists);
        # the others map the result. That is both one download instead of N and
        # one compiled copy instead of N — with a copy per worker, a small box
        # gets OOM-killed.
        await self._adopt_gravity()
        await self._adopt_notary()
        await self._adopt_updates()
        await self._adopt_prewarm()
        # The retention sweep belongs to the query log and is armed by its
        # applier (`_adopt_querylog`), which runs during `setup_storage`.
        if not self.primary and self.nworkers > 1:
            # The sibling workers' only channel back to the primary. A stat every
            # half minute is free, and it bounds how long workers can disagree
            # about policy — which they otherwise do indefinitely, because the
            # console runs in the primary and these are separate processes.
            self.scheduler.every(30.0, self._sync_with_primary, name="worker-sync")
        # Per-worker, and required: the limiter keys on the client address, so
        # without a reaper a spoofed-source flood grows its table until the box
        # is OOM-killed. Cheap enough to run regardless of the configured rate.
        if self.acme is not None:
            why = self.acme.reason_unavailable()
            if why is not None:
                log.warning("acme.enabled is set but cannot run: %s", why)
            else:
                # Twice a day. A certificate is renewed 30 days before it
                # expires, so the interval only decides how quickly a failed
                # attempt is retried, and a CA has rate limits worth respecting.
                self.scheduler.every(12 * 3600, self._renew_certificates,
                                     name="acme-renew")
                if self.acme.due():
                    self._bootstrap_cert = asyncio.ensure_future(
                        self._renew_certificates())
        self.scheduler.every(60.0, self._reap_ratelimiter, name="ratelimit-gc")
        if self.clients is not None and getattr(self.clients, "by_mac", None):
            # Only when a client is actually identified by MAC. Off the loop:
            # this shells out, and it used to do so on the query path.
            self.scheduler.every(30.0, self._refresh_neighbours, name="arp-refresh")

    async def _refresh_neighbours(self) -> None:
        from .clients.registry import refresh_neighbours
        try:
            await asyncio.to_thread(refresh_neighbours)
        except Exception:
            log.debug("neighbour table refresh failed", exc_info=True)

    async def _renew_certificates(self) -> None:
        if self.acme is not None:
            await self.acme.renew()

    async def _reap_ratelimiter(self) -> None:
        rl = getattr(self.pipeline, "ratelimiter", None)
        if rl is not None:
            rl.gc()

    def _tls_material(self, cert: str | None, key: str | None):
        """The certificate and key a TLS listener should use.

        An explicitly configured pair always wins — an operator who named a file
        meant that file. Otherwise, if ACME has obtained one, that is used; and
        failing both, the transports fall back to self-signing as they always
        have.
        """
        if cert and key:
            return cert, key
        if self.acme is not None and self.acme.cert_file.exists() \
                and self.acme.key_file.exists():
            return str(self.acme.cert_file), str(self.acme.key_file)
        return cert, key

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

    async def _sync_with_primary(self) -> None:
        """Pick up whatever the primary worker changed, by looking at its files.

        Two things can move underneath a sibling worker: the compiled block
        table, and the config file the console writes. Coordination is the
        filesystem in both cases — a `stat`, and an atomic replace on the
        writing side — so there is no IPC, no knowledge of the other processes,
        and a worker that misses a round catches it on the next one.

        Without the config half, a setting saved in the console reached the
        primary only. The other workers went on enforcing the old policy, so
        which answer a device got depended on which worker the kernel handed its
        datagram to.
        """
        self.adopt_refreshed_table()
        await self._adopt_changed_config()

    async def _adopt_changed_config(self) -> None:
        if not self._config_path:
            return
        try:
            mtime = os.stat(self._config_path).st_mtime
        except OSError:
            return
        if self._config_mtime is None:      # first look: record, do not re-apply
            self._config_mtime = mtime
            return
        if mtime == self._config_mtime:
            return
        self._config_mtime = mtime
        log.info("config file changed; adopting it in worker %d", self.worker_idx)
        await self.apply_config()

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

    def _banner(self, pending: bool = False) -> None:
        if not self.primary:
            log.info("worker %d/%d: Do53 on %s:%d (SO_REUSEPORT)", self.worker_idx,
                     self.nworkers, self.config.server.do53.host, self.config.server.do53.port)
            return
        s = self.config.server
        wk = f" x{self.nworkers} workers" if self.nworkers > 1 else ""
        log.info("DNS  : %s:%d (udp+tcp)%s", s.do53.host, s.do53.port, wk)
        log.info("upstream: %s [%s]", ", ".join(self.config.upstream.servers),
                 self.config.upstream.strategy)
        # On a first run the lists have not been compiled yet, and reporting
        # a bare 0 one line under "fetching blocklists in the background" reads
        # as "this is not filtering" to someone who has just installed it.
        if self.filter.size or not pending:
            log.info("blocked domains: %d", self.filter.size)
        else:
            log.info("blocked domains: none yet — the first list fetch is still running")
