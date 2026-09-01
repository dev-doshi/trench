"""The query pipeline. Each stage may set ctx.response and short-circuit.

P0 stages: validate -> filter -> cache -> forward -> finalize.
Later phases insert: access/ratelimit/cookies (P9), client policy (P4),
local/authoritative (P7), CNAME-cloak + DNSSEC (P2/P5), rebinding (P9).
"""
from __future__ import annotations

import asyncio
import copy
import struct
import time
from typing import TYPE_CHECKING, Any, NamedTuple

from ..cache import Cache, detach
from ..errors import UpstreamError
from ..filter import Action, Decision
from ..filter.cnamecloak import inspect as inspect_cloak
from ..filter.ipmatch import answer_addresses
from ..filter.safesearch import safe_target
from ..filter.svcparams import strip_ech_records
from ..log import get
from ..resolver.sanitize import sanitize
from ..stats import Counters
from ..store.querylog import record_from_ctx
from ..wire import RR, Class, Message, Question, Type
from ..wire import rdata as R
from ..wire.edns import ECS, Edns
from ..wire.name import Name
from ..wire.rrtypes import EDNSOption, Flags, Opcode, Rcode, type_to_text
from . import zerox20
from .context import QueryContext
from .cookies import COOKIE
from .rebinding import scrub
from .responses import build_block, build_rewrite

# Anything on the query path is imported here, once. A `from x import y` inside
# a per-query function is not free — it is a `__import__` call and a dict walk
# every time, measured at 0.6 us each and twelve of them per forwarded query,
# about 7% of that path — and after the first call it defers nothing, because
# the module is already in sys.modules. The imports below the TYPE_CHECKING
# guard are the ones that genuinely stay lazy: they are constructed by App only
# when their setting is on, so an unused subsystem is never imported at all.
if TYPE_CHECKING:                        # attached by App; imported lazily at
    from ..filter.dga import DGADetector  # runtime so a disabled subsystem is
    from ..filter.tunnel import TunnelDetector  # never imported at all
    from ..learn import PopularityTracker
    from .cookies import CookieJar
    from .fastpath import FastPath

log = get("pipeline")


class _Answer(NamedTuple):
    """The outcome of one upstream fetch.

    `resp` is the answer to serve. `block` is set instead when inspection
    rejected it (a cloaked CNAME), which is a verdict, not a failure — so it
    must not be confused with an exception, and must not be cached.
    """
    resp: Message | None
    block: object | None


def _detach_task(fut) -> None:
    """Let a future finish unobserved without an "exception was never retrieved"
    warning. Used when the waiter has already answered the client."""
    fut.add_done_callback(lambda f: not f.cancelled() and f.exception())


class Pipeline:
    def __init__(self, *, filter_engine, cache: Cache, forwarder,
                 counters: Counters, config, querylog=None, clients=None,
                 services=None, safebrowse=None, zones=None, plugins=None,
                 forwarders=None, workers: int = 1):
        # How many sibling workers share this machine's traffic. Every piece of
        # per-client state below — the rate-limit buckets, both detectors — lives
        # in this process only, so each sees about 1/N of a client's queries and
        # its thresholds have to be read in that light.
        self.workers = max(1, int(workers))
        self.fast: FastPath | None = None   # attached by App when enabled
        self._filter = filter_engine
        self.cache = cache
        self.forwarder = forwarder
        # Named upstream sets: {group name -> forwarder}. A client whose policy
        # names one resolves through it, and its answers are cached under a
        # separate key (see CacheKey.view) so they never reach anyone else.
        self.forwarders: dict = dict(forwarders or {})
        # Per-group filtering: {group name -> LayeredFilter over self._filter}.
        # Rebuilt from the compiled group engines whenever the rules change.
        self.group_filters: dict = {}
        self.counters = counters
        self.config = config
        self.querylog = querylog
        self.clients = clients          # ClientRegistry (P4)
        self.services = services        # Services (P4)
        self.safebrowse = safebrowse    # SafeBrowse (P4)
        self.zones = zones              # ZoneStore (P7)
        self.discovery: Any = None      # Discovery, when encrypted DNS is advertised
        self.hostnames: Any = None      # HostNames, when DHCP publishes leases
        self.ledger: Any = None         # clients.activity.Ledger, when enabled
        self.plugins = plugins          # PluginManager (P8)
        self.learn: PopularityTracker | None = None   # learned prewarm, set by App
        self._prefetching: set[Any] = set()  # cache keys with an in-flight prefetch
        self._prefetch_tasks: set[Any] = set()   # strong refs; see _prefetch
        self._inflight: dict[Any, Any] = {}       # cache key -> future for the query in flight
        # RFC 8767 §6 client response timer: how long a client waits for a
        # refresh before being handed retained stale data instead.
        self.stale_timeout = float(getattr(config.cache, "serve_stale_client_timeout", 1.8))
        self.ede = bool(getattr(getattr(config, "filtering", None), "ede", False))
        from .ratelimit import RateLimiter
        sec = getattr(config, "security", None)
        self.ratelimiter = RateLimiter(getattr(sec, "rate_limit", 0.0),
                                       getattr(sec, "rate_burst", 0),
                                       workers=self.workers)
        self.rebinding = bool(getattr(sec, "rebinding_protection", False))
        self.local_suffixes = tuple(getattr(sec, "local_suffixes", ()))
        self.use_0x20 = bool(getattr(sec, "use_0x20", False))
        self.cookies: CookieJar | None = None
        if getattr(sec, "dns_cookies", False):
            from .cookies import CookieJar
            self.cookies = CookieJar()
        self.dga: DGADetector | None = None
        if getattr(sec, "dga_detection", False):
            from ..filter.dga import DGADetector
            self.dga = DGADetector(threshold=sec.dga_threshold, block=sec.dga_block,
                                   workers=self.workers)
        self.tunnel: TunnelDetector | None = None
        if getattr(sec, "tunnel_detection", False):
            from ..filter.tunnel import TunnelDetector
            self.tunnel = TunnelDetector(threshold=sec.tunnel_threshold,
                                         block=sec.tunnel_block, workers=self.workers)
        self.enabled = True  # global blocking toggle
        # Timed pauses. `enabled` is the permanent switch; these are the "let it
        # through for five minutes" one, which is the control an operator
        # actually reaches for — the alternative is switching filtering off and
        # relying on a human to remember to switch it back.
        self.paused_until: float = 0.0            # everything, until this time
        self._client_pause: dict[str, float] = {}  # client ip -> until

    # ------------------------------------------------------------------ pause
    def pause(self, seconds: float, client: str = "") -> float:
        """Suspend filtering for `seconds`, globally or for one client.

        Returns the wall-clock time it resumes. A pause is deliberately not
        `enabled = False`: it expires on its own, so the network cannot be left
        unprotected by someone who forgot, and it can be scoped to the one
        device that needs it rather than the whole house.
        """
        until = time.time() + max(0.0, float(seconds))
        if client:
            self._client_pause[client] = until
        else:
            self.paused_until = until
        if self.fast is not None:
            self.fast.clear()
        return until

    def resume(self, client: str = "") -> None:
        """End a pause early."""
        if client:
            self._client_pause.pop(client, None)
        else:
            self.paused_until = 0.0
        if self.fast is not None:
            self.fast.clear()

    def paused(self, client_ip: str = "") -> bool:
        now = time.time()
        if self.paused_until > now:
            return True
        if self.paused_until:
            self.paused_until = 0.0        # expired; stop checking the clock
        if not client_ip:
            return False
        until = self._client_pause.get(client_ip)
        if until is None:
            return False
        if until > now:
            return True
        del self._client_pause[client_ip]
        return False

    @property
    def paused_any(self) -> bool:
        """True while any pause is in effect, for the replay table's gate."""
        now = time.time()
        return self.paused_until > now or any(u > now for u in self._client_pause.values())

    def pause_state(self) -> dict:
        now = time.time()
        return {
            "enabled": self.enabled,
            "paused_until": self.paused_until if self.paused_until > now else 0,
            "clients": {c: u for c, u in self._client_pause.items() if u > now},
        }

    @property
    def filter(self):
        return self._filter

    @filter.setter
    def filter(self, engine) -> None:
        """Swapping the rules invalidates every recorded reply.

        A blocklist refresh is the one event that can change a verdict without
        changing the query, so the wire-resident table has to be dropped with
        it. Doing that here rather than at each of the five call sites that
        rebuild the engine means a sixth cannot forget.
        """
        self._filter = engine
        if self.fast is not None:
            self.fast.clear()

    def set_group_filters(self, engines: dict) -> None:
        """Install compiled group engines: `{name: (engine, inherit)}`.

        Wrapped in `LayeredFilter`, which reads the default engine through a
        callback — so the next blocklist refresh moves every group with it
        instead of leaving them on the rules that were current when the group
        was built.
        """
        from ..filter.groups import LayeredFilter
        self.group_filters = {
            name: LayeredFilter(name, engine, lambda: self._filter, inherit)
            for name, (engine, inherit) in (engines or {}).items()
        }
        if self.fast is not None:
            self.fast.clear()

    def filter_for(self, policy) -> Any:
        """The rule set this client resolves under.

        A group named by a client but not compiled falls back to the default
        rules; `Config` refuses that combination at load, so reaching it means
        the group's own sources failed to fetch — in which case the household's
        rules are the right answer, not no rules at all.
        """
        group = getattr(policy, "group", "") or ""
        return self.group_filters.get(group, self._filter) if group else self._filter

    async def resolve(self, query: Message, client_ip: str, proto: str = "udp",
                      client_id: str = "") -> Message:
        ctx = await self.resolve_ctx(query, client_ip, proto, client_id)
        return ctx.response  # type: ignore[return-value]

    async def resolve_ctx(self, query: Message, client_ip: str, proto: str = "udp",
                          client_id: str = "") -> QueryContext:
        """As `resolve`, but hands back the whole context.

        The transport needs the verdict, not just the bytes: the wire-resident
        fast path may only record a reply once it knows *why* that reply was
        given (see `fastpath.FastPath._STORABLE`).
        """
        ctx = QueryContext(query=query, client_ip=client_ip, proto=proto, client_id=client_id)
        try:
            await self._run(ctx)
            if self.plugins is not None and self.plugins.active and ctx.response is not None:
                await self.plugins.on_answer(ctx)
        except Exception:  # never leak an exception to the wire
            log.exception("pipeline error for %s", ctx.qname)
            ctx.response = query.reply(Rcode.SERVFAIL)
            ctx.action = "failed"
        self._finalize(ctx)
        return ctx

    def _block(self, ctx: QueryContext, *, reason: str, source: str = "",
               rule: str = "") -> None:
        """Record a block verdict and build the answer for it.

        Every stage that blocks needs the same four config values and sets the
        same four context fields. Spelled out at each site, they drifted: some
        set `ctx.rule` and some did not, so what the query log and the RFC 8914
        error carried depended on which stage decided — for no reason a reader
        could see.
        """
        fc = self.config.filtering
        ctx.response = build_block(ctx.query, fc.block_mode, fc.block_ipv4, fc.block_ipv6)
        ctx.action = "blocked"
        ctx.reason, ctx.source, ctx.rule = reason, source, rule

    async def _run(self, ctx: QueryContext) -> None:
        q = ctx.query.question
        # 1. validate
        if ctx.query.qr or q is None or ctx.query.opcode != Opcode.QUERY:
            ctx.response = ctx.query.reply(Rcode.REFUSED)
            ctx.action = "refused"
            return

        fc = self.config.filtering

        # 1b. rate limit per client (anti-flood / anti-amplification)
        if self.ratelimiter.enabled and not self.ratelimiter.allow(ctx.client_ip):
            ctx.response = ctx.query.reply(Rcode.REFUSED)
            ctx.action = "ratelimited"
            return

        # 2. identify client -> effective policy
        if self.ledger is not None:
            self.ledger.note(ctx.client_ip, ctx.qname)
        policy = None
        if self.clients is not None:
            policy = self.clients.identify(ctx.client_ip, ctx.client_id)
            ctx.policy = policy
        # 2a. plugins may short-circuit the query
        if (self.plugins is not None and self.plugins.active
                and await self.plugins.on_query(ctx)):
            return

        # 2b. authoritative zones / local records (we own these names)
        if self.zones is not None and not self.zones.empty:
            auth = self.zones.resolve(ctx.query)
            if auth is not None:
                ctx.response = auth
                ctx.action = "authoritative"
                return

        # 2b-i. Encrypted-DNS discovery (RFC 9462). Before everything else that
        # could answer for it: `_dns.resolver.arpa` is a special-use name that
        # only the local resolver may answer, and a client's decision to upgrade
        # to DoT/DoH hangs on getting a straight answer to it.
        if self.discovery is not None:
            found = self.discovery.answers(ctx.query)
            if found is not None:
                ctx.response = found
                ctx.action = "authoritative"
                ctx.reason = "encrypted DNS discovery"
                return

        # 2b-ii. DHCP-learned device names. After configured zones (which the
        # operator wrote and therefore win) and before the cache, because these
        # names are ours: asking an upstream about `laptop.lan` both fails and
        # publishes the household's device names.
        if self.hostnames is not None:
            learned = self.hostnames.resolve(ctx.query)
            if learned is not None:
                ctx.response = learned
                ctx.action = "authoritative"
                ctx.reason = "dhcp lease"
                return

        # 2c. Firefox's DoH canary. Checked ahead of any client-specific policy:
        # the point is that no client's browser gets to unilaterally exit every
        # policy below this by auto-enabling encrypted DNS.
        sec = self.config.security
        if (getattr(sec, "block_doh_canary", False)
                and ctx.qname.lower() == "use-application-dns.net"):
            # NXDOMAIN specifically, and not `_block` — Firefox reads any
            # NOERROR here as "no DNS policy on this network" and turns its own
            # DoH on, so a sinkhole address (the `zero_ip` default) would answer
            # the canary in the affirmative and route around every policy below.
            ctx.response = ctx.query.reply(Rcode.NXDOMAIN)
            ctx.action = "blocked"
            ctx.reason, ctx.source = "DoH canary (Firefox)", "doh_canary"
            return

        # A pause is per client first, then global; either way it suspends every
        # filtering stage below without touching the permanent switch.
        active = self.enabled and not self.paused(ctx.client_ip)

        ctags = frozenset(getattr(policy, "ctags", frozenset()))
        pol_block = getattr(policy, "block", True)
        pol_safe_search = getattr(policy, "safe_search", False)
        pol_safe_browse = getattr(policy, "safe_browse", False)
        pol_parental = getattr(policy, "parental", False)
        pol_services = frozenset(getattr(policy, "services", frozenset()))

        # 3. safe search (independent of the block toggle)
        if pol_safe_search and active:
            target = safe_target(ctx.qname)
            if target:
                await self._safe_search_chain(ctx, target)
                ctx.action = "safesearch"
                ctx.reason = f"safe search -> {target}"
                return

        # 4. blocked services (per client, scheduled)
        if active and self.services is not None and pol_services:
            sid = self.services.is_blocked(ctx.qname, pol_services)
            if sid:
                self._block(ctx, reason=f"service blocked: {sid}", source="services")
                return

        # 5. safe browsing / parental
        if active and self.safebrowse is not None and (pol_safe_browse or pol_parental):
            cat = self.safebrowse.check(ctx.qname, safe_browse=pol_safe_browse,
                                        parental=pol_parental)
            if cat:
                self._block(ctx, reason=f"{cat} protection", source=cat)
                return

        # 6. filter (gravity + custom rules)
        if active and fc.enabled and pol_block:
            # $client rules match on the source IP, a CIDR containing it, or the
            # client's configured name — all three appear in real lists.
            cnames = frozenset(n for n in (policy.name if policy else "",) if n)
            d = self.filter_for(policy).match(ctx.qname, ctx.qtype, ctags=ctags,
                                              client=ctx.client_ip,
                                              client_names=cnames)
            if d.action == Action.BLOCK:
                self._block(ctx, reason=d.reason, source=d.source, rule=d.rule)
                return
            if d.action == Action.REWRITE:
                ctx.response = build_rewrite(ctx.query, d)
                ctx.action = "rewrite"
                ctx.reason, ctx.rule = d.reason, d.rule
                return
            # ALLOW falls through to resolution (just skips blocking)

        # 6b. real-time DGA detection: a random-looking name is only a prior, so
        # it is flagged and still resolved. Blocking waits until the client has
        # actually been seen cycling through failed random names (a campaign) —
        # scoring alone cannot tell malware from WiFi-calling or CDN hostnames.
        if active and self.dga is not None:
            res = self.dga.check(ctx.qname, ctx.client_ip)
            if res.suspicious:
                self.counters.note_dga(ctx.qname)
                ctx.reason = res.reason
                ctx.source = "dga"
                if res.block:
                    self._block(ctx, reason=res.reason, source="dga")
                    return
                # flag-only: annotate and keep resolving

        # 6c. DNS tunneling / exfiltration detection
        if active and self.tunnel is not None:
            res = self.tunnel.inspect(ctx.qname, ctx.qtype, ctx.client_ip)
            if res.suspicious:
                self.counters.note_tunnel(ctx.qname)
                ctx.reason, ctx.source = res.reason, "tunnel"
                if self.tunnel.block:
                    self._block(ctx, reason=res.reason, source="tunnel")
                    return

        # 7. cache (ECS scope keeps per-subnet answers separate, and so does
        # the client's upstream group — a different resolver is a different
        # answer, however identical the question)
        ecs_scope = self._ecs_scope(ctx)
        key = self.cache.key_for(ctx.query, ecs=ecs_scope, view=self._view(ctx))
        if key is not None:
            hit = self.cache.get(key)
            if hit is None and key.ecs:
                # An answer the upstream marked scope 0 is filed globally, so a
                # subnet-scoped miss still has to check there before forwarding.
                hit = self.cache.get(key._replace(ecs=""))
            if hit is not None:
                resp, stale = hit
                ctx.response = resp
                ctx.action = "cached"
                ctx.reason = "stale" if stale else ""
                if self.config.cache.prefetch and not stale:
                    self._maybe_prefetch(ctx, key)
                return

        # 8. resolve upstream (composes ECS + 0x20, coalescing, serve-stale)
        await self._resolve_upstream(ctx, key)

    # ------------------------------------------------------------------ upstream
    async def _resolve_upstream(self, ctx: QueryContext, key) -> None:
        """Get an answer from upstream, or fall back to retained stale data.

        Stale data is a fallback, never a shortcut (RFC 8767): the refresh is
        always attempted. It is used when that refresh fails, and — if a stale
        copy is on hand — when the refresh outlives the client response timer,
        in which case the refresh is left running to repair the cache.
        """
        fetch = asyncio.ensure_future(self._fetch_coalesced(ctx, key))
        wait = self.stale_timeout if (self.stale_timeout and key is not None
                                      and self.cache.has_stale(key)) else None
        try:
            if wait is None:
                answer = await fetch
            else:
                try:
                    answer = await asyncio.wait_for(asyncio.shield(fetch), wait)
                except TimeoutError:
                    _detach_task(fetch)   # keep refreshing in the background
                    if self._serve_stale(ctx, key, "stale-refreshing"):
                        return
                    answer = await fetch
        except Exception as e:
            if self._serve_stale(ctx, key, "stale-fallback"):
                return
            log.warning("upstream failed for %s: %s", ctx.qname, e)
            ctx.response = ctx.query.reply(Rcode.SERVFAIL)
            ctx.action = "failed"
            return
        if answer.block is not None:
            d = answer.block
            self._block(ctx, reason=d.reason, source=d.source, rule=d.rule)
            return
        ctx.response = answer.resp
        ctx.action = "forwarded"

    def _serve_stale(self, ctx: QueryContext, key, reason: str) -> bool:
        """Answer from a retained expired entry. False when there is none."""
        if key is None:
            return False
        stale = self.cache.get(key, allow_stale=True)
        if stale is None:
            return False
        ctx.response = stale[0]
        ctx.action = "cached"
        ctx.reason = reason
        return True

    def _view(self, ctx: QueryContext) -> str:
        """The named upstream set this client resolves through, or "".

        A group that is not configured falls back to the default resolver here,
        which is why `Config` refuses to load a client naming an unknown group:
        catching it at startup is the only place where the fallback can still
        be prevented rather than served.
        """
        group = getattr(ctx.policy, "upstream_group", "") or ""
        return group if group in self.forwarders else ""

    def _forwarder_for(self, ctx: QueryContext):
        return self.forwarders.get(self._view(ctx), self.forwarder)

    async def _forward(self, fwd: Message, ctx: QueryContext) -> Message:
        """Send upstream and record which server answered.

        `ctx.upstream` is what the query log, the per-upstream stats and the
        unsolicited-record warning all report. It was never being set, so the
        operator's upstream breakdown was permanently empty and a warning about a
        misbehaving upstream could not say which one.

        The callback is passed unconditionally: `plugins.api.Resolver` states
        that a resolver accepts it, so a forwarder that does not is a broken
        implementation and should say so, rather than quietly reverting the
        whole upstream breakdown to empty.
        """
        def note(who: str) -> None:
            ctx.upstream = who
        return await self._forwarder_for(ctx).resolve(fwd, note)

    async def warm(self, query: Message) -> Message | None:
        """Resolve and cache `query` as if a client had asked it.

        For background jobs with no client behind them (the learned-prewarm
        sweep). It goes through `_fetch`, keeping that the only route into the
        cache: an unattended job writing raw upstream answers straight into the
        cache is the last place anyone would think to look for a poisoned entry.
        No ECS scope is applied — there is no client subnet to scope to.
        """
        ctx = QueryContext(query=query, client_ip="127.0.0.1", proto="internal")
        return (await self._fetch(ctx, self.cache.key_for(query))).resp

    async def _fetch_coalesced(self, ctx: QueryContext, key) -> _Answer:
        """One upstream query per distinct question in flight.

        N clients asking the same question at the same moment used to produce N
        identical upstream queries. That wastes upstream capacity, and RFC 5452
        §9.2 makes it a security problem too: every extra outstanding query for
        the same name is another chance for an off-path spoofer to match one of
        them — a birthday attack. Followers wait for the leader's answer and get
        their own copy of it, because the caller goes on to rewrite the id,
        question and EDNS of whatever it is handed.

        The table is per worker, so a multi-worker deployment collapses a burst to
        at most one query per worker rather than one overall. Closing that would
        mean coordinating in-flight state through the shared cache, which is a
        lock on the hot path to save at most three queries.
        """
        if key is None:
            return await self._fetch(ctx, key)
        leader = self._inflight.get(key)
        if leader is not None and not leader.done():
            answer = await asyncio.shield(leader)
            if answer.resp is None:
                return answer
            return _Answer(detach(answer.resp), None)
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._inflight[key] = fut
        try:
            answer = await self._fetch(ctx, key)
        except BaseException as e:
            if not fut.done():
                # A cancelled leader must not cancel its followers. CancelledError
                # is a BaseException, so handing it over sails straight past the
                # followers' `except Exception` and they end cancelled too —
                # no SERVFAIL, no stale fallback, no reply at all for the whole
                # burst. Their own query was never cancelled; only ours was.
                fut.set_exception(
                    UpstreamError("upstream query cancelled")
                    if isinstance(e, asyncio.CancelledError) else e)
            raise
        else:
            if not fut.done():
                fut.set_result(answer)
            return answer
        finally:
            if self._inflight.get(key) is fut:
                del self._inflight[key]
            _detach_task(fut)   # followers may all have gone away

    async def _fetch(self, ctx: QueryContext, key) -> _Answer:
        """The only path by which an upstream answer enters this resolver.

        Every check that hardens or rejects an answer lives here — 0x20
        verification, unsolicited-record removal, cloak inspection, the
        rebinding scrub — and so does the cache write. Prefetch and background
        refreshes go through it as well, so there is no second, softer way in.
        """
        fc = self.config.filtering
        fwd, orig = self._prepare_forward(ctx)
        resp = await self._forward(fwd, ctx)
        if orig is not None:
            if not zerox20.verify(resp, fwd.question.name):
                raise UpstreamError("0x20 case mismatch (possible spoof)")
            zerox20.restore(resp, orig)
        # 8a. Discard records the upstream was not asked for. Runs before
        # anything else reads the response, so every later stage — cloak
        # inspection, rebinding scrub, the cache — only ever sees records
        # that legitimately answer this question.
        cut = sanitize(resp, ctx.qname)
        if cut.answers:
            # An upstream attaching answers for other names is either broken
            # or hostile; either way the operator should hear about it.
            log.warning("dropped %d unsolicited answer record(s) for %s from %s",
                        cut.answers, ctx.qname, ctx.upstream or "upstream")
        # 8a-ii. ECH policy on HTTPS/SVCB answers. Before the cache, so what is
        # stored is what clients will be given.
        if getattr(fc, "ech", "pass") == "strip":
            strip_ech_records(resp)
        # 8b. CNAME-cloak inspection: a first-party CNAME may resolve to a
        # blocked tracker — sinkhole if so.
        if (self.enabled and fc.enabled and fc.cname_inspect
                and hasattr(self.filter, "match") and resp.answers):
            pol = ctx.policy
            try:
                d = inspect_cloak(self.filter_for(ctx.policy), resp, ctx.qtype,
                            ctags=frozenset(getattr(pol, "ctags", ()) or ()),
                            client=ctx.client_ip,
                            client_names=frozenset(
                                n for n in (getattr(pol, "name", "") or "",) if n))
            except Exception:
                d = None
            if d is not None and d.blocked:
                return _Answer(None, d)   # and deliberately not cached
        # 8b-ii. Address lists: the name in the question may be new, but the
        # network the answer points into usually is not. Runs after the cloak
        # check so a cloaked name is still reported as a cloak.
        if self.enabled and fc.enabled and getattr(fc, "block_answer_ips", False):
            ips = getattr(self.filter, "ips", None)
            if ips:
                for addr in answer_addresses(resp):
                    hit = ips.match(addr)
                    if hit is not None:
                        return _Answer(None, Decision(
                            action=Action.BLOCK, rule=addr, source=hit or "ip-list",
                            reason=f"answer address {addr} is listed"))
        # 9. DNS-rebinding protection: strip private IPs from public answers
        if self.rebinding:
            scrub(resp, ctx.qname, local_suffixes=self.local_suffixes)
        if key is not None:
            self.cache.put(self._scoped_key(key, resp), resp)
        return _Answer(resp, None)

    @staticmethod
    def _scoped_key(key, resp):
        """Re-key an answer onto the scope the upstream actually declared.

        RFC 7871 §7.3.1: SCOPE PREFIX-LENGTH is the server's statement of how
        widely its answer applies, and scope 0 means "for every client". Storing
        under the asking client's own /24 regardless kept one duplicate entry
        per subnet for answers that were never subnet-specific, so a network
        with many subnets cached the same reply once per subnet and missed on
        all of them.
        """
        if not key.ecs or resp.edns is None:
            return key
        try:
            ecs = resp.edns.get_ecs()
        except Exception:
            return key
        if ecs is None or ecs.scope_prefix == 0:
            return key._replace(ecs="")      # global: one entry serves everyone
        return key

    def _ecs_scope(self, ctx: QueryContext) -> str:
        if getattr(self.config.upstream, "ecs", "off") != "forward":
            return ""
        try:
            return ECS.from_client(ctx.client_ip).network_text()
        except Exception:
            return ""

    def _prepare_forward(self, ctx: QueryContext):
        """Build the query to send upstream: apply ECS policy (forward/strip) and
        0x20 case randomization. Returns (forward_query, original_name_or_None)."""
        q = ctx.query
        fwd = q
        ecs_mode = getattr(self.config.upstream, "ecs", "off")
        if ecs_mode in ("forward", "strip"):
            fwd = copy.copy(q)
            fwd.questions = list(q.questions)
            base = q.edns
            if base is not None or ecs_mode == "forward":
                edns = Edns(udp_size=(base.udp_size if base else 1232),
                            flags=(base.flags if base else 0),
                            options=[o for o in (base.options if base else [])
                                     if o[0] != EDNSOption.ECS])
                if ecs_mode == "forward":
                    try:
                        edns.set_ecs(ECS.from_client(ctx.client_ip))
                    except Exception:
                        pass
                fwd.edns = edns
        # 0x20 case randomization (clone if not already cloned)
        orig = None
        if self.use_0x20 and q.question is not None:
            if fwd is q:
                fwd = copy.copy(q)
                fwd.questions = list(q.questions)
            rnd = zerox20.randomize_name(q.question.name)
            fwd.questions = [Question(rnd, q.question.rtype, q.question.rclass)]
            orig = q.question.name
        return fwd, orig

    def _maybe_prefetch(self, ctx: QueryContext, key) -> None:
        """Refresh a popular entry shortly before it expires (optimistic caching).

        Goes through `_fetch` like any other query. It used to call the forwarder
        directly and write the raw response into the cache, which made prefetch a
        second entrance that skipped 0x20 verification, unsolicited-record
        removal and the rebinding scrub — everything a client-driven query is
        checked for, on the one path nobody is waiting to notice.
        """
        rem = self.cache.remaining(key)
        if rem is None or rem > 30:
            return
        if key in self._prefetching:
            return
        self._prefetching.add(key)

        async def refresh():
            try:
                await self._fetch(ctx, key)
            except Exception:
                pass
            finally:
                self._prefetching.discard(key)

        task = asyncio.ensure_future(refresh())
        self._prefetch_tasks.add(task)
        task.add_done_callback(self._prefetch_tasks.discard)

    async def _safe_search_chain(self, ctx: QueryContext, target: str) -> None:
        """Answer with CNAME qname->safe-target, resolving the target's address
        so stub clients get a complete chain."""
        q = ctx.query.question
        resp = ctx.query.reply(Rcode.NOERROR)
        tgt = Name.from_text(target)
        resp.answers.append(RR(q.name, Type.CNAME, Class.IN, 300, R.CNAME(tgt)))
        if q.rtype in (Type.A, Type.AAAA):
            sub = Message(id=0)
            sub.set_flag(Flags.RD, True)
            sub.questions.append(Question(tgt, q.rtype, Class.IN))
            try:
                up = await self.forwarder.resolve(sub)
                for rr in up.answers:
                    if rr.rtype == q.rtype:
                        resp.answers.append(RR(tgt, rr.rtype, Class.IN, rr.ttl, rr.rdata))
            except Exception:
                pass
        ctx.response = resp

    def _finalize(self, ctx: QueryContext) -> None:
        resp = ctx.response
        if resp is None:
            resp = ctx.response = ctx.query.reply(Rcode.SERVFAIL)
        resp.id = ctx.query.id
        if not resp.questions:
            resp.questions = list(ctx.query.questions)
        # mirror EDNS presence (size/DO) so clients see a well-formed OPT
        if ctx.query.edns is not None and resp.edns is None:
            resp.edns = Edns(udp_size=self.config.server.edns_udp_size)
            resp.edns.do = ctx.query.edns.do
        elif ctx.query.edns is None and resp.edns is not None:
            # RFC 6891 §6.1.1: no OPT in a response to a query that had none. The
            # OPT here came from the upstream, possibly by way of the cache, so
            # without this a client that never spoke EDNS receives another
            # client's options — including, with cookies enabled, a server cookie
            # bound to that other client's address.
            resp.edns = None
        # DNS cookies: echo client cookie + our server cookie (RFC 7873)
        if self.cookies is not None and ctx.query.edns is not None:
            cc = ctx.query.edns.get_option(COOKIE)
            if cc and len(cc) >= 8 and resp.edns is not None:
                resp.edns.set_option(COOKIE, self.cookies.make_response(cc, ctx.client_ip))
        # RFC 8914 Extended DNS Error: carry the block reason in-band, so
        # `dig`/browsers/debug tools can show WHY a name was blocked
        if self.ede and ctx.action == "blocked" and resp.edns is not None:
            txt = (ctx.rule or ctx.reason or "blocked")[:200].encode("utf-8", "replace")
            resp.edns.set_option(EDNSOption.EXTENDED_ERROR,
                                 struct.pack(">H", 15) + txt)   # 15 = Blocked
        qname = ctx.qname or "."
        qtype = type_to_text(ctx.qtype)
        rcode = _rcode_text(resp.rcode)
        # DGA needs the outcome, not just the name: a random-looking name that
        # failed to resolve is evidence of a campaign, one that resolved is
        # evidence of real infrastructure.
        if self.dga is not None and ctx.action not in ("blocked", "block"):
            self.dga.note_outcome(qname, ctx.client_ip, rcode)
        # learned prewarm: only names we actually served count as "used" —
        # blocked/refused names must never be kept warm
        if self.learn is not None and ctx.action in ("cached", "forwarded"):
            self.learn.note(qname)
        self.counters.record(
            client=ctx.client_ip, qname=qname, qtype=qtype, action=ctx.action,
            rcode=rcode, upstream=ctx.upstream, elapsed_us=ctx.elapsed_us(),
            reason=ctx.reason,
        )
        if self.querylog is not None:
            answers = [rr.rdata.to_text() for rr in resp.answers if rr.rtype != Type.OPT]
            self.querylog.enqueue(record_from_ctx(qname, qtype, ctx, rcode, answers))


def _rcode_text(rc: int) -> str:
    try:
        return Rcode(rc).name
    except ValueError:
        return str(rc)
