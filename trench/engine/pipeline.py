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
from ..config import Config
from ..errors import TrenchError, UpstreamError
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
from .access import PLAINTEXT, RecursionAcl
from .context import QueryContext
from .cookies import COOKIE
from .localonly import is_local_only
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

#: Failures that are the upstream's or the network's, not ours. Anything else
#: reaching the handler in `_resolve_upstream` is a bug in this package.
_UPSTREAM_FAULTS = (TrenchError, OSError, TimeoutError)

#: Shared empty set for the `$client` name match — see `_run`.
_NO_NAMES: frozenset[str] = frozenset()

#: How close to expiry an entry must be before a query refreshes it early.
#: Read by `_maybe_prefetch` and by the fast path, which have to agree: if the
#: fast path replayed inside a window the cache would not refresh in, it would
#: schedule a refresh on every query for the rest of the entry's life.
PREFETCH_WINDOW = 30
#: Most prefetches in flight at once. Every popular entry near expiry spawns
#: one, and without a bound a burst of them — after a restart restores a cache
#: whose entries all expire together — hit the upstream all at the same moment.
PREFETCH_MAX = 64


class _Answer(NamedTuple):
    """The outcome of one upstream fetch.

    `resp` is the answer to serve. `block` is set instead when inspection
    rejected it (a cloaked CNAME), which is a verdict, not a failure — so it
    must not be confused with an exception, and must not be cached.
    """
    resp: Message | None
    #: A `Decision`, from the cloak inspection or built where an answer is
    #: rejected. Typed as `object` it was three unchecked attribute reads at the
    #: one place that unpacks it.
    block: Decision | None


#: EDNS options that describe one hop, never the answer. A client's cookie,
#: padding or keepalive must not travel upstream, and an upstream's must neither
#: be cached nor reach a client: a stored COOKIE is the upstream's server cookie
#: for *our* address, replayed to every later asker.
_HOP_BY_HOP = frozenset({EDNSOption.COOKIE, EDNSOption.TCP_KEEPALIVE,
                         EDNSOption.PADDING})


def _detach_task(fut) -> None:
    """Let a future finish unobserved without an "exception was never retrieved"
    warning. Used when the waiter has already answered the client."""
    fut.add_done_callback(lambda f: not f.cancelled() and f.exception())


class Pipeline:
    def __init__(self, *, filter_engine, cache: Cache, forwarder,
                 counters: Counters, config: Config, querylog=None, clients=None,
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
        #: True while any installed rule set scopes a rule to particular
        #: clients. Recomputed by `_refresh_client_rules` from the two setters
        #: below, which are the only ways an engine is ever installed — see
        #: `any_client_rules`.
        self._any_client_rules = False
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
        #: Prefetches issued and prefetches that came back with an answer. An
        #: operator cannot otherwise tell optimistic caching from a cache that
        #: simply expires — the two look identical from outside.
        self.prefetches = 0
        self.prefetch_failures = 0
        self._inflight: dict[Any, Any] = {}       # cache key -> future for the query in flight
        # RFC 8767 §6 client response timer: how long a client waits for a
        # refresh before being handed retained stale data instead.
        self.stale_timeout = float(getattr(config.cache, "serve_stale_client_timeout", 1.8))
        self.ede = bool(getattr(getattr(config, "filtering", None), "ede", False))
        from .ratelimit import RateLimiter
        sec = config.security
        self.ratelimiter = RateLimiter(getattr(sec, "rate_limit", 0.0),
                                       getattr(sec, "rate_burst", 0),
                                       workers=self.workers)
        self.recursion_acl = RecursionAcl(getattr(sec, "recursion_clients", ()))
        self.rebinding = bool(getattr(sec, "rebinding_protection", False))
        self.local_suffixes = tuple(getattr(sec, "local_suffixes", ()))
        self.use_0x20 = bool(getattr(sec, "use_0x20", False))
        self.cookies: CookieJar | None = None
        if sec.dns_cookies:
            from .cookies import CookieJar
            self.cookies = CookieJar()
        self.dga: DGADetector | None = None
        if sec.dga_detection:
            from ..filter.dga import DGADetector
            self.dga = DGADetector(threshold=sec.dga_threshold, block=sec.dga_block,
                                   workers=self.workers)
        self.tunnel: TunnelDetector | None = None
        if sec.tunnel_detection:
            from ..filter.tunnel import TunnelDetector
            self.tunnel = TunnelDetector(threshold=sec.tunnel_threshold,
                                         block=sec.tunnel_block)
        self._refresh_client_rules()
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
        # A pause is a rare, operator-initiated state, and this is asked on
        # every query. When nothing is paused there is nothing to compare
        # against, so neither the clock read nor the dict lookup below is worth
        # doing — both tables being empty is already the whole answer.
        if not self.paused_until and not self._client_pause:
            return False
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
        """True while any pause is in effect, for the replay table's gate.

        Read once per replayed query, so the no-pause case — which is every
        query on a box nobody has paused — answers without reading the clock or
        walking the per-client table.
        """
        if not self.paused_until and not self._client_pause:
            return False
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
        self._refresh_client_rules()
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
        self._refresh_client_rules()
        if self.fast is not None:
            self.fast.clear()

    @property
    def any_client_rules(self) -> bool:
        """True while any installed rule set carries a `$client` rule.

        Read once per query by the replay table's gate, which has to stand down
        entirely while such a rule exists: `$client` matches on the source
        address, and the address is not in the replay key. Working it out from
        the engines each time meant building a list of them per query, so it is
        derived when the engines are installed instead — `filter`'s setter and
        `set_group_filters` are the only two places that can install one.
        """
        return self._any_client_rules

    def _refresh_client_rules(self) -> None:
        engines = [self._filter, *[g.own for g in self.group_filters.values()]]
        self._any_client_rules = any(
            getattr(e, "has_client_rules", False) for e in engines if e is not None)

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
        bad = _header_error(ctx.query)
        if bad is not None:
            ctx.response = ctx.query.reply(bad)
            ctx.action = "refused"
            ctx.reason = _HEADER_REASON[bad]
            return
        if q is None:
            # RFC 7873 §5.4: a query with no question and a client cookie is how
            # a client fetches a server cookie. Answered NOERROR; `_finalize`
            # attaches the cookie.
            ctx.response = ctx.query.reply(Rcode.NOERROR)
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

        # 2b-0. Everything past this point is recursion or names that are ours
        # to keep (device names, discovery): plaintext DNS from outside the
        # local networks stops here. See engine/access.py.
        if ctx.proto in PLAINTEXT and not self.recursion_acl.allows(ctx.client_ip):
            ctx.response = ctx.query.reply(Rcode.REFUSED)
            ctx.action = "refused"
            ctx.reason = "recursion not allowed for this client"
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

        # 2b-iii. Names that are never forwarded (see engine/localonly.py): after
        # zones, discovery and DHCP names, which may answer them, and before
        # the filter, whose lists have no business with them. A route the
        # operator configured for one — the router's reverse zone — still wins.
        if is_local_only(ctx.qname, self.local_suffixes) and not self._routed(ctx):
            ctx.response = ctx.query.reply(Rcode.NXDOMAIN)
            ctx.action = "authoritative"
            ctx.reason = "local-only name"
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

        # 6. filter (gravity + custom rules). An allow rule, or a client whose
        # policy says unfiltered, also exempts the name from the detectors
        # below: they are guesses, and the operator has already answered.
        screen = active and pol_block
        if active and fc.enabled and pol_block:
            # $client rules match on the source IP, a CIDR containing it, or the
            # client's configured name — all three appear in real lists.
            #
            # Built only when some rule actually scopes itself to a client.
            # Otherwise `_applicable` never looks at it, and this was a genexp
            # and a frozenset allocated per query to be ignored.
            cnames = _NO_NAMES
            if self._any_client_rules and policy is not None and policy.name:
                cnames = frozenset((policy.name,))
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
            if d.action == Action.ALLOW:
                screen = False

        # 6b. real-time DGA detection: a random-looking name is only a prior, so
        # it is flagged and still resolved. Blocking waits until the client has
        # actually been seen cycling through failed random names (a campaign) —
        # scoring alone cannot tell malware from WiFi-calling or CDN hostnames.
        if screen and self.dga is not None:
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
        if screen and self.tunnel is not None:
            tun = self.tunnel.inspect(ctx.qname, ctx.qtype, ctx.client_ip)
            if tun.suspicious:
                self.counters.note_tunnel(ctx.qname)
                ctx.reason, ctx.source = tun.reason, "tunnel"
                if self.tunnel.block:
                    self._block(ctx, reason=tun.reason, source="tunnel")
                    return

        # 7. cache (ECS scope keeps per-subnet answers separate, and so does
        # the client's upstream group — a different resolver is a different
        # answer, however identical the question)
        ecs_scope = self._ecs_scope(ctx)
        key = self.cache.key_for(ctx.query, ecs=ecs_scope, view=self._view(ctx))
        if key is not None:
            hit = self.cache.get(key, count_miss=not key.ecs)
            if key.ecs and hit is None:
                # An answer the upstream marked scope 0 is filed globally, so a
                # subnet-scoped miss still has to check there before forwarding.
                # One lookup as far as the statistics go: counting both probes
                # reported every ECS miss twice and halved the hit rate shown.
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
            if isinstance(e, _UPSTREAM_FAULTS):
                log.warning("upstream failed for %s: %s", ctx.qname, e)
            else:
                # Not the upstream's fault. Everything above raises a
                # TrenchError or an OSError to *reject* an answer; anything else
                # getting here is our own code failing on a response, and saying
                # "upstream failed" sent the operator to debug the wrong host.
                # It is also the only signal that such a bug exists at all,
                # since the client just sees SERVFAIL either way — a malformed
                # A record in an answer hid here for exactly that reason.
                log.exception("internal error handling the answer for %s", ctx.qname)
            ctx.response = ctx.query.reply(Rcode.SERVFAIL)
            ctx.action = "failed"
            return
        if answer.block is not None:
            d = answer.block
            self._block(ctx, reason=d.reason, source=d.source, rule=d.rule)
            return
        if (answer.resp is not None and answer.resp.rcode == Rcode.SERVFAIL
                and self._serve_stale(ctx, key, "stale-fallback")):
            # RFC 8767 §4: a SERVFAIL is a failed refresh, the same as a
            # timeout. The forwarder raises on one; a resolver that returns it
            # (recursive mode, a plugin) must not bypass the retained answer.
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

    def _routed(self, ctx: QueryContext) -> bool:
        router = getattr(self._forwarder_for(ctx), "router", None)
        return router is not None and router.routed(ctx.qname)

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
                # Followers get a pristine copy. The leader's `_finalize` edits
                # the object it returns (cookie, EDE, OPT presence) before the
                # followers wake, so sharing it handed them the leader's cookie.
                fut.set_result(answer if answer.resp is None
                               else answer._replace(resp=detach(answer.resp)))
            return answer
        finally:
            if not fut.done():
                # Whatever went wrong above, a follower must never wait forever.
                fut.set_exception(UpstreamError("coalesced fetch failed"))
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
        # The query's own Name, not `ctx.qname`: sanitize only ever compares
        # names by their canonical key, so rendering this one to text and
        # parsing it straight back was a Name built per forwarded query.
        qq = ctx.query.question
        cut = sanitize(resp, qq.name if qq is not None else ctx.qname)
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
        #
        # `policy.block` is part of the guard because this is still blocking.
        # The name path honours a client exempted from filtering; these two
        # answer-side checks did not, so "filtering off for this client" turned
        # off only the half of it that matches on the question.
        pol_block = getattr(ctx.policy, "block", True)
        if (self.enabled and fc.enabled and fc.cname_inspect and pol_block
                and hasattr(self.filter, "match") and resp.answers):
            pol = ctx.policy
            try:
                d = inspect_cloak(self.filter_for(ctx.policy), resp, ctx.qtype,
                            ctags=frozenset(getattr(pol, "ctags", ()) or ()),
                            client=ctx.client_ip,
                            client_names=frozenset(
                                n for n in (getattr(pol, "name", "") or "",) if n))
            except Exception:
                # Fail open, as before — but visibly: a bug here silently
                # switched CNAME-cloak blocking off for every answer it hit.
                log.exception("cname-cloak inspection failed for %s", ctx.qname)
                d = None
            if d is not None and d.blocked:
                return _Answer(None, d)   # and deliberately not cached
        # 8b-ii. Address lists: the name in the question may be new, but the
        # network the answer points into usually is not. Runs after the cloak
        # check so a cloaked name is still reported as a cloak.
        if (self.enabled and fc.enabled and pol_block
                and getattr(fc, "block_answer_ips", False)):
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
        if resp.edns is not None:
            resp.edns.options = [o for o in resp.edns.options
                                 if o[0] not in _HOP_BY_HOP]
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
        base = q.edns
        if base is not None or ecs_mode == "forward":
            # Always a fresh OPT: the client's hop-by-hop options (its cookie
            # above all) are between it and us, and forwarding them let the
            # upstream's cookie reply be cached and served to other clients.
            fwd = copy.copy(q)
            fwd.questions = list(q.questions)
            # A client's own ECS is dropped in every mode: the cache is keyed
            # by subnet only under `forward`, so passing one through let a
            # single client pick the subnet an answer cached for all was for.
            edns = Edns(udp_size=(base.udp_size if base else 1232),
                        flags=(base.flags if base else 0),
                        options=[o for o in (base.options if base else [])
                                 if o[0] not in _HOP_BY_HOP
                                 and o[0] != EDNSOption.ECS])
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

    def prefetch_replayed(self, query: Message, client_ip: str, proto: str,
                          client_id: str = "") -> None:
        """Refresh the entry behind a reply the fast path is about to replay.

        `_maybe_prefetch` hangs off the cache read in `_run`, and the fast path
        answers repeat queries in `datagram_received` without ever reaching it.
        Those are the same queries: an entry is replayable precisely because it
        is being asked for repeatedly, which is also what makes it worth
        refreshing early. So the names with the most repeats were the only ones
        prefetch could never fire for, and each paid a full upstream round trip
        once per TTL. Measured on the live deployment: 72% of queries forwarded
        at a 159 ms p50, for names re-asked every 80-140 s.

        Parsing the query here undoes what the fast path exists to avoid, so it
        happens once per entry per TTL — the caller holds a flag — and only
        inside `PREFETCH_WINDOW`.
        """
        if not self.config.cache.prefetch:
            return
        ctx = QueryContext(query=query, client_ip=client_ip, proto=proto,
                           client_id=client_id)
        if self.clients is not None:
            ctx.policy = self.clients.identify(client_ip, client_id)
        key = self.cache.key_for(query, ecs=self._ecs_scope(ctx), view=self._view(ctx))
        if key is not None:
            self._maybe_prefetch(ctx, key)

    def _maybe_prefetch(self, ctx: QueryContext, key) -> None:
        """Refresh a popular entry shortly before it expires (optimistic caching).

        Goes through `_fetch` like any other query. It used to call the forwarder
        directly and write the raw response into the cache, which made prefetch a
        second entrance that skipped 0x20 verification, unsolicited-record
        removal and the rebinding scrub — everything a client-driven query is
        checked for, on the one path nobody is waiting to notice.
        """
        rem = self.cache.remaining(key)
        if rem is None or rem > PREFETCH_WINDOW:
            return
        if key in self._prefetching or len(self._prefetching) >= PREFETCH_MAX:
            return
        self._prefetching.add(key)

        self.prefetches += 1

        async def refresh():
            try:
                # Coalesced: a client query for the same key already in
                # flight is joined, not duplicated upstream.
                await self._fetch_coalesced(ctx, key)
            except Exception:
                self.prefetch_failures += 1
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
            # Through the cache and `_fetch_coalesced`, like any other answer:
            # calling the forwarder directly skipped the 0x20 check, sanitize,
            # the rebinding scrub and the client's own upstream group, and paid
            # a full round trip for every query to a search engine.
            sctx = QueryContext(query=sub, client_ip=ctx.client_ip, proto="internal")
            sctx.policy = ctx.policy
            key = self.cache.key_for(sub, view=self._view(sctx))
            hit = self.cache.get(key) if key is not None else None
            up: Message | None = None
            try:
                up = hit[0] if hit else (await self._fetch_coalesced(sctx, key)).resp
            except Exception as e:
                # The CNAME alone is still a correct answer; the stub resolves
                # the target itself.
                log.warning("safe-search target %s did not resolve: %s", target, e)
            ctx.upstream = sctx.upstream
            if up is not None:
                resp.answers.extend(rr for rr in up.answers
                                    if rr.rtype in (Type.CNAME, q.rtype))
        ctx.response = resp

    def _finalize(self, ctx: QueryContext) -> None:
        resp = ctx.response
        if resp is None:
            resp = ctx.response = ctx.query.reply(Rcode.SERVFAIL)
        resp.id = ctx.query.id
        # Always the asker's own question, letter for letter. A cached or
        # coalesced answer carries whoever asked first, and a 0x20-checking
        # downstream resolver rejects a mismatched echo as a spoof.
        resp.questions = list(ctx.query.questions)
        # mirror EDNS presence (size/DO) so clients see a well-formed OPT
        if ctx.query.edns is not None and resp.edns is None:
            resp.edns = Edns(udp_size=self.config.server.edns_udp_size)
            resp.edns.do = ctx.query.edns.do
        elif ctx.query.edns is not None and resp.edns is not None:
            # The OPT's size field is *our* receive limit (RFC 6891 §6.2.3). A
            # reply built by `Message.reply` echoed the client's figure and one
            # relayed from upstream carried the upstream's; either way the
            # client was told something about a buffer that is not ours.
            resp.edns.udp_size = self.config.server.edns_udp_size
            resp.edns.version = 0
        elif ctx.query.edns is None and resp.edns is not None:
            # RFC 6891 §6.1.1: no OPT in a response to a query that had none. The
            # OPT here came from the upstream, possibly by way of the cache, so
            # without this a client that never spoke EDNS receives another
            # client's options — including, with cookies enabled, a server cookie
            # bound to that other client's address.
            resp.edns = None
        # DNS cookies: echo client cookie + our server cookie (RFC 7873)
        if resp.edns is not None:
            resp.edns.remove_option(COOKIE)     # only ever our own, set below
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
        # RFC 8914 §4.4 / RFC 8767 §4: say so when the answer is stale, so a
        # client (or the operator reading `dig`) can tell "this is the record"
        # from "this is the last record we saw before the upstream went away".
        if (ctx.action == "cached" and ctx.reason.startswith("stale")
                and resp.edns is not None
                and resp.edns.get_option(EDNSOption.EXTENDED_ERROR) is None):
            resp.edns.set_option(EDNSOption.EXTENDED_ERROR, struct.pack(">H", 3))
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
        ql = self.querylog
        if ql is not None and getattr(ql, "recording", True):
            # Rendering the answer section costs a string per record, on the
            # query's own latency path — and at the two higher privacy levels
            # `enqueue` throws the whole record, or just the answers, away
            # again. Ask first rather than build and discard. `getattr` because
            # a stand-in log only has to provide `enqueue`.
            answers = ([rr.rdata.to_text() for rr in resp.answers if rr.rtype != Type.OPT]
                       if getattr(ql, "records_answers", True) else [])
            ql.enqueue(record_from_ctx(qname, qtype, ctx, rcode, answers))


_HEADER_REASON = {
    Rcode.REFUSED: "a response, not a query",
    Rcode.NOTIMP: "opcode not supported",   # e.g. a router's DNS UPDATE
    Rcode.BADVERS: "EDNS version not supported",
    Rcode.FORMERR: "not exactly one question",
}


def _header_error(query: Message) -> int | None:
    """The rcode a malformed or unsupported query header earns, or None.

    - QR set: a response is not a question. The transports drop these before
      they get here; REFUSED is the fallback for any caller that does not.
    - Opcode other than QUERY: NOTIMP (RFC 1035 §4.1.1, RFC 8906 §3.1.4).
      REFUSED said "not for you", which a client reads as policy, not as "this
      server does not do that".
    - EDNS version other than 0: BADVERS with a version-0 OPT (RFC 6891
      §6.1.3), so the client knows which version to fall back to. Answering it
      as if it were version 0 guessed at semantics we do not implement.
    - QDCOUNT other than 1, bar the cookie probe: FORMERR (RFC 9619). Only the
      first question was ever answered, and the rest silently dropped.
    """
    if query.qr:
        return Rcode.REFUSED
    if query.opcode != Opcode.QUERY:
        return Rcode.NOTIMP
    if query.edns is not None and query.edns.version != 0:
        return Rcode.BADVERS
    n = len(query.questions)
    if n > 1:
        return Rcode.FORMERR
    if n == 0 and (query.edns is None or query.edns.get_option(COOKIE) is None):
        return Rcode.FORMERR
    return None


#: Numeric rcode -> mnemonic. Same reasoning as `rrtypes._TYPE_TEXT`: this runs
#: once per query in `_finalize` and once per replayed reply, and building an
#: enum member to read `.name` off it costs five times a dict lookup.
_RCODE_TEXT: dict[int, str] = {int(r): r.name for r in Rcode}


def _rcode_text(rc: int) -> str:
    name = _RCODE_TEXT.get(rc)
    return name if name is not None else str(rc)
