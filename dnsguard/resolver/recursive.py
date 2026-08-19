"""Iterative (recursive) resolver: QNAME minimization, a delegation cache, and
a hard rule that nothing a server says is believed outside its own zone.

Resolving from the root is the one part of a resolver that takes instructions
from strangers. Every referral is an unauthenticated server telling us where to
ask next, and every step is a chance for it to nominate itself as the authority
for something it does not own. Three rules keep that in check, and they are
enforced in one place each:

  * **Bailiwick** (`_scrub`, `_referral`). A response is cut down to records
    inside the zone we asked, before anything looks at it. A referral is only
    followed if the delegated zone is a *proper* subdomain of the zone we are
    in and an ancestor of the name we are chasing — down and toward, never up
    or sideways. That single predicate refuses upward referrals, sibling
    referrals, self-referrals (which are also the natural loop detector) and
    off-path glue.
  * **Progress** (`_Job`). Every resolution carries a packet budget and a wall
    clock deadline, shared with the sub-resolutions it spawns to find
    nameserver addresses. A tree cannot make one client question cost an
    unbounded amount of traffic, whether by malice or by misconfiguration.
  * **Usefulness** (`_ask`). A server that returns SERVFAIL, REFUSED, or an
    empty non-authoritative answer with no referral has told us nothing; it is
    skipped and the next nameserver is tried. Believing a lame server's empty
    response produces a NODATA for a name that exists, which is the worst kind
    of wrong answer because it looks like a fact.

The delegation cache is what makes this usable rather than merely correct. The
root is a shared public resource; walking it for every query is abusive and
slow. Delegations are cached by zone with their TTL, and each resolution starts
at the deepest cached zone cut that encloses the name — for most queries that
is the authority itself, and the root is never touched.

Transport is injected (`async transport(server_ip, query) -> Message`) so the
whole algorithm is testable against a mock authority tree, including hostile
ones, without a network.
"""
from __future__ import annotations

import asyncio
import errno
import random
import socket
import time
from dataclasses import dataclass, field

from ..log import get
from ..wire import Class, Message, Question, Type
from ..wire.name import Name
from ..wire.rrtypes import Flags, Rcode
from .roothints import ROOT_HINTS

log = get("recursive")

ROOT = Name(())

# Rcodes that mean "this server did not answer the question", as distinct from
# NXDOMAIN/NOERROR which are answers. Seeing one is a reason to ask a different
# nameserver, never a reason to fail the name.
_USELESS = frozenset({Rcode.SERVFAIL, Rcode.REFUSED, Rcode.NOTIMP, Rcode.FORMERR})

# The kernel refusing to send at all, as opposed to a server not replying. On a
# box with no IPv6 route, every AAAA glue address fails this way instantly.
_NO_ROUTE = frozenset(e for e in (
    getattr(errno, n, None) for n in
    ("ENETUNREACH", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EHOSTUNREACH")) if e is not None)


class _Reachability:
    """Whether this host can reach an address family at all.

    A resolver on a v4-only network is handed IPv6 glue constantly — the root
    zone alone is half AAAA — and every one of those addresses is an instant
    error, not a slow server. Probing once and skipping them is worth several
    wasted round trips per resolution.

    The probe sends nothing: connecting a UDP socket only sets a default peer
    and asks the kernel for a route, which is exactly the question being asked.
    """

    def __init__(self):
        self._v6: bool | None = None

    def _probe_v6(self) -> bool:
        if not socket.has_ipv6:
            return False
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        except OSError:
            return False
        try:
            s.connect(("2001:4860:4860::8888", 53))
            return True
        except OSError:
            return False
        finally:
            s.close()

    def __call__(self, ip: str) -> bool:
        if ":" not in ip:
            return True
        if self._v6 is None:
            self._v6 = self._probe_v6()
            if not self._v6:
                log.info("no IPv6 route: skipping AAAA nameserver addresses")
        return self._v6


reachable = _Reachability()


@dataclass
class _Cut:
    """A cached zone cut: who serves `zone`, and where they are."""
    zone: Name
    names: tuple[Name, ...]
    addrs: dict[Name, tuple[str, ...]]
    expires: float

    def flat(self) -> list[str]:
        out: list[str] = []
        for nm in self.names:
            out.extend(self.addrs.get(nm, ()))
        return out


class InfraCache:
    """Delegations and nameserver addresses, by zone.

    Deliberately separate from the answer cache: this holds the resolver's map
    of the namespace, it is never served to a client, and it is only ever
    written from a referral that already passed the bailiwick check.
    """

    def __init__(self, clock=time.monotonic, max_zones: int = 10_000):
        self.clock = clock
        self.max_zones = max_zones
        self._cuts: dict[Name, _Cut] = {}
        self._addrs: dict[Name, tuple[tuple[str, ...], float]] = {}

    def closest(self, name: Name) -> _Cut | None:
        """The deepest cached cut that encloses `name`, or None for the root.

        Walking down from the name rather than up from the root means a second
        query into a known zone costs zero packets above the authority.
        """
        now = self.clock()
        labels = name.labels
        for i in range(len(labels), -1, -1):
            cut = self._cuts.get(Name(labels[len(labels) - i:]) if i else ROOT)
            if cut is None:
                continue
            if cut.expires <= now:
                self._cuts.pop(cut.zone, None)
                continue
            if cut.flat():
                return cut
        return None

    def put_cut(self, zone: Name, names: tuple[Name, ...],
                addrs: dict[Name, tuple[str, ...]], ttl: int) -> _Cut:
        cut = _Cut(zone, names, addrs, self.clock() + max(1, min(ttl, 86_400)))
        if len(self._cuts) >= self.max_zones and zone not in self._cuts:
            # cheapest useful eviction: drop something expired, else something
            # arbitrary. A delegation cache does not need LRU precision.
            now = self.clock()
            for k, v in list(self._cuts.items()):
                if v.expires <= now:
                    del self._cuts[k]
            while len(self._cuts) >= self.max_zones:
                self._cuts.pop(next(iter(self._cuts)))
        self._cuts[zone] = cut
        return cut

    def addrs_for(self, nsname: Name) -> tuple[str, ...]:
        got = self._addrs.get(nsname)
        if got is None:
            return ()
        addrs, exp = got
        if exp <= self.clock():
            self._addrs.pop(nsname, None)
            return ()
        return addrs

    def put_addrs(self, nsname: Name, addrs: tuple[str, ...], ttl: int) -> None:
        if addrs:
            self._addrs[nsname] = (addrs, self.clock() + max(1, min(ttl, 86_400)))


@dataclass
class _Peer:
    """What we have learned about one nameserver address."""
    rtt: float = 0.05
    fails: int = 0

    def rank(self) -> float:
        # A failing server is deprioritised, not banned: the failure may have
        # been the network, and permanently blacklisting an address on one
        # timeout is how a resolver talks itself into having no servers left.
        return self.rtt + min(self.fails, 4) * 0.5


@dataclass
class _Job:
    """Budget shared by one client question and everything it spawns."""
    deadline: float
    queries: int
    chasing: set = field(default_factory=set)

    def spent(self, now: float) -> bool:
        return self.queries <= 0 or now >= self.deadline


class Recursive:
    def __init__(self, transport, *, root_hints: list[str] | None = None,
                 qmin: bool = True, max_steps: int = 30, max_cname: int = 12,
                 validate: bool = False, anchors=None,
                 budget: float = 5.0, max_queries: int = 40,
                 query_timeout: float = 1.5,
                 max_ns_depth: int = 4, servers_per_step: int = 4,
                 clock=time.monotonic, cache: InfraCache | None = None,
                 reachable=reachable):
        self.transport = transport
        self.root_hints = root_hints or ROOT_HINTS
        self.qmin = qmin
        self.max_steps = max_steps
        self.max_cname = max_cname
        self.validate = validate
        self.budget = budget
        self.max_queries = max_queries
        self.query_timeout = query_timeout
        self.max_ns_depth = max_ns_depth
        self.servers_per_step = servers_per_step
        self.clock = clock
        self.reachable = reachable
        self.cache = cache or InfraCache(clock=clock)
        self._peers: dict[str, _Peer] = {}
        self._validator = None
        if validate:
            from .dnssec import Validator
            self._validator = Validator(self._validator_ask, anchors=anchors)

    # ------------------------------------------------------------- entry point
    async def resolve(self, qname: str, qtype: int) -> Message:
        name = Name.from_text(qname)
        job = _Job(deadline=self.clock() + self.budget, queries=self.max_queries)
        answers: list = []
        seen = {name}
        for _ in range(self.max_cname):
            result, target = await self._resolve_name(job, name, qtype, 0)
            answers.extend(result.answers)
            if target is None:
                if result.rcode not in (Rcode.NOERROR, Rcode.NXDOMAIN):
                    # The chain broke partway. Handing back the CNAMEs collected
                    # so far alongside a SERVFAIL states two contradictory
                    # things at once — here is the answer, and there was no
                    # answer — and a client that reads the records and ignores
                    # the rcode follows a chain to nowhere. A failure is empty.
                    log.debug("cname chain for %s failed at %s", qname, name.to_text())
                    return self._servfail(qname, qtype)
                out = result
                out.answers = answers
                # The message we are holding came from the last hop of the
                # chain, so its question names the final CNAME target. A
                # response has to echo the question that was asked — anything
                # downstream that checks (and this resolver's own pipeline
                # does, which is how this was caught) will otherwise reject a
                # perfectly good answer as being about a different name.
                out.questions = [Question(Name.from_text(qname), qtype, Class.IN)]
                if self.validate:
                    await self._apply_validation(out, name, qtype)
                return out
            if target in seen:
                # A CNAME loop is not an answer. Returning the records we
                # collected on the way round would hand the client a chain that
                # never terminates, so it fails empty.
                log.debug("cname loop at %s", target.to_text())
                return self._servfail(qname, qtype)
            seen.add(target)
            name = target
        return self._servfail(qname, qtype)

    # --------------------------------------------------------------- one name
    async def _resolve_name(self, job: _Job, name: Name, qtype: int, depth: int):
        """Resolve one name without following CNAMEs across calls.

        Returns (message, cname_target_or_None).
        """
        # A DS is held by the parent, so the search for a starting point must
        # stop one label short. Without this the delegation cache hands back the
        # cut for the name itself the moment it is known, and the question goes
        # to the child — which is the same mistake `_referral` refuses to make,
        # arriving by a different route.
        start = name.parent() if qtype == Type.DS and not name.is_root() else name
        cut = self.cache.closest(start)
        if cut is not None:
            # `_addresses`, not `cut.flat()`: a cut cached from a glueless
            # referral holds nameserver *names* only, and it must still be
            # usable on the second query into that zone rather than becoming a
            # cached failure until its TTL runs out.
            zone, servers = cut.zone, await self._addresses(job, cut, depth)
        else:
            zone, servers = ROOT, list(self.root_hints)

        probe = zone            # deepest name known to exist, for minimization
        qmin = self.qmin
        widened = False         # have we already given up on minimization once?

        for _ in range(self.max_steps):
            # No budget check here: `_ask` consults it before every packet and
            # returns None once it is gone, which lands on the same failure. A
            # second check would be untestable and would drift.
            if not servers:
                return self._servfail(name.to_text(), qtype), None

            if qmin and len(name) > len(probe) + 1:
                qn, qt = self._child(name, probe), Type.NS
            else:
                qn, qt = name, qtype

            msg = await self._ask(job, servers, qn, qt, zone, name)
            if msg is None:
                return self._servfail(name.to_text(), qtype), None

            deleg = self._referral(msg, zone, name, qt)
            if deleg is not None:
                dz, nsnames, ttl = deleg
                addrs = self._glue(msg, dz, nsnames)
                cut = self.cache.put_cut(dz, nsnames, addrs, ttl)
                next_servers = await self._addresses(job, cut, depth)
                if not next_servers:
                    return self._servfail(name.to_text(), qtype), None
                servers, zone, probe = next_servers, dz, dz
                continue

            if qn != name:
                # A response to a minimized probe. NOERROR means the name
                # exists — as an empty non-terminal or as a zone apex this
                # server also holds — so keep descending with the same servers.
                if msg.rcode == Rcode.NOERROR:
                    probe = qn
                    continue
                # Anything else (typically NXDOMAIN, which RFC 8020 says covers
                # the subtree but which too many servers return for empty
                # non-terminals) is not trustworthy enough to fail on. Ask once
                # more for the whole name; if that also fails, it is the answer.
                if not widened:
                    widened, qmin = True, False
                    continue
                return msg, None

            real = [rr for rr in msg.answers if rr.name == name and rr.rtype == qtype]
            if real:
                return msg, None
            cname = next((rr for rr in msg.answers
                          if rr.name == name and rr.rtype == Type.CNAME), None)
            if cname is not None:
                return msg, cname.rdata.name
            return msg, None            # authoritative NODATA / NXDOMAIN

        return self._servfail(name.to_text(), qtype), None

    # ------------------------------------------------------------- asking
    async def _ask(self, job: _Job, servers: list[str], qn: Name, qtype: int,
                   zone: Name, name: Name) -> Message | None:
        """Ask the servers for `zone` until one of them says something usable.

        The response is scrubbed to `zone` before it is returned, so no caller
        further up ever sees a record the server had no authority for.
        """
        query = Message(id=0)
        query.questions.append(Question(qn, qtype, Class.IN))
        if self.validate:
            from ..wire.edns import Edns
            query.edns = Edns(udp_size=1232)
            query.edns.do = True

        for ip in self._order(servers):
            now = self.clock()
            if job.spent(now):
                return None
            job.queries -= 1
            peer = self._peers.setdefault(ip, _Peer())
            t0 = now
            # The deadline has to bind inside the packet as well as between
            # packets. A nameserver that never replies — dropped UDP looks
            # identical to a black hole — would otherwise block here while the
            # budget quietly expires, and the client times out holding nothing,
            # even though the next nameserver in the delegation had the answer.
            # Whatever time is left is also a ceiling: there is no point waiting
            # two seconds for a server when the whole resolution has one.
            wait = min(self.query_timeout, max(0.0, job.deadline - now))
            if wait <= 0:
                return None
            try:
                msg = await asyncio.wait_for(self.transport(ip, query), wait)
            except OSError as e:
                if e.errno in _NO_ROUTE:
                    # Nothing was sent — the host has no route to this address
                    # family at all. Charging the budget for a packet that never
                    # left would let a delegation's IPv6 glue exhaust the whole
                    # resolution on a v4-only box before a reachable nameserver
                    # is ever tried, which is exactly what happened in testing.
                    job.queries += 1
                    peer.fails = 99          # unreachable, not merely slow
                    log.debug("no route to %s (%s)", ip, e)
                    continue
                peer.fails += 1
                log.debug("%s did not answer %s: %s", ip, qn.to_text(), e)
                continue
            # Timeouts included: asyncio.TimeoutError is a plain TimeoutError,
            # and so an Exception, since 3.11. CancelledError still propagates.
            except Exception as e:
                peer.fails += 1
                log.debug("%s did not answer %s: %s", ip, qn.to_text(), e)
                continue
            peer.rtt = 0.8 * peer.rtt + 0.2 * max(0.0, self.clock() - t0)

            if msg.rcode in _USELESS:
                peer.fails += 1
                continue
            msg = self._scrub(msg, zone, qn)
            if self._referral(msg, zone, name, qtype) is not None:
                peer.fails = 0
                return msg
            if msg.aa:
                peer.fails = 0
                return msg
            # Neither authoritative nor a usable referral: a lame delegation.
            peer.fails += 1
            log.debug("lame answer for %s from %s", qn.to_text(), ip)
        return None

    def _order(self, servers: list[str]) -> list[str]:
        """Fastest-known first, ties broken at random.

        The randomness matters: a fixed order concentrates every resolver's
        traffic on whichever nameserver happens to be listed first, and makes
        an off-path attacker's job easier by removing one thing to guess.
        """
        uniq = [ip for ip in dict.fromkeys(servers) if self.reachable(ip)]
        if not uniq:
            # Every address was filtered out. Better to try them and fail than
            # to invent a SERVFAIL because a reachability guess was wrong.
            uniq = list(dict.fromkeys(servers))
        random.shuffle(uniq)
        uniq.sort(key=lambda ip: self._peers.get(ip, _Peer()).rank())
        return uniq[:self.servers_per_step]

    # ------------------------------------------------------------- bailiwick
    @staticmethod
    def _scrub(msg: Message, zone: Name, qn: Name) -> Message:
        """Drop everything the serving zone had no authority to say.

        Two rules. Any record whose owner is outside `zone` is discarded
        wholesale — that covers off-path glue and records smuggled into the
        authority section to rewrite a delegation we already hold. Within the
        answer section, records must also lie on the CNAME chain that starts at
        the question, so an authority cannot attach unrelated names from its own
        zone to an answer the client did not ask for.
        """
        def in_zone(rr) -> bool:
            return rr.name.is_subdomain_of(zone)

        chain = {qn}
        answers = [rr for rr in msg.answers if in_zone(rr)]
        for _ in range(len(answers) + 1):
            grew = False
            for rr in answers:
                if rr.rtype == Type.CNAME and rr.name in chain and rr.rdata.name not in chain:
                    chain.add(rr.rdata.name)
                    grew = True
            if not grew:
                break
        msg.answers = [rr for rr in answers if rr.name in chain]
        msg.authority = [rr for rr in msg.authority if in_zone(rr)]
        msg.additional = [rr for rr in msg.additional if in_zone(rr)]
        return msg

    @staticmethod
    def _referral(msg: Message, zone: Name, name: Name, qtype: int = 0):
        """The delegation this response offers, if it is one we may follow.

        Down and toward: the delegated zone must be strictly below the zone we
        asked, and must still enclose the name we are chasing. Everything a
        hostile or broken server can do with a referral fails this test —
        pointing us up at a TLD, sideways at somebody else's domain, or back at
        itself (which is also how a delegation loop stops).
        """
        if msg.answers:
            return None
        ns = [rr for rr in msg.authority if rr.rtype == Type.NS]
        if not ns:
            return None
        dz = ns[0].name
        if len(dz) <= len(zone) or not dz.is_subdomain_of(zone):
            return None
        if not name.is_subdomain_of(dz):
            return None
        if qtype == Type.DS and dz == name:
            # A DS record belongs to the parent zone, not the child. Following
            # this delegation would ask the child whether it has a DS, and the
            # child is the one party with a motive to say no — that answer is
            # how a signed zone would opt itself out of DNSSEC.
            return None
        owned = [rr for rr in ns if rr.name == dz]
        ttl = min((rr.ttl for rr in owned), default=300)
        return dz, tuple(dict.fromkeys(rr.rdata.name for rr in owned)), ttl

    @staticmethod
    def _glue(msg: Message, dz: Name, nsnames: tuple[Name, ...]) -> dict[str, tuple[str, ...]]:
        """Addresses from the additional section, keyed by nameserver name.

        `_scrub` has already removed anything outside the *parent* zone. The
        filter here is a size guard, not the security control: an address is
        only ever reachable through `_Cut.flat()`, which looks names up from the
        delegation, so a record for some name we were not delegated to can never
        be queried whether it is stored or not.

        Glue for a nameserver outside the delegated zone is deliberately not
        rejected — `ns.example.net` serving `example.com` is legal and common,
        and the record still arrived inside the parent's bailiwick, which is the
        strongest claim a parent is entitled to make about its own delegation.
        """
        want = set(nsnames)
        out: dict[Name, list[str]] = {}
        for rr in msg.additional:
            if rr.rtype in (Type.A, Type.AAAA) and rr.name in want:
                out.setdefault(rr.name, []).append(rr.rdata.address)
        return {k: tuple(v) for k, v in out.items()}

    # -------------------------------------------------- nameserver addresses
    async def _addresses(self, job: _Job, cut: _Cut, depth: int) -> list[str]:
        """Where to send the next query for `cut.zone`.

        Glue first, then the address cache, then — only if the delegation gave
        us nothing usable — a bounded side resolution for a nameserver's own
        address. That last case is the query amplifier in every recursive
        resolver, so it is depth-limited, breadth-limited, and spends the
        caller's packet budget rather than a fresh one.
        """
        addrs = cut.flat()
        if addrs:
            return addrs
        for nm in cut.names:
            addrs.extend(self.cache.addrs_for(nm))
        if addrs:
            return addrs
        if cut.zone.is_root():
            return list(self.root_hints)
        if depth >= self.max_ns_depth:
            return []
        for nm in cut.names[:2]:
            if nm in job.chasing or job.spent(self.clock()):
                continue
            job.chasing.add(nm)
            try:
                msg, _ = await self._resolve_name(job, nm, Type.A, depth + 1)
                got = tuple(rr.rdata.address for rr in msg.answers
                            if rr.rtype == Type.A and rr.name == nm)
                if got:
                    ttl = min((rr.ttl for rr in msg.answers if rr.rtype == Type.A), default=300)
                    self.cache.put_addrs(nm, got, ttl)
                    return list(got)
            except Exception as e:
                log.debug("could not resolve nameserver %s: %s", nm.to_text(), e)
            finally:
                job.chasing.discard(nm)
        return []

    # ------------------------------------------------------------------ misc
    def _child(self, name: Name, zone: Name) -> Name:
        """The name one label below `zone` toward `name`."""
        extra = len(name) - len(zone) - 1
        return Name(name.labels[extra:])

    def _servfail(self, qname: str, qtype: int) -> Message:
        m = Message(id=0, flags=Flags.QR | Flags.RA)
        m.set_rcode(Rcode.SERVFAIL)
        m.questions.append(Question(Name.from_text(qname), qtype, Class.IN))
        return m

    # --------------------------------------------------------------- DNSSEC
    async def _validator_ask(self, name: Name, rtype: int) -> Message:
        job = _Job(deadline=self.clock() + self.budget, queries=self.max_queries)
        msg, _ = await self._resolve_name(job, name, rtype, 0)
        return msg

    async def _apply_validation(self, out: Message, name: Name, qtype: int) -> None:
        from .dnssec import ValidationResult
        out.set_flag(Flags.AD, False)  # only WE may assert AD; never trust upstream's
        rdatas = [rr.rdata for rr in out.answers if rr.rtype == qtype and rr.name == name]
        rrsigs = [rr.rdata for rr in out.answers
                  if rr.rtype == Type.RRSIG and rr.rdata.type_covered == qtype]
        try:
            if rdatas:
                # The authority section goes along: a wildcard-expanded answer
                # is only half a statement without the denial of the exact name.
                result = await self._validator.validate(name, qtype, rdatas, rrsigs,
                                                        out.authority)
            else:
                # NXDOMAIN / NODATA: authenticate the denial via NSEC/NSEC3. The
                # rcode is passed because the two denials prove different things
                # and a validator that accepts either for either lets one be
                # swapped for the other.
                result = await self._validator.validate_denial(name, qtype, out.authority,
                                                               out.rcode)
        except Exception as e:
            # An unexpected failure here is our bug, not the zone's. Treating it
            # as INSECURE keeps the answer flowing rather than turning a
            # validator defect into an outage, but it must be visible.
            log.warning("validator error for %s: %r", name.to_text(), e)
            result = ValidationResult.INSECURE
        if result == ValidationResult.SECURE:
            out.set_flag(Flags.AD, True)
        elif result == ValidationResult.BOGUS and not out.cd:
            out.answers = []
            out.authority = []
            out.set_rcode(Rcode.SERVFAIL)
            # RFC 8914. A bare SERVFAIL is indistinguishable from the resolver
            # being broken, which is how "DNSSEC is more trouble than it is
            # worth" gets decided. Say which of the two it was.
            self._ede(out, 10 if not rrsigs else 6,
                      "RRSIGs missing" if not rrsigs else "DNSSEC bogus")

    @staticmethod
    def _ede(msg: Message, code: int, text: str) -> None:
        import struct

        from ..wire.edns import Edns
        from ..wire.rrtypes import EDNSOption
        if msg.edns is None:
            msg.edns = Edns(udp_size=1232)
        msg.edns.set_option(EDNSOption.EXTENDED_ERROR,
                            struct.pack(">H", code) + text.encode("ascii"))


class RecursiveForwarder:
    """Adapter exposing the forwarder's `resolve(query) -> Message` API but
    resolving iteratively from the root over plain UDP/TCP.

    Upstream objects are pooled per address rather than built per query: a fresh
    one each time throws away the truncation-fallback path's connection and the
    per-address round-trip estimate that server ordering depends on.
    """

    def __init__(self, *, timeout: float = 4.0, qmin: bool = True,
                 validate: bool = False, budget: float = 5.0,
                 max_queries: int = 40, query_timeout: float = 1.5):
        self.timeout = timeout
        self.rec = Recursive(self._udp, qmin=qmin, validate=validate,
                             budget=budget, max_queries=max_queries,
                             query_timeout=query_timeout)
        self._pool: dict[str, object] = {}

    def _upstream(self, ip: str):
        up = self._pool.get(ip)
        if up is None:
            from ..transport.upstream import Upstream, UpstreamSpec
            # Deliberately no source-port pool here. A pool is per destination
            # because its sockets are connected, and recursion talks to hundreds
            # of authoritative addresses — a pool each would be thousands of
            # descriptors, and a pool small enough to afford would leave only a
            # few bits of port entropy on exactly the path where off-path
            # spoofing matters most. One shared pool of *unconnected* sockets is
            # the right answer, and it needs the source-address check that a
            # connected socket gives for free; until that is written and tested,
            # this path keeps a socket per query and its full entropy.
            up = Upstream(UpstreamSpec("udp", ip, 53), timeout=self.timeout)
            if len(self._pool) > 512:
                self._pool.clear()
            self._pool[ip] = up
        return up

    async def _udp(self, ip: str, query: Message) -> Message:
        return await self._upstream(ip).query(query)

    async def resolve(self, query: Message, note=None) -> Message:
        """`note` is accepted for interface parity with `Forwarder` and ignored:
        a full recursion talks to a chain of servers, so there is no single
        upstream to attribute the answer to."""
        q = query.question
        if q is None:
            return self.rec._servfail(".", 0)
        resp = await self.rec.resolve(q.name.to_text(), q.rtype)
        resp.id = query.id
        # Echo the client's own question objects rather than ones rebuilt from
        # text: they carry the original label casing, which is what 0x20
        # verification further up compares against.
        resp.questions = list(query.questions)
        return resp

    async def close(self) -> None:
        for up in list(self._pool.values()):
            close = getattr(up, "close", None)
            if close is not None:
                try:
                    await close()
                except Exception:
                    pass
        self._pool.clear()
