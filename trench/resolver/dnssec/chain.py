"""DNSSEC chain-of-trust validator.

The question this module answers is *not* "can I find a key somewhere that
verifies this signature". That question has a catastrophic answer: anyone who
owns a signed domain can sign an RRset for someone else's name, and a validator
that merely fetches `RRSIG.signer`'s keys and checks the maths will call it
SECURE. The question is "what does the chain from the root trust anchor say
about this name", and the two are only the same if the chain is walked
**downward**:

    root anchor ──DS──▶ tld DNSKEY ──DS──▶ zone DNSKEY ──RRSIG──▶ the answer

Each step is taken with a key the step above it already trusts, and the zone
that arrives at the bottom is the *only* zone permitted to sign the answer.
Three consequences fall out of that, and each is a real attack when missed:

  * **A missing signature is not a missing opinion.** If the descent reaches
    the name securely, the data must be signed; unsigned is BOGUS, not
    INSECURE. Otherwise stripping the RRSIGs is a complete bypass.
  * **Unsigned zones really do exist**, so INSECURE has to be *proven*: the
    parent must authenticate the absence of a DS (see `nsec`). An unproven
    absence is BOGUS.
  * **Verification is work an attacker gets to ask for.** Every signature check
    spends from a shared budget, so a zone answering with a pile of colliding
    key tags and junk signatures (CVE-2023-50387, "KeyTrap") costs a bounded
    amount of CPU instead of an unbounded one.

`ask(name, rtype) -> Message` is injected — it sets DO and returns RRSIGs — so
the whole validator is testable against a mock signed hierarchy with no network.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict

from ...wire import Type
from ...wire import rdata as R
from ...wire.name import Name
from ...wire.rrtypes import Rcode
from .keys import SUPPORTED_ALGOS, SUPPORTED_DIGESTS, ds_digest, key_tag
from .nsec import (
    MAX_NSEC3_ITERATIONS,
    Nsec3Set,
    nsec3_ds_denial,
    nsec3_nodata,
    nsec3_nxdomain,
    nsec3_wildcard_expansion,
    nsec_ds_denial,
    nsec_nodata,
    nsec_nxdomain,
    nsec_wildcard_expansion,
    nsec_wildcard_nodata,
)
from .validate import ValidationResult, verify_rrset

log = logging.getLogger("trench.dnssec")

# IANA root trust anchors (RFC 7958). Both the active KSK-2017 (tag 20326) and
# the KSK-2024 (tag 38696) are pinned so validation holds across the rollover.
ROOT_ANCHORS = [
    R.DS(key_tag=20326, algorithm=8, digest_type=2,
         digest=bytes.fromhex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")),
    R.DS(key_tag=38696, algorithm=8, digest_type=2,
         digest=bytes.fromhex("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")),
]

MAX_DEPTH = 128                 # a name cannot carry more labels than this
#: Longest any conclusion about a key or a delegation is trusted without being
#: re-established, whatever TTL the zone asked for (the usual resolver cap).
MAX_TRUST_TTL = 86400
ZONE_FLAG = 0x0100              # DNSKEY flags bit 7 (RFC 4034 §2.1.1)
ROOT = Name(())


class DNSSECError(Exception):
    pass


class _Work:
    """Shared ceilings for one validation.

    Both numbers exist because the peer chooses the shape of the work: how many
    signatures a response carries and how many keys a zone publishes are theirs
    to pick, and the product of the two is what we would otherwise pay.
    """

    def __init__(self, crypto: int, queries: int):
        self.crypto = crypto
        self.queries = queries

    def sign_op(self) -> None:
        self.crypto -= 1
        if self.crypto < 0:
            raise DNSSECError("signature-verification budget exhausted")

    def query(self) -> None:
        self.queries -= 1
        if self.queries < 0:
            raise DNSSECError("chain-query budget exhausted")


def _wildcard_owner(owner: Name, sig: R.RRSIG) -> tuple[Name, bool] | None:
    """The name the signature actually covers.

    RRSIG carries a label count precisely so a wildcard-expanded record can be
    told apart from a real one: fewer labels than the owner means the zone
    signed `*.<closest encloser>` and the server expanded it. Verifying against
    the expanded owner simply fails, which is also why wildcard answers do not
    validate at all until this is handled.
    """
    n = len(owner.labels)
    # The count excludes a leading wildcard, so a record whose owner *is* the
    # wildcard already looks one label short. Missing this marks every NSEC a
    # zone publishes at `*.something` as an expansion and throws it away.
    counted = n - 1 if n and owner.labels[0] == b"*" else n
    if sig.labels > counted:
        return None                       # claims more labels than exist: nonsense
    if sig.labels == counted:
        return owner, False
    return Name((b"*",) + owner.labels[n - sig.labels:]), True


class Validator:
    def __init__(self, ask, anchors: list[R.DS] | None = None, *,
                 max_crypto_ops: int = 48, max_chain_queries: int = 32,
                 max_nsec3_iterations: int = MAX_NSEC3_ITERATIONS,
                 now: float | None = None):
        self.ask = ask                                   # async (Name, rtype) -> Message
        self.anchors = anchors or ROOT_ANCHORS
        self.max_crypto_ops = max_crypto_ops
        self.max_chain_queries = max_chain_queries
        self.max_nsec3_iterations = max_nsec3_iterations
        self.now = now
        # keyed on (zone, DS-set fingerprint) — see _keys_for. Both caches hold
        # (expiry, value), expiry on the monotonic clock: see `_expiry`.
        self._keys: dict[tuple, tuple[float, list[R.DNSKEY]]] = {}
        self._state: dict[str, tuple[float, tuple[str, Name, list[R.DNSKEY] | None]]] = {}

    # ------------------------------------------------------------ cache ttl
    def _expiry(self, rrs, sigs=()) -> float:
        """When trust derived from these records must be re-established.

        The smallest record TTL, cut short by the earliest RRSIG expiration and
        capped at `MAX_TRUST_TTL`. These caches used to keep an entry until the
        process restarted, so a rolled or revoked key, or a zone that went
        insecure or became signed, was never noticed.
        """
        ttl = float(MAX_TRUST_TTL)
        for rr in rrs:
            ttl = min(ttl, rr.ttl)
        wall = int(self.now if self.now is not None else time.time())
        for sig in sigs:
            ttl = min(ttl, (sig.expiration - wall) % (1 << 32))   # serial arithmetic
        return time.monotonic() + max(0.0, ttl)

    @staticmethod
    def _cached(cache: dict, key):
        hit = cache.get(key)
        if hit is None:
            return None
        if hit[0] <= time.monotonic():
            del cache[key]
            return None
        return hit

    @staticmethod
    def _store(cache: dict, key, expires: float, value, limit: int) -> None:
        if expires <= time.monotonic():
            return
        if len(cache) >= limit:
            now = time.monotonic()
            for k in [k for k, (exp, _) in cache.items() if exp <= now]:
                del cache[k]
            if len(cache) >= limit:
                return
        cache[key] = (expires, value)

    # ------------------------------------------------------------ public API
    async def validate(self, owner: Name, rtype: int, rdatas: list,
                       rrsigs: list[R.RRSIG], authority=()) -> ValidationResult:
        """Validate an RRset (with its RRSIGs) against the trust anchor.

        `authority` is consulted only for wildcard-expanded answers, which are
        incomplete without a denial of the exact name.
        """
        work = _Work(self.max_crypto_ops, self.max_chain_queries)
        try:
            state, zone, keys = await self._trust_for(owner, rtype, rrsigs, work)
            if state != "secure":
                return ValidationResult.INSECURE
            ok, expanded = self._verify(owner, rtype, rdatas, rrsigs, keys, zone, work)
            if not ok:
                return ValidationResult.BOGUS
            if expanded is not None:
                nsecs, n3 = self._denial_records(authority, zone, keys, work)
                if not self._proves_expansion(owner, expanded, nsecs, n3):
                    log.debug("wildcard answer for %s lacks a denial of the exact name",
                              owner.to_text())
                    return ValidationResult.BOGUS
            return ValidationResult.SECURE
        except DNSSECError as e:
            log.debug("bogus %s/%s: %s", owner.to_text(), rtype, e)
            return ValidationResult.BOGUS

    async def validate_denial(self, qname: Name, qtype: int, authority,
                              rcode: int = Rcode.NOERROR) -> ValidationResult:
        """Authenticate an NXDOMAIN or NODATA from the NSEC/NSEC3 records in the
        authority section.

        The rcode is part of the check, not context. A NODATA proof and an
        NXDOMAIN proof are different statements, and a zone's genuine, signed
        records for one must not be accepted as the other — that swap alone
        turns "this host has no AAAA" into "this host does not exist".
        """
        work = _Work(self.max_crypto_ops, self.max_chain_queries)
        try:
            sigs = [rr.rdata for rr in authority if rr.rtype == Type.RRSIG]
            state, zone, keys = await self._trust_via_signer(qname, sigs, work)
            if state != "secure":
                return ValidationResult.INSECURE
            nsecs, n3 = self._denial_records(authority, zone, keys, work)
            if not nsecs and n3 is None:
                return ValidationResult.BOGUS
            return (ValidationResult.SECURE
                    if self._proves_denial(qname, qtype, rcode, nsecs, n3)
                    else ValidationResult.BOGUS)
        except DNSSECError as e:
            log.debug("bogus denial for %s: %s", qname.to_text(), e)
            return ValidationResult.BOGUS

    # ------------------------------------------------------- what proves what
    def _proves_denial(self, qname: Name, qtype: int, rcode: int, nsecs, n3) -> bool:
        if qtype == Type.DS and rcode != Rcode.NXDOMAIN:
            # A DS denial has an extra way to be wrong: it can come from the
            # child, which is the one party that benefits from it.
            if nsecs and nsec_ds_denial(qname, nsecs) is not None:
                return True
            return bool(n3 and nsec3_ds_denial(qname, n3) is not None)
        if rcode == Rcode.NXDOMAIN:
            if nsecs and nsec_nxdomain(qname, nsecs):
                return True
            return bool(n3 and nsec3_nxdomain(qname, n3))
        if nsecs and (nsec_nodata(qname, qtype, nsecs)
                      or nsec_wildcard_nodata(qname, qtype, nsecs)):
            return True
        return bool(n3 and nsec3_nodata(qname, qtype, n3))

    def _proves_expansion(self, qname: Name, expanded_from: Name, nsecs, n3) -> bool:
        if nsecs and nsec_wildcard_expansion(qname, expanded_from, nsecs):
            return True
        return bool(n3 and nsec3_wildcard_expansion(qname, expanded_from, n3))

    # --------------------------------------------------------- trust descent
    async def _trust_for(self, owner: Name, rtype: int, rrsigs, work):
        if rtype == Type.DS:
            # A DS lives in the parent zone; descending into the child to
            # validate it would be asking the child about its own delegation.
            return await self._trust_at(owner.parent(), work)
        return await self._trust_via_signer(owner, rrsigs, work)

    async def _trust_via_signer(self, owner: Name, rrsigs, work):
        """Descend only as far as the alleged signer, when there is one.

        Believing the signer's *name* costs nothing — the descent still has to
        reach it from the anchor, and whatever zone it lands on is the only one
        allowed to have signed. With no signer to aim at, the descent must go
        all the way to the name itself to discover whether some ancestor is a
        proven-insecure delegation.
        """
        # The *deepest* candidate signer, not the first one listed. Taking the
        # first let anyone prepend one junk RRSIG naming a shallow ancestor
        # (`signer=com`) to an authority section legitimately signed by
        # `example.com`: the descent stopped at com, every genuine record was
        # discarded as signed by the wrong zone, and a valid signed denial came
        # back BOGUS — a one-packet denial of service against any name.
        target = owner
        best = None
        for sig in rrsigs:
            signer = getattr(sig, "signer", None)
            if signer is None or not owner.is_subdomain_of(signer):
                continue
            if best is None or len(signer.labels) > len(best.labels):
                best = signer
        if best is not None:
            target = best
        return await self._trust_at(target, work)

    async def _trust_at(self, name: Name, work):
        """Return (state, zone, keys) for the deepest zone at or above `name`.

        state is 'secure' (keys are that zone's trusted DNSKEYs) or 'insecure'
        (a delegation at or above `name` was proven to carry no DS).
        """
        return (await self._trust(name, work))[1]

    async def _trust(self, name: Name, work):
        """`_trust_at`, plus when the answer stops being valid: a conclusion
        is only as fresh as the least fresh link in the chain behind it."""
        key = name.to_text()
        hit = self._cached(self._state, key)
        if hit is not None:
            return hit
        if len(name.labels) > MAX_DEPTH:
            raise DNSSECError("name too deep")

        if name.is_root():
            keys, exp = await self._keys_exp(ROOT, self.anchors, work)
            out = ("secure", ROOT, keys)
        else:
            exp, (state, zone, keys) = await self._trust(name.parent(), work)
            if state != "secure":
                out = (state, zone, keys)
            else:
                kind, child_keys, own = await self._delegation(name, zone, keys, work)
                exp = min(exp, own)
                if kind == "secure":
                    out = ("secure", name, child_keys)
                elif kind == "insecure":
                    out = ("insecure", name, None)
                else:                                   # no zone cut here
                    out = ("secure", zone, keys)
        self._store(self._state, key, exp, out, 8192)
        return exp, out

    async def _root_keys(self, work) -> list[R.DNSKEY]:
        return await self._keys_for(ROOT, self.anchors, work)

    async def _delegation(self, child: Name, parent_zone: Name,
                          parent_keys: list[R.DNSKEY], work):
        """Is `child` a zone cut, and if so is it signed?

        Returns ('secure', keys, expiry), ('insecure', None, expiry) or
        ('nocut', None, expiry).
        """
        work.query()
        msg = await self.ask(child, Type.DS)
        ds = [rr.rdata for rr in msg.answers
              if rr.rtype == Type.DS and rr.name == child
              and isinstance(rr.rdata, R.DS)]
        if ds:
            sigs = [rr.rdata for rr in msg.answers
                    if rr.rtype == Type.RRSIG and rr.name == child
                    and rr.rdata.type_covered == Type.DS]
            ok, expanded = self._verify(child, Type.DS, ds, sigs,
                                        parent_keys, parent_zone, work)
            if not ok or expanded is not None:
                # A wildcard-synthesized DS would assert a zone cut the parent
                # never published. There is no such thing.
                raise DNSSECError(
                    f"DS for {child.to_text()} not signed by {parent_zone.to_text()}")
            # RFC 4035 §5.2: only DS records we can act on count. A child
            # signed solely with an algorithm or digest we do not implement is
            # treated as unsigned; calling it bogus SERVFAILed the whole zone.
            # Either verdict rests on this DS set, so it lasts no longer.
            ds_rrs = [rr for rr in msg.answers if rr.rtype == Type.DS and rr.name == child]
            ds_exp = self._expiry(ds_rrs, sigs)
            usable = [d for d in ds if d.algorithm in SUPPORTED_ALGOS
                      and d.digest_type in SUPPORTED_DIGESTS]
            if not usable:
                return "insecure", None, ds_exp
            keys, kexp = await self._keys_exp(child, usable, work)
            return "secure", keys, min(kexp, ds_exp)

        nsecs, n3 = self._denial_records(msg.authority, parent_zone, parent_keys, work)
        verdict = None
        if nsecs:
            verdict = nsec_ds_denial(child, nsecs)
        if verdict is None and n3 is not None:
            verdict = nsec3_ds_denial(child, n3)
        if verdict is None:
            raise DNSSECError(f"absence of DS for {child.to_text()} is unproven")
        proof = [rr for rr in msg.authority if rr.rtype in (Type.NSEC, Type.NSEC3, Type.RRSIG)]
        return verdict, None, self._expiry(
            proof, [rr.rdata for rr in proof if isinstance(rr.rdata, R.RRSIG)])

    async def _keys_for(self, zone: Name, ds_set: list[R.DS], work) -> list[R.DNSKEY]:
        """Fetch `zone`'s DNSKEY RRset and anchor it against a trusted DS."""
        return (await self._keys_exp(zone, ds_set, work))[0]

    async def _keys_exp(self, zone: Name, ds_set: list[R.DS], work):
        """`_keys_for`, plus when the keys must be fetched and checked again."""
        # Keyed on the DS set as well as the zone. Returning a cached key list
        # before looking at `ds_set` meant a later descent arriving with a
        # rolled or revoked DS reused the keys the old DS anchored — the cache
        # answered a question it had not been asked.
        ck = (zone.to_text(), tuple(sorted(
            (d.key_tag, d.algorithm, d.digest_type, bytes(d.digest)) for d in ds_set)))
        cached = self._cached(self._keys, ck)
        if cached is not None:
            return cached[1], cached[0]
        work.query()
        msg = await self.ask(zone, Type.DNSKEY)
        # `isinstance`, not `rtype` alone: a DNSKEY record whose rdata did not
        # decode keeps rtype 48 and arrives as `Unknown` (see `parse_rdata`),
        # and the ZONE-flag filter below reads `.flags` off it *before* any
        # signature is checked. One such record in the RRset raised
        # AttributeError out of `validate`, where the caller turns an
        # unexpected error into INSECURE — so a spoofed DNSKEY response that
        # would have been rejected as bogus was served unvalidated instead.
        dnskeys = [rr.rdata for rr in msg.answers
                   if rr.rtype == Type.DNSKEY and rr.name == zone
                   and isinstance(rr.rdata, R.DNSKEY)]
        sigs = [rr.rdata for rr in msg.answers
                if rr.rtype == Type.RRSIG and rr.name == zone
                and rr.rdata.type_covered == Type.DNSKEY]
        if not dnskeys or not sigs:
            raise DNSSECError(f"no signed DNSKEY for {zone.to_text()}")

        # RFC 4509 §3: once the parent publishes a SHA-256 DS, the SHA-1 one is
        # there for old validators only and must not be what we rely on.
        strong = [d for d in ds_set if d.digest_type in (2, 4)]
        if strong:
            ds_set = strong

        # A key without the ZONE flag is not a zone key and must never verify
        # zone data, however well the arithmetic works out.
        usable = [k for k in dnskeys if k.flags & ZONE_FLAG]
        for k in usable:
            kt = key_tag(k)
            if not any(self._ds_matches(zone, k, kt, d) for d in ds_set):
                continue
            for sig in sigs:
                if sig.key_tag != kt or sig.algorithm != k.algorithm or sig.signer != zone:
                    continue
                work.sign_op()
                if verify_rrset(zone, Type.DNSKEY, 1, dnskeys, sig, k, now=self.now):
                    exp = self._expiry(
                        [rr for rr in msg.answers
                         if rr.rtype == Type.DNSKEY and rr.name == zone], [sig])
                    self._store(self._keys, ck, exp, usable, 4096)
                    return usable, exp
        raise DNSSECError(f"DNSKEY for {zone.to_text()} not anchored to its DS")

    @staticmethod
    def _ds_matches(zone: Name, k: R.DNSKEY, kt: int, ds: R.DS) -> bool:
        if ds.key_tag != kt or ds.algorithm != k.algorithm:
            return False
        try:
            return ds_digest(zone, k, ds.digest_type) == ds.digest
        except ValueError:
            return False                       # a digest type we cannot compute

    # ------------------------------------------------------------ signatures
    def _verify(self, owner: Name, rtype: int, rdatas: list, sigs, keys,
                zone: Name, work) -> tuple[bool, Name | None]:
        """Verify an RRset with `zone`'s keys. Returns (ok, wildcard_owner).

        The signer check is the whole point: `zone` is where the descent from
        the anchor landed, so a signature naming any other zone is not evidence
        about this name, no matter how valid that other zone's own chain is.
        """
        if not rdatas:
            return False, None
        # Tags are computed once per key and indexed, not recomputed per
        # (sig, key) pair. `work.sign_op()` bounds signature verifications, so
        # anything expensive *before* it is outside the budget: a zone
        # publishing 200 DNSKEYs against 1000 RRSIGs bought 200 000 key_tag()
        # calls — seconds of CPU per query, with zero signatures verified.
        by_tag: dict[int, list] = {}
        for k in keys:
            by_tag.setdefault(key_tag(k), []).append(k)
        for sig in sigs:
            if sig.signer != zone:
                continue
            found = _wildcard_owner(owner, sig)
            if found is None:
                continue
            signed_owner, expanded = found
            for k in by_tag.get(sig.key_tag, ()):
                if sig.algorithm != k.algorithm:
                    continue
                work.sign_op()
                if verify_rrset(signed_owner, rtype, 1, rdatas, sig, k, now=self.now):
                    return True, (signed_owner if expanded else None)
        return False, None

    def _denial_records(self, authority, zone: Name, keys, work):
        """Verify the NSEC/NSEC3 RRsets in an authority section.

        Records whose signature does not check out are dropped rather than
        failing the whole response: a message may legitimately carry records
        from more than one place, and only what `zone` actually signed is
        allowed to prove anything.
        """
        sigs = [(rr.name, rr.rdata) for rr in authority if rr.rtype == Type.RRSIG]
        nsecs: list[tuple[Name, R.NSEC]] = []
        nsec3s: list[tuple[Name, R.NSEC3]] = []
        # `isinstance`, not the rtype alone: a record claiming NSEC3 whose rdata
        # did not decode arrives as `Unknown` (see `parse_rdata`), and every
        # reader below takes `.salt`, `.next_hashed` and the rest off it. It is
        # dropped rather than carried: the surviving records are still what the
        # signature is checked against, so one that the zone really did sign
        # cannot be quietly excluded — its removal fails the RRset instead.
        for rtype, cls, into in ((Type.NSEC, R.NSEC, nsecs),
                                 (Type.NSEC3, R.NSEC3, nsec3s)):
            by_owner: dict[Name, list] = defaultdict(list)
            for rr in authority:
                if rr.rtype == rtype and isinstance(rr.rdata, cls):
                    by_owner[rr.name].append(rr.rdata)
            for owner, rdatas in by_owner.items():
                mine = [s for o, s in sigs if o == owner and s.type_covered == rtype]
                ok, expanded = self._verify(owner, rtype, rdatas, mine, keys, zone, work)
                if ok and expanded is None:
                    into.extend((owner, rd) for rd in rdatas)
        n3 = None
        if nsec3s:
            candidate = Nsec3Set(nsec3s, zone,
                                 max_iterations=self.max_nsec3_iterations)
            n3 = candidate if candidate.usable else None
        return nsecs, n3
