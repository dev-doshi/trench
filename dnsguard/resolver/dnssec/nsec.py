"""NSEC / NSEC3 denial-of-existence (RFC 4034 §6, RFC 4035 §5.4, RFC 5155 §8).

A signed zone proves a name — or a type at a name — does not exist by returning
records that *bracket* the queried name in the zone's canonical ordering. This
module decides what a set of such records proves. It does no cryptography: the
caller must have verified the RRSIGs over these records first, and everything
here assumes that has already happened.

Two rules drive the code below and both are easy to get wrong:

  * **A denial is only as strong as what it rules out.** Proving `x.example`
    is absent does not prove the answer is NXDOMAIN — a wildcard could still
    have synthesized one. Every NXDOMAIN proof therefore needs a *second*
    record showing the relevant wildcard is absent too.

  * **A proof must come from the right side of a zone cut.** The case that
    matters is DS: a child zone able to deny its own DS could opt itself out of
    DNSSEC at will. The SOA bit in the type bitmap is what tells the parent's
    delegation record apart from the child's apex record.
"""
from __future__ import annotations

import base64
import hashlib

from ...wire import Type
from ...wire.name import Name

# RFC 9276 §3.2: treat a zone demanding an excessive iteration count as
# insecure rather than pay the hashing an attacker asked for.
MAX_NSEC3_ITERATIONS = 100


# --- canonical name ordering (RFC 4034 §6.1) ---
def canon_key(name: Name) -> list[bytes]:
    """Sort key: labels in canonical (lowercase) order, least-significant first."""
    return [la.lower() for la in reversed(name.labels)]


def name_lt(a: Name, b: Name) -> bool:
    ka, kb = canon_key(a), canon_key(b)
    for x, y in zip(ka, kb, strict=False):
        if x != y:
            return x < y
    return len(ka) < len(kb)


def nsec_covers(owner: Name, next_name: Name, qname: Name) -> bool:
    """True if qname falls in the gap (owner, next_name) — proving qname is absent.
    Handles the wrap-around at the zone apex (next_name <= owner)."""
    if name_lt(owner, next_name):
        return name_lt(owner, qname) and name_lt(qname, next_name)
    # wrap: last NSEC points back to the apex
    return name_lt(owner, qname) or name_lt(qname, next_name)


# --- type bitmap (RFC 4034 §4.1.2) ---
def bitmap_has(bitmap: bytes, rtype: int) -> bool:
    i = 0
    win = rtype >> 8
    bit = rtype & 0xFF
    while i + 2 <= len(bitmap):
        w = bitmap[i]
        length = bitmap[i + 1]
        block = bitmap[i + 2:i + 2 + length]
        if w == win:
            byte = bit // 8
            return byte < len(block) and bool(block[byte] & (0x80 >> (bit % 8)))
        i += 2 + length
    return False


# --- names ---
def common_suffix(a: Name, b: Name) -> Name:
    """Longest common suffix — the closest ancestor two names share."""
    out: list[bytes] = []
    for x, y in zip(reversed(a.labels), reversed(b.labels), strict=False):
        if x.lower() != y.lower():
            break
        out.append(x)
    return Name(tuple(reversed(out)))


def wildcard_of(name: Name) -> Name:
    return Name((b"*",) + name.labels)


def _ancestors(qname: Name, zone: Name) -> list[Name]:
    """Every name from qname's parent up to `zone` inclusive, closest first."""
    out: list[Name] = []
    n = qname.parent()
    while len(n) >= len(zone):
        out.append(n)
        if n == zone or n.is_root():
            break
        n = n.parent()
    return out


def _covered(name: Name, nsecs: list[tuple[Name, object]]) -> bool:
    return any(nsec_covers(o, rd.next_name, name) for o, rd in nsecs)


def _is_delegation(rd) -> bool:
    """True for a *parent-side* delegation record: NS set, SOA clear.

    Such a record describes the cut, not the child's contents, so it proves
    nothing about types inside the child — the same asymmetry `nsec_ds_denial`
    relies on, read from the other direction. Without this test the parent's
    own public NSEC/NSEC3 denies any type at the child's apex.
    """
    return (bitmap_has(rd.type_bitmap, Type.NS)
            and not bitmap_has(rd.type_bitmap, Type.SOA))


def _gap_unproven(rd) -> bool:
    """True when a covering NSEC3 fails to prove its gap is empty — either no
    record covers the name, or the one that does has Opt-Out (RFC 5155 §6) set
    and therefore leaves room for an unsigned delegation."""
    return rd is None or bool(rd.flags & 0x01)


# ---------------------------------------------------------------- NSEC
def nsec_nodata(qname: Name, qtype: int, nsecs: list[tuple[Name, object]]) -> bool:
    """A NODATA proof: an NSEC at exactly qname whose bitmap lacks qtype.

    CNAME must be absent too — had one existed, the server owed us the chain
    rather than an empty answer. DS is deliberately not handled here: it lives
    on the parent side of a cut and has its own rule (`nsec_ds_denial`).
    """
    for owner, rd in nsecs:
        if owner != qname:
            continue
        if _is_delegation(rd):
            return False
        return not (bitmap_has(rd.type_bitmap, qtype)
                    or bitmap_has(rd.type_bitmap, Type.CNAME))
    return False


def nsec_wildcard_nodata(qname: Name, qtype: int,
                         nsecs: list[tuple[Name, object]]) -> bool:
    """NODATA at a name that exists only through a wildcard: the wildcard
    matches but carries no qtype, and the exact name is proven absent."""
    for owner, rd in nsecs:
        if not owner.labels or owner.labels[0] != b"*":
            continue
        ce = Name(owner.labels[1:])
        if not qname.is_subdomain_of(ce) or qname == ce:
            continue
        if bitmap_has(rd.type_bitmap, qtype) or bitmap_has(rd.type_bitmap, Type.CNAME):
            continue
        if _covered(qname, nsecs):
            return True
    return False


def nsec_nxdomain(qname: Name, nsecs: list[tuple[Name, object]]) -> bool:
    """An NXDOMAIN proof needs two things, and the second is routinely
    forgotten: the name is absent, *and* no wildcard could have answered for it.

    With only the first, any covering NSEC the zone ever published — and these
    are public records — denies names the zone really does serve via `*`.
    """
    ce: Name | None = None
    for owner, rd in nsecs:
        if nsec_covers(owner, rd.next_name, qname):
            # Both names bracketing the gap exist in the zone, so the deeper of
            # the two ancestors they share with qname is the closest encloser.
            a = common_suffix(owner, qname)
            b = common_suffix(rd.next_name, qname)
            ce = a if len(a) >= len(b) else b
            break
    if ce is None or len(ce) >= len(qname):
        return False
    wild = wildcard_of(ce)
    if any(owner == wild for owner, _ in nsecs):
        return False            # the wildcard exists; this is not an NXDOMAIN
    return _covered(wild, nsecs)


def nsec_wildcard_expansion(qname: Name, expanded_from: Name,
                            nsecs: list[tuple[Name, object]]) -> bool:
    """A wildcard-expanded answer is honest only if the exact name it stood in
    for really is absent — otherwise one wildcard signature can be replayed
    over every name the zone answers for directly."""
    ce = Name(expanded_from.labels[1:])
    if not qname.is_subdomain_of(ce) or qname == ce:
        return False
    return _covered(qname, nsecs)


def nsec_ds_denial(child: Name, nsecs: list[tuple[Name, object]]) -> str | None:
    """What the parent's NSEC records say about a missing DS.

    Returns 'insecure' (a real delegation carrying no DS — the subtree is
    unsigned), 'nocut' (no delegation here; keep descending), or None (no proof).
    """
    for owner, rd in nsecs:
        if owner != child:
            continue
        if bitmap_has(rd.type_bitmap, Type.DS):
            return None                       # denies DS while asserting it exists
        if bitmap_has(rd.type_bitmap, Type.SOA):
            # An apex NSEC proves nothing about DS: DS is the parent's record and
            # this one came from the child, which has every reason to deny it.
            return None
        return "insecure" if bitmap_has(rd.type_bitmap, Type.NS) else "nocut"
    for owner, rd in nsecs:
        if nsec_covers(owner, rd.next_name, child):
            return "nocut"                    # the name does not exist at all
    return None


# ---------------------------------------------------------------- NSEC3
def nsec3_hash(name: Name, salt: bytes, iterations: int) -> bytes:
    """RFC 5155 NSEC3 hash (SHA-1 over the canonical wire name, iterated with salt)."""
    from ...wire.writer import Writer
    w = Writer()
    for label in name.canonicalize().labels:
        w.u8(len(label))
        w.raw(label)
    w.u8(0)
    digest = hashlib.sha1(w.getvalue() + salt).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()
    return digest


# base32 -> base32hex translation (RFC 4648 extended hex alphabet, used by NSEC3)
_B32HEX = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                        "0123456789abcdefghijklmnopqrstuv")


def nsec3_b32(h: bytes) -> str:
    # Translate first, lowercase second. _B32HEX is keyed on the uppercase
    # alphabet, so lowercasing ahead of it silently turns the whole mapping
    # into a no-op and yields plain base32 — self-consistent with our own
    # signer, and wrong against every real NSEC3 zone.
    return base64.b32encode(h).decode().rstrip("=").translate(_B32HEX).lower()


def _between(lo: str, x: str, hi: str) -> bool:
    if lo < hi:
        return lo < x < hi
    return x > lo or x < hi   # wrap at the end of the chain


class Nsec3Set:
    """The NSEC3 records from one response, with their shared parameters.

    Construction fails (`usable` stays False) when the records disagree about
    parameters or ask for more hashing than RFC 9276 permits — both are reasons
    to stop, not to compute harder.
    """

    def __init__(self, items: list[tuple[Name, object]], zone: Name,
                 max_iterations: int = MAX_NSEC3_ITERATIONS):
        self.zone = zone
        self.usable = False
        self.records: list[tuple[str, object]] = []
        self.salt = b""
        self.iterations = 0
        self._cache: dict[Name, str] = {}
        if not items:
            return
        first = items[0][1]
        if first.hash_algorithm != 1:                 # SHA-1 is the only one defined
            return
        if first.iterations > max_iterations:
            return
        for _owner, rd in items:
            if (rd.hash_algorithm != first.hash_algorithm or rd.salt != first.salt
                    or rd.iterations != first.iterations):
                return                                # mixed parameters prove nothing
        self.salt, self.iterations = first.salt, first.iterations
        for owner, rd in items:
            if not owner.labels:
                return
            if Name(owner.labels[1:]) != zone:
                # An NSEC3 owner is <hash>.<zone>. Recording only labels[0] and
                # ignoring the rest let a record from a deeper cut contribute its
                # hash to this chain, shifting the gaps `cover()` reads.
                continue
            self.records.append((owner.labels[0].decode("latin-1").lower(), rd))
        self.usable = True

    def h(self, name: Name) -> str:
        got = self._cache.get(name)
        if got is None:
            got = self._cache[name] = nsec3_b32(nsec3_hash(name, self.salt, self.iterations))
        return got

    def match(self, name: Name):
        want = self.h(name)
        for owner_hash, rd in self.records:
            if owner_hash == want:
                return rd
        return None

    def cover(self, name: Name):
        want = self.h(name)
        for owner_hash, rd in self.records:
            if _between(owner_hash, want, nsec3_b32(rd.next_hashed)):
                return rd
        return None


def _closest_encloser(qname: Name, s: Nsec3Set) -> tuple[Name, Name] | None:
    """Return (closest encloser, next closer): the deepest ancestor of qname
    that exists, and the one-label-deeper name that does not."""
    for anc in _ancestors(qname, s.zone):
        if s.match(anc) is not None:
            depth = len(anc.labels)
            return anc, Name(qname.labels[len(qname.labels) - depth - 1:])
    return None


def nsec3_nodata(qname: Name, qtype: int, s: Nsec3Set) -> bool:
    rd = s.match(qname)
    if rd is not None:
        if _is_delegation(rd):                        # RFC 5155 §8.5
            return False
        return (not bitmap_has(rd.type_bitmap, qtype)
                and not bitmap_has(rd.type_bitmap, Type.CNAME))
    # NODATA at a name that exists only through a wildcard (RFC 5155 §8.6)
    found = _closest_encloser(qname, s)
    if found is None:
        return False
    ce, next_closer = found
    if _gap_unproven(s.cover(next_closer)):
        return False
    wrd = s.match(wildcard_of(ce))
    return (wrd is not None
            and not bitmap_has(wrd.type_bitmap, qtype)
            and not bitmap_has(wrd.type_bitmap, Type.CNAME))


def nsec3_nxdomain(qname: Name, s: Nsec3Set) -> bool:
    """RFC 5155 §8.4: the closest encloser matched, the next closer covered,
    and the wildcard under the closest encloser covered.

    Every covering record must have Opt-Out clear. An opt-out NSEC3 states only
    that no *signed* name falls in its gap, so it is compatible with an unsigned
    delegation existing there — under an opt-out TLD the zone's own genuine
    chain would otherwise prove NXDOMAIN for domains that plainly exist.
    """
    found = _closest_encloser(qname, s)
    if found is None:
        return False
    ce, next_closer = found
    if _gap_unproven(s.cover(next_closer)):
        return False
    wild = wildcard_of(ce)
    if s.match(wild) is not None:
        return False
    return not _gap_unproven(s.cover(wild))


def nsec3_wildcard_expansion(qname: Name, expanded_from: Name, s: Nsec3Set) -> bool:
    ce = Name(expanded_from.labels[1:])
    if not qname.is_subdomain_of(ce) or qname == ce:
        return False
    depth = len(ce.labels)
    next_closer = Name(qname.labels[len(qname.labels) - depth - 1:])
    return not _gap_unproven(s.cover(next_closer))


def nsec3_ds_denial(child: Name, s: Nsec3Set) -> str | None:
    """The NSEC3 counterpart of `nsec_ds_denial`, plus opt-out.

    Opt-out (RFC 5155 §6) is the one case where a merely *covering* record says
    something about a delegation: the zone declares in advance that unsigned
    delegations in the gap are not enumerated. It buys 'insecure' and never more.
    """
    rd = s.match(child)
    if rd is not None:
        if bitmap_has(rd.type_bitmap, Type.DS):
            return None
        if bitmap_has(rd.type_bitmap, Type.SOA):
            return None                       # child's own apex; see nsec_ds_denial
        return "insecure" if bitmap_has(rd.type_bitmap, Type.NS) else "nocut"
    cov = s.cover(child)
    if cov is None:
        return None
    if cov.flags & 0x01:                      # opt-out
        return "insecure"
    return "nocut"                            # provably no such name
