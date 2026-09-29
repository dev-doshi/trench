"""Sign a Zone with DNSSEC: generate a key, add DNSKEY, build the NSEC chain,
and produce an RRSIG for every RRset. Returns the DS record for the parent.

Uses a single combined signing key (KSK+ZSK, flags 257) for simplicity; ECDSA
P-256 (algorithm 13) by default. Signatures validate against our own
`dnssec.verify_rrset`, closing the sign/validate loop.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from ...resolver.dnssec.keys import ds_digest, key_tag
from ...resolver.dnssec.validate import _signed_data
from ...wire import Type
from ...wire import rdata as R
from ...wire.name import Name
from ..zone import Zone

_SIG_VALIDITY = 30 * 86400


@dataclass
class SignResult:
    dnskey: R.DNSKEY
    ds: R.DS
    key_tag: int


def encode_type_bitmap(types: set[int]) -> bytes:
    windows: dict[int, list[int]] = {}
    for t in types:
        windows.setdefault(t >> 8, []).append(t & 0xFF)
    out = bytearray()
    for win in sorted(windows):
        bits = windows[win]
        length = (max(bits) // 8) + 1
        ba = bytearray(length)
        for b in bits:
            ba[b // 8] |= 0x80 >> (b % 8)
        out += bytes([win, length]) + bytes(ba)
    return bytes(out)


def _cuts(zone: Zone) -> set[Name]:
    """Delegation points: an NS set anywhere below the apex."""
    return {n for n, node in zone.records.items()
            if n != zone.origin and Type.NS in node and Type.SOA not in node}


def _occluded(zone: Zone, name: Name, cuts: set[Name]) -> bool:
    """True for a name strictly below a zone cut — glue, which the child owns.

    RFC 4035 §2.2: glue is not authoritative data, so it is neither signed nor
    part of the denial chain. Signing it put RRSIGs on records we have no
    authority for, and chaining it let an NSEC claim names inside the child.
    """
    n = name.parent()
    while len(n) > len(zone.origin):
        if n in cuts:
            return True
        n = n.parent()
    return False


def _chain_names(zone: Zone, cuts: set[Name]) -> list[Name]:
    return [n for n in zone.names() if not _occluded(zone, n, cuts)]


def _present_types(zone: Zone, name: Name, cuts: set[Name]) -> set[int]:
    """The types an NSEC/NSEC3 bitmap lists for `name`.

    At a delegation point only NS and DS are ours (RFC 4035 §2.3); anything
    else found there — an address record sharing the cut's name — is glue.
    """
    types = set(zone.records[name].keys())
    if name in cuts:
        types &= {Type.NS, Type.DS}
    return types


def _denial_ttl(zone: Zone) -> int:
    """RFC 9077: NSEC/NSEC3 TTL = min(SOA TTL, SOA MINIMUM), the same as the
    negative answers they appear in."""
    soa = zone.soa
    ttl = zone.ttl_of(zone.origin, Type.SOA)
    return min(ttl, soa.minimum) if soa is not None else ttl


def _build_nsec3_chain(zone: Zone, salt: bytes, iterations: int,
                       cuts: set[Name] | None = None) -> None:
    """Replace the plain-NSEC step with an NSEC3 chain (RFC 5155)."""
    from ...resolver.dnssec.nsec import nsec3_b32, nsec3_hash

    cuts = _cuts(zone) if cuts is None else cuts
    # NSEC3PARAM at the apex advertises the hash parameters
    zone.add(zone.origin, Type.NSEC3PARAM, R.NSEC3PARAM(1, 0, iterations, salt),
             zone.ttl_of(zone.origin, Type.SOA))

    owners = _chain_names(zone, cuts)
    # RFC 5155 §7.1: empty non-terminals get an NSEC3 too. Without one there is
    # nothing to match `b.example.com` when only `a.b.example.com` exists, and
    # the NODATA answer for it cannot be proven.
    ents: set[Name] = set()
    for name in owners:
        n = name.parent()
        while len(n) > len(zone.origin) and n not in zone.records:
            ents.add(n)
            n = n.parent()
    hashed: list[tuple[bytes, set[int]]] = []
    for name in owners:
        present = _present_types(zone, name, cuts)
        # RRSIG only where something is signed: an unsigned delegation (NS
        # without DS) carries no signatures (RFC 5155 §7.1).
        if not (name in cuts and Type.DS not in present):
            present.add(Type.RRSIG)
        hashed.append((nsec3_hash(name, salt, iterations), present))
    hashed.extend((nsec3_hash(n, salt, iterations), set()) for n in ents)
    hashed.sort(key=lambda t: t[0])

    ttl = _denial_ttl(zone)
    for i, (h, present) in enumerate(hashed):
        nxt = hashed[(i + 1) % len(hashed)][0]
        owner = Name((nsec3_b32(h).encode("ascii"),) + zone.origin.labels)
        rd = R.NSEC3(hash_algorithm=1, flags=0, iterations=iterations, salt=salt,
                     next_hashed=nxt, type_bitmap=encode_type_bitmap(present))
        zone.add(owner, Type.NSEC3, rd, ttl)


def sign_zone(zone: Zone, *, algorithm: int = 13, now: float | None = None,
              nsec3: bool = False, nsec3_salt: bytes = b"", nsec3_iterations: int = 0,
              private_key=None) -> SignResult:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    now = int(now if now is not None else time.time())
    # reuse the caller's key when given — a stable key keeps the DS at the
    # parent valid across re-signs (dynamic updates must not roll the key)
    priv = private_key or ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    dnskey = R.DNSKEY(flags=257, protocol=3, algorithm=algorithm, public_key=pub)
    kt = key_tag(dnskey)

    # publish the DNSKEY at the apex
    zone.add(zone.origin, Type.DNSKEY, dnskey, zone.ttl_of(zone.origin, Type.SOA) or 3600)

    # publish CDS/CDNSKEY (RFC 7344) before building the denial chain so the
    # apex NSEC/NSEC3 type bitmap includes them
    ds = R.DS(key_tag=kt, algorithm=algorithm, digest_type=2,
              digest=ds_digest(zone.origin, dnskey, 2))
    zone.add(zone.origin, Type.CDNSKEY,
             R.CDNSKEY(dnskey.flags, dnskey.protocol, dnskey.algorithm, dnskey.public_key), 3600)
    zone.add(zone.origin, Type.CDS,
             R.CDS(ds.key_tag, ds.algorithm, ds.digest_type, ds.digest), 3600)

    cuts = _cuts(zone)
    if nsec3:
        _build_nsec3_chain(zone, nsec3_salt, nsec3_iterations, cuts)
    else:
        # build the NSEC chain over every authoritative owner name
        names = _chain_names(zone, cuts)
        ttl = _denial_ttl(zone)
        for i, name in enumerate(names):
            nxt = names[(i + 1) % len(names)]
            present = _present_types(zone, name, cuts) | {Type.RRSIG, Type.NSEC}
            zone.add(name, Type.NSEC,
                     R.NSEC(next_name=nxt, type_bitmap=encode_type_bitmap(present)), ttl)

    def sign_rrset(owner: Name, rtype: int, rdatas: list[R.Rdata], ttl: int) -> None:
        # RFC 4034 §3.1.3: the label count excludes the root and a leading
        # wildcard. It is how a validator tells a wildcard-expanded answer from
        # a real one, so counting the `*` makes every wildcard we sign
        # unverifiable at the far end.
        labels = len(owner.labels) - (1 if owner.labels and owner.labels[0] == b"*" else 0)
        rrsig = R.RRSIG(type_covered=rtype, algorithm=algorithm,
                        labels=labels, original_ttl=ttl,
                        expiration=now + _SIG_VALIDITY, inception=now - 3600,
                        key_tag=kt, signer=zone.origin, signature=b"")
        data = _signed_data(owner, rtype, 1, rrsig, rdatas)
        der = priv.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        rrsig.signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        zone.rrsigs[(owner, rtype)] = rrsig

    # Sign every authoritative RRset (snapshot first; we mutate zone.records
    # while iterating). At a cut only the DS and the NSEC are the parent's: the
    # NS set there and any glue belong to the child (RFC 4035 §2.2).
    snapshot = [(name, rtype, list(rds))
                for name, node in zone.records.items()
                if not _occluded(zone, name, cuts)
                for rtype, rds in node.items()
                if rtype != Type.RRSIG
                and (name not in cuts or rtype in (Type.DS, Type.NSEC))]
    for name, rtype, rds in snapshot:
        sign_rrset(name, rtype, rds, zone.ttl_of(name, rtype))

    zone.signed = True
    # remember the key + parameters so a later re-sign (dynamic update) keeps
    # the same DS and denial-of-existence flavor
    zone.signing_key = priv
    zone.sign_params = {"algorithm": algorithm, "nsec3": nsec3,
                        "nsec3_salt": nsec3_salt, "nsec3_iterations": nsec3_iterations}
    return SignResult(dnskey=dnskey, ds=ds, key_tag=kt)
