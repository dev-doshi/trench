"""RFC 2136 dynamic UPDATE: prerequisite checking + atomic record mutation.

An UPDATE message names a zone (question), lists prerequisites (answer section),
and lists changes (authority section). We evaluate every prerequisite first; if
all pass we apply the changes atomically, bump the SOA serial, and append an
IXFR journal entry so secondaries can pull the delta.
"""
from __future__ import annotations

from ..wire import RR, Message, Type
from ..wire.name import Name
from ..wire.rrtypes import Class, Rcode
from .zone import Zone

MAX_JOURNAL = 64


class UpdatePolicy:
    """Which names/types a given credential may change. Default: full control."""
    def __init__(self, allow: bool = True, names: set[Name] | None = None):
        self.allow = allow
        self.names = names            # None = any name in zone

    def permits(self, zone: Zone, name: Name) -> bool:
        if not self.allow or not name.is_subdomain_of(zone.origin):
            return False
        return self.names is None or name in self.names


def check_prerequisites(zone: Zone, prereqs: list[RR]) -> int:
    """RFC 2136 §3.2. Returns NOERROR if all satisfied, else the error rcode."""
    for rr in prereqs:
        if rr.ttl != 0:
            return Rcode.FORMERR
        node = zone.records.get(rr.name, {})
        if rr.rclass == Class.ANY:
            if rr.rtype == Type.ANY:                       # name is in use
                if not node:
                    return Rcode.NXDOMAIN
            else:                                          # RRset exists (value independent)
                if rr.rtype not in node:
                    return Rcode.NXRRSET
        elif rr.rclass == Class.NONE:
            if rr.rtype == Type.ANY:                       # name is not in use
                if node:
                    return Rcode.YXDOMAIN
            else:                                          # RRset does not exist
                if rr.rtype in node:
                    return Rcode.YXRRSET
        else:                                              # value-dependent: exact RRset
            want = _rdata_set(prereqs, rr.name, rr.rtype)
            have = {rd.to_text() for rd in node.get(rr.rtype, [])}
            if want != have:
                return Rcode.NXRRSET
    return Rcode.NOERROR


def _rdata_set(rrs: list[RR], name: Name, rtype: int) -> set[str]:
    return {rr.rdata.to_text() for rr in rrs if rr.name == name and rr.rtype == rtype}


def _bump_serial(zone: Zone) -> tuple[int, int]:
    soa = zone.soa
    old = soa.serial
    soa.serial = (old + 1) & 0xFFFFFFFF
    return old, soa.serial


def apply_update(zone: Zone, msg: Message, policy: UpdatePolicy | None = None) -> int:
    """Apply an RFC 2136 UPDATE to `zone`. Returns the response rcode."""
    policy = policy or UpdatePolicy()
    q = msg.question
    if q is None or q.rtype != Type.SOA:
        return Rcode.FORMERR
    if zone.origin != q.name:
        return Rcode.NOTAUTH

    rc = check_prerequisites(zone, msg.answers)
    if rc != Rcode.NOERROR:
        return rc

    # authorization: every update must fall under the policy
    for rr in msg.authority:
        if not rr.name.is_subdomain_of(zone.origin):
            return Rcode.NOTZONE
        if not policy.permits(zone, rr.name):
            return Rcode.REFUSED

    if zone.soa is None:                                   # not a servable zone
        return Rcode.SERVFAIL
    deletions: list[RR] = []
    additions: list[RR] = []
    for rr in msg.authority:
        _apply_one(zone, rr, deletions, additions)

    if not additions and not deletions:
        return Rcode.NOERROR                               # no-op, don't bump serial
    old, new = _bump_serial(zone)
    _journal(zone, old, new, deletions, additions)
    if zone.signed:
        _resign(zone)
    return Rcode.NOERROR


def _apply_one(zone: Zone, rr: RR, deletions: list[RR], additions: list[RR]) -> None:
    node = zone.records.get(rr.name)
    if rr.rclass == Class.ANY:
        if rr.rtype == Type.ANY:                           # delete all RRsets at name
            if node:
                for rtype, rds in list(node.items()):
                    if rr.name == zone.origin and rtype in (Type.SOA, Type.NS):
                        continue
                    for rd in rds:
                        deletions.append(RR(rr.name, rtype, Class.IN, 0, rd))
                    del node[rtype]
                if not node:
                    zone.records.pop(rr.name, None)
        else:                                              # delete one RRset (type)
            if rr.name == zone.origin and rr.rtype in (Type.SOA, Type.NS):
                return
            if node and rr.rtype in node:
                for rd in node[rr.rtype]:
                    deletions.append(RR(rr.name, rr.rtype, Class.IN, 0, rd))
                del node[rr.rtype]
                zone.rrsigs.pop((rr.name, rr.rtype), None)
                if not node:
                    zone.records.pop(rr.name, None)
    elif rr.rclass == Class.NONE:                          # delete an individual RR
        if node and rr.rtype in node:
            keep = [rd for rd in node[rr.rtype] if rd.to_text() != rr.rdata.to_text()]
            if len(keep) != len(node[rr.rtype]):
                deletions.append(RR(rr.name, rr.rtype, Class.IN, 0, rr.rdata))
            if keep:
                node[rr.rtype] = keep
            else:
                del node[rr.rtype]
                if not node:
                    zone.records.pop(rr.name, None)
    else:                                                  # add / replace (zone class = IN)
        existing = zone.records.get(rr.name, {}).get(rr.rtype, [])
        if all(rd.to_text() != rr.rdata.to_text() for rd in existing):
            zone.add(rr.name, rr.rtype, rr.rdata, rr.ttl)
            additions.append(rr)


def _journal(zone: Zone, old: int, new: int, dels: list[RR], adds: list[RR]) -> None:
    zone.journal.append({"from": old, "to": new, "delete": dels, "add": adds})
    del zone.journal[:-MAX_JOURNAL]


# every record type the signer synthesizes; all must be dropped before a re-sign
_DNSSEC_TYPES = (Type.NSEC, Type.NSEC3, Type.NSEC3PARAM, Type.DNSKEY,
                 Type.CDS, Type.CDNSKEY)


def _resign(zone: Zone) -> None:
    """Re-sign after a change: strip every signer-generated artifact (RRSIGs,
    NSEC/NSEC3 chains + their hashed owner names, DNSKEY, CDS/CDNSKEY), then
    re-run the signer with the SAME key and denial flavor — the DS at the
    parent must stay valid across dynamic updates."""
    import copy

    from .sign import sign_zone
    # Stripped and re-signed on a copy, swapped in only once signing succeeds.
    # Doing it in place had no rollback: a signer that raised — a missing key,
    # bad sign_params — left a live zone stripped and unsigned while the
    # parent's DS still pointed at it, so every validating resolver returned
    # SERVFAIL for the whole zone.
    staged = copy.copy(zone)
    # Fresh containers, shared leaves. A deepcopy would try to clone the
    # signing key, which is not copyable; the rdata objects are never mutated
    # in place, so sharing them is safe and the copy stays cheap.
    staged.records = {n: {t: list(rds) for t, rds in node.items()}
                      for n, node in zone.records.items()}
    staged.ttls = dict(zone.ttls)
    staged.rrsigs = dict(zone.rrsigs)
    for name in list(staged.records):
        node = staged.records[name]
        for t in _DNSSEC_TYPES:
            node.pop(t, None)
            staged.ttls.pop((name, t), None)
        if not node:                        # e.g. an NSEC3 hashed owner name
            del staged.records[name]
    staged.rrsigs.clear()
    staged.signed = False
    sign_zone(staged, private_key=staged.signing_key, **staged.sign_params)
    zone.records = staged.records
    zone.ttls = staged.ttls
    zone.rrsigs = staged.rrsigs
    zone.signed = staged.signed
    zone.signing_key = staged.signing_key
    zone.sign_params = staged.sign_params
