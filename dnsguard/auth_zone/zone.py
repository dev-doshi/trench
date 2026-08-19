"""A single authoritative zone: records, wildcard/CNAME-aware lookup, and
DNSSEC signature attachment.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..wire import RR, Class, Type
from ..wire import rdata as R
from ..wire.name import Name
from ..wire.rrtypes import Rcode

DEFAULT_TTL = 3600


@dataclass
class Answer:
    rcode: int = Rcode.NOERROR
    aa: bool = True
    answers: list[RR] = field(default_factory=list)
    authority: list[RR] = field(default_factory=list)
    additional: list[RR] = field(default_factory=list)


class Zone:
    def __init__(self, origin: Name):
        self.origin = origin
        # name -> type -> list[Rdata]
        self.records: dict[Name, dict[int, list[R.Rdata]]] = {}
        self.ttls: dict[tuple[Name, int], int] = {}
        # DNSSEC: (name, type) -> RRSIG rdata ; NSEC RRs added as normal records
        self.rrsigs: dict[tuple[Name, int], R.RRSIG] = {}
        self.signed = False
        self.signing_key = None            # kept across re-signs (stable DS)
        self.sign_params: dict = {}        # nsec3 flavor etc., set by sign_zone
        self.journal: list[dict] = []      # IXFR delta log (RFC 1995)

    # --- build ---
    def add(self, name: Name, rtype: int, rdata: R.Rdata, ttl: int = DEFAULT_TTL) -> None:
        self.records.setdefault(name, {}).setdefault(rtype, []).append(rdata)
        self.ttls[(name, rtype)] = ttl

    @property
    def soa(self) -> R.SOA | None:
        node = self.records.get(self.origin, {})
        soas = node.get(Type.SOA)
        return soas[0] if soas else None

    def names(self) -> list[Name]:
        return sorted(self.records.keys(), key=lambda n: tuple(reversed(n._lower)))

    def ttl_of(self, name: Name, rtype: int) -> int:
        return self.ttls.get((name, rtype), DEFAULT_TTL)

    # --- query ---
    def lookup(self, qname: Name, qtype: int, *, do: bool = False) -> Answer:
        node = self.records.get(qname)
        owner = qname
        if node is None:
            wnode = self._wildcard(qname)
            if wnode is None:
                return self._nxdomain(do, qname)
            node = wnode
        return self._answer_at(owner, node, qtype, do)

    def _answer_at(self, owner: Name, node: dict, qtype: int, do: bool) -> Answer:
        # CNAME (unless explicitly asking for CNAME)
        if qtype != Type.CNAME and Type.CNAME in node:
            rd = node[Type.CNAME][0]
            ans = [RR(owner, Type.CNAME, Class.IN, self.ttl_of(owner, Type.CNAME), rd)]
            self._attach_sig(ans, owner, Type.CNAME, do)
            target = rd.name
            if target in self.records and self._in_bailiwick(target):
                sub = self.lookup(target, qtype, do=do)
                ans.extend(sub.answers)
            return Answer(answers=ans)
        if qtype in node:
            ttl = self.ttl_of(owner, qtype)
            ans = [RR(owner, qtype, Class.IN, ttl, rd) for rd in node[qtype]]
            self._attach_sig(ans, owner, qtype, do)
            return Answer(answers=ans)
        # NODATA
        return self._nodata(do, owner)

    def _wildcard(self, qname: Name) -> dict | None:
        if len(qname) <= len(self.origin):
            return None
        wild = Name((b"*",) + qname.parent().labels)
        return self.records.get(wild)

    def _in_bailiwick(self, name: Name) -> bool:
        return name.is_subdomain_of(self.origin)

    def _soa_rr(self) -> list[RR]:
        soa = self.soa
        if soa is None:
            return []
        rr = [RR(self.origin, Type.SOA, Class.IN, self.ttl_of(self.origin, Type.SOA), soa)]
        return rr

    def _nodata(self, do: bool, owner: Name) -> Answer:
        auth = self._soa_rr()
        self._attach_sig(auth, self.origin, Type.SOA, do)
        if do:
            self._attach_nsec(auth, owner)
        return Answer(rcode=Rcode.NOERROR, authority=auth)

    def _nxdomain(self, do: bool, qname: Name) -> Answer:
        auth = self._soa_rr()
        self._attach_sig(auth, self.origin, Type.SOA, do)
        if do:
            self._attach_nsec(auth, qname)
        return Answer(rcode=Rcode.NXDOMAIN, authority=auth)

    def _attach_sig(self, rrs: list[RR], name: Name, rtype: int, do: bool) -> None:
        if not (do and self.signed):
            return
        sig = self.rrsigs.get((name, rtype))
        if sig is not None:
            rrs.append(RR(name, Type.RRSIG, Class.IN, self.ttl_of(name, rtype), sig))

    def _attach_nsec(self, rrs: list[RR], qname: Name) -> None:
        # attach the NSEC covering the closest existing name (proof of non-existence)
        node = self.records.get(self.origin, {})
        if Type.NSEC in node:
            rrs.append(RR(self.origin, Type.NSEC, Class.IN,
                          self.ttl_of(self.origin, Type.NSEC), node[Type.NSEC][0]))
            self._attach_sig(rrs, self.origin, Type.NSEC, True)
