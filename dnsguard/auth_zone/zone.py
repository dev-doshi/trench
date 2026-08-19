"""A single authoritative zone: records, wildcard/CNAME-aware lookup, and
DNSSEC signature attachment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

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
        # The record store is keyed by rtype and holds bare Rdata; the SOA slot
        # holds SOA by construction. cast rather than widen the return type,
        # which every caller relies on.
        return cast("R.SOA | None", soas[0]) if soas else None

    def names(self) -> list[Name]:
        return sorted(self.records.keys(), key=lambda n: tuple(reversed(n._lower)))

    def ttl_of(self, name: Name, rtype: int) -> int:
        return self.ttls.get((name, rtype), DEFAULT_TTL)

    # --- query ---
    #: A CNAME chain inside one zone is a configuration, not a search space.
    #: Anything longer than this is a loop or a mistake, and either way is not
    #: worth another lookup.
    MAX_CNAME_CHAIN = 16

    def lookup(self, qname: Name, qtype: int, *, do: bool = False) -> Answer:
        cut = self._delegation(qname, qtype)
        if cut is not None:
            return cut
        node = self.records.get(qname)
        owner = qname
        if node is None:
            found = self._wildcard(qname)
            if found is None:
                # An empty non-terminal exists without holding records, so it is
                # NODATA rather than NXDOMAIN: names below it do exist.
                if self._is_empty_non_terminal(qname):
                    return self._nodata(do, qname)
                return self._nxdomain(do, qname)
            owner, node = found
        return self._answer_at(owner, node, qtype, do)

    def _delegation(self, qname: Name, qtype: int) -> Answer | None:
        """A referral, when `qname` lives inside a child zone we delegated.

        Without this the parent answered for the whole delegated subtree out of
        its own records — returning an authoritative NXDOMAIN for every name in
        a child zone it does not hold, which denies the child to every client
        instead of pointing at it.

        A DS query is answered by the parent, so it stops at the cut rather than
        being sent across it.
        """
        n = qname
        while len(n) > len(self.origin):
            if qtype == Type.DS and n == qname:
                n = n.parent()
                continue
            node = self.records.get(n)
            if node and Type.NS in node and Type.SOA not in node:
                ns = [RR(n, Type.NS, Class.IN, self.ttl_of(n, Type.NS), rd)
                      for rd in node[Type.NS]]
                extra: list[RR] = []
                for rd in node[Type.NS]:
                    target = cast("R.NS", rd).name   # NS slot holds NS rdata
                    if not target.is_subdomain_of(n):
                        continue                  # out-of-zone NS needs no glue
                    glue = self.records.get(target) or {}
                    for gt in (Type.A, Type.AAAA):
                        extra.extend(
                            RR(target, gt, Class.IN, self.ttl_of(target, gt), g)
                            for g in glue.get(gt, ()))
                # DS proves the delegation is signed and belongs in the referral.
                ds = self.records.get(n, {}).get(Type.DS)
                if ds:
                    ns.extend(RR(n, Type.DS, Class.IN, self.ttl_of(n, Type.DS), rd)
                              for rd in ds)
                return Answer(rcode=Rcode.NOERROR, aa=False,
                              authority=ns, additional=extra)
            n = n.parent()
        return None

    def _answer_at(self, owner: Name, node: dict, qtype: int, do: bool) -> Answer:
        # CNAME (unless explicitly asking for CNAME)
        if qtype != Type.CNAME and Type.CNAME in node:
            ans: list[RR] = []
            seen: set[Name] = set()
            cur, cur_node = owner, node
            # Chased iteratively with a visited set. Recursing meant a zone
            # holding `a CNAME b` / `b CNAME a` — loadable from a zonefile, a
            # dynamic UPDATE, or an inbound AXFR — turned every query for that
            # name into a RecursionError, so a query flood became a CPU and
            # stack denial of service with a logged traceback per packet.
            while Type.CNAME in cur_node and len(ans) < self.MAX_CNAME_CHAIN:
                if cur in seen:
                    break
                seen.add(cur)
                rd = cur_node[Type.CNAME][0]
                ans.append(RR(cur, Type.CNAME, Class.IN,
                              self.ttl_of(cur, Type.CNAME), rd))
                self._attach_sig(ans[-1:], cur, Type.CNAME, do)
                target = rd.name
                if target in seen or not self._in_bailiwick(target):
                    break
                nxt = self.records.get(target)
                if nxt is None:
                    break
                if qtype in nxt:
                    tail = [RR(target, qtype, Class.IN, self.ttl_of(target, qtype), r)
                            for r in nxt[qtype]]
                    self._attach_sig(tail, target, qtype, do)
                    ans.extend(tail)
                    break
                cur, cur_node = target, nxt
            return Answer(answers=ans)
        if qtype in node:
            ttl = self.ttl_of(owner, qtype)
            ans = [RR(owner, qtype, Class.IN, ttl, rd) for rd in node[qtype]]
            self._attach_sig(ans, owner, qtype, do)
            return Answer(answers=ans)
        # NODATA
        return self._nodata(do, owner)

    def _is_empty_non_terminal(self, qname: Name) -> bool:
        """True when `qname` holds no records but some name below it does."""
        return any(n != qname and n.is_subdomain_of(qname) for n in self.records)

    def _wildcard(self, qname: Name) -> tuple[Name, dict] | None:
        """RFC 4592 closest-encloser synthesis: `*` at the deepest ancestor of
        `qname` that exists, not merely at its immediate parent.

        Trying only the parent meant `*.example.com` answered `x.example.com`
        and returned NXDOMAIN for `deep.sub.example.com`, which the zone does
        cover. The walk stops at a delegation, since names below a cut are the
        child's to answer.
        """
        if len(qname) <= len(self.origin):
            return None
        n = qname.parent()
        while len(n) >= len(self.origin):
            node = self.records.get(n)
            if node and Type.NS in node and Type.SOA not in node:
                return None                   # a cut: not ours to synthesize past
            wild = self.records.get(Name((b"*",) + n.labels))
            if wild is not None:
                return Name((b"*",) + n.labels), wild
            if n == self.origin:
                break
            n = n.parent()
        return None

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
