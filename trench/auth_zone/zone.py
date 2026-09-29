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
        if node is not None and not _nsec3_only(node):
            return self._answer_at(qname, node, qtype, do)
        encloser = self._closest_encloser(qname)
        if encloser == qname:
            # An empty non-terminal exists without holding records, so it is
            # NODATA rather than NXDOMAIN: names below it do exist.
            return self._nodata(do, qname, encloser=encloser)
        # RFC 4592 §3.3.1: only `*.<closest encloser>` may synthesize. A
        # wildcard further up does not reach past a name that exists — with
        # `*.example.com` and `foo.example.com` in the zone, `x.foo.example.com`
        # is NXDOMAIN, not the wildcard's data.
        wild_name = Name((b"*",) + encloser.labels)
        wild = self.records.get(wild_name)
        if wild is not None:
            return self._answer_at(wild_name, wild, qtype, do,
                                   synth=qname, encloser=encloser)
        return self._nxdomain(do, qname, encloser)

    def _closest_encloser(self, qname: Name) -> Name:
        """The deepest ancestor-or-self of `qname` that exists in the zone.

        A name exists when it owns records or has a descendant that does (an
        empty non-terminal). The longest common suffix between `qname` and any
        owner name is exactly that: it is an ancestor-or-self of an owner, so it
        exists, and nothing deeper does. One pass, no per-ancestor rescans.
        """
        want = tuple(reversed(qname._lower))
        base = len(self.origin)
        best = base
        for name, node in self.records.items():
            if _nsec3_only(node):
                continue                    # hashed owners are not in the namespace
            low = name._lower
            k = base
            n = len(low)
            while k < n and k < len(want) and low[n - 1 - k] == want[k]:
                k += 1
            if k > best:
                best = k
                if best == len(want):
                    break
        return Name(qname.labels[len(qname) - best:])

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

    def _answer_at(self, owner: Name, node: dict, qtype: int, do: bool, *,
                   synth: Name | None = None, encloser: Name | None = None) -> Answer:
        """Answer from `node`, the records at `owner`.

        `synth` is the query name when `owner` is a wildcard: RFC 4592 §3.3.1
        says the answer is owned by the name asked for, not by `*`. Handing back
        `*.example.com` records to a query for `x.example.com` is an answer a
        stub discards (the owner does not match the question) and a validator
        cannot check. The RRSIG is the wildcard's own; its label count tells a
        validator that it was expanded.
        """
        shown = synth or owner
        # CNAME (unless explicitly asking for CNAME)
        if qtype != Type.CNAME and Type.CNAME in node:
            ans: list[RR] = []
            seen: set[Name] = set()
            cur, cur_node, cur_shown = owner, node, shown
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
                ans.append(RR(cur_shown, Type.CNAME, Class.IN,
                              self.ttl_of(cur, Type.CNAME), rd))
                self._attach_sig(ans, cur, Type.CNAME, do, shown=cur_shown)
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
                cur, cur_node, cur_shown = target, nxt, target
            out = Answer(answers=ans)
        elif qtype in node:
            ttl = self.ttl_of(owner, qtype)
            ans = [RR(shown, qtype, Class.IN, ttl, rd) for rd in node[qtype]]
            self._attach_sig(ans, owner, qtype, do, shown=shown)
            out = Answer(answers=ans)
        else:
            return self._nodata(do, shown, wildcard=owner if synth else None,
                                encloser=encloser)
        if synth is not None and self._proving(do):
            # RFC 4035 §3.1.3.3: a wildcard answer carries the proof that the
            # name asked for does not exist, or a validator has to assume the
            # expansion replaced a real record and fail it.
            out.authority.extend(self._denial(synth, encloser or owner.parent(),
                                              kind="wildcard"))
        return out

    def _in_bailiwick(self, name: Name) -> bool:
        return name.is_subdomain_of(self.origin)

    def _negative_ttl(self) -> int:
        """RFC 2308 §3 / RFC 9077: the SOA in a negative answer, and the denial
        records beside it, live min(SOA TTL, SOA MINIMUM). Using the SOA's own
        TTL let a zone with a one-hour SOA and a five-minute MINIMUM have its
        NXDOMAINs cached twelve times longer than it asked."""
        soa = self.soa
        ttl = self.ttl_of(self.origin, Type.SOA)
        return min(ttl, soa.minimum) if soa is not None else ttl

    def _soa_rr(self, do: bool = False) -> list[RR]:
        soa = self.soa
        if soa is None:
            return []
        ttl = self._negative_ttl()
        rr = [RR(self.origin, Type.SOA, Class.IN, ttl, soa)]
        self._attach_sig(rr, self.origin, Type.SOA, do, ttl=ttl)
        return rr

    def _nodata(self, do: bool, qname: Name, *, wildcard: Name | None = None,
                encloser: Name | None = None) -> Answer:
        auth = self._soa_rr(do)
        if self._proving(do):
            if wildcard is not None:
                auth.extend(self._denial(qname, encloser or wildcard.parent(),
                                         kind="wildcard-nodata", wildcard=wildcard))
            else:
                auth.extend(self._denial(qname, encloser or qname, kind="nodata"))
        return Answer(rcode=Rcode.NOERROR, authority=auth)

    def _nxdomain(self, do: bool, qname: Name, encloser: Name) -> Answer:
        auth = self._soa_rr(do)
        if self._proving(do):
            auth.extend(self._denial(qname, encloser, kind="nxdomain"))
        return Answer(rcode=Rcode.NXDOMAIN, authority=auth)

    def _attach_sig(self, rrs: list[RR], name: Name, rtype: int, do: bool, *,
                    shown: Name | None = None, ttl: int | None = None) -> None:
        if not (do and self.signed):
            return
        sig = self.rrsigs.get((name, rtype))
        if sig is not None:
            rrs.append(RR(shown or name, Type.RRSIG, Class.IN,
                          self.ttl_of(name, rtype) if ttl is None else ttl, sig))

    # --- authenticated denial (RFC 4035 §3.1.3, RFC 5155 §7.2) ---
    def _proving(self, do: bool) -> bool:
        return do and self.signed

    def _denial(self, qname: Name, encloser: Name, *, kind: str,
                wildcard: Name | None = None) -> list[RR]:
        """The NSEC or NSEC3 records (with signatures) a validator needs.

        This used to attach the apex NSEC to every negative answer, whatever
        the name. The apex NSEC covers only the gap between the apex and the
        first name after it, so for nearly every query it proved nothing, and a
        validating resolver answered SERVFAIL for every NXDOMAIN and NODATA in
        a signed zone.
        """
        if Type.NSEC3PARAM in self.records.get(self.origin, {}):
            return self._nsec3_denial(qname, encloser, kind, wildcard)
        want: list[Name] = []
        if kind == "nodata" and Type.NSEC in self.records.get(qname, {}):
            want.append(qname)                       # the NSEC at the name itself
        elif kind == "nodata":
            want.append(self._nsec_predecessor(qname))   # empty non-terminal
        else:
            want.append(self._nsec_predecessor(qname))   # qname does not exist
            if kind == "nxdomain":
                # ...and neither does the wildcard that could have answered it.
                want.append(self._nsec_predecessor(Name((b"*",) + encloser.labels)))
            elif kind == "wildcard-nodata" and wildcard is not None:
                want.append(wildcard)                # the wildcard lacks the type
        return self._denial_rrs(want, Type.NSEC)

    def _nsec_predecessor(self, name: Name) -> Name:
        """The NSEC owner whose gap holds `name`: the last one before it in
        canonical order (RFC 4034 §6.1). The apex sorts first, so it is the
        fallback."""
        from ..resolver.dnssec.nsec import name_lt
        best = self.origin
        for owner, node in self.records.items():
            if Type.NSEC in node and name_lt(owner, name) and name_lt(best, owner):
                best = owner
        return best

    def _nsec3_denial(self, qname: Name, encloser: Name, kind: str,
                      wildcard: Name | None) -> list[RR]:
        chain = self._nsec3_chain()
        if not chain:
            return []
        next_closer = Name(qname.labels[len(qname) - len(encloser) - 1:]) \
            if len(qname) > len(encloser) else qname
        want: list[Name | None] = []   # an unmatched name is simply skipped
        if kind == "nodata":
            want.append(self._nsec3_owner(chain, qname, match=True))
        elif kind == "wildcard":
            want.append(self._nsec3_owner(chain, next_closer, match=False))
        else:
            # RFC 5155 §7.2.1/§7.2.5: the closest encloser exists, the next
            # closer name does not, and (for NXDOMAIN) neither does the wildcard.
            want.append(self._nsec3_owner(chain, encloser, match=True))
            want.append(self._nsec3_owner(chain, next_closer, match=False))
            if kind == "nxdomain":
                want.append(self._nsec3_owner(
                    chain, Name((b"*",) + encloser.labels), match=False))
            elif wildcard is not None:
                want.append(self._nsec3_owner(chain, wildcard, match=True))
        return self._denial_rrs([w for w in want if w is not None], Type.NSEC3)

    def _nsec3_chain(self) -> list[tuple[str, Name]]:
        return sorted((owner.labels[0].decode("ascii").lower(), owner)
                      for owner, node in self.records.items()
                      if Type.NSEC3 in node and owner.labels)

    def _nsec3_owner(self, chain: list[tuple[str, Name]], name: Name, *,
                     match: bool) -> Name | None:
        from ..resolver.dnssec.nsec import nsec3_b32, nsec3_hash
        p = self.sign_params
        h = nsec3_b32(nsec3_hash(name, p.get("nsec3_salt", b""),
                                 p.get("nsec3_iterations", 0))).lower()
        prev = chain[-1][1]                  # wrap: the last hash covers the front
        for owner_hash, owner in chain:
            if owner_hash == h:
                return owner
            if owner_hash > h:
                break
            prev = owner
        return None if match else prev

    def _denial_rrs(self, owners: list[Name], rtype: int) -> list[RR]:
        out: list[RR] = []
        seen: set[Name] = set()
        ttl = self._negative_ttl()
        for owner in owners:
            if owner in seen:
                continue
            seen.add(owner)
            rds = self.records.get(owner, {}).get(rtype)
            if not rds:
                continue
            out.append(RR(owner, rtype, Class.IN, ttl, rds[0]))
            self._attach_sig(out, owner, rtype, True, ttl=ttl)
        return out


def _nsec3_only(node: dict) -> bool:
    """A hashed NSEC3 owner: bookkeeping stored beside the zone's names, not a
    name in it. Treating one as real made `<hash>.example.com` exist."""
    return bool(node) and Type.NSEC3 in node and all(
        t in (Type.NSEC3, Type.RRSIG) for t in node)
