"""Discard records an upstream was never asked for (RFC 5452 §6).

A forwarder that relays a response verbatim will relay whatever the upstream put
in it. Checking the question section — which we now do — proves the *response*
belongs to our query; it says nothing about the individual records inside. A
compromised or merely sloppy upstream can attach an A record for someone else's
bank to an answer about an ad domain, and every downstream stub and OS cache
that trusts its resolver then sees it.

So the answer section is rebuilt rather than copied: start at the question name,
follow the CNAME chain, and keep only records owned by a name on that chain.
Everything else was unsolicited by definition.

Two things this must not break, which is why it is a filter and not a whitelist
of types:

  * **DNSSEC.** A validating client needs the RRSIGs covering what it received
    and the NSEC/NSEC3 records proving a negative answer. Those are kept
    wherever their owner is legitimate.
  * **Delegations and negative answers.** The authority section carries SOA and
    NS records for the zone, whose owner is a *parent* of the question name, so
    in-bailiwick ancestors are kept too.

Glue in the additional section is kept only when something we kept actually
points at it. A forwarding resolver never follows glue itself, so an address
record for an unrelated name has no legitimate reason to be there.
"""
from __future__ import annotations

from ..wire.message import RR, Message
from ..wire.name import Name
from ..wire.rrtypes import Type

# A chain longer than this is not a real service configuration; it is either a
# loop or an attempt to make us walk one.
MAX_CNAME_CHAIN = 16

# Types whose rdata names another record that may legitimately need glue.
_TARGET_TYPES = (Type.NS, Type.MX, Type.SRV, Type.SVCB, Type.HTTPS)


class Sanitized:
    """What was removed, for logging and metrics."""
    __slots__ = ("answers", "authority", "additional")

    def __init__(self) -> None:
        self.answers = 0
        self.authority = 0
        self.additional = 0

    @property
    def total(self) -> int:
        return self.answers + self.authority + self.additional

    def __bool__(self) -> bool:
        return self.total > 0

    def __repr__(self) -> str:
        return (f"Sanitized(answers={self.answers}, authority={self.authority}, "
                f"additional={self.additional})")


def _chain(qname: Name, answers: list[RR]) -> set[Name]:
    """Names legitimately answerable for `qname`: itself plus its CNAME chain.

    Built by following CNAMEs actually present in the response. A record whose
    owner never appears as a chain link was not asked for.
    """
    chain = {qname}
    # index CNAME targets by owner; a well-formed response has one per owner
    cnames: dict[Name, Name] = {}
    for rr in answers:
        if rr.rtype == Type.CNAME and rr.name not in cnames:
            target = getattr(rr.rdata, "target", None) or getattr(rr.rdata, "name", None)
            if isinstance(target, Name):
                cnames[rr.name] = target
    cur = qname
    for _ in range(MAX_CNAME_CHAIN):
        nxt = cnames.get(cur)
        if nxt is None or nxt in chain:   # end of chain, or a loop
            break
        chain.add(nxt)
        cur = nxt
    return chain


def _in_bailiwick(name: Name, qname: Name) -> bool:
    """True when `name` is the question name or one of its ancestors.

    The authority section of a delegation or a negative answer is owned by the
    enclosing zone, so ancestors are expected there. A *descendant* or an
    unrelated name is not.
    """
    return qname.is_subdomain_of(name)


def _targets(rrs: list[RR]) -> set[Name]:
    """Names a kept record points at, and which may therefore have glue.

    A target only earns its glue when it sits inside the zone that named it.
    Without that test an authority record for `com. NS ns.attacker.net` made
    `ns.attacker.net` "wanted", so its address record in the additional section
    survived and was relayed to the stub — the unsolicited-record relay this
    module exists to stop, arriving through the allow-list rather than past it.
    """
    out: set[Name] = set()
    for rr in rrs:
        if rr.rtype not in _TARGET_TYPES:
            continue
        for attr in ("target", "exchange", "nsdname", "name"):
            v = getattr(rr.rdata, attr, None)
            if isinstance(v, Name):
                if v == rr.name or v.is_subdomain_of(rr.name):
                    out.add(v)
                break
    return out


def sanitize(resp: Message, qname: str) -> Sanitized:
    """Strip unsolicited records from `resp` in place. Returns what was removed."""
    dropped = Sanitized()
    q = resp.question
    try:
        owner = Name.from_text(qname) if qname else (q.name if q else None)
    except Exception:
        owner = q.name if q else None
    if owner is None:
        # No question and no caller-supplied name: nothing can be shown to be in
        # bailiwick for anything, so every record here is unsolicited. Returning
        # early instead would hand the whole authority and additional sections
        # straight through to the cache and the client.
        dropped.answers = len(resp.answers)
        dropped.authority = len(resp.authority)
        dropped.additional = len(resp.additional)
        resp.answers, resp.authority, resp.additional = [], [], []
        return dropped

    allowed = _chain(owner, resp.answers)
    kept_answers = [rr for rr in resp.answers if rr.name in allowed]
    dropped.answers = len(resp.answers) - len(kept_answers)
    resp.answers = kept_answers

    # Authority: the zone that answered, or proof there is no answer. Owned by
    # the question name or an ancestor of it.
    kept_auth = [rr for rr in resp.authority
                 if rr.name in allowed or _in_bailiwick(rr.name, owner)]
    dropped.authority = len(resp.authority) - len(kept_auth)
    resp.authority = kept_auth

    # Additional: only glue for something we actually kept.
    wanted = allowed | _targets(kept_answers) | _targets(kept_auth)
    kept_add = [rr for rr in resp.additional if rr.name in wanted]
    dropped.additional = len(resp.additional) - len(kept_add)
    resp.additional = kept_add
    return dropped
