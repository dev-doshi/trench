"""Authoritative answers a validating resolver can actually check.

RFC 4592 wildcard synthesis (closest encloser only, owner rewritten to the
query name), RFC 4035 / RFC 5155 denial proofs matched to the name asked for,
RFC 2308 negative TTLs, and a signer that leaves glue and delegation NS sets
unsigned. Every proof is run through the resolver's own checkers, so the two
halves of the DNSSEC loop are held to each other.
"""
from __future__ import annotations

import pytest

from trench.auth_zone import Zone
from trench.auth_zone.sign import sign_zone
from trench.resolver.dnssec import verify_rrset
from trench.resolver.dnssec.nsec import (
    Nsec3Set,
    nsec3_nodata,
    nsec3_nxdomain,
    nsec3_wildcard_expansion,
    nsec_nodata,
    nsec_nxdomain,
    nsec_wildcard_expansion,
    nsec_wildcard_nodata,
)
from trench.wire import Class, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode

ORIGIN = Name.from_text("example.com")


def n(text: str) -> Name:
    return Name.from_text(text)


def build() -> Zone:
    z = Zone(ORIGIN)
    # SOA TTL 3600, MINIMUM 300: negative answers must use the smaller.
    z.add(ORIGIN, Type.SOA, R.SOA(n("ns.example.com"), n("hostmaster.example.com"),
                                  1, 7200, 3600, 1209600, 300), 3600)
    z.add(ORIGIN, Type.NS, R.NS(n("ns.example.com")))
    z.add(n("ns.example.com"), Type.A, R.A("192.0.2.1"))
    z.add(n("www.example.com"), Type.A, R.A("192.0.2.2"))
    z.add(n("foo.example.com"), Type.TXT, R.TXT([b"foo"]))
    z.add(n("*.example.com"), Type.A, R.A("192.0.2.99"))
    z.add(n("a.b.example.com"), Type.A, R.A("192.0.2.3"))     # b.example.com is an ENT
    z.add(n("sub.example.com"), Type.NS, R.NS(n("ns.sub.example.com")))
    z.add(n("ns.sub.example.com"), Type.A, R.A("192.0.2.9"))  # glue
    return z


@pytest.fixture(params=["nsec", "nsec3"])
def signed(request):
    z = build()
    res = sign_zone(z, nsec3=request.param == "nsec3", nsec3_salt=b"\xab\xcd")
    return z, res.dnskey, request.param


def _nsecs(auth, rtype):
    return [(rr.name, rr.rdata) for rr in auth if rr.rtype == rtype]


def _all_signed(z, dnskey, rrs) -> None:
    """Every RRset in `rrs` carries an RRSIG that verifies."""
    sets: dict = {}
    for rr in rrs:
        if rr.rtype != Type.RRSIG:
            sets.setdefault((rr.name, rr.rtype), []).append(rr.rdata)
    for (owner, rtype), rds in sets.items():
        sigs = [rr.rdata for rr in rrs if rr.rtype == Type.RRSIG
                and rr.name == owner and rr.rdata.type_covered == rtype]
        assert sigs, f"{owner} {rtype} unsigned"
        signer_owner = owner
        if sigs[0].labels < len(owner):       # wildcard expansion
            signer_owner = Name((b"*",) + owner.labels[len(owner) - sigs[0].labels:])
        assert verify_rrset(signer_owner, rtype, Class.IN, rds, sigs[0], dnskey), \
            f"{owner} {rtype} bad signature"


# --- RFC 4592 ---------------------------------------------------------------

def test_a_wildcard_answer_is_owned_by_the_query_name():
    ans = build().lookup(n("x.example.com"), Type.A)
    assert [rr.name for rr in ans.answers] == [n("x.example.com")]


def test_a_wildcard_does_not_reach_past_an_existing_name():
    """`foo.example.com` exists, so it is the closest encloser of
    `x.foo.example.com`, and `*.foo.example.com` does not exist."""
    ans = build().lookup(n("x.foo.example.com"), Type.A)
    assert ans.rcode == Rcode.NXDOMAIN and ans.answers == []


def test_a_wildcard_does_not_answer_below_an_empty_non_terminal():
    ans = build().lookup(n("x.b.example.com"), Type.A)
    assert ans.rcode == Rcode.NXDOMAIN


def test_an_empty_non_terminal_is_not_wildcard_synthesized():
    ans = build().lookup(n("b.example.com"), Type.A)
    assert ans.rcode == Rcode.NOERROR and ans.answers == []


def test_negative_answers_use_the_soa_minimum():
    for q in ("nope.foo.example.com", "www.example.com"):
        ans = build().lookup(n(q), Type.MX)
        soa = [rr for rr in ans.authority if rr.rtype == Type.SOA]
        assert soa and soa[0].ttl == 300, q


# --- denial proofs ----------------------------------------------------------

def _check(z, dnskey, flavor, qname, qtype, verdict):
    ans = z.lookup(n(qname), qtype, do=True)
    _all_signed(z, dnskey, ans.answers)
    _all_signed(z, dnskey, ans.authority)
    if flavor == "nsec":
        nsecs = _nsecs(ans.authority, Type.NSEC)
        return ans, verdict["nsec"](n(qname), nsecs)
    s = Nsec3Set(_nsecs(ans.authority, Type.NSEC3), ORIGIN)
    assert s.usable
    return ans, verdict["nsec3"](n(qname), s)


def test_nxdomain_is_proven(signed):
    z, key, flavor = signed
    ans, ok = _check(z, key, flavor, "x.foo.example.com", Type.A, {
        "nsec": nsec_nxdomain, "nsec3": nsec3_nxdomain})
    assert ans.rcode == Rcode.NXDOMAIN and ok


def test_nodata_is_proven(signed):
    z, key, flavor = signed
    ans, ok = _check(z, key, flavor, "www.example.com", Type.MX, {
        "nsec": lambda q, s: nsec_nodata(q, Type.MX, s),
        "nsec3": lambda q, s: nsec3_nodata(q, Type.MX, s)})
    assert ans.rcode == Rcode.NOERROR and not ans.answers and ok


def test_nodata_at_an_empty_non_terminal_is_proven(signed):
    """RFC 5155 §7.1 needs an NSEC3 at the ENT; with NSEC the covering record's
    next name sits below it."""
    from trench.resolver.dnssec.nsec import nsec_covers
    z, key, flavor = signed
    ans, ok = _check(z, key, flavor, "b.example.com", Type.A, {
        "nsec": lambda q, s: any(nsec_covers(o, rd.next_name, q)
                                 and rd.next_name.is_subdomain_of(q) for o, rd in s),
        "nsec3": lambda q, s: nsec3_nodata(q, Type.A, s)})
    assert ans.rcode == Rcode.NOERROR and ok


def test_a_wildcard_answer_carries_proof_the_name_is_absent(signed):
    z, key, flavor = signed
    wild = n("*.example.com")
    ans, ok = _check(z, key, flavor, "x.example.com", Type.A, {
        "nsec": lambda q, s: nsec_wildcard_expansion(q, wild, s),
        "nsec3": lambda q, s: nsec3_wildcard_expansion(q, wild, s)})
    assert [rr.rdata.address for rr in ans.answers if rr.rtype == Type.A] == ["192.0.2.99"]
    assert ok


def test_wildcard_nodata_is_proven(signed):
    z, key, flavor = signed
    ans, ok = _check(z, key, flavor, "x.example.com", Type.MX, {
        "nsec": lambda q, s: nsec_wildcard_nodata(q, Type.MX, s),
        "nsec3": lambda q, s: nsec3_nodata(q, Type.MX, s)})
    assert ans.rcode == Rcode.NOERROR and not ans.answers and ok


# --- signer scope -----------------------------------------------------------

def test_glue_and_delegation_ns_are_not_signed(signed):
    z, _key, _flavor = signed
    assert (n("sub.example.com"), Type.NS) not in z.rrsigs
    assert (n("ns.sub.example.com"), Type.A) not in z.rrsigs
    assert (n("ns.example.com"), Type.A) in z.rrsigs          # in-zone, ours
    assert Type.NSEC not in z.records.get(n("ns.sub.example.com"), {})


def test_denial_records_use_the_negative_ttl(signed):
    z, _key, flavor = signed
    rtype = Type.NSEC if flavor == "nsec" else Type.NSEC3
    ttls = {z.ttl_of(o, rtype) for o, node in z.records.items() if rtype in node}
    assert ttls == {300}
