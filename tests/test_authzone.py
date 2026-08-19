"""Authoritative zones: lookup semantics, zonefile parsing, DNSSEC sign↔validate."""
from __future__ import annotations

from dnsguard.auth_zone import Zone, ZoneStore
from dnsguard.auth_zone.sign import sign_zone
from dnsguard.auth_zone.zonefile import parse_zonefile
from dnsguard.resolver.dnssec import verify_rrset
from dnsguard.wire import Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode

ORIGIN = Name.from_text("example.com")


def build_zone() -> Zone:
    z = Zone(ORIGIN)
    z.add(ORIGIN, Type.SOA, R.SOA(Name.from_text("ns.example.com"),
                                  Name.from_text("hostmaster.example.com"),
                                  2024010101, 7200, 3600, 1209600, 3600))
    z.add(ORIGIN, Type.NS, R.NS(Name.from_text("ns.example.com")))
    z.add(ORIGIN, Type.A, R.A("93.184.216.34"))
    z.add(Name.from_text("www.example.com"), Type.A, R.A("93.184.216.34"))
    z.add(Name.from_text("alias.example.com"), Type.CNAME, R.CNAME(Name.from_text("www.example.com")))
    z.add(Name.from_text("*.example.com"), Type.A, R.A("10.0.0.99"))
    return z


def test_lookup_exact_and_nodata():
    z = build_zone()
    a = z.lookup(Name.from_text("www.example.com"), Type.A)
    assert a.rcode == Rcode.NOERROR and a.answers[0].rdata.to_text() == "93.184.216.34"
    nodata = z.lookup(Name.from_text("www.example.com"), Type.MX)
    assert nodata.rcode == Rcode.NOERROR and not nodata.answers
    assert any(rr.rtype == Type.SOA for rr in nodata.authority)


def test_lookup_cname_chase():
    z = build_zone()
    a = z.lookup(Name.from_text("alias.example.com"), Type.A)
    kinds = [(rr.rtype, rr.rdata.to_text()) for rr in a.answers]
    assert (Type.CNAME, "www.example.com.") in kinds
    assert (Type.A, "93.184.216.34") in kinds


def test_lookup_wildcard():
    z = build_zone()
    a = z.lookup(Name.from_text("anything.example.com"), Type.A)
    assert a.answers[0].rdata.to_text() == "10.0.0.99"


def test_lookup_nxdomain():
    z = Zone(ORIGIN)
    z.add(ORIGIN, Type.SOA, R.SOA(Name.from_text("ns.example.com"),
                                  Name.from_text("h.example.com"), 1, 1, 1, 1, 1))
    z.add(ORIGIN, Type.A, R.A("1.1.1.1"))
    a = z.lookup(Name.from_text("missing.example.com"), Type.A)
    assert a.rcode == Rcode.NXDOMAIN
    assert any(rr.rtype == Type.SOA for rr in a.authority)


def test_zonestore_resolve():
    store = ZoneStore()
    store.add(build_zone())
    q = Message(id=1)
    q.questions.append(Question(Name.from_text("www.example.com"), Type.A, Class.IN))
    resp = store.resolve(q)
    assert resp is not None and resp.aa and resp.answers[0].rdata.to_text() == "93.184.216.34"
    # not authoritative for other names
    q2 = Message(id=2)
    q2.questions.append(Question(Name.from_text("google.com"), Type.A, Class.IN))
    assert store.resolve(q2) is None


def test_zonefile_parse():
    text = """
$ORIGIN example.com.
$TTL 3600
@   IN SOA ns.example.com. admin.example.com. (
        2024010101 7200 3600 1209600 3600 )
@       IN NS    ns.example.com.
@       IN A     93.184.216.34
www     IN A     93.184.216.34
mail    IN MX    10 mail.example.com.
txt     IN TXT   "hello world"
"""
    z = parse_zonefile(text, "example.com.")
    assert z.soa is not None and z.soa.serial == 2024010101
    a = z.lookup(Name.from_text("www.example.com"), Type.A)
    assert a.answers[0].rdata.to_text() == "93.184.216.34"
    mx = z.lookup(Name.from_text("mail.example.com"), Type.MX)
    assert mx.answers[0].rdata.preference == 10


def test_dnssec_sign_validate_loop():
    z = build_zone()
    result = sign_zone(z)
    dnskey = result.dnskey
    # every signed RRset must validate against the zone DNSKEY
    checks = 0
    for (name, rtype), rrsig in z.rrsigs.items():
        if rtype == Type.RRSIG:
            continue
        rdatas = z.records[name][rtype]
        assert verify_rrset(name, rtype, Class.IN, rdatas, rrsig, dnskey), \
            f"signature failed for {name.to_text()} type {rtype}"
        checks += 1
    assert checks >= 4  # SOA, NS, A, www A, NSEC, DNSKEY...
    # DS matches the DNSKEY
    from dnsguard.resolver.dnssec import ds_digest
    assert result.ds.digest == ds_digest(ORIGIN, dnskey, 2)


def test_dnssec_signed_response_includes_rrsig():
    z = build_zone()
    sign_zone(z)
    a = z.lookup(Name.from_text("www.example.com"), Type.A, do=True)
    assert any(rr.rtype == Type.RRSIG for rr in a.answers)
