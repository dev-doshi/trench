"""Authoritative zones: lookup semantics, zonefile parsing, DNSSEC sign↔validate."""
from __future__ import annotations

from dnsguard.auth_zone import Zone, ZoneStore
from dnsguard.auth_zone.sign import sign_zone
from dnsguard.auth_zone.update import apply_update
from dnsguard.auth_zone.zonefile import parse_zonefile
from dnsguard.resolver.dnssec import verify_rrset
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Flags, Opcode, Rcode

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


# ------------------------------------------------- shapes that used to break
def _zone_with(origin_text, records):
    from dnsguard.wire import Class  # noqa: F401
    z = Zone(Name.from_text(origin_text))
    z.add(Name.from_text(origin_text), Type.SOA,
          R.SOA(Name.from_text("ns." + origin_text),
                Name.from_text("hm." + origin_text), 1, 2, 3, 4, 300))
    for name, rtype, rd in records:
        z.add(Name.from_text(name), rtype, rd)
    return z


def test_a_cname_loop_does_not_blow_the_stack():
    """`a -> b -> a` is loadable from a zonefile, a dynamic UPDATE, or an
    inbound AXFR. Chased recursively it turned one 30-byte query into a
    RecursionError per packet."""
    z = _zone_with("example.com.", [
        ("a.example.com.", Type.CNAME, R.CNAME(Name.from_text("b.example.com."))),
        ("b.example.com.", Type.CNAME, R.CNAME(Name.from_text("a.example.com."))),
    ])
    ans = z.lookup(Name.from_text("a.example.com."), Type.A)
    assert len(ans.answers) <= Zone.MAX_CNAME_CHAIN

    z2 = _zone_with("example.com.", [
        ("self.example.com.", Type.CNAME, R.CNAME(Name.from_text("self.example.com."))),
    ])
    assert len(z2.lookup(Name.from_text("self.example.com."), Type.A).answers) <= 2


def test_a_delegated_child_gets_a_referral_not_an_authoritative_nxdomain():
    """The parent holds no records for the child, but it must not answer for
    it: an AA=1 NXDOMAIN here denies the whole delegated zone to every client."""
    z = _zone_with("example.com.", [
        ("sub.example.com.", Type.NS, R.NS(Name.from_text("ns1.other.net."))),
    ])
    ans = z.lookup(Name.from_text("www.sub.example.com."), Type.A)
    assert ans.rcode == Rcode.NOERROR
    assert ans.aa is False
    assert [rr.rtype for rr in ans.authority] == [Type.NS]


def test_wildcards_synthesize_from_the_closest_encloser():
    """RFC 4592. Trying only the immediate parent left `*.example.com` covering
    `x.example.com` and returning NXDOMAIN for anything deeper."""
    z = _zone_with("example.com.", [
        ("*.example.com.", Type.A, R.A("1.2.3.4")),
    ])
    for qname in ("x.example.com.", "deep.sub.example.com."):
        ans = z.lookup(Name.from_text(qname), Type.A)
        assert ans.rcode == Rcode.NOERROR, qname
        assert [rr.rdata.address for rr in ans.answers] == ["1.2.3.4"], qname


def test_an_empty_non_terminal_is_nodata_not_nxdomain():
    z = _zone_with("example.com.", [
        ("a.b.example.com.", Type.A, R.A("1.2.3.4")),
    ])
    ans = z.lookup(Name.from_text("b.example.com."), Type.A)
    assert ans.rcode == Rcode.NOERROR and not ans.answers


def _update_msg(origin, records):
    """An UPDATE message carrying `records` in the update (authority) section."""
    msg = Message(id=9)
    msg.flags |= (Opcode.UPDATE << Flags.OPCODE_SHIFT)
    msg.questions.append(Question(Name.from_text(origin), Type.SOA, Class.IN))
    msg.authority.extend(records)
    return msg


def test_deleting_the_apex_soa_is_ignored_rather_than_bricking_the_zone():
    """RFC 2136 §3.4.2.4. The class-NONE branch had none of the guards the
    class-ANY branches have: the delete was applied, then `_bump_serial` raised
    on the missing SOA — no reply, no journal entry, no NOTIFY, and SERVFAIL for
    every update afterwards."""
    zone = build_zone()
    before = zone.soa.serial
    rr = RR(zone.origin, Type.SOA, Class.NONE, 0, zone.records[zone.origin][Type.SOA][0])
    assert apply_update(zone, _update_msg("example.com.", [rr])) == Rcode.NOERROR
    assert zone.soa is not None
    assert zone.soa.serial == before          # nothing changed, so no bump either


def test_the_last_apex_ns_survives_an_individual_delete():
    zone = build_zone()
    ns = zone.records[zone.origin][Type.NS]
    while len(zone.records[zone.origin][Type.NS]) > 1:
        zone.records[zone.origin][Type.NS].pop()
    rr = RR(zone.origin, Type.NS, Class.NONE, 0, ns[0])
    assert apply_update(zone, _update_msg("example.com.", [rr])) == Rcode.NOERROR
    assert zone.records[zone.origin][Type.NS]


def test_an_update_record_of_a_foreign_class_is_formerr():
    zone = build_zone()
    rr = RR(Name.from_text("new.example.com."), Type.A, Class.CH, 60, R.A("10.0.0.9"))
    assert apply_update(zone, _update_msg("example.com.", [rr])) == Rcode.FORMERR
    assert Name.from_text("new.example.com.") not in zone.records
