"""Full DNSSEC chain-of-trust validation over a mock signed hierarchy.

Builds signed root -> "test" -> "example.test" zones (each with the child's DS
published + signed by the parent), then validates a leaf A record all the way up
to the root anchor. Proves the real chain logic with no network.
"""
from __future__ import annotations

import pytest

from trench.auth_zone import Zone
from trench.auth_zone.sign import sign_zone
from trench.resolver.dnssec import ValidationResult, Validator
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags

ROOT = Name.from_text(".")
TEST = Name.from_text("test.")
LEAF = Name.from_text("example.test.")


def _soa(origin):
    mname = Name((b"ns",) + origin.labels)
    rname = Name((b"admin",) + origin.labels)
    return R.SOA(mname, rname, 1, 7200, 3600, 1209600, 3600)


def build_hierarchy():
    # leaf
    leaf = Zone(LEAF)
    leaf.add(LEAF, Type.SOA, _soa(LEAF))
    leaf.add(LEAF, Type.A, R.A("93.184.216.34"))
    leaf_res = sign_zone(leaf)
    # tld "test" publishes DS(example.test)
    tld = Zone(TEST)
    tld.add(TEST, Type.SOA, _soa(TEST))
    tld.add(LEAF, Type.DS, leaf_res.ds)
    tld_res = sign_zone(tld)
    # root publishes DS(test)
    root = Zone(ROOT)
    root.add(ROOT, Type.SOA, _soa(ROOT))
    root.add(TEST, Type.DS, tld_res.ds)
    root_res = sign_zone(root)
    zones = {".": root, "test.": tld, "example.test.": leaf}
    return zones, [root_res.ds]   # root_res.ds = anchor (DS of root KSK)


def _msg_for(zone: Zone, owner: Name, rtype: int) -> Message:
    m = Message(id=0, flags=Flags.QR | Flags.AA)
    ttl = zone.ttl_of(owner, rtype)
    for rd in zone.records.get(owner, {}).get(rtype, []):
        m.answers.append(RR(owner, rtype, Class.IN, ttl, rd))
    sig = zone.rrsigs.get((owner, rtype))
    if sig is not None:
        m.answers.append(RR(owner, Type.RRSIG, Class.IN, ttl, sig))
    return m


def make_ask(zones):
    async def ask(name: Name, rtype: int) -> Message:
        key = name.to_text()
        if rtype == Type.DNSKEY:
            return _msg_for(zones[key], name, Type.DNSKEY)
        if rtype == Type.DS:
            parent = zones[name.parent().to_text()]
            return _msg_for(parent, name, Type.DS)
        return _msg_for(zones[key], name, rtype)
    return ask


@pytest.mark.asyncio
async def test_chain_secure():
    zones, anchors = build_hierarchy()
    v = Validator(make_ask(zones), anchors=anchors)
    leaf = zones["example.test."]
    rdatas = leaf.records[LEAF][Type.A]
    rrsig = leaf.rrsigs[(LEAF, Type.A)]
    result = await v.validate(LEAF, Type.A, rdatas, [rrsig])
    assert result == ValidationResult.SECURE


@pytest.mark.asyncio
async def test_chain_bogus_on_tamper():
    zones, anchors = build_hierarchy()
    v = Validator(make_ask(zones), anchors=anchors)
    leaf = zones["example.test."]
    rrsig = leaf.rrsigs[(LEAF, Type.A)]
    # tampered answer data -> signature must fail -> BOGUS
    result = await v.validate(LEAF, Type.A, [R.A("6.6.6.6")], [rrsig])
    assert result == ValidationResult.BOGUS


@pytest.mark.asyncio
async def test_chain_bogus_on_wrong_anchor():
    zones, _ = build_hierarchy()
    # wrong trust anchor (IANA default) -> root DNSKEY not anchored -> BOGUS
    v = Validator(make_ask(zones))   # uses real ROOT_ANCHORS, not our test root
    leaf = zones["example.test."]
    rdatas = leaf.records[LEAF][Type.A]
    rrsig = leaf.rrsigs[(LEAF, Type.A)]
    result = await v.validate(LEAF, Type.A, rdatas, [rrsig])
    assert result == ValidationResult.BOGUS


@pytest.mark.asyncio
async def test_missing_signatures_under_a_published_ds_are_bogus():
    """`test.` publishes a DS for `example.test.`, so the chain reaches this
    name securely and the data has to be signed. Answering INSECURE for an
    unsigned RRset would make stripping two records a complete bypass."""
    zones, anchors = build_hierarchy()
    v = Validator(make_ask(zones), anchors=anchors)
    result = await v.validate(LEAF, Type.A, [R.A("1.2.3.4")], [])  # no RRSIG
    assert result == ValidationResult.BOGUS


# --- recursive resolver wired to validate against the mock anchor ---
@pytest.mark.asyncio
async def test_recursive_sets_ad_when_secure():
    from trench.resolver.recursive import Recursive
    zones, anchors = build_hierarchy()

    async def transport(ip, query):
        q = query.question
        name, rtype = q.name, q.rtype
        if rtype == Type.DS:
            parent = zones.get(name.parent().to_text())
            return _msg_for(parent, name, Type.DS) if parent else Message(id=0, flags=Flags.QR)
        z = zones.get(name.to_text())
        if z is None:
            return Message(id=0, flags=Flags.QR | Flags.AA)
        return _msg_for(z, name, rtype)

    rec = Recursive(transport, root_hints=["10.0.0.1"], qmin=False,
                    validate=True, anchors=anchors)
    resp = await rec.resolve("example.test", Type.A)
    assert resp.ad is True                       # AD set => chain validated
    assert any(rr.rtype == Type.A for rr in resp.answers)


@pytest.mark.asyncio
async def test_recursive_servfail_on_bogus():
    from trench.resolver.recursive import Recursive
    zones, anchors = build_hierarchy()
    # corrupt the leaf A RRSIG so validation must fail
    leaf = zones["example.test."]
    bad = leaf.rrsigs[(LEAF, Type.A)]
    leaf.rrsigs[(LEAF, Type.A)] = R.RRSIG(**{**bad.__dict__,
                                             "signature": bytes(len(bad.signature))})

    async def transport(ip, query):
        q = query.question
        if q.rtype == Type.DS:
            parent = zones.get(q.name.parent().to_text())
            return _msg_for(parent, q.name, Type.DS) if parent else Message(id=0, flags=Flags.QR)
        z = zones.get(q.name.to_text())
        return _msg_for(z, q.name, q.rtype) if z else Message(id=0, flags=Flags.QR | Flags.AA)

    rec = Recursive(transport, root_hints=["10.0.0.1"], qmin=False,
                    validate=True, anchors=anchors)
    resp = await rec.resolve("example.test", Type.A)
    from trench.wire.rrtypes import Rcode
    assert resp.rcode == Rcode.SERVFAIL and not resp.answers


# --- CNAME chains: every hop is validated, not only the final name ---
VICTIM = Name.from_text("bank.test.")
EVIL = Name.from_text("evil.test.")


def _cname_hierarchy(victim_cname=False):
    """root -> test -> {bank.test, evil.test}, both signed and delegated."""
    zones = {}
    tld = Zone(TEST)
    tld.add(TEST, Type.SOA, _soa(TEST))
    for n, ip in ((VICTIM, "192.0.2.10"), (EVIL, "203.0.113.66")):
        z = Zone(n)
        z.add(n, Type.SOA, _soa(n))
        if n == VICTIM and victim_cname:
            z.add(n, Type.CNAME, R.CNAME(EVIL))
        else:
            z.add(n, Type.A, R.A(ip))
        tld.add(n, Type.DS, sign_zone(z).ds)
        zones[n.to_text()] = z
    tld_ds = sign_zone(tld).ds
    root = Zone(ROOT)
    root.add(ROOT, Type.SOA, _soa(ROOT))
    root.add(TEST, Type.DS, tld_ds)
    anchor = sign_zone(root).ds
    zones.update({".": root, "test.": tld})
    return zones, [anchor]


def _chain_transport(zones, forge=None):
    async def transport(ip, query):
        q = query.question
        if q.rtype == Type.DS:
            return _msg_for(zones[q.name.parent().to_text()], q.name, Type.DS)
        if forge is not None and q.name == VICTIM and q.rtype == Type.A:
            return forge()
        z = zones[q.name.to_text()]
        if q.rtype not in (Type.DNSKEY, Type.SOA) and z.records.get(q.name, {}).get(Type.CNAME):
            return _msg_for(z, q.name, Type.CNAME)
        return _msg_for(z, q.name, q.rtype)
    return transport


@pytest.mark.asyncio
async def test_forged_unsigned_cname_into_a_signed_zone_is_bogus():
    """An unsigned CNAME at a signed name must not reach the client — least
    of all with AD set because the zone it points into is validly signed."""
    from trench.resolver.recursive import Recursive
    from trench.wire.rrtypes import Rcode
    zones, anchors = _cname_hierarchy()

    def forge():
        m = Message(id=0, flags=Flags.QR | Flags.AA)
        m.answers.append(RR(VICTIM, Type.CNAME, Class.IN, 3600, R.CNAME(EVIL)))
        return m

    rec = Recursive(_chain_transport(zones, forge), root_hints=["10.0.0.1"],
                    qmin=False, validate=True, anchors=anchors)
    resp = await rec.resolve("bank.test", Type.A)
    assert resp.rcode == Rcode.SERVFAIL
    assert not resp.ad and not resp.answers


@pytest.mark.asyncio
async def test_signed_cname_chain_across_signed_zones_is_secure():
    from trench.resolver.recursive import Recursive
    zones, anchors = _cname_hierarchy(victim_cname=True)
    rec = Recursive(_chain_transport(zones), root_hints=["10.0.0.1"],
                    qmin=False, validate=True, anchors=anchors)
    resp = await rec.resolve("bank.test", Type.A)
    assert resp.ad is True
    assert [rr.rtype for rr in resp.answers if rr.rtype != Type.RRSIG] == [Type.CNAME, Type.A]

