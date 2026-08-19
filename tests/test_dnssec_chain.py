"""Full DNSSEC chain-of-trust validation over a mock signed hierarchy.

Builds signed root -> "test" -> "example.test" zones (each with the child's DS
published + signed by the parent), then validates a leaf A record all the way up
to the root anchor. Proves the real chain logic with no network.
"""
from __future__ import annotations

import pytest

from dnsguard.auth_zone import Zone
from dnsguard.auth_zone.sign import sign_zone
from dnsguard.resolver.dnssec import ValidationResult, Validator
from dnsguard.wire import RR, Class, Message, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Flags

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
    from dnsguard.resolver.recursive import Recursive
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
    from dnsguard.resolver.recursive import Recursive
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
    from dnsguard.wire.rrtypes import Rcode
    assert resp.rcode == Rcode.SERVFAIL and not resp.answers
