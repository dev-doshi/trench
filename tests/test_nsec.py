"""NSEC/NSEC3 denial-of-existence: ordering, bitmaps, and authenticated denial."""
from __future__ import annotations

import pytest

from trench.auth_zone import Zone
from trench.auth_zone.sign import sign_zone
from trench.auth_zone.sign.signer import encode_type_bitmap
from trench.resolver.dnssec import ValidationResult, Validator
from trench.resolver.dnssec.nsec import (
    bitmap_has,
    name_lt,
    nsec_covers,
    nsec_nodata,
    nsec_nxdomain,
)
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Rcode

ROOT = Name.from_text(".")


# --- pure logic ---
def test_name_ordering_and_covers():
    a, b, c = Name.from_text("a."), Name.from_text("b."), Name.from_text("c.")
    assert name_lt(a, b) and name_lt(b, c)
    assert nsec_covers(a, c, b)             # a < b < c
    assert not nsec_covers(a, c, c)         # next is exclusive
    assert nsec_covers(c, a, Name.from_text("z."))  # wrap-around past apex


def test_bitmap_has():
    bm = encode_type_bitmap({Type.A, Type.RRSIG, Type.NSEC})
    assert bitmap_has(bm, Type.A) and bitmap_has(bm, Type.NSEC)
    assert not bitmap_has(bm, Type.MX) and not bitmap_has(bm, Type.AAAA)


def test_nsec_denial_logic():
    a = Name.from_text("a.")
    b = Name.from_text("b.")
    bitmap = encode_type_bitmap({Type.A, Type.RRSIG, Type.NSEC})
    gap = R.NSEC(next_name=Name.from_text("c."), type_bitmap=bitmap)
    # the apex NSEC covers "*.", which is what rules out a wildcard answer
    apex = R.NSEC(next_name=a, type_bitmap=bitmap)
    both = [(ROOT, apex), (a, gap)]
    # NXDOMAIN: b is covered by the a->c gap, and no wildcard could have answered
    assert nsec_nxdomain(b, both)
    # the covering record alone proves only that the name is absent, which a
    # wildcard would make irrelevant -- not enough for NXDOMAIN
    assert not nsec_nxdomain(b, [(a, gap)])
    # NODATA: a exists but has no MX
    assert nsec_nodata(a, Type.MX, [(a, gap)])
    assert not nsec_nodata(a, Type.A, [(a, gap)])
    # not covered -> no proof
    assert not nsec_nxdomain(Name.from_text("zz."), both)


# --- full crypto integration ---
def _signed_root_with(names):
    z = Zone(ROOT)
    z.add(ROOT, Type.SOA, R.SOA(Name.from_text("ns."), Name.from_text("admin."),
                                1, 7200, 3600, 1209600, 3600))
    for n in names:
        z.add(Name.from_text(n), Type.A, R.A("1.2.3.4"))
    res = sign_zone(z)
    return z, [res.ds]


def _ask_for(zone):
    async def ask(name, rtype):
        m = Message(id=0, flags=Flags.QR | Flags.AA)
        ttl = zone.ttl_of(name, rtype)
        for rd in zone.records.get(name, {}).get(rtype, []):
            m.answers.append(RR(name, rtype, Class.IN, ttl, rd))
        sig = zone.rrsigs.get((name, rtype))
        if sig is not None:
            m.answers.append(RR(name, Type.RRSIG, Class.IN, ttl, sig))
        return m
    return ask


def _nsec_authority(zone, owner_name):
    owner = Name.from_text(owner_name)
    rd = zone.records[owner][Type.NSEC][0]
    sig = zone.rrsigs[(owner, Type.NSEC)]
    return [RR(owner, Type.NSEC, Class.IN, 3600, rd),
            RR(owner, Type.RRSIG, Class.IN, 3600, sig)]


@pytest.mark.asyncio
async def test_authenticated_nxdomain():
    zone, anchors = _signed_root_with(["a.", "c."])
    v = Validator(_ask_for(zone), anchors=anchors)
    # the NSEC at "a." (next "c.") covers nonexistent "b."; the apex NSEC
    # covers "*." and so rules out a wildcard having answered for it
    auth = _nsec_authority(zone, ".") + _nsec_authority(zone, "a.")
    assert await v.validate_denial(Name.from_text("b."), Type.A, auth,
                                   Rcode.NXDOMAIN) == ValidationResult.SECURE


@pytest.mark.asyncio
async def test_authenticated_nodata():
    zone, anchors = _signed_root_with(["a.", "c."])
    v = Validator(_ask_for(zone), anchors=anchors)
    auth = _nsec_authority(zone, "a.")            # "a." exists with A but no MX
    assert await v.validate_denial(Name.from_text("a."), Type.MX, auth) == ValidationResult.SECURE


@pytest.mark.asyncio
async def test_denial_bogus_when_not_covered():
    zone, anchors = _signed_root_with(["a.", "c."])
    v = Validator(_ask_for(zone), anchors=anchors)
    auth = _nsec_authority(zone, "a.")            # only proves the a->c gap
    # "z." is NOT covered by that NSEC -> denial unproven -> BOGUS
    assert await v.validate_denial(Name.from_text("z."), Type.A, auth,
                                   Rcode.NXDOMAIN) == ValidationResult.BOGUS


@pytest.mark.asyncio
async def test_a_denial_with_no_proof_at_all_is_bogus():
    """The zone is signed and anchored, so silence is not an insecure zone —
    it is a proof someone removed."""
    zone, anchors = _signed_root_with(["a."])
    v = Validator(_ask_for(zone), anchors=anchors)
    assert await v.validate_denial(Name.from_text("b."), Type.A, [],
                                   Rcode.NXDOMAIN) == ValidationResult.BOGUS
