"""Regression tests for RFC-conformance bugs found in an audit of the DNSSEC
validator, the recursive resolver, the encrypted upstreams and the DNR option.

Each test fails against the code as it was before its fix.
"""
from __future__ import annotations

import pytest
from test_dnssec_chain import LEAF, _msg_for, build_hierarchy

from trench.auth_zone import Zone
from trench.auth_zone.sign import sign_zone
from trench.auth_zone.sign.signer import encode_type_bitmap
from trench.resolver.dnssec.keys import key_tag
from trench.resolver.dnssec.nsec import (
    Nsec3Set,
    _closest_encloser,
    nsec3_b32,
    nsec3_hash,
    nsec3_nxdomain,
    nsec_nxdomain,
)
from trench.resolver.dnssec.validate import _signed_data, verify_rrset
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Rcode


def n(s: str) -> Name:
    return Name.from_text(s)


# --------------------------------------------------- RFC 5155 §2: algorithm 7
def test_rsasha1_nsec3_sha1_signatures_verify():
    """Algorithm 7 is RSA/SHA-1 under another number. It was missing from the
    hash table, so every zone signed with it validated BOGUS."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = priv.public_key().public_numbers()
    e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    mod = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    dnskey = R.DNSKEY(flags=257, protocol=3, algorithm=7,
                      public_key=bytes([len(e)]) + e + mod)
    owner = n("example.test.")
    rdatas = [R.A("192.0.2.1")]
    unsigned = R.RRSIG(type_covered=Type.A, algorithm=7, labels=2,
                       original_ttl=300, expiration=2_000_000_000,
                       inception=1_000_000_000, key_tag=key_tag(dnskey),
                       signer=owner, signature=b"")
    data = _signed_data(owner, Type.A, 1, unsigned, rdatas)
    sig = priv.sign(data, padding.PKCS1v15(), hashes.SHA1())
    rrsig = R.RRSIG(**{**unsigned.__dict__, "signature": sig})
    assert verify_rrset(owner, Type.A, 1, rdatas, rrsig, dnskey, now=1_500_000_000)


# ------------------------------------ RFC 6840 §4.1: ancestor delegation NSEC
def test_a_delegation_nsec_cannot_deny_names_inside_the_child():
    """The parent's NSEC for `child.example.test` sorts every name under the
    child into its gap. Those names are the child's; the parent's record says
    nothing about them, and accepting it forges NXDOMAIN for the whole zone."""
    child = n("child.example.test.")
    deleg = R.NSEC(next_name=n("d.example.test."),
                   type_bitmap=encode_type_bitmap({Type.NS, Type.DS, Type.RRSIG,
                                                   Type.NSEC}))
    assert not nsec_nxdomain(n("www.child.example.test."), [(child, deleg)])


def test_a_dname_nsec_cannot_deny_names_beneath_it():
    owner = n("alias.example.test.")
    rd = R.NSEC(next_name=n("b.example.test."),
                type_bitmap=encode_type_bitmap({Type.DNAME, Type.RRSIG, Type.NSEC}))
    assert not nsec_nxdomain(n("x.alias.example.test."), [(owner, rd)])


def test_an_ordinary_nsec_still_denies_names_beneath_it():
    """The rule is about zone cuts only: a plain name with no children really
    does prove its descendants absent."""
    owner = n("a.example.test.")
    rd = R.NSEC(next_name=n("b.example.test."),
                type_bitmap=encode_type_bitmap({Type.A, Type.RRSIG, Type.NSEC}))
    apex = R.NSEC(next_name=owner,
                  type_bitmap=encode_type_bitmap({Type.SOA, Type.NS, Type.RRSIG,
                                                  Type.NSEC}))
    assert nsec_nxdomain(n("x.a.example.test."),
                         [(owner, rd), (n("example.test."), apex)])


def _chain(zone_text: str, present: dict[str, set[int]]) -> Nsec3Set:
    raw = sorted((nsec3_hash(n(name), b"", 0), types) for name, types in present.items())
    items = []
    for i, (h, types) in enumerate(raw):
        items.append((n(f"{nsec3_b32(h)}.{zone_text}"),
                      R.NSEC3(hash_algorithm=1, flags=0, iterations=0, salt=b"",
                              next_hashed=raw[(i + 1) % len(raw)][0],
                              type_bitmap=encode_type_bitmap(types))))
    return Nsec3Set(items, n(zone_text))


def test_an_nsec3_delegation_is_not_a_closest_encloser():
    """RFC 5155 §8.3. The NSEC3 form of the same replay."""
    s = _chain("example.test.", {
        "example.test.": {Type.SOA, Type.NS, Type.DNSKEY, Type.NSEC3PARAM},
        "child.example.test.": {Type.NS, Type.DS},
    })
    q = n("www.child.example.test.")
    assert _closest_encloser(q, s) is None
    assert not nsec3_nxdomain(q, s)


# ---------------------------------------- RFC 4035 §3.2.3: AD covers every RRset
WWW = n("www.example.test.")


def _cname_world(*, sign_cname: bool):
    zones, anchors = build_hierarchy()
    leaf: Zone = zones["example.test."]
    if sign_cname:
        # Re-sign the leaf with the CNAME in it, then republish its DS above.
        fresh = Zone(LEAF)
        for owner, by_type in leaf.records.items():
            for rtype, rds in by_type.items():
                if rtype in (Type.SOA, Type.A):
                    for rd in rds:
                        fresh.add(owner, rtype, rd)
        fresh.add(WWW, Type.CNAME, R.CNAME(LEAF))
        res = sign_zone(fresh)
        zones["example.test."] = fresh
        tld = zones["test."]
        tld_fresh = Zone(tld.origin)
        tld_fresh.add(tld.origin, Type.SOA, tld.records[tld.origin][Type.SOA][0])
        tld_fresh.add(LEAF, Type.DS, res.ds)
        tres = sign_zone(tld_fresh)
        zones["test."] = tld_fresh
        root = zones["."]
        root_fresh = Zone(root.origin)
        root_fresh.add(root.origin, Type.SOA, root.records[root.origin][Type.SOA][0])
        root_fresh.add(n("test."), Type.DS, tres.ds)
        rres = sign_zone(root_fresh)
        zones["."] = root_fresh
        anchors = [rres.ds]
    return zones, anchors


def _transport(zones, *, sign_cname: bool):
    async def transport(ip, query):
        q = query.question
        if q.rtype == Type.DS:
            parent = zones.get(q.name.parent().to_text())
            return (_msg_for(parent, q.name, Type.DS) if parent
                    else Message(id=0, flags=Flags.QR))
        if q.name == WWW:
            leaf = zones["example.test."]
            if sign_cname:
                return _msg_for(leaf, WWW, Type.CNAME)
            # An off-path spoof: a CNAME the zone never signed.
            m = Message(id=0, flags=Flags.QR | Flags.AA)
            m.answers.append(RR(WWW, Type.CNAME, Class.IN, 300, R.CNAME(LEAF)))
            return m
        z = zones.get(q.name.to_text())
        return (_msg_for(z, q.name, q.rtype) if z
                else Message(id=0, flags=Flags.QR | Flags.AA))
    return transport


@pytest.mark.asyncio
async def test_an_unsigned_cname_in_a_signed_zone_is_bogus_not_authenticated():
    """Only the final RRset used to be validated, so a forged CNAME whose target
    validated came back with AD set."""
    from trench.resolver.recursive import Recursive
    zones, anchors = _cname_world(sign_cname=False)
    rec = Recursive(_transport(zones, sign_cname=False), root_hints=["10.0.0.1"],
                    qmin=False, validate=True, anchors=anchors)
    resp = await rec.resolve("www.example.test", Type.A)
    assert not resp.ad
    assert resp.rcode == Rcode.SERVFAIL


@pytest.mark.asyncio
async def test_a_signed_cname_chain_is_authenticated():
    from trench.resolver.recursive import Recursive
    zones, anchors = _cname_world(sign_cname=True)
    rec = Recursive(_transport(zones, sign_cname=True), root_hints=["10.0.0.1"],
                    qmin=False, validate=True, anchors=anchors)
    resp = await rec.resolve("www.example.test", Type.A)
    assert resp.rcode == Rcode.NOERROR
    assert resp.ad is True
    assert {rr.rtype for rr in resp.answers} >= {Type.CNAME, Type.A}


# -------------------------------------- RFC 9250 §4.2.1 / RFC 8484 §4.1: ID 0
@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["quic", "https"])
async def test_encrypted_upstreams_send_message_id_zero(scheme):
    from trench.transport.upstream import Upstream, parse_upstream
    from trench.wire import Question

    up = Upstream(parse_upstream(f"{scheme}://dns.example.test"))
    seen = []

    async def fake(wire: bytes) -> bytes:
        q = Message.parse(wire)
        seen.append(q.id)
        return q.reply(Rcode.NOERROR).to_wire()

    setattr(up, "_doq" if scheme == "quic" else "_doh", fake)
    query = Message(id=0x1234)
    query.questions.append(Question(n("example.test."), Type.A, Class.IN))
    resp = await up.query(query)
    assert seen == [0]
    assert resp.id == 0x1234            # the client still gets its own id back


# ------------------------------------------------ RFC 3396: long DHCP options
def test_a_dhcp_option_longer_than_255_octets_is_split_and_rejoined():
    """The DNR option grows with each endpoint and the hostname; past 255
    octets `to_wire` raised and the lease was never sent."""
    from trench.dhcp.v4 import OPT_DNR, DhcpPacket

    value = bytes(range(256)) * 2 + b"tail"
    p = DhcpPacket(op=2, xid=1, chaddr=b"\x02" * 6, options={OPT_DNR: value})
    back = DhcpPacket.parse(p.to_wire())
    assert back.options[OPT_DNR] == value
