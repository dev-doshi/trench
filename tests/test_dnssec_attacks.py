"""Adversarial DNSSEC validation tests.

Every test here is an attacker with a specific capability, and the assertion is
what the validator must refuse. They are written against a real signed
hierarchy — root -> test -> {example.test, evil.test, plain.test} — built and
signed with this project's own signer, so the signatures are genuine and the
only thing being tested is the validator's judgement.

The capabilities modelled are, in rough order of severity:

  * owning some other signed domain (`evil.test`) and signing whatever you like
  * being on-path: deleting records from a response
  * being a signed zone that would rather not be (denying your own DS)
  * being a zone that wants to spend the resolver's CPU
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from trench.auth_zone import Zone
from trench.auth_zone.sign import sign_zone
from trench.resolver.dnssec import ValidationResult, Validator
from trench.resolver.dnssec.validate import _signed_data
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Rcode

ROOT = Name.from_text(".")
TEST = Name.from_text("test.")
GOOD = Name.from_text("example.test.")
EVIL = Name.from_text("evil.test.")
PLAIN = Name.from_text("plain.test.")           # delegated but unsigned


def _soa(origin: Name) -> R.SOA:
    return R.SOA(Name((b"ns",) + origin.labels), Name((b"admin",) + origin.labels),
                 1, 7200, 3600, 1209600, 3600)


class World:
    """A signed hierarchy plus the `ask` callback a Validator drives it with."""

    def __init__(self, *, nsec3: bool = False, nsec3_iterations: int = 0,
                 nonzone_key: bool = False):
        self.zones: dict[str, Zone] = {}
        self.keytags: dict[str, int] = {}
        self.privkeys: dict[str, object] = {}
        self.drop: set[tuple[str, int]] = set()      # (zone_text, rtype) to censor
        self.asked: list[tuple[str, int]] = []
        sign = {"nsec3": nsec3, "nsec3_iterations": nsec3_iterations}

        good = Zone(GOOD)
        good.add(GOOD, Type.SOA, _soa(GOOD))
        good.add(GOOD, Type.NS, R.NS(Name.from_text("ns.example.test.")))
        good.add(GOOD, Type.A, R.A("93.184.216.34"))
        good.add(Name.from_text("www.example.test."), Type.A, R.A("93.184.216.35"))
        good.add(Name.from_text("wild.example.test."), Type.A, R.A("10.9.9.1"))
        good.add(Name.from_text("*.wild.example.test."), Type.A, R.A("10.9.9.9"))
        # a name at the same depth as a wildcard expansion, which therefore
        # exists and cannot be denied
        good.add(Name.from_text("real.wild.example.test."), Type.A, R.A("10.1.1.1"))
        if nonzone_key:
            # A second key the zone really does publish, with the ZONE flag
            # clear. It is inside the signed DNSKEY RRset, so it is authentic —
            # it is simply not a key that may sign zone data.
            self.nonzone_priv = ec.generate_private_key(ec.SECP256R1())
            nums = self.nonzone_priv.public_key().public_numbers()
            self.nonzone_key = R.DNSKEY(
                flags=0, protocol=3, algorithm=13,
                public_key=nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big"))
            good.add(GOOD, Type.DNSKEY, self.nonzone_key, 3600)
        good_res = sign_zone(good, **sign)

        evil = Zone(EVIL)
        evil.add(EVIL, Type.SOA, _soa(EVIL))
        evil.add(EVIL, Type.A, R.A("6.6.6.6"))
        evil_res = sign_zone(evil, **sign)

        tld = Zone(TEST)
        tld.add(TEST, Type.SOA, _soa(TEST))
        tld.add(TEST, Type.NS, R.NS(Name.from_text("ns.test.")))
        tld.add(GOOD, Type.DS, good_res.ds)
        tld.add(EVIL, Type.DS, evil_res.ds)
        # plain.test is delegated but has no DS: a genuine insecure delegation.
        tld.add(PLAIN, Type.NS, R.NS(Name.from_text("ns.plain.test.")))
        tld_res = sign_zone(tld, **sign)

        root = Zone(ROOT)
        root.add(ROOT, Type.SOA, _soa(ROOT))
        root.add(ROOT, Type.NS, R.NS(Name.from_text("a.root-servers.net.")))
        root.add(TEST, Type.DS, tld_res.ds)
        root_res = sign_zone(root, **sign)

        # plain.test itself is unsigned
        plain = Zone(PLAIN)
        plain.add(PLAIN, Type.SOA, _soa(PLAIN))
        plain.add(PLAIN, Type.A, R.A("192.0.2.1"))

        self.zones = {".": root, "test.": tld, "example.test.": good,
                      "evil.test.": evil, "plain.test.": plain}
        self.keytags = {".": root_res.key_tag, "test.": tld_res.key_tag,
                        "example.test.": good_res.key_tag, "evil.test.": evil_res.key_tag}
        self.anchors = [root_res.ds]

    # --- building responses ---
    def owner_zone(self, name: Name) -> Zone:
        """The zone that would answer for `name` (deepest apex at or above it)."""
        n = name
        while True:
            z = self.zones.get(n.to_text())
            if z is not None:
                return z
            if n.is_root():
                return self.zones["."]
            n = n.parent()

    def response(self, name: Name, rtype: int) -> Message:
        zone = self.zones[name.parent().to_text()] if rtype == Type.DS else self.owner_zone(name)
        self.asked.append((name.to_text(), rtype))
        m = Message(id=0, flags=Flags.QR | Flags.AA)
        node = zone.records.get(name, {})
        rds = node.get(rtype, [])
        if rds and (zone.origin.to_text(), rtype) not in self.drop:
            ttl = zone.ttl_of(name, rtype)
            for rd in rds:
                m.answers.append(RR(name, rtype, Class.IN, ttl, rd))
            sig = zone.rrsigs.get((name, rtype))
            if sig is not None and (zone.origin.to_text(), Type.RRSIG) not in self.drop:
                m.answers.append(RR(name, Type.RRSIG, Class.IN, ttl, sig))
            return m
        # no data: attach the zone's denial records for `name`
        m.authority.extend(self.denial(zone, name))
        return m

    def denial(self, zone: Zone, name: Name) -> list[RR]:
        """Every NSEC/NSEC3 RR in `zone` that could bear on `name`, signed."""
        out: list[RR] = []
        for owner, node in zone.records.items():
            for rtype in (Type.NSEC, Type.NSEC3):
                if rtype not in node:
                    continue
                ttl = zone.ttl_of(owner, rtype)
                for rd in node[rtype]:
                    out.append(RR(owner, rtype, Class.IN, ttl, rd))
                sig = zone.rrsigs.get((owner, rtype))
                if sig is not None:
                    out.append(RR(owner, Type.RRSIG, Class.IN, ttl, sig))
        return out

    def ask(self):
        async def _ask(name: Name, rtype: int) -> Message:
            return self.response(name, rtype)
        return _ask

    def validator(self, **kw) -> Validator:
        return Validator(self.ask(), anchors=self.anchors, **kw)

    # --- forging ---
    def sign_as(self, zone_text: str, owner: Name, rtype: int, rdatas: list,
                *, labels: int | None = None, priv=None, key_tag: int | None = None) -> R.RRSIG:
        """Sign an arbitrary RRset with `zone_text`'s real private key."""
        zone = self.zones[zone_text]
        sig = R.RRSIG(type_covered=rtype, algorithm=13,
                      labels=len(owner.labels) if labels is None else labels,
                      original_ttl=3600, expiration=2 ** 31 - 1, inception=0,
                      key_tag=self.keytags[zone_text] if key_tag is None else key_tag,
                      signer=zone.origin, signature=b"")
        data = _signed_data(owner, rtype, 1, sig, rdatas)
        der = (priv or zone.signing_key).sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        sig.signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return sig


def rrset(world: World, name: Name, rtype: int):
    zone = world.owner_zone(name)
    return zone.records[name][rtype], [zone.rrsigs[(name, rtype)]]


# ---------------------------------------------------------------- baseline
@pytest.mark.asyncio
async def test_a_correctly_signed_answer_is_secure():
    w = World()
    rdatas, sigs = rrset(w, GOOD, Type.A)
    assert await w.validator().validate(GOOD, Type.A, rdatas, sigs) == ValidationResult.SECURE


@pytest.mark.asyncio
async def test_tampered_data_is_bogus():
    w = World()
    _, sigs = rrset(w, GOOD, Type.A)
    assert await w.validator().validate(
        GOOD, Type.A, [R.A("6.6.6.6")], sigs) == ValidationResult.BOGUS


# ------------------------------------- attacker owns a different signed zone
@pytest.mark.asyncio
async def test_another_zones_valid_signature_does_not_authenticate_this_name():
    """The whole point of a chain.

    evil.test has a real, complete, root-anchored chain of its own. That earns
    it the right to speak for evil.test and for nothing else. A validator that
    fetches RRSIG.signer's keys and checks the maths will call this SECURE,
    which means anyone who can register one signed domain can forge every
    answer on the internet.
    """
    w = World()
    forged = [R.A("6.6.6.6")]
    sig = w.sign_as("evil.test.", GOOD, Type.A, forged)
    assert await w.validator().validate(GOOD, Type.A, forged, [sig]) == ValidationResult.BOGUS


@pytest.mark.asyncio
async def test_a_signed_sibling_cannot_forge_a_denial_either():
    w = World()
    victim = Name.from_text("www.example.test.")
    evil = w.zones["evil.test."]
    nsecs = [rr for rr in w.denial(evil, victim) if rr.rtype == Type.NSEC]
    result = await w.validator().validate_denial(victim, Type.A, nsecs, Rcode.NXDOMAIN)
    assert result != ValidationResult.SECURE


# --------------------------------------------------- attacker deletes things
@pytest.mark.asyncio
async def test_stripping_the_signature_is_bogus_not_insecure():
    """A signed zone that suddenly has no signatures is under attack.

    Answering INSECURE here — "no RRSIG, so nothing to check" — makes the whole
    of DNSSEC optional at the attacker's discretion: delete two records and the
    forged answer sails through unvalidated.
    """
    w = World()
    rdatas, _ = rrset(w, GOOD, Type.A)
    assert await w.validator().validate(GOOD, Type.A, rdatas, []) == ValidationResult.BOGUS


@pytest.mark.asyncio
async def test_stripping_the_ds_is_bogus_not_insecure():
    """Deleting the DS at the parent must not silently downgrade the child."""
    w = World()
    w.drop.add(("test.", Type.DS))
    rdatas, sigs = rrset(w, GOOD, Type.A)
    assert await w.validator().validate(GOOD, Type.A, rdatas, sigs) == ValidationResult.BOGUS


@pytest.mark.asyncio
async def test_a_genuinely_unsigned_delegation_is_insecure():
    """The other half: unsigned zones exist and must still resolve.

    plain.test is delegated by a signed parent that publishes no DS for it, and
    the parent's NSEC proves that. That is a real insecure delegation, not an
    attack, and answering BOGUS here would break every unsigned domain.
    """
    w = World()
    plain = w.zones["plain.test."]
    result = await w.validator().validate(
        PLAIN, Type.A, plain.records[PLAIN][Type.A], [])
    assert result == ValidationResult.INSECURE


@pytest.mark.asyncio
async def test_an_unproven_absence_of_ds_is_bogus():
    """Same shape as above, but with the proof deleted."""
    w = World()
    w.drop.add(("test.", Type.NSEC))
    plain = w.zones["plain.test."]

    async def ask(name: Name, rtype: int) -> Message:
        m = w.response(name, rtype)
        if rtype == Type.DS:
            m.authority = []            # on-path deletion of the denial
        return m

    v = Validator(ask, anchors=w.anchors)
    result = await v.validate(PLAIN, Type.A, plain.records[PLAIN][Type.A], [])
    assert result == ValidationResult.BOGUS


# ------------------------------------------- a zone denying its own security
@pytest.mark.asyncio
async def test_a_child_cannot_deny_its_own_ds():
    """The apex NSEC of any signed zone lacks the DS bit — DS lives upstairs.

    If that record is accepted as proof of "no DS", every signed zone can opt
    itself out of DNSSEC by answering the DS query from its own apex, and so
    can anyone who can redirect the DS query to the child's servers.
    """
    w = World()

    async def ask(name: Name, rtype: int) -> Message:
        if rtype == Type.DS and name == GOOD:
            child = w.zones["example.test."]
            m = Message(id=0, flags=Flags.QR | Flags.AA)
            m.authority.extend(w.denial(child, name))     # child's own apex NSEC
            return m
        return w.response(name, rtype)

    v = Validator(ask, anchors=w.anchors)
    rdatas, sigs = rrset(w, GOOD, Type.A)
    assert await v.validate(GOOD, Type.A, rdatas, sigs) == ValidationResult.BOGUS


# ------------------------------------------------------ denial-type swapping
@pytest.mark.asyncio
async def test_a_nodata_proof_is_not_an_nxdomain_proof():
    """Both records are genuine and signed; only the claim is wrong.

    example.test exists and has no MX. Replaying that (valid) NODATA proof
    under an NXDOMAIN rcode says the whole domain is gone.
    """
    w = World()
    zone = w.zones["example.test."]
    proof = w.denial(zone, GOOD)
    v = w.validator()
    assert await v.validate_denial(GOOD, Type.MX, proof, Rcode.NOERROR) == ValidationResult.SECURE
    assert await v.validate_denial(GOOD, Type.MX, proof, Rcode.NXDOMAIN) == ValidationResult.BOGUS


@pytest.mark.asyncio
async def test_nxdomain_needs_the_wildcard_denied_too():
    """A covering NSEC alone does not prove NXDOMAIN.

    NSEC records are public; a name under `*.wild.example.test` is covered by
    one of them and yet the zone answers for it. Accepting the covering record
    on its own lets an attacker replay it to deny names that resolve.
    """
    w = World()
    zone = w.zones["example.test."]
    victim = Name.from_text("anything.wild.example.test.")
    full = w.denial(zone, victim)
    # The zone's own proof denies the wildcard nowhere, because the wildcard
    # exists: a correct validator must refuse NXDOMAIN for this name.
    assert await w.validator().validate_denial(
        victim, Type.A, full, Rcode.NXDOMAIN) == ValidationResult.BOGUS


# ------------------------------------------------------------- wildcards
@pytest.mark.asyncio
async def test_a_real_wildcard_answer_validates():
    """Correctness, not attack: the signature covers `*.wild.example.test`, so
    verifying it against the expanded owner name cannot work, and every
    wildcard-served domain fails until the RRSIG label count is honoured."""
    w = World()
    zone = w.zones["example.test."]
    wild = Name.from_text("*.wild.example.test.")
    qname = Name.from_text("host.wild.example.test.")
    rdatas = zone.records[wild][Type.A]
    sigs = [zone.rrsigs[(wild, Type.A)]]
    proof = w.denial(zone, qname)
    assert await w.validator().validate(
        qname, Type.A, rdatas, sigs, proof) == ValidationResult.SECURE


@pytest.mark.asyncio
async def test_a_wildcard_signature_cannot_be_replayed_over_a_real_name():
    """`real.wild.example.test` sits at the depth the wildcard expands to and
    has its own A record. Serving the wildcard's data under its name is a
    genuine signature over a name the zone answers for directly, and the only
    thing that catches it is demanding proof the exact name is absent — which
    the zone cannot give, because it is not."""
    w = World()
    zone = w.zones["example.test."]
    wild = Name.from_text("*.wild.example.test.")
    victim = Name.from_text("real.wild.example.test.")
    rdatas = zone.records[wild][Type.A]
    sigs = [zone.rrsigs[(wild, Type.A)]]
    assert await w.validator().validate(
        victim, Type.A, rdatas, sigs, w.denial(zone, victim)) == ValidationResult.BOGUS


@pytest.mark.asyncio
async def test_a_signature_claiming_more_labels_than_the_name_has_is_bogus():
    w = World()
    rdatas = w.zones["example.test."].records[GOOD][Type.A]
    sig = w.sign_as("example.test.", GOOD, Type.A, rdatas, labels=9)
    assert await w.validator().validate(GOOD, Type.A, rdatas, [sig]) == ValidationResult.BOGUS


# ------------------------------------------------------------- resource use
@pytest.mark.asyncio
async def test_a_pile_of_junk_signatures_costs_bounded_cpu():
    """CVE-2023-50387 ("KeyTrap") in miniature.

    The peer chooses how many signatures a response carries and how many keys a
    zone publishes, and a validator that tries every pair does |sigs| x |keys|
    public-key operations on demand. Here the signatures are individually
    plausible — right signer, right key tag — and all wrong.
    """
    import trench.resolver.dnssec.chain as chain

    w = World()
    rdatas = w.zones["example.test."].records[GOOD][Type.A]
    real = w.zones["example.test."].rrsigs[(GOOD, Type.A)]
    junk = [R.RRSIG(**{**real.__dict__, "signature": bytes(64)}) for _ in range(500)]

    calls = 0
    original = chain.verify_rrset

    def counted(*a, **k):
        nonlocal calls
        calls += 1
        return original(*a, **k)

    chain.verify_rrset = counted
    try:
        result = await w.validator().validate(GOOD, Type.A, rdatas, junk)
    finally:
        chain.verify_rrset = original
    assert result == ValidationResult.BOGUS
    assert calls <= 64, f"{calls} signature verifications for one query"


@pytest.mark.asyncio
async def test_excessive_nsec3_iterations_are_refused_not_computed():
    """RFC 9276 §3.2. The iteration count is the zone's choice and the hashing
    is ours to pay for, so a hostile count is a reason to stop."""
    from trench.resolver.dnssec.nsec import Nsec3Set

    rd = R.NSEC3(hash_algorithm=1, flags=0, iterations=5000, salt=b"",
                 next_hashed=b"\x00" * 20, type_bitmap=b"")
    s = Nsec3Set([(Name.from_text("aaaa.example.test."), rd)], GOOD)
    assert not s.usable


@pytest.mark.asyncio
async def test_nsec3_records_with_mixed_parameters_prove_nothing():
    from trench.resolver.dnssec.nsec import Nsec3Set

    a = R.NSEC3(hash_algorithm=1, flags=0, iterations=0, salt=b"\x01",
                next_hashed=b"\x00" * 20, type_bitmap=b"")
    b = R.NSEC3(hash_algorithm=1, flags=0, iterations=0, salt=b"\x02",
                next_hashed=b"\x00" * 20, type_bitmap=b"")
    s = Nsec3Set([(Name.from_text("aa.example.test."), a),
                  (Name.from_text("bb.example.test."), b)], GOOD)
    assert not s.usable


# ------------------------------------------------------------- key handling
@pytest.mark.asyncio
async def test_a_key_without_the_zone_flag_cannot_sign_zone_data():
    """RFC 4034 §2.1.1. The key here is genuinely published by the zone and
    genuinely inside the KSK-signed DNSKEY RRset — everything about it checks
    out except that its ZONE bit is clear, which means it is not a key for
    signing zone data and its signatures must not count."""
    from trench.resolver.dnssec.keys import key_tag

    w = World(nonzone_key=True)
    forged = [R.A("6.6.6.6")]
    sig = w.sign_as("example.test.", GOOD, Type.A, forged,
                    priv=w.nonzone_priv, key_tag=key_tag(w.nonzone_key))
    assert await w.validator().validate(GOOD, Type.A, forged, [sig]) == ValidationResult.BOGUS


def test_an_apex_nsec_never_proves_anything_about_a_ds():
    """RFC 4035 §5.2, at the level it is decided.

    A record carrying SOA came from a zone's own apex, and DS is the parent's
    record. This is the contract of `nsec_ds_denial` in isolation: end to end
    the same forgery is also stopped by the signer check, which is why it has
    to be tested here to be tested at all.
    """
    from trench.auth_zone.sign.signer import encode_type_bitmap
    from trench.resolver.dnssec.nsec import nsec_ds_denial

    child = Name.from_text("example.test.")
    parent_side = R.NSEC(next_name=Name.from_text("evil.test."),
                         type_bitmap=encode_type_bitmap({Type.NS, Type.RRSIG, Type.NSEC}))
    child_side = R.NSEC(next_name=Name.from_text("www.example.test."),
                        type_bitmap=encode_type_bitmap(
                            {Type.SOA, Type.NS, Type.A, Type.RRSIG, Type.NSEC}))
    assert nsec_ds_denial(child, [(child, parent_side)]) == "insecure"
    assert nsec_ds_denial(child, [(child, child_side)]) is None


# --------------------------------------------------- canonical form on the wire
# The two tests below are pinned to values from outside this codebase. Both bugs
# they cover were invisible to every other test here, because our signer and our
# validator computed the same wrong thing and agreed with each other perfectly.
# Only real zones disagreed.

def test_nsec3_hashing_matches_the_rfc_5155_vectors():
    """RFC 5155 Appendix A: the `example.` zone, salt aabbccdd, 12 iterations.

    NSEC3 owner names are base32*hex*, not base32. Lowercasing before applying
    the translation table turns the mapping into a no-op — the output still
    looks like a hash, our own signer produced the same one, and not a single
    real NSEC3 zone could be validated.
    """
    from trench.resolver.dnssec.nsec import nsec3_b32, nsec3_hash

    salt = bytes.fromhex("aabbccdd")
    expected = {
        "example.": "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
        "a.example.": "35mthgpgcu1qg68fab165klnsnk3dpvl",
        "ai.example.": "gjeqe526plbf1g8mklp59enfd789njgi",
        "ns1.example.": "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
        "*.w.example.": "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
    }
    for name, want in expected.items():
        assert nsec3_b32(nsec3_hash(Name.from_text(name), salt, 12)) == want, name


def test_rrsets_are_ordered_by_rdata_not_by_encoded_length():
    """RFC 4034 §6.3 sorts the RRs of an RRset by their RDATA alone.

    Sorting by the whole encoded RR looks identical — owner, type, class and
    TTL are the same for every member — except that the two-byte rdlength sits
    between them, so a shorter RDATA sorts first regardless of content. Every
    RRset whose members differ in length then hashes in the wrong order.
    Fixed-length types such as A never expose it.
    """
    owner = Name.from_text("example.test.")
    sig = R.RRSIG(type_covered=Type.MX, algorithm=13, labels=2, original_ttl=3600,
                  expiration=2 ** 31 - 1, inception=0, key_tag=1,
                  signer=owner, signature=b"")
    # Same first label length, so RDATA order is decided by "aa" < "zz" — but
    # the "aa" record is the longer of the two, so length order is the reverse.
    longer = R.MX(10, Name.from_text("aa.deeper.example.test."))
    shorter = R.MX(10, Name.from_text("zz.example.test."))
    data = _signed_data(owner, Type.MX, 1, sig, [shorter, longer])
    assert data.index(b"\x02aa") < data.index(b"\x02zz")


def test_a_ds_query_is_never_followed_into_the_child():
    """The resolver half of "a child cannot deny its own DS".

    Asking com's servers for `example.com DS` normally draws a referral to
    example.com. Following it hands the question to the only party that gains
    from answering no, so the referral is refused for DS and DS alone.
    """
    from trench.resolver.recursive import Recursive

    com = Name.from_text("com.")
    child = Name.from_text("example.com.")
    msg = Message(id=0, flags=Flags.QR)
    msg.authority.append(RR(child, Type.NS, Class.IN, 3600,
                            R.NS(Name.from_text("ns.example.com."))))

    assert Recursive._referral(msg, com, child, Type.A) is not None
    assert Recursive._referral(msg, com, child, Type.DS) is None
    # a DS query for something deeper still descends normally
    deeper = Name.from_text("sub.example.com.")
    assert Recursive._referral(msg, com, deeper, Type.DS) is not None


# ------------------------------------------------------------- NSEC3 flavour
@pytest.mark.asyncio
async def test_the_same_rules_hold_for_an_nsec3_zone():
    w = World(nsec3=True, nsec3_iterations=5)
    rdatas, sigs = rrset(w, GOOD, Type.A)
    v = w.validator()
    assert await v.validate(GOOD, Type.A, rdatas, sigs) == ValidationResult.SECURE

    forged = [R.A("6.6.6.6")]
    sig = w.sign_as("evil.test.", GOOD, Type.A, forged)
    assert await w.validator().validate(GOOD, Type.A, forged, [sig]) == ValidationResult.BOGUS

    zone = w.zones["example.test."]
    proof = w.denial(zone, GOOD)
    assert await w.validator().validate_denial(
        GOOD, Type.MX, proof, Rcode.NOERROR) == ValidationResult.SECURE


@pytest.mark.asyncio
async def test_nsec3_nxdomain_needs_the_full_closest_encloser_proof():
    w = World(nsec3=True, nsec3_iterations=5)
    zone = w.zones["example.test."]
    victim = Name.from_text("nothing.here.example.test.")
    proof = w.denial(zone, victim)
    v = w.validator()
    assert await v.validate_denial(victim, Type.A, proof, Rcode.NXDOMAIN) == ValidationResult.SECURE

    # And here is what the third record is for. `under.wild.example.test` does
    # not exist as a name, so its closest encloser is matched and its next
    # closer is covered exactly as above — but a wildcard sits at that encloser
    # and answers for it. Stopping one record early calls a name that resolves
    # nonexistent.
    under = Name.from_text("under.wild.example.test.")
    assert await w.validator().validate_denial(
        under, Type.A, w.denial(zone, under), Rcode.NXDOMAIN) != ValidationResult.SECURE


# ------------------------------------------------------- denial from the wrong side
def _nsec3_chain(zone_text: str, present: list[str], *, opt_out: bool = False,
                 bitmap: bytes = b""):
    """An NSEC3 chain over exactly `present`, linked in hash order.

    Names absent from `present` fall in a gap and are therefore *covered*;
    names in it are *matched*. That is what a real zone publishes, so a proof
    built from this chain is one the zone genuinely signed.
    """
    from trench.resolver.dnssec.nsec import Nsec3Set, nsec3_b32, nsec3_hash

    zone = Name.from_text(zone_text)
    raw = sorted(nsec3_hash(Name.from_text(n), b"", 0) for n in present)
    items = []
    for i, h in enumerate(raw):
        items.append((Name.from_text(f"{nsec3_b32(h)}.{zone_text}"),
                      R.NSEC3(hash_algorithm=1, flags=1 if opt_out else 0,
                              iterations=0, salt=b"",
                              next_hashed=raw[(i + 1) % len(raw)],
                              type_bitmap=bitmap)))
    return Nsec3Set(items, zone)


def test_opt_out_nsec3_cannot_prove_a_name_is_absent():
    """RFC 5155 §6. Opt-out says only that no *signed* name is in the gap, so
    an unsigned delegation may sit there. Without this rule an opt-out TLD's
    own genuine chain proves NXDOMAIN for domains that plainly exist."""
    from trench.resolver.dnssec.nsec import nsec3_nxdomain

    victim = Name.from_text("victim.example.test.")
    signed = _nsec3_chain("example.test.", ["example.test."], opt_out=False)
    assert signed.usable and nsec3_nxdomain(victim, signed)

    opted = _nsec3_chain("example.test.", ["example.test."], opt_out=True)
    assert opted.usable
    assert not nsec3_nxdomain(victim, opted)


def test_parent_side_delegation_nsec_cannot_deny_the_childs_own_types():
    """An NSEC owned by the child but published by the *parent* carries NS and
    no SOA. It describes the cut, not the child's contents — and it is public,
    so accepting it denies any type at the apex of any delegated zone."""
    from trench.auth_zone.sign.signer import encode_type_bitmap
    from trench.resolver.dnssec.nsec import nsec_nodata

    child = Name.from_text("child.example.test.")
    delegation = R.NSEC(next_name=Name.from_text("z.example.test."),
                        type_bitmap=encode_type_bitmap(
                            {Type.NS, Type.DS, Type.RRSIG, Type.NSEC}))
    assert not nsec_nodata(child, Type.A, [(child, delegation)])

    # The child's own apex NSEC has SOA set and does deny it.
    apex = R.NSEC(next_name=Name.from_text("z.child.example.test."),
                  type_bitmap=encode_type_bitmap(
                      {Type.SOA, Type.NS, Type.RRSIG, Type.NSEC}))
    assert nsec_nodata(child, Type.A, [(child, apex)])
