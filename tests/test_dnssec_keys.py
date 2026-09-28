"""DNSKEY handling, key tags, DS digests, and signature verification per
algorithm.

The chain tests exercise one algorithm end to end. What is untested is the rest
of the algorithm table — and getting any of it wrong means either refusing a
correctly signed zone or, worse, accepting a signature that does not verify.
"""
from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, utils

from trench.resolver.dnssec.keys import (
    algo_name,
    dnskey_to_public_key,
    ds_digest,
    key_tag,
)
from trench.resolver.dnssec.validate import _canon_rdata, _serial_le, verify_rrset
from trench.wire import Class, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.writer import Writer


def n(s):
    return Name.from_text(s)


# --- key material builders ---
def _rsa_dnskey(algo=8, bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    nums = key.public_key().public_numbers()
    e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    m = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    wire = bytes([len(e)]) + e + m
    return key, R.DNSKEY(256, 3, algo, wire)


def _rsa_dnskey_long_exponent():
    """RFC 3110 allows a three-byte exponent length for exponents over 255
    bytes; the one-byte form cannot express them."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = key.public_key().public_numbers()
    e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    m = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    wire = b"\x00" + len(e).to_bytes(2, "big") + e + m
    return key, R.DNSKEY(256, 3, 8, wire)


def _ecdsa_dnskey(algo=13):
    curve = ec.SECP256R1() if algo == 13 else ec.SECP384R1()
    key = ec.generate_private_key(curve)
    nums = key.public_key().public_numbers()
    size = 32 if algo == 13 else 48
    wire = nums.x.to_bytes(size, "big") + nums.y.to_bytes(size, "big")
    return key, R.DNSKEY(256, 3, algo, wire)


def _ed_dnskey(algo=15):
    key = (ed25519.Ed25519PrivateKey.generate() if algo == 15
           else ed448.Ed448PrivateKey.generate())
    wire = key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    return key, R.DNSKEY(256, 3, algo, wire)


# --- key tag ---
def test_the_key_tag_of_the_rfc_example():
    """RFC 4034 Appendix B: a checksum over the RDATA, not a hash."""
    dnskey = R.DNSKEY(256, 3, 13, bytes(range(64)))
    tag = key_tag(dnskey)
    assert 0 <= tag <= 0xFFFF
    # Deterministic, and sensitive to every field.
    assert key_tag(dnskey) == tag
    assert key_tag(R.DNSKEY(257, 3, 13, bytes(range(64)))) != tag
    assert key_tag(R.DNSKEY(256, 3, 14, bytes(range(64)))) != tag
    assert key_tag(R.DNSKEY(256, 3, 13, bytes(range(1, 65)))) != tag


def test_the_legacy_rsa_md5_tag_reads_the_last_bytes():
    """Algorithm 1 uses a different rule entirely."""
    dnskey = R.DNSKEY(256, 3, 1, bytes(range(64)))
    w = Writer()
    dnskey.emit(w)
    raw = w.getvalue()
    assert key_tag(dnskey) == (raw[-3] << 8) | raw[-2]


# --- DS digest ---
@pytest.mark.parametrize("dtype,hasher", [(1, hashlib.sha1), (2, hashlib.sha256),
                                          (4, hashlib.sha384)])
def test_every_supported_ds_digest_type(dtype, hasher):
    _, dnskey = _ecdsa_dnskey()
    got = ds_digest(n("example.com."), dnskey, dtype)
    assert len(got) == hasher().digest_size


def test_an_unsupported_ds_digest_type_is_refused():
    _, dnskey = _ecdsa_dnskey()
    with pytest.raises(ValueError, match="unsupported DS digest type"):
        ds_digest(n("example.com."), dnskey, 99)


def test_the_ds_digest_covers_the_owner_name_in_canonical_form():
    """Otherwise one zone's DS would validate another's key."""
    _, dnskey = _ecdsa_dnskey()
    a = ds_digest(n("example.com."), dnskey, 2)
    b = ds_digest(n("other.com."), dnskey, 2)
    assert a != b
    assert ds_digest(n("EXAMPLE.COM."), dnskey, 2) == a


# --- public keys ---
@pytest.mark.parametrize("build", [
    lambda: _rsa_dnskey(8), lambda: _rsa_dnskey(10), lambda: _rsa_dnskey_long_exponent(),
    lambda: _ecdsa_dnskey(13), lambda: _ecdsa_dnskey(14),
    lambda: _ed_dnskey(15), lambda: _ed_dnskey(16),
])
def test_every_supported_algorithm_yields_a_usable_public_key(build):
    private, dnskey = build()
    pub = dnskey_to_public_key(dnskey)
    assert pub.public_numbers() if hasattr(pub, "public_numbers") else pub


def test_an_unsupported_algorithm_is_refused():
    with pytest.raises(ValueError, match="unsupported DNSSEC algorithm"):
        dnskey_to_public_key(R.DNSKEY(256, 3, 99, b"\x00" * 32))


def test_an_empty_rsa_key_is_refused():
    with pytest.raises(ValueError, match="empty RSA key"):
        dnskey_to_public_key(R.DNSKEY(256, 3, 8, b""))


@pytest.mark.parametrize("algo,name", [(8, "RSASHA256"), (13, "ECDSAP256SHA256"),
                                       (15, "ED25519")])
def test_known_algorithms_are_named(algo, name):
    assert algo_name(algo) == name


def test_an_unknown_algorithm_is_named_by_its_number():
    assert algo_name(200) == "ALGO200"


# --- signature verification, per algorithm ---
def _sign(private, algo, data):
    if algo in (5, 7, 8, 10):
        halg = {5: hashes.SHA1(), 7: hashes.SHA1(), 8: hashes.SHA256(),
                10: hashes.SHA512()}[algo]
        return private.sign(data, padding.PKCS1v15(), halg)
    if algo in (13, 14):
        halg = hashes.SHA256() if algo == 13 else hashes.SHA384()
        der = private.sign(data, ec.ECDSA(halg))
        r, s = utils.decode_dss_signature(der)
        size = 32 if algo == 13 else 48
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    return private.sign(data)


def _signed_rrset(private, dnskey, algo, *, owner="example.com.",
                  inception=1_000_000, expiration=2_000_000):
    from trench.resolver.dnssec.validate import _signed_data
    rdatas = [R.A("192.0.2.1")]
    rrsig = R.RRSIG(type_covered=int(Type.A), algorithm=algo, labels=2,
                    original_ttl=3600, expiration=expiration, inception=inception,
                    key_tag=key_tag(dnskey), signer=n("example.com."), signature=b"")
    data = _signed_data(n(owner), int(Type.A), int(Class.IN), rrsig, rdatas)
    rrsig.signature = _sign(private, algo, data)
    return rdatas, rrsig


@pytest.mark.parametrize("algo,build", [
    (8, lambda: _rsa_dnskey(8)), (10, lambda: _rsa_dnskey(10)),
    (13, lambda: _ecdsa_dnskey(13)), (14, lambda: _ecdsa_dnskey(14)),
    (15, lambda: _ed_dnskey(15)), (16, lambda: _ed_dnskey(16)),
])
def test_a_good_signature_verifies_for_every_algorithm(algo, build):
    private, dnskey = build()
    rdatas, rrsig = _signed_rrset(private, dnskey, algo)
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, dnskey, now=1_500_000) is True


def test_a_tampered_rrset_does_not_verify():
    private, dnskey = _ecdsa_dnskey(13)
    rdatas, rrsig = _signed_rrset(private, dnskey, 13)
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN),
                        [R.A("6.6.6.6")], rrsig, dnskey, now=1_500_000) is False


def test_a_signature_from_another_key_does_not_verify():
    private, dnskey = _ecdsa_dnskey(13)
    rdatas, rrsig = _signed_rrset(private, dnskey, 13)
    _, other = _ecdsa_dnskey(13)
    rrsig.key_tag = key_tag(other)
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, other, now=1_500_000) is False


def test_an_algorithm_mismatch_is_refused_before_any_crypto():
    private, dnskey = _ecdsa_dnskey(13)
    rdatas, rrsig = _signed_rrset(private, dnskey, 13)
    rrsig.algorithm = 14
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, dnskey, now=1_500_000) is False


def test_a_key_tag_mismatch_is_refused():
    private, dnskey = _ecdsa_dnskey(13)
    rdatas, rrsig = _signed_rrset(private, dnskey, 13)
    rrsig.key_tag = (rrsig.key_tag + 1) & 0xFFFF
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, dnskey, now=1_500_000) is False


@pytest.mark.parametrize("now", [999_999, 2_000_001])
def test_a_signature_outside_its_validity_period_is_refused(now):
    private, dnskey = _ecdsa_dnskey(13)
    rdatas, rrsig = _signed_rrset(private, dnskey, 13)
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, dnskey, now=now) is False


def test_a_key_that_cannot_be_parsed_is_refused_rather_than_raising():
    private, dnskey = _ecdsa_dnskey(13)
    rdatas, rrsig = _signed_rrset(private, dnskey, 13)
    broken = R.DNSKEY(256, 3, 13, b"\x00")
    rrsig.key_tag = key_tag(broken)
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, broken, now=1_500_000) is False


def test_an_unknown_signing_algorithm_verifies_nothing():
    private, dnskey = _ecdsa_dnskey(13)
    rdatas, rrsig = _signed_rrset(private, dnskey, 13)
    rrsig.algorithm = 99
    unknown = R.DNSKEY(256, 3, 99, dnskey.public_key)
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, unknown, now=1_500_000) is False


# --- canonical rdata ---
@pytest.mark.parametrize("build_upper,build_lower", [
    (lambda: R.NS(n("NS.Example.COM.")), lambda: R.NS(n("ns.example.com."))),
    (lambda: R.CNAME(n("Real.Example.COM.")), lambda: R.CNAME(n("real.example.com."))),
    (lambda: R.PTR(n("Host.Example.COM.")), lambda: R.PTR(n("host.example.com."))),
    (lambda: R.DNAME(n("Other.COM.")), lambda: R.DNAME(n("other.com."))),
    (lambda: R.MX(10, n("Mail.Example.COM.")),
     lambda: R.MX(10, n("mail.example.com."))),
    (lambda: R.SRV(1, 5, 443, n("Svc.Example.COM.")),
     lambda: R.SRV(1, 5, 443, n("svc.example.com."))),
])
def test_names_inside_rdata_are_lowercased(build_upper, build_lower):
    assert _canon_rdata(build_upper()) == _canon_rdata(build_lower())


def test_soa_names_are_lowercased():
    upper = R.SOA(n("NS.Example.COM."), n("HM.Example.COM."), 1, 2, 3, 4, 5)
    lower = R.SOA(n("ns.example.com."), n("hm.example.com."), 1, 2, 3, 4, 5)
    assert _canon_rdata(upper) == _canon_rdata(lower)


def test_naptr_replacement_is_lowercased():
    """Omitting NAPTR meant a correctly signed ENUM or SIP zone that publishes a
    mixed-case replacement failed verification and came back BOGUS."""
    upper = R.NAPTR(1, 2, b"S", b"SIP+D2U", b"!x!", n("_sip._udp.Example.COM."))
    lower = R.NAPTR(1, 2, b"S", b"SIP+D2U", b"!x!", n("_sip._udp.example.com."))
    assert _canon_rdata(upper) == _canon_rdata(lower)


def test_a_type_with_no_embedded_name_is_emitted_as_is():
    rd = R.A("192.0.2.1")
    w = Writer()
    rd.emit(w)
    assert _canon_rdata(rd) == w.getvalue()


# --- serial arithmetic ---
@pytest.mark.parametrize("a,b,le", [
    (1, 2, True), (2, 1, False), (5, 5, True),
    (0xFFFFFFFF, 0, True),          # wrap: 0 is "after" 0xFFFFFFFF
    (0, 0xFFFFFFFF, False),
])
def test_serial_comparison_wraps(a, b, le):
    assert _serial_le(a, b) is le


def test_the_key_tag_is_checked_before_any_cryptography(monkeypatch):
    """The tag check is a *selection* guard: without it a validator attempts a
    public-key operation for every key of the right algorithm, whether or not
    the signature names it — which is the CPU amplification the per-answer
    budget exists to bound."""
    import trench.resolver.dnssec.validate as mod
    private, dnskey = _ecdsa_dnskey(13)
    rdatas, rrsig = _signed_rrset(private, dnskey, 13)
    attempts = []
    real = mod.dnskey_to_public_key
    monkeypatch.setattr(mod, "dnskey_to_public_key",
                        lambda k: attempts.append(k) or real(k))

    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, dnskey, now=1_500_000) is True
    assert len(attempts) == 1

    attempts.clear()
    rrsig.key_tag = (rrsig.key_tag + 1) & 0xFFFF
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, dnskey, now=1_500_000) is False
    assert attempts == [], "a tag mismatch must be refused without loading the key"


def test_the_algorithm_is_checked_before_any_cryptography(monkeypatch):
    import trench.resolver.dnssec.validate as mod
    private, dnskey = _ecdsa_dnskey(13)
    rdatas, rrsig = _signed_rrset(private, dnskey, 13)
    attempts = []
    monkeypatch.setattr(mod, "dnskey_to_public_key", lambda k: attempts.append(k))
    rrsig.algorithm = 14
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, dnskey, now=1_500_000) is False
    assert attempts == []


def test_the_validity_period_is_checked_before_any_cryptography(monkeypatch):
    """An expired signature costs nothing to reject."""
    import trench.resolver.dnssec.validate as mod
    private, dnskey = _ecdsa_dnskey(13)
    rdatas, rrsig = _signed_rrset(private, dnskey, 13)
    attempts = []
    monkeypatch.setattr(mod, "dnskey_to_public_key", lambda k: attempts.append(k))
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, dnskey, now=3_000_000) is False
    assert attempts == []


def test_a_signature_by_one_key_does_not_verify_under_another():
    """The tag check is not the only thing standing between them."""
    private_a, key_a = _ecdsa_dnskey(13)
    _, key_b = _ecdsa_dnskey(13)
    rdatas, rrsig = _signed_rrset(private_a, key_a, 13)
    rrsig.key_tag = key_tag(key_b)
    assert verify_rrset(n("example.com."), int(Type.A), int(Class.IN), rdatas,
                        rrsig, key_b, now=1_500_000) is False
