"""DNSSEC RRSIG verification across algorithms, plus key-tag/DS self-consistency.

We generate a zone key, sign an RRset by feeding our own canonical `_signed_data`
to cryptography, then assert verify_rrset accepts it and rejects tampering.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, utils

from dnsguard.resolver.dnssec import ds_digest, key_tag, verify_rrset
from dnsguard.resolver.dnssec.validate import _signed_data
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Class, Type

OWNER = Name.from_text("example.com")
RRSET = [R.A("93.184.216.34"), R.A("93.184.216.35")]


def _dnskey_ecdsa(priv):
    nums = priv.public_key().public_numbers()
    pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    return R.DNSKEY(flags=256, protocol=3, algorithm=13, public_key=pub)


def _dnskey_ed25519(priv):
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    return R.DNSKEY(flags=256, protocol=3, algorithm=15, public_key=raw)


def _dnskey_rsa(priv):
    nums = priv.public_key().public_numbers()
    e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    prefix = bytes([len(e)]) if len(e) <= 255 else b"\x00" + len(e).to_bytes(2, "big")
    n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    return R.DNSKEY(flags=256, protocol=3, algorithm=8, public_key=prefix + e + n)


def _make_rrsig(dnskey, sign_fn):
    now = int(time.time())
    rrsig = R.RRSIG(type_covered=Type.A, algorithm=dnskey.algorithm, labels=2,
                    original_ttl=3600, expiration=now + 86400, inception=now - 3600,
                    key_tag=key_tag(dnskey), signer=OWNER, signature=b"")
    data = _signed_data(OWNER, Type.A, Class.IN, rrsig, RRSET)
    rrsig.signature = sign_fn(data)
    return rrsig


def test_ecdsa_p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    dnskey = _dnskey_ecdsa(priv)

    def sign(data):
        der = priv.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    rrsig = _make_rrsig(dnskey, sign)
    assert verify_rrset(OWNER, Type.A, Class.IN, RRSET, rrsig, dnskey) is True
    # tamper the data -> reject
    assert verify_rrset(OWNER, Type.A, Class.IN, [R.A("1.1.1.1")], rrsig, dnskey) is False


def test_ed25519():
    priv = ed25519.Ed25519PrivateKey.generate()
    dnskey = _dnskey_ed25519(priv)
    rrsig = _make_rrsig(dnskey, lambda data: priv.sign(data))
    assert verify_rrset(OWNER, Type.A, Class.IN, RRSET, rrsig, dnskey) is True
    # flip a signature byte -> reject
    bad = R.RRSIG(**{**rrsig.__dict__, "signature": bytes([rrsig.signature[0] ^ 1]) + rrsig.signature[1:]})
    assert verify_rrset(OWNER, Type.A, Class.IN, RRSET, bad, dnskey) is False


def test_rsa_sha256():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    dnskey = _dnskey_rsa(priv)

    def sign(data):
        from cryptography.hazmat.primitives.asymmetric import padding
        return priv.sign(data, padding.PKCS1v15(), hashes.SHA256())

    rrsig = _make_rrsig(dnskey, sign)
    assert verify_rrset(OWNER, Type.A, Class.IN, RRSET, rrsig, dnskey) is True


def test_expired_signature_rejected():
    priv = ed25519.Ed25519PrivateKey.generate()
    dnskey = _dnskey_ed25519(priv)
    now = int(time.time())
    rrsig = R.RRSIG(type_covered=Type.A, algorithm=15, labels=2, original_ttl=3600,
                    expiration=now - 100, inception=now - 200, key_tag=key_tag(dnskey),
                    signer=OWNER, signature=b"")
    data = _signed_data(OWNER, Type.A, Class.IN, rrsig, RRSET)
    rrsig.signature = priv.sign(data)
    assert verify_rrset(OWNER, Type.A, Class.IN, RRSET, rrsig, dnskey) is False  # expired


def test_key_tag_and_ds():
    priv = ec.generate_private_key(ec.SECP256R1())
    dnskey = _dnskey_ecdsa(priv)
    kt = key_tag(dnskey)
    assert 0 <= kt <= 0xFFFF
    digest = ds_digest(OWNER, dnskey, 2)
    assert len(digest) == 32  # SHA-256
    assert ds_digest(OWNER, dnskey, 4) != digest  # SHA-384 differs


def test_key_tag_known_vector_root_ksk_2017():
    """RFC/IANA known answer: the root KSK-2017 has key tag 20326 and a fixed
    SHA-256 DS. This guards the key-tag byte-order (App. B) against regression."""
    import base64

    from dnsguard.resolver.dnssec import ds_digest, key_tag
    from dnsguard.wire.name import Name
    KSK2017_B64 = (
        "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3"
        "+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8Pzg"
        "Cmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7"
        "LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=")
    ksk = R.DNSKEY(flags=257, protocol=3, algorithm=8,
                   public_key=base64.b64decode(KSK2017_B64))
    assert key_tag(ksk) == 20326
    digest = ds_digest(Name.from_text("."), ksk, 2).hex().upper()
    assert digest == "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
