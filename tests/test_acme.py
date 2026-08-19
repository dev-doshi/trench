"""ACME (RFC 8555) offline units: JWK thumbprint, ES256 JWS, dns-01, CSR."""
from __future__ import annotations

import base64
import hashlib
import json

from dnsguard.security.acme import (
    ACMEAccount,
    b64url,
    dns01_txt,
    http01_keyauth,
    make_csr,
)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_thumbprint_format_and_stability():
    acct = ACMEAccount()
    tp = acct.thumbprint()
    assert "=" not in tp and len(tp) == 43              # sha256 -> 32 bytes -> 43 b64url chars
    assert acct.thumbprint() == tp                      # deterministic


def test_thumbprint_canonical_ordering():
    acct = ACMEAccount()
    jwk = acct.jwk()
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
                       separators=(",", ":"), sort_keys=True).encode()
    assert acct.thumbprint() == b64url(hashlib.sha256(canon).digest())


def test_jws_signature_verifies():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    acct = ACMEAccount()
    jws = acct.jws("https://acme.test/order", "nonce123", {"hello": "world"})
    # reconstruct the signing input and verify with the account public key
    signing_input = f'{jws["protected"]}.{jws["payload"]}'.encode()
    raw = _b64url_decode(jws["signature"])
    r = int.from_bytes(raw[:32], "big"); s = int.from_bytes(raw[32:], "big")
    der = utils.encode_dss_signature(r, s)
    acct.key.public_key().verify(der, signing_input, ec.ECDSA(hashes.SHA256()))  # raises on bad sig
    # protected header carries the embedded jwk (pre-registration) and correct alg/url
    prot = json.loads(_b64url_decode(jws["protected"]))
    assert prot["alg"] == "ES256" and prot["url"].endswith("/order") and "jwk" in prot


def test_jws_uses_kid_after_registration():
    acct = ACMEAccount()
    acct.kid = "https://acme.test/acct/1"
    prot = json.loads(_b64url_decode(acct.jws("https://x/y", "n", "")["protected"]))
    assert prot["kid"] == acct.kid and "jwk" not in prot


def test_jws_post_as_get_empty_payload():
    acct = ACMEAccount()
    jws = acct.jws("https://x/y", "n", "")
    assert jws["payload"] == ""                         # POST-as-GET


def test_dns01_digest():
    tp = ACMEAccount().thumbprint()
    val = dns01_txt("tokenABC", tp)
    expected = b64url(hashlib.sha256(f"tokenABC.{tp}".encode()).digest())
    assert val == expected and len(val) == 43


def test_http01_keyauth():
    assert http01_keyauth("tok", "thumb") == "tok.thumb"


def test_csr_has_sans():
    from cryptography import x509
    der, key_pem = make_csr(["dns.example.com", "www.example.com"])
    csr = x509.load_der_x509_csr(der)
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert set(san.value.get_values_for_type(x509.DNSName)) == \
        {"dns.example.com", "www.example.com"}
    assert csr.is_signature_valid
    assert b"PRIVATE KEY" in key_pem


def test_account_pem_roundtrip():
    acct = ACMEAccount()
    pem = acct.to_pem()
    restored = ACMEAccount.from_pem(pem)
    assert restored.thumbprint() == acct.thumbprint()
