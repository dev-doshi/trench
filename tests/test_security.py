"""Password hashing + TOTP."""
from __future__ import annotations

from trench.security import hashutil, totp


def test_password_hash_roundtrip():
    h = hashutil.hash_password("hunter2", n=2 ** 12)  # low cost for test speed
    assert hashutil.verify_password("hunter2", h)
    assert not hashutil.verify_password("wrong", h)
    assert h != hashutil.hash_password("hunter2", n=2 ** 12)  # salted


def test_token_hash():
    pepper = b"\x01" * 32
    t = hashutil.new_token()
    assert hashutil.hash_token(t, pepper) == hashutil.hash_token(t, pepper)
    assert hashutil.hash_token(t, pepper) != hashutil.hash_token(hashutil.new_token(), pepper)
    # keyed, not bare: a different installation's key gives a different digest
    assert hashutil.hash_token(t, pepper) != hashutil.hash_token(t, b"\x02" * 32)


def test_identifier_hash_is_stable_and_salted():
    salt = b"\x07" * 32
    a = hashutil.hash_identifier("ads.example.com", salt)
    assert a == hashutil.hash_identifier("ads.example.com", salt)   # counts still count
    assert a != hashutil.hash_identifier("other.example.com", salt)
    assert a != hashutil.hash_identifier("ads.example.com", b"\x08" * 32)
    assert len(a) == 32 and "ads" not in a


def test_totp_verify_window():
    secret = totp.new_secret()
    code = totp.totp(secret)
    assert totp.verify(secret, code)
    assert not totp.verify(secret, "000000", window=0) or code == "000000"
    # code from the previous step still accepted within window
    prev = totp.totp(secret, at=__import__("time").time() - 30)
    assert totp.verify(secret, prev, window=1)


def test_totp_provisioning_uri():
    uri = totp.provisioning_uri("ABCDEF", "admin")
    assert uri.startswith("otpauth://totp/") and "secret=ABCDEF" in uri
