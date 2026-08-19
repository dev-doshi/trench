"""Password hashing + TOTP."""
from __future__ import annotations

from dnsguard.security import hashutil, totp


def test_password_hash_roundtrip():
    h = hashutil.hash_password("hunter2", n=2 ** 12)  # low cost for test speed
    assert hashutil.verify_password("hunter2", h)
    assert not hashutil.verify_password("wrong", h)
    assert h != hashutil.hash_password("hunter2", n=2 ** 12)  # salted


def test_token_hash():
    t = hashutil.new_token()
    assert hashutil.hash_token(t) == hashutil.hash_token(t)
    assert hashutil.hash_token(t) != hashutil.hash_token(hashutil.new_token())


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
