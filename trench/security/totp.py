"""TOTP 2FA (RFC 6238) + provisioning URI, stdlib only."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def new_secret() -> str:
    """Base32 secret for an authenticator app."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    pad = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(secret_b32: str, *, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    counter = int((at if at is not None else time.time()) // step)
    return _hotp(secret_b32, counter, digits)


def verify(secret_b32: str, code: str, *, at: float | None = None, window: int = 1) -> bool:
    """Accept codes within +/- `window` time steps (clock skew tolerance)."""
    now = at if at is not None else time.time()
    code = code.strip()
    for w in range(-window, window + 1):
        if hmac.compare_digest(totp(secret_b32, at=now + w * 30), code):
            return True
    return False


def provisioning_uri(secret_b32: str, account: str, issuer: str = "Trench") -> str:
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30")
