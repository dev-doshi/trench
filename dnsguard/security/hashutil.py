"""Password hashing (scrypt, stdlib) + token hashing + constant-time compare."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

_N = 2 ** 15
_R = 8
_P = 1


# scrypt needs ~128*r*n bytes; give OpenSSL generous headroom over the default 32 MB
_MAXMEM = 256 * 1024 * 1024


def hash_password(password: str, *, n: int = _N, r: int = _R, p: int = _P) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=_MAXMEM)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, hash_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                            n=int(n), r=int(r), p=int(p), dklen=len(hash_hex) // 2,
                            maxmem=_MAXMEM)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def needs_rehash(stored: str, *, n: int = _N) -> bool:
    try:
        return int(stored.split("$")[1]) < n
    except Exception:
        return True


def new_token() -> str:
    """A fresh opaque API token (URL-safe)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Tokens are stored as a salted SHA-256 (fast lookup, not user passwords)."""
    return hashlib.sha256(token.encode()).hexdigest()


def constant_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
