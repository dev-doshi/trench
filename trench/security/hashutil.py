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


def hash_token(token: str, pepper: bytes) -> str:
    """Stored digest for an API token: keyed SHA-256, not a bare one.

    The docstring here used to claim "salted" over a plain `sha256(token)`,
    which was simply untrue — a database leak yielded directly precomputable
    digests. It was safe only because `new_token` happens to be 256-bit random,
    an invariant nothing enforced.

    `pepper` is required, and comes from `Database.secret("api_token")`. It used
    to be a module constant regenerated at import, which meant every token in
    the table stopped verifying the moment the process restarted — a stored
    credential that silently expired on reboot, with nothing to say so.
    """
    return hmac.new(pepper, token.encode(), hashlib.sha256).hexdigest()


def hash_identifier(value: str, salt: bytes) -> str:
    """A stable, non-reversible stand-in for one identifier.

    For query-log privacy level 2, where the point is to keep the *shape* of the
    traffic — the same domain reads as the same domain, so a count is still a
    count — while removing the name itself. Truncated to 128 bits: this is not a
    password, and a shorter column keeps the index small on an SD card.

    Salted per installation, so two Trenchs cannot be cross-referenced and a
    stolen database cannot be matched against a precomputed table of every
    domain in a public blocklist.
    """
    return hmac.new(salt, value.encode(), hashlib.sha256).hexdigest()[:32]

