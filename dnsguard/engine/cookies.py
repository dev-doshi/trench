"""DNS Cookies (RFC 7873): a lightweight transaction mechanism that thwarts
off-path spoofing and denial-of-service amplification.

The server derives an 8-byte server cookie = HMAC(secret, client_cookie || client_ip)
and echoes client+server cookie in the response. A returning client that presents
a valid server cookie is proven to be on-path (not a spoofed source), which lets
us relax rate limiting and (optionally) refuse un-cookied UDP from new clients.
The secret rotates so old cookies expire.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time

from ..wire.rrtypes import EDNSOption

COOKIE = int(EDNSOption.COOKIE)
_ROTATE = 3600.0  # rotate the server secret hourly (keep previous for overlap)


class CookieJar:
    def __init__(self) -> None:
        self._secret = os.urandom(16)
        self._prev = self._secret
        self._rotated = time.monotonic()

    def _maybe_rotate(self) -> None:
        now = time.monotonic()
        if now - self._rotated >= _ROTATE:
            self._prev = self._secret
            self._secret = os.urandom(16)
            self._rotated = now

    def _server_cookie(self, client_cookie: bytes, client_ip: str, secret: bytes) -> bytes:
        return hmac.new(secret, client_cookie + client_ip.encode(), hashlib.sha256).digest()[:8]

    def make_response(self, client_cookie: bytes, client_ip: str) -> bytes:
        """Return the 16-byte client+server cookie to send back."""
        self._maybe_rotate()
        return client_cookie[:8] + self._server_cookie(client_cookie[:8], client_ip, self._secret)

    def valid(self, full_cookie: bytes, client_ip: str) -> bool:
        """True iff the presented server cookie matches (current or previous secret)."""
        if full_cookie is None or len(full_cookie) < 16:
            return False
        cc, sc = full_cookie[:8], full_cookie[8:16]
        for secret in (self._secret, self._prev):
            if hmac.compare_digest(sc, self._server_cookie(cc, client_ip, secret)):
                return True
        return False
