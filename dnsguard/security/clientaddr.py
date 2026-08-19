"""Deciding which address a request really came from.

`X-Forwarded-For` is written by whoever sent the request. Believing it
unconditionally — which both HTTP frontends did, in two separate copies of the
same helper — hands the client a free choice of identity, and that identity is
not cosmetic: it selects the per-client filtering policy, the rate-limit bucket,
the login-failure counter that drives account lockout, and the subnet forwarded
upstream in ECS. One header rotated per request defeats all four.

So the header counts only when the peer that delivered it is a proxy the
operator named. With no proxies configured the socket address is the answer,
which is correct for every deployment that does not have one.
"""
from __future__ import annotations

import ipaddress

from aiohttp import web

from ..log import get

log = get("clientaddr")

#: Where each HTTP frontend stores its parsed `security.trusted_proxies`, so
#: `client_ip` can find it without every call site threading it through.
TRUSTED_KEY: web.AppKey = web.AppKey("dnsguard_trusted_proxies")


class TrustedProxies:
    """Membership test for `security.trusted_proxies`, parsed once."""

    __slots__ = ("_nets",)

    def __init__(self, entries=()):
        self._nets = []
        for entry in entries or ():
            try:
                self._nets.append(ipaddress.ip_network(str(entry).strip(),
                                                       strict=False))
            except ValueError:
                log.warning("ignoring unparseable trusted_proxies entry %r", entry)

    def __bool__(self) -> bool:
        return bool(self._nets)

    def __contains__(self, ip: str) -> bool:
        if not self._nets:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._nets)


def peer_ip(request) -> str:
    """The socket address the request arrived on."""
    peer = request.transport.get_extra_info("peername") if request.transport else None
    return peer[0] if peer else "?"


def client_ip(request, trusted: TrustedProxies | None = None) -> str:
    """The client's address, honouring X-Forwarded-For only from a trusted peer.

    The left-most entry is taken, and only when the immediate peer is trusted.
    A longer chain is not walked: every hop past the first is written by
    something we have not authenticated.
    """
    if trusted is None:
        trusted = request.app.get(TRUSTED_KEY)
    peer = peer_ip(request)
    if not trusted or peer not in trusted:
        return peer
    xff = request.headers.get("X-Forwarded-For")
    if not xff:
        return peer
    candidate = xff.split(",")[0].strip()
    if not candidate:
        return peer
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return peer          # not an address; the proxy is misconfigured
    return candidate
