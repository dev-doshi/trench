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
    """Membership test for `security.trusted_proxies`, parsed on assignment."""

    __slots__ = ("_nets",)

    def __init__(self, entries=()):
        self._nets = []
        self.replace(entries)

    def replace(self, entries=()) -> None:
        """Re-parse in place.

        In place, and not by building a replacement, because this object is held
        in three spots at once — the frontend, the aiohttp app key, and any
        request already in flight. An aiohttp application is frozen once it is
        running, so the app key cannot be reassigned; mutating the one object
        every holder shares is what lets this setting change without a restart.
        """
        nets = []
        for entry in entries or ():
            try:
                nets.append(ipaddress.ip_network(str(entry).strip(), strict=False))
            except ValueError:
                log.warning("ignoring unparseable trusted_proxies entry %r", entry)
        self._nets = nets

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

    The header is read from the **right**, not the left. Both nginx's
    `$proxy_add_x_forwarded_for` and HAProxy's `forwardfor` *append* the address
    they saw, so a client that sends `X-Forwarded-For: 6.6.6.6` of its own makes
    the header read `6.6.6.6, <real client>`. Taking the left-most entry — what
    this did — hands that forged value straight to the login lockout counter,
    the per-client filtering policy, the rate-limit bucket and the ECS subnet
    sent upstream, so rotating one header per request defeats the lockout
    outright and lets any client wear another client's policy.

    Walking from the right and skipping hops that are themselves trusted
    proxies is correct for both conventions: with a proxy that overwrites the
    header there is one entry and it is the client; with one that appends, the
    entry the trusted proxy added is the last untrusted one.
    """
    if trusted is None:
        trusted = request.app.get(TRUSTED_KEY)
    peer = peer_ip(request)
    if not trusted or peer not in trusted:
        return peer
    xff = request.headers.get("X-Forwarded-For")
    if not xff:
        return peer
    for raw in reversed(xff.split(",")):
        candidate = raw.strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return peer      # not an address; the proxy is misconfigured
        if candidate in trusted:
            continue         # another hop we run; keep walking left
        return candidate
    # Every entry names a proxy we trust, so the header says nothing about who
    # the client is. The socket address is the only thing left that is true.
    return peer
