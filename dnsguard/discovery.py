"""Telling clients this resolver speaks encrypted DNS, so they use it.

Windows 11 and Apple devices send a SVCB query for `_dns.resolver.arpa` when
they join a network, asking the local resolver whether it has an encrypted
endpoint. DNSGuard runs DoT, DoH, DoQ and DoH3 and, until now, answered that
question with nothing — so every device kept using plaintext Do53, or went and
found a public resolver of its own.

Two mechanisms, both from November 2023, and they are the same information
delivered by different means:

  * **DDR** (RFC 9462): answer the `_dns.resolver.arpa` SVCB query with one
    ServiceMode record per encrypted endpoint.
  * **DNR** (RFC 9463): hand the same thing out in the DHCP lease, so a client
    is configured before it asks anything at all.

The part that decides whether this works is the certificate, not the record.
A client only *uses* a designation it can authenticate:

  * Designating by name (what both mechanisms here do) means the client checks
    the TLS certificate against `discovery.hostname`. Use a name you own,
    certify it with the ACME dns-01 flow this server already implements, and
    point it at the LAN address. That is a publicly trusted certificate for a
    private address, with no inbound reachability required.
  * Designating by IP would need the resolver's address in a certificate SAN.
    Let's Encrypt issues IP certificates, but only through http-01 and
    tls-alpn-01 — dns-01 cannot prove control of an address — and no CA will
    ever issue for 192.168.x.x. So there is no IP path on a home LAN, and
    `discovery.hostname` is required rather than optional.

Get that wrong and clients silently ignore the record; there is no error to
see. Hence the startup check in `Discovery.problems()`.
"""
from __future__ import annotations

import ipaddress
import struct

from .log import get
from .wire import RR, Class, Message, Type
from .wire import rdata as R
from .wire.name import Name
from .wire.rrtypes import Flags, Rcode

log = get("discovery")

#: The name clients ask. Fixed by RFC 9462; nothing else is answered here.
DDR_QNAME = "_dns.resolver.arpa"

#: SvcParamKeys used below (RFC 9460 §14.3).
KEY_ALPN, KEY_PORT, KEY_DOHPATH = 1, 3, 7

_U16 = struct.Struct("!H")


def _alpn(*protocols: str) -> bytes:
    """The `alpn` SvcParamValue: each protocol as a length-prefixed string."""
    out = bytearray()
    for proto in protocols:
        raw = proto.encode()
        out.append(len(raw))
        out += raw
    return bytes(out)


def build_params(pairs) -> bytes:
    """SvcParams wire form: ascending key order, as RFC 9460 §2.2 requires."""
    out = bytearray()
    for key, value in sorted(pairs, key=lambda kv: kv[0]):
        out += _U16.pack(key)
        out += _U16.pack(len(value))
        out += value
    return bytes(out)


class Endpoint:
    """One encrypted way in, as both a SVCB record and a DNR instance."""

    __slots__ = ("kind", "port", "priority", "path")

    #: alpn tokens per transport. DoH3 advertises h3; DoH advertises h2, which
    #: is what this server actually speaks over TLS.
    ALPN = {"dot": ("dot",), "doh": ("h2",), "doq": ("doq",), "doh3": ("h3",)}
    DEFAULT_PORT = {"dot": 853, "doh": 443, "doq": 853, "doh3": 443}

    def __init__(self, kind: str, port: int, priority: int, path: str = ""):
        self.kind = kind
        self.port = port
        self.priority = priority
        self.path = path

    def params(self) -> bytes:
        pairs = [(KEY_ALPN, _alpn(*self.ALPN[self.kind]))]
        # The port is only sent when it is not the default for the transport;
        # a client reading a redundant port is fine, but a wrong one is fatal
        # and this keeps the record honest about what is non-standard here.
        if self.port != self.DEFAULT_PORT[self.kind]:
            pairs.append((KEY_PORT, _U16.pack(self.port)))
        if self.kind in ("doh", "doh3") and self.path:
            pairs.append((KEY_DOHPATH, self.path.encode()))
        return build_params(pairs)


class Discovery:
    """Builds the DDR answer and the DNR option from the running config."""

    def __init__(self, hostname: str, endpoints: list[Endpoint], *,
                 ttl: int = 300, addresses: list[str] | None = None):
        self.hostname = hostname.strip(".").lower()
        self.endpoints = endpoints
        self.ttl = ttl
        self.addresses = list(addresses or [])

    # ------------------------------------------------------------ diagnostics
    def problems(self) -> list[str]:
        """Reasons clients would ignore what we publish. Logged at startup.

        A DDR record that no client acts on is worse than none: it looks
        configured and changes nothing.
        """
        out = []
        if not self.hostname:
            out.append("discovery.hostname is empty; clients authenticate the "
                       "designation against that name and will ignore a record "
                       "without one")
        if not self.endpoints:
            out.append("no encrypted listener is enabled, so there is nothing "
                       "to advertise (enable server.dot / doh / doq / doh3)")
        return out

    @property
    def usable(self) -> bool:
        return not self.problems()

    # -------------------------------------------------------------------- DDR
    def answers(self, query: Message) -> Message | None:
        """The SVCB answer for `_dns.resolver.arpa`, or None if not that query.

        NODATA — not NXDOMAIN — for other types under the name: the name exists,
        it just has nothing of that type, and NXDOMAIN would tell a client the
        whole special-use name is absent.
        """
        q = query.question
        if q is None or not self.usable:
            return None
        name = q.name.to_text().strip(".").lower()
        if name != DDR_QNAME:
            return None
        resp = query.reply(Rcode.NOERROR)
        resp.set_flag(Flags.AA, True)
        if q.rtype not in (Type.SVCB, Type.ANY):
            return resp                     # NODATA
        target = Name.from_text(self.hostname + ".")
        for ep in self.endpoints:
            resp.answers.append(RR(q.name, Type.SVCB, Class.IN, self.ttl,
                                   R.SVCB(ep.priority, target, ep.params())))
        return resp

    # -------------------------------------------------------------------- DNR
    def dhcp_option(self) -> bytes:
        """OPTION_V4_DNR (162) payload: one DNR instance per endpoint.

        Layout per RFC 9463 §3.1, and the reason each field is where it is:

            DNR Instance Data Length   2 octets   (everything after this field)
            Service Priority           2 octets
            ADN Length                 1 octet
            authentication-domain-name variable   (DNS wire format, not text)
            Addr Length                1 octet
            IPv4 Address(es)           variable   (multiple of 4)
            Service Parameters         variable

        `ipv4hint`/`ipv6hint` are forbidden inside those SvcParams — the
        addresses field above supersedes them — so `Endpoint.params()` never
        emits either.
        """
        if not self.usable:
            return b""
        # `Name.key` is the lowercased, uncompressed wire form — which is
        # exactly what the option wants; DHCP has no message to compress into.
        adn = Name.from_text(self.hostname + ".").key
        addrs = b"".join(ipaddress.IPv4Address(a).packed for a in self.addresses
                         if _is_v4(a))
        out = bytearray()
        for ep in self.endpoints:
            body = bytearray()
            body += _U16.pack(ep.priority)
            body.append(len(adn))
            body += adn
            body.append(len(addrs))
            body += addrs
            body += ep.params()
            out += _U16.pack(len(body))
            out += body
        return bytes(out)


def _is_v4(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).version == 4
    except ValueError:
        return False


def from_config(config) -> Discovery | None:
    """Build a `Discovery` from `server.discovery`, or None when it is off."""
    disc = getattr(config.server, "discovery", None)
    if disc is None or not disc.enabled:
        return None
    endpoints: list[Endpoint] = []
    server = config.server
    for kind, priority in (("dot", 1), ("doh", 2), ("doq", 3), ("doh3", 4)):
        listener = getattr(server, kind, None)
        if listener is None or not getattr(listener, "enabled", False):
            continue
        endpoints.append(Endpoint(
            kind, getattr(listener, "port", Endpoint.DEFAULT_PORT[kind]), priority,
            path=_doh_path(listener) if kind in ("doh", "doh3") else ""))
    found = Discovery(disc.hostname, endpoints, ttl=disc.ttl,
                      addresses=list(disc.addresses))
    for problem in found.problems():
        log.warning("encrypted-DNS discovery is enabled but %s", problem)
    return found


def _doh_path(listener) -> str:
    """The DoH URI template. `dohpath` is a template, so the query part matters:
    a client that gets a bare path has nowhere to put the question."""
    path = getattr(listener, "path", "/dns-query") or "/dns-query"
    return path + "{?dns}"
