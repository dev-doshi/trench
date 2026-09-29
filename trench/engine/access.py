"""Who may use this server as a recursive resolver over plain DNS.

A resolver bound to a LAN address answers whatever reaches that address, and
port forwards, a flat ISP network or an IPv6 address with no firewall in front
all put the internet within reach. Unrestricted, that is an open resolver: a
reflector for spoofed-source floods whose answers (ANY, DNSKEY, large TXT) are
many times the size of the question.

The default is what dnsmasq calls `local-service`: private and loopback
addresses, plus whatever networks are directly attached to this host. That last
part matters for IPv6, where a home LAN uses global addresses that no fixed list
of private ranges would contain.

Only the plaintext transports are gated. Encrypted DNS runs over a handshake a
spoofed source cannot complete, so it reflects nothing, and it is how a phone
away from home still reaches its own resolver. Authoritative zones stay open to
everyone: that is what serving a zone means, and an ACME dns-01 challenge is
checked by a CA somewhere on the internet.
"""
from __future__ import annotations

import ipaddress
import time

from ..log import get

log = get("access")

#: Transports the ACL applies to — the ones a spoofed source can reflect off.
PLAINTEXT = frozenset({"udp", "tcp"})

LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10",            # CGNAT, and Tailscale's tailnet addresses
    "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
))

#: A route shorter than this is not a LAN, whatever the routing table says. A
#: VPN that splits the default route into two /1s "on-link" would otherwise
#: allow the whole internet.
_MIN_PREFIX = {4: 8, 6: 32}

#: How often the attached networks are re-read when an unknown address asks.
REFRESH = 60.0
MAX_MEMO = 65536


def connected_networks() -> list:
    """Networks directly attached to this host (Linux; empty elsewhere)."""
    nets: list = []
    try:
        with open("/proc/net/route") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) < 8 or parts[2] != "00000000":
                    continue                    # via a gateway: not attached
                dest = ipaddress.IPv4Address(int(parts[1], 16).to_bytes(4, "little"))
                mask = ipaddress.IPv4Address(int(parts[7], 16).to_bytes(4, "little"))
                net = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
                if net.prefixlen >= _MIN_PREFIX[4]:
                    nets.append(net)
    except (OSError, ValueError):
        pass
    try:
        with open("/proc/net/ipv6_route") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 10 or set(parts[4]) != {"0"}:
                    continue
                plen = int(parts[1], 16)
                if plen < _MIN_PREFIX[6]:
                    continue
                net = ipaddress.ip_network(
                    f"{ipaddress.IPv6Address(bytes.fromhex(parts[0]))}/{plen}",
                    strict=False)
                if not net.is_multicast:
                    nets.append(net)
    except (OSError, ValueError):
        pass
    return nets


class RecursionAcl:
    """`allows(ip)` for `security.recursion_clients`.

    Empty is the local default above. Otherwise the entries are CIDRs taken
    literally, plus the word `local` for the default: `["local",
    "203.0.113.0/24"]` adds an office network, and `["0.0.0.0/0", "::/0"]` is a
    deliberate open resolver. Empty rather than unset means default because a
    settings form saved with the box blank must not lock the LAN out.
    """

    def __init__(self, entries=(), *, routes=connected_networks):
        entries = [str(e).strip() for e in (entries or ()) if str(e).strip()]
        self.auto = not entries or any(e.lower() == "local" for e in entries)
        nets = list(LOCAL_NETWORKS) if self.auto else []
        for entry in entries:
            if entry.lower() == "local":
                continue
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                log.warning("ignoring unparseable recursion_clients entry %r", entry)
        self.nets = nets
        self.open = any(n.prefixlen == 0 for n in nets if n.version == 4) and \
            any(n.prefixlen == 0 for n in nets if n.version == 6)
        self._routes = routes
        self._attached: list = []
        self._read_at = -REFRESH
        self._memo: dict[str, bool] = {}
        self._memo_at = time.monotonic()
        self.refused = 0

    def allows(self, ip: str) -> bool:
        if self.open:
            return True
        hit = self._memo.get(ip)
        if hit is not None:
            if not self.auto or time.monotonic() - self._memo_at < REFRESH:
                return hit
            self._memo.clear()      # attached networks may have changed since
            self._memo_at = time.monotonic()
        try:
            addr = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            return False
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        ok = any(addr in n for n in self.nets if n.version == addr.version)
        if not ok and self.auto:
            ok = self._attached_to(addr)
        if ok:
            # Only answers that are yes are remembered: a refusal costs the
            # sender a lookup each time, and the addresses a spoofed flood
            # rotates through must not be able to fill the table.
            if len(self._memo) >= MAX_MEMO:
                self._memo.clear()
            self._memo[ip] = True
        else:
            self.refused += 1
        return ok

    def _attached_to(self, addr) -> bool:
        now = time.monotonic()
        if now - self._read_at >= REFRESH:
            self._read_at = now
            try:
                attached = self._routes()
            except Exception:
                log.exception("could not read the attached networks")
                attached = []
            if attached != self._attached:
                self._attached = attached
                self._memo.clear()          # a network that went away is no longer local
        return any(addr in n for n in self._attached if n.version == addr.version)
