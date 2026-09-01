"""Which devices stopped talking to this resolver, and where they went instead.

Every filtering product ships the Firefox canary and treats encrypted-DNS bypass
as handled. It is not. An application with a hardcoded DoH endpoint never asks
the local resolver anything, so it leaves no trace in the one place the operator
looks — the query log — and the filtering silently stops applying to it.

The signal is the absence, and this resolver is unusually placed to read it:

  * the DHCP server knows a device exists and is renewing a lease;
  * the query log knows it has asked nothing for forty minutes;
  * and bypass usually announces itself on the way out, because a client must
    resolve `mozilla.cloudflare-dns.com` or `dns.google` **in plaintext**,
    through this server, before it can switch to talking to them directly.

So this keeps two cheap things per client: when it last asked anything, and
whether it has ever looked up a known encrypted-resolver endpoint. A device that
did the second and then went quiet is not idle; it has changed resolver. The
report says which, with the evidence, and stops there — nothing here blocks,
quarantines or rate-limits anything. Naming the device is the useful part; what
to do about it is the operator's call.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..log import get
from ..wire.name import suffixes

log = get("activity")

#: Hostnames a client resolves in plaintext *before* it can start using an
#: encrypted resolver directly: the bootstrap names of the public DoH/DoT/DoQ
#: services, plus the discovery names browsers use. Matched on the name and its
#: parent suffixes, so `chrome.cloudflare-dns.com` matches `cloudflare-dns.com`.
#:
#: This list is evidence, not policy. Resolving one of these is completely
#: normal — a browser checking whether its provider is reachable does it — and
#: it only becomes interesting alongside the silence that follows.
BOOTSTRAP_NAMES: frozenset[str] = frozenset({
    # Cloudflare
    "cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
    "security.cloudflare-dns.com", "family.cloudflare-dns.com",
    # Google
    "dns.google", "dns.google.com",
    # Quad9
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
    # AdGuard
    "dns.adguard.com", "dns.adguard-dns.com", "family.adguard-dns.com",
    "unfiltered.adguard-dns.com",
    # NextDNS / Control D / Mullvad / OpenDNS / others
    "dns.nextdns.io", "nextdns.io",
    "dns.controld.com", "freedns.controld.com",
    "dns.mullvad.net", "doh.mullvad.net",
    "doh.opendns.com", "dns.opendns.com",
    "doh.dns.sb", "dns.sb",
    "dnsforge.de", "doh.pub", "dot.pub",
    "dns.alidns.com",
    # Apple and Firefox discovery paths
    "doh.dns.apple.com", "mask.icloud.com", "mask-h2.icloud.com",
    "use-application-dns.net",
})

#: A device that has asked nothing for this long, while still present on the
#: network, is treated as quiet. Long enough that an idle phone with a warm
#: cache does not trip it on its own.
QUIET_AFTER = 30 * 60


@dataclass
class Device:
    ip: str
    first_seen: float = 0.0
    last_query: float = 0.0
    queries: int = 0
    # Encrypted-resolver bootstrap lookups: how many, which one last, and when.
    bootstrap_hits: int = 0
    bootstrap_last: str = ""
    bootstrap_at: float = 0.0
    # Set from DHCP: the device is demonstrably on the network right now.
    lease_seen: float = 0.0
    name: str = ""

    def quiet_for(self, now: float) -> float:
        return max(0.0, now - self.last_query) if self.last_query else 0.0

    def present(self, now: float, lease_window: float) -> bool:
        return bool(self.lease_seen) and (now - self.lease_seen) < lease_window


@dataclass
class Ledger:
    """Per-client activity, bounded by `max_devices` (LRU by last activity)."""

    quiet_after: float = QUIET_AFTER
    #: How long a DHCP lease renewal counts as "this device is here". Longer
    #: than a typical renewal interval, shorter than a lease.
    lease_window: float = 6 * 3600
    max_devices: int = 4096
    devices: dict[str, Device] = field(default_factory=dict)

    # ---------------------------------------------------------------- writing
    def note(self, client_ip: str, qname: str, now: float | None = None) -> None:
        """Record one query. On the hot path: two dict lookups and, for a name
        with N labels, at most N set lookups against a frozenset."""
        if not client_ip:
            return
        now = now or time.time()
        dev = self.devices.get(client_ip)
        if dev is None:
            dev = self.devices[client_ip] = Device(ip=client_ip, first_seen=now)
            self._evict()
        dev.last_query = now
        dev.queries += 1
        for suffix in suffixes(qname):
            if suffix in BOOTSTRAP_NAMES:
                dev.bootstrap_hits += 1
                dev.bootstrap_last = suffix
                dev.bootstrap_at = now
                break

    def note_lease(self, ip: str, hostname: str = "", now: float | None = None) -> None:
        """Record that DHCP just served this address — the device is here."""
        now = now or time.time()
        dev = self.devices.get(ip)
        if dev is None:
            dev = self.devices[ip] = Device(ip=ip, first_seen=now)
            self._evict()
        dev.lease_seen = now
        if hostname:
            dev.name = hostname

    def _evict(self) -> None:
        while len(self.devices) > self.max_devices:
            oldest = min(self.devices.values(),
                         key=lambda d: max(d.last_query, d.lease_seen))
            self.devices.pop(oldest.ip, None)

    # ---------------------------------------------------------------- reading
    def status(self, dev: Device, now: float) -> str:
        """One word for what this device is doing, in the strongest form the
        evidence supports.

        `bypassing` is only claimed when both halves are present: the device is
        demonstrably on the network *and* it went quiet after looking up an
        encrypted resolver. Everything weaker is reported as what it is.
        """
        quiet = dev.quiet_for(now) >= self.quiet_after or not dev.last_query
        present = dev.present(now, self.lease_window)
        if quiet and present and dev.bootstrap_hits:
            return "bypassing"
        if quiet and present:
            return "silent"
        if dev.bootstrap_hits and not quiet:
            return "resolver-curious"
        return "active"

    def report(self, now: float | None = None) -> list[dict]:
        """Every tracked device, most suspicious first.

        Deliberately a report and not an action: a sleeping laptop and a device
        that has switched to DoH look identical for the first half hour, and a
        resolver that punished the difference would be wrong regularly.
        """
        now = now or time.time()
        rank = {"bypassing": 0, "silent": 1, "resolver-curious": 2, "active": 3}
        rows: list[dict] = []
        for dev in self.devices.values():
            status = self.status(dev, now)
            rows.append({
                "ip": dev.ip,
                "name": dev.name,
                "status": status,
                "queries": dev.queries,
                "quiet_for": int(dev.quiet_for(now)),
                "first_seen": int(dev.first_seen),
                "last_query": int(dev.last_query),
                "encrypted_at": int(dev.bootstrap_at),
                "lease_seen": int(dev.lease_seen),
                "encrypted_resolver": dev.bootstrap_last,
                "encrypted_lookups": dev.bootstrap_hits,
                "evidence": self._evidence(dev, status, now),
            })
        rows.sort(key=lambda r: (rank.get(str(r["status"]), 9), -int(r["quiet_for"])))
        return rows

    def _evidence(self, dev: Device, status: str, now: float) -> str:
        if status == "active":
            return f"{dev.queries} queries, last {int(dev.quiet_for(now))}s ago"
        quiet = int(dev.quiet_for(now)) if dev.last_query else -1
        seen = int(now - dev.lease_seen) if dev.lease_seen else -1
        parts = []
        if quiet >= 0:
            parts.append(f"no queries for {quiet}s")
        else:
            parts.append("has never queried this resolver")
        if seen >= 0:
            parts.append(f"DHCP lease served {seen}s ago")
        if dev.bootstrap_hits:
            parts.append(f"looked up {dev.bootstrap_last} "
                         f"{dev.bootstrap_hits}x before going quiet")
        return "; ".join(parts)

    def device(self, ip: str, now: float | None = None) -> dict | None:
        dev = self.devices.get(ip)
        if dev is None:
            return None
        now = now or time.time()
        return next((r for r in self.report(now) if r["ip"] == ip), None)
