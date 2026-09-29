"""DHCP scope: address pool + reservations + lease bookkeeping (in-memory)."""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field


@dataclass
class Lease:
    ip: str
    mac: str
    hostname: str = ""
    expire: float = 0.0
    offered: bool = False         # an OFFER held for the client, not a lease yet


@dataclass
class Scope:
    network: str                      # e.g. 192.168.1.0/24
    range_start: str
    range_end: str
    router: str = ""
    dns: list[str] = field(default_factory=list)
    lease_time: int = 86400
    domain: str = "lan"
    reservations: dict[str, str] = field(default_factory=dict)   # mac -> ip
    # Above this many tracked MACs, expired leases are swept before allocating.
    # The table is keyed on a client-supplied chaddr, so it is only as bounded
    # as the sender chooses to be.
    max_leases: int = 4096
    # How long an OFFER holds its address. RFC 2131 has the client REQUEST it
    # within seconds; reserving it for the whole lease time let a burst of
    # DISCOVERs from made-up chaddrs empty a /24 for a day without ever
    # completing a handshake.
    offer_hold: int = 60
    # At most this share of the pool may be held by outstanding offers, so a
    # DISCOVER flood cannot take the addresses committed leases would use.
    offer_share: float = 0.25
    _leases: dict[str, Lease] = field(default_factory=dict)        # mac -> lease

    def _pool(self):
        start = int(ipaddress.IPv4Address(self.range_start))
        end = int(ipaddress.IPv4Address(self.range_end))
        return start, end

    def _in_use(self, now: float) -> set[str]:
        return ({lease.ip for lease in self._leases.values() if lease.expire > now}
                | set(self.reservations.values()))

    def allocate(self, mac: str, hostname: str = "", requested: str | None = None,
                 now: float | None = None, *, offer: bool = False) -> Lease | None:
        """The address for `mac`: committed as a lease, or with `offer` only
        held for `offer_hold` seconds while the client decides (DISCOVER)."""
        now = now if now is not None else time.time()
        mac = mac.lower()
        self._reap(now)
        existing = self._leases.get(mac)
        live = existing is not None and existing.expire > now
        if offer and live:
            return existing          # an offer never shortens a lease it repeats
        if mac in self.reservations:
            ip = self.reservations[mac]
            return self._grant(mac, ip, hostname, now, offer)
        if live and existing is not None:
            return self._grant(mac, existing.ip, hostname, now, offer)
        if offer and self._offers(now) >= self._offer_cap():
            return None
        in_use = self._in_use(now)
        # honor a valid request if free
        if requested and requested not in in_use and self._in_range(requested):
            return self._grant(mac, requested, hostname, now, offer)
        start, end = self._pool()
        for n in range(start, end + 1):
            ip = str(ipaddress.IPv4Address(n))
            if ip not in in_use:
                return self._grant(mac, ip, hostname, now, offer)
        return None  # pool exhausted

    def _offers(self, now: float) -> int:
        return sum(1 for lease in self._leases.values()
                   if lease.offered and lease.expire > now)

    def _offer_cap(self) -> int:
        start, end = self._pool()
        return max(4, int((end - start + 1) * self.offer_share))

    def _reap(self, now: float) -> None:
        """Drop expired leases before allocating.

        Nothing evicted this table, while `_in_use` rebuilt a set over all of it
        on every allocation — so a client cycling spoofed chaddrs across expiries
        grew it without bound *and* made every subsequent DHCP packet cost
        O(leases ever granted).
        """
        if len(self._leases) <= self.max_leases:
            return
        for mac in [m for m, lease in self._leases.items() if lease.expire <= now]:
            del self._leases[mac]

    def _in_range(self, ip: str) -> bool:
        return (int(ipaddress.IPv4Address(self.range_start))
                <= int(ipaddress.IPv4Address(ip))
                <= int(ipaddress.IPv4Address(self.range_end)))

    def _grant(self, mac: str, ip: str, hostname: str, now: float,
               offer: bool = False) -> Lease:
        hold = min(self.offer_hold, self.lease_time) if offer else self.lease_time
        lease = Lease(ip=ip, mac=mac, hostname=hostname, expire=now + hold,
                      offered=offer)
        self._leases[mac] = lease
        return lease

    def release(self, mac: str, ciaddr: str = "") -> str:
        """Drop a lease at the client's request.

        `ciaddr` must match the lease being released. RELEASE is unauthenticated
        and carries whatever chaddr the sender chose, so honouring it on the
        sender's word alone let any host on the LAN delete a neighbour's lease
        while that neighbour was still using the address — and then REQUEST the
        freed address for itself.

        Returns the address released, or "" when nothing was.
        """
        mac = mac.lower()
        held = self._leases.get(mac)
        if held is None:
            return ""
        if ciaddr and held.ip != ciaddr:
            return ""
        self._leases.pop(mac, None)
        return held.ip

    def active_leases(self, now: float | None = None) -> list[Lease]:
        now = now if now is not None else time.time()
        return [lease for lease in self._leases.values()
                if lease.expire > now and not lease.offered]
