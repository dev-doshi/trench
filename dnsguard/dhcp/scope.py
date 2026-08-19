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
    _leases: dict[str, Lease] = field(default_factory=dict)        # mac -> lease

    def _pool(self):
        start = int(ipaddress.IPv4Address(self.range_start))
        end = int(ipaddress.IPv4Address(self.range_end))
        return start, end

    def _in_use(self, now: float) -> set[str]:
        return ({lease.ip for lease in self._leases.values() if lease.expire > now}
                | set(self.reservations.values()))

    def allocate(self, mac: str, hostname: str = "", requested: str | None = None,
                 now: float | None = None) -> Lease | None:
        now = now if now is not None else time.time()
        mac = mac.lower()
        if mac in self.reservations:
            ip = self.reservations[mac]
            return self._grant(mac, ip, hostname, now)
        existing = self._leases.get(mac)
        if existing and existing.expire > now:
            return self._grant(mac, existing.ip, hostname, now)
        in_use = self._in_use(now)
        # honor a valid request if free
        if requested and requested not in in_use and self._in_range(requested):
            return self._grant(mac, requested, hostname, now)
        start, end = self._pool()
        for n in range(start, end + 1):
            ip = str(ipaddress.IPv4Address(n))
            if ip not in in_use:
                return self._grant(mac, ip, hostname, now)
        return None  # pool exhausted

    def _in_range(self, ip: str) -> bool:
        return (int(ipaddress.IPv4Address(self.range_start))
                <= int(ipaddress.IPv4Address(ip))
                <= int(ipaddress.IPv4Address(self.range_end)))

    def _grant(self, mac: str, ip: str, hostname: str, now: float) -> Lease:
        lease = Lease(ip=ip, mac=mac, hostname=hostname, expire=now + self.lease_time)
        self._leases[mac] = lease
        return lease

    def release(self, mac: str) -> None:
        self._leases.pop(mac.lower(), None)

    def active_leases(self, now: float | None = None) -> list[Lease]:
        now = now if now is not None else time.time()
        return [lease for lease in self._leases.values() if lease.expire > now]
