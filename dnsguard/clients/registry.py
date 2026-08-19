"""Resolve a request to a Client + effective Policy.

Match order: exact IP -> CIDR -> ClientID (encrypted-transport token) -> MAC
(best-effort ARP) -> default. Results are memoized per (ip, client_id).
"""
from __future__ import annotations

import ipaddress
from collections import OrderedDict

from ..log import get
from .model import Client, Policy

log = get("clients")


class ClientRegistry:
    def __init__(self, clients: list[Client], default: Policy):
        self.default = default
        self.exact: dict[str, Client] = {}
        self.cidrs: list[tuple[ipaddress._BaseNetwork, Client]] = []
        self.by_clientid: dict[str, Client] = {}
        self.by_mac: dict[str, Client] = {}
        for c in clients:
            if c.ident_type == "ip":
                self.exact[c.ident] = c
            elif c.ident_type == "cidr":
                try:
                    self.cidrs.append((ipaddress.ip_network(c.ident, strict=False), c))
                except ValueError:
                    log.warning("bad CIDR client ident %s", c.ident)
            elif c.ident_type in ("clientid", "token"):
                self.by_clientid[c.ident] = c
            elif c.ident_type == "mac":
                self.by_mac[c.ident.lower()] = c
        # Keyed on (client_ip, client_id): both come off the wire. The old
        # 100k ceiling simply *stopped caching* once reached, so a spoofed-source
        # flood not only filled it but permanently evicted every real client
        # from the fast path — and each subsequent miss paid a full _resolve,
        # including the ARP lookup below.
        self._cache: OrderedDict[tuple[str, str], Policy] = OrderedDict()
        self.max_cache = 4096

    def identify(self, client_ip: str, client_id: str = "") -> Policy:
        key = (client_ip, client_id)
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            return cached
        policy = self._resolve(client_ip, client_id)
        self._cache[key] = policy
        while len(self._cache) > self.max_cache:
            self._cache.popitem(last=False)
        return policy

    def _resolve(self, client_ip: str, client_id: str) -> Policy:
        if client_id and client_id in self.by_clientid:
            return self.by_clientid[client_id].policy
        c = self.exact.get(client_ip)
        if c is not None:
            return c.policy
        try:
            ip = ipaddress.ip_address(client_ip)
            for net, client in self.cidrs:
                if ip in net:
                    return client.policy
        except ValueError:
            pass
        if self.by_mac:
            mac = _arp_lookup(client_ip)
            if mac and mac in self.by_mac:
                return self.by_mac[mac].policy
        return self.default

    def invalidate(self) -> None:
        self._cache.clear()

    @classmethod
    def default_policy(cls, cfg) -> Policy:
        fc = cfg.filtering
        return Policy(
            name="default", block=True,
            safe_search=fc.safe_search, safe_browse=fc.safe_browse,
            parental=fc.parental, services=frozenset(fc.services),
            ctags=frozenset(fc.ctags),
        )

    @classmethod
    def from_config(cls, cfg, extra_clients: list[Client] | None = None) -> ClientRegistry:
        fc = cfg.filtering
        default = cls.default_policy(cfg)
        clients: list[Client] = []
        for c in cfg.clients:
            pol = Policy(
                name=c.name or c.ident, block=c.block,
                ctags=frozenset(c.tags),
                safe_search=c.safe_search if c.safe_search is not None else fc.safe_search,
                safe_browse=c.safe_browse if c.safe_browse is not None else fc.safe_browse,
                parental=c.parental if c.parental is not None else fc.parental,
                services=frozenset(c.services) if c.services else frozenset(fc.services),
                upstream_group=c.upstream_group,
            )
            clients.append(Client(c.ident, c.type, c.name, pol))
        if extra_clients:
            clients.extend(extra_clients)      # DB-managed clients override config on same ident
        return cls(clients, default)

    @staticmethod
    def client_from_row(cfg, row) -> Client:
        """Build a Client from a `client` table row (policy stored as JSON)."""
        import json
        fc = cfg.filtering
        try:
            ov = json.loads(row["policy"]) if row["policy"] else {}
        except (ValueError, TypeError):
            ov = {}
        pol = Policy(
            name=row["name"] or row["ident"],
            block=bool(ov.get("block", True)),
            ctags=frozenset(ov.get("tags", [])),
            safe_search=bool(ov.get("safe_search", fc.safe_search)),
            safe_browse=bool(ov.get("safe_browse", fc.safe_browse)),
            parental=bool(ov.get("parental", fc.parental)),
            services=frozenset(ov.get("services", fc.services)),
            upstream_group=ov.get("upstream_group", ""),
        )
        return Client(row["ident"], row["ident_type"], row["name"] or "", pol)


#: MAC addresses from the OS neighbour table, refreshed on a timer rather than
#: looked up per query. `identify` runs on the hot path inside the event loop,
#: and the old implementation forked `arp` there: one client configured
#: `type: mac` meant every query from an unknown source forked a process and
#: could stall every worker's loop for up to a second, which a spoofed-source
#: flood turns into a fork bomb.
_NEIGHBOURS: dict[str, str] = {}
_NEIGHBOURS_AT = 0.0
NEIGHBOUR_TTL = 30.0


def _arp_lookup(ip: str) -> str | None:
    """The cached MAC for `ip`, or None. Never blocks and never forks."""
    return _NEIGHBOURS.get(ip)


def refresh_neighbours(timeout: float = 2.0) -> int:
    """Reload the neighbour table. Blocking: call it from a worker thread.

    Reads the whole table in one pass rather than one process per address.
    """
    import subprocess
    import time as _t
    global _NEIGHBOURS, _NEIGHBOURS_AT
    table: dict[str, str] = {}
    for argv in (["ip", "neigh", "show"], ["arp", "-an"]):
        try:
            out = subprocess.run(argv, capture_output=True, text=True,
                                 timeout=timeout)
        except Exception:
            continue
        if out.returncode != 0 or not out.stdout:
            continue
        for line in out.stdout.splitlines():
            ip = mac = ""
            for tok in line.replace("(", " ").replace(")", " ").split():
                if not ip and tok.count(".") == 3 and tok[0].isdigit():
                    ip = tok
                elif not ip and ":" in tok and tok.count(":") > 5:
                    pass
                elif ":" in tok and len(tok) >= 11 and tok.count(":") == 5:
                    mac = tok.lower()
            if ip and mac:
                table[ip] = mac
        if table:
            break
    _NEIGHBOURS = table
    _NEIGHBOURS_AT = _t.time()
    return len(table)
