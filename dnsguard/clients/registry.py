"""Resolve a request to a Client + effective Policy.

Match order: exact IP -> CIDR -> ClientID (encrypted-transport token) -> MAC
(best-effort ARP) -> default. Results are memoized per (ip, client_id).
"""
from __future__ import annotations

import ipaddress

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
        self._cache: dict[tuple[str, str], Policy] = {}

    def identify(self, client_ip: str, client_id: str = "") -> Policy:
        key = (client_ip, client_id)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        policy = self._resolve(client_ip, client_id)
        if len(self._cache) < 100_000:
            self._cache[key] = policy
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


def _arp_lookup(ip: str) -> str | None:
    """Best-effort MAC from the OS neighbor table (LAN only). Cheap + cached upstream."""
    import subprocess
    try:
        out = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=1)
        for tok in out.stdout.split():
            if ":" in tok and len(tok) >= 11:
                return tok.lower()
    except Exception:
        return None
    return None
