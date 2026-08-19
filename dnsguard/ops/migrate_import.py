"""Import configuration from PiHole (gravity.db) and AdGuard Home (YAML)."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ImportResult:
    sources: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)   # adblock-syntax / regex

    def summary(self) -> str:
        return (f"{len(self.sources)} adlists, {len(self.deny)} deny, "
                f"{len(self.allow)} allow, {len(self.rules)} rules")


def import_pihole(gravity_db: str) -> ImportResult:
    """Read a PiHole v5/v6 gravity.db. domainlist.type: 0/2 = allow exact/regex,
    1/3 = deny exact/regex."""
    res = ImportResult()
    con = sqlite3.connect(f"file:{gravity_db}?mode=ro", uri=True)
    try:
        for (addr,) in con.execute("SELECT address FROM adlist WHERE enabled=1"):
            res.sources.append(addr)
        for dtype, domain in con.execute("SELECT type, domain FROM domainlist WHERE enabled=1"):
            if dtype == 0:
                res.allow.append(domain)
            elif dtype == 1:
                res.deny.append(domain)
            elif dtype == 2:
                res.rules.append(f"@@/{domain}/")
            elif dtype == 3:
                res.rules.append(f"/{domain}/")
    finally:
        con.close()
    return res


def import_adguard(yaml_path: str) -> ImportResult:
    """Read AdGuardHome.yaml: filters[].url, whitelist_filters[].url, user_rules[]."""
    import yaml
    res = ImportResult()
    data = yaml.safe_load(Path(yaml_path).read_text()) or {}
    dns = data.get("filtering", data)  # newer configs nest under 'filtering'
    for f in (data.get("filters") or dns.get("filters") or []):
        if f.get("enabled", True) and f.get("url"):
            res.sources.append(f["url"])
    for f in (data.get("whitelist_filters") or []):
        if f.get("url"):
            res.sources.append(f["url"])
    for rule in (data.get("user_rules") or dns.get("user_rules") or []):
        rule = rule.strip()
        if not rule or rule.startswith("!"):
            continue
        if rule.startswith("@@"):
            res.allow.append(rule)
        else:
            res.rules.append(rule)
    return res
