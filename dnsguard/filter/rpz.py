"""Minimal RPZ (Response Policy Zone, RFC-ish) parser.

Supports the common policy triggers used by threat-intel feeds:
    owner            CNAME .          -> NXDOMAIN  (block)
    owner            CNAME *.         -> NODATA
    owner            A 0.0.0.0        -> sinkhole  (block)
    *.owner          CNAME .          -> block subtree
Passthru rules (`CNAME rpz-passthru.`) become allow exceptions.
"""
from __future__ import annotations

import re

from .rule import Rewrite, Rule

_RR = re.compile(r"^(?P<owner>\S+)\s+(?:\d+\s+)?(?:IN\s+)?(?P<type>CNAME|A|AAAA)\s+(?P<data>\S+)",
                 re.IGNORECASE)


def looks_like_rpz(text: str) -> bool:
    head = text[:4000].lower()
    return ("soa" in head and ("rpz" in head or "in cname ." in head)) or "rpz-passthru" in head


def parse_rpz(text: str, source: str = "") -> list[Rule]:
    rules: list[Rule] = []
    origin = ""
    for raw in text.splitlines():
        line = raw.split(";")[0].strip()
        if not line:
            continue
        if line.upper().startswith("$ORIGIN"):
            origin = line.split()[1].rstrip(".").lower()
            continue
        if " SOA " in line.upper() or line.upper().startswith("@") or " NS " in line.upper():
            continue
        m = _RR.match(line)
        if not m:
            continue
        owner = m.group("owner").rstrip(".").lower()
        # the policy trigger is the owner name with the RPZ origin stripped
        if origin and owner.endswith("." + origin):
            owner = owner[: -(len(origin) + 1)]
        elif owner == origin:
            continue
        owner = owner.lstrip("*.")
        data = m.group("data").rstrip(".").lower()
        if not owner:
            continue
        if data in ("rpz-passthru", "rpz-passthru."):
            rules.append(Rule(raw=owner, block=False, important=True, suffix=owner, source=source))
        elif data in ("", "."):  # CNAME . -> NXDOMAIN
            rules.append(Rule(raw=owner, block=True, suffix=owner, source=source,
                              rewrite=Rewrite(rcode=3)))
        else:  # sinkhole address or CNAME target -> plain block
            rules.append(Rule(raw=owner, block=True, suffix=owner, source=source))
    return rules
