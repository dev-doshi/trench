"""Minimal BIND-style zonefile parser (common RR types).

Supports $ORIGIN, $TTL, @ / blank owner continuation, and A AAAA NS CNAME DNAME
PTR MX TXT SRV CAA SOA records. Enough to load zones from disk and for tests.
"""
from __future__ import annotations

from ..wire import rdata as R
from ..wire.name import Name
from ..wire.rrtypes import type_from_text
from .zone import Zone


def parse_zonefile(text: str, origin: str) -> Zone:
    org = Name.from_text(origin)
    zone = Zone(org)
    default_ttl = 3600
    last_owner = org

    for raw in _logical_lines(text):
        line = raw.split(";")[0].rstrip()
        if not line.strip():
            continue
        if line.startswith("$ORIGIN"):
            # Only the suffix for relative owner names. Reassigning zone.origin
            # moved the apex, so a legal file that switches $ORIGIN partway left
            # zone.soa (which reads records[origin]) returning None — and with
            # it AXFR, dynamic UPDATE, and every negative answer's authority
            # section quietly broke for that zone.
            org = Name.from_text(line.split()[1])
            continue
        if line.startswith("$TTL"):
            default_ttl = _ttl(line.split()[1])
            continue

        owner, rest = _owner(line, last_owner, org)
        last_owner = owner
        toks = rest.split()
        ttl = default_ttl
        i = 0
        if toks and toks[i].isdigit():
            ttl = int(toks[i]); i += 1
        if i < len(toks) and toks[i].upper() in ("IN", "CH", "HS"):
            i += 1
        if i >= len(toks):
            continue
        rtype_s = toks[i].upper(); i += 1
        rdata_toks = toks[i:]
        rd = _rdata(rtype_s, rdata_toks, org)
        if rd is not None:
            zone.add(owner, int(type_from_text(rtype_s)), rd, ttl)
    return zone


def _logical_lines(text: str):
    """Join parenthesized multi-line records (used by SOA)."""
    buf = ""
    depth = 0
    for line in text.splitlines():
        code = line.split(";")[0]
        depth += code.count("(") - code.count(")")
        buf += " " + line.replace("(", " ").replace(")", " ")
        if depth <= 0:
            yield buf.strip()
            buf = ""
            depth = 0


def _owner(line: str, last: Name, org: Name) -> tuple[Name, str]:
    if line[0].isspace():
        return last, line.strip()
    owner_s, _, rest = line.partition(" ") if " " in line else line.partition("\t")
    if owner_s == "@":
        return org, rest.strip()
    if owner_s.endswith("."):
        return Name.from_text(owner_s), rest.strip()
    return Name.from_text(f"{owner_s}.{org.to_text()}"), rest.strip()


def _qualify(s: str, org: Name) -> Name:
    if s == "@":
        return org
    if s.endswith("."):
        return Name.from_text(s)
    return Name.from_text(f"{s}.{org.to_text()}")


def _ttl(s: str) -> int:
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if s and s[-1].lower() in units:
        return int(s[:-1]) * units[s[-1].lower()]
    return int(s)


def _rdata(rtype: str, toks: list[str], org: Name):
    try:
        if rtype == "A":
            return R.A(toks[0])
        if rtype == "AAAA":
            return R.AAAA(toks[0])
        if rtype in ("NS", "PTR", "CNAME", "DNAME"):
            cls = {"NS": R.NS, "PTR": R.PTR, "CNAME": R.CNAME, "DNAME": R.DNAME}[rtype]
            return cls(_qualify(toks[0], org))
        if rtype == "MX":
            return R.MX(int(toks[0]), _qualify(toks[1], org))
        if rtype == "SRV":
            return R.SRV(int(toks[0]), int(toks[1]), int(toks[2]), _qualify(toks[3], org))
        if rtype == "TXT":
            text = " ".join(toks).strip('"')
            return R.TXT([text.encode()])
        if rtype == "CAA":
            return R.CAA(int(toks[0]), toks[1].encode(), " ".join(toks[2:]).strip('"').encode())
        if rtype == "SOA":
            mname = _qualify(toks[0], org)
            rname = _qualify(toks[1], org)
            nums = [int(x) for x in toks[2:7]]
            return R.SOA(mname, rname, *nums)
    except (IndexError, ValueError):
        return None
    return None
