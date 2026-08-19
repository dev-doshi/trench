"""Filter rule model + $dnsrewrite parsing.

A Rule is the compiled form of one line from any supported dialect (hosts,
plain domain, Adblock DNS syntax, regex). The matcher consumes Rules; the
parser produces them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..wire import rdata as R
from ..wire.name import Name
from ..wire.rrtypes import Rcode, Type, type_from_text


@dataclass
class Rewrite:
    """Result of a $dnsrewrite modifier."""
    rcode: int | None = None          # REFUSED / NXDOMAIN / NOERROR
    rdata: R.Rdata | None = None      # forged answer (A/AAAA/CNAME/...)
    rtype: int = 0


@dataclass(slots=True)
class Rule:
    """One compiled rule.

    `slots=True` matters at this scale: a large aggregate blocklist is ~600k
    rules and a refresh holds two engines at once. Measured at ~310 B/rule
    without slots, which is ~190 MB per copy — on a box with a 955 MB ceiling
    that has already been OOM-killed.
    """
    raw: str
    block: bool = True                # False => exception (@@)
    # match forms (exactly one primary form set)
    suffix: str | None = None         # ||domain^ or hosts -> domain + subdomains
    exact: str | None = None          # |domain| -> exact only
    regex: re.Pattern | None = None   # /regex/
    # modifiers
    important: bool = False
    badfilter: bool = False
    # Each of $dnstype/$ctag/$client can list values to require and values to
    # exclude (`~value`). Both may appear on one rule: `$dnstype=A|AAAA|~HTTPS`.
    # Semantics follow AdGuard — an excluded value disqualifies the rule outright;
    # a required set, if present, must be satisfied.
    dnstypes: frozenset[int] | None = None       # restrict to these qtypes
    dnstypes_not: frozenset[int] | None = None   # $dnstype=~A — all but these
    ctags: frozenset[str] | None = None          # client tags (P4)
    ctags_not: frozenset[str] | None = None
    clients: frozenset[str] | None = None        # client idents: IP, CIDR or name
    clients_not: frozenset[str] | None = None
    denyallow: tuple[str, ...] = ()           # carve-outs (never block these)
    rewrite: Rewrite | None = None
    source: str = ""                  # list name (explainability)

    def key(self) -> str:
        """Identity for $badfilter matching (same pattern + type, opposite enable)."""
        base = self.suffix or self.exact or (self.regex.pattern if self.regex else "")
        return f"{int(self.block)}|{base}|{self.dnstypes}"


def parse_dnsrewrite(spec: str) -> Rewrite:
    """Parse a $dnsrewrite value. Forms:
        REFUSED | NXDOMAIN | NOERROR
        1.2.3.4               (A)        ::1 (AAAA)
        example.org           (CNAME)
        NOERROR;A;1.2.3.4     (explicit)
    """
    spec = spec.strip()
    up = spec.upper()
    if up in ("REFUSED", "NXDOMAIN", "NOERROR", "SERVFAIL"):
        if up == "NOERROR":
            return Rewrite(rcode=Rcode.NOERROR)
        return Rewrite(rcode=int(Rcode[up]))
    if ";" in spec:
        parts = spec.split(";")
        rcode_s, rtype_s = parts[0].strip().upper(), parts[1].strip().upper()
        value = parts[2].strip() if len(parts) > 2 else ""
        rd, rtype = _rdata_for(rtype_s, value)
        rcode = int(Rcode[rcode_s]) if rcode_s in Rcode.__members__ else Rcode.NOERROR
        return Rewrite(rcode=rcode, rdata=rd, rtype=rtype)
    # bare value: infer type
    if _is_ipv4(spec):
        return Rewrite(rdata=R.A(spec), rtype=Type.A)
    if ":" in spec and _is_ipv6(spec):
        return Rewrite(rdata=R.AAAA(spec), rtype=Type.AAAA)
    # treat as CNAME target
    return Rewrite(rdata=R.CNAME(Name.from_text(spec)), rtype=Type.CNAME)


def _rdata_for(rtype_s: str, value: str) -> tuple[R.Rdata | None, int]:
    if not value:
        return None, (type_from_text(rtype_s) if rtype_s else 0)
    rtype = type_from_text(rtype_s)
    if rtype == Type.A:
        return R.A(value), rtype
    if rtype == Type.AAAA:
        return R.AAAA(value), rtype
    if rtype == Type.CNAME:
        return R.CNAME(Name.from_text(value)), rtype
    if rtype == Type.TXT:
        return R.TXT([value.encode()]), rtype
    if rtype == Type.MX:
        pref, _, exch = value.partition(" ")
        return R.MX(int(pref or 0), Name.from_text(exch or value)), rtype
    return None, rtype


_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _is_ipv4(s: str) -> bool:
    return bool(_IPV4.match(s)) and all(0 <= int(p) <= 255 for p in s.split("."))


def _is_ipv6(s: str) -> bool:
    import socket
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        return False
