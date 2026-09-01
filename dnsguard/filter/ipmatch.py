"""Blocking on the address in the answer, not just the name in the question.

Name matching alone has a hole every tracker and malware operator knows: the
name is cheap and disposable, the hosting is not. A domain generated an hour ago
appears in no list, but it resolves into the same handful of networks it did
yesterday. Blocklists of addresses and prefixes — Spamhaus DROP, Feodo, an
operator's own "nothing in this range" rule — are the answer to that, and every
competitor in this category can consume them.

Two entry points, deliberately sharing one matcher:

  * `filtering.ip_sources`, a list of files/URLs of addresses and CIDRs, in the
    same shape blocklists already come in;
  * RPZ's `rpz-ip` triggers, which encode a prefix in the owner name
    (`32.5.4.3.2.rpz-ip` is 2.3.4.5/32) and which the RPZ parser previously
    skipped, so an RPZ feed's address rules were silently ignored.

Matching is longest-prefix over a per-length dictionary rather than a trie: a
household list is thousands of prefixes, not millions, and there are only 33
possible IPv4 lengths — so this is a handful of dict lookups per answer, on a
path that has already spent a network round trip.
"""
from __future__ import annotations

import ipaddress
import re

from ..log import get
from ..wire import Message, Type

log = get("filter.ip")

#: `8.5.4.3.2.rpz-ip` -> prefix length 8, address 2.3.4.5 (RFC-less, but this is
#: the de-facto format BIND defined and every RPZ feed uses).
_RPZ_IP = re.compile(r"^(\d{1,3})\.(.+)\.rpz-ip$", re.IGNORECASE)


class IPMatcher:
    """A set of v4/v6 prefixes, with the source each came from for attribution."""

    __slots__ = ("v4", "v6", "size")

    def __init__(self) -> None:
        # prefix length -> {network int -> source label}
        self.v4: dict[int, dict[int, str]] = {}
        self.v6: dict[int, dict[int, str]] = {}
        self.size = 0

    def add(self, cidr: str, source: str = "") -> bool:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return False
        table = self.v4 if net.version == 4 else self.v6
        table.setdefault(net.prefixlen, {})[int(net.network_address)] = source
        self.size += 1
        return True

    def add_many(self, text: str, source: str = "") -> int:
        """Load a list file: one address or CIDR per line, `#`/`;` comments.

        Hosts-style and adblock-style lines are ignored rather than guessed at —
        an address list and a domain list are different files, and quietly
        half-reading one as the other is how a source ends up looking loaded
        while blocking nothing.
        """
        added = 0
        for raw in text.splitlines():
            line = raw.split("#")[0].split(";")[0].strip()
            if not line:
                continue
            token = line.split()[0]
            if self.add(token, source):
                added += 1
        return added

    def match(self, ip: str) -> str | None:
        """The source label of the most specific prefix containing `ip`, or None.

        Returns `""` for a match from an unlabelled source, so callers must test
        `is not None` rather than truthiness.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version == 4:
            table, bits, value = self.v4, 32, int(addr)
        else:
            table, bits, value = self.v6, 128, int(addr)
        if not table:
            return None
        for length in sorted(table, reverse=True):      # longest prefix wins
            mask = ((1 << length) - 1) << (bits - length) if length else 0
            hit = table[length].get(value & mask)
            if hit is not None:
                return hit
        return None

    def __bool__(self) -> bool:
        return self.size > 0


def rpz_ip_prefix(owner: str) -> str | None:
    """The CIDR encoded in an `rpz-ip` owner name, or None.

    `32.5.4.3.2.rpz-ip` -> `2.3.4.5/32`. IPv6 uses `zz` for the run of zeroes,
    exactly as BIND writes it.
    """
    m = _RPZ_IP.match(owner.strip(".").lower())
    if not m:
        return None
    length, rest = int(m.group(1)), m.group(2)
    parts = rest.split(".")
    try:
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            addr = ".".join(reversed(parts))
            return str(ipaddress.ip_network(f"{addr}/{length}", strict=False))
        # IPv6: reversed 16-bit groups, `zz` standing in for the zero run
        groups = list(reversed(parts))
        if "zz" in groups:
            cut = groups.index("zz")
            addr = ":".join(groups[:cut]) + "::" + ":".join(groups[cut + 1:])
        else:
            addr = ":".join(groups)
        return str(ipaddress.ip_network(f"{addr}/{length}", strict=False))
    except ValueError:
        return None


def answer_addresses(response: Message) -> list[str]:
    """Every A/AAAA address in the answer section, in order."""
    out = []
    for rr in response.answers:
        if rr.rtype in (Type.A, Type.AAAA):
            try:
                out.append(rr.rdata.to_text())
            except Exception:
                continue
    return out
