"""DNS tunneling / exfiltration detection.

Malware uses DNS as a covert channel (iodine, dnscat2, DNS data exfil): data is
base32/hex-encoded into long, high-entropy subdomain labels and pulled out with
TXT/NULL/CNAME queries. This detector flags that shape per query — no
signature feed.

It used to add up to 0.4 for query *volume* to one "registrable" domain (the
last two labels) from one client. Busy is not suspicious: a phone syncing
through `*.s3.amazonaws.com`, a PTR sweep, an Apple device polling its push
hosts all crossed the rate, and one more trivial signal took them over the
threshold — on one deployment 96% of this detector's blocks scored exactly the
threshold that way. A tunnel moving data has the payload shape regardless.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from ..wire.rrtypes import Type

_NULL = 10  # query types NULL/TXT often carry tunneling payloads


@dataclass
class TunnelResult:
    suspicious: bool
    score: float
    reason: str = ""


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _hexish_ratio(s: str) -> float:
    if not s:
        return 0.0
    enc = sum(1 for c in s if c in "0123456789abcdefghijklmnopqrstuvwxyz=-")
    return enc / len(s)


class TunnelDetector:
    def __init__(self, *, threshold: float = 0.45, block: bool = False):
        self.threshold = threshold
        self.block = block

    def score(self, qname: str, qtype: int) -> float:
        name = qname.rstrip(".").lower()
        labels = name.split(".")
        if len(labels) < 2:
            return 0.0
        sub = "".join(labels[:-2])            # everything below the registrable domain
        if not sub:
            return 0.0
        maxlabel = max(len(la) for la in labels)
        total = len(name)
        ent = _entropy(sub)
        hexish = _hexish_ratio(sub)

        s = 0.0
        if maxlabel >= 30:
            s += 0.30 * min(1.0, (maxlabel - 30) / 33 + 0.4)
        if total >= 80:
            s += 0.20 * min(1.0, (total - 80) / 120 + 0.3)
        if ent >= 3.5:                          # high-entropy encoded payload
            s += 0.25 * min(1.0, (ent - 3.5) / 1.0 + 0.3)
        if hexish >= 0.9 and len(sub) >= 20:
            s += 0.15
        if qtype in (_NULL, Type.TXT) and len(sub) >= 20:
            s += 0.15                            # NULL/TXT carrying a long payload
        if len(labels) >= 6:
            s += 0.05
        return min(1.0, s)

    def inspect(self, qname: str, qtype: int, client: str = "") -> TunnelResult:
        sc = round(self.score(qname, qtype), 3)
        if sc >= self.threshold:
            return TunnelResult(True, sc, reason=f"DNS tunneling/exfil (score {sc:.2f})")
        return TunnelResult(False, sc)
