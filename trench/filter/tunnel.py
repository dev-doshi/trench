"""DNS tunneling / exfiltration detection.

Malware uses DNS as a covert channel (iodine, dnscat2, DNS data exfil): data is
base32/hex-encoded into long, high-entropy subdomain labels and pulled out with
TXT/NULL/CNAME queries, often at high volume to one registrable domain. This
detector flags it structurally (per query) and volumetrically (rate to one
domain from one client) — no signature feed.
"""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque
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


def _registrable(qname: str) -> str:
    parts = qname.rstrip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else qname


def _hexish_ratio(s: str) -> float:
    if not s:
        return 0.0
    enc = sum(1 for c in s if c in "0123456789abcdefghijklmnopqrstuvwxyz=-")
    return enc / len(s)


class TunnelDetector:
    def __init__(self, *, threshold: float = 0.45, block: bool = False,
                 window: float = 60.0, rate_limit: int = 100, workers: int = 1):
        self.threshold = threshold
        self.block = block
        self.window = window
        self.workers = max(1, int(workers))
        # queries / window to one 2LD before the volumetric flag. Divided per
        # worker for the same reason as DGADetector.burst_min_names: each worker
        # only sees its share of a client's traffic, so an unscaled 100 means
        # 100 x N in aggregate before anything notices.
        self.rate_limit = max(2, round(rate_limit / self.workers))
        # Keyed on (client, registrable domain), both attacker-chosen. Unlike
        # DGADetector this had no ceiling at all, so one host cycling distinct
        # second-level domains retained a deque per name until the box died.
        self.max_tracked = 20_000
        self._seen: dict[tuple[str, str], deque] = defaultdict(deque)

    def _volumetric(self, client: str, reg: str, now: float) -> float:
        key = (client, reg)
        if key not in self._seen and len(self._seen) >= self.max_tracked:
            self._sweep(now)
        dq = self._seen[key]
        dq.append(now)
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.rate_limit:
            return min(0.4, 0.2 + (len(dq) - self.rate_limit) / (self.rate_limit * 5))
        return 0.0

    def _sweep(self, now: float) -> None:
        """Drop entries whose window has emptied; clear outright if that is not
        enough. This state is advisory, so losing it costs a detection delay,
        never correctness — the same trade DGADetector makes."""
        cutoff = now - self.window
        for key, dq in list(self._seen.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self._seen[key]
        if len(self._seen) >= self.max_tracked:
            self._seen.clear()

    def score(self, qname: str, qtype: int, client: str = "", now: float | None = None) -> float:
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
        s += self._volumetric(client, _registrable(name),
                              now if now is not None else time.time())
        return min(1.0, s)

    def inspect(self, qname: str, qtype: int, client: str = "",
                now: float | None = None) -> TunnelResult:
        sc = round(self.score(qname, qtype, client, now), 3)
        if sc >= self.threshold:
            return TunnelResult(True, sc, reason=f"DNS tunneling/exfil (score {sc:.2f})")
        return TunnelResult(False, sc)
