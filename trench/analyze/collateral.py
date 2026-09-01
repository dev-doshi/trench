"""Collateral-damage detection: which blocks are breaking something real.

An aggressive blocklist inevitably catches domains that a working service
depends on, and the failure is silent — a photo library stops syncing, a chat
app spins. Every other resolver shows blocked domains ranked by hit count,
which cannot distinguish "an ad call was blocked, nobody cared" from "an app
has been retrying for an hour".

Client *behaviour* separates them cleanly. Software retries what it needs:
a broken dependency produces tight, repeated lookups from the same client. An
ad or telemetry beacon is fired once and forgotten. So instead of counting
hits, this measures the shape of the retries:

    api.apple-cloudkit.com   8 lookups / 267s, gaps ~30s   -> iCloud retrying
    ads.doubleclick.net      2 lookups / 853s              -> working as intended

Deliberately deterministic and evidence-first. It ranks *suspects* and shows
the reasoning; it never edits policy on its own. A detector that silently
unblocks domains would be a way to attack the blocklist.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

# A retry loop is tight; an unrelated second visit hours later is not.
RETRY_GAP_S = 180.0
# Dual-stack clients fire A and AAAA for the same name in the same instant, and
# some resolvers duplicate a query across sockets. Those are one attempt, not a
# retry, so gaps below this are ignored when counting.
MIN_RETRY_GAP_S = 1.0
# Two lookups can be coincidence. Three with short gaps is a pattern.
MIN_RETRIES = 2
# Buckets used to tell "one bad minute" from "broken all afternoon".
PERSISTENCE_BUCKET_S = 600.0


@dataclass
class CollateralFinding:
    domain: str
    hits: int
    clients: list[str]
    span_s: float
    retries: int                 # same-client lookups within RETRY_GAP_S
    median_gap_s: float
    buckets: int                 # distinct 10-min windows it recurred in
    score: float
    severity: str                # "high" | "medium"
    rule: str = ""               # the blocklist rule that matched
    source: str = ""             # which list it came from
    evidence: str = ""

    def to_json(self) -> dict:
        return {
            "domain": self.domain, "hits": self.hits, "clients": self.clients,
            "client_count": len(self.clients), "span_s": round(self.span_s, 1),
            "retries": self.retries, "median_gap_s": round(self.median_gap_s, 1),
            "buckets": self.buckets, "score": round(self.score, 2),
            "severity": self.severity, "rule": self.rule, "source": self.source,
            "evidence": self.evidence, "suggested_action": f"allow {self.domain}",
        }


@dataclass
class _Acc:
    times: list[float] = field(default_factory=list)
    # keyed by (client, qtype): an A and an AAAA lookup are separate series, so
    # a dual-stack pair never looks like one query retrying the other
    by_series: dict[tuple[str, str], list[float]] = field(
        default_factory=lambda: defaultdict(list))
    clients: set[str] = field(default_factory=set)
    rule: str = ""
    source: str = ""


def _median(xs: list[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2


def analyze_collateral(rows: list[dict], *, min_retries: int = MIN_RETRIES,
                       retry_gap_s: float = RETRY_GAP_S,
                       exclude: set[str] | None = None,
                       limit: int = 50) -> list[CollateralFinding]:
    """Rank blocked domains by how strongly client behaviour suggests breakage.

    `rows` are query-log records (ts in microseconds). Only blocked rows are
    considered; anything in `exclude` (already allowlisted) is skipped.
    """
    exclude = exclude or set()
    acc: dict[str, _Acc] = defaultdict(_Acc)
    for r in rows:
        if r.get("action") not in ("blocked", "block"):
            continue
        name = (r.get("qname") or "").lower().rstrip(".")
        if not name or name in exclude:
            continue
        ts = float(r.get("ts") or 0) / 1e6
        client = r.get("client_ip") or "?"
        a = acc[name]
        a.times.append(ts)
        a.clients.add(client)
        a.by_series[(client, r.get("qtype") or "")].append(ts)
        a.rule = a.rule or (r.get("rule") or "")
        a.source = a.source or (r.get("source") or "")

    findings: list[CollateralFinding] = []
    for domain, a in acc.items():
        times = sorted(a.times)
        hits = len(times)
        if hits < 2:
            continue  # a single lookup can never show a retry pattern

        # Retries are counted within a (client, qtype) series: two devices each
        # asking once is not a retry loop, and neither is one device asking for
        # A and AAAA at the same moment.
        retries = 0
        real_gaps: list[float] = []
        for series in a.by_series.values():
            series.sort()
            for prev, cur in zip(series, series[1:], strict=False):
                gap = cur - prev
                if MIN_RETRY_GAP_S <= gap <= retry_gap_s:
                    retries += 1
                    real_gaps.append(gap)
        if retries < min_retries:
            continue

        span = times[-1] - times[0]
        med = _median(real_gaps)
        buckets = len({int(t // PERSISTENCE_BUCKET_S) for t in times})
        clients = sorted(a.clients)

        # Score: how insistent the retries are, how tight they are, how long the
        # problem persisted, and how many devices it affects. Log-damped so one
        # very chatty client cannot dominate the ranking.
        tightness = 1.0 if med <= 0 else min(1.0, retry_gap_s / max(med, 1.0))
        score = (math.log1p(retries) * 2.0
                 + tightness * 1.5
                 + math.log1p(buckets)
                 + math.log1p(len(clients)) * 1.5)
        severity = "high" if (retries >= 3 and buckets >= 2) or retries >= 6 else "medium"

        per_min = hits / (span / 60) if span > 30 else float(hits)
        findings.append(CollateralFinding(
            domain=domain, hits=hits, clients=clients, span_s=span, retries=retries,
            median_gap_s=med, buckets=buckets, score=score, severity=severity,
            rule=a.rule, source=a.source,
            evidence=(f"{hits} blocked lookups from {len(clients)} client"
                      f"{'' if len(clients) == 1 else 's'} over {_dur(span)}, "
                      f"{retries} retried within {int(retry_gap_s)}s "
                      f"(typical gap {int(med)}s, {per_min:.1f}/min) — "
                      f"the client keeps asking, which is what software does when "
                      f"something it needs is failing."),
        ))

    findings.sort(key=lambda f: (-f.score, -f.hits))
    return findings[:limit]


def _dur(s: float) -> str:
    if s < 90:
        return f"{int(s)}s"
    if s < 5400:
        return f"{int(s / 60)}m"
    return f"{s / 3600:.1f}h"


async def collateral_from_querylog(querylog, *, hours: float = 24.0,
                                   exclude: set[str] | None = None,
                                   limit: int = 50, scan: int = 20000):
    """Pull recent blocked queries and analyze them."""
    import time
    since = int((time.time() - hours * 3600) * 1_000_000)
    rows = await querylog.search(action="blocked", since=since, limit=scan)
    return analyze_collateral(rows, exclude=exclude, limit=limit)
