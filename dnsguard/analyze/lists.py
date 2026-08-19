"""Blocklist return-on-investment.

Stacking blocklists is free in the marketing copy and not free in RAM, and the
memory is spent whether or not a list ever blocks anything. Nothing in this space
tells you which of your lists actually earn it.

This pairs two facts the resolver already has:

  * how many domains each list *contributed* — the engine records the source of
    every block rule, and duplicates keep the first contributor, so this is the
    list's marginal addition in load order, not its raw line count;
  * how many blocks each list *caused* — every blocked query records its source.

The ratio is the interesting number. A list holding 300k domains that caused two
blocks all week is paying rent on memory the box does not have.

One correction the raw ratio cannot make on its own: a threat-intelligence feed
that never fires is not waste, it is the outcome you were paying for. Protective
lists are therefore reported with the same numbers but judged on a different
question — can you afford the cover? — rather than on hit rate.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

# Fallback only. The real figure is read from the live table (see
# `_bytes_per_domain`), because it depends on how the blocklist is stored and
# that has changed by an order of magnitude before: a `dict[str, str]` cost
# ~350 B/domain resident, the shared table costs ~33 B. Quoting a stale constant
# here would tell the operator to drop a list to reclaim memory that is not
# actually being spent.
BYTES_PER_DOMAIN = 33


def _bytes_per_domain(engine) -> float:
    """Measured cost per domain in the engine as it is actually stored."""
    table = getattr(engine, "block_table", None)
    n = len(table) if table is not None else 0
    if n and table.nbytes:
        return table.nbytes / n
    return BYTES_PER_DOMAIN


# Conventional naming across the public feed families (HaGeZi tif.*, various
# "threat"/"malware"/"phishing" aggregates). Only a default: an operator can
# name their own protective sources in filtering.protective_sources.
_PROTECTIVE_HINTS = ("tif", "threat", "malware", "phishing", "scam", "ransom",
                     "botnet", "cryptojacking", "spam")


def is_protective(source: str, extra: tuple[str, ...] = ()) -> bool:
    s = source.lower()
    if any(e.lower() in s for e in extra if e):
        return True
    # match on path segments so "certificate.txt" does not read as "cert"→threat
    parts = [p for chunk in s.replace("/", ".").replace("-", ".").split(".") if (p := chunk)]
    return any(p in _PROTECTIVE_HINTS for p in parts)


@dataclass
class ListStat:
    source: str
    domains: int              # marginal contribution (first list to add the name)
    blocks: int               # blocked queries attributed to this list in the window
    est_bytes: int
    blocks_per_100k: float
    share_of_domains: float   # 0..1
    verdict: str              # "earning" | "marginal" | "dead weight" | "on watch"
    note: str = ""
    protective: bool = False

    def to_json(self) -> dict:
        return {
            "source": self.source, "domains": self.domains, "blocks": self.blocks,
            "est_mb": round(self.est_bytes / 1_048_576, 1),
            "blocks_per_100k": round(self.blocks_per_100k, 1),
            "share_of_domains": round(self.share_of_domains * 100, 1),
            "verdict": self.verdict, "note": self.note, "protective": self.protective,
        }


def _verdict(domains: int, blocks: int, per_100k: float,
             protective: bool) -> tuple[str, str]:
    if protective:
        # Judged on cover, not on hit rate — silence here is the desired result.
        if blocks:
            return "earning", f"stopped {blocks} lookup(s) against known-malicious names"
        return "on watch", ("no threats seen — for a protective feed that is the "
                            "intended outcome, so weigh it on memory you can spare, "
                            "not on hit rate")
    if domains < 1000:
        # A small curated list is cheap enough that ROI is not the question.
        return ("earning" if blocks else "marginal",
                "small list — memory cost is negligible either way")
    if blocks == 0:
        return "dead weight", "held in memory the whole window without blocking anything"
    if per_100k < 5:
        return "marginal", "very few blocks for the number of domains it holds"
    return "earning", "blocking at a rate that justifies its size"


def list_effectiveness(engine, blocked_rows: list[dict], *,
                       operator_sources: frozenset[str] | None = None,
                       protective_hints: tuple[str, ...] = ()) -> list[ListStat]:
    """Per-source contribution vs. blocks caused.

    `engine` is the live FilterEngine; `blocked_rows` are query-log rows for the
    window under review.
    """
    from ..filter.engine import OPERATOR_SOURCES
    operator_sources = operator_sources or OPERATOR_SOURCES

    domains: Counter[str] = Counter(engine.plain_source_counts())
    for rules in engine.block_suffix.values():
        for r in rules:
            domains[r.source] += 1

    blocks: Counter[str] = Counter()
    for r in blocked_rows:
        src = (r.get("source") or "").strip()
        if src:
            blocks[src] += 1

    per_domain = _bytes_per_domain(engine)
    total_domains = sum(domains.values()) or 1
    out: list[ListStat] = []
    for src in set(domains) | set(blocks):
        if src in operator_sources:
            continue  # operator rules are intentional, not an ROI question
        n = domains.get(src, 0)
        b = blocks.get(src, 0)
        per = (b / n * 100_000) if n else 0.0
        prot = is_protective(src, protective_hints)
        verdict, note = _verdict(n, b, per, prot)
        out.append(ListStat(source=src, domains=n, blocks=b,
                            est_bytes=int(n * per_domain), blocks_per_100k=per,
                            share_of_domains=n / total_domains,
                            verdict=verdict, note=note, protective=prot))
    # biggest memory consumers first — that is the decision being made
    out.sort(key=lambda s: -s.domains)
    return out


async def lists_from_querylog(engine, querylog, *, hours: float = 24.0, scan: int = 50000,
                              protective_hints: tuple[str, ...] = ()):
    import time
    now = time.time()
    since = int((now - hours * 3600) * 1_000_000)
    rows = await querylog.search(action="blocked", since=since, limit=scan)
    stats = list_effectiveness(engine, rows, protective_hints=protective_hints)
    # "No blocks in the last 7 days" means nothing if the box has only been up
    # for 10 hours. Report how much history actually backs the verdicts.
    oldest = min((r["ts"] for r in rows if r.get("ts")), default=None)
    observed = (now - oldest / 1_000_000) / 3600 if oldest else 0.0
    return stats, round(min(observed, hours), 1)
