"""What-if policy replay: dry-run a proposed rule change against the queries
this network actually made, before applying it.

Every other resolver makes you apply a blocklist and wait for something to
break. Here the query log is a recorded workload: compile the proposed rules
into a candidate engine, replay the distinct names from the last N hours
through both current and candidate policy, and report exactly which domains
flip — weighted by how often each was queried. "Will this list break my TV?"
becomes a query, not an experiment on your family.

Semantics are additive (the common case — adding lists/rules on top of the
current policy): a proposed allow overrides everything, a proposed block adds
to the current decision, anything else keeps the current verdict.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..filter import Action, FilterEngine
from ..filter.parser import parse_list
from ..filter.rule import Rule


@dataclass
class Flip:
    qname: str
    hits: int
    rule: str          # the proposed rule that caused the flip


@dataclass
class WhatIfResult:
    total_names: int = 0
    total_hits: int = 0
    newly_blocked: list[Flip] = field(default_factory=list)
    newly_allowed: list[Flip] = field(default_factory=list)
    affected_hits: int = 0          # queries/period that would change outcome

    def to_json(self, limit: int = 100) -> dict:
        pct = (100.0 * self.affected_hits / self.total_hits) if self.total_hits else 0.0
        return {
            "total_names": self.total_names,
            "total_hits": self.total_hits,
            "affected_hits": self.affected_hits,
            "affected_pct": round(pct, 2),
            "newly_blocked": [vars(f) for f in self.newly_blocked[:limit]],
            "newly_allowed": [vars(f) for f in self.newly_allowed[:limit]],
            "newly_blocked_count": len(self.newly_blocked),
            "newly_allowed_count": len(self.newly_allowed),
        }


def compile_delta(deny: list[str] = (), allow: list[str] = (),
                  list_text: str = "") -> FilterEngine:
    """Compile the proposed change: plain deny/allow domains plus optionally the
    raw text of a blocklist (hosts / adblock syntax) being considered."""
    rules: list[Rule] = []
    for d in deny:
        d = d.strip().lower()
        if d:
            rules.append(Rule(raw=d, block=True, suffix=d, source="whatif"))
    for d in allow:
        d = d.strip().lower()
        if d:
            rules.append(Rule(raw=d, block=False, important=True, suffix=d, source="whatif"))
    if list_text:
        rules.extend(parse_list(list_text, source="whatif-list"))
    return FilterEngine.compile(rules)


def diff_decisions(current: FilterEngine, delta: FilterEngine,
                   names: list[tuple[str, int]]) -> WhatIfResult:
    """Replay `names` [(qname, hits)] through current policy vs current+delta."""
    res = WhatIfResult(total_names=len(names))
    for qname, hits in names:
        res.total_hits += hits
        qname = qname.lower()
        cur_blocked = current.match(qname).action == Action.BLOCK
        d = delta.match(qname)
        if d.action == Action.ALLOW:            # proposed allow overrides
            cand_blocked, via = False, d.rule
        elif d.action == Action.BLOCK:          # proposed block adds
            cand_blocked, via = True, d.rule
        else:
            cand_blocked, via = cur_blocked, ""
        if cand_blocked == cur_blocked:
            continue
        res.affected_hits += hits
        flip = Flip(qname=qname, hits=hits, rule=via)
        (res.newly_blocked if cand_blocked else res.newly_allowed).append(flip)
    res.newly_blocked.sort(key=lambda f: f.hits, reverse=True)
    res.newly_allowed.sort(key=lambda f: f.hits, reverse=True)
    return res


async def whatif_from_querylog(db, current: FilterEngine, delta: FilterEngine, *,
                               hours: float = 24.0, limit: int = 5000) -> WhatIfResult:
    """Pull the distinct names queried in the last `hours` (weighted by count)
    and diff them. `db` is the async Database; querylog.ts is in microseconds."""
    cutoff = int((time.time() - hours * 3600) * 1_000_000)
    rows = await db.fetchall(
        "SELECT qname, COUNT(*) AS hits FROM querylog "
        "WHERE ts >= ? AND qname != '' GROUP BY qname ORDER BY hits DESC LIMIT ?",
        (cutoff, limit))
    return diff_decisions(current, delta, [(r["qname"], r["hits"]) for r in rows])
