"""Reviewing a blocklist update instead of just applying it.

Public blocklists change daily and every resolver in this space swaps them in
silently. That is where the folklore comes from: someone's Instagram stops
loading on a Tuesday, and nothing anywhere connects it to a maintainer having
added `graph.facebook.com` to a list overnight. The operator's only evidence is
a working network that suddenly is not one, with no diff to look at.

The naive fix — diff the two domain sets — produces tens of thousands of lines
nobody will read, because almost every added domain is one this network will
never look up. The useful question is narrower:

    of the names this network actually asked for recently, which ones does the
    new list decide differently?

That is a few thousand names, not 600k, and it answers the question that
matters. Each change is reported with the traffic behind it, so "this will break
something" and "this is one stray beacon" are told apart by evidence rather than
by guessing.

Nothing here blocks or reverts an update. Auto-quarantining risky additions was
considered and rejected: it would mean silently *not* blocking something a
threat feed just flagged, which is a worse failure than a broken site the
operator can see and allow in one click.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

# A name that several devices ask for repeatedly is load-bearing; one lookup
# from one device is noise. These only rank and label — nothing is suppressed.
_BUSY_HITS = 20
_BUSY_CLIENTS = 2


@dataclass
class VerdictChange:
    qname: str
    before: str                # action name before the update
    after: str                 # action name after
    hits: int                  # lookups in the reviewed window
    clients: int               # distinct devices that asked
    last_seen: int             # microseconds
    rule: str = ""             # the rule responsible for the new verdict
    source: str = ""           # which list supplied it
    risk: str = "low"          # low | medium | high

    def to_json(self) -> dict:
        return {"qname": self.qname, "before": self.before, "after": self.after,
                "hits": self.hits, "clients": self.clients,
                "last_seen": self.last_seen, "rule": self.rule,
                "source": self.source, "risk": self.risk}


@dataclass
class ListUpdateReview:
    at: float = field(default_factory=time.time)
    window_hours: float = 24.0
    names_checked: int = 0
    newly_blocked: list[VerdictChange] = field(default_factory=list)
    newly_allowed: list[VerdictChange] = field(default_factory=list)
    domains_before: int = 0
    domains_after: int = 0
    per_source: dict[str, int] = field(default_factory=dict)   # signed delta

    @property
    def high_risk(self) -> int:
        return sum(1 for c in self.newly_blocked if c.risk == "high")

    def summary(self) -> str:
        d = self.domains_after - self.domains_before
        return (f"{self.domains_after} domains ({d:+d}); of {self.names_checked} names "
                f"seen in the last {self.window_hours:g}h, {len(self.newly_blocked)} "
                f"newly blocked ({self.high_risk} high risk), "
                f"{len(self.newly_allowed)} no longer blocked")

    def to_json(self) -> dict:
        return {
            "at": self.at, "window_hours": self.window_hours,
            "names_checked": self.names_checked,
            "domains_before": self.domains_before, "domains_after": self.domains_after,
            "domains_delta": self.domains_after - self.domains_before,
            "per_source": self.per_source,
            "high_risk": self.high_risk,
            "newly_blocked": [c.to_json() for c in self.newly_blocked],
            "newly_allowed": [c.to_json() for c in self.newly_allowed],
            "summary": self.summary(),
        }


def _risk(hits: int, clients: int, was_blocked: bool) -> str:
    """How likely is this change to be felt?

    The strongest signal is that the name was being *answered* before: something
    on this network was using it successfully and now will not be able to.
    """
    if was_blocked:
        # Already blocked by another rule, so nothing observable changes.
        return "low"
    if hits >= _BUSY_HITS and clients >= _BUSY_CLIENTS:
        return "high"
    if hits >= _BUSY_HITS or clients >= _BUSY_CLIENTS:
        return "medium"
    return "low"


def review_update(old_engine, new_engine, names: list[dict], *,
                  window_hours: float = 24.0, top: int = 200) -> ListUpdateReview:
    """Compare two compiled engines over names this network actually queried.

    `names` are rows from `QueryLog.distinct_names()`: qname, hits, clients,
    last_seen, blocked_hits.
    """
    rev = ListUpdateReview(window_hours=window_hours, names_checked=len(names))
    rev.domains_before = old_engine.size if old_engine is not None else 0
    rev.domains_after = new_engine.size

    before_counts = old_engine.plain_source_counts() if old_engine is not None else {}
    after_counts = new_engine.plain_source_counts()
    for src in set(before_counts) | set(after_counts):
        delta = after_counts.get(src, 0) - before_counts.get(src, 0)
        if delta:
            rev.per_source[src] = delta

    if old_engine is None:
        return rev   # first build: everything is "new", which tells you nothing

    for row in names:
        qname = (row.get("qname") or "").strip().lower()
        if not qname:
            continue
        old = old_engine.match(qname)
        new = new_engine.match(qname)
        old_act = getattr(old.action, "name", str(old.action))
        new_act = getattr(new.action, "name", str(new.action))
        if old_act == new_act:
            continue
        hits = int(row.get("hits") or 0)
        clients = int(row.get("clients") or 0)
        change = VerdictChange(
            qname=qname, before=old_act, after=new_act, hits=hits, clients=clients,
            last_seen=int(row.get("last_seen") or 0),
            rule=(new.rule or "") if new_act == "BLOCK" else (old.rule or ""),
            source=(new.source or "") if new_act == "BLOCK" else (old.source or ""),
        )
        if new_act == "BLOCK":
            # `blocked_hits` covers the whole window: if every lookup was already
            # being blocked, this rule change is not what the network will notice.
            was_blocked = int(row.get("blocked_hits") or 0) >= hits
            change.risk = _risk(hits, clients, was_blocked)
            rev.newly_blocked.append(change)
        elif old_act == "BLOCK":
            rev.newly_allowed.append(change)

    # Loudest first, and cap the report: a diff nobody reads is not a review.
    rev.newly_blocked.sort(key=lambda c: (-{"high": 2, "medium": 1}.get(c.risk, 0),
                                          -c.clients, -c.hits))
    rev.newly_allowed.sort(key=lambda c: (-c.clients, -c.hits))
    rev.newly_blocked = rev.newly_blocked[:top]
    rev.newly_allowed = rev.newly_allowed[:top]
    return rev


async def review_from_querylog(old_engine, new_engine, querylog, *,
                               hours: float = 24.0, limit: int = 20000):
    since = int((time.time() - hours * 3600) * 1_000_000)
    names = await querylog.distinct_names(since=since, limit=limit)
    return review_update(old_engine, new_engine, names, window_hours=hours)
