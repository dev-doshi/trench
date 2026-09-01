"""Learned query popularity + proactive cache prewarm.

`PopularityTracker` keeps an EWMA score per qname: each fold interval, the
raw count from the last window is blended into the long-term score
(`score = (1-alpha)*score + alpha*count`) and near-zero entries are pruned.
The result is a stable, restart-surviving ranking of the names this network
actually uses — mornings look like yesterday morning.

`prewarm()` walks the learned top-N and re-resolves any entry whose cache TTL
is gone or nearly gone. Unlike the reactive prefetch in the pipeline (which
needs a query to arrive within seconds of expiry), this repopulates the cache
after restarts and overnight TTL expiry, so the first query of the day is
already hot.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..log import get
from ..wire import Class, Message, Question
from ..wire.name import Name
from ..wire.rrtypes import Flags, Rcode, Type

log = get("learn")


class PopularityTracker:
    def __init__(self, *, alpha: float = 0.3, max_entries: int = 4096,
                 floor: float = 0.05):
        if not 0.0 < alpha <= 1.0:
            raise ValueError("alpha must be in (0, 1]")
        self.alpha = alpha
        self.max_entries = max_entries
        self.floor = floor                      # scores below this are forgotten
        self.scores: dict[str, float] = {}      # long-term EWMA
        self._window: dict[str, int] = {}       # raw counts since the last fold

    # --- hot path (called per resolved query) ---
    def note(self, qname: str) -> None:
        w = self._window
        if qname in w:
            w[qname] += 1
        elif len(w) < self.max_entries * 4:     # bound memory under qname floods
            w[qname] = 1

    # --- periodic maintenance ---
    def fold(self) -> None:
        """Blend the current window into the long-term scores and start a new
        window. Names absent from the window decay toward zero."""
        a = self.alpha
        scores = self.scores
        for name in set(scores) | set(self._window):
            new = (1 - a) * scores.get(name, 0.0) + a * self._window.get(name, 0)
            if new >= self.floor:
                scores[name] = new
            else:
                scores.pop(name, None)
        self._window = {}
        if len(scores) > self.max_entries:      # keep only the strongest
            keep = sorted(scores.items(), key=lambda kv: kv[1],
                          reverse=True)[:self.max_entries]
            self.scores = dict(keep)

    def top(self, n: int) -> list[str]:
        return [name for name, _ in
                sorted(self.scores.items(), key=lambda kv: kv[1], reverse=True)[:n]]

    def __len__(self) -> int:
        return len(self.scores)

    # --- persistence ---
    def dump(self, path: str | Path) -> int:
        data = {"alpha": self.alpha, "scores": self.scores}
        Path(path).write_text(json.dumps(data))
        return len(self.scores)

    def load(self, path: str | Path) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        try:
            data = json.loads(p.read_text())
            scores = data.get("scores", {})
            self.scores = {str(k): float(v) for k, v in scores.items()
                           if float(v) >= self.floor}
        except (ValueError, TypeError, OSError):
            log.warning("popularity file %s unreadable; starting fresh", p)
            return 0
        return len(self.scores)


async def prewarm(tracker: PopularityTracker, cache, resolve, *, top: int = 50,
                  qtypes: tuple[int, ...] = (Type.A, Type.AAAA),
                  min_remaining: float = 60.0) -> int:
    """Re-resolve the learned top-N names whose cache entry is missing or about
    to expire. Returns how many entries were refreshed.

    `resolve(query) -> Message` must both resolve *and* store the answer — pass
    `Pipeline.warm`. It used to be the bare forwarder, with the answer written
    into the cache here, which made this sweep a second way into the cache that
    skipped the checks a client query goes through.
    """
    warmed = 0
    for qname in tracker.top(top):
        try:
            name = Name.from_text(qname)
        except Exception:
            continue                             # a hostile name must not kill the job
        for qt in qtypes:
            q = Message(id=0)
            q.set_flag(Flags.RD, True)
            q.questions.append(Question(name, qt, Class.IN))
            key = cache.key_for(q)
            if key is None:
                continue
            rem = cache.remaining(key)
            if rem is not None and rem > min_remaining:
                continue                         # still comfortably fresh
            try:
                resp = await resolve(q)
            except Exception:
                continue
            if resp is not None and resp.rcode == Rcode.NOERROR:
                warmed += 1   # `resolve` has already cached it
    if warmed:
        log.info("prewarmed %d cache entries from learned top-%d", warmed, top)
    return warmed
