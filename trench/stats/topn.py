"""A bounded counter for "top N" statistics.

`collections.Counter` is the obvious thing to reach for and the wrong thing to
keep: one entry per distinct key, forever. A resolver sees a new name every time
someone loads a page with a fresh CDN hostname in it, so the counters that feed
the dashboard's top-domains and top-clients lists grow without limit — measured
at 27 MB per 200k distinct names, on a box with a 700 MB container limit.

This keeps at most `cap` keys. When it overflows it prunes back to the heaviest
half, which is exactly the population a top-N list is asking about: a key that
matters is not sitting at the bottom of the distribution. Counts for surviving
keys are exact; the approximation is only that a key which was rare, got pruned,
and later became popular starts counting again from zero.

Pruning costs O(cap log cap) once every cap/2 insertions, so the amortised cost
per insertion stays constant and small.
"""
from __future__ import annotations


class TopCounter:
    """Counter-compatible enough for the statistics code that uses it."""

    __slots__ = ("cap", "_d", "pruned")

    def __init__(self, cap: int = 20_000):
        self.cap = cap
        self._d: dict[str, int] = {}
        self.pruned = 0          # how many keys have been dropped, for honesty

    def add(self, key: str, n: int = 1) -> None:
        d = self._d
        got = d.get(key)
        if got is None:
            if len(d) >= self.cap:
                self._prune()
            d[key] = n
        else:
            d[key] = got + n

    # `counter[key] += 1` support, so call sites read the same as before
    def __getitem__(self, key: str) -> int:
        return self._d.get(key, 0)

    def __setitem__(self, key: str, value: int) -> None:
        if key in self._d:
            self._d[key] = value
        else:
            self.add(key, value)

    def _prune(self) -> None:
        keep = self.cap // 2
        survivors = sorted(self._d.items(), key=lambda kv: kv[1], reverse=True)[:keep]
        self.pruned += len(self._d) - len(survivors)
        self._d = dict(survivors)

    def most_common(self, n: int | None = None) -> list[tuple[str, int]]:
        items = sorted(self._d.items(), key=lambda kv: kv[1], reverse=True)
        return items if n is None else items[:n]

    def values(self):
        return self._d.values()

    def items(self):
        return self._d.items()

    def get(self, key: str, default: int = 0) -> int:
        return self._d.get(key, default)

    def __contains__(self, key: str) -> bool:
        return key in self._d

    def __len__(self) -> int:
        return len(self._d)

    def clear(self) -> None:
        self._d.clear()
