"""Per-client token-bucket rate limiting (anti-flood / anti-amplification)."""
from __future__ import annotations

import time

#: Hard ceiling on tracked source addresses. The key is the client address,
#: which on a UDP listener is attacker-chosen and effectively unlimited, so
#: without a cap a spoofed-source flood turns the limiter itself into the
#: memory-exhaustion vector it exists to prevent.
MAX_KEYS = 65536


class RateLimiter:
    def __init__(self, rate: float = 0.0, burst: int = 0, max_keys: int = MAX_KEYS,
                 workers: int = 1):
        # rate <= 0 disables limiting
        #
        # `workers` divides both figures. There is one limiter per worker and
        # the kernel spreads a client's datagrams across all of them, so an
        # unscaled `rate_limit: 150` on a four-worker box let a single source
        # sustain ~600 q/s — four independent buckets, none of which knew about
        # the others. A token bucket splits cleanly, so the aggregate after
        # dividing is the number the operator actually typed; only the shape of
        # a burst differs.
        self.workers = max(1, int(workers))
        self.rate = rate / self.workers if rate > 0 else rate
        self.burst = ((burst / self.workers) if burst > 0 else max(1.0, self.rate))
        self.burst = max(1.0, self.burst)
        self.max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last)

    @property
    def enabled(self) -> bool:
        return self.rate > 0

    def allow(self, key: str, now: float | None = None) -> bool:
        if not self.enabled:
            return True
        now = now if now is not None else time.monotonic()
        tokens, last = self._buckets.get(key, (float(self.burst), now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        allowed = tokens >= 1.0
        if key not in self._buckets and len(self._buckets) >= self.max_keys:
            self._trim(now)
        self._buckets[key] = (tokens - 1.0 if allowed else tokens, now)
        return allowed

    def _trim(self, now: float) -> None:
        """Make room by dropping the least recently seen quarter of the table.

        A bucket at full tokens carries no state worth keeping, so evicting the
        stalest keys costs nothing but a fresh allowance for a client that has
        been quiet longer than everyone else in the table.
        """
        stale = sorted(self._buckets.items(), key=lambda kv: kv[1][1])
        for k, _ in stale[:max(1, len(stale) // 4)]:
            self._buckets.pop(k, None)

    def gc(self, now: float | None = None, idle: float = 300.0) -> None:
        """Drop buckets nobody has touched for `idle` seconds.

        Called on a timer by App._schedule_jobs (the `ratelimit-gc` job). Left
        uncalled this table only ever grows.
        """
        now = now if now is not None else time.monotonic()
        for k in [k for k, (_, last) in self._buckets.items() if now - last > idle]:
            self._buckets.pop(k, None)
