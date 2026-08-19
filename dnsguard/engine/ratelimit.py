"""Per-client token-bucket rate limiting (anti-flood / anti-amplification)."""
from __future__ import annotations

import time


class RateLimiter:
    def __init__(self, rate: float = 0.0, burst: int = 0):
        # rate <= 0 disables limiting
        self.rate = rate
        self.burst = burst if burst > 0 else max(1, int(rate))
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
        if tokens < 1.0:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - 1.0, now)
        return True

    def gc(self, now: float | None = None, idle: float = 300.0) -> None:
        now = now if now is not None else time.monotonic()
        for k in [k for k, (_, last) in self._buckets.items() if now - last > idle]:
            self._buckets.pop(k, None)
