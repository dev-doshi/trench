"""Realtime counters + recent-query ring. Updated on the event loop only."""
from __future__ import annotations

import time
from collections import Counter, deque

from .topn import TopCounter

_EVENT_FIELDS = ("ts", "client", "domain", "type", "action", "rcode",
                 "upstream", "elapsed_us", "reason")


def _as_event(row: tuple) -> dict:
    return dict(zip(_EVENT_FIELDS, row, strict=True))


class Counters:
    SERIES_BUCKETS = 180      # per-minute history retained (3 hours)

    def __init__(self, recent_max: int = 500, shared=None, top_cap: int = 20_000):
        self.start = time.time()
        self.shared = shared          # optional SharedScalars (multi-worker aggregate)
        self.total = 0
        self.by_action: Counter[str] = Counter()
        self.by_qtype: Counter[str] = Counter()
        self.by_rcode: Counter[str] = Counter()
        # Bounded, not Counter: these are keyed on domain and client, so a
        # plain Counter grows for the life of the process. See stats/topn.py.
        self.queries = TopCounter(top_cap)
        self.blocked = TopCounter(top_cap)
        self.clients = TopCounter(top_cap)
        self.upstreams = TopCounter(1024)
        self.dga = TopCounter(4096)             # DGA-flagged domains
        self.tunnel = TopCounter(4096)          # tunneling/exfil-flagged domains
        self.latency_us_sum = 0
        self.latency_n = 0
        # recent latency samples (ring) — enough for stable p50/p95/p99 without
        # unbounded memory; percentiles therefore reflect *recent* behaviour,
        # which is what you want when debugging a slow upstream right now
        self.latency_samples: deque[int] = deque(maxlen=2048)
        self.recent: deque = deque(maxlen=recent_max)
        # per-minute time series: minute_epoch -> {total, blocked, cached, ...}
        self._series: dict[int, dict[str, int]] = {}
        # live listeners: called synchronously with each recorded event dict
        self._listeners: list = []

    def subscribe(self, cb) -> None:
        self._listeners.append(cb)

    def unsubscribe(self, cb) -> None:
        try:
            self._listeners.remove(cb)
        except ValueError:
            pass

    def _bucket(self, action: str, latency_us: int, now: float) -> None:
        minute = int(now) // 60 * 60
        b = self._series.get(minute)
        if b is None:
            b = self._series[minute] = {"total": 0, "blocked": 0, "cached": 0,
                                        "forwarded": 0, "failed": 0, "lat_sum": 0, "lat_n": 0}
            # Pruning belongs here, inside the branch that just added a bucket.
            # Outside it, the length check is true on *every* query once uptime
            # passes three hours, so every query sorted a 181-key dict — the one
            # piece of per-query work that got slower the longer the process ran.
            if len(self._series) > self.SERIES_BUCKETS:
                for old in sorted(self._series)[:-self.SERIES_BUCKETS]:
                    del self._series[old]
        b["total"] += 1
        key = "blocked" if action in ("blocked", "block") else action
        if key in b:
            b[key] += 1
        if latency_us:
            b["lat_sum"] += latency_us
            b["lat_n"] += 1

    def series(self, minutes: int = 60) -> list[dict]:
        """Return the last `minutes` per-minute buckets (oldest first), gap-filled."""
        now_min = int(time.time()) // 60 * 60
        out = []
        for i in range(minutes - 1, -1, -1):
            m = now_min - i * 60
            b = self._series.get(m)
            if b:
                lat = round(b["lat_sum"] / b["lat_n"] / 1000, 2) if b["lat_n"] else 0
                out.append({"t": m, "total": b["total"], "blocked": b["blocked"],
                            "cached": b["cached"], "forwarded": b["forwarded"],
                            "failed": b["failed"], "latency_ms": lat})
            else:
                out.append({"t": m, "total": 0, "blocked": 0, "cached": 0,
                            "forwarded": 0, "failed": 0, "latency_ms": 0})
        return out

    def record(self, *, client: str, qname: str, qtype: str, action: str,
               rcode: str = "", upstream: str = "", elapsed_us: int = 0,
               reason: str = "") -> None:
        self.total += 1
        self.by_action[action] += 1
        self.by_qtype[qtype] += 1
        if rcode:
            self.by_rcode[rcode] += 1
        # `.add()` rather than `c[k] += 1`: the latter is a __getitem__ and a
        # __setitem__ through the TopCounter wrapper, i.e. two dict lookups and
        # two method calls where one will do. Bookkeeping is 42% of the replay
        # path, so this is not a rounding error there.
        self.queries.add(qname)
        self.clients.add(client)
        if action in ("blocked", "block"):
            self.blocked.add(qname)
        if upstream:
            self.upstreams.add(upstream)
        if elapsed_us:
            self.latency_us_sum += elapsed_us
            self.latency_n += 1
            self.latency_samples.append(elapsed_us)
        now = time.time()
        # A tuple, not a dict. The ring holds 500 entries and both readers turn
        # it into a list of dicts anyway, so building the dict here meant
        # allocating nine keys per query for a record that is usually discarded
        # before anyone looks at it. `recent_events()` does the conversion for
        # the handful that are actually read.
        self.recent.appendleft((now, client, qname, qtype, action, rcode,
                                upstream, elapsed_us, reason))
        self._bucket(action, elapsed_us, now)
        if self._listeners:                 # live push (WS); listeners must not raise
            event = _as_event(self.recent[0])
            for cb in self._listeners:
                try:
                    cb(event)
                except Exception:
                    pass
        if self.shared is not None:
            self.shared.inc("total")
            metric = "blocked" if action in ("blocked", "block") else action
            self.shared.inc(metric)

    def recent_events(self, limit: int) -> list[dict]:
        """The recent-query ring as dicts, built on read rather than on write."""
        out = []
        for row in self.recent:
            out.append(_as_event(row))
            if len(out) >= limit:
                break
        return out

    def note_dga(self, qname: str) -> None:
        self.dga.add(qname)

    def note_tunnel(self, qname: str) -> None:
        self.tunnel.add(qname)

    def snapshot(self, top: int = 15) -> dict:
        # aggregate scalar totals across workers when running multi-process
        if self.shared is not None:
            agg = self.shared.totals()
            total_all, blocked = agg["total"], agg["blocked"]
            cached, forwarded, failed = agg["cached"], agg["forwarded"], agg["failed"]
        else:
            total_all = self.total
            blocked = self.by_action.get("blocked", 0) + self.by_action.get("block", 0)
            cached = self.by_action.get("cached", 0)
            forwarded = self.by_action.get("forwarded", 0)
            failed = self.by_action.get("failed", 0)
        total = total_all or 1
        avg_us = (self.latency_us_sum / self.latency_n) if self.latency_n else 0
        if self.latency_samples:
            ordered = sorted(self.latency_samples)
            last = len(ordered) - 1

            def pct(p: float) -> float:
                return round(ordered[int(last * p)] / 1000, 2)

            p50, p95, p99 = pct(0.50), pct(0.95), pct(0.99)
        else:
            p50 = p95 = p99 = 0.0
        return {
            "uptime": int(time.time() - self.start),
            "total": total_all,
            "blocked": blocked,
            "cached": cached,
            "forwarded": forwarded,
            "failed": failed,
            "block_pct": round(blocked / total * 100, 1),
            "avg_latency_ms": round(avg_us / 1000, 2),
            "latency_p50_ms": p50,
            "latency_p95_ms": p95,
            "latency_p99_ms": p99,
            "by_qtype": self.by_qtype.most_common(),
            "by_rcode": self.by_rcode.most_common(),
            "top_queries": self.queries.most_common(top),
            "top_blocked": self.blocked.most_common(top),
            "top_clients": self.clients.most_common(top),
            "top_upstreams": self.upstreams.most_common(top),
            "dga_flagged": sum(self.dga.values()),
            "top_dga": self.dga.most_common(top),
            "tunnel_flagged": sum(self.tunnel.values()),
            "top_tunnel": self.tunnel.most_common(top),
            "recent": self.recent_events(100),
        }
