"""Cross-process counters over a shared mmap.

In multi-worker mode each worker has its own event loop and its own rich stats.
Two things have to be aggregated anyway, because the console shows them side by
side and a reader cannot tell them apart:

  * the headline scalar totals, and
  * the per-minute series the chart under those totals is drawn from.

Leaving the second per worker meant the number and the graph directly beneath it
disagreed by a factor of `nworkers`, both drawn from the same response. The
series is a fixed-size ring — 180 minutes, the same window `Counters` keeps — so
sharing it costs about 12 KB per worker and nothing per query.

Each worker writes only its own row; readers sum the columns. No locks: a writer
never touches another writer's memory, and a reader that catches a half-updated
minute is one bucket out of 180 for one refresh of a chart.
"""
from __future__ import annotations

import mmap
import struct

METRICS = ["total", "blocked", "cached", "forwarded", "failed"]
NM = len(METRICS)
_SLOT = 8  # int64 little-endian

#: The per-minute series. `SERIES_BUCKETS` matches `Counters.SERIES_BUCKETS`;
#: a slot holds the minute it stands for plus the six figures the chart needs,
#: so a reader can tell a live bucket from one three hours stale without any
#: coordination.
SERIES_BUCKETS = 180
SERIES_FIELDS = ["minute", "total", "blocked", "cached", "forwarded", "failed",
                 "lat_sum", "lat_n"]
NS = len(SERIES_FIELDS)


class SharedScalars:
    def __init__(self, path: str, nworkers: int, idx: int):
        self.nworkers = nworkers
        self.idx = idx
        self.size = self.layout_size(nworkers)
        self._f = open(path, "r+b")  # noqa: SIM115 - kept open for the mmap's lifetime
        self.mm = mmap.mmap(self._f.fileno(), self.size)
        self._series_base = nworkers * NM * _SLOT

    @staticmethod
    def layout_size(nworkers: int) -> int:
        return nworkers * NM * _SLOT + nworkers * SERIES_BUCKETS * NS * _SLOT

    @staticmethod
    def create(path: str, nworkers: int) -> None:
        with open(path, "wb") as f:
            f.write(b"\x00" * SharedScalars.layout_size(nworkers))

    # ---- scalars ----
    def inc(self, metric: str, n: int = 1) -> None:
        try:
            mi = METRICS.index(metric)
        except ValueError:
            return
        off = (self.idx * NM + mi) * _SLOT
        v = struct.unpack_from("<q", self.mm, off)[0] + n
        struct.pack_into("<q", self.mm, off, v)

    def totals(self) -> dict[str, int]:
        out = dict.fromkeys(METRICS, 0)
        for w in range(self.nworkers):
            for mi, m in enumerate(METRICS):
                out[m] += struct.unpack_from("<q", self.mm, (w * NM + mi) * _SLOT)[0]
        return out

    # ---- per-minute series ----
    def _slot_off(self, worker: int, minute: int) -> int:
        bucket = (minute // 60) % SERIES_BUCKETS
        return self._series_base + ((worker * SERIES_BUCKETS + bucket) * NS * _SLOT)

    def add_minute(self, minute: int, action: str, latency_us: int) -> None:
        """Fold one query into this worker's bucket for `minute`.

        The bucket is claimed by stamping its minute, which is also how it is
        recycled: three hours later the same slot comes round again and the
        stamp no longer matches, so it is reset rather than added to.
        """
        off = self._slot_off(self.idx, minute)
        stamp = struct.unpack_from("<q", self.mm, off)[0]
        if stamp != minute:
            struct.pack_into(f"<{NS}q", self.mm, off, minute, 0, 0, 0, 0, 0, 0, 0)
        key = "blocked" if action in ("blocked", "block") else action
        fields = [1 if f == "total" else (1 if f == key else 0)
                  for f in SERIES_FIELDS]
        for i, add in enumerate(fields):
            if not add:
                continue
            pos = off + i * _SLOT
            struct.pack_into("<q", self.mm, pos,
                             struct.unpack_from("<q", self.mm, pos)[0] + add)
        if latency_us:
            for name, add in (("lat_sum", latency_us), ("lat_n", 1)):
                pos = off + SERIES_FIELDS.index(name) * _SLOT
                struct.pack_into("<q", self.mm, pos,
                                 struct.unpack_from("<q", self.mm, pos)[0] + add)

    def minute(self, minute: int) -> dict[str, int] | None:
        """Every worker's figures for one minute, summed. None when nobody has any."""
        out = dict.fromkeys(SERIES_FIELDS[1:], 0)
        seen = False
        for w in range(self.nworkers):
            off = self._slot_off(w, minute)
            values = struct.unpack_from(f"<{NS}q", self.mm, off)
            if values[0] != minute:
                continue          # this worker's slot has been recycled
            seen = True
            for i, name in enumerate(SERIES_FIELDS[1:], start=1):
                out[name] += values[i]
        return out if seen else None

    def close(self) -> None:
        try:
            self.mm.close()
            self._f.close()
        except Exception:
            pass
