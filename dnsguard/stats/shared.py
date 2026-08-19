"""Cross-process scalar counters over a shared mmap.

In multi-worker (SO_REUSEPORT) mode each worker has its own event loop and its
own rich stats; the headline scalar totals are kept here so the admin API can
report an accurate aggregate. Each worker writes only its own row (no
cross-process contention); readers sum the columns.
"""
from __future__ import annotations

import mmap
import struct

METRICS = ["total", "blocked", "cached", "forwarded", "failed"]
NM = len(METRICS)
_SLOT = 8  # int64 little-endian


class SharedScalars:
    def __init__(self, path: str, nworkers: int, idx: int):
        self.nworkers = nworkers
        self.idx = idx
        self.size = nworkers * NM * _SLOT
        self._f = open(path, "r+b")  # noqa: SIM115 - kept open for the mmap's lifetime
        self.mm = mmap.mmap(self._f.fileno(), self.size)

    @staticmethod
    def create(path: str, nworkers: int) -> None:
        with open(path, "wb") as f:
            f.write(b"\x00" * (nworkers * NM * _SLOT))

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

    def close(self) -> None:
        try:
            self.mm.close()
            self._f.close()
        except Exception:
            pass
