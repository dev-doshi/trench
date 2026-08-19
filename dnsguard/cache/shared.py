"""Cross-process shared DNS cache over an anonymous shared mmap.

All forked workers map the same memory, so a response cached by one worker is a
hit for every other worker (1 cache instead of N, higher hit rate, bounded RAM).

Layout: a direct-mapped table of fixed-size slots. Each slot stores a stable
64-bit key hash, the insert time, the TTL, the wire length, and the response
wire bytes. Hash collisions simply evict (it's a cache). Writes/reads take a
striped lock (inherited multiprocessing.Lock) so reads never tear.

Keys are hashed with BLAKE2b (NOT the process-randomized `hash()`), so the same
query maps to the same slot in every worker.
"""
from __future__ import annotations

import hashlib
import mmap
import struct
import time

_HDR = struct.Struct("<QdIH")   # keyhash(u64), inserted(f64), ttl(u32), length(u16)
_HDR_LEN = _HDR.size
_STRIPES = 64


def key64(qname: bytes, qtype: int, qclass: int, do: bool, ecs: str = "",
          cd: bool = False) -> int:
    # qname arrives as the lowercased wire form, so it is already a canonical
    # byte string and needs no formatting trip through str.
    raw = b"%s|%d|%d|%d|%s|%d" % (qname, qtype, qclass, int(do), ecs.encode(),
                                  int(cd))
    return int.from_bytes(hashlib.blake2b(raw, digest_size=8).digest(), "big")


class SharedCache:
    def __init__(self, mm, locks, slots: int, payload: int):
        self.mm = mm
        self.locks = locks
        self.slots = slots
        self.payload = payload
        self.slot_size = _HDR_LEN + payload

    @classmethod
    def create(cls, slots: int = 16384, payload: int = 1232) -> SharedCache:
        import multiprocessing
        size = slots * (_HDR_LEN + payload)
        mm = mmap.mmap(-1, size)  # anonymous MAP_SHARED -> inherited across fork
        locks = [multiprocessing.Lock() for _ in range(_STRIPES)]
        return cls(mm, locks, slots, payload)

    def _slot(self, k: int) -> tuple[int, object]:
        bucket = k % self.slots
        return bucket * self.slot_size, self.locks[bucket % _STRIPES]

    def get(self, k: int) -> tuple[bytes, float] | None:
        off, lock = self._slot(k)
        with lock:
            kh, inserted, ttl, length = _HDR.unpack_from(self.mm, off)
            if kh != k or length == 0:
                return None
            remaining = ttl - (time.monotonic() - inserted)
            if remaining <= 0:
                return None
            wire = bytes(self.mm[off + _HDR_LEN: off + _HDR_LEN + length])
        return wire, remaining

    def put(self, k: int, wire: bytes, ttl: int) -> None:
        if not wire or len(wire) > self.payload or ttl <= 0:
            return
        off, lock = self._slot(k)
        with lock:
            _HDR.pack_into(self.mm, off, k, time.monotonic(), int(ttl), len(wire))
            self.mm[off + _HDR_LEN: off + _HDR_LEN + len(wire)] = wire

    def delete(self, k: int) -> None:
        """Invalidate one slot. Needed so a targeted flush is not undone by the
        next L1 miss reading the flushed answer straight back out of L2."""
        off, lock = self._slot(k)
        with lock:
            kh, _, _, _ = _HDR.unpack_from(self.mm, off)
            if kh == k:
                _HDR.pack_into(self.mm, off, 0, 0.0, 0, 0)

    def clear(self) -> None:
        """Invalidate every slot.

        One lock acquisition per stripe, not one per slot. Taking a
        cross-process lock 16k times ran on the event-loop thread — every
        in-flight query waited on it — and a worker killed mid-clear (this
        deployment has an OOM history) left a stripe lock held forever, which
        no reader can time out of.
        """
        blank = _HDR.pack(0, 0.0, 0, 0)
        for i in range(_STRIPES):
            with self.locks[i]:
                for b in range(i, self.slots, _STRIPES):
                    off = b * self.slot_size
                    self.mm[off:off + _HDR_LEN] = blank
