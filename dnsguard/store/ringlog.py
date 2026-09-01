"""Cross-process hand-off for query-log records.

SQLite wants a single writer, so only the primary worker owns the database. But
Do53 runs in *every* worker and the kernel spreads a client's datagrams across
all of them, so on a four-worker box the primary sees about a quarter of the
traffic — and the query log, the breakage report, the blocklist ROI figures and
the what-if replay were all computed from that quarter as if it were the whole.
Nothing said so, and the undercount varies per name, so it could not even be
corrected for after the fact.

This is the missing channel. Each worker owns one lane of a shared ring and
pushes finished records into it; the primary drains every lane on its own flush
tick and writes them with its own. The shape follows `stats/shared.py`: an
anonymous mmap created before the fork, one lane per worker so a writer never
touches another writer's memory, and a reader that simply sums what it finds.

Records arrive already redacted — `QueryLog.enqueue` applies the privacy level
before anything is queued — so nothing here ever holds a name the operator asked
not to keep.

Bounded, and it sheds rather than blocks: a full lane drops the record and
counts it, exactly as the in-process queue does under flood. A DNS server that
stops answering because its log is behind has its priorities backwards.
"""
from __future__ import annotations

import json
import mmap
import struct

#: head, tail, dropped — three u64 per lane. The writer owns `head` and
#: `dropped`, the reader owns `tail`, so the two sides never write the same
#: word; the lock below is what keeps a slot from being read half-written.
_LANE_HDR = struct.Struct("<QQQ")
_LEN = struct.Struct("<H")


class RecordRing:
    """A single-producer/single-consumer ring per worker, over one shared mmap."""

    def __init__(self, mm, locks, lanes: int, slots: int, slot_bytes: int,
                 lane: int = 0):
        self.mm = mm
        self.locks = locks
        self.lanes = lanes
        self.slots = slots
        self.slot_bytes = slot_bytes
        self.lane = lane            # which lane this process writes to

    # ---- construction ----
    @classmethod
    def create(cls, lanes: int, slots: int = 2048, slot_bytes: int = 768) -> RecordRing:
        """Allocate the ring in the supervisor, before it forks.

        `slots` is per worker. At the query log's 250 ms flush interval, 2048
        slots is a little over 8000 queries per second per worker before
        anything is shed — far above what the hardware this targets can answer.
        """
        import multiprocessing
        size = lanes * (_LANE_HDR.size + slots * slot_bytes)
        mm = mmap.mmap(-1, size)    # anonymous MAP_SHARED: inherited across fork
        locks = [multiprocessing.Lock() for _ in range(lanes)]
        return cls(mm, locks, lanes, slots, slot_bytes)

    def for_lane(self, lane: int) -> RecordRing:
        """This ring as seen by worker `lane`. Same memory, same locks."""
        return RecordRing(self.mm, self.locks, self.lanes, self.slots,
                          self.slot_bytes, lane)

    # ---- layout ----
    def _lane_off(self, lane: int) -> int:
        return lane * (_LANE_HDR.size + self.slots * self.slot_bytes)

    def _slot_off(self, lane: int, index: int) -> int:
        return (self._lane_off(lane) + _LANE_HDR.size
                + (index % self.slots) * self.slot_bytes)

    # ---- writer ----
    def push(self, row: list) -> bool:
        """Publish one row. False when the lane is full and the row was dropped."""
        try:
            payload = json.dumps(row, separators=(",", ":")).encode()
        except (TypeError, ValueError):
            return False
        if len(payload) + _LEN.size > self.slot_bytes:
            shrunk = self._shrink(row)
            if shrunk is None:
                return False
            payload = shrunk
        off = self._lane_off(self.lane)
        with self.locks[self.lane]:
            head, tail, dropped = _LANE_HDR.unpack_from(self.mm, off)
            if head - tail >= self.slots:
                _LANE_HDR.pack_into(self.mm, off, head, tail, dropped + 1)
                return False
            slot = self._slot_off(self.lane, head)
            _LEN.pack_into(self.mm, slot, len(payload))
            self.mm[slot + _LEN.size: slot + _LEN.size + len(payload)] = payload
            _LANE_HDR.pack_into(self.mm, off, head + 1, tail, dropped)
        return True

    def _shrink(self, row: list) -> bytes | None:
        """Drop the answers and retry once.

        The answer list is the only unbounded field, and it is the least load
        bearing: it is context on a row whose subject is the question. Losing it
        is better than losing the row.
        """
        row = list(row)
        for i, value in enumerate(row):
            if isinstance(value, str) and value.startswith("["):
                row[i] = "[]"
        payload = json.dumps(row, separators=(",", ":")).encode()
        return payload if len(payload) + _LEN.size <= self.slot_bytes else None

    # ---- reader ----
    def drain(self, limit: int = 4096) -> list[list]:
        """Every row published since the last drain, across all lanes."""
        out: list[list] = []
        for lane in range(self.lanes):
            if lane == self.lane and self.lanes > 1:
                continue        # the primary's own records go straight to SQLite
            out.extend(self._drain_lane(lane, limit - len(out)))
            if len(out) >= limit:
                break
        return out

    def _drain_lane(self, lane: int, limit: int) -> list[list]:
        out: list[list] = []
        off = self._lane_off(lane)
        while len(out) < limit:
            with self.locks[lane]:
                head, tail, dropped = _LANE_HDR.unpack_from(self.mm, off)
                if tail >= head:
                    break
                slot = self._slot_off(lane, tail)
                (length,) = _LEN.unpack_from(self.mm, slot)
                raw = bytes(self.mm[slot + _LEN.size: slot + _LEN.size + length])
                _LANE_HDR.pack_into(self.mm, off, head, tail + 1, dropped)
            try:
                out.append(json.loads(raw))
            except ValueError:
                continue        # a torn or truncated frame is one lost row
        return out

    def dropped(self) -> int:
        """How many records every lane has shed since start."""
        total = 0
        for lane in range(self.lanes):
            off = self._lane_off(lane)
            with self.locks[lane]:
                _, _, dropped = _LANE_HDR.unpack_from(self.mm, off)
            total += dropped
        return total
