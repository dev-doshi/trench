"""Blocklist storage that is shared, restartable, and swappable.

A 600k-domain aggregate held as `dict[str, str]` costs ~200 MB resident, and
every forked worker pays it again — which is why a 4-core, 1 GB board ends up
running one worker. The dict is not even the expensive part: the per-string
object headers and refcount fields are. Refcounts also defeat the obvious fix,
because merely *reading* a shared Python object writes to its header and
copy-on-write hands the child a private page.

So the domains leave the object graph entirely:

  * every domain is appended to one `blob` of raw UTF-8;
  * an open-addressed table of 64-bit slots maps crc32(domain) to a packed
    (offset, length, source-id) triple pointing into that blob.

Both live in one mmap. Backed by a file it is better than merely shared: the
kernel page cache holds a single copy for every process that maps it, the table
survives a restart (so a resolver can answer queries immediately instead of
re-downloading and re-parsing 600k domains first), and a refresh can be handed
over by writing a new file and letting readers re-map it — no IPC, no signals,
no duplicated parse in four workers.

`crc32` rather than the faster built-in `hash()` is what makes all of that
possible: CPython randomises its SipHash key per process, so a `hash()`-indexed
table is only meaningful inside the process that built it. crc32 costs about
90 ns more per lookup and is stable everywhere and forever. It is a bucket
index, not a checksum — correctness does not depend on its quality.

Lookups compare the stored bytes, so this is exact: unlike a Bloom or
fingerprint table it cannot invent a block for a domain that is not on a list.
That matters more than the megabytes saved — a false positive here is a website
that mysteriously does not load.
"""
from __future__ import annotations

import json
import mmap
import os
import struct
import zlib
from collections import Counter
from pathlib import Path

_MAGIC = b"DGBT"
_VERSION = 1
_HEADER = struct.Struct("<4sIQQQQQQ")   # magic, version, nslots, n, blob_off,
_HEADER_SIZE = 64                        # blob_len, srcs_off, srcs_len (padded)

_LOAD_FACTOR = 0.7
_MIN_SLOTS = 1024
_MAX_LEN = 0xFF          # domain length that fits the packed slot
_MAX_SOURCES = 0xFFFF

# slot = (blob_offset << 24) | (length << 16) | source_id, 0 meaning empty.
# A real entry always has length > 0, so offset 0 does not collide with empty.
_OFF_SHIFT = 24
_LEN_SHIFT = 16


def _next_pow2(n: int) -> int:
    p = _MIN_SLOTS
    while p < n:
        p <<= 1
    return p


class TableFormatError(Exception):
    """An on-disk table is unreadable — always recoverable by rebuilding."""


class SharedBlockTable:
    """Immutable domain -> source map in shared memory.

    Built once, then read-only. `discard()` exists for operator edits and keeps
    a small private overlay rather than touching the shared pages.
    """

    __slots__ = ("_mm", "_slots", "_blob", "_mask", "_n", "_sources",
                 "source_counts", "_removed", "path", "token")

    def __init__(self) -> None:
        self._mm: mmap.mmap | None = None
        self._slots: memoryview | None = None
        self._blob: memoryview = memoryview(b"")
        self._mask = 0
        self._n = 0
        self._sources: list[str] = []
        self.source_counts: Counter[str] = Counter()
        self._removed: set[str] = set()
        self.path: Path | None = None
        self.token: tuple | None = None   # identity of the file this was opened from

    # --- construction ---
    @classmethod
    def build(cls, items: list[tuple[str, str]], path: str | Path | None = None,
              ) -> SharedBlockTable:
        """Compile `items` — (domain, source) in load order, first list wins.

        With `path`, the table is written there and atomically swapped into
        place, so other processes can pick it up; without, it lives in an
        anonymous mapping that only fork children will see.
        """
        nslots = _next_pow2(int(len(items) / _LOAD_FACTOR) + 1) if items else _MIN_SLOTS
        # Duplicates make this an over-estimate; the slack is never read, and an
        # untouched page costs nothing resident either way.
        blob_cap = sum(len(d) for d, _ in items) or 1

        slots_size = nslots * 8
        # The source names are a short JSON tail whose length is only known once
        # every item has been seen, so the body is assembled in a buffer and the
        # tail appended before anything is written out.
        buf = bytearray(_HEADER_SIZE + slots_size + blob_cap)
        slots = memoryview(buf)[_HEADER_SIZE:_HEADER_SIZE + slots_size].cast("Q")
        blob = memoryview(buf)[_HEADER_SIZE + slots_size:]

        mask = nslots - 1
        sources: list[str] = []
        source_id: dict[str, int] = {}
        counts: Counter[str] = Counter()
        write = 0
        n = 0
        for domain, source in items:
            raw = domain.encode()
            ln = len(raw)
            if not ln or ln > _MAX_LEN:
                continue  # unrepresentable; the caller keeps these as Rule objects
            i = zlib.crc32(raw) & mask
            dup = False
            while (v := slots[i]) != 0:
                off, vln = v >> _OFF_SHIFT, (v >> _LEN_SHIFT) & _MAX_LEN
                if blob[off:off + vln] == raw:
                    dup = True   # already supplied by an earlier list
                    break
                i = (i + 1) & mask
            if dup:
                continue
            sid = source_id.get(source)
            if sid is None:
                if len(sources) >= _MAX_SOURCES:
                    continue
                sid = source_id[source] = len(sources)
                sources.append(source)
            blob[write:write + ln] = raw
            slots[i] = (write << _OFF_SHIFT) | (ln << _LEN_SHIFT) | sid
            write += ln
            n += 1
            counts[source] += 1

        srcs = json.dumps({"sources": sources, "counts": counts}).encode()
        blob_off = _HEADER_SIZE + slots_size
        header = _HEADER.pack(_MAGIC, _VERSION, nslots, n, blob_off, write,
                              blob_off + write, len(srcs))
        buf[:len(header)] = header
        del slots, blob   # release views before truncating the bytearray

        payload = bytes(buf[:blob_off + write]) + srcs
        if path is None:
            t = cls()
            t._mm = mmap.mmap(-1, len(payload))
            t._mm[:] = payload
            t._attach()
            return t

        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
        try:
            tmp.write_bytes(payload)
            os.replace(tmp, p)   # atomic: readers see either the old or new file
        finally:
            tmp.unlink(missing_ok=True)
        return cls.open(p)

    @classmethod
    def open(cls, path: str | Path) -> SharedBlockTable:
        """Map an existing table. Read-only and shared with every other reader."""
        p = Path(path)
        fd = os.open(p, os.O_RDONLY)
        try:
            st = os.fstat(fd)
            if st.st_size < _HEADER_SIZE:
                raise TableFormatError(f"{p}: too short to be a table")
            t = cls()
            t._mm = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
        finally:
            os.close(fd)
        t.path = p
        t.token = (st.st_ino, st.st_size, st.st_mtime_ns)
        t._attach()
        return t

    def _attach(self) -> None:
        """Point the lookup views at the mapping and read back the metadata."""
        mm = self._mm
        assert mm is not None
        magic, version, nslots, n, blob_off, blob_len, srcs_off, srcs_len = \
            _HEADER.unpack_from(mm, 0)
        if magic != _MAGIC:
            raise TableFormatError(f"bad magic {magic!r}")
        if version != _VERSION:
            raise TableFormatError(f"table version {version}, expected {_VERSION}")
        if srcs_off + srcs_len > len(mm):
            raise TableFormatError("table is truncated")
        mv = memoryview(mm)
        self._slots = mv[_HEADER_SIZE:_HEADER_SIZE + nslots * 8].cast("Q")
        self._blob = mv[blob_off:blob_off + blob_len]
        self._mask = nslots - 1
        self._n = n
        meta = json.loads(bytes(mv[srcs_off:srcs_off + srcs_len]) or b"{}")
        self._sources = meta.get("sources", [])
        self.source_counts = Counter(meta.get("counts", {}))

    # --- lookup ---
    def get(self, domain: str) -> str | None:
        slots = self._slots
        if slots is None:
            return None
        raw = domain.encode()
        mask = self._mask
        i = zlib.crc32(raw) & mask
        v = slots[i]
        if v == 0:
            return None   # the common case: most names are on no list at all
        blob = self._blob
        while v != 0:
            off = v >> _OFF_SHIFT
            if blob[off:off + ((v >> _LEN_SHIFT) & _MAX_LEN)] == raw:
                if self._removed and domain in self._removed:
                    return None
                return self._sources[v & _MAX_SOURCES]
            i = (i + 1) & mask
            v = slots[i]
        return None

    def __contains__(self, domain: str) -> bool:
        return self.get(domain) is not None

    def __len__(self) -> int:
        return self._n - len(self._removed)

    def discard(self, domain: str) -> None:
        """Operator removal. The shared pages stay untouched — deleting from an
        open-addressed table would break probe chains for other domains, and a
        handful of exceptions is not worth a rebuild."""
        if self.get(domain) is not None:
            self._removed.add(domain)

    @property
    def nbytes(self) -> int:
        return len(self._mm) if self._mm is not None else 0

    def stale(self) -> bool:
        """True when the file this was opened from has since been replaced.

        The coordination mechanism for refreshes: whoever rebuilds writes a new
        file, and every other reader notices on its next check. One `stat` —
        cheap enough to poll, and it needs no knowledge of the other processes.
        """
        if self.path is None or self.token is None:
            return False
        try:
            st = self.path.stat()
        except OSError:
            return False   # mid-swap or removed; keep serving what we have
        return (st.st_ino, st.st_size, st.st_mtime_ns) != self.token

    def close(self) -> None:
        self._slots = None
        self._blob = memoryview(b"")
        if self._mm is not None:
            try:
                self._mm.close()
            except BufferError:
                pass   # a view is still alive; the GC will get it
            self._mm = None
