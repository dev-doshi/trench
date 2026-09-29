"""TTL + LRU answer cache with negative caching and serve-stale.

Single-event-loop design: all access happens on the loop thread, so no locks
are needed. TTLs are decremented on read so downstream clients see a correct
remaining lifetime.

Two rules this cache holds itself to, both learned the hard way:

  * **An expired entry is a miss.** Serve-stale (RFC 8767) is a fallback for
    when the upstream cannot be reached, not a substitute for refreshing. A
    cache that answers from an expired entry on the normal read path never
    refetches it, so a record whose address changed at the origin stays wrong
    for as long as stale data is retained.
  * **Callers get their own copy.** The response handed to a client is mutated
    downstream (its id, question and EDNS are rewritten per client, and a DNS
    cookie is stamped into its OPT). Handing out the stored object would let one
    client's cookie reach the next one.
"""
from __future__ import annotations

import copy
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import NamedTuple

from ..wire import RR, Message, Type
from ..wire.name import wire_key
from ..wire.rrtypes import Rcode
from .shared import key64


class CacheKey(NamedTuple):
    # The lowercased wire form of the name, not its text. Rendering a name to
    # text costs a Python string per byte, and a dictionary key never needed to
    # be readable — only comparable.
    qname: bytes
    qtype: int
    qclass: int
    do: bool     # DNSSEC OK — secure and insecure answers cache separately
    ecs: str = ""  # ECS scope network text, "" when not ECS-scoped
    # Checking Disabled. A CD=1 query is forwarded with the bit set, so the
    # upstream skips validation and returns bogus data as NOERROR instead of
    # SERVFAIL. Sharing a key with CD=0 let any client poison every other
    # client's view of a name simply by asking for it with CD set.
    cd: bool = False
    # Which named upstream set produced the answer. A client group pointed at a
    # different resolver must not be served another group's answer for the same
    # name — that is the whole point of pointing it somewhere else.
    view: str = ""


@dataclass
class _Entry:
    msg: Message
    inserted: float       # monotonic
    ttl: int              # seconds, authoritative remaining-at-insert
    stale_until: float    # monotonic deadline past which even stale is dropped
    hits: int = 0
    size: int = 0         # wire bytes, charged against `max_bytes`


def _copy_edns(edns):
    """An independent OPT. `set_option` rebinds `edns.options`, so two responses
    sharing one `Edns` share every option written into either of them — which is
    how one client's DNS cookie ends up in another client's answer."""
    if edns is None:
        return None
    dup = copy.copy(edns)
    dup.options = list(edns.options)
    return dup


def detach(msg: Message) -> Message:
    """A stored entry must not be reachable from the response we hand out.

    `_finalize` rewrites the id, question and EDNS of whatever it is given; the
    rebinding scrub and the cloak inspector also work on live responses. Record
    objects are replaced rather than edited in place, so shallow section lists
    are enough — the EDNS is not, hence `_copy_edns`.
    """
    return replace(msg, questions=list(msg.questions), answers=list(msg.answers),
                   authority=list(msg.authority), additional=list(msg.additional),
                   edns=_copy_edns(msg.edns))


#: Default bound on the wire bytes the cache holds. `max_entries` alone bounds
#: the count and not the size: at 100,000 entries an answer can be as large as
#: TCP allows, 64 KiB, so the worst case was over 6 GiB — reachable by anyone
#: able to query many names under a zone that serves large answers. Ordinary
#: traffic averages a couple of hundred bytes an answer and never gets near it.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024


class Cache:
    def __init__(self, *, max_entries: int = 100_000,
                 max_bytes: int = DEFAULT_MAX_BYTES, min_ttl: int = 0,
                 max_ttl: int = 86_400, negative_ttl: int = 900,
                 serve_stale: bool = True, serve_stale_max: int = 86_400,
                 enabled: bool = True, shared=None):
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self.bytes = 0                # wire bytes currently held
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.negative_ttl = negative_ttl
        self.serve_stale = serve_stale
        self.serve_stale_max = serve_stale_max
        self.enabled = enabled
        self.shared = shared          # optional SharedCache (cross-worker L2)
        # called on flush() so derived copies drop too
        # Return value is ignored — FastPath.clear reports a count.
        self.on_flush: Callable[[], object] | None = None
        self._store: OrderedDict[CacheKey, _Entry] = OrderedDict()
        self.stats = {"hits": 0, "stale_hits": 0, "misses": 0, "stores": 0,
                      "evictions": 0, "shared_hits": 0}

    @staticmethod
    def key_for(msg: Message, ecs: str = "", view: str = "") -> CacheKey | None:
        q = msg.question
        if q is None:
            return None
        return CacheKey(q.name.key, q.rtype, q.rclass, msg.wants_dnssec(), ecs,
                        msg.cd, view)

    def _clamp(self, ttl: int) -> int:
        return max(self.min_ttl, min(self.max_ttl, ttl))

    def get(self, key: CacheKey, *, allow_stale: bool = False) -> tuple[Message, bool] | None:
        """Return (response, is_stale) or None on miss. Response TTLs are
        decremented by elapsed age; is_stale True means serve-stale was used.

        An expired entry is a miss unless the caller explicitly asks for stale
        data — see the module docstring. The entry is kept until its stale
        deadline passes, so the caller can come back for it if the refresh it
        goes on to attempt fails.
        """
        if not self.enabled:
            return None
        now = time.monotonic()
        entry = self._store.get(key)
        if entry is not None:
            remaining = entry.ttl - (now - entry.inserted)
            if remaining > 0:
                self._store.move_to_end(key)
                entry.hits += 1
                self.stats["hits"] += 1
                return self._with_ttl(entry.msg, max(0, int(remaining))), False
            if self.serve_stale and now < entry.stale_until:
                if allow_stale:
                    self.stats["stale_hits"] += 1
                    return self._with_ttl(entry.msg, 1), True  # RFC 8767
                # expired: treat as a miss so it gets refetched, but keep the
                # entry around as a fallback in case that refetch fails
            else:
                self._discard(key)
        # local miss -> consult the shared cross-worker cache (L2)
        shared_hit = self._shared_get(key, now)
        if shared_hit is not None:
            return shared_hit
        self.stats["misses"] += 1
        return None

    def _shared_get(self, key: CacheKey, now: float):
        if self.shared is None:
            return None
        got = self.shared.get(key64(*key))
        if got is None:
            return None
        wire, remaining = got
        try:
            msg = Message.parse(wire)
        except Exception:
            return None
        # promote into the local L1 so subsequent hits are lock-free
        # Same trim `put` does. Without it this path grew L1 without limit: a
        # read-mostly worker fed by a sibling's L2 never inserts through `put`,
        # so max_entries was never enforced on it at all.
        self._insert(key, _Entry(msg=msg, inserted=now, ttl=remaining,
                                 stale_until=now + remaining + self.serve_stale_max,
                                 size=len(wire)))
        self.stats["shared_hits"] += 1
        return self._with_ttl(msg, max(0, int(remaining))), False

    def put(self, key: CacheKey, msg: Message) -> None:
        if not self.enabled:
            return
        # A failure is not an answer. SERVFAIL, REFUSED and friends describe the
        # moment, not the name: storing one turns a transient blip into an
        # outage that lasts a TTL, and — because a store also replaces whatever
        # was there — it destroys the retained answer that serve-stale exists to
        # fall back on, at exactly the moment that fallback is needed. Negative
        # answers (NXDOMAIN, NODATA) are excluded from this: they are statements
        # about the name and are cached normally, per RFC 2308.
        if msg.rcode not in (Rcode.NOERROR, Rcode.NXDOMAIN):
            return
        ttl = self._derive_ttl(msg)
        if ttl <= 0 and msg.rcode == Rcode.NOERROR and msg.answers:
            return  # explicit zero-TTL, do not cache
        try:
            wire = msg.to_wire()
        except Exception:
            return      # cannot be sized, and could not be served back either
        if len(wire) > self.max_bytes:
            return
        now = time.monotonic()
        self._insert(key, _Entry(msg=detach(msg), inserted=now, ttl=ttl,
                                 stale_until=now + ttl + self.serve_stale_max,
                                 size=len(wire)))
        self.stats["stores"] += 1
        # write through to the shared L2 so other workers benefit
        if self.shared is not None:
            try:
                self.shared.put(key64(*key), wire, ttl)
            except Exception:
                pass

    def _insert(self, key: CacheKey, entry: _Entry) -> None:
        """Store `entry` as the most recently used, then trim to both bounds."""
        self._discard(key)
        self._store[key] = entry
        self.bytes += entry.size
        self.trim()

    def _discard(self, key: CacheKey) -> None:
        old = self._store.pop(key, None)
        if old is not None:
            self.bytes -= old.size

    def trim(self) -> None:
        """Evict least recently used entries until within both bounds."""
        while self._store and (len(self._store) > self.max_entries
                               or self.bytes > self.max_bytes):
            _, old = self._store.popitem(last=False)
            self.bytes -= old.size
            self.stats["evictions"] += 1

    def _derive_ttl(self, msg: Message) -> int:
        mt = msg.min_ttl()
        if msg.rcode in (Rcode.NXDOMAIN, Rcode.NOERROR) and not msg.answers:
            # negative answer: use SOA minimum if present, else configured floor
            # RFC 2308 §4: the negative TTL is the *lesser* of the SOA's own TTL
            # and its MINIMUM field. Reading only rr.ttl ignored the floor the
            # zone actually publishes, so a name created moments ago stayed
            # NXDOMAIN for the SOA's full TTL — an hour on many zones.
            soa = [rr for rr in msg.authority if rr.rtype == Type.SOA]
            base = min((min(rr.ttl, getattr(rr.rdata, "minimum", rr.ttl))
                        for rr in soa), default=self.negative_ttl)
            return self._clamp(min(base, self.negative_ttl))
        return self._clamp(mt if mt is not None else self.min_ttl)

    def _with_ttl(self, msg: Message, ttl: int) -> Message:
        # Constructed directly rather than via `dataclasses.replace`. Replace has
        # to walk `fields()`, getattr each one and build a kwargs dict; profiling
        # a cache hit put it at the very top, four calls deep per query. Naming
        # the five fields costs a line of maintenance and about half the time.
        # Every record is rebuilt, even when its TTL already matches. Handing
        # back the stored object would alias the cache into a live response, and
        # `detach`'s "records are replaced, never edited in place" would stop
        # being a convention and start being load-bearing.
        def retimed(rrs: list) -> list:
            return [RR(rr.name, rr.rtype, rr.rclass, ttl, rr.rdata) for rr in rrs]

        return Message(id=msg.id, flags=msg.flags, questions=list(msg.questions),
                       answers=retimed(msg.answers), authority=retimed(msg.authority),
                       additional=retimed(msg.additional), edns=_copy_edns(msg.edns))

    def has_stale(self, key: CacheKey) -> bool:
        """True when an expired-but-still-retained entry could answer `key`.

        Used to decide whether a slow refresh is worth waiting out or whether
        there is something to fall back on.
        """
        if not (self.enabled and self.serve_stale):
            return False
        entry = self._store.get(key)
        return entry is not None and time.monotonic() < entry.stale_until

    def remaining(self, key: CacheKey) -> float | None:
        """Seconds of fresh TTL left for an entry, or None if absent/expired."""
        entry = self._store.get(key)
        if entry is None:
            return None
        rem = entry.ttl - (time.monotonic() - entry.inserted)
        return rem if rem > 0 else None

    def flush(self, domain: str | None = None) -> int:
        # Anything downstream holding a copy of an answer has to hear about a
        # flush too, or "clear the cache" clears only the slowest copy of it.
        if self.on_flush is not None:
            self.on_flush()
        if domain is None:
            n = len(self._store)
            self._store.clear()
            self.bytes = 0
            if self.shared is not None:
                self.shared.clear()
            return n
        d = wire_key(domain)
        victims = [k for k in self._store
                   if k.qname == d or k.qname.endswith(d) and len(k.qname) > len(d)]
        for k in victims:
            self._discard(k)
            # also drop it from the shared L2, or the next miss reads the
            # flushed answer straight back in
            if self.shared is not None:
                self.shared.delete(key64(*k))
        if self.shared is not None:
            # The victim list comes from *this* worker's L1, but L2 is shared:
            # an entry another worker cached and we never read is not in that
            # list, survives the flush, and gets promoted back on our next miss.
            # L2 is a hash table with no reverse index, so a targeted sweep is
            # not possible — and a blocklist update that silently fails to
            # invalidate is worse than the extra misses from clearing it.
            self.shared.clear()
        return len(victims)

    @property
    def size(self) -> int:
        return len(self._store)

    def dump(self, path) -> int:
        """Persist fresh entries (wire + remaining TTL) to disk."""
        import json
        from pathlib import Path
        now = time.monotonic()
        items = []
        for key, e in self._store.items():
            rem = int(e.ttl - (now - e.inserted))
            if rem <= 0:
                continue
            try:
                # the key's name is wire bytes, which JSON cannot hold — hex it
                items.append([[key.qname.hex(), *key[1:]], e.msg.to_wire().hex(), rem])
            except Exception:
                continue
        # Written aside and renamed into place. The dump runs at shutdown, which
        # is exactly when a supervisor's stop timeout sends SIGKILL; a write in
        # place cut off there left a truncated file that restored nothing.
        import os
        target = Path(path)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(json.dumps(items))
        os.replace(tmp, target)
        return len(items)

    def load(self, path) -> int:
        """Restore a previously dumped cache (entries keep their remaining TTL)."""
        import json
        from pathlib import Path
        p = Path(path)
        if not p.exists():
            return 0
        try:
            items = json.loads(p.read_text())
        except Exception:
            return 0
        now = time.monotonic()
        n = 0
        for item in items:
            # The unpack is inside the guard, not outside it. A truncated or
            # hand-edited file gives an item of the wrong shape, and unpacking
            # in the `for` clause raised straight out of `load` — discarding
            # every remaining entry over one bad row, which is the opposite of
            # what the per-item guard below exists to do.
            try:
                key_list, wire_hex, ttl = item
                key = CacheKey(bytes.fromhex(key_list[0]), *key_list[1:])
                wire = bytes.fromhex(wire_hex)
                msg = Message.parse(wire)
                # Checked here, not trusted: a TTL that is not a number used to
                # be stored as-is and then raised TypeError from `get` on every
                # query for that name, long after start-up had reported success.
                if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
                    continue
                # Capped, not clamped: it is a remaining lifetime, and raising
                # it to `min_ttl` would extend an answer past its own TTL.
                ttl = min(ttl, self.max_ttl)
            except Exception:
                continue
            # The same bounds `put` keeps. A dump taken under a larger
            # `max_entries` — or one simply edited by hand — was restored in
            # full, leaving the cache over its limit until enough new answers
            # had been stored to trim it. The file is in LRU order, so the
            # oldest are the ones dropped.
            self._insert(key, _Entry(msg=msg, inserted=now, ttl=ttl,
                                     stale_until=now + ttl + self.serve_stale_max,
                                     size=len(wire)))
            n += 1
        return min(n, len(self._store))
