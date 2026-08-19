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


class CacheKey(NamedTuple):
    # The lowercased wire form of the name, not its text. Rendering a name to
    # text costs a Python string per byte, and a dictionary key never needed to
    # be readable — only comparable.
    qname: bytes
    qtype: int
    qclass: int
    do: bool     # DNSSEC OK — secure and insecure answers cache separately
    ecs: str = ""  # ECS scope network text, "" when not ECS-scoped


@dataclass
class _Entry:
    msg: Message
    inserted: float       # monotonic
    ttl: int              # seconds, authoritative remaining-at-insert
    stale_until: float    # monotonic deadline past which even stale is dropped
    hits: int = 0


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


class Cache:
    def __init__(self, *, max_entries: int = 100_000, min_ttl: int = 0,
                 max_ttl: int = 86_400, negative_ttl: int = 900,
                 serve_stale: bool = True, serve_stale_max: int = 86_400,
                 enabled: bool = True, shared=None):
        self.max_entries = max_entries
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.negative_ttl = negative_ttl
        self.serve_stale = serve_stale
        self.serve_stale_max = serve_stale_max
        self.enabled = enabled
        self.shared = shared          # optional SharedCache (cross-worker L2)
        # called on flush() so derived copies drop too
        self.on_flush: Callable[[], None] | None = None
        self._store: OrderedDict[CacheKey, _Entry] = OrderedDict()
        self.stats = {"hits": 0, "stale_hits": 0, "misses": 0, "stores": 0,
                      "evictions": 0, "shared_hits": 0}

    @staticmethod
    def key_for(msg: Message, ecs: str = "") -> CacheKey | None:
        q = msg.question
        if q is None:
            return None
        return CacheKey(q.name.key, q.rtype, q.rclass, msg.wants_dnssec(), ecs)

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
                self._store.pop(key, None)
        # local miss -> consult the shared cross-worker cache (L2)
        shared_hit = self._shared_get(key, now)
        if shared_hit is not None:
            return shared_hit
        self.stats["misses"] += 1
        return None

    def _shared_get(self, key: CacheKey, now: float):
        if self.shared is None:
            return None
        from .shared import key64
        got = self.shared.get(key64(*key))
        if got is None:
            return None
        wire, remaining = got
        try:
            msg = Message.parse(wire)
        except Exception:
            return None
        # promote into the local L1 so subsequent hits are lock-free
        self._store[key] = _Entry(msg=msg, inserted=now, ttl=remaining,
                                  stale_until=now + remaining + self.serve_stale_max)
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
        now = time.monotonic()
        entry = _Entry(msg=detach(msg), inserted=now, ttl=ttl,
                       stale_until=now + ttl + self.serve_stale_max)
        self._store[key] = entry
        self._store.move_to_end(key)
        self.stats["stores"] += 1
        while len(self._store) > self.max_entries:
            self._store.popitem(last=False)
            self.stats["evictions"] += 1
        # write through to the shared L2 so other workers benefit
        if self.shared is not None:
            from .shared import key64
            try:
                self.shared.put(key64(*key), msg.to_wire(), ttl)
            except Exception:
                pass

    def _derive_ttl(self, msg: Message) -> int:
        mt = msg.min_ttl()
        if msg.rcode in (Rcode.NXDOMAIN, Rcode.NOERROR) and not msg.answers:
            # negative answer: use SOA minimum if present, else configured floor
            soa_ttls = [rr.ttl for rr in msg.authority if rr.rtype == Type.SOA]
            base = min(soa_ttls) if soa_ttls else self.negative_ttl
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
            if self.shared is not None:
                self.shared.clear()
            return n
        d = wire_key(domain)
        victims = [k for k in self._store
                   if k.qname == d or k.qname.endswith(d) and len(k.qname) > len(d)]
        for k in victims:
            self._store.pop(k, None)
            # also drop it from the shared L2, or the next miss reads the
            # flushed answer straight back in
            if self.shared is not None:
                from .shared import key64
                self.shared.delete(key64(*k))
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
        Path(path).write_text(json.dumps(items))
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
        for key_list, wire_hex, ttl in items:
            try:
                key = CacheKey(bytes.fromhex(key_list[0]), *key_list[1:])
                msg = Message.parse(bytes.fromhex(wire_hex))
            except Exception:
                continue
            self._store[key] = _Entry(msg=msg, inserted=now, ttl=ttl,
                                      stale_until=now + ttl + self.serve_stale_max)
            n += 1
        return n
