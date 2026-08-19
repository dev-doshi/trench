"""The wire-resident fast path: answer a repeat query without parsing it.

A DNS response is a sequence of bytes that depends only on the query that asked
for it and the answer that was found. Ask the same question twice and, apart
from the transaction id and the seconds ticked off the TTLs, the reply is the
same reply. The normal path rediscovers that every time: parse the datagram into
objects, walk a dozen pipeline stages, rebuild the objects, serialize them back.
Measured, that is ~36 µs, and ~20 µs of it is the codec alone.

So this module records the bytes the normal path produced, keyed by the exact
query that produced them, and replays them: copy the blob, patch the id, patch
the TTLs, restore the client's own capitalisation of the question. Measured at
0.7 µs.

**The key is the whole query.** Not a normalised summary of it — the question
name lowercased, and then every remaining octet verbatim: type, class, and the
entire EDNS tail with its options, plus the header flags. Anything that differs
in the query at all, in any way, produces a different key and misses. That is
what makes replay safe rather than merely fast: a hit means the recorded reply
was produced for a query byte-identical to this one (modulo the id and the
letter case DNS defines as insignificant), by the same pipeline, under the same
policy.

Correctness here is not argued, it is tested: `tests/test_fastpath_equivalence.py`
runs both paths over the hostile corpus and asserts the two replies are
byte-identical, so this file cannot drift away from the pipeline without a test
failing.
"""
from __future__ import annotations

import struct
import time

from ..wire.rrtypes import Type

_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")

# What a query may look like and still be replayable. These reject, in order:
# a response rather than a query, a non-QUERY opcode, anything but exactly one
# question, and any query arriving with answer or authority records.
_QR = 0x8000
_OPCODE_MASK = 0x7800


def query_key(data: bytes) -> tuple[bytes, int] | None:
    """`(key, question_end)` for a replayable query, or None.

    None is not a failure — it means "use the normal path", which is the answer
    for anything unusual. Nothing here interprets the query; it only locates the
    question so the name can be case-folded, because DNS says case is
    insignificant and clients randomise it (RFC 5452 0x20).
    """
    n = len(data)
    if n < 17:                                  # header + shortest question
        return None
    flags = (data[2] << 8) | data[3]
    if flags & _QR or flags & _OPCODE_MASK:
        return None
    if data[4] or data[5] != 1:                 # QDCOUNT != 1
        return None
    if data[6] or data[7] or data[8] or data[9]:  # ANCOUNT/NSCOUNT nonzero
        return None
    p = 12
    while p < n:
        ln = data[p]
        if ln == 0:
            p += 1
            break
        if ln & 0xC0:
            # A compression pointer cannot legitimately appear in a question —
            # there is nothing before it to point at. Also covers the reserved
            # label types.
            return None
        p += ln + 1
    else:
        return None
    if p + 4 > n:
        return None
    # The name is lowercased; everything after it is taken verbatim. Label
    # lengths are safe to pass through `bytes.lower()` because any octet above
    # 63 was rejected above, and 'A' is 65.
    return data[12:p].lower() + data[p:] + data[2:4], p


def ttl_offsets(blob: bytes) -> tuple[int, ...] | None:
    """Byte offsets of every record's TTL field in a serialized message.

    Walked once when an answer is recorded, so replay is a handful of
    `pack_into` calls rather than a re-serialization. OPT is skipped on purpose:
    the four octets in its TTL position are the extended rcode and flags, and
    counting a clock down over them would corrupt the response.
    """
    n = len(blob)
    if n < 12:
        return None
    counts = _U16.unpack_from(blob, 4)[0], _U16.unpack_from(blob, 6)[0], \
        _U16.unpack_from(blob, 8)[0], _U16.unpack_from(blob, 10)[0]
    qd, an, ns, ar = counts
    p = 12
    for _ in range(qd):
        p = _skip_name(blob, p)
        if p < 0 or p + 4 > n:
            return None
        p += 4
    out: list[int] = []
    for _ in range(an + ns + ar):
        p = _skip_name(blob, p)
        if p < 0 or p + 10 > n:
            return None
        rtype = _U16.unpack_from(blob, p)[0]
        if rtype != Type.OPT:
            out.append(p + 4)
        rdlen = _U16.unpack_from(blob, p + 8)[0]
        p += 10 + rdlen
        if p > n:
            return None
    return tuple(out)


def edns_option(blob: bytes, code: int) -> tuple[int, int] | None:
    """`(offset, length)` of an EDNS option's value inside a message, or None.

    Used to find the DNS cookie in both the query and the recorded reply. The
    cookie is the one part of a response that is a function of the *client*
    rather than of the question, so replay has to recompute it — and to
    recompute it in place, it has to know where it sits.
    """
    n = len(blob)
    if n < 12:
        return None
    qd = _U16.unpack_from(blob, 4)[0]
    total = qd + _U16.unpack_from(blob, 6)[0] + _U16.unpack_from(blob, 8)[0] \
        + _U16.unpack_from(blob, 10)[0]
    p = 12
    for i in range(total):
        p = _skip_name(blob, p)
        if p < 0:
            return None
        if i < qd:
            p += 4
            continue
        if p + 10 > n:
            return None
        rtype = _U16.unpack_from(blob, p)[0]
        rdlen = _U16.unpack_from(blob, p + 8)[0]
        body = p + 10
        if rtype == Type.OPT:
            end = min(n, body + rdlen)
            q = body
            while q + 4 <= end:
                ocode = _U16.unpack_from(blob, q)[0]
                olen = _U16.unpack_from(blob, q + 2)[0]
                if ocode == code:
                    return (q + 4, olen) if q + 4 + olen <= end else None
                q += 4 + olen
            return None
        p = body + rdlen
    return None


def _skip_name(blob: bytes, p: int) -> int:
    """Advance past a (possibly compressed) name. -1 if malformed."""
    n = len(blob)
    while p < n:
        ln = blob[p]
        if ln == 0:
            return p + 1
        if ln & 0xC0 == 0xC0:
            return p + 2 if p + 2 <= n else -1
        if ln & 0xC0:
            return -1
        p += ln + 1
    return -1


class WireAnswer:
    """One recorded reply, plus everything the bookkeeping will ask for.

    The log and counter fields are rendered once here rather than per hit. The
    normal path re-renders an answer's rdata to text on every single query; this
    is both faster and — because it is the very text that path produced — the
    same.
    """

    __slots__ = ("blob", "ttls", "base_ttl", "inserted", "qend", "qname", "qtype",
                 "action", "rcode", "reason", "rule", "source", "upstream",
                 "proto", "answers", "rtype", "cookie_at", "q_cookie_at")

    def __init__(self, blob: bytes, ttls: tuple[int, ...], base_ttl: int,
                 inserted: float, qend: int, *, qname: str, qtype: str,
                 action: str, rcode: str, reason: str, rule: str, source: str,
                 upstream: str, proto: str, answers: list, rtype: int = 0,
                 cookie_at: int = -1, q_cookie_at: int = -1):
        self.blob = blob
        self.ttls = ttls
        self.base_ttl = base_ttl
        self.inserted = inserted
        self.qend = qend
        self.qname = qname
        self.qtype = qtype
        self.action = action
        self.rcode = rcode
        self.reason = reason
        self.rule = rule
        self.source = source
        self.upstream = upstream
        self.proto = proto
        self.answers = answers
        self.rtype = rtype              # numeric qtype, for the detectors
        # Byte offsets of the 16-octet DNS cookie value in the reply and in the
        # query. -1 when cookies are not in play.
        self.cookie_at = cookie_at
        self.q_cookie_at = q_cookie_at


class FastPath:
    """The replay table, and the decision about whether replay is allowed.

    `usable` is deliberately a conservative gate rather than a clever one. Every
    feature that makes a response depend on something outside the query bytes
    turns it off wholesale: DNS cookies bind a response to a client address,
    plugins may rewrite anything, ECS makes answers subnet-specific, and the
    detectors carry per-client state that a replay would not update. Falling
    back costs the normal path; getting it wrong costs correctness.
    """

    __slots__ = ("pipeline", "table", "max_entries", "enabled",
                 "hits", "stores", "_policy_ids")

    # Replayable answers are per (query, policy), so this is bounded by traffic
    # diversity rather than by name count. 16k covers a home network's working
    # set several times over.
    DEFAULT_MAX = 16_384

    def __init__(self, pipeline, max_entries: int = DEFAULT_MAX):
        self.pipeline = pipeline
        self.table: dict[bytes, WireAnswer] = {}
        self.max_entries = max_entries
        self.enabled = True
        self.hits = 0
        self.stores = 0
        self._policy_ids: dict[object, bytes] = {}

    # ------------------------------------------------------------------ gates
    @property
    def usable(self) -> bool:
        p = self.pipeline
        if not (self.enabled and p.enabled):
            return False
        if p.plugins is not None and p.plugins.active:
            return False                    # a plugin may rewrite anything
        # With ECS in play the answers become subnet-specific, so a recorded
        # one cannot be replayed to another client.
        return getattr(p.config.upstream, "ecs", "off") in ("off", "strip")

    def _policy_tag(self, client_ip: str, client_id: str = "") -> bytes:
        """A short, stable tag for the policy this client resolves under.

        It has to be in the key. Two clients can send byte-identical queries and
        be owed different answers — that is the entire point of per-client
        policy — so a table keyed on the query alone would serve one client's
        verdict to the other.
        """
        clients = self.pipeline.clients
        if clients is None:
            return b"\x00\x00"
        policy = clients.identify(client_ip, client_id)
        tag = self._policy_ids.get(policy)
        if tag is None:
            tag = self._policy_ids[policy] = _U16.pack(len(self._policy_ids) + 1)
        return tag

    # ------------------------------------------------------------------ serve
    def serve(self, data: bytes, client_ip: str, client_id: str = ""):
        """Replayed response bytes, or None to fall through to the normal path."""
        if not self.usable:
            return None
        found = query_key(data)
        if found is None:
            return None
        key, qend = found
        entry = self.table.get(key + self._policy_tag(client_ip, client_id))
        if entry is None:
            return None
        now = time.monotonic()
        remaining = entry.base_ttl - (now - entry.inserted)
        if remaining <= 0:
            return None                     # let the normal path refresh it
        p = self.pipeline
        rl = p.ratelimiter
        if rl.enabled and not rl.allow(client_ip):
            return None                     # the normal path owes them a REFUSED

        # The detectors carry per-client state and must see every query, or
        # enabling them would quietly switch this path off (which is exactly
        # what happened on the first deployment: the live config has cookies,
        # DGA and tunnel detection all on, and the fast path served nothing).
        # Anything they flag is handed to the normal path, which owns flagging,
        # blocking and counting.
        if p.dga is not None and p.dga.check(entry.qname, client_ip).suspicious:
            return None
        if p.tunnel is not None and p.tunnel.inspect(entry.qname, entry.rtype, client_ip).suspicious:
            return None

        out = bytearray(entry.blob)
        out[0:2] = data[0:2]                            # the client's own id
        out[12:qend] = data[12:qend]                    # and its own letter case
        # Round up, not down. Every hop that floors a fractional TTL loses up to
        # a second, and this is the second hop: the cache had already turned 300
        # into 299, so flooring again reported 298 with no time having passed.
        # Rounding up makes an immediate replay byte-identical to the answer it
        # was recorded from, and still never exceeds that answer's own TTL.
        ttl = -int(-remaining // 1)
        for off in entry.ttls:
            _U32.pack_into(out, off, ttl)
        if entry.cookie_at >= 0 and p.cookies is not None:
            # A server cookie is HMAC(secret, client_cookie || client_ip): a
            # function of who is asking, not of what they asked. The key pins the
            # query's bytes, so the client cookie sits at a known offset; the
            # reply's cookie is recomputed and patched, which also keeps working
            # across the hourly secret rotation.
            cc = data[entry.q_cookie_at:entry.q_cookie_at + 8]
            out[entry.cookie_at:entry.cookie_at + 16] = p.cookies.make_response(cc, client_ip)
        self.hits += 1
        self._book(entry, client_ip)
        return out

    def _book(self, entry: WireAnswer, client_ip: str) -> None:
        """Count and log the hit exactly as the normal path would.

        A faster path that stops telling the truth about traffic is not faster,
        it is broken: the dashboard, the query log and the blocklist ROI report
        all read these.
        """
        p = self.pipeline
        p.counters.record(client=client_ip, qname=entry.qname, qtype=entry.qtype,
                          action=entry.action, rcode=entry.rcode,
                          upstream=entry.upstream, elapsed_us=1,
                          reason=entry.reason)
        if p.dga is not None and entry.action not in ("blocked", "block"):
            # The DGA detector learns from outcomes, not just from names: this is
            # how a random-looking name that resolves is told apart from a
            # campaign of ones that do not.
            p.dga.note_outcome(entry.qname, client_ip, entry.rcode)
        if p.learn is not None and entry.action in ("cached", "forwarded"):
            p.learn.note(entry.qname)
        if p.querylog is not None:
            from ..store.querylog import QueryRecord
            # A fresh record per hit: `enqueue` redacts fields in place at higher
            # privacy levels, so a shared instance would leak one client's
            # redaction into the next client's row.
            p.querylog.enqueue(QueryRecord(
                ts=int(time.time() * 1_000_000), client_ip=client_ip, client_id="",
                qname=entry.qname, qtype=entry.qtype, proto=entry.proto,
                action=entry.action, reason=entry.reason, rule=entry.rule,
                source=entry.source, upstream=entry.upstream, rcode=entry.rcode,
                answers=entry.answers, elapsed_us=1))

    # ------------------------------------------------------------------ store
    # Only outcomes that are a pure function of (query, policy) are recorded.
    # `authoritative` is left out because a zone edit would have to invalidate
    # it, and `safesearch`/`rewrite` because they chain further work.
    _STORABLE = frozenset({"cached", "forwarded", "blocked"})

    def store(self, data: bytes, blob: bytes, ctx) -> None:
        if not self.usable or ctx.action not in self._STORABLE:
            return
        found = query_key(data)
        if found is None:
            return
        key, qend = found
        offs = ttl_offsets(blob)
        if not offs:
            # No TTL field means nothing to count down, and therefore no honest
            # moment to stop replaying. Not recorded.
            return
        base = min(_U32.unpack_from(blob, o)[0] for o in offs)
        if base < 1:
            return                          # TTL 0 means "do not reuse this"
        resp = ctx.response
        if resp is None:
            return
        from ..wire.rrtypes import EDNSOption, type_to_text
        from .pipeline import _rcode_text
        cookie_at = q_cookie_at = -1
        if self.pipeline.cookies is not None:
            # Only a reply that actually carries a cookie has anything
            # client-specific in it. Demanding a cookie pair regardless meant
            # that with cookies enabled, every client that does not send one —
            # which is most of them — was excluded from replay entirely.
            found_r = edns_option(blob, int(EDNSOption.COOKIE))
            if found_r is not None:
                found_q = edns_option(data, int(EDNSOption.COOKIE))
                if not (found_r[1] == 16 and found_q and found_q[1] >= 8):
                    return              # a cookie we cannot recompute: not recorded
                cookie_at, q_cookie_at = found_r[0], found_q[0]
        answers = [rr.rdata.to_text() for rr in resp.answers if rr.rtype != Type.OPT]
        if len(self.table) >= self.max_entries:
            self.table.clear()              # cheaper than LRU, and rare
        self.table[key + self._policy_tag(ctx.client_ip, ctx.client_id)] = WireAnswer(
            bytes(blob), offs, base, time.monotonic(), qend,
            qname=ctx.qname or ".", qtype=type_to_text(ctx.qtype),
            action=ctx.action, rcode=_rcode_text(resp.rcode), reason=ctx.reason,
            rule=ctx.rule, source=ctx.source, upstream=ctx.upstream,
            proto=ctx.proto, answers=answers, rtype=ctx.qtype,
            cookie_at=cookie_at, q_cookie_at=q_cookie_at)
        self.stores += 1

    def clear(self) -> int:
        """Drop everything. Called whenever policy or cached data changes
        underneath us — a blocklist refresh, a cache flush, a config reload."""
        n = len(self.table)
        self.table.clear()
        self._policy_ids.clear()
        return n

    @property
    def size(self) -> int:
        return len(self.table)
