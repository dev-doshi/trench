# Trench code review

**Scope:** the query hot path (`trench/engine/`, `trench/transport/`, `trench/cache/`, `trench/resolver/forwarder.py`, and the client half of `trench/transport/upstream.py`). I also looked at `clients/registry.py`, `engine/ratelimit.py`, `stats/counters.py`, `store/export.py` and the lifecycle parts of `app.py` to check for blocking I/O and unbounded growth. A second pass covered `resolver/recursive.py`, `resolver/dnssec/` and the TSIG, transfer and NOTIFY code in `auth_zone/`; see [Second pass](#second-pass-fixed-in-this-change). I did not review `api/`, `dhcp/`, `filter/`, `auth_zone/update.py` or `ops/` in depth.

**Status:** every finding is closed. M2, M3, M6, L8, L13 and the ID half of M5 were fixed on `main`. L5 is accepted as a design choice. Everything else is fixed on `main` by the follow-up commits of this review. Regression tests are in `tests/test_review_fixes.py`, `tests/test_sanitize.py`, `tests/test_upstream.py`, `tests/test_clients.py` and `tests/test_transport_base.py`. Each finding's heading is followed by its status. With all fixes in, the suite gives 2650 passed, 2 skipped and 4 failed. All four failures come from the sandbox: three are the "unwritable directory" tests defeated by running as root, and one is `test_bind_do53_uses_inet6_for_a_v6_host`, which fails because the sandbox has no IPv6. Ruff and `mypy_gate` pass.

**Branch reviewed:** `claude/beautiful-thompson-as41c7` @ `c5b3b5f`

## Tooling results

| Check | Result |
|---|---|
| `python3 scripts/mypy_gate.py` | Pass: no new type errors. 64 baselined findings no longer occur, so `--update` can shrink the baseline. |
| `ruff check trench/ tests/ scripts/` | Pass: all checks passed. |
| `pytest -q` (with `uv sync --extra dev`) | Before the fixes: 2540 passed, 2 skipped, **7 failed**. After them: 2550 passed (the 10 new regression tests included), with the same 7 failures. All 7 failures come from the sandbox: the container has no IPv6 (`EAFNOSUPPORT` in `test_doq`, `test_doh3`, `test_upstream_doq`, `test_bind_do53_uses_inet6_for_a_v6_host`), and it runs as root, which defeats the three "unwritable directory" tests. None of the failures point at the code. |

In this sandbox the pytest process also does not exit after printing its summary, with or without these fixes. The likely cause is the QUIC servers of the failed IPv6 tests, which are never stopped. The pytest installed on the system has no project dependencies (collection fails on `import aiohttp`). Run the suite through `uv run pytest`.

## Severity legend

- **High**: wrong answers, a privacy leak, or a denial-of-service lever, reproduced against the code.
- **Medium**: a correctness or robustness defect with a narrower trigger.
- **Low**: maintainability or readability, a latent bug, or a test gap.

Findings marked *Reproduced* were run with the script in the [appendix](#appendix-reproduction-script).

---

## `trench/engine/` and `trench/transport/base.py`

### H1. The server replies to DNS *responses*, so two servers can be made to ping-pong (UDP reflection loop). *Reproduced*

**Fixed.**

**Where:** `Pipeline._run` (`trench/engine/pipeline.py`, validate stage) and `transport/base.py::_formerr`.

**What happens:**
- A datagram with `QR=1` is parsed and answered with `REFUSED`.
- A malformed datagram of 2 bytes or more is answered with a 12-byte `FORMERR`, which has `QR=1` set.

Both replies are themselves responses. An attacker can spoof one packet from `victimA:53` to a Trench instance at `B:53`. B replies to A. If A is another Trench server (or any resolver that answers responses), A replies to B, and the loop keeps going with no further input from the attacker. The rate limiter does not stop the loop, because a rate-limited query also gets a `REFUSED` reply.

The fast path already declines `QR=1` (`fastpath.query_key`), but it then hands the packet to the normal path, which does answer it.

**Fix:**
- In `_UDPProtocol.datagram_received` / `process_query`, drop any UDP datagram with the QR bit set before parsing it.
- Send a FORMERR only when at least a full 12-byte header is present and `QR=0`.

RFC 1035 behaviour is to ignore a response that arrives where a query was expected. Over TCP a reply is harmless, but dropping there too keeps the two transports consistent.

**Test gap:** nothing asserts that a `QR=1` datagram gets no reply.

### H2. Request coalescing copies one client's DNS cookie into another client's answer. *Reproduced*

**Fixed.**

**Where:** `Pipeline._fetch_coalesced` together with `Pipeline._finalize`.

**Why it happens:**
1. `fut.set_result(answer)` wakes the followers through `call_soon`.
2. The leader's own `resolve_ctx` is queued ahead of them. It runs `_finalize` on `answer.resp` first, and `_finalize` calls `set_option(COOKIE, …)` with the leader's client cookie and server cookie.
3. Each follower then runs `detach(answer.resp)` on that already-finalized message.
4. A follower whose query has EDNS but no cookie never overwrites the option.

The result is that client B receives client A's client cookie and a server cookie bound to A's IP address.

The cache module's docstring names this exact leak ("one client's cookie reach the next one"), and this path gets around the protection. The same mechanism also leaks the leader's EDE option into followers when the leader was blocked, and strips upstream OPT options from followers when the leader's query had no EDNS (`_finalize` sets `resp.edns = None` on the shared object).

**Reproduction output:**
```
C leader cookie: b'AAAAAAAA\xaa\xda\xa5\xc9\x7f\xcf\xad<'
C follower (sent no cookie) cookie: b'AAAAAAAA\xaa\xda\xa5\xc9\x7f\xcf\xad<'
```

**Fix:** have the leader take its own copy before it returns: `return _Answer(detach(answer.resp), None)` for the leader too, or store a detached copy in `fut`. That way nothing a client finalizes is shared. The more robust fix is for `_finalize` to strip `COOKIE` and `EXTENDED_ERROR` from any response before it adds its own.

**Test gap:** `test_a_follower_gets_its_own_copy_of_the_answer` checks `a is not b`. It does not check that the *contents* the follower started from were untouched by the leader's finalize.

### H3. Cache hits return the first asker's letter case in the question section. *Reproduced*

**Fixed.**

**Where:** `Pipeline._finalize` only fills `resp.questions` when it is empty. `Cache._with_ttl` copies the stored question list, which keeps the casing of whoever populated the cache.

```
B cached question name: Example.COM. (asked eXaMpLe.cOm)
```

Downstream resolvers that use 0x20 (Unbound `use-caps-for-id`, and Trench's own `zerox20.verify`) treat a mismatched echo as a spoof and discard the answer. So pointing a 0x20-validating resolver at Trench fails on every cache hit and every coalesced follower.

The fast path already handles this correctly: it patches `out[12:qend] = data[12:qend]`. That makes the two paths disagree, and `test_fastpath_equivalence.py` does not catch it because it never varies case between the recording query and the replayed one.

**Fix:** in `_finalize`, always set `resp.questions = list(ctx.query.questions)` when the response's question matches the query's by key. It is one list copy.

### M1. The safe-search chain bypasses `_fetch`, the per-group upstream, and the cache.

**Fixed.** The target is resolved through `_fetch_coalesced` with its own cache key, so it gets the group upstream, sanitising, caching and coalescing.

**Where:** `Pipeline._safe_search_chain` calls `self.forwarder.resolve(sub)` directly.

- **Invariant break:** `_fetch`'s docstring says it is "the only path by which an upstream answer enters this resolver". This call skips 0x20 verification, `sanitize`, the rebinding scrub and cloak inspection. The records it copies are rewritten to the target's owner name without any check.
- **Wrong upstream:** it ignores `_forwarder_for(ctx)`. A client in a named upstream group has its safe-search lookups sent to the default resolver, which the group setting exists to prevent.
- **No caching or coalescing:** every safe-search `A`/`AAAA` query for a search engine costs a full upstream round trip.
- **Silent failure:** `except Exception: pass` hides every failure, including internal bugs.

**Fix:** resolve the target with a synthetic `QueryContext` through `_fetch_coalesced` (with a cache key), in the same way `warm()` does.

### M2. The stream frontend drops answers on half-close, and its idle timer cuts off slow in-flight queries. *Reproduced (half-close)*

**Fixed on `main`.**

**Where:** `transport/stream.py::serve_stream`.

When the peer half-closes after sending its queries (`shutdown(SHUT_WR)`, `nc -N`, and some stub resolvers do this), `_read` returns `None` and the loop breaks. The `finally` block then **cancels every in-flight task**, so the client gets no answers:

```
D bytes received after half-close: 0
```

The same `finally` runs when the idle read times out. A client that sends one query and then waits for an answer longer than `idle_timeout` loses it. For example, a recursive resolution or a slow upstream with `idle_timeout=10`. RFC 7766 §6.2.3 measures idleness from the last *activity*, and an outstanding query counts as activity.

**Fix:**
- On EOF or idle timeout, stop reading but `await asyncio.wait(inflight, timeout=...)` before closing. Cancel only on a hard error or at shutdown.
- Only start the idle timer while `inflight` is empty.

### L1. Cloak inspection swallows exceptions.

**Fixed.** The failure is logged with `log.exception`.

`_fetch` wraps `inspect_cloak` in `except Exception: d = None`. A bug there silently disables CNAME-cloak blocking. The module's own comments argue that our own failures should be logged as errors (see `_resolve_upstream`). At minimum, add `log.exception`.

### L2. The ECS fallback lookup double-counts misses.

**Fixed.** `Cache.get` takes `count_miss`, and the ECS probe passes `count_miss=False`.

`_run` calls `cache.get(key)` and then `cache.get(key._replace(ecs=""))`. When the second call hits, the first has already incremented `stats["misses"]`, so the reported hit rate reads low. A `count_miss=False` flag on the first lookup would fix this.

### L3. Prefetch has no concurrency bound and does not go through the coalescing table.

**Fixed.** Prefetch goes through `_fetch_coalesced` and is capped at `PREFETCH_MAX` in flight.

`_maybe_prefetch` calls `_fetch` directly. A burst of popular names entering `PREFETCH_WINDOW` together, which is typical after a restart with a restored cache, launches one upstream query per key with no cap. A client query that arrives when the entry expires does not coalesce with a prefetch that is still in flight. A small semaphore, plus routing through `_fetch_coalesced`, fixes both.

### L4. The fast path clears its whole table when full.

**Fixed.** The table evicts its oldest entries one at a time.

`FastPath.store` calls `self.table.clear()` at `max_entries`. This is documented as a deliberate choice. The downside is that a busy server repeatedly drops to 0% replay all at once. An `OrderedDict` trimmed with `popitem(last=False)`, which `Cache` already does, costs about the same.

---

## `trench/cache/`

### M3. `Cache.load` ignores `max_entries`, the TTL clamps and the shape of each row.

**Fixed on `main`.**

- Restored entries are inserted without the trim loop that `put` and `_shared_get` run. A cache dumped with a larger `max_entries` (or edited by hand) restores above the configured bound, and stays there until the next `put`.
- `ttl` is taken from the file as written: it is not clamped to the current `min_ttl`/`max_ttl` and not checked for being a positive int. After an operator lowers `max_ttl`, restored entries keep the old, longer lifetime.
- `CacheKey(bytes.fromhex(...), *key_list[1:])` does not check field types. A malformed row can create a key that never matches anything but still takes a slot.

**Fix:** run `self._clamp(int(ttl))`, skip rows where `ttl <= 0`, and trim after loading.

### M4. `Cache.dump` is non-atomic and runs synchronously on the event loop at shutdown.

**Fixed.** `App.stop` calls `Cache.dump_async`, which serialises and writes in a worker thread. The write goes to a temporary file, is fsynced and then renamed over the old one.

`App.stop` calls `cache.dump()` before the frontends are stopped. That serializes up to `max_entries` messages to JSON on the loop thread while listeners are still accepting queries. `Path.write_text` also truncates the file before writing, so a crash or `SIGKILL` part-way through leaves a truncated file. `load` then discards the entire file.

**Fix:** stop the frontends first (or run the dump in `asyncio.to_thread`), and write to a temporary file followed by `os.replace`.

### L5. The memory bound counts entries, not bytes.

**Accepted as a design choice.** The bound stays a count. Operators size `max_entries` for their memory.

`max_entries=100_000` is a count. Responses fetched over TCP can reach 64 KiB each, so the worst case is several GiB. By comparison, L2 caps each payload at 1232 bytes. Add a per-entry size cap for L1, such as skipping `put` for responses over a threshold, or add byte accounting.

### L6. Targeted flush matching on wire suffixes is technically imprecise.

**Fixed.** `wire.name.key_is_under` confirms the match on a label boundary. `flush` and `is_subdomain_of` both use it.

`k.qname.endswith(d)` on wire-format keys works for ordinary names. A label containing a byte equal to a length octet (legal in wire format) can produce a false-positive suffix match. The consequence is only an extra eviction. Comparing label boundaries (for example, `wire_key` split into labels) would make the match exact.

### L7. `get()` does not refresh LRU position on a stale hit.

**Fixed.** A stale hit calls `move_to_end`.

The stale-serve path does not call `move_to_end`. An entry that is actively being served stale during an upstream outage can be evicted before entries nobody reads. Small change, worth making given the RFC 8767 intent.

---

## `trench/transport/upstream.py` and `trench/resolver/forwarder.py`

### M5. The DoQ upstream sends the client's message ID and opens a new QUIC connection for every query.

**Fixed.** The ID half was fixed on `main`. This change adds `DoQClient` (`transport/quicclient.py`), which keeps one connection per upstream and reconnects only when that connection dies.

- RFC 9250 §4.2.1: "the DNS Message ID **MUST** be set to 0." `_doq` sends `msg.to_wire()` with the client's ID. Strict servers may close the connection with `DOQ_PROTOCOL_ERROR`.
- Each query runs `aioquic.connect(...)`, a full handshake. `self.timeout` does not bound that handshake, because `wait_for` covers only the response future. An unreachable DoQ upstream can therefore hold a query for aioquic's idle timeout rather than for `upstream.timeout`.
- The protocol class is defined inside the method on every call.

**Fix:** zero the ID (restore it on the response, as the TCP path does), put the whole `async with connect(...)` inside `wait_for`, and pool connections the way `_StreamConn` does for DoT.

RFC 8484 §4.1 makes an ID of 0 a SHOULD for DoH as well. The comment `# RFC 8484: id is 0` next to `_check_response` is inaccurate: nothing sets it.

### M6. `_StreamConn.query` has no timeout on `drain()`, and does not close the replaced writer.

**Fixed on `main`.**

- `await self.writer.drain()` sits outside the `wait_for`. An upstream that stops reading (zero TCP window) blocks the query indefinitely. `Pipeline._resolve_upstream` has no overall deadline unless a stale entry exists. On UDP each blocked query also holds an `inflight` slot, so a stalled DoT upstream can eventually fill `udp_max_inflight`, and after that every UDP query is dropped.
- When the read loop ends on EOF, `_abort` marks the connection closed but never closes `self.writer`. `_open` then overwrites it. The previous transport stays open until garbage collection, and DoT providers close idle connections often. The one-shot `_tcp` fallback has the same missing timeout on `drain`.

**Fix:** wrap the whole write, drain and wait sequence in a single `wait_for(…, self.up.timeout)`, and close any previous writer inside `_open`.

### L8. `fastest` demotes an upstream permanently after one failure.

**Fixed on `main`** (`_FAILURE_MEMORY` in `resolver/forwarder.py`).

`failures` resets only on success, and an upstream sorted last is only asked when the head fails. So after a single transient error, a faster upstream can go unused indefinitely. Add decay or occasional probing, for example resetting `failures` after N seconds.

### L9. `_tcp`'s `server_hostname` expression is hard to read (readability).

**Fixed.** The expression is now parenthesised as `(sni or None) if ssl_ctx else None`. Its meaning is unchanged. Commit `8908baf` wrongly called this a behaviour bug, and the code comment has been corrected.

`server_hostname=self.spec.sni or None if ssl_ctx else None` is correct, because it parses as `(sni or None) if ssl_ctx else None`. It still reads like a precedence bug, and it is spelled differently from the equivalent at line 296 (`(spec.sni or spec.host) if ssl_ctx else None`). Parenthesise it and use one form in both places.

### L10. A spoofed response with a matching ID fails the query instead of being ignored.

**Fixed.** `_UdpSocket` records each query's question and holds back a reply whose question does not match (RFC 5452 §9.1), so the real reply can still arrive. If nothing better arrives before the timeout, the held reply goes to `_check_response`, which fails it with the usual "different question" error. A reply with no question (a bare FORMERR) goes straight through.

`_UdpSocket.datagram_received` resolves the waiter for any datagram with a matching ID. `_check_response` then raises on a question mismatch, which fails the whole query when it could have kept waiting for the genuine reply. This is low severity, since the spoofer still has to guess the ID and the outcome is a SERVFAIL rather than poisoning. The more robust approach is to validate before resolving the future.

---

## `trench/transport/doh.py`, `trench/transport/doq.py`

### L11. DoH rejects a valid `Content-Type` with parameters.

**Fixed.** The check compares the parsed `request.content_type`.

`request.headers.get("Content-Type") != "application/dns-message"` is an exact string comparison, so `application/dns-message; charset=…` gets a 415 response. Compare `request.content_type` (the parsed media type) instead.

### L12. The DoQ server reads the peer address from private aioquic state.

**Fixed.** `LimitedQuicProtocol` takes the peer from the first datagram passed to the public `datagram_received` callback. `doq.py` and `doh3.py` read it through `peer_ip()`.

`self._quic._network_paths[0].addr[0]` is private API. It breaks silently (`"?"` for every client, which merges every client into one policy and one rate-limit bucket) if aioquic changes it. Capture the address in `connection_made` or from the transport's `peername`.

### L13. The DoQ server can answer a stream twice.

**Fixed on `main`.**

If a stream's buffer is `_complete` before `end_stream` arrives, the answer task starts and the buffer is removed. A later `StreamDataReceived` on the same stream then starts a new buffer and, if `end_stream` is set, a second `_answer`. Track the IDs of streams already answered.

---

## Second pass (fixed in this change)

### H4. Hop-by-hop EDNS options crossed hops, and a client's ECS poisoned the shared cache.
`_prepare_forward` copied the client's EDNS options upstream: its DNS COOKIE, and its ECS option when `ecs` was `off`. `_fetch` then cached the upstream reply with the upstream's COOKIE still in it, and served that COOKIE to later clients. A client that sent ECS with `ecs: off` got an answer tailored to its chosen subnet, and that answer was cached globally for everyone.
**Fix:** the forwarded EDNS is always rebuilt without COOKIE, TCP-KEEPALIVE, PADDING and any client ECS; `_fetch` strips the same hop-by-hop options before caching; `_finalize` drops any leftover COOKIE before it adds its own. NSID and other end-to-end options are kept.

### D1. DNSSEC: algorithm 7 (RSASHA1-NSEC3-SHA1) was treated as unknown.
`validate.py` mapped algorithms 5 and 8/10 to hashes but not 7, so zones signed with algorithm 7 (still common among NSEC3 zones) failed validation. **Fix:** 7 maps to SHA-1, like 5.

### D2. DNSSEC: a DS set that used only unsupported algorithms or digests made the zone BOGUS.
RFC 4035 §5.2 says a zone like that is INSECURE. BOGUS turns a signing change by the parent into SERVFAIL for the whole zone. **Fix:** `_delegation` filters DS records to `SUPPORTED_ALGOS` × `SUPPORTED_DIGESTS` and returns insecure if none remain.

### D3. Recursive: AD was set on answers whose CNAME chain was never validated.
`_apply_validation` validated the final RRset only, using RRSIGs that were not filtered by owner name. A forged or unsigned CNAME in front of a signed target still produced AD=1. **Fix:** RRSIGs are matched by owner, and each CNAME is validated. The weakest verdict wins, so a bogus link makes the answer BOGUS and an insecure link makes it INSECURE.

### T1. TSIG: BADSIG and BADKEY errors were signed with the key.
RFC 8945 §5.3.2 requires an empty MAC. Signing the error reply turned the server into a signing oracle for arbitrary messages. **Fix:** `sign_error` sends an empty MAC for errors 16 and 17.

### T2. TSIG: multi-message transfers used the full-variable digest on every message.
RFC 8945 §5.3.1 digests only the timers after the first message. BIND and Knot secondaries rejected Trench's signed AXFR, and Trench rejected theirs. **Fix:** `sign_wire` and `verify_wire` take `timers_only`. The primary uses it for message 2 onward. The secondary tries timers-only first and falls back to full variables for older Trench primaries.

### T3. A signed NOTIFY got an unsigned reply.
RFC 8945 §5.3 requires a signed reply. Strict primaries discard an unsigned NOTIFY acknowledgement and keep retrying. **Fix:** the reply is signed with the request MAC chained in.

### Lows from the second pass (all fixed)
- A request whose TSIG carries a non-zero error field was accepted. `verify_wire` now fails it with BADSIG.
- A message with more than one OPT record was accepted. It now fails to parse, so the client gets FORMERR (RFC 6891 §6.1.1).
- `ECS.from_bytes` did not validate the family or the prefix lengths. It now raises on an unknown family, on a prefix longer than the address, and on an address whose length does not match its prefix. A malformed option in an upstream reply therefore keeps the answer cached per subnet instead of marking it global.
- The docstring of `is_subdomain_of` described the opposite of its behaviour. The docstring is corrected, and the function now uses the label-exact `key_is_under`.
- `sanitize` dropped the target zone's SOA after a cross-zone CNAME, so negative answers there lost their TTL. Authority records are now kept when they belong to any name on the CNAME chain or to an ancestor of one.
- `RecursiveForwarder` clears its pool without closing the connections. **No change needed:** a UDP `Upstream` opens a socket per query and holds nothing between queries. A comment now says so.

---

## Async and blocking-I/O audit

| Location | Verdict |
|---|---|
| `clients/registry._arp_lookup` | OK: reads an in-memory table; the refresh runs in a worker thread. |
| `store/export.QueryExport.write` | OK: called through `asyncio.to_thread`. |
| `gravity/manager` local list read | OK: `asyncio.to_thread`. |
| `Cache.dump` / `Cache.load`, `learn.dump` / `learn.load` in `App.start` / `App.stop` | `Cache.dump` at shutdown now runs in a worker thread (M4, fixed). The loads and `learn.dump` still block, but they run only at start-up or are small. |
| `SharedCache.get/put/clear` | Takes a cross-process `multiprocessing.Lock` on the loop thread. Critical sections are short, but a worker killed while holding a stripe lock wedges every reader of that stripe for good (the docstring acknowledges this). Consider a lock-free seqlock or timed acquires. |
| `app.py:354` zone file `read_text` | Start-up only; acceptable. |

## Unbounded-growth audit

The rate limiter (`max_keys`), the stats counters (`TopCounter` caps), the client policy LRU, the fast-path table and `Cache` (by entry count) are all bounded. The one exception is L5: the bound counts entries, not bytes, and is accepted as a design choice. M3 (the bound not applied on `load`) is fixed on `main`. `Pipeline._client_pause` grows only through operator action.

## Suggested regression tests

1. A UDP datagram with `QR=1`, and a 12-byte FORMERR-shaped packet, get **no** reply (H1).
2. Coalesced follower with EDNS and no cookie → response carries no `COOKIE` option (H2).
3. A cached answer asked with different letter case echoes the asker's case, on both the normal path and the fast path (H3), and the fast-path equivalence corpus includes mixed-case replays.
4. A TCP client that half-closes after sending N pipelined queries receives N answers (M2).
5. `Cache.load` of a dump larger than `max_entries` ends at `size == max_entries`, and restored TTLs respect `max_ttl` (M3).
6. The DoQ upstream sends message ID 0 (M5).

## Appendix: reproduction script

Run it with `uv run python repro.py` from the repository root. Output on `c5b3b5f`:

```
A server answered a QR=1 packet: qr=True rcode=5
A server answered 8-byte garbage with QR set: 123480010000000000000000
B cached question name: Example.COM. (asked eXaMpLe.cOm)
C leader cookie: b'AAAAAAAA\xaa\xda\xa5\xc9\x7f\xcf\xad<'
C follower (sent no cookie) cookie: b'AAAAAAAA\xaa\xda\xa5\xc9\x7f\xcf\xad<'
D bytes received after half-close: 0
```

```python
import asyncio, socket, sys
from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.filter import FilterEngine, compile_rules
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.edns import Edns
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, EDNSOption
from trench.transport.do53 import Do53Server

class Up:
    def __init__(self, delay=0.0): self.delay=delay; self.calls=0
    async def resolve(self, q, note=None):
        self.calls += 1
        await asyncio.sleep(self.delay)
        r = q.reply(0)
        r.answers.append(RR(q.question.name, Type.A, Class.IN, 300, R.A("1.2.3.4")))
        return r

def pipe(up, sec=None):
    raw = {"security": sec} if sec else {}
    return Pipeline(filter_engine=FilterEngine.compile(compile_rules("", "t")),
                    cache=Cache(), forwarder=up, counters=Counters(),
                    config=Config.model_validate(raw))

def q(name, txid=1, edns=False, cookie=None):
    m = Message(id=txid); m.set_flag(Flags.RD, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    if edns or cookie:
        m.edns = Edns(udp_size=1232)
        if cookie: m.edns.set_option(EDNSOption.COOKIE, cookie)
    return m

async def case_b():
    p = pipe(Up())
    await p.resolve(q("Example.COM"), "10.0.0.1")
    r = await p.resolve(q("eXaMpLe.cOm", 2), "10.0.0.2")
    print("B cached question name:", r.question.name.to_text(), "(asked eXaMpLe.cOm)")

async def case_c():
    p = pipe(Up(0.05), {"dns_cookies": True})
    a, b = await asyncio.gather(
        p.resolve(q("example.com", 1, cookie=b"AAAAAAAA"), "10.0.0.1"),
        p.resolve(q("example.com", 2, edns=True), "10.0.0.2"))
    print("C leader cookie:", a.edns.get_option(EDNSOption.COOKIE))
    print("C follower (sent no cookie) cookie:", b.edns and b.edns.get_option(EDNSOption.COOKIE))

async def case_a():
    p = pipe(Up())
    srv = Do53Server(p, "127.0.0.1", 0, tcp=False); await srv.start()
    port = srv._udp_transport.get_extra_info("sockname")[1]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setblocking(False)
    s.bind(("127.0.0.1", 0))
    resp = q("example.com"); resp.flags |= Flags.QR   # a *response* packet
    loop = asyncio.get_running_loop()
    await loop.sock_sendto(s, resp.to_wire(), ("127.0.0.1", port))
    try:
        data = await asyncio.wait_for(loop.sock_recv(s, 4096), 1)
        m = Message.parse(data)
        print("A server answered a QR=1 packet: qr=%s rcode=%s" % (m.qr, m.rcode))
    except asyncio.TimeoutError:
        print("A no reply to QR=1 packet")
    await loop.sock_sendto(s, b"\x12\x34\x80\x00" + b"\x00"*4, ("127.0.0.1", port))
    try:
        data = await asyncio.wait_for(loop.sock_recv(s, 4096), 1)
        print("A server answered 8-byte garbage with QR set:", data.hex())
    except asyncio.TimeoutError:
        print("A no reply to garbage")
    await srv.stop()

async def case_d():
    p = pipe(Up(0.05))
    srv = Do53Server(p, "127.0.0.1", 0, udp=False); await srv.start()
    port = srv._tcp_server.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", port)
    wire = q("example.com").to_wire()
    w.write(len(wire).to_bytes(2,"big") + wire); await w.drain()
    w.write_eof()     # half-close: "no more queries", still reading
    data = await r.read()
    print("D bytes received after half-close:", len(data))
    await srv.stop()

for c in (case_a, case_b, case_c, case_d):
    asyncio.run(c())
```
