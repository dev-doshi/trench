"""Hot-path microbenchmarks.

Usage: python3 scripts/bench.py [--json] [--compare baseline.json]

Kept in the tree for the same reason the fuzzer is: a resolver's speed is a
property that rots silently. Every number here is a component of the cost of
answering one query, measured in isolation so a regression points at a
function rather than at "things feel slower".

`--json` writes a machine-readable snapshot; `--compare` diffs against one and
exits non-zero if anything regressed beyond the threshold.

CI runs both halves on one runner — the base commit, then the branch — because a
baseline recorded on another machine says nothing, and a shared runner is too
noisy for an absolute number to mean anything.
"""
from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import pathlib
import socket
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.engine.responses import build_block
from dnsguard.filter import FilterEngine, compile_rules
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode

# Regressions beyond this fraction fail --compare. Loose enough to absorb a
# noisy shared runner, tight enough that a real algorithmic slip shows up —
# those are rarely subtle: the ones caught so far were 10%, 31% and 19x.
# Override with --threshold on a machine that is quieter or busier than this one.
THRESHOLD = 0.10

WWW = "www.example.com."
results: dict[str, float] = {}


# Microbenchmarks are noisy upward, never downward: nothing makes a loop run
# faster than it can, but anything on the machine can make it run slower. The
# minimum of several rounds is therefore the honest estimate, and using a
# single sample produced 30% "regressions" in code that had not been touched.
ROUNDS = 5


def _report(label: str, dt: float) -> float:
    results[label] = dt
    print(f"  {label:38} {dt:8.3f} us  {1000 / dt if dt else 0:9.1f} k/s")
    return dt


def bench(label: str, fn, n: int = 100_000) -> float:
    fn()                                    # warm
    n = max(1, n // ROUNDS)
    best = min(_time_loop(fn, n) for _ in range(ROUNDS))
    return _report(label, best / n * 1e6)


def _time_loop(fn, n: int) -> float:
    t = time.perf_counter()
    for _ in range(n):
        fn()
    return time.perf_counter() - t


def bench_async(label: str, loop, coro_fn, n: int = 20_000) -> float:
    n = max(1, n // ROUNDS)
    # The counter must not restart each round: a "cache miss" benchmark that
    # replays the same indices is measuring cache hits from round two onward.
    counter = itertools.count(1)

    async def run():
        t = time.perf_counter()
        for _ in range(n):
            await coro_fn(next(counter))
        return time.perf_counter() - t

    loop.run_until_complete(coro_fn(next(counter)))
    best = min(loop.run_until_complete(run()) for _ in range(ROUNDS))
    return _report(label, best / n * 1e6)


def _query(name: str = WWW, qid: int = 1, qtype: int = Type.A) -> Message:
    m = Message(id=qid)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), qtype, Class.IN))
    return m


class _FakeForwarder:
    async def resolve(self, query: Message) -> Message:
        r = query.reply(Rcode.NOERROR)
        for i in range(3):
            r.answers.append(RR(query.question.name, Type.A, Class.IN, 300, R.A(f"1.2.3.{i}")))
        return r


def bench_codec() -> None:
    print("\nwire codec")
    q = _query()
    qb = q.to_wire()
    resp = q.reply(Rcode.NOERROR)
    for i in range(3):
        resp.answers.append(RR(Name.from_text(WWW), Type.A, Class.IN, 300, R.A(f"93.184.216.{i}")))
    rb = resp.to_wire()

    bench("parse(query)", lambda: Message.parse(qb), 200_000)
    bench("parse(response 3xA)", lambda: Message.parse(rb), 100_000)
    bench("to_wire(response)", lambda: resp.to_wire(), 200_000)
    bench("parse+to_wire roundtrip", lambda: Message.parse(rb).to_wire(), 100_000)
    n = Name.from_text(WWW)
    bench("Name.from_text", lambda: Name.from_text(WWW), 200_000)
    bench("Name.to_text", lambda: n.to_text(), 200_000)


def bench_filter() -> None:
    print("\nfilter engine (200k rules)")
    text = "\n".join(f"blocked{i}.example.com" for i in range(200_000))
    t = time.perf_counter()
    eng = FilterEngine.compile(compile_rules(text, "bench"))
    print(f"  {'compile 200k rules':38} {time.perf_counter() - t:8.3f} s")
    bench("match() hit", lambda: eng.match("blocked12345.example.com", 1), 200_000)
    bench("match() miss", lambda: eng.match(WWW.rstrip("."), 1), 200_000)


def bench_pipeline() -> None:
    print("\npipeline (object in -> object out, no sockets)")
    cfg = Config.model_validate({})
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=_FakeForwarder(), counters=Counters(), config=cfg)
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(pipe.resolve(_query(), "10.0.0.1"))
        bench_async("cache HIT", loop,
                    lambda i: pipe.resolve(_query(qid=i), "10.0.0.1"), 30_000)
        bench_async("forward (uncached)", loop,
                    lambda i: pipe.resolve(_query(f"u{i}.example.com.", i), "10.0.0.1"), 10_000)
    finally:
        loop.close()


def bench_fastpath() -> None:
    print("\nwire-resident fast path")
    from dnsguard.engine.fastpath import FastPath, query_key, ttl_offsets
    from dnsguard.transport.base import process_query

    cfg = Config.model_validate({})
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=_FakeForwarder(), counters=Counters(), config=cfg)
    fast = FastPath(pipe)
    pipe.fast = fast
    data = _query().to_wire()
    loop = asyncio.new_event_loop()
    try:
        blob = loop.run_until_complete(
            process_query(pipe, data, "10.0.0.1", "udp", stream=False, fast=fast))
    finally:
        loop.close()
    assert fast.size == 1, "nothing was recorded; the benchmark would be meaningless"

    bench("query_key()", lambda: query_key(data), 200_000)
    bench("ttl_offsets()", lambda: ttl_offsets(blob), 200_000)
    bench("serve() replay", lambda: fast.serve(data, "10.0.0.1"), 200_000)
    # The same work with bookkeeping suppressed, to show what the counters and
    # the query log cost relative to the answer itself.
    pipe.counters = _NullCounters()
    bench("serve() replay, no bookkeeping",
          lambda: fast.serve(data, "10.0.0.1"), 200_000)


class _NullCounters:
    def record(self, **kw):
        pass


def bench_bookkeeping() -> None:
    print("\nper-query bookkeeping")
    c = Counters()
    bench("counters.record()",
          lambda: c.record(client="10.0.0.1", qname="www.example.com", qtype="A",
                           action="cached", rcode="NOERROR", elapsed_us=100), 200_000)
    q = _query("ads.example.com.")
    bench("build_block()", lambda: build_block(q, "zero_ip", "0.0.0.0", "::"), 200_000)
    bench("build_block()+to_wire",
          lambda: build_block(q, "zero_ip", "0.0.0.0", "::").to_wire(), 100_000)


def bench_upstream() -> None:
    """Upstream UDP, against a local echo server.

    Absolute numbers include a real round trip; the point of the comparison is
    what a source-port pool saves over opening a socket per query.
    """
    print("\nupstream UDP (local echo server)")
    from dnsguard.transport.upstream import Upstream, parse_upstream

    class _Echo(asyncio.DatagramProtocol):
        def connection_made(self, t):
            self.t = t

        def datagram_received(self, d, a):
            g = Message.parse(d)
            r = Message(id=g.id)
            r.set_flag(0x8000, True)
            r.questions = list(g.questions)
            self.t.sendto(r.to_wire(), a)

    async def run(ports: int, n: int) -> float:
        loop = asyncio.get_running_loop()
        tr, _ = await loop.create_datagram_endpoint(_Echo, local_addr=("127.0.0.1", 0))
        port = tr.get_extra_info("sockname")[1]
        up = Upstream(parse_upstream(f"127.0.0.1:{port}"), timeout=3.0,
                      udp_source_ports=ports)
        try:
            await up.query(_query())             # warm; excludes pool construction
            t = time.perf_counter()
            for i in range(n):
                await up.query(_query(qid=i + 1))
            return time.perf_counter() - t
        finally:
            await up.close()
            tr.close()

    # The default asyncio loop, not uvloop: uvloop has no sock_recvfrom, and the
    # comparison only needs to be internally consistent.
    for label, ports in (("socket per query", 0), ("1024-port pool", 1024)):
        n = 2000
        dt = min(asyncio.new_event_loop().run_until_complete(run(ports, n))
                 for _ in range(2))
        _report(f"upstream, {label}", dt / n * 1e6)


def bench_syscalls() -> None:
    print("\nsyscall / event-loop floor")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    addr = s.getsockname()
    payload = b"x" * 80
    try:
        bench("raw sendto()", lambda: s.sendto(payload, addr), 100_000)
    finally:
        s.close()

    async def noop():
        return 1

    loop = asyncio.new_event_loop()
    try:
        n = 100_000

        async def spawn():
            t = time.perf_counter()
            for _ in range(n):
                asyncio.ensure_future(noop())
            await asyncio.sleep(0)
            return time.perf_counter() - t

        async def direct():
            t = time.perf_counter()
            for _ in range(n):
                await noop()
            return time.perf_counter() - t

        for label, coro in (("ensure_future per packet", spawn), ("direct await", direct)):
            dt = loop.run_until_complete(coro()) / n * 1e6
            results[label] = dt
            print(f"  {label:38} {dt:8.3f} us  {1000 / dt:9.1f} k/s")
    finally:
        loop.close()


def compare(path: str, threshold: float = THRESHOLD) -> int:
    base = json.loads(pathlib.Path(path).read_text())["results"]
    bad = []
    print("\ncomparison vs baseline")
    for label, now in results.items():
        was = base.get(label)
        if was is None:
            print(f"  {label:38} (new)")
            continue
        delta = (now - was) / was
        flag = "REGRESSED" if delta > threshold else ""
        print(f"  {label:38} {was:8.3f} -> {now:8.3f} us  {delta:+7.1%} {flag}")
        if delta > threshold:
            bad.append(label)
    if bad:
        print(f"\n{len(bad)} benchmark(s) regressed by more than {threshold:.0%}")
        return 1
    print("\nno regressions")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", metavar="PATH", help="write results to PATH")
    ap.add_argument("--compare", metavar="PATH", help="diff against a previous --json run")
    ap.add_argument("--quick", action="store_true", help="skip the 200k-rule filter build")
    ap.add_argument("--threshold", type=float, default=THRESHOLD,
                    help="regression fraction that fails --compare "
                         f"(default {THRESHOLD:.0%})".replace("%", "%%"))
    args = ap.parse_args()

    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loopname = "uvloop"
    except ImportError:
        loopname = "asyncio"
    print(f"python {sys.version.split()[0]}  {loopname}  {sys.platform}")

    bench_codec()
    if not args.quick:
        bench_filter()
    bench_pipeline()
    bench_fastpath()
    bench_bookkeeping()
    bench_upstream()
    bench_syscalls()

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(
            {"python": sys.version.split()[0], "loop": loopname,
             "platform": sys.platform, "results": results}, indent=2) + "\n")
        print(f"\nwrote {args.json}")
    return compare(args.compare, args.threshold) if args.compare else 0


if __name__ == "__main__":
    raise SystemExit(main())
