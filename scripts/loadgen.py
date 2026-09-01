"""UDP load generator with latency percentiles.

Usage:
  python3 scripts/loadgen.py --target 127.0.0.1:5354 --seconds 5 --concurrency 64
  python3 scripts/loadgen.py --self-test          # spin a server up in-process

Microbenchmarks measure functions; this measures the thing the user actually
waits for. It sends real queries over a real socket, so the syscalls, the event
loop and the reply path are all in the number — and it reports p99, because a
resolver whose average is fast and whose tail is not is a resolver that feels
broken.
"""
from __future__ import annotations

import argparse
import asyncio
import pathlib
import random
import socket
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from trench.wire import Class, Message, Question, Type
from trench.wire.name import Name

# A mix rather than one name repeated: a single question would sit entirely in
# whatever the innermost cache is and flatter every layer above it.
HOT = [f"host{i}.example.com" for i in range(64)]
BLOCKED = [f"ads{i}.example.com" for i in range(16)]


def build(name: str, qid: int, qtype: int = Type.A) -> bytes:
    m = Message(id=qid & 0xFFFF)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), qtype, Class.IN))
    return m.to_wire()


def percentile(sorted_us: list[float], p: float) -> float:
    if not sorted_us:
        return 0.0
    i = min(len(sorted_us) - 1, int(len(sorted_us) * p))
    return sorted_us[i]


class Flow(asyncio.DatagramProtocol):
    """One socket keeping `depth` queries in flight at all times."""

    def __init__(self, addr, names, depth, deadline, latencies):
        self.addr = addr
        self.names = names
        self.depth = depth
        self.deadline = deadline
        self.latencies = latencies
        self.transport = None
        self.sent = self.recv = self.lost = 0
        self.pending: dict[int, float] = {}
        self.qid = random.randrange(0xFFFF)
        self.done = asyncio.get_event_loop().create_future()

    def connection_made(self, transport):
        self.transport = transport
        for _ in range(self.depth):
            self._fire()

    def _fire(self):
        if time.monotonic() >= self.deadline:
            if not self.pending and not self.done.done():
                self.done.set_result(None)
            return
        self.qid = (self.qid + 1) & 0xFFFF
        name = random.choice(self.names)
        self.pending[self.qid] = time.perf_counter()
        try:
            self.transport.sendto(build(name, self.qid))
            self.sent += 1
        except Exception:
            self.pending.pop(self.qid, None)

    def datagram_received(self, data, addr):
        if len(data) < 2:
            return
        qid = (data[0] << 8) | data[1]
        started = self.pending.pop(qid, None)
        if started is None:
            return                       # a duplicate or an id we never sent
        self.latencies.append((time.perf_counter() - started) * 1e6)
        self.recv += 1
        self._fire()

    def error_received(self, exc):
        pass


async def run(host: str, port: int, seconds: float, concurrency: int,
              depth: int, names: list[str]) -> None:
    loop = asyncio.get_running_loop()
    deadline = time.monotonic() + seconds
    latencies: list[float] = []
    flows = []
    for _ in range(concurrency):
        _t, proto = await loop.create_datagram_endpoint(
            lambda: Flow((host, port), names, depth, deadline, latencies),
            remote_addr=(host, port))
        flows.append(proto)

    t0 = time.monotonic()
    # Everything is in flight already; wait out the window, then give the last
    # replies a moment to land so they are not counted as loss.
    await asyncio.sleep(seconds)
    await asyncio.sleep(0.25)
    dt = time.monotonic() - t0
    for f in flows:
        if f.transport:
            f.transport.close()

    sent = sum(f.sent for f in flows)
    recv = sum(f.recv for f in flows)
    lat = sorted(latencies)
    print(f"  sent {sent}  answered {recv}  lost {sent - recv} "
          f"({(sent - recv) / sent * 100 if sent else 0:.2f}%)")
    print(f"  throughput  {recv / dt:,.0f} answers/s over {dt:.1f}s")
    if lat:
        print(f"  latency     p50 {percentile(lat, 0.50):7.0f} us   "
              f"p99 {percentile(lat, 0.99):7.0f} us   "
              f"p99.9 {percentile(lat, 0.999):7.0f} us   "
              f"max {lat[-1]:7.0f} us")


async def _self_test(seconds: float, concurrency: int, depth: int, fast: bool) -> None:
    """Serve from an in-process pipeline on a loopback port, then hammer it."""
    from trench.cache import Cache
    from trench.config import Config
    from trench.engine import Pipeline
    from trench.engine.fastpath import FastPath
    from trench.filter import FilterEngine, compile_rules
    from trench.stats import Counters
    from trench.transport.do53 import Do53Server
    from trench.wire import RR
    from trench.wire import rdata as R
    from trench.wire.rrtypes import Rcode

    class Up:
        async def resolve(self, query):
            r = query.reply(Rcode.NOERROR)
            r.answers.append(RR(query.question.name, Type.A, Class.IN, 300,
                               R.A("93.184.216.34")))
            return r

    rules = "\n".join(BLOCKED)
    pipe = Pipeline(filter_engine=FilterEngine.compile(compile_rules(rules, "loadgen")),
                    cache=Cache(), forwarder=Up(), counters=Counters(),
                    config=Config.model_validate({}))
    fp = None
    if fast:
        fp = FastPath(pipe)
        pipe.fast = fp
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    port = sock.getsockname()[1]
    server = Do53Server(pipe, "127.0.0.1", port, tcp=False, sock_udp=sock, fast=fp)
    await server.start()
    print(f"\nfast path: {'ON' if fast else 'off'}")
    try:
        await run("127.0.0.1", port, seconds, concurrency, depth, HOT + BLOCKED)
    finally:
        await server.stop()
    if fp is not None:
        print(f"  replay      {fp.hits:,} hits, {fp.stores:,} recorded, "
              f"{fp.size} entries")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="127.0.0.1:5354", help="host:port")
    ap.add_argument("--seconds", type=float, default=5.0)
    ap.add_argument("--concurrency", type=int, default=64, help="sockets")
    ap.add_argument("--depth", type=int, default=4, help="queries in flight per socket")
    ap.add_argument("--self-test", action="store_true",
                    help="serve in-process and compare fast path on vs off")
    args = ap.parse_args()

    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass

    if args.self_test:
        for fast in (False, True):
            asyncio.run(_self_test(args.seconds, args.concurrency, args.depth, fast))
        return 0

    host, _, port = args.target.rpartition(":")
    print(f"target {host}:{port}  {args.concurrency} sockets x {args.depth} in flight")
    asyncio.run(run(host, int(port), args.seconds, args.concurrency,
                    args.depth, HOT + BLOCKED))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
