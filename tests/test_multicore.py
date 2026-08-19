"""Shared cross-process scalar counters (multi-worker stats aggregation)."""
from __future__ import annotations

import asyncio
import socket as _socket

import pytest

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.filter import SimpleEngine
from dnsguard.stats import Counters
from dnsguard.stats.shared import SharedScalars
from dnsguard.transport.do53 import Do53Server
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


def test_shared_scalars_sum_across_workers(tmp_path):
    path = str(tmp_path / "stats.shm")
    SharedScalars.create(path, nworkers=3)
    w0 = SharedScalars(path, 3, 0)
    w1 = SharedScalars(path, 3, 1)
    w2 = SharedScalars(path, 3, 2)
    for _ in range(10):
        w0.inc("total"); w0.inc("blocked")
    for _ in range(5):
        w1.inc("total"); w1.inc("cached")
    for _ in range(7):
        w2.inc("total"); w2.inc("forwarded")
    # any worker's view of the aggregate is the same (sum of all rows)
    t = w0.totals()
    assert t["total"] == 22 and t["blocked"] == 10 and t["cached"] == 5 and t["forwarded"] == 7
    assert w2.totals() == t
    w0.close(); w1.close(); w2.close()


def test_counters_use_shared_aggregate(tmp_path):
    path = str(tmp_path / "s.shm")
    SharedScalars.create(path, nworkers=2)
    c0 = Counters(shared=SharedScalars(path, 2, 0))
    c1 = Counters(shared=SharedScalars(path, 2, 1))
    c0.record(client="a", qname="x.com", qtype="A", action="blocked")
    c1.record(client="b", qname="y.com", qtype="A", action="forwarded")
    c1.record(client="b", qname="z.com", qtype="A", action="cached")
    # each Counters reports the GLOBAL aggregate, not just its own slice
    snap = c0.snapshot()
    assert snap["total"] == 3 and snap["blocked"] == 1 and snap["forwarded"] == 1 and snap["cached"] == 1
    assert snap["block_pct"] == round(1 / 3 * 100, 1)


# --- Do53 over a pre-bound (inherited) socket: the multi-core sharing path ---


class _FakeFwd:
    async def resolve(self, q):
        r = q.reply(Rcode.NOERROR)
        r.answers.append(RR(q.question.name, Type.A, Class.IN, 60, R.A("9.9.9.9")))
        return r


@pytest.mark.asyncio
async def test_do53_on_inherited_socket():
    usock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    usock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    usock.bind(("127.0.0.1", 0))
    usock.setblocking(False)
    port = usock.getsockname()[1]
    pipe = Pipeline(filter_engine=SimpleEngine(blocked={"ads.test"}), cache=Cache(),
                    forwarder=_FakeFwd(), counters=__import__("dnsguard.stats", fromlist=["Counters"]).Counters(),
                    config=Config())
    srv = Do53Server(pipe, "127.0.0.1", port, udp=True, tcp=False, sock_udp=usock)
    await srv.start()
    try:
        loop = asyncio.get_running_loop()
        cs = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM); cs.setblocking(False)
        await loop.sock_connect(cs, ("127.0.0.1", port))
        q = Message(id=7); q.set_flag(0x0100, True)
        q.questions.append(Question(Name.from_text("ads.test"), Type.A, Class.IN))
        await loop.sock_sendall(cs, q.to_wire())
        data = await asyncio.wait_for(loop.sock_recv(cs, 2048), 3)
        resp = Message.parse(data)
        assert resp.answers[0].rdata.to_text() == "0.0.0.0"  # blocked path over shared sock
        cs.close()
    finally:
        await srv.stop()
