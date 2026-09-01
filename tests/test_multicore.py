"""Shared cross-process scalar counters (multi-worker stats aggregation)."""
from __future__ import annotations

import asyncio
import socket as _socket

import pytest
from support import blocked_engine

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.stats import Counters
from trench.stats.shared import SharedScalars
from trench.transport.do53 import Do53Server
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


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
    async def resolve(self, q, note=None):
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
    pipe = Pipeline(filter_engine=blocked_engine("ads.test"), cache=Cache(),
                    forwarder=_FakeFwd(), counters=__import__("trench.stats", fromlist=["Counters"]).Counters(),
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


def test_the_series_aggregates_across_workers_like_the_totals(tmp_path):
    """The console draws the chart from `series()` and the tiles above it from
    `snapshot()`. With the series per worker, the two disagreed by a factor of
    `nworkers` in the same response, and nothing distinguished them."""
    path = str(tmp_path / "series.shm")
    SharedScalars.create(path, nworkers=3)
    cs = [Counters(shared=SharedScalars(path, 3, i)) for i in range(3)]

    for i, c in enumerate(cs):
        for _ in range(i + 1):                       # 1, then 2, then 3
            c.record(client="a", qname="x.test", qtype="A", action="blocked",
                     elapsed_us=1000)

    for c in cs:
        snap = c.snapshot()
        assert snap["total"] == 6 and snap["blocked"] == 6
        # the most recent bucket has to carry the same six, whichever worker asks
        latest = c.series(2)[-1]
        assert latest["total"] == 6 and latest["blocked"] == 6
        assert latest["latency_ms"] == 1.0
    for c in cs:
        c.shared.close()


def test_a_recycled_minute_starts_from_zero(tmp_path):
    """The ring is 180 minutes wide; three hours later the same slot comes round
    again and must not be added to."""
    path = str(tmp_path / "recycle.shm")
    SharedScalars.create(path, nworkers=1)
    sh = SharedScalars(path, 1, 0)
    minute = 1_700_000_000 // 60 * 60
    sh.add_minute(minute, "blocked", 500)
    sh.add_minute(minute, "cached", 500)
    assert sh.minute(minute) == {"total": 2, "blocked": 1, "cached": 1,
                                 "forwarded": 0, "failed": 0,
                                 "lat_sum": 1000, "lat_n": 2}

    later = minute + 180 * 60                        # exactly one lap
    sh.add_minute(later, "forwarded", 0)
    assert sh.minute(later) == {"total": 1, "blocked": 0, "cached": 0,
                                "forwarded": 1, "failed": 0,
                                "lat_sum": 0, "lat_n": 0}
    assert sh.minute(minute) is None                 # the old stamp is gone
    sh.close()
