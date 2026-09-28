"""The fast path has to keep optimistic caching alive.

`Pipeline._maybe_prefetch` hangs off the cache read in `_run`, and the fast path
answers repeat queries in `datagram_received` without ever reaching it. Those are
the same queries — an entry is replayable because it is being asked for
repeatedly, which is also what makes it worth refreshing early — so prefetch
could fire for every name except the ones it was written for, and each of those
paid a full upstream round trip once per TTL.
"""
from __future__ import annotations

import asyncio

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.engine.fastpath import FastPath
from trench.engine.pipeline import PREFETCH_WINDOW
from trench.filter import FilterEngine, compile_rules
from trench.stats import Counters
from trench.transport.base import process_query
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Rcode

CLIENT = "10.0.0.5"


class Upstream:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self.calls = 0

    async def resolve(self, query: Message, note=None) -> Message:
        self.calls += 1
        q = query.question
        r = query.reply(Rcode.NOERROR)
        r.answers.append(RR(q.name, Type.A, Class.IN, self.ttl, R.A("93.184.216.34")))
        return r


def _setup(ttl: int, *, prefetch: bool = True):
    cfg = Config.model_validate({"cache": {"prefetch": prefetch}})
    up = Upstream(ttl)
    pipe = Pipeline(filter_engine=FilterEngine.compile(compile_rules("ads.example.com\n", "t")),
                    cache=Cache(), forwarder=up, counters=Counters(), config=cfg)
    return pipe, FastPath(pipe), up


def _count_calls(pipe):
    """Wrap `prefetch_replayed`, returning a callable for the count so far."""
    calls = []
    real = pipe.prefetch_replayed

    def spy(*a, **k):
        calls.append(1)
        return real(*a, **k)

    pipe.prefetch_replayed = spy
    return lambda: len(calls)


def _query(name="example.com") -> bytes:
    m = Message(id=0x1234)
    m.set_flag(Flags.RD, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m.to_wire()


def _drive(pipe, fast, data, *, replays=1, age=0):
    """Prime both caches through the normal path, then replay `replays` times.

    `age` backdates the recorded entry, which is the only way to reach the far
    end of a TTL the test did not choose — a block's TTL is `BLOCK_TTL`, not the
    upstream's.

    All of it inside one running loop, because that is where the real caller
    lives: `serve` is called from `datagram_received`, and the refresh it starts
    is a task on that loop.
    """
    async def run():
        await process_query(pipe, data, CLIENT, "udp", stream=False, fast=fast)
        for entry in fast.table.values():
            entry.inserted -= age
        served = [fast.serve(data, CLIENT) for _ in range(replays)]
        await asyncio.sleep(0)      # let the refresh task run
        await asyncio.sleep(0)
        return served

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(run())
    finally:
        loop.close()


def test_a_replay_inside_the_window_refreshes_the_entry():
    pipe, fast, up = _setup(ttl=PREFETCH_WINDOW - 10)
    data = _query()
    served = _drive(pipe, fast, data)
    assert served[0] is not None, "the query should have been replayed"
    assert up.calls == 2, "the replay should have refreshed the entry behind it"
    assert pipe.prefetches == 1


def test_a_replay_outside_the_window_refreshes_nothing():
    pipe, fast, up = _setup(ttl=PREFETCH_WINDOW + 600)
    served = _drive(pipe, fast, _query())
    assert served[0] is not None
    assert up.calls == 1, "an entry nowhere near expiry must not be refreshed"
    assert pipe.prefetches == 0


def test_repeated_replays_reach_the_pipeline_once():
    """A busy name is replayed many times a second, and the entry stays inside
    the window for the rest of its life. `Pipeline._prefetching` already stops
    the second *fetch*; what the entry's own flag stops is re-parsing the query
    and rebuilding a context on the hot path, once per replay, to be told no."""
    pipe, fast, up = _setup(ttl=PREFETCH_WINDOW - 10)
    asked = _count_calls(pipe)
    served = _drive(pipe, fast, _query(), replays=25)
    assert all(s is not None for s in served)
    assert asked() == 1, "25 replays must not re-parse 25 times"
    assert up.calls == 2
    assert pipe.prefetches == 1


def test_the_prefetch_switch_is_honoured():
    pipe, fast, up = _setup(ttl=PREFETCH_WINDOW - 10, prefetch=False)
    _drive(pipe, fast, _query())
    assert up.calls == 1
    assert pipe.prefetches == 0


def test_a_replayed_block_is_not_taken_to_the_pipeline():
    """Nothing upstream backs a block, so there is nothing to refresh — and on
    this deployment blocks are a fifth of all traffic, so paying a parse per
    replayed block to discover that is not free."""
    from trench.engine.responses import BLOCK_TTL

    pipe, fast, up = _setup(ttl=300)
    asked = _count_calls(pipe)
    served = _drive(pipe, fast, _query("ads.example.com"), replays=5,
                    age=BLOCK_TTL - PREFETCH_WINDOW + 1)   # inside the window
    assert all(s is not None for s in served), "a block is replayable"
    assert asked() == 0
    assert up.calls == 0
    assert pipe.prefetches == 0
