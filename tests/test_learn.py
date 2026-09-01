"""Learned popularity + prewarm: EWMA math, decay/prune/cap, persistence,
prewarm sweep semantics, and the pipeline note gate."""
from __future__ import annotations

import pytest

from trench.cache import Cache
from trench.learn import PopularityTracker, prewarm
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


# --- EWMA math ---
def test_fold_blends_and_ranks():
    t = PopularityTracker(alpha=0.5)
    for _ in range(8):
        t.note("popular.com.")
    t.note("rare.com.")
    t.fold()
    assert t.scores["popular.com."] == pytest.approx(4.0)   # 0.5*8
    assert t.scores["rare.com."] == pytest.approx(0.5)
    assert t.top(1) == ["popular.com."]


def test_absent_names_decay_to_forgotten():
    t = PopularityTracker(alpha=0.5, floor=0.05)
    t.note("once.com.")
    t.fold()                                   # score 0.5
    for _ in range(4):                         # halves each fold: 0.25, 0.125, 0.0625, 0.03125
        t.fold()
    assert "once.com." not in t.scores         # dropped below the floor


def test_max_entries_cap_keeps_strongest():
    t = PopularityTracker(alpha=1.0, max_entries=3, floor=0.01)
    for i in range(10):
        for _ in range(i + 1):
            t.note(f"d{i}.com.")
    t.fold()
    assert len(t) == 3
    assert set(t.top(3)) == {"d9.com.", "d8.com.", "d7.com."}


def test_window_bounded_under_flood():
    t = PopularityTracker(max_entries=10)
    for i in range(1000):                      # random-subdomain flood
        t.note(f"x{i}.evil.com.")
    assert len(t._window) <= 40                # 4x max_entries bound


def test_persistence_roundtrip(tmp_path):
    t = PopularityTracker(alpha=1.0)
    t.note("keep.com."); t.note("keep.com.")
    t.fold()
    path = tmp_path / "pop.json"
    assert t.dump(path) == 1
    t2 = PopularityTracker()
    assert t2.load(path) == 1
    assert t2.top(1) == ["keep.com."]


def test_load_corrupt_file_starts_fresh(tmp_path):
    p = tmp_path / "pop.json"
    p.write_text("{not json")
    t = PopularityTracker()
    assert t.load(p) == 0 and len(t) == 0


# --- prewarm sweep ---
def _resp_for(q: Message, ttl=300) -> Message:
    resp = q.reply(Rcode.NOERROR)
    if q.question.rtype == Type.A:
        resp.answers.append(RR(q.question.name, Type.A, Class.IN, ttl, R.A("192.0.2.1")))
    else:
        resp.answers.append(RR(q.question.name, Type.AAAA, Class.IN, ttl, R.AAAA("2001:db8::1")))
    return resp


class FakeForwarder:
    """Stands in for `Pipeline.warm`, which resolves *and* caches.

    Prewarm must not write to the cache itself: doing so was a way into the cache
    that skipped the checks every client-driven answer goes through.
    """

    def __init__(self, cache=None):
        self.calls: list[str] = []
        self.cache = cache

    async def resolve(self, q: Message, note=None) -> Message:
        self.calls.append(f"{q.question.name.to_text()}/{q.question.rtype}")
        resp = _resp_for(q)
        if self.cache is not None:
            self.cache.put(self.cache.key_for(q), resp)
        return resp


@pytest.mark.asyncio
async def test_prewarm_fills_cold_cache():
    t = PopularityTracker(alpha=1.0)
    t.note("hot.com."); t.fold()
    cache = Cache()
    fwd = FakeForwarder(cache)
    warmed = await prewarm(t, cache, fwd.resolve, top=10)
    assert warmed == 2                                     # A + AAAA
    q = Message(id=1); q.set_flag(0x0100, True)
    q.questions.append(Question(Name.from_text("hot.com."), Type.A, Class.IN))
    assert cache.get(cache.key_for(q)) is not None         # future queries hit


@pytest.mark.asyncio
async def test_prewarm_skips_fresh_entries():
    t = PopularityTracker(alpha=1.0)
    t.note("fresh.com."); t.fold()
    cache = Cache()
    fwd = FakeForwarder(cache)
    await prewarm(t, cache, fwd.resolve, top=10)           # fills both qtypes
    fwd.calls.clear()
    warmed = await prewarm(t, cache, fwd.resolve, top=10, min_remaining=60)
    assert warmed == 0 and fwd.calls == []                 # TTL 300 still fresh


@pytest.mark.asyncio
async def test_prewarm_survives_hostile_name_and_failures():
    t = PopularityTracker(alpha=1.0)
    t.note("." + "x" * 300); t.note("ok.com.")             # unparseable name first
    t.fold()

    class FlakyForwarder(FakeForwarder):
        async def resolve(self, q, note=None):
            if q.question.rtype == Type.AAAA:
                raise OSError("upstream down")
            return await super().resolve(q)

    warmed = await prewarm(t, Cache(), FlakyForwarder().resolve, top=10)
    assert warmed == 1                                     # ok.com A succeeded


# --- pipeline gate: blocked names are never learned ---
def test_pipeline_notes_only_served():
    from trench.config import Config
    from trench.engine.context import QueryContext
    from trench.engine.pipeline import Pipeline
    from trench.stats import Counters

    p = Pipeline(filter_engine=None, cache=Cache(), forwarder=None,
                 counters=Counters(), config=Config())
    notes: list[str] = []

    class T:
        def note(self, n): notes.append(n)
    p.learn = T()

    for action, expected in [("cached", True), ("forwarded", True),
                             ("blocked", False), ("refused", False),
                             ("failed", False)]:
        q = Message(id=1)
        q.questions.append(Question(Name.from_text(f"{action}.com."), Type.A, Class.IN))
        ctx = QueryContext(query=q, client_ip="127.0.0.1")
        ctx.action = action
        ctx.response = q.reply(Rcode.NOERROR)
        p._finalize(ctx)                                   # the real path
        assert (f"{action}.com" in notes[-1] if expected
                else all(action not in n for n in notes))
    assert len(notes) == 2                                 # cached + forwarded only
