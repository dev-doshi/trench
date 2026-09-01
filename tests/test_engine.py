"""Cache, filter, and pipeline behavior (P0)."""
from __future__ import annotations

import asyncio

from support import blocked_engine

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.filter import Action
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


def mkquery(name="example.com", rtype=Type.A, txid=1):
    m = Message(id=txid)
    m.set_flag(0x0100, True)  # RD
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    return m


def mkanswer(query, ip="1.2.3.4", ttl=100):
    resp = query.reply(Rcode.NOERROR)
    q = query.question
    resp.answers.append(RR(q.name, Type.A, Class.IN, ttl, R.A(ip)))
    return resp


# --- filter ---
def test_engine_precedence():
    eng = blocked_engine("ads.com", "tracker.net", allow=("good.ads.com",))
    assert eng.match("ads.com").action == Action.BLOCK
    assert eng.match("x.ads.com").action == Action.BLOCK          # subdomain
    assert eng.match("good.ads.com").action == Action.ALLOW       # allow wins
    assert eng.match("tracker.net").action == Action.BLOCK
    assert eng.match("example.com").action == Action.NONE


# --- cache ---
def test_cache_ttl_and_expiry(monkeypatch):
    import dnsguard.cache.cache as cmod
    t = [1000.0]
    monkeypatch.setattr(cmod.time, "monotonic", lambda: t[0])
    c = Cache(serve_stale=False)
    q = mkquery()
    key = c.key_for(q)
    c.put(key, mkanswer(q, ttl=100))
    hit = c.get(key)
    assert hit is not None and hit[0].answers[0].ttl <= 100 and not hit[1]
    t[0] += 50
    assert c.get(key)[0].answers[0].ttl <= 50      # decremented
    t[0] += 100                                     # now expired
    assert c.get(key) is None


def test_cache_serve_stale(monkeypatch):
    """Stale data is a fallback the caller must ask for, not a normal hit —
    otherwise an expired entry is answered from and never refreshed."""
    import dnsguard.cache.cache as cmod
    t = [1000.0]
    monkeypatch.setattr(cmod.time, "monotonic", lambda: t[0])
    c = Cache(serve_stale=True, serve_stale_max=3600)
    q = mkquery()
    key = c.key_for(q)
    c.put(key, mkanswer(q, ttl=10))
    t[0] += 50  # expired but within stale window
    assert c.get(key) is None                       # a miss: go refresh it
    hit = c.get(key, allow_stale=True)              # the refresh failed
    assert hit is not None and hit[1] is True       # stale flag


def test_cache_negative():
    c = Cache(negative_ttl=300)
    q = mkquery("nope.example")
    resp = q.reply(Rcode.NXDOMAIN)
    key = c.key_for(q)
    c.put(key, resp)
    assert c.get(key) is not None                   # negatives cached


# --- pipeline ---
class FakeForwarder:
    def __init__(self, answer): self.answer = answer; self.calls = 0
    async def resolve(self, query, note=None):
        self.calls += 1
        a = self.answer
        a.id = query.id
        return a


def build_pipeline(forwarder, blocked=None):
    cfg = Config()
    eng = blocked_engine(*(blocked or {"doubleclick.net"}))
    return Pipeline(filter_engine=eng, cache=Cache(), forwarder=forwarder,
                    counters=Counters(), config=cfg)


def test_pipeline_blocks():
    q = mkquery("doubleclick.net")
    pipe = build_pipeline(FakeForwarder(mkanswer(q)))
    resp = asyncio.run(pipe.resolve(q, "127.0.0.1"))
    assert resp.answers[0].rdata.to_text() == "0.0.0.0"
    assert resp.id == q.id


def test_pipeline_forwards_and_caches():
    q1 = mkquery("example.com", txid=11)
    fwd = FakeForwarder(mkanswer(q1, ip="9.9.9.9"))
    pipe = build_pipeline(fwd)
    r1 = asyncio.run(pipe.resolve(q1, "127.0.0.1"))
    assert r1.answers[0].rdata.to_text() == "9.9.9.9"
    # second identical query -> served from cache, forwarder not called again
    q2 = mkquery("example.com", txid=22)
    r2 = asyncio.run(pipe.resolve(q2, "127.0.0.1"))
    assert r2.id == 22 and r2.answers[0].rdata.to_text() == "9.9.9.9"
    assert fwd.calls == 1


def test_pipeline_toggle_disables_blocking():
    q = mkquery("doubleclick.net")
    fwd = FakeForwarder(mkanswer(q, ip="5.5.5.5"))
    pipe = build_pipeline(fwd)
    pipe.enabled = False
    resp = asyncio.run(pipe.resolve(q, "127.0.0.1"))
    assert resp.answers[0].rdata.to_text() == "5.5.5.5"   # forwarded, not blocked


def test_pipeline_refuses_non_query():
    resp_msg = mkquery()
    resp_msg.set_flag(0x8000, True)  # QR set => it's a response, not a query
    pipe = build_pipeline(FakeForwarder(mkanswer(resp_msg)))
    out = asyncio.run(pipe.resolve(resp_msg, "127.0.0.1"))
    assert out.rcode == Rcode.REFUSED
