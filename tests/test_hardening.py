"""Rate limiting + DNS-rebinding protection (unit and pipeline)."""
from __future__ import annotations

import asyncio

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.engine.ratelimit import RateLimiter
from dnsguard.engine.rebinding import scrub
from dnsguard.filter import FilterEngine
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


def test_ratelimiter_bucket():
    rl = RateLimiter(rate=10, burst=2)
    t = 1000.0
    assert rl.allow("a", t) and rl.allow("a", t)   # burst of 2
    assert not rl.allow("a", t)                    # empty
    assert rl.allow("a", t + 0.11)                 # ~1 token refilled after 0.1s


def test_ratelimiter_disabled():
    rl = RateLimiter(rate=0)
    assert all(rl.allow("x") for _ in range(1000))


def test_rebinding_scrub():
    m = Message(id=1)
    m.answers = [
        RR(Name.from_text("evil.com"), Type.A, Class.IN, 60, R.A("192.168.1.5")),
        RR(Name.from_text("evil.com"), Type.A, Class.IN, 60, R.A("1.2.3.4")),
    ]
    removed = scrub(m, "evil.com", local_suffixes=("lan",))
    assert removed == 1
    assert [rr.rdata.to_text() for rr in m.answers] == ["1.2.3.4"]


def test_rebinding_keeps_local():
    m = Message(id=1)
    m.answers = [RR(Name.from_text("nas.lan"), Type.A, Class.IN, 60, R.A("192.168.1.5"))]
    assert scrub(m, "nas.lan", local_suffixes=("lan",)) == 0   # local names allowed


class FakeForwarder:
    def __init__(self, ip): self.ip = ip
    async def resolve(self, query):
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A(self.ip)))
        return resp


def mkquery(name="x.com"):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


def test_pipeline_ratelimit():
    cfg = Config.model_validate({"security": {"rate_limit": 1, "rate_burst": 1}})
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder("1.2.3.4"), counters=Counters(), config=cfg)
    r1 = asyncio.run(pipe.resolve(mkquery(), "10.0.0.1"))
    r2 = asyncio.run(pipe.resolve(mkquery(), "10.0.0.1"))
    assert r1.answers and r2.rcode == Rcode.REFUSED   # 2nd over the limit


def test_pipeline_rebinding():
    cfg = Config.model_validate({"security": {"rebinding_protection": True}})
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder("10.0.0.9"), counters=Counters(), config=cfg)
    r = asyncio.run(pipe.resolve(mkquery("public.com"), "1.1.1.1"))
    assert not r.answers   # private answer to a public name stripped
