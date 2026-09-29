"""0x20 query-name case randomization: apply / verify / restore + pipeline drop."""
from __future__ import annotations

import asyncio

from support import open_resolver

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline, zerox20
from trench.filter import FilterEngine
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


def test_randomize_preserves_identity_not_case():
    n = Name.from_text("example.com")
    r = zerox20.randomize_name(n)
    assert r == n                      # case-insensitively equal
    # at least sometimes differs in case over a few tries (probabilistic)
    assert any(zerox20.randomize_name(Name.from_text("verylongexampledomain.com")).labels
               != n.labels for _ in range(5))


def test_verify_and_restore():
    """The randomized name is built here rather than by a helper in the module.

    There used to be a `zerox20.apply` that cloned the query and swapped in the
    randomized question, and this test was its only caller — the pipeline builds
    the forwarded query itself, because it has to keep the clone it already made
    for ECS rather than start a fresh one. Two implementations of the forward
    path, and the test exercised the one the resolver does not use.
    """
    orig = Name.from_text("Example.COM")
    randomized = zerox20.randomize_name(orig)
    # a compliant response echoes the randomized case exactly
    resp = Message(id=1)
    resp.questions.append(Question(randomized, Type.A, Class.IN))
    resp.answers.append(RR(randomized, Type.A, Class.IN, 60, R.A("1.2.3.4")))
    assert zerox20.verify(resp, randomized)
    zerox20.restore(resp, orig)
    assert resp.question.name.labels == orig.labels       # client case restored
    assert resp.answers[0].name.labels == orig.labels


class CaseForwarder:
    """Echoes back the EXACT case it received (compliant upstream)."""
    def __init__(self, mangle=False): self.mangle = mangle
    async def resolve(self, query: Message, note=None) -> Message:
        name = query.question.name
        if self.mangle:  # simulate a spoofer that doesn't preserve 0x20 case
            name = Name(tuple(la.lower() for la in name.labels))
        resp = query.reply(Rcode.NOERROR)
        resp.questions = [Question(name, Type.A, Class.IN)]
        resp.answers.append(RR(name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def _pipe(forwarder):
    cfg = Config.model_validate({"security": {"use_0x20": True}})
    return Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=forwarder, counters=Counters(), config=open_resolver(cfg))


def mkquery(name="bigexampledomainname.com"):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


def test_pipeline_0x20_accepts_compliant():
    r = asyncio.run(_pipe(CaseForwarder(mangle=False)).resolve(mkquery(), "1.1.1.1"))
    assert r.answers and r.answers[0].rdata.to_text() == "1.2.3.4"


def test_pipeline_0x20_rejects_case_mismatch():
    # mangled (lowercased) echo => treated as spoof => SERVFAIL, no answer cached
    r = asyncio.run(_pipe(CaseForwarder(mangle=True)).resolve(mkquery(), "1.1.1.1"))
    assert r.rcode == Rcode.SERVFAIL and not r.answers
