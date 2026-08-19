"""0x20 query-name case randomization: apply / verify / restore + pipeline drop."""
from __future__ import annotations

import asyncio

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline, zerox20
from dnsguard.filter import FilterEngine
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


def test_randomize_preserves_identity_not_case():
    n = Name.from_text("example.com")
    r = zerox20.randomize_name(n)
    assert r == n                      # case-insensitively equal
    # at least sometimes differs in case over a few tries (probabilistic)
    assert any(zerox20.randomize_name(Name.from_text("verylongexampledomain.com")).labels
               != n.labels for _ in range(5))


def test_verify_and_restore():
    q = Message(id=1)
    q.questions.append(Question(Name.from_text("Example.COM"), Type.A, Class.IN))
    fwd, orig = zerox20.apply(q)
    # a compliant response echoes the randomized case exactly
    resp = Message(id=1)
    resp.questions.append(Question(fwd.question.name, Type.A, Class.IN))
    resp.answers.append(RR(fwd.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
    assert zerox20.verify(resp, fwd.question.name)
    zerox20.restore(resp, orig)
    assert resp.question.name.labels == orig.labels       # client case restored
    assert resp.answers[0].name.labels == orig.labels


class CaseForwarder:
    """Echoes back the EXACT case it received (compliant upstream)."""
    def __init__(self, mangle=False): self.mangle = mangle
    async def resolve(self, query: Message) -> Message:
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
                    forwarder=forwarder, counters=Counters(), config=cfg)


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
