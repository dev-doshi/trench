"""Real-time DGA detection: scoring separation + pipeline flag/block modes."""
from __future__ import annotations

import asyncio

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.filter import FilterEngine
from dnsguard.filter.dga import DGADetector
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode

DGA = ["kq3v9z7xp2w8.com", "xjwqzkfbmn.net", "zzxcvbnmqwer.ru", "fdghjklzxcvb.com"]
LEGIT = ["google.com", "github.com", "amazon.com", "cloudflare.com", "wikipedia.org",
         "netflix.com", "microsoft.com", "anthropic.com"]
CDN = ["d1a2b3c4e5.cloudfront.net", "xyz123abc.akamai.net"]


def test_dga_separation():
    d = DGADetector()
    assert all(d.check(n).suspicious for n in DGA), "DGA samples must flag"
    assert not any(d.check(n).suspicious for n in LEGIT), "legit must not flag"
    assert not any(d.check(n).suspicious for n in CDN), "CDN 2LD must not flag"
    # clear score margin
    assert min(d.score(d.check(n).label) for n in DGA) > max(
        d.score(d.check(n).label) for n in LEGIT + CDN)


class FakeForwarder:
    async def resolve(self, query: Message) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def mkquery(name):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


def _pipe(cfg):
    return Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder(), counters=Counters(), config=cfg)


def test_pipeline_dga_block_needs_a_confirmed_campaign():
    """`dga_block` no longer sinkholes on the lexical score alone — that score
    cannot separate malware from CDN/carrier hostnames (see
    test_dga_behavioural.py). One random-looking name still resolves; blocking
    starts once the client is observed cycling through failed random names."""
    cfg = Config.model_validate({"security": {"dga_detection": True, "dga_block": True}})
    pipe = _pipe(cfg)
    r = asyncio.run(pipe.resolve(mkquery("kq3v9z7xp2w8.com"), "1.1.1.1"))
    assert r.answers[0].rdata.to_text() == "1.2.3.4"          # flagged, not blocked
    assert pipe.counters.dga["kq3v9z7xp2w8.com"] == 1

    # now simulate the campaign: distinct random names that fail to resolve
    for i in range(pipe.dga.burst_min_names):
        pipe.dga.note_outcome(f"zq8v2x7n1m{i}.com", "1.1.1.1", "NXDOMAIN")
    r = asyncio.run(pipe.resolve(mkquery("pw4k9z2v7n3q.com"), "1.1.1.1"))
    assert r.answers[0].rdata.to_text() == "0.0.0.0"          # now blocked


def test_pipeline_dga_flag_mode_resolves():
    cfg = Config.model_validate({"security": {"dga_detection": True, "dga_block": False}})
    pipe = _pipe(cfg)
    r = asyncio.run(pipe.resolve(mkquery("xjwqzkfbmn.net"), "1.1.1.1"))
    assert r.answers[0].rdata.to_text() == "1.2.3.4"          # still resolves
    assert pipe.counters.dga["xjwqzkfbmn.net"] == 1           # but flagged
    snap = pipe.counters.snapshot()
    assert snap["dga_flagged"] == 1


def test_pipeline_dga_off_by_default():
    pipe = _pipe(Config())
    asyncio.run(pipe.resolve(mkquery("kq3v9z7xp2w8.com"), "1.1.1.1"))
    assert pipe.counters.snapshot()["dga_flagged"] == 0
