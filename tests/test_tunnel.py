"""DNS tunneling/exfiltration detection: structural + volumetric + pipeline."""
from __future__ import annotations

import asyncio

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.filter import FilterEngine
from dnsguard.filter.tunnel import TunnelDetector
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode

TUN = ["a8f3b2c9d4e5f6a7b8c9d0e1f2a3b4c5a8f3b2c9.exfil.evil.com",
       "kj4h5k2j4h5k2j4h5k2j4h5k2j4h5k2j4h5k2.tunnel.example.com",
       "nbswy3dpfqqho33snrsccaf4mfrggzdf.data.bad.net"]
NORMAL = ["www.google.com", "api.github.com", "d111111abcdef8.cloudfront.net",
          "mail.protonmail.com", "_dmarc.example.com"]


def test_tunnel_separation():
    d = TunnelDetector()
    assert all(d.inspect(n, Type.TXT).suspicious for n in TUN)
    assert not any(d.inspect(n, Type.A).suspicious for n in NORMAL)


def test_tunnel_volumetric():
    d = TunnelDetector(rate_limit=20, window=60)
    # many queries to one registrable domain from one client -> volumetric boost
    base_score = d.score("x.beacon.evil.io", Type.A, "10.0.0.1", now=1000.0)
    for i in range(40):
        d.score(f"q{i}.beacon.evil.io", Type.A, "10.0.0.1", now=1000.0)
    boosted = d.score("y.beacon.evil.io", Type.A, "10.0.0.1", now=1000.0)
    assert boosted > base_score        # rate tracking raised the score


class FakeForwarder:
    async def resolve(self, query: Message) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def mkquery(name, rtype=Type.TXT):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    return m


def _pipe(cfg):
    return Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder(), counters=Counters(), config=cfg)


def test_pipeline_tunnel_flag():
    cfg = Config.model_validate({"security": {"tunnel_detection": True}})
    pipe = _pipe(cfg)
    asyncio.run(pipe.resolve(mkquery(TUN[0]), "1.1.1.1"))
    assert pipe.counters.snapshot()["tunnel_flagged"] == 1


def test_pipeline_tunnel_block():
    cfg = Config.model_validate({"security": {"tunnel_detection": True, "tunnel_block": True}})
    pipe = _pipe(cfg)
    r = asyncio.run(pipe.resolve(mkquery(TUN[0], Type.A), "1.1.1.1"))
    assert r.answers[0].rdata.to_text() == "0.0.0.0"
