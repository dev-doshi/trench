"""DNS tunneling/exfiltration detection: structural scoring + pipeline."""
from __future__ import annotations

import asyncio

from support import open_resolver

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.filter import FilterEngine
from trench.filter.tunnel import TunnelDetector
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode

TUN = ["a8f3b2c9d4e5f6a7b8c9d0e1f2a3b4c5a8f3b2c9.exfil.evil.com",
       "nbswy3dpfqqho33snrsccaf4mfrggzdf.data.bad.net"]
NORMAL = ["www.google.com", "api.github.com", "d111111abcdef8.cloudfront.net",
          "mail.protonmail.com", "_dmarc.example.com"]


def test_tunnel_separation():
    d = TunnelDetector()
    assert all(d.inspect(n, Type.TXT).suspicious for n in TUN)
    assert not any(d.inspect(n, Type.A).suspicious for n in NORMAL)


def test_volume_alone_is_not_suspicious():
    """Busy is not a tunnel: a device polling one domain hard scored its way
    over the threshold on query rate alone."""
    d = TunnelDetector()
    for i in range(500):
        assert not d.inspect(f"q{i}.a.b.c.s3.amazonaws.com", Type.A, "10.0.0.1").suspicious
    assert not d.inspect("4.3.2.1.in-addr.arpa", Type.PTR, "10.0.0.1").suspicious


def test_cloud_hostnames_are_not_tunnels():
    """Flagged on a home network, each asked for over and over by name."""
    d = TunnelDetector()
    for n in ["davs-bluetooth-config-artifacts.s3.amazonaws.com",
              "v6.cloudfront.web.us-east-1.prod.diagnostic.networking.aws.dev",
              "haproxy-ingress-bumblebee.life360.com.cdn.cloudflare.net",
              "bunq-prod-model-storage-public.s3.eu-central-1.amazonaws.com"]:
        assert not d.inspect(n, Type.A).suspicious, n


class FakeForwarder:
    async def resolve(self, query: Message, note=None) -> Message:
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
                    forwarder=FakeForwarder(), counters=Counters(), config=open_resolver(cfg))


def test_pipeline_tunnel_flag():
    cfg = Config.model_validate({"security": {"tunnel_detection": True}})
    pipe = _pipe(cfg)
    asyncio.run(pipe.resolve(mkquery(TUN[0]), "1.1.1.1"))
    assert pipe.counters.snapshot()["tunnel_flagged"] == 1


def test_pipeline_tunnel_block():
    cfg = Config.model_validate({"security": {"tunnel_detection": True, "tunnel_block": True}})
    pipe = _pipe(cfg)
    ctx = asyncio.run(pipe.resolve_ctx(mkquery(TUN[0]), "1.1.1.1"))
    assert (ctx.action, ctx.source) == ("blocked", "tunnel") and not ctx.response.answers
