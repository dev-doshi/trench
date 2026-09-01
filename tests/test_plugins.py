"""Plugin system: on_query short-circuit (block_tld) and on_answer (dns64)."""
from __future__ import annotations

import asyncio

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.filter import FilterEngine
from trench.plugins import PluginManager
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


class FakeForwarder:
    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        q = query.question
        if q.rtype == Type.A:
            resp.answers.append(RR(q.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        # AAAA -> NODATA (no IPv6), which is what triggers DNS64
        return resp


class FakeApp:
    def __init__(self):
        self.forwarder = FakeForwarder()


def mkquery(name, rtype=Type.A):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    return m


def build_pipeline(plugins):
    return Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder(), counters=Counters(), config=Config(),
                    plugins=plugins)


def test_block_tld_plugin():
    mgr = PluginManager.from_config(FakeApp(), [{"name": "block_tld", "options": {"tlds": ["zip", "mov"]}}])
    pipe = build_pipeline(mgr)
    r = asyncio.run(pipe.resolve(mkquery("setup.zip"), "127.0.0.1"))
    assert r.rcode == Rcode.NXDOMAIN
    r2 = asyncio.run(pipe.resolve(mkquery("example.com"), "127.0.0.1"))
    assert r2.answers[0].rdata.to_text() == "1.2.3.4"  # forwarded


def test_dns64_plugin():
    app = FakeApp()
    mgr = PluginManager.from_config(app, ["dns64"])
    pipe = build_pipeline(mgr)
    r = asyncio.run(pipe.resolve(mkquery("v4only.example", Type.AAAA), "127.0.0.1"))
    aaaa = [rr.rdata.to_text() for rr in r.answers if rr.rtype == Type.AAAA]
    assert aaaa == ["64:ff9b::102:304"]  # 1.2.3.4 mapped into the NAT64 prefix


def test_plugin_load_failure_isolated():
    # an unknown plugin must not crash the manager
    mgr = PluginManager.from_config(FakeApp(), ["does.not:Exist"])
    assert mgr.plugins == []
