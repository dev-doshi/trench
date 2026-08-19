"""DNS cookies (RFC 7873) + EDNS Client Subnet forward/strip + ECS-scoped cache."""
from __future__ import annotations

import asyncio

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.engine.cookies import COOKIE, CookieJar
from dnsguard.filter import FilterEngine
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.edns import Edns
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


def test_cookie_jar_roundtrip():
    jar = CookieJar()
    client_cookie = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    full = jar.make_response(client_cookie, "9.9.9.9")
    assert len(full) == 16 and full[:8] == client_cookie
    assert jar.valid(full, "9.9.9.9")
    assert not jar.valid(full, "8.8.8.8")           # bound to client ip
    assert not jar.valid(client_cookie, "9.9.9.9")  # missing server cookie


class FakeForwarder:
    def __init__(self):
        self.last_ecs = None
    async def resolve(self, query: Message) -> Message:
        if query.edns is not None:
            self.last_ecs = query.edns.get_ecs()
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def mkquery(name="example.com", cookie=False, do=False):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    if cookie or do:
        m.edns = Edns(udp_size=1232)
        m.edns.do = do
        if cookie:
            m.edns.set_option(COOKIE, b"CLIENTAA")
    return m


def test_pipeline_emits_cookie():
    cfg = Config.model_validate({"security": {"dns_cookies": True}})
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder(), counters=Counters(), config=cfg)
    resp = asyncio.run(pipe.resolve(mkquery(cookie=True), "9.9.9.9"))
    ck = resp.edns.get_option(COOKIE)
    assert ck is not None and len(ck) == 16 and ck[:8] == b"CLIENTAA"


def test_ecs_forwarded_and_scoped_cache():
    cfg = Config.model_validate({"upstream": {"ecs": "forward"}})
    fwd = FakeForwarder()
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=fwd, counters=Counters(), config=cfg)
    asyncio.run(pipe.resolve(mkquery(), "203.0.113.45"))
    assert fwd.last_ecs is not None and fwd.last_ecs.network_text().startswith("203.0.113")
    # a client in a different /24 must NOT share the cached answer (separate ECS scope)
    cache = pipe.cache
    k1 = cache.key_for(mkquery(), ecs="203.0.113.0/24")
    k2 = cache.key_for(mkquery(), ecs="8.8.8.0/24")
    assert k1 != k2


def test_ecs_strip_removes_subnet():
    cfg = Config.model_validate({"upstream": {"ecs": "strip"}})
    fwd = FakeForwarder()
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=fwd, counters=Counters(), config=cfg)
    q = mkquery(do=True)
    q.edns.set_ecs(__import__("dnsguard.wire.edns", fromlist=["ECS"]).ECS.from_client("1.2.3.4"))
    asyncio.run(pipe.resolve(q, "1.2.3.4"))
    assert fwd.last_ecs is None       # ECS stripped before forwarding
