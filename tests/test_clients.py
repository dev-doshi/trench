"""Per-client policy, services blocking, safe-search, safe-browse + pipeline wiring."""
from __future__ import annotations

import asyncio

from trench.cache import Cache
from trench.clients import Client, ClientRegistry, Policy
from trench.config import Config
from trench.engine import Pipeline
from trench.filter import FilterEngine
from trench.filter.safebrowse import SafeBrowse
from trench.filter.safesearch import safe_target
from trench.filter.services import Services
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


# --- registry ---
def test_identify_ip_cidr_clientid_default():
    reg = ClientRegistry([
        Client("10.0.0.5", "ip", "exact", Policy(name="exact")),
        Client("192.168.1.0/24", "cidr", "lan", Policy(name="lan")),
        Client("phone", "clientid", "phone", Policy(name="phone")),
    ], default=Policy(name="default"))
    assert reg.identify("10.0.0.5").name == "exact"
    assert reg.identify("192.168.1.42").name == "lan"
    assert reg.identify("8.8.8.8").name == "default"
    assert reg.identify("8.8.8.8", "phone").name == "phone"


# --- services ---
def test_services_match_and_schedule():
    s = Services()
    assert s.service_for("www.youtube.com") == "youtube"
    assert s.service_for("googlevideo.com") == "youtube"
    assert s.service_for("example.com") is None
    assert s.is_blocked("youtu.be", frozenset({"youtube"})) == "youtube"
    assert s.is_blocked("youtu.be", frozenset({"tiktok"})) is None
    # scheduled: blocked only Monday 0-60 min; outside -> not blocked
    s2 = Services(schedules={"youtube": [(0, 0, 60)]})
    import time
    monday = time.mktime(time.strptime("2024-01-01 00:30", "%Y-%m-%d %H:%M"))  # Mon
    tuesday = time.mktime(time.strptime("2024-01-02 00:30", "%Y-%m-%d %H:%M"))
    assert s2.blocked_now("youtube", monday) is True
    assert s2.blocked_now("youtube", tuesday) is False


# --- safe search ---
def test_safe_target():
    assert safe_target("www.google.com") == "forcesafesearch.google.com"
    assert safe_target("google.de") == "forcesafesearch.google.com"
    assert safe_target("bing.com") == "strict.bing.com"
    assert safe_target("www.youtube.com") == "restrict.youtube.com"
    assert safe_target("example.com") is None


# --- safe browse ---
def test_safebrowse():
    sb = SafeBrowse()
    assert sb.check("malware.testing.google.test", safe_browse=True, parental=False) == "malware"
    assert sb.check("x.evil.test", safe_browse=True, parental=False) == "malware"  # subdomain
    assert sb.check("adult.example", safe_browse=True, parental=True) == "adult"
    assert sb.check("good.com", safe_browse=True, parental=True) is None


# --- pipeline integration ---
class FakeForwarder:
    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def mkquery(name, rtype=Type.A):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    return m


def build_pipeline():
    reg = ClientRegistry([
        Client("10.0.0.5", "ip", "kid",
               Policy(name="kid", services=frozenset({"youtube"}),
                      safe_browse=True, parental=True)),
        Client("10.0.0.6", "ip", "filtered", Policy(name="filtered", safe_search=True)),
    ], default=Policy(name="default"))
    return Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder(), counters=Counters(), config=Config(),
                    clients=reg, services=Services(), safebrowse=SafeBrowse())


def test_pipeline_service_block_per_client():
    pipe = build_pipeline()
    # kid -> youtube blocked
    r = asyncio.run(pipe.resolve(mkquery("www.youtube.com"), "10.0.0.5"))
    assert r.answers[0].rdata.to_text() == "0.0.0.0"
    # default client -> youtube forwarded
    r2 = asyncio.run(pipe.resolve(mkquery("www.youtube.com"), "9.9.9.9"))
    assert r2.answers[0].rdata.to_text() == "1.2.3.4"


def test_pipeline_safe_search_chain():
    pipe = build_pipeline()
    r = asyncio.run(pipe.resolve(mkquery("google.com"), "10.0.0.6"))
    kinds = [(rr.rtype, rr.rdata.to_text()) for rr in r.answers]
    assert (Type.CNAME, "forcesafesearch.google.com.") in kinds
    assert any(rt == Type.A and val == "1.2.3.4" for rt, val in kinds)


def test_pipeline_safebrowse_parental():
    pipe = build_pipeline()
    r = asyncio.run(pipe.resolve(mkquery("malware.testing.google.test"), "10.0.0.5"))
    assert r.answers[0].rdata.to_text() == "0.0.0.0"
    r2 = asyncio.run(pipe.resolve(mkquery("adult.example"), "10.0.0.5"))
    assert r2.answers[0].rdata.to_text() == "0.0.0.0"
