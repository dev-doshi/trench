"""Blocking on the answer's address: matcher, rpz-ip triggers, pipeline wiring."""
from __future__ import annotations

import asyncio

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.filter import FilterEngine
from trench.filter.ipmatch import IPMatcher, answer_addresses, rpz_ip_prefix
from trench.filter.rpz import iter_rpz_ips
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


# --- matcher ---
def test_longest_prefix_wins_and_source_is_reported():
    m = IPMatcher()
    m.add("10.0.0.0/8", "wide")
    m.add("10.1.2.0/24", "narrow")
    assert m.match("10.1.2.3") == "narrow"
    assert m.match("10.9.9.9") == "wide"
    assert m.match("11.0.0.1") is None


def test_v6_and_default_route_prefixes():
    m = IPMatcher()
    m.add("2001:db8::/32", "doc")
    assert m.match("2001:db8::1") == "doc"
    assert m.match("2001:db9::1") is None
    m.add("0.0.0.0/0", "everything")
    assert m.match("8.8.8.8") == "everything"


def test_list_parsing_ignores_comments_and_domain_lines():
    m = IPMatcher()
    added = m.add_many("""
        # a comment
        1.2.3.0/24
        9.9.9.9
        ||ads.example^          ; a domain rule does not belong in an address list
        not-an-address
    """, "feed")
    assert added == 2
    assert m.match("1.2.3.4") == "feed"
    assert m.match("9.9.9.9") == "feed"


def test_unlabelled_source_still_matches():
    """`match` returns the source, which may legitimately be empty."""
    m = IPMatcher()
    m.add("5.5.5.0/24")
    assert m.match("5.5.5.1") == ""
    assert m.match("5.5.5.1") is not None


# --- rpz-ip ---
def test_rpz_ip_triggers_decode():
    assert rpz_ip_prefix("32.5.4.3.2.rpz-ip") == "2.3.4.5/32"
    assert rpz_ip_prefix("24.0.4.3.2.rpz-ip") == "2.3.4.0/24"
    assert rpz_ip_prefix("48.zz.db8.2001.rpz-ip") == "2001:db8::/48"
    assert rpz_ip_prefix("bad.example") is None


def test_rpz_zone_ip_triggers_are_collected():
    zone = """$TTL 60
@ SOA localhost. root.localhost. 1 1 1 1 1
32.5.4.3.2.rpz-ip CNAME .
24.0.4.3.2.rpz-ip.rpz.example.com. CNAME *.
tracker.example CNAME .
"""
    assert list(iter_rpz_ips(zone, "feed")) == [("2.3.4.5/32", "feed"),
                                                ("2.3.4.0/24", "feed")]


# --- pipeline ---
class Fwd:
    def __init__(self, addr: str):
        self.addr = addr

    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A(self.addr)))
        return resp


def mkquery(name: str) -> Message:
    m = Message(id=3)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


def build(addr: str, prefixes: list[str]) -> Pipeline:
    engine = FilterEngine.compile([])
    for cidr in prefixes:
        engine.ips.add(cidr, "badnets")
    return Pipeline(filter_engine=engine, cache=Cache(enabled=False),
                    forwarder=Fwd(addr), counters=Counters(), config=Config())


def test_answer_in_a_listed_network_is_blocked():
    pipe = build("9.9.9.9", ["9.9.9.0/24"])
    resp = asyncio.run(pipe.resolve(mkquery("brand-new-domain.example"), "10.0.0.1"))
    assert resp.answers[0].rdata.to_text() == "0.0.0.0"


def test_answer_outside_the_lists_resolves():
    pipe = build("8.8.4.4", ["9.9.9.0/24"])
    resp = asyncio.run(pipe.resolve(mkquery("ok.example"), "10.0.0.1"))
    assert resp.answers[0].rdata.to_text() == "8.8.4.4"


def test_the_check_can_be_switched_off():
    pipe = build("9.9.9.9", ["9.9.9.0/24"])
    pipe.config.filtering.block_answer_ips = False
    resp = asyncio.run(pipe.resolve(mkquery("ok.example"), "10.0.0.1"))
    assert resp.answers[0].rdata.to_text() == "9.9.9.9"


def test_blocked_answer_is_not_cached():
    """A verdict is not an answer; caching it would keep serving the block after
    the list changed."""
    pipe = build("9.9.9.9", ["9.9.9.0/24"])
    pipe.cache.enabled = True
    asyncio.run(pipe.resolve(mkquery("x.example"), "10.0.0.1"))
    assert pipe.cache.size == 0


def test_answer_addresses_reads_a_and_aaaa_only():
    msg = Message(id=1)
    name = Name.from_text("x.example")
    msg.answers = [
        RR(name, Type.A, Class.IN, 60, R.A("1.1.1.1")),
        RR(name, Type.CNAME, Class.IN, 60, R.CNAME(Name.from_text("y.example"))),
        RR(name, Type.AAAA, Class.IN, 60, R.AAAA("2001:db8::1")),
    ]
    assert answer_addresses(msg) == ["1.1.1.1", "2001:db8::1"]
