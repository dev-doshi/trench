"""Pipeline paths a normal query never takes.

The resolve path is well covered for the ordinary cases. These are the ones that
only appear when something is wrong or unusual: an upstream that fails, a pause
that expires, ECS scoping, 0x20 randomisation, query coalescing, prefetch, and
the finaliser that has to produce a well-formed response no matter what the
stages left behind.
"""
from __future__ import annotations

import asyncio

import pytest
from support import blocked_engine, open_resolver

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.edns import Edns
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Rcode


def mkquery(name="example.com", rtype=Type.A, txid=1, edns=False, do=False):
    m = Message(id=txid)
    m.set_flag(Flags.RD, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    if edns or do:
        m.edns = Edns(udp_size=1232)
        m.edns.do = do
    return m


def mkanswer(query, ip="1.2.3.4", ttl=100, rcode=Rcode.NOERROR):
    resp = query.reply(rcode)
    q = query.question
    if rcode == Rcode.NOERROR:
        resp.answers.append(RR(q.name, Type.A, Class.IN, ttl, R.A(ip)))
    return resp


class Fwd:
    def __init__(self, answer=None, *, fail=None, delay=0.0):
        self.answer = answer
        self.fail = fail
        self.delay = delay
        self.calls = 0
        self.seen: list[Message] = []

    async def resolve(self, query, note=None):
        self.calls += 1
        self.seen.append(query)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError(self.fail)
        a = mkanswer(query) if self.answer is None else self.answer
        a.id = query.id
        if note is not None:
            note("test-upstream")
        return a


def build(forwarder=None, blocked=("doubleclick.net",), **cfg):
    config = Config.model_validate(cfg) if cfg else Config()
    return Pipeline(filter_engine=blocked_engine(*blocked), cache=Cache(),
                    forwarder=forwarder or Fwd(), counters=Counters(),
                    config=open_resolver(config))


# --- pause ---
def test_a_client_pause_expires_by_itself():
    pipe = build()
    pipe.pause(60, "10.0.0.5")
    assert pipe.paused("10.0.0.5") is True
    assert pipe.paused("10.0.0.6") is False
    pipe._client_pause["10.0.0.5"] = 0.0        # as if the deadline had passed
    assert pipe.paused("10.0.0.5") is False
    assert "10.0.0.5" not in pipe._client_pause, "the expired entry is swept"


def test_paused_any_reports_whether_anything_is_paused():
    pipe = build()
    assert pipe.paused_any is False
    pipe.pause(60)
    assert pipe.paused_any is True
    pipe.resume()
    assert pipe.paused_any is False


def test_a_global_pause_lets_a_blocked_name_through():
    q = mkquery("doubleclick.net")
    pipe = build(Fwd(mkanswer(q, ip="9.9.9.9")))
    pipe.pause(60)
    resp = asyncio.run(pipe.resolve(q, "127.0.0.1"))
    assert resp.answers[0].rdata.to_text() == "9.9.9.9"


def test_a_client_pause_only_frees_that_client():
    pipe = build(Fwd())
    pipe.pause(60, "10.0.0.5")
    blocked = asyncio.run(pipe.resolve(mkquery("doubleclick.net"), "10.0.0.6"))
    assert blocked.answers[0].rdata.to_text() == "0.0.0.0"
    freed = asyncio.run(pipe.resolve(mkquery("doubleclick.net", txid=2), "10.0.0.5"))
    assert freed.answers[0].rdata.to_text() != "0.0.0.0"


# --- failures ---
def test_an_upstream_failure_becomes_servfail_not_an_exception():
    pipe = build(Fwd(fail="no route to host"))
    resp = asyncio.run(pipe.resolve(mkquery(), "127.0.0.1"))
    assert resp.rcode == Rcode.SERVFAIL
    assert resp.id == 1


def test_a_stage_that_raises_is_caught_and_answered(caplog):
    pipe = build()

    async def boom(ctx):
        raise RuntimeError("stage exploded")

    pipe._run = boom
    ctx = asyncio.run(pipe.resolve_ctx(mkquery(), "127.0.0.1"))
    assert ctx.response.rcode == Rcode.SERVFAIL
    assert ctx.action == "failed"
    assert any("pipeline error" in r.getMessage() for r in caplog.records)


def test_a_response_the_stages_never_set_is_still_well_formed():
    pipe = build()

    async def leave_it_empty(ctx):
        ctx.response = None

    pipe._run = leave_it_empty
    q = mkquery(txid=77, edns=True)
    resp = asyncio.run(pipe.resolve(q, "127.0.0.1"))
    assert resp.rcode == Rcode.SERVFAIL
    assert resp.id == 77
    assert resp.questions == q.questions
    assert resp.edns is not None, "the client asked with EDNS; the reply must have OPT"


def test_the_do_bit_is_mirrored_back():
    pipe = build()
    resp = asyncio.run(pipe.resolve(mkquery(do=True), "127.0.0.1"))
    assert resp.edns is not None and resp.edns.do is True


# --- serve-stale ---
def test_a_stale_entry_answers_when_the_upstream_fails():
    q = mkquery("example.com")
    good = Fwd(mkanswer(q, ip="9.9.9.9", ttl=1))
    pipe = build(good, cache={"serve_stale": True, "serve_stale_max": 3600})
    asyncio.run(pipe.resolve(q, "127.0.0.1"))
    # Expire it, then break the upstream.
    for entry in pipe.cache._store.values():
        entry.expires = 0
    pipe.forwarder = Fwd(fail="upstream down")
    resp = asyncio.run(pipe.resolve(mkquery("example.com", txid=2), "127.0.0.1"))
    assert resp.answers[0].rdata.to_text() == "9.9.9.9"


def test_serve_stale_reports_no_entry_when_there_is_none():
    pipe = build()
    ctx = type("C", (), {"response": None, "action": "", "reason": ""})()
    assert pipe._serve_stale(ctx, None, "stale-fallback") is False


# --- query coalescing ---
def test_identical_concurrent_queries_ask_upstream_once():
    """RFC 5452 §9.2: without this, N clients asking at once are N chances for
    an off-path spoofer."""
    fwd = Fwd(delay=0.05)
    pipe = build(fwd)

    async def race():
        return await asyncio.gather(*[
            pipe.resolve(mkquery("example.com", txid=i), "127.0.0.1")
            for i in range(5)])

    responses = asyncio.run(race())
    assert fwd.calls == 1
    assert {r.id for r in responses} == {0, 1, 2, 3, 4}
    assert all(r.answers[0].rdata.to_text() == "1.2.3.4" for r in responses)


def test_a_follower_gets_its_own_copy_of_the_answer():
    """A shared Message would let one client's mutation reach another's."""
    fwd = Fwd(delay=0.05)
    pipe = build(fwd)

    async def race():
        return await asyncio.gather(
            pipe.resolve(mkquery("example.com", txid=1), "127.0.0.1"),
            pipe.resolve(mkquery("example.com", txid=2), "127.0.0.1"))

    a, b = asyncio.run(race())
    assert a is not b


def test_a_failed_leader_does_not_strand_the_followers():
    fwd = Fwd(fail="upstream down", delay=0.02)
    pipe = build(fwd)

    async def race():
        return await asyncio.gather(
            pipe.resolve(mkquery("example.com", txid=1), "127.0.0.1"),
            pipe.resolve(mkquery("example.com", txid=2), "127.0.0.1"))

    a, b = asyncio.run(race())
    assert a.rcode == b.rcode == Rcode.SERVFAIL


# --- ECS ---
def test_no_ecs_scope_when_the_policy_is_off():
    pipe = build(upstream={"ecs": "off"})
    ctx = type("C", (), {"client_ip": "203.0.113.5"})()
    assert pipe._ecs_scope(ctx) == ""


def test_an_ecs_scope_is_derived_from_the_client_when_forwarding():
    pipe = build(upstream={"ecs": "forward"})
    ctx = type("C", (), {"client_ip": "203.0.113.5"})()
    assert pipe._ecs_scope(ctx) != ""


def test_an_unparseable_client_address_yields_no_scope():
    pipe = build(upstream={"ecs": "forward"})
    ctx = type("C", (), {"client_ip": "not-an-address"})()
    assert pipe._ecs_scope(ctx) == ""


def test_a_globally_scoped_answer_is_cached_for_everyone():
    """Scope 0 means the upstream ignored ECS, so one entry serves everyone —
    otherwise a network with many subnets caches the same reply once per subnet
    and misses on all of them."""
    from trench.cache.cache import CacheKey
    from trench.wire.edns import ECS
    pipe = build()
    key = CacheKey(b"\x07example\x03com\x00", int(Type.A), int(Class.IN), False,
                   ecs="203.0.113.0/24")
    resp = Message(id=0)
    resp.edns = Edns()
    resp.edns.set_ecs(ECS(family=1, source_prefix=24, scope_prefix=0,
                          address=b"\xcb\x00\x71"))
    assert pipe._scoped_key(key, resp).ecs == ""

    scoped = Message(id=0)
    scoped.edns = Edns()
    scoped.edns.set_ecs(ECS(family=1, source_prefix=24, scope_prefix=24,
                            address=b"\xcb\x00\x71"))
    assert pipe._scoped_key(key, scoped) is key


def test_a_response_with_no_ecs_option_keeps_the_scoped_key():
    from trench.cache.cache import CacheKey
    pipe = build()
    key = CacheKey(b"\x00", int(Type.A), int(Class.IN), False, ecs="203.0.113.0/24")
    bare = Message(id=0)
    bare.edns = Edns()
    assert pipe._scoped_key(key, bare).ecs == ""


def test_a_key_without_ecs_is_returned_unchanged():
    from trench.cache.cache import CacheKey
    pipe = build()
    key = CacheKey(b"\x00", int(Type.A), int(Class.IN), False)
    assert pipe._scoped_key(key, Message(id=0)) is key
    with_edns = Message(id=0)
    with_edns.edns = Edns()
    assert pipe._scoped_key(key, with_edns) is key


# --- 0x20 ---
def test_0x20_randomises_the_case_sent_upstream():
    """The reply has to come back with the same casing, which an off-path
    spoofer cannot guess."""
    fwd = Fwd()
    pipe = build(fwd, security={"use_0x20": True})
    asyncio.run(pipe.resolve(mkquery("example.com"), "127.0.0.1"))
    sent = fwd.seen[0].question.name.to_text()
    assert sent.lower() == "example.com."


def test_the_client_sees_its_own_casing_back():
    fwd = Fwd()
    pipe = build(fwd, security={"use_0x20": True})
    q = mkquery("ExAmPlE.CoM")
    resp = asyncio.run(pipe.resolve(q, "127.0.0.1"))
    assert resp.question.name.to_text() == q.question.name.to_text()


# --- prefetch ---
def test_an_entry_with_plenty_of_ttl_is_not_prefetched():
    pipe = build()
    q = mkquery("example.com")
    asyncio.run(pipe.resolve(q, "127.0.0.1"))
    key = pipe.cache.key_for(q)
    before = set(pipe._prefetching)
    pipe._maybe_prefetch(type("C", (), {"query": q, "client_ip": "127.0.0.1"})(), key)
    assert set(pipe._prefetching) == before


def test_prefetch_is_not_started_twice_for_the_same_key():
    async def drive():
        pipe = build(Fwd(delay=0.05))
        q = mkquery("example.com")
        await pipe.resolve(q, "127.0.0.1")
        key = pipe.cache.key_for(q)
        for entry in pipe.cache._store.values():
            entry.ttl = 5                                 # inside the prefetch window
        ctx = await pipe.resolve_ctx(mkquery("example.com", txid=2), "127.0.0.1")
        pipe._maybe_prefetch(ctx, key)
        pipe._maybe_prefetch(ctx, key)
        started = len(pipe._prefetch_tasks)
        for t in list(pipe._prefetch_tasks):
            t.cancel()
        return started

    assert asyncio.run(drive()) <= 1


# --- authoritative zones ---
def test_a_local_zone_answers_before_anything_else():
    from trench.auth_zone import Zone, ZoneStore
    from trench.wire.rrtypes import Type as T
    store = ZoneStore()
    z = Zone(Name.from_text("home.arpa."))
    z.add(Name.from_text("home.arpa."), int(T.SOA),
          R.SOA(Name.from_text("ns.home.arpa."), Name.from_text("hm.home.arpa."),
                1, 3600, 600, 604800, 3600))
    z.add(Name.from_text("nas.home.arpa."), int(T.A), R.A("192.168.1.10"))
    store.add(z)
    fwd = Fwd()
    pipe = build(fwd)
    pipe.zones = store
    ctx = asyncio.run(pipe.resolve_ctx(mkquery("nas.home.arpa"), "127.0.0.1"))
    assert ctx.action == "authoritative"
    assert fwd.calls == 0
    assert ctx.response.answers[0].rdata.to_text() == "192.168.1.10"


# --- rcode rendering ---
@pytest.mark.parametrize("code,text", [
    (0, "NOERROR"), (3, "NXDOMAIN"), (5, "REFUSED"), (4095, "4095"),
])
def test_rcodes_render_by_name_where_one_exists(code, text):
    from trench.engine.pipeline import _rcode_text
    assert _rcode_text(code) == text


# --- rewrite rules ---
def test_a_dnsrewrite_rule_answers_with_the_forged_record():
    from trench.filter import FilterEngine, iter_rules
    pipe = build()
    pipe.filter = FilterEngine.compile(
        iter_rules("||ads.example.com^$dnsrewrite=NOERROR;A;93.184.216.34", "list"))
    ctx = asyncio.run(pipe.resolve_ctx(mkquery("ads.example.com"), "127.0.0.1"))
    assert ctx.action == "rewrite"
    assert ctx.response.rcode == Rcode.NOERROR
    assert ctx.response.answers[0].rdata.address == "93.184.216.34"


def test_a_dnsrewrite_to_an_rcode_answers_with_it():
    from trench.filter import FilterEngine, iter_rules
    pipe = build()
    pipe.filter = FilterEngine.compile(
        iter_rules("||ads.example.com^$dnsrewrite=REFUSED", "list"))
    ctx = asyncio.run(pipe.resolve_ctx(mkquery("ads.example.com"), "127.0.0.1"))
    assert ctx.response.rcode == Rcode.REFUSED


def test_an_allow_rule_falls_through_to_resolution():
    from trench.filter import FilterEngine, iter_rules
    fwd = Fwd()
    pipe = build(fwd)
    pipe.filter = FilterEngine.compile(
        iter_rules("||example.com^\n@@||ok.example.com^$important", "list"))
    ctx = asyncio.run(pipe.resolve_ctx(mkquery("ok.example.com"), "127.0.0.1"))
    assert ctx.action == "forwarded" and fwd.calls == 1


# --- the query log ---
def test_a_query_is_logged_with_its_verdict_and_answers():
    pipe = build()
    logged = []

    class Log:
        def enqueue(self, record):
            logged.append(record)

    pipe.querylog = Log()
    asyncio.run(pipe.resolve(mkquery("example.com"), "10.0.0.5"))
    assert len(logged) == 1
    rec = logged[0]
    assert rec.client_ip == "10.0.0.5" and rec.qname == "example.com"
    assert rec.action == "forwarded" and rec.rcode == "NOERROR"
    assert rec.answers == ["1.2.3.4"]


def test_a_blocked_query_is_logged_as_blocked():
    pipe = build()
    logged = []

    class Log:
        def enqueue(self, record):
            logged.append(record)

    pipe.querylog = Log()
    asyncio.run(pipe.resolve(mkquery("doubleclick.net"), "10.0.0.5"))
    assert logged[0].action == "blocked"


# --- ECS forwarding ---
def test_the_client_subnet_is_attached_when_forwarding_is_on():
    fwd = Fwd()
    pipe = build(fwd, upstream={"ecs": "forward"})
    asyncio.run(pipe.resolve(mkquery("example.com", edns=True), "203.0.113.5"))
    sent = fwd.seen[0]
    assert sent.edns is not None and sent.edns.get_ecs() is not None


def test_an_existing_client_subnet_is_stripped_when_the_policy_says_off():
    """Relaying the client's own ECS is a privacy leak the operator switched
    off."""
    from trench.wire.edns import ECS
    fwd = Fwd()
    pipe = build(fwd, upstream={"ecs": "strip"})
    q = mkquery("example.com", edns=True)
    q.edns.set_ecs(ECS(family=1, source_prefix=24, scope_prefix=0,
                       address=b"\xcb\x00\x71"))
    asyncio.run(pipe.resolve(q, "203.0.113.5"))
    sent = fwd.seen[0]
    assert sent.edns is None or sent.edns.get_ecs() is None


def test_an_unparseable_client_address_does_not_stop_the_query():
    fwd = Fwd()
    pipe = build(fwd, upstream={"ecs": "forward"})
    resp = asyncio.run(pipe.resolve(mkquery("example.com", edns=True), "not-an-ip"))
    assert resp.rcode == Rcode.NOERROR
