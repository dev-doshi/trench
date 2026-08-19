"""Cache freshness, query coalescing, and cache-entry isolation.

Four defects motivated this file, all of them invisible from the outside until
you count upstream queries or compare two clients' answers:

  * an entry whose TTL had lapsed was answered from serve-stale on the normal
    read path, so it was never refetched — a record that changed at the origin
    stayed wrong for as long as stale data was retained (a day, by default);
  * identical concurrent misses each got their own upstream query. Wasteful, and
    RFC 5452 §9.2 makes it a security problem: every extra outstanding query for
    a name is another chance for an off-path spoofer to match one of them;
  * the stored entry was the same object as the response handed to the client,
    which then had its id, question and EDNS rewritten in place;
  * prefetch called the forwarder directly and wrote the raw answer into the
    cache, bypassing every check a client-driven query goes through.
"""
from __future__ import annotations

import asyncio

import pytest

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.filter import FilterEngine
from dnsguard.stats import Counters
from dnsguard.wire import Class, Message, Question
from dnsguard.wire.edns import Edns
from dnsguard.wire.message import RR
from dnsguard.wire.name import Name
from dnsguard.wire.rdata import A
from dnsguard.wire.rrtypes import EDNSOption, Flags, Rcode, Type


def n(text: str) -> Name:
    return Name.from_text(text)


def query(name="a.example.", *, edns=None, qid=7) -> Message:
    m = Message(id=qid)
    m.set_flag(Flags.RD, True)
    m.questions.append(Question(n(name), Type.A, Class.IN))
    m.edns = edns
    return m


class Upstream:
    """Counts queries and can be told to be slow, to fail, or to change its mind."""

    def __init__(self, ip="1.1.1.1", ttl=60, delay=0.0, fail=False, extra=()):
        self.ip, self.ttl, self.delay, self.fail = ip, ttl, delay, fail
        self.extra = list(extra)
        self.calls = 0
        self.seen: list[Message] = []

    async def resolve(self, q):
        self.calls += 1
        self.seen.append(q)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise OSError("upstream down")
        r = Message(id=q.id)
        r.set_flag(Flags.QR, True)
        r.questions = list(q.questions)
        r.answers = [RR(q.question.name, Type.A, Class.IN, self.ttl, A(self.ip))]
        r.additional = list(self.extra)
        r.edns = Edns(udp_size=1232)
        return r


def build(up, *, cache=None, cfg=None, **cache_kw):
    conf = {"filtering": {"enabled": False}, "cache": {"prefetch": False}}
    if cfg:
        for k, v in cfg.items():
            conf.setdefault(k, {}).update(v)
    return Pipeline(filter_engine=FilterEngine.compile([]),
                    cache=cache if cache is not None else Cache(**cache_kw),
                    forwarder=up, counters=Counters(),
                    config=Config.model_validate(conf))


def ip_of(resp: Message) -> str:
    return resp.answers[0].rdata.to_text()


# --- freshness: an expired entry must be refetched ---
@pytest.mark.asyncio
async def test_expired_entry_is_refetched_not_served_stale():
    """The whole point of a TTL. Serving stale here means a record that moved at
    the origin is wrong until the stale window closes."""
    up = Upstream(ttl=1)
    p = build(up)
    assert ip_of(await p.resolve(query(), "10.0.0.1")) == "1.1.1.1"
    up.ip = "2.2.2.2"                      # the origin changed the record
    await asyncio.sleep(1.05)              # the TTL has lapsed
    assert ip_of(await p.resolve(query(), "10.0.0.1")) == "2.2.2.2"
    assert up.calls == 2, "the expired entry was answered without a refresh"


@pytest.mark.asyncio
async def test_fresh_entry_is_still_served_from_cache():
    up = Upstream(ttl=300)
    p = build(up)
    for _ in range(5):
        await p.resolve(query(), "10.0.0.1")
    assert up.calls == 1


@pytest.mark.asyncio
async def test_stale_is_served_when_the_upstream_fails():
    up = Upstream(ttl=1)
    p = build(up)
    await p.resolve(query(), "10.0.0.1")
    await asyncio.sleep(1.05)
    up.fail = True
    resp = await p.resolve(query(), "10.0.0.1")
    assert ip_of(resp) == "1.1.1.1", "nothing served although a stale copy was held"
    assert up.calls == 2, "stale was served without even trying to refresh"


@pytest.mark.asyncio
async def test_no_stale_copy_means_servfail_not_a_lie():
    from dnsguard.wire.rrtypes import Rcode
    p = build(Upstream(fail=True))
    resp = await p.resolve(query(), "10.0.0.1")
    assert resp.rcode == Rcode.SERVFAIL and not resp.answers


@pytest.mark.asyncio
async def test_stale_is_served_when_the_refresh_outlives_the_client_timer():
    """RFC 8767 §6: a client should not be made to wait out a slow upstream when
    a usable answer is on hand. The refresh keeps running and repairs the cache."""
    up = Upstream(ttl=1)
    p = build(up, cfg={"cache": {"serve_stale_client_timeout": 0.05}})
    await p.resolve(query(), "10.0.0.1")
    await asyncio.sleep(1.05)
    up.ip, up.delay = "2.2.2.2", 0.4       # refresh is slower than the timer
    resp = await p.resolve(query(), "10.0.0.1")
    assert ip_of(resp) == "1.1.1.1", "waited for the slow refresh instead of answering"
    assert resp.answers[0].ttl == 1        # stale answers carry a 1s TTL
    await asyncio.sleep(0.5)               # let the detached refresh land
    assert ip_of(await p.resolve(query(), "10.0.0.1")) == "2.2.2.2", (
        "the background refresh never repaired the cache")


@pytest.mark.asyncio
async def test_a_slow_upstream_is_waited_for_when_there_is_no_stale_copy():
    up = Upstream(delay=0.1)
    p = build(up, cfg={"cache": {"serve_stale_client_timeout": 0.02}})
    assert ip_of(await p.resolve(query(), "10.0.0.1")) == "1.1.1.1"


@pytest.mark.asyncio
async def test_serve_stale_off_means_no_stale_answer():
    up = Upstream(ttl=1)
    p = build(up, serve_stale=False)
    await p.resolve(query(), "10.0.0.1")
    await asyncio.sleep(1.05)
    up.fail = True
    from dnsguard.wire.rrtypes import Rcode
    assert (await p.resolve(query(), "10.0.0.1")).rcode == Rcode.SERVFAIL


# --- coalescing ---
@pytest.mark.asyncio
async def test_identical_concurrent_misses_make_one_upstream_query():
    up = Upstream(delay=0.05)
    p = build(up)
    resps = await asyncio.gather(*[p.resolve(query(), f"10.0.0.{i}")
                                  for i in range(40)])
    assert up.calls == 1, f"{up.calls} upstream queries for one question"
    assert all(ip_of(r) == "1.1.1.1" for r in resps)


@pytest.mark.asyncio
async def test_coalesced_waiters_get_independent_responses():
    """Each waiter's response is rewritten per client (id, question, EDNS). One
    shared object would mean the last writer wins for everyone."""
    up = Upstream(delay=0.05)
    p = build(up)
    resps = await asyncio.gather(*[p.resolve(query(qid=100 + i), f"10.0.0.{i}")
                                  for i in range(8)])
    assert [r.id for r in resps] == [100 + i for i in range(8)]
    assert len({id(r) for r in resps}) == 8, "waiters shared one response object"


@pytest.mark.asyncio
async def test_different_questions_are_not_coalesced():
    up = Upstream(delay=0.05)
    p = build(up)
    await asyncio.gather(*[p.resolve(query(f"h{i}.example."), "10.0.0.1")
                           for i in range(6)])
    assert up.calls == 6


@pytest.mark.asyncio
async def test_a_failing_leader_does_not_hang_its_followers():
    from dnsguard.wire.rrtypes import Rcode
    up = Upstream(delay=0.05, fail=True)
    p = build(up)
    resps = await asyncio.gather(*[p.resolve(query(), f"10.0.0.{i}")
                                  for i in range(10)])
    assert all(r.rcode == Rcode.SERVFAIL for r in resps)
    assert up.calls == 1


@pytest.mark.asyncio
async def test_the_inflight_table_does_not_leak_entries():
    up = Upstream(delay=0.01)
    p = build(up)
    await asyncio.gather(*[p.resolve(query(f"h{i}.example."), "10.0.0.1")
                           for i in range(5)])
    assert p._inflight == {}, f"left {len(p._inflight)} entries behind"


@pytest.mark.asyncio
async def test_a_second_burst_after_the_first_completes_refetches():
    """Coalescing must not turn into a permanent lock on the question."""
    up = Upstream(ttl=0, delay=0.02)   # ttl 0 -> never cached
    p = build(up)
    await asyncio.gather(*[p.resolve(query(), "10.0.0.1") for _ in range(4)])
    assert up.calls == 1
    await asyncio.gather(*[p.resolve(query(), "10.0.0.1") for _ in range(4)])
    assert up.calls == 2


# --- isolation: a cached entry is nobody else's to mutate ---
@pytest.mark.asyncio
async def test_the_cached_entry_is_not_the_response_handed_to_the_client():
    cache = Cache()
    p = build(Upstream(ttl=300), cache=cache)
    resp = await p.resolve(query(qid=42), "10.0.0.1")
    stored = next(iter(cache._store.values())).msg
    assert stored is not resp
    assert stored.edns is not resp.edns
    assert stored.id != 42 or stored.questions is not resp.questions


@pytest.mark.asyncio
async def test_a_client_that_did_not_use_edns_gets_no_opt():
    """RFC 6891 §6.1.1. The upstream's OPT reaches the cache; handing it on would
    give a plain client another client's options."""
    p = build(Upstream(ttl=300))
    await p.resolve(query(edns=Edns(udp_size=4096)), "10.0.0.1")
    plain = await p.resolve(query(edns=None), "10.0.0.2")
    assert plain.edns is None
    assert all(rr.rtype != Type.OPT for rr in plain.additional)


@pytest.mark.asyncio
async def test_one_clients_dns_cookie_never_reaches_another():
    cookie = b"clientAAA"
    p = build(Upstream(ttl=300), cfg={"security": {"dns_cookies": True}})
    a = Edns(udp_size=1232)
    a.set_option(EDNSOption.COOKIE, cookie)
    first = await p.resolve(query(edns=a), "10.0.0.1")
    mine = first.edns.get_option(EDNSOption.COOKIE)
    assert mine and mine[:8] == cookie[:8]

    b = Edns(udp_size=1232)
    b.set_option(EDNSOption.COOKIE, b"clientBBB")
    second = await p.resolve(query(edns=b), "10.0.0.2")
    theirs = second.edns.get_option(EDNSOption.COOKIE)
    assert theirs != mine, "the second client was handed the first client's cookie"


@pytest.mark.asyncio
async def test_a_client_that_sent_no_cookie_is_not_given_someone_elses():
    """The case a shared OPT actually leaks through: this client uses EDNS, so
    its OPT is not stripped, but it asked for no cookie — so it must get none."""
    a = Edns(udp_size=1232)
    a.set_option(EDNSOption.COOKIE, b"clientAAA")
    b = Edns(udp_size=1232)
    b.set_option(EDNSOption.COOKIE, b"clientBBB")
    p = build(Upstream(ttl=300), cfg={"security": {"dns_cookies": True}})
    await p.resolve(query(edns=a), "10.0.0.1")   # populates the cache
    await p.resolve(query(edns=b), "10.0.0.2")   # a cache hit, with a cookie
    other = await p.resolve(query(edns=Edns(udp_size=1232)), "10.0.0.3")
    assert other.edns is not None
    assert other.edns.get_option(EDNSOption.COOKIE) is None, (
        "inherited a cookie from an earlier client's answer")


# --- prefetch must not be a softer way into the cache ---
@pytest.mark.asyncio
async def test_prefetch_still_strips_unsolicited_records():
    """Prefetch used to call the forwarder directly, so an injected record went
    into the cache unchecked — on the one path with no client waiting to notice."""
    poison = RR(n("bank.example."), Type.A, Class.IN, 300, A("6.6.6.6"))
    up = Upstream(ttl=20, extra=[poison])
    p = build(up, cfg={"cache": {"prefetch": True}})
    await p.resolve(query(), "10.0.0.1")          # populates the cache
    # pretend the entry is nearly expired so the next hit triggers a prefetch
    entry = next(iter(p.cache._store.values()))
    entry.ttl = 5
    await p.resolve(query(), "10.0.0.1")
    for _ in range(20):                            # let the prefetch land
        await asyncio.sleep(0)
    resp = await p.resolve(query(), "10.0.0.1")
    owners = [rr.name.to_text() for rr in resp.answers + resp.additional]
    assert "bank.example." not in owners, f"prefetch cached an injected record: {owners}"
    assert up.calls >= 2, "no prefetch happened, so this proved nothing"


@pytest.mark.asyncio
async def test_prefetch_applies_the_configured_ecs_and_case_randomisation():
    up = Upstream(ttl=20)
    p = build(up, cfg={"cache": {"prefetch": True},
                       "security": {"use_0x20": True}})
    await p.resolve(query(), "10.0.0.1")
    entry = next(iter(p.cache._store.values()))
    entry.ttl = 5
    await p.resolve(query(), "10.0.0.1")
    for _ in range(20):
        await asyncio.sleep(0)
    assert up.calls >= 2
    names = [m.question.name.to_text() for m in up.seen]
    assert any(x != "a.example." for x in names), (
        f"prefetch sent the name unrandomised: {names}")


@pytest.mark.asyncio
async def test_background_prewarm_goes_through_the_same_checks():
    """`Pipeline.warm` is what the learned-prewarm sweep calls. It used to be the
    bare forwarder with a `cache.put` next to it."""
    poison = RR(n("bank.example."), Type.A, Class.IN, 300, A("6.6.6.6"))
    p = build(Upstream(ttl=300, extra=[poison]))
    warmed = await p.warm(query("hot.example."))
    assert warmed is not None
    assert all(rr.name.to_text() != "bank.example."
               for rr in warmed.answers + warmed.additional)
    served = await p.resolve(query("hot.example."), "10.0.0.1")
    owners = [rr.name.to_text() for rr in served.answers + served.additional]
    assert "bank.example." not in owners, f"prewarm poisoned the cache: {owners}"


# --- which upstream answered ---
@pytest.mark.asyncio
async def test_the_answering_upstream_is_recorded():
    """`ctx.upstream` feeds the query log, the per-upstream stats panel and the
    unsolicited-record warning. Nothing was ever assigning it."""
    from dnsguard.resolver.forwarder import Forwarder

    fwd = Forwarder(["udp://192.0.2.1", "udp://192.0.2.2"], strategy="sequential")
    seen = []

    class Fake:
        def __init__(self, label): self.label = label
        def __repr__(self): return self.label
        async def query(self, q):
            if self.label == "first":
                raise OSError("down")
            r = Message(id=q.id)
            r.set_flag(Flags.QR, True)
            r.questions = list(q.questions)
            r.answers = [RR(q.question.name, Type.A, Class.IN, 60, A("1.1.1.1"))]
            return r

    fwd.router.default = [Fake("first"), Fake("second")]
    resp = await fwd.resolve(query(), seen.append)
    assert ip_of(resp) == "1.1.1.1"
    assert seen == ["second"], f"credited the wrong upstream: {seen}"


@pytest.mark.asyncio
async def test_the_upstream_reaches_the_operators_stats():
    """The end of the wire: an upstream nobody records is a stats panel that is
    always empty and a warning that cannot name the culprit."""
    class Reporting(Upstream):
        async def resolve(self, q, note=None):
            if note is not None:
                note("tls://9.9.9.9:853")
            return await super().resolve(q)

    counters = Counters()
    p = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                 forwarder=Reporting(), counters=counters,
                 config=Config.model_validate({"filtering": {"enabled": False},
                                               "cache": {"prefetch": False}}))
    await p.resolve(query(), "10.0.0.1")
    assert counters.snapshot()["top_upstreams"] == [("tls://9.9.9.9:853", 1)]


@pytest.mark.asyncio
async def test_a_parallel_race_credits_the_upstream_that_won():
    """A loser finishing after the winner has been picked must not take credit."""
    from dnsguard.resolver.forwarder import Forwarder

    class Fake:
        def __init__(self, label, delay): self.label, self.delay = label, delay
        def __repr__(self): return self.label
        async def query(self, q):
            await asyncio.sleep(self.delay)
            r = Message(id=q.id)
            r.set_flag(Flags.QR, True)
            r.questions = list(q.questions)
            r.answers = [RR(q.question.name, Type.A, Class.IN, 60, A("1.1.1.1"))]
            return r

    fwd = Forwarder(["udp://192.0.2.1"], strategy="parallel")
    fwd.router.default = [Fake("slow", 0.05), Fake("quick", 0.0)]
    seen = []
    await fwd.resolve(query(), seen.append)
    await asyncio.sleep(0.1)               # let the loser finish
    assert seen == ["quick"], f"credited the wrong upstream: {seen}"


# --- a targeted flush must actually flush ---
def test_flushing_a_domain_also_drops_it_from_the_shared_cache():
    class FakeShared:
        def __init__(self): self.deleted = []
        def get(self, k): return None
        def put(self, k, wire, ttl): pass
        def delete(self, k): self.deleted.append(k)
        def clear(self): pass

    shared = FakeShared()
    c = Cache(shared=shared)
    q = query("tracker.example.")
    key = c.key_for(q)
    r = Message(id=1)
    r.set_flag(Flags.QR, True)
    r.questions = list(q.questions)
    r.answers = [RR(n("tracker.example."), Type.A, Class.IN, 300, A("1.2.3.4"))]
    c.put(key, r)
    assert c.flush("tracker.example") == 1
    assert shared.deleted, "the L2 copy survived, so the next miss re-reads it"


# --- a failure is not an answer, and must not be stored as one ---
#
# Found while running the resolver against the real internet: one slow cold
# resolution of www.bbc.co.uk failed, and every subsequent query for that name
# returned SERVFAIL instantly, from the cache, until the entry aged out. A
# failure says nothing about the name — only about the moment — so storing one
# converts a transient blip into a sticky outage, and, worse, evicts the good
# answer that was standing in its place.
def _failure(name="a.example.", code=Rcode.SERVFAIL) -> Message:
    r = Message(id=1)
    r.set_flag(Flags.QR, True)
    r.questions = list(query(name).questions)
    r.set_rcode(code)
    return r


def _good(name="a.example.", ip="1.2.3.4", ttl=300) -> Message:
    r = Message(id=1)
    r.set_flag(Flags.QR, True)
    r.questions = list(query(name).questions)
    r.answers = [RR(n(name), Type.A, Class.IN, ttl, A(ip))]
    return r


@pytest.mark.parametrize("code", [Rcode.SERVFAIL, Rcode.REFUSED, Rcode.NOTIMP])
def test_a_failure_response_is_never_cached(code):
    """A TTL floor is a normal thing to configure, and it must not apply here."""
    c = Cache(min_ttl=60)
    q = query()
    key = c.key_for(q)
    c.put(key, _failure(code=code))
    got = c.get(key)                      # a miss is None, not a tuple
    assert got is None or got[0] is None, f"served a cached {code!r} instead of retrying"


def test_a_failure_does_not_evict_the_good_answer_it_replaces():
    """The point of serve-stale is to survive an upstream outage.

    If the SERVFAIL that outage produces overwrites the entry, the fallback is
    destroyed by the very event it exists for — and the resolver then serves the
    stored failure as though it were retained data.
    """
    c = Cache(min_ttl=0, serve_stale=True, serve_stale_max=86400)
    q = query()
    key = c.key_for(q)
    c.put(key, _good())
    c.put(key, _failure())
    assert c.has_stale(key), "the retained answer was replaced by a failure"
    msg, stale = c.get(key, allow_stale=True)
    assert msg is not None and msg.rcode == Rcode.NOERROR, "serve-stale handed back a failure"
    assert [rr.rdata.to_text() for rr in msg.answers] == ["1.2.3.4"]


def test_nxdomain_and_nodata_are_still_cached():
    """Negative caching (RFC 2308) is not what this refuses: NXDOMAIN and NODATA
    are answers about the name, and they still belong in the cache."""
    for code in (Rcode.NXDOMAIN, Rcode.NOERROR):
        c = Cache(min_ttl=0, negative_ttl=900)
        q = query()
        key = c.key_for(q)
        c.put(key, _failure(code=code))       # empty response, that rcode
        msg, _ = c.get(key)
        assert msg is not None, f"stopped caching a negative answer ({code!r})"
