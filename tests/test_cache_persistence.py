"""Saving the cache across a restart, and restoring it."""
from __future__ import annotations

from trench.cache import Cache
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


def _answer(name="example.com", ip="1.2.3.4", ttl=300):
    q = Message(id=1)
    q.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    resp = q.reply(Rcode.NOERROR)
    resp.answers.append(RR(q.question.name, Type.A, Class.IN, ttl, R.A(ip)))
    return q, resp


def test_cache_persistence_roundtrip(tmp_path):
    c = Cache()
    for i in range(5):
        q, resp = _answer(f"site{i}.com", f"10.0.0.{i}")
        c.put(c.key_for(q), resp)
    path = tmp_path / "cache.json"
    assert c.dump(path) == 5
    # fresh cache restores them
    c2 = Cache()
    assert c2.load(path) == 5
    q, _ = _answer("site3.com")
    hit = c2.get(c2.key_for(q))
    assert hit is not None and hit[0].answers[0].rdata.to_text() == "10.0.0.3"


def test_cache_load_missing_file(tmp_path):
    assert Cache().load(tmp_path / "nope.json") == 0


# --- keys, eviction, and the persisted form ---

from trench.wire.edns import Edns  # noqa: E402
from trench.wire.rrtypes import Flags  # noqa: E402


def _q(name="example.com", rtype=Type.A, do=False, cd=False):
    m = Message(id=1)
    m.set_flag(Flags.RD, True)
    if cd:
        m.set_flag(Flags.CD, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    if do:
        m.edns = Edns(udp_size=1232)
        m.edns.do = True
    return m


def _a(query, ip="93.184.216.34", ttl=300, rcode=Rcode.NOERROR):
    resp = query.reply(rcode)
    if rcode == Rcode.NOERROR:
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, ttl, R.A(ip)))
    return resp


def test_a_query_without_a_question_cannot_be_keyed():
    assert Cache.key_for(Message(id=1)) is None


def test_the_key_separates_dnssec_and_checking_disabled():
    """A CD=1 query is forwarded with the bit set, so the upstream skips
    validation and returns bogus data as NOERROR."""
    plain = Cache.key_for(_q())
    signed = Cache.key_for(_q(do=True))
    unchecked = Cache.key_for(_q(cd=True))
    assert len({plain, signed, unchecked}) == 3


def test_the_key_separates_ecs_scopes_and_views():
    base = Cache.key_for(_q())
    scoped = Cache.key_for(_q(), ecs="203.0.113.0/24")
    viewed = Cache.key_for(_q(), view="kids")
    assert len({base, scoped, viewed}) == 3


def test_the_key_is_case_insensitive_on_the_name():
    assert Cache.key_for(_q("EXAMPLE.COM")) == Cache.key_for(_q("example.com"))


def test_the_store_evicts_the_least_recently_used():
    c = Cache(max_entries=3)
    for i in range(3):
        q = _q(f"h{i}.example.com")
        c.put(c.key_for(q), _a(q))
    c.get(c.key_for(_q("h0.example.com")))            # touch the oldest
    q = _q("h9.example.com")
    c.put(c.key_for(q), _a(q))
    assert c.size == 3
    assert c.get(c.key_for(_q("h0.example.com"))) is not None
    assert c.get(c.key_for(_q("h1.example.com"))) is None
    assert c.stats["evictions"] >= 1


def test_a_disabled_cache_stores_and_serves_nothing():
    c = Cache(enabled=False)
    q = _q()
    c.put(c.key_for(q), _a(q))
    assert c.size == 0
    assert c.get(c.key_for(q)) is None


def test_a_failure_is_not_stored():
    """SERVFAIL describes the moment, not the name: storing one turns a
    transient blip into an outage that lasts a TTL."""
    c = Cache()
    q = _q()
    c.put(c.key_for(q), _a(q, rcode=Rcode.SERVFAIL))
    assert c.size == 0


def test_a_negative_answer_takes_the_lesser_of_the_soa_ttl_and_its_minimum():
    """RFC 2308 §4. Reading only rr.ttl ignored the floor the zone publishes,
    so a name created moments ago stayed NXDOMAIN for the SOA's full TTL."""
    c = Cache(min_ttl=1, max_ttl=86400)
    q = _q("gone.example.com")
    resp = q.reply(Rcode.NXDOMAIN)
    resp.authority.append(RR(Name.from_text("example.com."), Type.SOA, Class.IN,
                             3600, R.SOA(Name.from_text("ns.example.com."),
                                         Name.from_text("hm.example.com."),
                                         1, 7200, 3600, 1209600, 60)))
    c.put(c.key_for(q), resp)
    assert c.remaining(c.key_for(q)) <= 60


def test_the_persisted_form_survives_a_round_trip(tmp_path):
    c = Cache()
    q = _q()
    c.put(c.key_for(q), _a(q))
    path = tmp_path / "cache.json"
    assert c.dump(path) == 1

    restored = Cache()
    assert restored.load(path) == 1
    hit = restored.get(restored.key_for(q))
    assert hit is not None and hit[0].answers[0].rdata.address == "93.184.216.34"


def test_expired_entries_are_not_persisted(tmp_path):
    c = Cache()
    q = _q()
    c.put(c.key_for(q), _a(q))
    for entry in c._store.values():
        entry.ttl = 0
    assert c.dump(tmp_path / "cache.json") == 0


def test_an_unreadable_entry_in_the_file_is_skipped(tmp_path):
    """Regression: unpacking in the `for` clause raised straight out of `load`,
    discarding every remaining entry over one bad row."""
    import json
    path = tmp_path / "cache.json"
    good = Cache()
    q = _q()
    good.put(good.key_for(q), _a(q))
    good.dump(path)
    items = json.loads(path.read_text())
    items.append([["zzz", 1, 1, False, "", False, ""], "not hex", 300])
    items.append(["totally wrong shape"])
    path.write_text(json.dumps(items))

    restored = Cache()
    assert restored.load(path) == 1


def test_flushing_reports_how_many_went_and_fires_the_callback():
    c = Cache()
    for i in range(3):
        q = _q(f"h{i}.example.com")
        c.put(c.key_for(q), _a(q))
    fired = []
    c.on_flush = lambda: fired.append(1)
    assert c.flush() == 3
    assert c.size == 0 and fired == [1]
