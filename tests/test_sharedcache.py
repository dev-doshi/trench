"""Cross-worker shared cache: backend basics + L1/L2 sharing between instances."""
from __future__ import annotations

from trench.cache import Cache
from trench.cache.shared import SharedCache, key64
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name, wire_key
from trench.wire.rrtypes import Rcode


def test_key64_stable_and_distinct():
    com, org = wire_key("example.com"), wire_key("example.org")
    a = key64(com, 1, 1, False)
    assert a == key64(com, 1, 1, False)                    # deterministic
    assert a != key64(com, 28, 1, False)                   # qtype matters
    assert a != key64(org, 1, 1, False)                    # name matters
    assert 0 <= a < 2 ** 64


def test_shared_backend_put_get():
    sc = SharedCache.create(slots=256, payload=512)
    sc.put(123, b"hello-wire", 60)
    got = sc.get(123)
    assert got is not None and got[0] == b"hello-wire" and 0 < got[1] <= 60
    assert sc.get(999) is None                              # miss
    sc.put(0, b"x", 0)                                      # ttl<=0 not stored
    assert sc.get(0) is None


def test_shared_backend_oversize_skipped():
    sc = SharedCache.create(slots=16, payload=8)
    sc.put(5, b"this-is-way-too-long", 60)
    assert sc.get(5) is None                                # exceeds payload, skipped


def mkquery(name="example.com", rtype=Type.A):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    return m


def mkanswer(query, ip="9.9.9.9", ttl=120):
    resp = query.reply(Rcode.NOERROR)
    resp.answers.append(RR(query.question.name, Type.A, Class.IN, ttl, R.A(ip)))
    return resp


def test_cross_instance_sharing():
    """Two Cache objects backed by one SharedCache = two workers sharing a cache."""
    sc = SharedCache.create(slots=1024, payload=1232)
    worker_a = Cache(shared=sc)
    worker_b = Cache(shared=sc)
    q = mkquery()
    key = Cache.key_for(q)
    # worker A resolves + caches
    worker_a.put(key, mkanswer(q, ip="1.2.3.4"))
    # worker B has an empty local cache, but hits the shared L2
    hit = worker_b.get(key)
    assert hit is not None
    msg, stale = hit
    assert msg.answers[0].rdata.to_text() == "1.2.3.4" and not stale
    assert worker_b.stats["shared_hits"] == 1
    assert worker_b.stats["hits"] == 0                      # not a local hit


def test_shared_flush():
    sc = SharedCache.create(slots=64, payload=512)
    c = Cache(shared=sc)
    q = mkquery("flushme.com")
    key = Cache.key_for(q)
    c.put(key, mkanswer(q))
    c2 = Cache(shared=sc)
    assert c2.get(key) is not None
    c.flush()                                               # clears local + shared
    c3 = Cache(shared=sc)
    assert c3.get(key) is None


def test_a_read_mostly_worker_still_evicts():
    """Regression: a worker fed entirely by a sibling's L2 never inserts through
    `put`, so `max_entries` was never enforced on it at all and its local cache
    grew without limit."""
    sc = SharedCache.create(slots=1024, payload=1232)
    writer = Cache(shared=sc)
    reader = Cache(shared=sc, max_entries=4)
    keys = []
    for i in range(20):
        q = mkquery(f"h{i}.example.com")
        key = Cache.key_for(q)
        keys.append(key)
        writer.put(key, mkanswer(q, ip=f"93.184.216.{i + 1}"))

    for key in keys:
        assert reader.get(key) is not None       # every one comes from L2
    assert reader.stats["shared_hits"] == 20
    assert reader.size <= 4, "the promotion path must trim like `put` does"
    assert reader.stats["evictions"] >= 16


def test_a_promoted_entry_is_served_locally_next_time():
    sc = SharedCache.create(slots=1024, payload=1232)
    writer = Cache(shared=sc)
    reader = Cache(shared=sc)
    q = mkquery("promoted.example.com")
    key = Cache.key_for(q)
    writer.put(key, mkanswer(q, ip="93.184.216.34"))

    assert reader.get(key) is not None
    assert reader.stats["shared_hits"] == 1 and reader.stats["hits"] == 0
    assert reader.get(key) is not None
    assert reader.stats["shared_hits"] == 1, "the second read must not touch L2"
    assert reader.stats["hits"] == 1


def test_an_unparseable_l2_entry_is_a_miss_not_a_crash():
    """The L2 is shared memory another process writes."""
    sc = SharedCache.create(slots=1024, payload=1232)
    reader = Cache(shared=sc)
    q = mkquery("corrupt.example.com")
    key = Cache.key_for(q)
    sc.put(key64(*key), b"\x00\x01not a message", 60)
    assert reader.get(key) is None
    assert reader.size == 0


def test_a_cache_with_no_shared_backend_never_consults_one():
    c = Cache()
    q = mkquery("local.example.com")
    assert c.get(Cache.key_for(q)) is None
    assert c.stats["shared_hits"] == 0


def test_a_stripe_lock_held_by_a_dead_worker_does_not_hang_the_caller():
    """A worker killed inside a critical section never releases its stripe.
    Every other worker used to block on it for good, on the event loop."""
    import time
    sc = SharedCache.create(slots=128, payload=64)
    k = 12345
    sc.put(k, b"wire", 60)
    _, lock = sc._slot(k)
    lock.acquire()                      # the worker that will never release it
    try:
        t = time.monotonic()
        assert sc.get(k) is None        # a miss, not a hang
        sc.put(k, b"other", 60)
        sc.delete(k)
        sc.clear()
        assert time.monotonic() - t < 2.0
    finally:
        lock.release()
    assert sc.get(k) is not None        # untouched while wedged, served once free
