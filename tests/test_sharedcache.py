"""Cross-worker shared cache: backend basics + L1/L2 sharing between instances."""
from __future__ import annotations

from dnsguard.cache import Cache
from dnsguard.cache.shared import SharedCache, key64
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name, wire_key
from dnsguard.wire.rrtypes import Rcode


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
