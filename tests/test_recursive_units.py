"""The recursive resolver's own data structures and entry points.

The adversarial suite drives the resolver end to end; these cover the pieces it
reaches only incidentally — the IPv6 reachability probe that saves several
wasted round trips per resolution, the delegation cache's eviction (the half
that once grew until the box did), and the `RecursiveResolver` façade the
pipeline actually holds.
"""
from __future__ import annotations

import socket

import pytest

from trench.resolver.recursive import (
    ROOT,
    InfraCache,
    Recursive,
    RecursiveForwarder,
    _Cut,
    _Job,
    _Reachability,
)
from trench.wire import Class, Message, Question, Type
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Rcode


def n(s):
    return Name.from_text(s)


# --- IPv6 reachability ---
def test_an_ipv4_address_is_always_reachable():
    r = _Reachability()
    assert r("192.0.2.1") is True
    assert r._v6 is None, "a v4 address must not trigger the probe"


def test_the_probe_runs_once_and_is_remembered(monkeypatch, caplog):
    import logging
    caplog.set_level(logging.INFO)
    r = _Reachability()
    probes = []
    r._probe_v6 = lambda: probes.append(1) or False
    assert r("2001:db8::1") is False
    assert r("2001:db8::2") is False
    assert probes == [1]
    assert any("no IPv6 route" in x.getMessage() for x in caplog.records)


def test_a_reachable_v6_host_offers_v6_addresses():
    r = _Reachability()
    r._probe_v6 = lambda: True
    assert r("2001:db8::1") is True


def test_the_probe_reports_false_without_ipv6_support(monkeypatch):
    monkeypatch.setattr(socket, "has_ipv6", False)
    assert _Reachability()._probe_v6() is False


def test_the_probe_reports_false_when_the_socket_cannot_be_made(monkeypatch):
    def boom(*a, **kw):
        raise OSError("address family not supported")

    monkeypatch.setattr(socket, "socket", boom)
    assert _Reachability()._probe_v6() is False


def test_the_probe_reports_false_when_there_is_no_route(monkeypatch):
    class FakeSock:
        def connect(self, addr):
            raise OSError("network unreachable")

        def close(self):
            self.closed = True

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSock())
    assert _Reachability()._probe_v6() is False


def test_the_probe_sends_nothing_and_closes_its_socket(monkeypatch):
    """Connecting a UDP socket only asks the kernel for a route, which is
    exactly the question being asked."""
    events = []

    class FakeSock:
        def connect(self, addr):
            events.append(("connect", addr))

        def close(self):
            events.append(("close", None))

        def send(self, data):        # pragma: no cover - must never be called
            raise AssertionError("the probe must not send")

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSock())
    assert _Reachability()._probe_v6() is True
    assert [e[0] for e in events] == ["connect", "close"]


# --- InfraCache ---
class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _cache():
    clock = Clock()
    return InfraCache(clock=clock), clock


def test_an_empty_cache_encloses_nothing():
    cache, _ = _cache()
    assert cache.closest(n("www.example.com.")) is None


def test_the_deepest_enclosing_cut_wins():
    """A second query into a known zone costs zero packets above the
    authority."""
    cache, _ = _cache()
    cache.put_cut(ROOT, (n("a.root."),), {n("a.root."): ("10.0.0.1",)}, 300)
    cache.put_cut(n("com."), (n("ns.com."),), {n("ns.com."): ("10.0.0.2",)}, 300)
    cache.put_cut(n("example.com."), (n("ns.example.com."),),
                  {n("ns.example.com."): ("10.0.0.3",)}, 300)
    got = cache.closest(n("www.example.com."))
    assert got.zone == n("example.com.")
    assert cache.closest(n("other.com.")).zone == n("com.")
    assert cache.closest(n("elsewhere.net.")).zone == ROOT


def test_an_expired_cut_is_dropped_and_skipped():
    cache, clock = _cache()
    cache.put_cut(n("com."), (n("ns.com."),), {n("ns.com."): ("10.0.0.2",)}, 60)
    cache.put_cut(ROOT, (n("a.root."),), {n("a.root."): ("10.0.0.1",)}, 86400)
    clock.t += 120
    assert cache.closest(n("x.com.")).zone == ROOT
    assert n("com.") not in cache._cuts


def test_a_cut_with_no_addresses_is_not_returned():
    """A glueless cut still has to be resolvable, not served as a dead end."""
    cache, _ = _cache()
    cache.put_cut(n("com."), (n("ns.com."),), {}, 300)
    assert cache.closest(n("x.com.")) is None


def test_a_cut_ttl_is_clamped():
    cache, clock = _cache()
    forever = cache.put_cut(n("a."), (n("ns.a."),), {n("ns.a."): ("1.2.3.4",)},
                            10 ** 9)
    assert forever.expires <= clock.t + 86_400
    instant = cache.put_cut(n("b."), (n("ns.b."),), {n("ns.b."): ("1.2.3.4",)}, 0)
    assert instant.expires >= clock.t + 1


def test_the_cut_table_is_bounded():
    cache, _ = _cache()
    cache.max_zones = 8
    for i in range(40):
        z = n(f"zone{i}.test.")
        cache.put_cut(z, (n("ns.test."),), {n("ns.test."): ("1.2.3.4",)}, 300)
    assert len(cache._cuts) <= 8


def test_bounding_prefers_dropping_expired_entries():
    cache, clock = _cache()
    cache.max_zones = 4
    for i in range(3):
        cache.put_cut(n(f"old{i}.test."), (n("ns.test."),),
                      {n("ns.test."): ("1.2.3.4",)}, 10)
    clock.t += 60
    cache.put_cut(n("fresh.test."), (n("ns.test."),),
                  {n("ns.test."): ("1.2.3.4",)}, 300)
    cache.put_cut(n("newest.test."), (n("ns.test."),),
                  {n("ns.test."): ("1.2.3.4",)}, 300)
    assert n("newest.test.") in cache._cuts
    assert not any(k.to_text().startswith("old") for k in cache._cuts)


def test_replacing_a_known_zone_does_not_count_against_the_bound():
    cache, _ = _cache()
    cache.max_zones = 2
    for i in range(2):
        cache.put_cut(n(f"z{i}.test."), (n("ns.test."),),
                      {n("ns.test."): ("1.2.3.4",)}, 300)
    cache.put_cut(n("z0.test."), (n("ns2.test."),),
                  {n("ns2.test."): ("5.6.7.8",)}, 300)
    assert cache._cuts[n("z0.test.")].flat() == ["5.6.7.8"]
    assert len(cache._cuts) == 2


def test_addresses_round_trip_and_expire():
    cache, clock = _cache()
    assert cache.addrs_for(n("ns.example.com.")) == ()
    cache.put_addrs(n("ns.example.com."), ("10.0.0.9",), 60)
    assert cache.addrs_for(n("ns.example.com.")) == ("10.0.0.9",)
    clock.t += 120
    assert cache.addrs_for(n("ns.example.com.")) == ()
    assert n("ns.example.com.") not in cache._addrs


def test_empty_addresses_are_not_stored():
    cache, _ = _cache()
    cache.put_addrs(n("ns.example.com."), (), 60)
    assert cache._addrs == {}


def test_the_address_table_is_bounded():
    """A hostile delegation naming many glueless nameservers gets one entry per
    name; this half had no cap and no sweep, so it grew until the box did."""
    cache, _ = _cache()
    cache.max_zones = 8
    for i in range(50):
        cache.put_addrs(n(f"ns{i}.evil.test."), ("1.2.3.4",), 300)
    assert len(cache._addrs) <= 8


def test_address_bounding_prefers_expired_entries():
    cache, clock = _cache()
    cache.max_zones = 4
    for i in range(3):
        cache.put_addrs(n(f"old{i}.test."), ("1.2.3.4",), 10)
    clock.t += 60
    cache.put_addrs(n("fresh.test."), ("1.2.3.4",), 300)
    cache.put_addrs(n("newest.test."), ("1.2.3.4",), 300)
    assert cache.addrs_for(n("newest.test.")) == ("1.2.3.4",)


def test_an_address_ttl_is_clamped():
    cache, clock = _cache()
    cache.put_addrs(n("ns.test."), ("1.2.3.4",), 10 ** 9)
    assert cache._addrs[n("ns.test.")][1] <= clock.t + 86_400


def test_a_cut_flattens_its_addresses_in_nameserver_order():
    cut = _Cut(n("com."), (n("a.com."), n("b.com."), n("c.com.")),
               {n("a.com."): ("1.1.1.1",), n("c.com."): ("3.3.3.3", "4.4.4.4")},
               expires=0)
    assert cut.flat() == ["1.1.1.1", "3.3.3.3", "4.4.4.4"]


# --- the façade the pipeline holds ---
@pytest.mark.asyncio
async def test_a_query_without_a_question_is_a_servfail():
    r = RecursiveForwarder(validate=False)
    resp = await r.resolve(Message(id=5))
    assert resp.rcode == Rcode.SERVFAIL
    await r.close()


@pytest.mark.asyncio
async def test_the_answer_echoes_the_clients_id_and_question_objects():
    """The originals carry the label casing 0x20 verification compares
    against."""
    r = RecursiveForwarder(validate=False)
    q = Message(id=0x1234)
    q.questions.append(Question(Name.from_text("ExAmPlE.CoM."), Type.A, Class.IN))

    async def fake(name, rtype):
        m = Message(id=0, flags=Flags.QR)
        m.set_rcode(Rcode.NOERROR)
        return m

    r.rec.resolve = fake
    resp = await r.resolve(q)
    assert resp.id == 0x1234
    assert resp.questions[0] is q.questions[0]
    await r.close()


@pytest.mark.asyncio
async def test_upstreams_are_pooled_per_address_and_closed():
    r = RecursiveForwarder(validate=False)
    first = r._upstream("10.0.0.1")
    assert r._upstream("10.0.0.1") is first
    assert r._upstream("10.0.0.2") is not first
    assert len(r._pool) == 2
    await r.close()
    assert r._pool == {}


@pytest.mark.asyncio
async def test_the_upstream_pool_is_bounded():
    """Recursion talks to hundreds of authoritative addresses."""
    r = RecursiveForwarder(validate=False)
    for i in range(600):
        r._upstream(f"10.0.{i // 256}.{i % 256}")
    assert len(r._pool) <= 513
    await r.close()


@pytest.mark.asyncio
async def test_closing_survives_an_upstream_that_will_not_close():
    r = RecursiveForwarder(validate=False)
    up = r._upstream("10.0.0.1")

    async def boom():
        raise OSError("socket already gone")

    up.close = boom
    await r.close()                # must not raise
    assert r._pool == {}


@pytest.mark.asyncio
async def test_the_udp_transport_goes_through_the_pooled_upstream():
    r = RecursiveForwarder(validate=False)
    asked = []

    class FakeUp:
        async def query(self, q):
            asked.append(q)
            return Message(id=0, flags=Flags.QR)

        async def close(self):
            pass

    r._pool["10.0.0.1"] = FakeUp()
    q = Message(id=1)
    await r._udp("10.0.0.1", q)
    assert asked == [q]
    await r.close()


# --- the per-resolution budget object ---
def test_a_job_is_spent_once_its_deadline_passes():
    job = _Job(deadline=100.0, queries=5)
    assert job.spent(99.0) is False
    assert job.spent(101.0) is True


def test_a_job_is_spent_once_its_packet_budget_is_gone():
    job = _Job(deadline=100.0, queries=0)
    assert job.spent(0.0) is True


# --- SERVFAIL construction ---
def test_a_servfail_carries_the_question_it_failed_on():
    rec = Recursive(lambda ip, q: None, validate=False)
    resp = rec._servfail("example.com.", int(Type.AAAA))
    assert resp.rcode == Rcode.SERVFAIL
    assert resp.qr is True
    assert resp.question.name == n("example.com.")
    assert resp.question.rtype == Type.AAAA
    assert resp.answers == []


# --- _child ---
@pytest.mark.parametrize("name,zone,child", [
    ("www.example.com.", "com.", "example.com."),
    ("a.b.c.example.com.", "example.com.", "c.example.com."),
    ("example.com.", ".", "com."),
])
def test_the_next_label_down_toward_a_name(name, zone, child):
    rec = Recursive(lambda ip, q: None, validate=False)
    assert rec._child(n(name), n(zone)) == n(child)
