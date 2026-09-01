"""The limiter's own table must not become the exhaustion vector.

Keys are client addresses. On a UDP listener the source address is
attacker-chosen and effectively unlimited, so an unbounded bucket table turns
a spoofed-source flood into memory exhaustion — the exact thing rate limiting
is there to prevent.
"""
from __future__ import annotations

from trench.engine.ratelimit import MAX_KEYS, RateLimiter


def test_table_is_capped_under_a_spoofed_source_flood():
    rl = RateLimiter(rate=100, burst=100, max_keys=64)
    for i in range(5000):
        rl.allow(f"10.0.{i // 256}.{i % 256}", now=1000.0 + i * 0.001)
    assert len(rl._buckets) <= 64


def test_trim_keeps_the_most_recently_seen():
    rl = RateLimiter(rate=100, burst=100, max_keys=8)
    # "steady" is touched last on every pass, so it must survive the trims.
    for i in range(200):
        rl.allow(f"burst-{i}", now=1000.0 + i)
        rl.allow("steady", now=1000.0 + i)
    assert "steady" in rl._buckets
    assert len(rl._buckets) <= 8


def test_limiting_still_works_after_a_trim():
    rl = RateLimiter(rate=1, burst=1, max_keys=4)
    for i in range(50):                       # evict the victim's bucket
        rl.allow(f"filler-{i}", now=2000.0)
    assert rl.allow("victim", now=2000.0) is True
    assert rl.allow("victim", now=2000.0) is False    # burst of 1 is spent


def test_a_rejected_query_still_costs_the_client_its_bucket_slot():
    # A refused client must not get a free pass on bookkeeping, or a flood
    # of over-limit sources would leave no trace to rate-limit against.
    rl = RateLimiter(rate=1, burst=1)
    assert rl.allow("c", now=0.0) is True
    assert rl.allow("c", now=0.0) is False
    assert "c" in rl._buckets


def test_gc_drops_only_idle_buckets():
    rl = RateLimiter(rate=10, burst=10)
    rl.allow("old", now=0.0)
    rl.allow("recent", now=600.0)
    rl.gc(now=700.0, idle=300.0)
    assert "old" not in rl._buckets
    assert "recent" in rl._buckets


def test_disabled_limiter_allows_everything():
    rl = RateLimiter(rate=0.0)
    assert not rl.enabled
    assert all(rl.allow(f"c{i}", now=0.0) for i in range(100))


def test_default_cap_is_bounded():
    assert 0 < MAX_KEYS <= 1 << 20
