"""Bounded top-N counters.

The dashboard's top-domains and top-clients lists were backed by plain
`Counter`s, which keep one entry per distinct key for the life of the process. A
resolver meets a new hostname on almost every page load, so that grows without
limit — measured at 27 MB per 200k distinct names, on a Pi with a 700 MB
container ceiling and a history of being OOM-killed.

`TopCounter` caps the key count and prunes to the heaviest half. The trade is
stated in both directions here: memory is bounded, and a key that was rare, got
pruned, and later became popular starts counting again from zero.
"""
from __future__ import annotations

from dnsguard.stats import Counters
from dnsguard.stats.topn import TopCounter


def test_counts_are_exact_while_under_the_cap():
    c = TopCounter(cap=100)
    for _ in range(5):
        c["a.example"] += 1
    c["b.example"] += 1
    assert c["a.example"] == 5 and c["b.example"] == 1
    assert c.most_common(1) == [("a.example", 5)]
    assert c.pruned == 0


def test_memory_is_bounded_by_the_cap():
    c = TopCounter(cap=1000)
    for i in range(50_000):
        c[f"h{i}.example"] += 1
    assert len(c) <= 1000, "the whole point is that this cannot grow"
    assert c.pruned > 0


def test_heavy_hitters_survive_pruning():
    """The only thing a top-N list is asked for. A popular name must not be
    evicted by a flood of one-hit wonders, because that is precisely the traffic
    pattern that triggers pruning."""
    c = TopCounter(cap=1000)
    for i in range(20_000):
        c[f"noise{i}.example"] += 1
        if i % 5 == 0:
            c["popular.example"] += 1
    top = [k for k, _ in c.most_common(3)]
    assert top[0] == "popular.example", f"heavy hitter lost, got {top}"
    assert c["popular.example"] >= 4000


def test_the_lost_precision_is_named_not_hidden():
    """A key pruned while rare restarts from zero rather than resuming. That is
    the approximation being bought, so it is asserted rather than glossed."""
    c = TopCounter(cap=4)
    c["rare"] += 1
    for i in range(20):
        c[f"heavy{i}"] += 100
    assert "rare" not in c
    c["rare"] += 1
    assert c["rare"] == 1                     # not 2 — the earlier count is gone
    assert c.pruned >= 1


def test_counters_top_lists_stay_bounded_end_to_end():
    c = Counters(top_cap=2000)
    for i in range(30_000):
        c.record(client=f"10.0.{i % 256}.{i % 251}", qname=f"h{i}.example.com",
                 qtype="A", action="forwarded")
    assert len(c.queries) <= 2000
    assert len(c.clients) <= 2000
    snap = c.snapshot(top=5)
    assert len(snap["top_queries"]) <= 5
    assert len(snap["top_clients"]) <= 5
    assert snap["total"] == 30_000, "the running total is exact; only the lists are capped"
