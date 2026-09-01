"""Blocklist ROI: what each list contributes versus what it costs to hold.

The point is to make "should I keep this list?" answerable from data rather than
from the list's own description.
"""
from __future__ import annotations

import time

import pytest

from trench.analyze import list_effectiveness
from trench.filter import FilterEngine, compile_rules
from trench.filter.rule import Rule


def engine_with(**per_source: int) -> FilterEngine:
    """Build an engine where each source contributes N distinct domains."""
    rules: list[Rule] = []
    n = 0
    for src, count in per_source.items():
        text = "\n".join(f"||d{n + i}.example^" for i in range(count))
        n += count
        rules += compile_rules(text, src)
    return FilterEngine.compile(rules)


def blocked(source: str, count: int) -> list[dict]:
    now = int(time.time() * 1_000_000)
    return [{"action": "blocked", "source": source, "qname": f"x{i}.example",
             "ts": now, "client_ip": "10.0.0.1"} for i in range(count)]


def by_source(stats):
    return {s.source: s for s in stats}


def test_large_list_with_no_blocks_is_dead_weight():
    eng = engine_with(big=5000, useful=2000)
    stats = by_source(list_effectiveness(eng, blocked("useful", 400)))
    assert stats["big"].verdict == "dead weight"
    assert stats["big"].blocks == 0
    assert "without blocking anything" in stats["big"].note
    assert stats["useful"].verdict == "earning"


def test_marginal_list_is_called_out():
    eng = engine_with(huge=200_000)
    stats = by_source(list_effectiveness(eng, blocked("huge", 3)))
    assert stats["huge"].verdict == "marginal"
    assert stats["huge"].blocks_per_100k < 5


def test_small_list_is_not_judged_on_roi():
    # a 50-domain curated list costs nothing; ROI is the wrong lens
    eng = engine_with(tiny=50)
    s = by_source(list_effectiveness(eng, []))["tiny"]
    assert s.verdict == "marginal" and "negligible" in s.note


def test_memory_estimate_scales_with_domains():
    eng = engine_with(a=10_000, b=1_000)
    stats = by_source(list_effectiveness(eng, []))
    assert stats["a"].est_bytes == pytest.approx(stats["b"].est_bytes * 10, rel=1e-3)
    assert stats["a"].to_json()["est_mb"] > 0


def test_share_of_domains_sums_to_one():
    eng = engine_with(a=3000, b=1000, c=1000)
    stats = list_effectiveness(eng, [])
    assert sum(s.share_of_domains for s in stats) == pytest.approx(1.0)


def test_ranked_by_memory_cost():
    eng = engine_with(small=100, biggest=9000, middle=3000)
    ordered = [s.source for s in list_effectiveness(eng, [])]
    assert ordered == ["biggest", "middle", "small"]


def test_duplicate_domains_are_attributed_to_the_first_list_only():
    """Marginal contribution, not raw line count: a list that only repeats what
    an earlier list already provided has contributed nothing."""
    first = compile_rules("||dup.example^\n||only-a.example^", "list-a")
    second = compile_rules("||dup.example^", "list-b")
    eng = FilterEngine.compile(first + second)
    stats = by_source(list_effectiveness(eng, []))
    assert stats["list-a"].domains == 2
    assert stats.get("list-b") is None or stats["list-b"].domains == 0


def test_operator_rules_are_excluded():
    eng = engine_with(gravity=2000)
    eng.add_deny("mine.example")          # source="custom"
    stats = by_source(list_effectiveness(eng, blocked("custom", 50)))
    assert "custom" not in stats, "operator rules are intentional, not an ROI question"
    assert "gravity" in stats


def test_list_appearing_only_in_blocks_still_reported():
    # a list was removed from config but its blocks are still in the window
    eng = engine_with(current=1000)
    stats = by_source(list_effectiveness(eng, blocked("retired", 20)))
    assert stats["retired"].domains == 0 and stats["retired"].blocks == 20


def test_empty_engine_and_no_traffic():
    assert list_effectiveness(FilterEngine.compile([]), []) == []


@pytest.mark.asyncio
async def test_lists_from_querylog(tmp_path):
    from trench.analyze import lists_from_querylog
    from trench.store import Database
    from trench.store.querylog import QueryLog
    db = Database(tmp_path / "q.db")
    await db.connect()
    ql = QueryLog(db)
    try:
        now = int(time.time() * 1_000_000)
        for i in range(4):
            await db.execute(
                "INSERT INTO querylog(ts,client_ip,qname,qtype,action,source)"
                " VALUES(?,?,?,?,?,?)",
                (now, "10.0.0.1", f"ad{i}.example", "A", "blocked", "hagezi"))
        eng = engine_with(hagezi=1500, unused=4000)
        stats_list, observed = await lists_from_querylog(eng, ql, hours=24)
        stats = by_source(stats_list)
        assert 0 <= observed <= 24
        assert stats["hagezi"].blocks == 4 and stats["hagezi"].verdict == "earning"
        assert stats["unused"].verdict == "dead weight"
    finally:
        await db.close()


def test_threat_feed_with_no_hits_is_not_called_dead_weight():
    """A malware feed that never fires means the network is clean. Reporting
    that as waste pushes operators to remove exactly the list they want."""
    eng = engine_with(**{"tif.medium.txt": 300_000, "ads.txt": 50_000})
    stats = by_source(list_effectiveness(eng, blocked("ads.txt", 900)))
    tif = stats["tif.medium.txt"]
    assert tif.protective and tif.verdict == "on watch"
    assert "intended outcome" in tif.note
    assert stats["ads.txt"].verdict == "earning" and not stats["ads.txt"].protective


def test_protective_feed_that_fires_is_earning():
    eng = engine_with(**{"threat.txt": 200_000})
    s = by_source(list_effectiveness(eng, blocked("threat.txt", 3)))["threat.txt"]
    # 3 blocks over 200k domains is far under the nuisance-list ratio floor,
    # but stopping three malware lookups is the whole point of the list.
    assert s.verdict == "earning" and "known-malicious" in s.note


def test_operator_can_declare_their_own_protective_list():
    eng = engine_with(**{"corp-blocklist.txt": 40_000})
    plain = by_source(list_effectiveness(eng, []))["corp-blocklist.txt"]
    named = by_source(list_effectiveness(eng, [], protective_hints=("corp-",)))["corp-blocklist.txt"]
    assert plain.verdict == "dead weight"
    assert named.verdict == "on watch"


def test_ordinary_names_are_not_mistaken_for_threat_feeds():
    eng = engine_with(**{"notification.txt": 30_000, "certificates.txt": 30_000})
    stats = by_source(list_effectiveness(eng, []))
    assert not any(s.protective for s in stats.values())


def test_memory_estimate_follows_the_actual_storage_cost():
    """The per-domain figure is read off the live table, not a constant. The
    storage has already changed by 10x once; a stale constant would tell the
    operator to drop a list to reclaim memory that is not being spent."""
    eng = engine_with(big=20_000)
    s = by_source(list_effectiveness(eng, []))["big"]
    measured = eng.block_table.nbytes / len(eng.block_table)
    assert s.est_bytes == pytest.approx(20_000 * measured, rel=1e-3)
    assert s.est_bytes < 20_000 * 100, "should reflect the compact table, not a dict"
