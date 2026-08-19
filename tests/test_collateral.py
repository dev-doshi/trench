"""Collateral-damage detection: retrying clients mean a block is breaking
something; fire-and-forget beacons do not.

The decisive test replays the real pattern observed on a live Pi, where an
aggressive list blocked iCloud (api.apple-cloudkit.com) while ordinary ad
blocking sat in the same log.
"""
from __future__ import annotations

import time

import pytest

from dnsguard.analyze import analyze_collateral

NOW = time.time()


def row(qname, client="10.0.0.5", offset=0.0, action="blocked", rule="", source="hagezi",
        qtype="A"):
    return {"qname": qname, "client_ip": client, "action": action, "qtype": qtype,
            "ts": int((NOW + offset) * 1_000_000), "rule": rule, "source": source}


def by_domain(findings):
    return {f.domain: f for f in findings}


# --- the core discrimination ---
def test_retrying_client_is_flagged_beacon_is_not():
    rows = []
    # iCloud: an app retrying every ~30s for four minutes
    for i in range(8):
        rows.append(row("api.apple-cloudkit.com", offset=i * 30))
    # an ad beacon: fired twice, 14 minutes apart, nobody retried
    rows += [row("ads.doubleclick.net", offset=0), row("ads.doubleclick.net", offset=850)]

    found = by_domain(analyze_collateral(rows))
    assert "api.apple-cloudkit.com" in found
    assert "ads.doubleclick.net" not in found, "one-shot beacons must not be reported"
    f = found["api.apple-cloudkit.com"]
    assert f.severity == "high" and f.retries == 7
    assert 25 <= f.median_gap_s <= 35


def test_single_lookup_never_reported():
    assert analyze_collateral([row("one.example")]) == []


def test_two_distant_lookups_are_not_a_retry():
    rows = [row("slow.example", offset=0), row("slow.example", offset=3600)]
    assert analyze_collateral(rows) == []


def test_retries_are_counted_per_client_not_globally():
    # ten different devices each asking once is not a retry loop
    rows = [row("popular.example", client=f"10.0.0.{i}", offset=i * 2) for i in range(10)]
    assert analyze_collateral(rows) == []


def test_dual_stack_pairs_are_one_attempt_not_a_retry():
    """A dual-stack client asks for A and AAAA in the same instant. That is one
    attempt; counting it as a retry would make every blocked domain look broken."""
    rows = []
    for i in range(6):                       # six attempts, 10 minutes apart
        t = i * 600
        rows.append(row("beacon.example", offset=t, qtype="A"))
        rows.append(row("beacon.example", offset=t + 0.01, qtype="AAAA"))
    assert analyze_collateral(rows) == [], "dual-stack pairs must not read as retries"


def test_same_qtype_repeats_still_count():
    rows = [row("retry.example", offset=i * 20, qtype="A") for i in range(5)]
    f = analyze_collateral(rows)[0]
    assert f.retries == 4 and 15 <= f.median_gap_s <= 25


def test_duplicate_identical_queries_are_ignored():
    # a client whose stub duplicates each query across sockets, milliseconds apart
    rows = []
    for i in range(8):
        rows.append(row("dup.example", offset=i * 300, qtype="A"))
        rows.append(row("dup.example", offset=i * 300 + 0.002, qtype="A"))
    assert analyze_collateral(rows) == []


def test_multiple_affected_clients_rank_higher():
    one = [row("single.example", client="10.0.0.1", offset=i * 20) for i in range(4)]
    many = []
    for c in range(3):
        many += [row("shared.example", client=f"10.0.0.{c}", offset=i * 20) for i in range(4)]
    ranked = analyze_collateral(one + many)
    assert ranked[0].domain == "shared.example"
    assert len(by_domain(ranked)["shared.example"].clients) == 3


def test_persistence_raises_severity():
    # brief burst -> medium; recurring across windows -> high
    burst = [row("burst.example", offset=i * 20) for i in range(3)]
    spread = [row("spread.example", offset=i * 20) for i in range(3)]
    spread += [row("spread.example", offset=1200 + i * 20) for i in range(3)]
    found = by_domain(analyze_collateral(burst + spread))
    assert found["burst.example"].severity == "medium"
    assert found["spread.example"].severity == "high"
    assert found["spread.example"].buckets >= 2


def test_allowlisted_domains_are_excluded():
    rows = [row("fixed.example", offset=i * 20) for i in range(6)]
    assert analyze_collateral(rows) != []
    assert analyze_collateral(rows, exclude={"fixed.example"}) == []


def test_only_blocked_rows_are_considered():
    rows = [row("ok.example", offset=i * 20, action="forwarded") for i in range(8)]
    assert analyze_collateral(rows) == []


def test_findings_carry_actionable_evidence():
    rows = [row("broken.example", offset=i * 25, rule="||broken.example^",
                source="hagezi-ultimate") for i in range(5)]
    f = analyze_collateral(rows)[0]
    j = f.to_json()
    assert j["suggested_action"] == "allow broken.example"
    assert j["source"] == "hagezi-ultimate" and j["rule"] == "||broken.example^"
    assert "retried" in j["evidence"] and "client" in j["evidence"]
    assert j["client_count"] == 1


def test_trailing_dot_and_case_are_normalised():
    rows = [row("MiXeD.Example.", offset=i * 20) for i in range(4)]
    assert analyze_collateral(rows)[0].domain == "mixed.example"


def test_limit_is_respected():
    rows = []
    for d in range(12):
        rows += [row(f"d{d}.example", offset=i * 20) for i in range(4)]
    assert len(analyze_collateral(rows, limit=5)) == 5


# --- replay of the live Pi log ---
def test_replays_real_pi_traffic():
    """Observed on the deployed Pi: iCloud + Slack + Datadog were being retried
    while ordinary ad domains sat quietly in the same window."""
    rows = []
    for i in range(8):                       # api.apple-cloudkit.com, 8 over 267s
        rows.append(row("api.apple-cloudkit.com", offset=i * 38))
    for i in range(4):                       # datadog agent, 4 over 74s
        rows.append(row("http-intake.logs.us5.datadoghq.com", offset=i * 24))
    for i in range(3):                       # slack, tight burst
        rows.append(row("slackb.com", offset=i * 10))
    for d in ("adservice.google.com", "pixel.facebook.com",
              "telemetry.microsoft.com", "ads.doubleclick.net"):
        rows += [row(d, offset=0), row(d, offset=853)]   # 2 hits, 14 min apart

    found = by_domain(analyze_collateral(rows))
    # the three broken services surface...
    assert {"api.apple-cloudkit.com", "http-intake.logs.us5.datadoghq.com",
            "slackb.com"} <= set(found)
    # ...and none of the ad domains do
    assert not ({"adservice.google.com", "pixel.facebook.com",
                 "telemetry.microsoft.com", "ads.doubleclick.net"} & set(found))
    assert found["api.apple-cloudkit.com"].severity == "high"


@pytest.mark.asyncio
async def test_collateral_from_querylog(tmp_path):
    from dnsguard.analyze import collateral_from_querylog
    from dnsguard.store import Database
    from dnsguard.store.querylog import QueryLog
    db = Database(tmp_path / "q.db")
    await db.connect()
    ql = QueryLog(db)
    try:
        now_us = int(time.time() * 1_000_000)
        for i in range(6):
            await db.execute(
                "INSERT INTO querylog(ts,client_ip,qname,qtype,action,rcode,rule,source)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (now_us + i * 20_000_000, "10.0.0.7", "sync.example", "A",
                 "blocked", "NXDOMAIN", "||sync.example^", "hagezi"))
        await db.execute(
            "INSERT INTO querylog(ts,client_ip,qname,qtype,action,rcode)"
            " VALUES(?,?,?,?,?,?)", (now_us, "10.0.0.7", "fine.example", "A",
                                     "forwarded", "NOERROR"))
        out = await collateral_from_querylog(ql, hours=24)
        assert [f.domain for f in out] == ["sync.example"]
        assert out[0].source == "hagezi"
    finally:
        await db.close()
