"""Reviewing a blocklist update.

The point is not to diff two domain sets — that produces tens of thousands of
lines about names this network will never look up. It is to answer "of the names
we actually asked for, which does the new list decide differently, and which of
those will someone notice".
"""
from __future__ import annotations

import time

import pytest

from trench.analyze import review_update
from trench.filter import FilterEngine, compile_rules


def eng(text: str, source: str = "hagezi") -> FilterEngine:
    return FilterEngine.compile(compile_rules(text, source))


def seen(qname: str, hits: int = 1, clients: int = 1, blocked_hits: int = 0) -> dict:
    return {"qname": qname, "hits": hits, "clients": clients, "blocked_hits": blocked_hits,
            "last_seen": int(time.time() * 1_000_000)}


def by_name(changes):
    return {c.qname: c for c in changes}


def test_only_names_the_network_asked_for_are_reported():
    """A list can add 300k domains; if none are ever looked up, the update is a
    non-event and must read as one."""
    old = eng("||ads.example^")
    new = eng("||ads.example^\n" + "\n".join(f"||unused{i}.example^" for i in range(5000)))
    rev = review_update(old, new, [seen("wanted.example", hits=90)])
    assert rev.newly_blocked == [] and rev.newly_allowed == []
    assert rev.domains_after - rev.domains_before == 5000
    assert rev.per_source == {"hagezi": 5000}


def test_a_newly_blocked_busy_name_is_high_risk():
    """The scenario this exists for: a maintainer adds a domain real devices
    depend on, and today nothing connects the outage to the list update."""
    old = eng("||ads.example^")
    new = eng("||ads.example^\n||graph.facebook.com^")
    rev = review_update(old, new, [seen("graph.facebook.com", hits=340, clients=4)])
    assert len(rev.newly_blocked) == 1
    c = rev.newly_blocked[0]
    assert c.qname == "graph.facebook.com"
    assert c.before == "NONE" and c.after == "BLOCK"
    assert c.risk == "high" and c.hits == 340 and c.clients == 4
    assert c.source == "hagezi"
    assert rev.high_risk == 1


def test_a_single_lookup_from_one_device_is_not_high_risk():
    old = eng("")
    new = eng("||beacon.example^")
    rev = review_update(old, new, [seen("beacon.example", hits=1, clients=1)])
    assert rev.newly_blocked[0].risk == "low"
    assert rev.high_risk == 0


def test_subdomain_of_a_new_rule_is_caught():
    """Matching, not string comparison: the added rule is for the parent."""
    old = eng("")
    new = eng("||tracker.example^")
    rev = review_update(old, new, [seen("api.eu.tracker.example", hits=50, clients=3)])
    assert by_name(rev.newly_blocked)["api.eu.tracker.example"].risk == "high"


def test_traffic_already_being_blocked_is_not_flagged_as_a_new_break():
    """Risk keys off whether the network was *getting answers*. A name whose
    every lookup in the window was already blocked (a list dropped it and this
    update puts it back) is a busy name whose users never had it working, so
    restoring the block breaks nothing new."""
    old = eng("||other.example^")
    new = eng("||other.example^\n||ads.example^")
    names = [seen("ads.example", hits=200, clients=5, blocked_hits=200)]
    rev = review_update(old, new, names)
    assert len(rev.newly_blocked) == 1, "the verdict did change and must be reported"
    assert rev.newly_blocked[0].risk == "low"
    assert rev.high_risk == 0

    # identical traffic, but it was being answered -> the operator will feel it
    answered = [seen("ads.example", hits=200, clients=5, blocked_hits=0)]
    assert review_update(old, new, answered).newly_blocked[0].risk == "high"


def test_names_that_stop_being_blocked_are_reported_separately():
    """The other direction matters too: a list dropping a domain silently
    un-blocks it, which is a policy change the operator never approved."""
    old = eng("||tracker.example^\n||ads.example^")
    new = eng("||ads.example^")
    rev = review_update(old, new, [seen("tracker.example", hits=80, clients=3, blocked_hits=80)])
    assert not rev.newly_blocked
    assert len(rev.newly_allowed) == 1
    c = rev.newly_allowed[0]
    assert c.qname == "tracker.example" and c.before == "BLOCK" and c.after == "NONE"


def test_unchanged_verdicts_are_omitted():
    old = eng("||ads.example^")
    new = eng("||ads.example^")
    rev = review_update(old, new, [seen("ads.example", hits=10), seen("fine.example", hits=10)])
    assert not rev.newly_blocked and not rev.newly_allowed
    assert rev.names_checked == 2


def test_riskiest_first_and_the_report_is_capped():
    old = eng("")
    new = eng("\n".join(f"||d{i}.example^" for i in range(50)))
    names = [seen(f"d{i}.example", hits=1, clients=1) for i in range(50)]
    names.append(seen("d7.example", hits=500, clients=9))   # the one that matters
    rev = review_update(old, new, names, top=5)
    assert len(rev.newly_blocked) == 5
    assert rev.newly_blocked[0].qname == "d7.example"
    assert rev.newly_blocked[0].risk == "high"


def test_first_build_reports_no_changes():
    """With nothing to compare against, every domain is 'new', which tells the
    operator nothing — so it must not be presented as a diff."""
    new = eng("||ads.example^")
    rev = review_update(None, new, [seen("ads.example", hits=99, clients=5)])
    assert not rev.newly_blocked and not rev.newly_allowed
    assert rev.domains_before == 0 and rev.domains_after == 1


def test_per_source_delta_is_signed():
    old = FilterEngine.compile(compile_rules("||a.example^\n||b.example^", "listA")
                               + compile_rules("||c.example^", "listB"))
    new = FilterEngine.compile(compile_rules("||a.example^", "listA")
                               + compile_rules("||c.example^\n||d.example^", "listB"))
    rev = review_update(old, new, [])
    assert rev.per_source == {"listA": -1, "listB": 1}


def test_allowlisted_domain_does_not_appear_as_newly_blocked():
    """An operator exception must survive a list update without being reported
    as breakage."""
    old = eng("")
    new = FilterEngine.compile(compile_rules("||keep.example^", "hagezi")
                               + compile_rules("@@||keep.example^", "allowlist"))
    rev = review_update(old, new, [seen("keep.example", hits=300, clients=6)])
    assert not rev.newly_blocked


def test_summary_states_the_numbers_a_human_needs():
    old = eng("||ads.example^")
    new = eng("||ads.example^\n||graph.facebook.com^")
    rev = review_update(old, new, [seen("graph.facebook.com", hits=300, clients=5)])
    s = rev.summary()
    assert "+1" in s and "1 newly blocked" in s and "1 high risk" in s


@pytest.mark.asyncio
async def test_review_from_querylog_aggregates_real_rows(tmp_path):
    from trench.analyze import review_from_querylog
    from trench.store import Database
    from trench.store.querylog import QueryLog
    db = Database(tmp_path / "q.db")
    await db.connect()
    ql = QueryLog(db)
    try:
        now = int(time.time() * 1_000_000)
        for i in range(30):     # busy name, several devices
            await db.execute(
                "INSERT INTO querylog(ts,client_ip,qname,qtype,action) VALUES(?,?,?,?,?)",
                (now, f"10.0.0.{i % 3}", "graph.facebook.com", "A", "forwarded"))
        await db.execute(
            "INSERT INTO querylog(ts,client_ip,qname,qtype,action) VALUES(?,?,?,?,?)",
            (now, "10.0.0.9", "once.example", "A", "forwarded"))

        old = eng("||ads.example^")
        new = eng("||ads.example^\n||graph.facebook.com^\n||once.example^")
        rev = await review_from_querylog(old, new, ql, hours=24)
        changes = by_name(rev.newly_blocked)
        assert changes["graph.facebook.com"].hits == 30
        assert changes["graph.facebook.com"].clients == 3
        assert changes["graph.facebook.com"].risk == "high"
        assert changes["once.example"].risk == "low"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_refresh_records_a_review(tmp_path):
    """End to end: a refresh must leave behind a readable record of what it
    changed, without the operator having asked for one."""
    from trench.app import App
    from trench.config import Config

    listfile = tmp_path / "list.txt"
    listfile.write_text("||ads.example^\n")
    cfg = Config.model_validate({
        "data_dir": str(tmp_path), "server": {"do53": {"enabled": False}},
        "filtering": {"sources": [str(listfile)]},
    })
    app = App(cfg)
    await app.setup_storage()
    try:
        await app.load_blocklists()
        now = int(time.time() * 1_000_000)
        for i in range(40):
            await app.db.execute(
                "INSERT INTO querylog(ts,client_ip,qname,qtype,action) VALUES(?,?,?,?,?)",
                (now, f"10.0.0.{i % 4}", "cdn.example", "A", "forwarded"))

        listfile.write_text("||ads.example^\n||cdn.example^\n")
        await app.refresh_blocklists()

        row = await app.db.fetchone(
            "SELECT domains_before, domains_after, high_risk, detail FROM list_review")
        assert row is not None, "a refresh must record a review"
        assert row["domains_after"] == row["domains_before"] + 1
        assert row["high_risk"] == 1
        import json
        detail = json.loads(row["detail"])
        assert detail["newly_blocked"][0]["qname"] == "cdn.example"
        assert detail["newly_blocked"][0]["clients"] == 4
    finally:
        await app.db.close()
