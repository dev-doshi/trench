"""What-if policy replay + RFC 8914 Extended DNS Errors."""
from __future__ import annotations

import socket
import struct
import time

import pytest

from trench.filter import FilterEngine
from trench.filter.rule import Rule
from trench.ops.whatif import compile_delta, diff_decisions, whatif_from_querylog
from trench.wire import Class, Message, Question, Type
from trench.wire.edns import Edns
from trench.wire.name import Name
from trench.wire.rrtypes import EDNSOption


def _current():
    return FilterEngine.compile([
        Rule(raw="||ads.example^", block=True, suffix="ads.example", source="gravity"),
    ])


# --- what-if: pure diff semantics ---
def test_whatif_newly_blocked_with_subdomains():
    delta = compile_delta(deny=["tracker.example"])
    names = [("tracker.example", 10), ("cdn.tracker.example", 5),
             ("safe.example", 100), ("ads.example", 7)]
    res = diff_decisions(_current(), delta, names)
    flipped = {f.qname for f in res.newly_blocked}
    assert flipped == {"tracker.example", "cdn.tracker.example"}   # suffix match
    assert res.newly_allowed == []
    assert res.affected_hits == 15 and res.total_hits == 122
    # ranked by hits, and already-blocked ads.example did NOT flip
    assert res.newly_blocked[0].qname == "tracker.example"


def test_whatif_allow_overrides_current_block():
    delta = compile_delta(allow=["ads.example"])
    res = diff_decisions(_current(), delta, [("ads.example", 42), ("x.example", 1)])
    assert [f.qname for f in res.newly_allowed] == ["ads.example"]
    assert res.newly_blocked == [] and res.affected_hits == 42


def test_whatif_from_pasted_blocklist_text():
    text = "0.0.0.0 telemetry.example\n||spy.example^\n# comment\n"
    delta = compile_delta(list_text=text)
    res = diff_decisions(_current(), delta,
                         [("telemetry.example", 3), ("api.spy.example", 2), ("ok.example", 9)])
    assert {f.qname for f in res.newly_blocked} == {"telemetry.example", "api.spy.example"}


def test_whatif_json_shape_and_pct():
    delta = compile_delta(deny=["t.example"])
    res = diff_decisions(_current(), delta, [("t.example", 25), ("o.example", 75)])
    j = res.to_json()
    assert j["affected_pct"] == 25.0
    assert j["newly_blocked_count"] == 1
    assert j["newly_blocked"][0]["qname"] == "t.example"


# --- what-if: against a real query log DB ---
@pytest.mark.asyncio
async def test_whatif_from_querylog(tmp_path):
    from trench.store import Database
    db = Database(tmp_path / "t.db")
    await db.connect()
    try:
        now_us = int(time.time() * 1_000_000)
        rows = [("tracker.example", 4), ("safe.example", 2)]
        for qname, n in rows:
            for _ in range(n):
                await db.execute(
                    "INSERT INTO querylog(ts, client_ip, qname, qtype, action, rcode) "
                    "VALUES(?,?,?,?,?,?)", (now_us, "10.0.0.1", qname, "A", "forwarded", "NOERROR"))
        # an OLD row outside the window must not count
        await db.execute(
            "INSERT INTO querylog(ts, client_ip, qname, qtype, action, rcode) "
            "VALUES(?,?,?,?,?,?)",
            (now_us - 3 * 86400 * 1_000_000, "10.0.0.1", "tracker.example", "A", "forwarded", "NOERROR"))
        delta = compile_delta(deny=["tracker.example"])
        res = await whatif_from_querylog(db, _current(), delta, hours=24)
        assert res.newly_blocked[0].qname == "tracker.example"
        assert res.newly_blocked[0].hits == 4          # old row excluded
        assert res.total_hits == 6
    finally:
        await db.close()


# --- what-if: API endpoint ---
@pytest.mark.asyncio
async def test_whatif_api(tmp_path):
    import aiohttp

    from trench.api import APIServer
    from trench.app import App
    from trench.config import Config
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "filtering": {"deny": ["ads.example"]},
                                 "web": {"enabled": True, "admin_password": "pw"}})
    app = App(cfg)
    await app.setup_storage()
    now_us = int(time.time() * 1_000_000)
    await app.db.execute(
        "INSERT INTO querylog(ts, client_ip, qname, qtype, action, rcode) VALUES(?,?,?,?,?,?)",
        (now_us, "10.0.0.1", "tv-telemetry.example", "A", "forwarded", "NOERROR"))
    s_ = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_.bind(("127.0.0.1", 0)); port = s_.getsockname()[1]; s_.close()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
            r = await s.post(f"{base}/api/v1/whatif",
                             json={"deny": ["tv-telemetry.example"]})
            data = await r.json()
            assert data["newly_blocked_count"] == 1
            assert data["newly_blocked"][0]["qname"] == "tv-telemetry.example"
            # live filter untouched: nothing was applied
            from trench.filter import Action
            assert app.filter.match("tv-telemetry.example").action != Action.BLOCK
    finally:
        await app.api.stop(); await app.db.close()


# --- RFC 8914 EDE on blocked responses ---
def _pipeline(ede=True):
    from trench.cache import Cache
    from trench.config import Config
    from trench.engine.pipeline import Pipeline
    from trench.stats import Counters
    cfg = Config.model_validate({"filtering": {"ede": ede}})
    return Pipeline(filter_engine=_current(), cache=Cache(), forwarder=None,
                    counters=Counters(), config=cfg)


def _query(name="ads.example", edns=True):
    q = Message(id=9)
    q.set_flag(0x0100, True)
    q.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    if edns:
        q.edns = Edns(udp_size=1232)
    return q


@pytest.mark.asyncio
async def test_ede_attached_to_blocked_response():
    p = _pipeline()
    resp = await p.resolve(_query(), "127.0.0.1", "udp")
    opt = resp.edns.get_option(EDNSOption.EXTENDED_ERROR)
    assert opt is not None
    info_code = struct.unpack(">H", opt[:2])[0]
    assert info_code == 15                                  # Blocked
    assert b"ads.example" in opt[2:]                        # the matched rule text
    # and it survives real wire serialization (what a client actually sees)
    parsed = Message.parse(resp.to_wire())
    wire_opt = parsed.edns.get_option(EDNSOption.EXTENDED_ERROR)
    assert wire_opt == opt


@pytest.mark.asyncio
async def test_ede_not_on_plain_dns_or_when_disabled():
    # no EDNS in the query -> no OPT -> no EDE (spec: EDE rides in OPT)
    p = _pipeline()
    resp = await p.resolve(_query(edns=False), "127.0.0.1", "udp")
    assert resp.edns is None
    # feature disabled -> clean response
    p2 = _pipeline(ede=False)
    resp2 = await p2.resolve(_query(), "127.0.0.1", "udp")
    assert resp2.edns.get_option(EDNSOption.EXTENDED_ERROR) is None
