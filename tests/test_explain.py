"""The composed 'why is this broken' report."""
from __future__ import annotations

import asyncio

from trench.clients.activity import QUIET_AFTER, Ledger
from trench.clients.names import HostNames
from trench.config import Config
from trench.filter import FilterEngine
from trench.filter.contract import parse_all
from trench.filter.parser import parse_line
from trench.ops.explain import explain
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.rrtypes import Rcode


class Fwd:
    def __init__(self, rcode=Rcode.NOERROR, addr="93.184.216.34"):
        self.rcode, self.addr = rcode, addr

    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(self.rcode)
        if self.rcode == Rcode.NOERROR:
            resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60,
                                   R.A(self.addr)))
        if note is not None:
            note("test-upstream")
        return resp


def make_app(tmp_path, rules=(), clients=(), forwarder=None):
    from trench.app import App
    cfg = Config.load_dict({"data_dir": str(tmp_path), "clients": list(clients)})
    app = App(cfg)
    engine = FilterEngine.compile([parse_line(r, "testlist") for r in rules])
    app.filter = engine
    app.pipeline.filter = engine
    if forwarder is not None:
        app.pipeline.forwarder = forwarder
    return app


def run(app, name, **kw):
    return asyncio.run(explain(app, name, **kw))


def test_a_blocked_name_names_the_rule_and_the_list(tmp_path):
    app = make_app(tmp_path, rules=["||ads.example^"])
    report = run(app, "ads.example")
    assert "blocked" in report["verdict"]
    assert report["rule"]["rule"] == "ads.example"
    assert any(f["stage"] == "filter" and "testlist" in f["detail"]
               for f in report["findings"])


def test_a_name_nothing_touches_says_so(tmp_path):
    app = make_app(tmp_path, rules=["||ads.example^"])
    report = run(app, "example.com")
    assert "nothing here blocks it" in report["verdict"]


def test_a_pause_is_reported_ahead_of_the_rule(tmp_path):
    """The rule still matches; it is not what is happening right now."""
    app = make_app(tmp_path, rules=["||ads.example^"])
    app.pipeline.pause(300)
    report = run(app, "ads.example")
    assert "paused" in report["verdict"]


def test_a_locally_published_lease_is_reported(tmp_path):
    app = make_app(tmp_path)
    app.hostnames = HostNames(domain="lan", network="192.168.1.0/24")
    app.hostnames.register("192.168.1.50", "kids-tablet")
    report = run(app, "kids-tablet.lan")
    assert "answered here" in report["verdict"]
    assert "192.168.1.50" in report["findings"][0]["detail"]


def test_a_silent_device_is_surfaced_for_the_client_that_asked(tmp_path):
    app = make_app(tmp_path)
    app.ledger = Ledger()
    import time
    now = time.time()
    app.ledger.note("10.0.0.5", "chrome.cloudflare-dns.com", now=now - QUIET_AFTER * 2)
    app.ledger.note_lease("10.0.0.5", "laptop", now=now - 60)
    report = run(app, "example.com", client="10.0.0.5")
    assert report["device"]["status"] == "bypassing"
    assert "not asking this resolver" in report["verdict"]


def test_service_membership_is_explained_even_when_not_selected(tmp_path):
    app = make_app(tmp_path)
    report = run(app, "www.youtube.com", client="10.0.0.5")
    (finding,) = [f for f in report["findings"] if f["stage"] == "service"]
    assert finding["verdict"] == "would block if selected"
    assert "youtube" in finding["detail"]


def test_service_block_for_a_client_that_selected_it(tmp_path):
    app = make_app(tmp_path, clients=[{"ident": "10.0.0.5", "services": ["youtube"]}])
    report = run(app, "www.youtube.com", client="10.0.0.5")
    assert "blocked" in report["verdict"]


def test_live_resolution_reports_servfail(tmp_path):
    app = make_app(tmp_path, forwarder=Fwd(rcode=Rcode.SERVFAIL))
    report = run(app, "broken.example", resolve=True)
    assert report["live"]["rcode"] == "SERVFAIL"
    assert "SERVFAIL" in report["verdict"]


def test_live_resolution_reports_a_normal_answer(tmp_path):
    app = make_app(tmp_path, forwarder=Fwd())
    report = run(app, "example.com", resolve=True)
    assert report["live"]["answers"] == ["93.184.216.34"]
    assert "resolves normally" in report["verdict"]
    # the cache section describes what was cached when the complaint came in,
    # which is deliberately read before the live probe runs
    assert report["cache"]["present"] is False


def test_a_failing_contract_assertion_is_attached(tmp_path):
    from trench.filter.contract import check
    app = make_app(tmp_path, rules=["||bank.example^"])
    app.contract_failures = check(app.filter, parse_all(["bank.example must resolve"]))
    report = run(app, "bank.example")
    assert any(f["stage"] == "contract" for f in report["findings"])


# --- the halves that were never asked ---
def test_an_unknown_record_type_falls_back_to_a(tmp_path):
    app = make_app(tmp_path)
    assert run(app, "example.com", qtype="NOTATYPE")["type"] == "A"


def test_the_record_type_is_carried_through(tmp_path):
    app = make_app(tmp_path)
    assert run(app, "example.com", qtype="aaaa")["type"] == "AAAA"


def test_the_name_is_normalised(tmp_path):
    app = make_app(tmp_path)
    assert run(app, "  ADS.Example.  ")["name"] == "ads.example"


def test_the_client_policy_is_reported(tmp_path):
    app = make_app(tmp_path, clients=[{"ident": "10.0.0.5", "name": "kid",
                                       "services": ["tiktok"]}])
    report = run(app, "example.com", client="10.0.0.5")
    assert report["policy"]["name"] == "kid"
    assert report["policy"]["services"] == ["tiktok"]
    assert report["policy"]["block"] is True


def test_no_policy_block_without_a_client(tmp_path):
    assert "policy" not in run(make_app(tmp_path), "example.com")


def test_an_allow_rule_is_reported_as_explicitly_allowed(tmp_path):
    app = make_app(tmp_path, rules=["||ads.example^", "@@||ok.ads.example^$important"])
    report = run(app, "ok.ads.example")
    assert report["rule"]["action"] == "allow"
    assert any(f["verdict"] == "explicitly allowed" for f in report["findings"])
    assert "explicitly allowed" in report["verdict"]


def test_a_rewrite_rule_is_reported(tmp_path):
    app = make_app(tmp_path, rules=["||ads.example^$dnsrewrite=NXDOMAIN"])
    report = run(app, "ads.example")
    assert report["rule"]["action"] in ("rewrite", "block")


def test_filtering_switched_off_outranks_the_rule(tmp_path):
    app = make_app(tmp_path, rules=["||ads.example^"])
    app.pipeline.enabled = False
    report = run(app, "ads.example")
    assert "filtering off" in report["verdict"]


def test_an_authoritative_zone_is_reported(tmp_path):
    from trench.auth_zone import Zone, ZoneStore
    from trench.wire import rdata as R2
    from trench.wire.name import Name
    from trench.wire.rrtypes import Type as T
    app = make_app(tmp_path)
    store = ZoneStore()
    zone = Zone(Name.from_text("home.arpa."))
    zone.add(Name.from_text("home.arpa."), int(T.SOA),
             R2.SOA(Name.from_text("ns.home.arpa."), Name.from_text("hm.home.arpa."),
                    1, 3600, 600, 604800, 3600))
    store.add(zone)
    app.zones = store
    report = run(app, "nas.home.arpa")
    assert any(f["stage"] == "zone" for f in report["findings"])
    assert "answered here" in report["verdict"]


def test_a_name_that_is_not_a_legal_wire_name_is_reported_not_raised(tmp_path):
    """`name=` in the console's URL is unvalidated input; an over-long label
    used to raise out of the cache probe and turn the report into a 500."""
    from trench.auth_zone import Zone, ZoneStore
    from trench.wire.name import Name
    app = make_app(tmp_path, rules=["||ads.example^"])
    store = ZoneStore()
    store.add(Zone(Name.from_text("home.arpa.")))
    app.zones = store
    report = run(app, "a" * 300, resolve=True)
    assert "not a valid name" in report["verdict"]
    assert any(f["stage"] == "name" for f in report["findings"])
    assert "cache" not in report and "live" not in report


def test_a_cache_hit_is_reported_with_its_answers(tmp_path):
    from trench.wire import Question
    from trench.wire.name import Name
    app = make_app(tmp_path)
    n = Name.from_text("cached.example.")
    probe = Message(id=0)
    probe.questions.append(Question(n, Type.A, Class.IN))
    resp = probe.reply(Rcode.NOERROR)
    resp.answers.append(RR(n, Type.A, Class.IN, 300, R.A("192.0.2.7")))
    app.cache.put(app.cache.key_for(probe), resp)
    report = run(app, "cached.example")
    assert report["cache"]["present"] is True
    assert report["cache"]["stale"] is False
    assert report["cache"]["rcode"] == "NOERROR"
    assert report["cache"]["answers"] == ["192.0.2.7"]


def test_a_cache_miss_is_reported_as_absent(tmp_path):
    report = run(make_app(tmp_path), "never.asked.example")
    assert report["cache"] == {"present": False}


def test_a_query_log_failure_does_not_fail_the_report(tmp_path, caplog):
    app = make_app(tmp_path)

    class Broken:
        async def search(self, **kw):
            raise RuntimeError("database is locked")

        async def history(self, *a, **kw):
            return []

    app.querylog = Broken()
    report = run(app, "example.com")
    assert report["verdict"]
    assert any("query log lookup failed" in r.getMessage() for r in caplog.records)


def test_a_changed_answer_set_is_surfaced_from_the_history(tmp_path):
    app = make_app(tmp_path)

    class Log:
        async def search(self, **kw):
            return [{"ts": 1, "client_ip": "10.0.0.5", "action": "forwarded",
                     "rcode": "NOERROR", "reason": ""}]

        async def history(self, name, **kw):
            return [{"answers": ["192.0.2.1"]}, {"answers": ["198.51.100.1"]}]

    app.querylog = Log()
    report = run(app, "moved.example")
    assert report["recent"][0]["client"] == "10.0.0.5"
    assert any(f["verdict"] == "answer changed" for f in report["findings"])
    assert "192.0.2.1" in str(report["findings"])


def test_a_history_with_no_addresses_still_reads(tmp_path):
    app = make_app(tmp_path)

    class Log:
        async def search(self, **kw):
            return []

        async def history(self, name, **kw):
            return [{"answers": []}, {"answers": []}]

    app.querylog = Log()
    report = run(app, "empty.example")
    assert "no addresses" in str(report["findings"])


def test_a_live_resolution_failure_is_reported_as_an_error(tmp_path):
    app = make_app(tmp_path)

    class Broken:
        async def resolve_ctx(self, *a, **kw):
            raise RuntimeError("no upstream configured")

    app.pipeline.resolve_ctx = Broken().resolve_ctx
    report = run(app, "example.com", resolve=True)
    assert report["live"] == {"error": "no upstream configured"}


def test_extended_errors_are_read_off_the_live_response(tmp_path):
    from trench.wire.edns import Edns
    from trench.wire.rrtypes import EDNSOption
    app = make_app(tmp_path)

    class Ctx:
        action = "blocked"
        reason = "on a list"
        upstream = ""

        def __init__(self, resp):
            self.response = resp

    async def resolve_ctx(query, client, proto=""):
        resp = query.reply(Rcode.NXDOMAIN)
        resp.edns = Edns()
        resp.edns.set_option(EDNSOption.EXTENDED_ERROR,
                             (15).to_bytes(2, "big") + b"Blocked")
        return Ctx(resp)

    app.pipeline.resolve_ctx = resolve_ctx
    report = run(app, "ads.example", resolve=True)
    assert report["live"]["extended_errors"] == [{"code": 15, "text": "Blocked"}]


def test_a_response_without_edns_reports_no_extended_errors(tmp_path):
    from trench.ops.explain import _edns_errors
    assert _edns_errors(Message(id=0)) == []


def test_a_truncated_extended_error_option_is_ignored(tmp_path):
    from trench.ops.explain import _edns_errors
    from trench.wire.edns import Edns
    from trench.wire.rrtypes import EDNSOption
    m = Message(id=0)
    m.edns = Edns()
    m.edns.set_option(EDNSOption.EXTENDED_ERROR, b"\x00")   # one byte, not two
    assert _edns_errors(m) == []


def test_a_device_that_is_bypassing_outranks_the_rule(tmp_path):
    import time
    app = make_app(tmp_path, rules=["||ads.example^"])
    ledger = Ledger()

    class FakeLedger:
        def device(self, client):
            return {"status": "bypassing", "evidence": "seen resolving elsewhere",
                    "client": client}

    app.ledger = FakeLedger()
    report = run(app, "ads.example", client="10.0.0.5")
    assert report["device"]["status"] == "bypassing"
    assert "bypassing" in report["verdict"]
    assert ledger is not None and time is not None


def test_an_unknown_device_contributes_nothing(tmp_path):
    app = make_app(tmp_path)

    class FakeLedger:
        def device(self, client):
            return None

    app.ledger = FakeLedger()
    report = run(app, "example.com", client="10.0.0.5")
    assert "device" not in report


def test_a_normally_resolving_name_says_so(tmp_path):
    app = make_app(tmp_path, forwarder=Fwd())
    report = run(app, "example.com", resolve=True)
    assert "resolves normally" in report["verdict"]
    assert "93.184.216.34" in report["verdict"]
