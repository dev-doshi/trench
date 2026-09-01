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
