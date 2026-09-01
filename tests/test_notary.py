"""Quorum resolution for pinned names."""
from __future__ import annotations

import asyncio

from trench.ops.notary import Notary, network_of
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.rrtypes import Rcode


class FakeUpstream:
    def __init__(self, label: str, addrs: list[str] | None = None, fail: str = ""):
        self.label, self.addrs, self.fail = label, addrs or [], fail

    def __repr__(self) -> str:
        return self.label

    async def query(self, msg: Message) -> Message:
        if self.fail:
            raise OSError(self.fail)
        resp = msg.reply(Rcode.NOERROR)
        for a in self.addrs:
            resp.answers.append(RR(msg.question.name, Type.A, Class.IN, 60, R.A(a)))
        return resp


class FakeForwarder:
    def __init__(self, ups):
        self.router = type("R", (), {"default": ups, "routes": {}})()


def notary(ups, names=("bank.example",)) -> Notary:
    return Notary(FakeForwarder(ups), list(names))


def test_network_granularity():
    assert network_of("93.184.216.34") == "93.184.216.0/24"
    assert network_of("2001:db8:1:2::5") == "2001:db8:1::/48"
    assert network_of("not-an-ip") == ""


def test_agreement_produces_nothing_to_report():
    n = notary([FakeUpstream("a", ["93.184.216.34"]),
                FakeUpstream("b", ["93.184.216.99"])])   # same /24
    assert asyncio.run(n.run_once()) == []


def test_disagreement_is_reported_with_every_answer():
    n = notary([FakeUpstream("a", ["93.184.216.34"]),
                FakeUpstream("b", ["203.0.113.7"])])
    (finding,) = asyncio.run(n.run_once())
    assert finding.agreed is False
    assert "disagree" in finding.note
    labels = {o.upstream: o.addresses for o in finding.observations}
    assert labels == {"a": ["93.184.216.34"], "b": ["203.0.113.7"]}


def test_a_new_network_for_a_known_name_is_reported_even_when_upstreams_agree():
    ups = [FakeUpstream("a", ["93.184.216.34"]), FakeUpstream("b", ["93.184.216.35"])]
    n = notary(ups)
    assert asyncio.run(n.run_once()) == []          # first round: baseline
    ups[0].addrs = ups[1].addrs = ["198.51.100.9"]
    (finding,) = asyncio.run(n.run_once())
    assert finding.agreed is True
    assert "not seen for this name before" in finding.note


def test_an_upstream_being_down_is_an_absence_not_a_disagreement():
    n = notary([FakeUpstream("a", ["93.184.216.34"]),
                FakeUpstream("b", fail="connection refused")])
    assert asyncio.run(n.run_once()) == []


def test_one_upstream_cannot_be_compared_with_itself():
    n = notary([FakeUpstream("a", ["93.184.216.34"])])
    finding = asyncio.run(n.check("bank.example"))
    assert finding.agreed and "nothing to compare" in finding.note


def test_history_is_bounded():
    n = notary([FakeUpstream("a", ["93.184.216.34"]), FakeUpstream("b", ["203.0.113.7"])],
               names=[f"name{i}.example" for i in range(40)])
    asyncio.run(n.run_once())
    assert len(n.findings) == Notary.HISTORY
