"""Policy assertions: parsing, checking, and gating a blocklist refresh."""
from __future__ import annotations

import asyncio

import pytest

from trench.config import Config
from trench.errors import ConfigError
from trench.filter import FilterEngine
from trench.filter.contract import (
    ContractError,
    check,
    parse_all,
    parse_assertion,
    summarise,
)
from trench.filter.parser import parse_line
from trench.wire.rrtypes import Type


def engine(*lines: str) -> FilterEngine:
    return FilterEngine.compile([parse_line(ln, "somelist") for ln in lines])


# --- parsing ---
def test_forms_that_parse():
    a = parse_assertion("bank.example must resolve")
    assert (a.name, a.expect, a.qtype) == ("bank.example", "resolve", Type.A)
    b = parse_assertion("mail.example MX must block")
    assert (b.name, b.expect, b.qtype) == ("mail.example", "block", Type.MX)


@pytest.mark.parametrize("text", [
    "nonsense here",
    "bank.example must maybe",
    "bank.example A AAAA must resolve",
    "bank.example XYZZY must resolve",
    " must resolve",
])
def test_forms_that_are_refused(text):
    with pytest.raises(ContractError):
        parse_assertion(text)


def test_config_refuses_an_unparseable_assertion_at_load():
    """The point of the gate is that it fires at 3am; the syntax error must not."""
    with pytest.raises(ConfigError):
        Config.load_dict({"filtering": {"assertions": ["bank.example must maybe"]}})
    ok = Config.load_dict({"filtering": {"assertions": ["bank.example must resolve"]}})
    assert ok.filtering.assertions == ["bank.example must resolve"]


# --- checking ---
def test_violations_are_reported_with_the_rule_responsible():
    eng = engine("||bank.example^")
    (failure,) = check(eng, parse_all(["bank.example must resolve"]))
    assert failure.rule == "bank.example"
    assert failure.list_source == "somelist"
    assert "would be blocked" in failure.describe()


def test_a_satisfied_contract_has_no_failures():
    eng = engine("||ads.example^")
    assert check(eng, parse_all(["bank.example must resolve",
                                 "ads.example must block"])) == []


def test_missing_block_rule_is_a_failure_too():
    (failure,) = check(engine(), parse_all(["ads.example must block"]))
    assert "would resolve" in failure.describe()


def test_wildcard_assertion_probes_under_the_name():
    eng = engine("||internal.lan^")
    assert check(eng, parse_all(["*.internal.lan must resolve"]))
    assert check(engine(), parse_all(["*.internal.lan must resolve"])) == []


def test_summary_truncates():
    fails = check(engine("||a.example^", "||b.example^", "||c.example^", "||d.example^"),
                  parse_all([f"{c}.example must resolve" for c in "abcd"]))
    assert "+1 more" in summarise(fails)


# --- refresh gate ---
class FakeGravity:
    def __init__(self, engine):
        self._engine = engine
        self.report = type("R", (), {"errors": []})()
        self.sources = ["list"]
        self.group_engines = {}

    async def build(self):
        return self._engine


def make_app(tmp_path, assertions: list[str]):
    from trench.app import App
    cfg = Config.load_dict({"data_dir": str(tmp_path),
                            "filtering": {"assertions": assertions,
                                          "sources": ["data/default_blocklist.txt"]}})
    return App(cfg)


def test_refresh_that_breaks_an_assertion_is_not_adopted(tmp_path):
    app = make_app(tmp_path, ["bank.example must resolve"])
    good = engine("||ads.example^")
    app.filter = good
    app.pipeline.filter = good
    app._gravity = FakeGravity(engine("||ads.example^", "||bank.example^"))
    asyncio.run(app.refresh_blocklists())
    assert app.pipeline.filter is good                    # previous rules kept
    assert app.contract_failures and app.contract_failures[0].rule == "bank.example"


def test_a_clean_refresh_is_adopted_and_clears_the_failure(tmp_path):
    app = make_app(tmp_path, ["bank.example must resolve"])
    app.filter = app.pipeline.filter = engine()
    app.contract_failures = ["stale"]
    candidate = engine("||ads.example^")
    app._gravity = FakeGravity(candidate)
    asyncio.run(app.refresh_blocklists())
    assert app.pipeline.filter is candidate
    assert app.contract_failures == []
