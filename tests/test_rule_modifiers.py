"""Adblock DNS modifiers: $client, $ctag, $dnstype — including exclusions.

Three defects motivated this file, all of them silent:

  * `$client=` rules never matched, because the pipeline never told the matcher
    who was asking. A rule that looks correct in the UI did nothing.
  * `$dnstype=~A` was *inverted*: the `~` was stripped, turning "every type
    except A" into "only A". Worse than ignoring the rule.
  * `$ctag=~kids` / `$client=~1.2.3.4` were read as literal values, so they
    matched a tag or client whose name began with a tilde — i.e. never.
"""
from __future__ import annotations

import pytest

from dnsguard.filter import Action, FilterEngine, compile_rules
from dnsguard.wire.rrtypes import Type


def eng(text: str) -> FilterEngine:
    return FilterEngine.compile(compile_rules(text, "list"))


# --- $client ---
def test_client_rule_matches_by_ip():
    e = eng("||ads.example^$client=10.0.0.5")
    assert e.match("ads.example", client="10.0.0.5").action == Action.BLOCK
    assert e.match("ads.example", client="10.0.0.6").action == Action.NONE


def test_client_rule_ignored_when_no_client_is_supplied():
    """Guards the original bug from the other side: with no identity known, a
    client-scoped rule must not fire for everyone."""
    e = eng("||ads.example^$client=10.0.0.5")
    assert e.match("ads.example").action == Action.NONE


def test_client_rule_matches_by_cidr():
    e = eng("||ads.example^$client=10.0.0.0/24")
    assert e.match("ads.example", client="10.0.0.77").action == Action.BLOCK
    assert e.match("ads.example", client="10.0.1.77").action == Action.NONE


def test_client_rule_matches_by_client_name():
    e = eng("||ads.example^$client=kids-tablet")
    assert e.match("ads.example", client="10.0.0.5",
                   client_names=frozenset({"kids-tablet"})).action == Action.BLOCK
    assert e.match("ads.example", client="10.0.0.5",
                   client_names=frozenset({"office"})).action == Action.NONE


def test_client_rule_accepts_quoted_names():
    e = eng("||ads.example^$client='Marys laptop'")
    assert e.match("ads.example", client_names=frozenset({"Marys laptop"})).action == Action.BLOCK


def test_client_exclusion_blocks_everyone_else():
    e = eng("||ads.example^$client=~10.0.0.5")
    assert e.match("ads.example", client="10.0.0.9").action == Action.BLOCK
    assert e.match("ads.example", client="10.0.0.5").action == Action.NONE


def test_client_exclusion_by_cidr():
    e = eng("||ads.example^$client=~10.0.0.0/24")
    assert e.match("ads.example", client="192.168.1.1").action == Action.BLOCK
    assert e.match("ads.example", client="10.0.0.1").action == Action.NONE


def test_client_include_and_exclude_together():
    e = eng("||ads.example^$client=10.0.0.0/8|~10.1.2.3")
    assert e.match("ads.example", client="10.5.5.5").action == Action.BLOCK
    assert e.match("ads.example", client="10.1.2.3").action == Action.NONE
    assert e.match("ads.example", client="192.168.0.1").action == Action.NONE


def test_client_allow_rule_exempts_only_that_client():
    e = eng("||ads.example^\n@@||ads.example^$client=10.0.0.5")
    assert e.match("ads.example", client="10.0.0.5").action == Action.ALLOW
    assert e.match("ads.example", client="10.0.0.6").action == Action.BLOCK


# --- $dnstype ---
def test_dnstype_restriction():
    e = eng("||ads.example^$dnstype=AAAA")
    assert e.match("ads.example", qtype=Type.AAAA).action == Action.BLOCK
    assert e.match("ads.example", qtype=Type.A).action == Action.NONE


def test_dnstype_exclusion_is_not_inverted():
    """`~A` means every type *except* A. Stripping the tilde produced exactly
    the opposite behaviour, blocking only the type the author exempted."""
    e = eng("||ads.example^$dnstype=~A")
    assert e.match("ads.example", qtype=Type.A).action == Action.NONE
    assert e.match("ads.example", qtype=Type.AAAA).action == Action.BLOCK
    assert e.match("ads.example", qtype=Type.HTTPS).action == Action.BLOCK


def test_dnstype_include_and_exclude_together():
    e = eng("||ads.example^$dnstype=A|AAAA|~AAAA")
    assert e.match("ads.example", qtype=Type.A).action == Action.BLOCK
    assert e.match("ads.example", qtype=Type.AAAA).action == Action.NONE


def test_unknown_dnstype_value_is_ignored_not_fatal():
    e = eng("||ads.example^$dnstype=NOTATYPE")
    assert e.match("ads.example", qtype=Type.A).action == Action.BLOCK


# --- $ctag ---
def test_ctag_restriction():
    e = eng("||ads.example^$ctag=kids")
    assert e.match("ads.example", ctags=frozenset({"kids"})).action == Action.BLOCK
    assert e.match("ads.example", ctags=frozenset({"adults"})).action == Action.NONE


def test_ctag_exclusion():
    e = eng("||ads.example^$ctag=~adults")
    assert e.match("ads.example", ctags=frozenset({"kids"})).action == Action.BLOCK
    assert e.match("ads.example", ctags=frozenset({"adults"})).action == Action.NONE


# --- the storage optimisation must not swallow modifiers ---
@pytest.mark.parametrize("rule", [
    "||ads.example^$dnstype=~A",
    "||ads.example^$ctag=~kids",
    "||ads.example^$client=~10.0.0.1",
])
def test_exclusion_rules_are_not_treated_as_plain(rule):
    """Modifier-free rules take a compact path that drops modifiers. A rule
    carrying only an *exclusion* must not be mistaken for one of them."""
    from dnsguard.filter.engine import _is_plain
    compiled = compile_rules(rule, "list")
    assert compiled and not _is_plain(compiled[0])
    e = FilterEngine.compile(compiled)
    assert len(e.block_table) == 0, "must not land in the compact table"
    assert e.block_suffix, "must be kept as a full Rule"


# --- the pipeline actually supplies the identity (the original defect) ---
@pytest.mark.asyncio
async def test_pipeline_passes_client_identity_to_the_matcher():
    """The matcher supported $client all along; the pipeline never told it who
    was asking, so every such rule was inert end to end."""
    from dnsguard.cache import Cache
    from dnsguard.config import Config
    from dnsguard.engine import Pipeline
    from dnsguard.stats import Counters
    from dnsguard.wire import Class, Message, Question
    from dnsguard.wire.name import Name

    cfg = Config.model_validate({"filtering": {"enabled": True}})

    class NoUpstream:
        async def resolve(self, *a, **k):
            raise AssertionError("must not reach the upstream when blocked")

    pipe = Pipeline(filter_engine=eng("||ads.example^$client=10.0.0.5"),
                    cache=Cache(enabled=False), forwarder=NoUpstream(),
                    counters=Counters(), config=cfg)

    def query():
        q = Message(id=1)
        q.set_flag(0x0100, True)
        q.questions.append(Question(Name.from_text("ads.example"), Type.A, Class.IN))
        return q

    # blocked answers are synthesised locally, so the sinkhole address is the
    # observable proof the rule fired for this client
    resp = await pipe.resolve(query(), "10.0.0.5")
    assert resp.answers and resp.answers[0].rdata.to_text() == "0.0.0.0"

    # a client the rule does not name must instead go out to resolution
    class Upstream:
        called = False
        async def resolve(self, *a, **k):
            Upstream.called = True
            raise TimeoutError("no network in tests")
    pipe.forwarder = Upstream()
    resp = await pipe.resolve(query(), "10.0.0.6")
    assert Upstream.called, "an unscoped client should have gone to resolution"
    assert not (resp.answers and resp.answers[0].rdata.to_text() == "0.0.0.0")
