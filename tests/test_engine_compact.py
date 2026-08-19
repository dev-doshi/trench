"""Compact block table: modifier-free rules are stored as strings, but must
behave exactly like the Rule-backed path (precedence, specificity, removal).
"""
from __future__ import annotations

from dnsguard.filter import Action, FilterEngine, compile_rules
from dnsguard.filter.engine import _is_plain
from dnsguard.filter.rule import Rule
from dnsguard.wire.rrtypes import Type


def eng(text: str, source: str = "list") -> FilterEngine:
    return FilterEngine.compile(compile_rules(text, source))


# --- routing: plain vs modifier-carrying ---
def test_plain_rules_use_compact_table():
    e = eng("||ads.example^\n0.0.0.0 tracker.example\nplain.example\n")
    assert len(e.block_table) == 3                 # imported rules go to shared memory
    assert not e.block_plain and not e.block_suffix   # nothing needed a Rule object
    assert e.size == 3


def test_modifier_rules_keep_rule_objects():
    e = eng("||a.example^$important\n||b.example^$dnstype=AAAA\n"
            "||c.example^$denyallow=ok.c.example\n||d.example^\n")
    assert "d.example" in e.block_table            # only the bare one is compact
    assert len(e.block_table) == 1
    assert set(e.block_suffix) == {"a.example", "b.example", "c.example"}


def test_is_plain_predicate():
    assert _is_plain(Rule(raw="x", block=True, suffix="x"))
    assert not _is_plain(Rule(raw="x", block=True, suffix="x", important=True))
    assert not _is_plain(Rule(raw="x", block=False, suffix="x"))
    assert not _is_plain(Rule(raw="x", block=True, suffix="x", dnstypes=frozenset({1})))


def test_operator_rules_stay_enumerable():
    """The shared table cannot list its keys back, so anything the API has to
    show the operator must not go into it."""
    e = FilterEngine.compile(compile_rules("||mine.example^", "denylist")
                             + compile_rules("||ads.example^", "hagezi"))
    assert set(e.block_plain) == {"mine.example"}
    assert "ads.example" in e.block_table
    deny, _ = e.custom_rules()
    assert deny == ["mine.example"]


def test_source_counts_cover_both_stores():
    e = FilterEngine.compile(compile_rules("||a.example^\n||b.example^", "hagezi")
                             + compile_rules("||mine.example^", "denylist"))
    assert e.plain_source_counts() == {"hagezi": 2, "denylist": 1}


# --- matching parity ---
def test_compact_rule_blocks_domain_and_subdomains():
    e = eng("||ads.example^")
    assert e.match("ads.example").action == Action.BLOCK
    assert e.match("deep.sub.ads.example").action == Action.BLOCK
    assert e.match("notads.example").action == Action.NONE


def test_materialised_rule_carries_source_and_text():
    e = eng("||ads.example^", source="hagezi-ultimate")
    d = e.match("x.ads.example")
    assert d.action == Action.BLOCK
    assert d.source == "hagezi-ultimate"
    assert d.rule == "ads.example"                 # the matched suffix, not the qname
    assert "ads.example" in d.reason


def test_exception_overrides_compact_block():
    e = eng("||ads.example^\n@@||ok.ads.example^")
    assert e.match("ads.example").action == Action.BLOCK
    assert e.match("ok.ads.example").action == Action.ALLOW


def test_important_block_beats_plain_exception():
    e = eng("||ads.example^$important\n@@||ads.example^")
    assert e.match("ads.example").action == Action.BLOCK


def test_most_specific_wins_across_tables():
    # compact broad rule + Rule-backed specific rule -> the specific one is reported
    # (modifier rules keep their raw source line; compact ones report the suffix)
    e = eng("||example^\n||deep.sub.example^$important")
    d = e.match("deep.sub.example")
    assert d.action == Action.BLOCK and "deep.sub.example" in d.rule
    # a name only the broad compact rule covers still reports the compact suffix
    assert e.match("other.example").rule == "example"


def test_qtype_gate_still_applies_alongside_compact():
    e = eng("||only-aaaa.example^$dnstype=AAAA\n||both.example^")
    assert e.match("only-aaaa.example", Type.A).action == Action.NONE
    assert e.match("only-aaaa.example", Type.AAAA).action == Action.BLOCK
    assert e.match("both.example", Type.A).action == Action.BLOCK


def test_duplicate_across_lists_keeps_first_source():
    rules = compile_rules("||dup.example^", "list-a") + compile_rules("||dup.example^", "list-b")
    e = FilterEngine.compile(rules)
    assert e.size == 1
    assert e.match("dup.example").source == "list-a"


# --- runtime edits ---
def test_remove_clears_compact_entry():
    e = eng("||ads.example^")
    assert e.match("ads.example").action == Action.BLOCK
    e.remove_rule("ads.example")
    assert e.match("ads.example").action == Action.NONE
    assert e.size == 0


def test_add_deny_then_remove_roundtrip():
    e = eng("")
    e.add_deny("bad.example")
    assert e.match("sub.bad.example").action == Action.BLOCK
    e.remove_rule("bad.example")
    assert e.match("bad.example").action == Action.NONE


# --- API surface: operator rules only ---
def test_custom_rules_excludes_imported_lists():
    e = eng("||imported-one.example^\n||imported-two.example^", source="hagezi")
    e.add_deny("blocked-by-admin.example")
    e.add_allow("allowed-by-admin.example")
    deny, allow = e.custom_rules()
    assert deny == ["blocked-by-admin.example"]
    assert allow == ["allowed-by-admin.example"]
    assert e.size == 3                              # imported still counted + matched
    assert e.match("imported-one.example").action == Action.BLOCK


def test_custom_rules_includes_config_lists():
    e = FilterEngine.compile([
        Rule(raw="cfg-deny.example", block=True, suffix="cfg-deny.example", source="denylist"),
        Rule(raw="cfg-allow.example", block=False, important=True,
             suffix="cfg-allow.example", source="allowlist"),
        *compile_rules("||gravity.example^", "hagezi"),
    ])
    deny, allow = e.custom_rules()
    assert deny == ["cfg-deny.example"] and allow == ["cfg-allow.example"]


# --- the reason this exists: memory ---
def test_compact_table_is_substantially_smaller():
    import tracemalloc
    domains = [f"ad{i}.tracker{i % 500}.example" for i in range(40_000)]
    text = "\n".join("||" + d + "^" for d in domains)
    rules = compile_rules(text, "bench")

    tracemalloc.start()
    compact = FilterEngine.compile(rules)
    compact_mem, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # emulate the old layout: a Rule object + list wrapper per domain
    tracemalloc.start()
    legacy: dict[str, list[Rule]] = {}
    for r in rules:
        legacy.setdefault(r.suffix, []).append(r)
    legacy_mem, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert compact.size == len(domains)
    assert compact_mem * 2 < legacy_mem, (compact_mem, legacy_mem)
