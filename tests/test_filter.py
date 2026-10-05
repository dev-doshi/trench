"""Filtering engine: parser dialects, matcher precedence, rewrite, CNAME-cloak, RPZ."""
from __future__ import annotations

import pytest

from trench.filter import Action, FilterEngine
from trench.filter.cnamecloak import inspect
from trench.filter.parser import detect_format, parse_line
from trench.filter.rpz import parse_rpz
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


def eng(*lines: str) -> FilterEngine:
    rules = []
    for ln in lines:
        r = parse_line(ln, "test")
        if r:
            rules.append(r)
    return FilterEngine.compile(rules)


# --- parser ---
def test_parse_dialects():
    assert parse_line("0.0.0.0 ads.com").suffix == "ads.com"
    assert parse_line("127.0.0.1 tracker.net").suffix == "tracker.net"
    assert parse_line("ads.example").suffix == "ads.example"
    assert parse_line("||doubleclick.net^").suffix == "doubleclick.net"
    assert parse_line("@@||good.com^").block is False
    assert parse_line("address=/dnsmasq.block/0.0.0.0").suffix == "dnsmasq.block"
    assert parse_line("# comment") is None
    assert parse_line("! adblock comment") is None
    r = parse_line("/^ad[0-9]+\\./")
    assert r and r.regex is not None


def test_detect_format():
    assert detect_format("||a^\n||b^\n@@||c^") == "adblock"
    assert detect_format("0.0.0.0 a.com\n0.0.0.0 b.com") == "hosts"
    assert detect_format("a.com\nb.com") == "domain"


# --- matcher precedence ---
def test_block_and_subdomain():
    e = eng("||ads.com^")
    assert e.match("ads.com").action == Action.BLOCK
    assert e.match("x.y.ads.com").action == Action.BLOCK
    assert e.match("notads.com").action == Action.NONE


def test_exception_beats_block():
    e = eng("||ads.com^", "@@||good.ads.com^")
    assert e.match("good.ads.com").action == Action.ALLOW
    assert e.match("bad.ads.com").action == Action.BLOCK


def test_important_block_beats_exception():
    e = eng("||ads.com^$important", "@@||ads.com^")
    assert e.match("ads.com").action == Action.BLOCK


def test_dnstype_restriction():
    e = eng("||track.com^$dnstype=AAAA")
    assert e.match("track.com", Type.AAAA).action == Action.BLOCK
    assert e.match("track.com", Type.A).action == Action.NONE


def test_denyallow():
    e = eng("||cdn.com^$denyallow=safe.cdn.com")
    assert e.match("x.cdn.com").action == Action.BLOCK
    assert e.match("safe.cdn.com").action == Action.NONE


def test_regex_rule():
    e = eng("/^ads?[0-9]*\\./")
    assert e.match("ad1.example.com").action == Action.BLOCK
    assert e.match("ads.example.com").action == Action.BLOCK
    assert e.match("news.example.com").action == Action.NONE


def test_badfilter_disables():
    e = eng("||ads.com^", "||ads.com^$badfilter")
    assert e.match("ads.com").action == Action.NONE


def test_dnsrewrite_ip():
    e = eng("||rewrite.com^$dnsrewrite=1.2.3.4")
    d = e.match("rewrite.com", Type.A)
    assert d.action == Action.REWRITE
    assert d.rdata.to_text() == "1.2.3.4"


def test_dnsrewrite_refused():
    e = eng("||nope.com^$dnsrewrite=REFUSED")
    d = e.match("nope.com")
    assert d.action == Action.REWRITE and d.rcode == Rcode.REFUSED


def test_most_specific_wins():
    e = eng("||example.com^", "@@||safe.example.com^")
    assert e.match("safe.example.com").action == Action.ALLOW
    assert e.match("ads.example.com").action == Action.BLOCK


# --- CNAME cloak ---
def test_cname_cloak():
    e = eng("||tracker.evil^")
    resp = Message(id=1)
    resp.answers.append(RR(Name.from_text("www.shop.com"), Type.CNAME, Class.IN, 300,
                           R.CNAME(Name.from_text("tracker.evil"))))
    d = inspect(e, resp, Type.A)
    assert d is not None and d.blocked


def test_cname_cloak_clean():
    e = eng("||tracker.evil^")
    resp = Message(id=1)
    resp.answers.append(RR(Name.from_text("www.shop.com"), Type.CNAME, Class.IN, 300,
                           R.CNAME(Name.from_text("cdn.good.com"))))
    assert inspect(e, resp, Type.A) is None


# --- RPZ ---
def test_rpz_parse():
    rpz = """$ORIGIN rpz.example.
@ IN SOA ns hostmaster 1 1h 15m 1w 1h
bad.domain  CNAME .
sink.domain A 0.0.0.0
ok.domain   CNAME rpz-passthru.
"""
    rules = parse_rpz(rpz, "rpz")
    e = FilterEngine.compile(rules)
    assert e.match("bad.domain").action in (Action.BLOCK, Action.REWRITE)
    assert e.match("sink.domain").action == Action.BLOCK
    assert e.match("ok.domain").action == Action.ALLOW


def test_badfilter_works_across_sources_when_compiled_as_a_stream():
    """A $badfilter in one list disables a rule in another.

    The corpus is compiled in one pass now — no rule is held in memory waiting
    for a second look — so the set of disabled patterns is worked out from the
    raw text first. If that prepass misses a source, a $badfilter silently stops
    disabling anything, which looks exactly like it working.
    """
    from trench.filter import badfilter_keys, iter_rules

    first = "||ads.com^\n||trackers.example^"
    second = "! a later list retracts one of them\n||ads.com^$badfilter"
    texts = [("first", first), ("second", second)]

    keys = badfilter_keys(texts)
    rules = (r for src, text in texts for r in iter_rules(text, src))
    e = FilterEngine.compile(rules, badfilter_keys=keys)

    assert e.match("ads.com").action == Action.NONE
    assert e.match("trackers.example").action == Action.BLOCK


def test_compiling_from_an_iterator_matches_compiling_from_a_list():
    lines = [f"||a{i}.example^" for i in range(50)]
    lines += ["|exact.example|", "/^re[0-9]+\\.example$/", "||m.example^$important"]
    text = "\n".join(lines)

    from trench.filter import compile_rules, iter_rules
    listed = FilterEngine.compile(compile_rules(text, "t"))
    streamed = FilterEngine.compile(iter_rules(text, "t"))

    assert streamed.size == listed.size
    for name in ("a7.example", "exact.example", "re42.example", "m.example",
                 "nothing.example"):
        assert streamed.match(name).action == listed.match(name).action, name


# --- dialect detection and the pattern forms ---
def test_detect_format_reads_the_first_lines():
    assert detect_format("||ads.example^\n@@||ok.example^\n") == "adblock"
    assert detect_format("0.0.0.0 ads.example\n127.0.0.1 tracker.example\n") == "hosts"
    assert detect_format("ads.example\ntracker.example\n") == "domain"
    assert detect_format("") == "domain"
    assert detect_format("# only a comment\n! and another\n") == "domain"


def test_detect_format_only_looks_at_the_head():
    text = "\n".join([f"ads{i}.example" for i in range(300)] + ["||late.example^"])
    assert detect_format(text) == "domain"


def test_a_regex_rule_is_compiled():
    rule = parse_line("/^ads[0-9]+\\.example\\.com$/", "list")
    assert rule is not None and rule.regex is not None
    assert rule.regex.match("ads12.example.com")
    assert not rule.regex.match("safe.example.com")


def test_a_regex_with_nested_quantifiers_is_refused(caplog):
    """A list-supplied pattern that can blow up is not compiled at all."""
    assert parse_line("/(a+)+$/", "list") is None
    assert any("nested quantifiers" in r.getMessage() for r in caplog.records)


def test_an_over_long_regex_is_refused(caplog):
    assert parse_line("/" + ("a" * 600) + "/", "list") is None
    assert any("over-long regex" in r.getMessage() for r in caplog.records)


def test_an_uncompilable_regex_is_dropped():
    assert parse_line("/[unclosed/", "list") is None


def test_a_wildcard_in_the_middle_becomes_a_regex():
    rule = parse_line("||ads.*.example.com^", "list")
    assert rule is not None and rule.regex is not None
    assert rule.regex.match("ads.eu.example.com")
    assert not rule.regex.match("ads.example.com")


def test_a_leading_wildcard_is_a_suffix_rule():
    rule = parse_line("*.ads.example.com", "list")
    assert rule is not None and rule.suffix == "ads.example.com"


def test_an_exact_anchor_matches_only_that_name():
    rule = parse_line("|ads.example.com|", "list")
    assert rule is not None and rule.exact == "ads.example.com"
    assert rule.suffix is None


@pytest.mark.parametrize("line", ["", "   ", "# a comment", "! another comment"])
def test_blank_and_comment_lines_are_skipped(line):
    assert parse_line(line, "list") is None


@pytest.mark.parametrize("name", ["localhost", "broadcasthost", "ip6-localhost",
                                  "localhost.localdomain"])
def test_the_hosts_boilerplate_is_ignored(name):
    assert parse_line(f"127.0.0.1 {name}", "list") is None


def test_a_hosts_line_takes_only_the_first_domain():
    rule = parse_line("0.0.0.0 ads.example.com tracker.example.com", "list")
    assert rule is not None and rule.suffix == "ads.example.com"


def test_a_single_label_is_a_valid_rule():
    """Blocking a whole TLD (`zip`, `mov`) is a real thing operators do, and
    requiring two labels silently dropped every such entry."""
    assert parse_line("zip", "list").suffix == "zip"
    assert parse_line("||mov^", "list").suffix == "mov"


@pytest.mark.parametrize("line", ["a..b", "a/b", "exa%mple.com"])
def test_a_first_token_that_is_not_a_domain_is_dropped(line):
    """A bare line is read as `domain [more...]`, so only the first token has to
    be a name — and it has to actually be one."""
    assert parse_line(line, "list") is None


def test_a_bare_line_takes_only_its_first_token():
    assert parse_line("zip and some trailing words", "list").suffix == "zip"


def test_the_dnsmasq_address_form():
    rule = parse_line("address=/ads.example.com/0.0.0.0", "list")
    assert rule is not None and rule.suffix == "ads.example.com"
    assert parse_line("address=//0.0.0.0", "list") is None


def test_an_ipv6_hosts_line_is_recognised():
    assert parse_line(":: ads.example.com", "list").suffix == "ads.example.com"


def test_an_exception_rule_is_not_a_block():
    rule = parse_line("@@||ok.example.com^", "list")
    assert rule is not None and rule.block is False


def test_a_pattern_that_resolves_to_nothing_is_dropped():
    assert parse_line("||^$important", "list") is None


def test_modifiers_with_empty_segments_are_tolerated():
    rule = parse_line("||ads.example.com^$important,,badfilter", "list")
    assert rule is not None and rule.important and rule.badfilter


def test_an_unknown_modifier_is_ignored():
    rule = parse_line("||ads.example.com^$third-party,app=chrome", "list")
    assert rule is not None and rule.suffix == "ads.example.com"


def test_a_negated_modifier_value_with_nothing_after_it_is_skipped():
    from trench.filter.parser import _split_negated
    assert _split_negated("a|~|b") == (["a", "b"], [])
    assert _split_negated("") == ([], [])
    assert _split_negated("~a|b") == (["b"], ["a"])


def test_an_unknown_dnstype_is_ignored_not_fatal():
    rule = parse_line("||ads.example.com^$dnstype=A|NOTATYPE", "list")
    assert rule is not None
    from trench.wire.rrtypes import Type
    assert rule.dnstypes == frozenset({int(Type.A)})


def test_iter_badfilter_finds_only_the_disabling_rules():
    from trench.filter.parser import iter_badfilter
    text = ("||ads.example.com^\n"
            "||ads.example.com^$badfilter\n"
            "||other.example.com^\n")
    got = list(iter_badfilter(text, "list"))
    assert len(got) == 1 and got[0].badfilter is True


def test_iter_badfilter_ignores_a_line_that_only_mentions_the_word():
    from trench.filter.parser import iter_badfilter
    assert list(iter_badfilter("# $badfilter is a modifier\n", "list")) == []


def test_bounded_repeats_in_sequence_are_refused_without_running_them(caplog):
    """`a{0,16}` six times is 17**6 tries per position. The structural check
    counted only unbounded repeats, so this reached the timing probe — which
    measures a pattern only after it returns, and it did not return."""
    import time
    t = time.perf_counter()
    assert parse_line("/" + "a{0,16}" * 6 + "b/", "list") is None
    assert time.perf_counter() - t < 1.0
    assert any("too many repeats" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("pattern", [
    "^ad[0-9]{1,3}\\.[a-z]{2,6}$",
    "^(.+[_.-])?adse?rv(er?|ice)?s?[0-9]*[_.-]",   # a real list's shape
    "^track(er|ing)?[0-9]{0,3}\\.",
])
def test_ordinary_list_regexes_are_still_accepted(pattern):
    rule = parse_line(f"/{pattern}/", "list")
    assert rule is not None and rule.regex is not None


@pytest.mark.parametrize("pattern", ["a*a*a{0,16}b", ".*a{0,16}a{0,16}b", "a?" * 24 + "b"])
def test_repeats_that_multiply_past_the_budget_are_refused(pattern):
    assert parse_line(f"/{pattern}/", "list") is None
