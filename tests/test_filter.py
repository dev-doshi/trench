"""Filtering engine: parser dialects, matcher precedence, rewrite, CNAME-cloak, RPZ."""
from __future__ import annotations

from dnsguard.filter import Action, FilterEngine
from dnsguard.filter.cnamecloak import inspect
from dnsguard.filter.parser import detect_format, parse_line
from dnsguard.filter.rpz import parse_rpz
from dnsguard.wire import RR, Class, Message, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


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
    from dnsguard.filter import badfilter_keys, iter_rules

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

    from dnsguard.filter import compile_rules, iter_rules
    listed = FilterEngine.compile(compile_rules(text, "t"))
    streamed = FilterEngine.compile(iter_rules(text, "t"))

    assert streamed.size == listed.size
    for name in ("a7.example", "exact.example", "re42.example", "m.example",
                 "nothing.example"):
        assert streamed.match(name).action == listed.match(name).action, name
