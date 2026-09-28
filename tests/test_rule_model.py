"""The Rule model, operator allow/deny compilation, and $dnsrewrite parsing.

`$dnsrewrite` reached the suite only through the two shapes the rule-modifier
tests use, so most of its dialect — explicit `rcode;type;value` triples, MX and
TXT targets, SERVFAIL — was parsed by no test at all.
"""
from __future__ import annotations

import re

import pytest

from trench.filter.rule import (
    Rewrite,
    Rule,
    _is_ipv4,
    _is_ipv6,
    _rdata_for,
    operator_rules,
    parse_dnsrewrite,
)
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode, Type


# --- Rule.key (badfilter identity) ---
def test_key_distinguishes_pattern_block_and_dnstype():
    a = Rule(raw="||x.com^", suffix="x.com")
    b = Rule(raw="@@||x.com^", block=False, suffix="x.com")
    c = Rule(raw="||x.com^$dnstype=A", suffix="x.com", dnstypes=frozenset({Type.A}))
    assert a.key() != b.key()
    assert a.key() != c.key()
    assert a.key() == Rule(raw="other text", suffix="x.com").key()


def test_key_uses_exact_then_regex_then_empty():
    assert "x.com" in Rule(raw="|x.com|", exact="x.com").key()
    assert "ad[0-9]" in Rule(raw="/ad[0-9]/", regex=re.compile("ad[0-9]")).key()
    # No primary form at all still yields a stable key rather than raising.
    assert Rule(raw="").key() == "1||None"


# --- operator_rules ---
def test_operator_rules_shape():
    rules = operator_rules(["Good.Example.COM"], ["Bad.Example.NET"])
    allow, deny = rules[0], rules[1]
    assert allow.block is False and allow.important is True
    assert allow.suffix == "good.example.com" and allow.source == "allowlist"
    assert allow.raw == "Good.Example.COM"
    assert deny.block is True and deny.important is False
    assert deny.suffix == "bad.example.net" and deny.source == "denylist"


def test_operator_rules_ordering_puts_allows_first():
    rules = operator_rules(["a.com", "b.com"], ["c.com"])
    assert [r.suffix for r in rules] == ["a.com", "b.com", "c.com"]


def test_operator_rules_empty():
    assert operator_rules([], []) == []


# --- parse_dnsrewrite: bare rcodes ---
@pytest.mark.parametrize("text,rcode", [
    ("REFUSED", Rcode.REFUSED),
    ("NXDOMAIN", Rcode.NXDOMAIN),
    ("NOERROR", Rcode.NOERROR),
    ("SERVFAIL", Rcode.SERVFAIL),
    ("nxdomain", Rcode.NXDOMAIN),
    ("  refused  ", Rcode.REFUSED),
])
def test_dnsrewrite_bare_rcode(text, rcode):
    rw = parse_dnsrewrite(text)
    assert rw.rcode == rcode
    assert rw.rdata is None


# --- parse_dnsrewrite: inferred types ---
def test_dnsrewrite_infers_a():
    rw = parse_dnsrewrite("192.0.2.10")
    assert rw.rtype == Type.A and rw.rdata.address == "192.0.2.10"
    assert rw.rcode is None


def test_dnsrewrite_infers_aaaa():
    rw = parse_dnsrewrite("2001:db8::1")
    assert rw.rtype == Type.AAAA and rw.rdata.address == "2001:db8::1"


def test_dnsrewrite_infers_cname():
    rw = parse_dnsrewrite("real.example.org")
    assert rw.rtype == Type.CNAME
    assert rw.rdata.name.to_text(omit_root=True) == "real.example.org"


def test_dnsrewrite_out_of_range_octets_are_not_an_address():
    """`999.1.1.1` matches the digit shape but is not an A record."""
    rw = parse_dnsrewrite("999.1.1.1")
    assert rw.rtype == Type.CNAME


def test_dnsrewrite_colon_that_is_not_ipv6_is_a_cname():
    rw = parse_dnsrewrite("not:an:address")
    assert rw.rtype == Type.CNAME


# --- parse_dnsrewrite: explicit triples ---
def test_dnsrewrite_explicit_triple_a():
    rw = parse_dnsrewrite("NOERROR;A;192.0.2.1")
    assert rw.rcode == Rcode.NOERROR and rw.rtype == Type.A
    assert rw.rdata.address == "192.0.2.1"


def test_dnsrewrite_explicit_triple_aaaa_cname_txt_mx():
    assert parse_dnsrewrite("NOERROR;AAAA;::1").rdata.address == "::1"
    cn = parse_dnsrewrite("NOERROR;CNAME;target.example.org")
    assert cn.rdata.name.to_text(omit_root=True) == "target.example.org"
    txt = parse_dnsrewrite("NOERROR;TXT;hello world")
    assert txt.rtype == Type.TXT and txt.rdata.strings == [b"hello world"]
    mx = parse_dnsrewrite("NOERROR;MX;10 mail.example.org")
    assert mx.rtype == Type.MX and mx.rdata.preference == 10
    assert mx.rdata.exchange.to_text(omit_root=True) == "mail.example.org"


def test_dnsrewrite_triple_unknown_rcode_defaults_to_noerror():
    rw = parse_dnsrewrite("NOTARCODE;A;192.0.2.1")
    assert rw.rcode == Rcode.NOERROR


def test_dnsrewrite_triple_without_a_value_carries_type_only():
    rw = parse_dnsrewrite("NXDOMAIN;A")
    assert rw.rcode == Rcode.NXDOMAIN
    assert rw.rdata is None
    assert rw.rtype == Type.A


def test_dnsrewrite_triple_with_unsupported_type_has_no_rdata():
    """A known rtype Trench cannot forge: the rcode still applies, no answer."""
    rw = parse_dnsrewrite("NOERROR;SRV;0 0 443 x.example.org")
    assert rw.rdata is None
    assert rw.rtype == Type.SRV


@pytest.mark.parametrize("spec", [
    "NOERROR;NOTATYPE;x",          # unknown rtype
    "NOERROR;;x",                  # empty rtype with a value
    "a" * 300,                     # label longer than the wire allows
    "NOERROR;CNAME;" + "b" * 300,  # same, as an explicit triple
    "NOERROR;MX;notanumber mail.example.org",
])
def test_dnsrewrite_rejects_unrepresentable_specs(spec):
    with pytest.raises(ValueError):
        parse_dnsrewrite(spec)


def test_dnsrewrite_mx_without_a_preference_is_accepted():
    rw = parse_dnsrewrite("NOERROR;MX;mail.example.org")
    assert rw.rtype == Type.MX and rw.rdata.preference == 0
    assert rw.rdata.exchange.to_text(omit_root=True) == "mail.example.org"


def test_dnsrewrite_triple_is_case_and_space_insensitive():
    rw = parse_dnsrewrite(" noerror ; a ; 192.0.2.1 ")
    assert rw.rcode == Rcode.NOERROR and rw.rdata.address == "192.0.2.1"


# --- _rdata_for ---
def test_rdata_for_empty_value_and_empty_type():
    assert _rdata_for("A", "") == (None, Type.A)
    assert _rdata_for("", "") == (None, 0)


def test_rdata_for_mx_without_a_preference():
    rd, rtype = _rdata_for("MX", "mail.example.org")
    assert rtype == Type.MX
    assert rd.preference == 0
    assert rd.exchange == Name.from_text("mail.example.org")


# --- address predicates ---
@pytest.mark.parametrize("s,ok", [
    ("0.0.0.0", True), ("255.255.255.255", True), ("1.2.3.4", True),
    ("256.1.1.1", False), ("1.2.3", False), ("1.2.3.4.5", False),
    ("a.b.c.d", False), ("", False), ("1.2.3.4 ", False),
])
def test_is_ipv4(s, ok):
    assert _is_ipv4(s) is ok


@pytest.mark.parametrize("s,ok", [
    ("::", True), ("::1", True), ("2001:db8::1", True),
    ("1.2.3.4", False), ("gg::1", False), ("", False), ("2001:db8::1::2", False),
])
def test_is_ipv6(s, ok):
    assert _is_ipv6(s) is ok


def test_rewrite_defaults():
    rw = Rewrite()
    assert rw.rcode is None and rw.rdata is None and rw.rtype == 0


# --- one bad line must not take the list with it ---
def test_a_malformed_dnsrewrite_drops_only_its_own_rule():
    """Regression: `parse_dnsrewrite` raising aborted the streaming compile of
    the whole corpus, so one bad line in a subscribed list silently disarmed
    every rule after it."""
    from trench.filter import compile_rules
    text = "\n".join([
        "||first.example.com^",
        "||bad1.example.com^$dnsrewrite=NOERROR;NOTATYPE;x",
        "||bad2.example.com^$dnsrewrite=" + "a" * 300,
        "||bad3.example.com^$dnsrewrite=NOERROR;MX;nope mail.example.org",
        "||last.example.com^",
    ])
    suffixes = [r.suffix for r in compile_rules(text, "list")]
    assert suffixes == ["first.example.com", "last.example.com"]


def test_engine_still_serves_rules_after_a_malformed_line():
    from trench.filter import Action, FilterEngine, iter_rules
    text = ("||bad.example.com^$dnsrewrite=NOERROR;NOTATYPE;x\n"
            "||blocked.example.com^\n")
    eng = FilterEngine.compile(iter_rules(text, "list"))
    assert eng.match("blocked.example.com").action == Action.BLOCK
    assert eng.match("bad.example.com").action == Action.NONE
