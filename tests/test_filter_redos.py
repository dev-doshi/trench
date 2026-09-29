"""List-supplied patterns cannot stall the resolver.

A rule list is remote input and a rule's matcher runs against an attacker-chosen
query name, on the loop the listeners share. One pathological line plus one
query used to freeze DNS for that worker.
"""
from __future__ import annotations

import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from trench.filter.parser import Glob, parse_line

HOSTILE = "a" * 252 + "!"


@pytest.mark.parametrize("line", [
    "/^(a|aa)+$/",            # overlapping alternation: Fibonacci backtracking
    "/((a+))+$/",             # nesting the old textual check could not see
    "/(a*)*b/",
    "/^(\\w+\\.)+x$/",
    "/^a.*a.*a.*a.*b$/",      # four unbounded loops: polynomial, degree 4
    "/(a)\\1/",               # backreference
    "/(?=a)b/",               # lookaround
])
def test_pathological_regex_rules_are_refused(line):
    assert parse_line(line) is None or parse_line(line).regex is None


@pytest.mark.parametrize("line, hit, miss", [
    ("/^ad[0-9]*\\.example\\.com$/", "ad12.example.com", "adx.example.com"),
    ("/(^|\\.)doubleclick\\.net$/", "g.doubleclick.net", "notdoubleclick.net"),
    ("/^(ads|track)\\./", "ads.x.org", "adsx.org"),
    ("/^.*tracker.*$/", "my.tracker.io", "tracer.io"),
])
def test_ordinary_regex_rules_still_work(line, hit, miss):
    rule = parse_line(line)
    assert rule.regex.search(hit) and not rule.regex.search(miss)


def test_a_many_star_wildcard_rule_is_linear():
    rule = parse_line("||a*a*a*a*a*a*a*a*a*b^")
    assert isinstance(rule.regex, Glob)
    t = time.perf_counter()
    assert not rule.regex.search("a" * 250 + ".c")
    assert time.perf_counter() - t < 0.05
    assert rule.regex.search("aaaaaaaaab")


def _glob_to_re(glob: str):
    import re
    return re.compile("^" + re.escape(glob).replace(r"\*", ".*") + "$", re.I)


@given(st.text("ab.*", min_size=1, max_size=8), st.text("abAB.", max_size=12))
def test_glob_agrees_with_the_regex_it_replaced(glob, name):
    assert Glob(glob).search(name) == bool(_glob_to_re(glob).search(name))
