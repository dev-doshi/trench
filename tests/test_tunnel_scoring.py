"""The DNS-tunnelling detector's scoring and its bounded state.

`score` is a sum of independent signals, and the existing suite only checks that
an obvious tunnel scores above a benign name. Each signal is worth pinning on
its own — a detector nobody can reason about gets its threshold tuned by
guesswork — and so is the sweep, which is the only thing between a host cycling
second-level domains and a deque per name until the box dies.
"""
from __future__ import annotations

import base64

import pytest

from trench.filter.tunnel import (
    TunnelDetector,
    TunnelResult,
    _entropy,
    _hexish_ratio,
    _registrable,
)
from trench.wire import Type

_NULL = 10


# --- helpers ---
def test_entropy_of_an_empty_string_is_zero():
    assert _entropy("") == 0.0


def test_entropy_rises_with_variety():
    assert _entropy("aaaaaaaa") == 0.0
    assert _entropy("ab") == 1.0
    assert _entropy("abcd") == 2.0
    assert _entropy("abcdefgh") > _entropy("aabbccdd")


@pytest.mark.parametrize("qname,reg", [
    ("www.example.com", "example.com"),
    ("a.b.c.example.co", "example.co"),
    ("example.com.", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("localhost", "localhost"),
    ("", ""),
])
def test_the_registrable_domain(qname, reg):
    assert _registrable(qname) == reg


def test_the_encoded_character_ratio():
    assert _hexish_ratio("") == 0.0
    assert _hexish_ratio("deadbeef") == 1.0
    assert _hexish_ratio("abc-123=") == 1.0
    assert _hexish_ratio("ABC") == 0.0        # upper case is not in the alphabet
    assert _hexish_ratio("ab_cd") == 0.8


# --- score: the shapes that score zero ---
@pytest.mark.parametrize("qname", ["com", "localhost", ""])
def test_a_name_with_fewer_than_two_labels_scores_nothing(qname):
    assert TunnelDetector().score(qname, int(Type.A)) == 0.0


def test_a_bare_registrable_domain_scores_nothing():
    """There is no subdomain to carry a payload."""
    assert TunnelDetector().score("example.com", int(Type.A)) == 0.0


def test_an_ordinary_name_scores_low():
    d = TunnelDetector()
    assert d.score("www.example.com", int(Type.A)) < 0.2
    assert d.score("mail.google.com", int(Type.A)) < 0.2


# --- score: each signal on its own ---
def test_a_very_long_label_contributes():
    d = TunnelDetector()
    short = d.score("abc.example.com", int(Type.A), client="a")
    long_label = d.score("a" * 40 + ".example.com", int(Type.A), client="b")
    assert long_label > short


def test_a_very_long_name_contributes():
    d = TunnelDetector()
    chunks = ".".join("abcdefghij" for _ in range(10))
    assert d.score(f"{chunks}.example.com", int(Type.A), client="a") > 0.2


def test_high_entropy_contributes():
    d = TunnelDetector()
    payload = base64.b32encode(bytes(range(40))).decode().lower().rstrip("=")
    encoded = d.score(f"{payload}.example.com", int(Type.A), client="a")
    repeated = d.score(f"{'a' * len(payload)}.example.com", int(Type.A), client="b")
    assert encoded > repeated


def test_a_null_or_txt_query_with_a_long_payload_contributes():
    d = TunnelDetector()
    sub = "abcdefghijklmnopqrstuvwxyz012345"
    a = d.score(f"{sub}.example.com", int(Type.A), client="a")
    txt = d.score(f"{sub}.example.com", int(Type.TXT), client="b")
    null = d.score(f"{sub}.example.com", _NULL, client="c")
    assert txt > a and null > a
    assert txt == null


def test_a_short_payload_does_not_earn_the_record_type_bonus():
    d = TunnelDetector()
    a = d.score("abc.example.com", int(Type.A), client="a")
    txt = d.score("abc.example.com", int(Type.TXT), client="b")
    assert txt == a


def test_many_labels_contribute():
    d = TunnelDetector()
    flat = d.score("abcdef.example.com", int(Type.A), client="a")
    deep = d.score("a.b.c.d.e.f.example.com", int(Type.A), client="b")
    assert deep > flat


def test_the_score_is_capped_at_one():
    d = TunnelDetector()
    payload = base64.b32encode(bytes(range(200))).decode().lower().rstrip("=")
    labels = ".".join(payload[i:i + 60] for i in range(0, len(payload), 60))
    assert d.score(f"{labels}.example.com", int(Type.TXT), client="a") <= 1.0


# --- volumetric ---
def test_volume_to_one_domain_adds_to_the_score():
    d = TunnelDetector(rate_limit=5, window=60)
    for _ in range(4):
        d.score("a.example.com", int(Type.A), client="10.0.0.1", now=1000.0)
    below = d.score("a.example.com", int(Type.A), client="10.0.0.2", now=1000.0)
    for _ in range(20):
        d.score("a.example.com", int(Type.A), client="10.0.0.1", now=1000.0)
    above = d.score("a.example.com", int(Type.A), client="10.0.0.1", now=1000.0)
    assert above > below


def test_the_volumetric_bonus_is_capped():
    d = TunnelDetector(rate_limit=2, window=60)
    for _ in range(500):
        d.score("a.example.com", int(Type.A), client="10.0.0.1", now=1000.0)
    assert d._volumetric("10.0.0.1", "example.com", 1000.0) <= 0.4


def test_the_window_slides():
    d = TunnelDetector(rate_limit=3, window=60)
    for _ in range(10):
        d._volumetric("10.0.0.1", "example.com", 1000.0)
    assert d._volumetric("10.0.0.1", "example.com", 1000.0) > 0
    # Far enough ahead that every recorded query has aged out.
    assert d._volumetric("10.0.0.1", "example.com", 2000.0) == 0.0


def test_the_rate_limit_is_divided_across_workers():
    """Each worker sees only its share of a client's traffic, so an unscaled
    100 means 100xN in aggregate before anything notices."""
    assert TunnelDetector(rate_limit=100, workers=4).rate_limit == 25
    assert TunnelDetector(rate_limit=100, workers=1).rate_limit == 100
    assert TunnelDetector(rate_limit=2, workers=8).rate_limit == 2, "never below two"
    assert TunnelDetector(rate_limit=100, workers=0).rate_limit == 100


def test_clients_are_tracked_separately():
    d = TunnelDetector(rate_limit=3, window=60)
    for _ in range(10):
        d._volumetric("10.0.0.1", "example.com", 1000.0)
    assert d._volumetric("10.0.0.2", "example.com", 1000.0) == 0.0


def test_domains_are_tracked_separately():
    d = TunnelDetector(rate_limit=3, window=60)
    for _ in range(10):
        d._volumetric("10.0.0.1", "example.com", 1000.0)
    assert d._volumetric("10.0.0.1", "other.com", 1000.0) == 0.0


# --- the bounded table ---
def test_stale_entries_are_swept_rather_than_retained():
    """One host cycling distinct second-level domains retained a deque per name
    until the box died."""
    d = TunnelDetector(window=60)
    d.max_tracked = 50
    for i in range(120):
        d._volumetric("10.0.0.1", f"d{i}.com", 1000.0)
    # The table never grows past the ceiling plus the entries added since the
    # last sweep; without the sweep it would hold all 120.
    assert len(d._seen) < 120
    # Once every recorded query has aged out, the next insert clears the lot.
    d._volumetric("10.0.0.1", "fresh.com", 5000.0)
    assert len(d._seen) < 120


def test_a_table_that_cannot_be_swept_is_cleared_outright():
    d = TunnelDetector(window=60)
    d.max_tracked = 10
    for i in range(10):
        d._volumetric("10.0.0.1", f"d{i}.com", 1000.0)
    d._sweep(1000.0)              # nothing has aged out, so it clears instead
    assert d._seen == {}


def test_the_sweep_keeps_entries_still_inside_the_window():
    d = TunnelDetector(window=60)
    d._volumetric("10.0.0.1", "old.com", 1000.0)
    d._volumetric("10.0.0.1", "new.com", 1090.0)
    d._sweep(1100.0)
    assert ("10.0.0.1", "new.com") in d._seen
    assert ("10.0.0.1", "old.com") not in d._seen


# --- inspect ---
def test_inspect_reports_a_verdict_with_the_rounded_score():
    d = TunnelDetector(threshold=0.9)
    result = d.inspect("www.example.com", int(Type.A))
    assert isinstance(result, TunnelResult)
    assert result.suspicious is False and result.reason == ""
    assert result.score == round(result.score, 3)


def test_inspect_explains_itself_when_it_flags():
    d = TunnelDetector(threshold=0.01)
    result = d.inspect("a" * 45 + ".example.com", int(Type.TXT), client="10.0.0.1")
    assert result.suspicious is True
    assert "DNS tunneling/exfil" in result.reason
    assert f"{result.score:.2f}" in result.reason


def test_the_threshold_decides():
    name = "a" * 45 + ".example.com"
    lenient = TunnelDetector(threshold=0.99).inspect(name, int(Type.TXT))
    strict = TunnelDetector(threshold=0.01).inspect(name, int(Type.TXT))
    assert lenient.suspicious is False and strict.suspicious is True
    assert lenient.score == strict.score
