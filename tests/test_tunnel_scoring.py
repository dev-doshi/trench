"""The DNS-tunnelling detector's scoring and its bounded state.

`score` is a sum of independent signals, and the existing suite only checks that
an obvious tunnel scores above a benign name. Each signal is worth pinning on
its own — a detector nobody can reason about gets its threshold tuned by
guesswork.
"""
from __future__ import annotations

import base64

import pytest

from trench.filter.tunnel import (
    TunnelDetector,
    TunnelResult,
    _entropy,
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
    short = d.score("abc.example.com", int(Type.A))
    long_label = d.score("a" * 40 + ".example.com", int(Type.A))
    assert long_label > short


def test_a_very_long_name_contributes():
    d = TunnelDetector()
    def chunks(n):
        return ".".join("abcdefghij" for _ in range(n)) + ".example.com"
    assert len(chunks(6)) < 80 <= len(chunks(10))
    assert d.score(chunks(10), int(Type.A)) > d.score(chunks(6), int(Type.A))


def test_high_entropy_contributes():
    d = TunnelDetector()
    payload = base64.b32encode(bytes(range(40))).decode().lower().rstrip("=")
    encoded = d.score(f"{payload}.example.com", int(Type.A))
    repeated = d.score(f"{'a' * len(payload)}.example.com", int(Type.A))
    assert encoded > repeated


def test_a_null_or_txt_query_with_a_long_payload_contributes():
    d = TunnelDetector()
    sub = "abcdefghijklmnopqrstuvwxyz012345"
    a = d.score(f"{sub}.example.com", int(Type.A))
    txt = d.score(f"{sub}.example.com", int(Type.TXT))
    null = d.score(f"{sub}.example.com", _NULL)
    assert txt > a and null > a
    assert txt == null


def test_a_short_payload_does_not_earn_the_record_type_bonus():
    d = TunnelDetector()
    a = d.score("abc.example.com", int(Type.A))
    txt = d.score("abc.example.com", int(Type.TXT))
    assert txt == a


def test_many_labels_contribute():
    d = TunnelDetector()
    flat = d.score("abcdef.example.com", int(Type.A))
    deep = d.score("a.b.c.d.e.f.example.com", int(Type.A))
    assert deep > flat


def test_the_score_is_capped_at_one():
    d = TunnelDetector()
    payload = base64.b32encode(bytes(range(200))).decode().lower().rstrip("=")
    labels = ".".join(payload[i:i + 60] for i in range(0, len(payload), 60))
    assert d.score(f"{labels}.example.com", int(Type.TXT)) <= 1.0


# --- inspect ---
def test_inspect_reports_a_verdict_with_the_rounded_score():
    d = TunnelDetector(threshold=0.9)
    result = d.inspect("www.example.com", int(Type.A))
    assert isinstance(result, TunnelResult)
    assert result.suspicious is False and result.reason == ""
    assert result.score == round(result.score, 3)


def test_inspect_explains_itself_when_it_flags():
    d = TunnelDetector(threshold=0.01)
    result = d.inspect("a" * 45 + ".example.com", int(Type.TXT))
    assert result.suspicious is True
    assert "DNS tunneling/exfil" in result.reason
    assert f"{result.score:.2f}" in result.reason


def test_the_threshold_decides():
    name = "a" * 45 + ".example.com"
    lenient = TunnelDetector(threshold=0.99).inspect(name, int(Type.TXT))
    strict = TunnelDetector(threshold=0.01).inspect(name, int(Type.TXT))
    assert lenient.suspicious is False and strict.suspicious is True
    assert lenient.score == strict.score
