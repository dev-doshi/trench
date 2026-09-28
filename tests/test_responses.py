"""Synthetic response construction — every block mode and rewrite shape.

`build_block`/`build_rewrite` are the only place a client-visible answer is
invented rather than relayed, and the suite reached them only indirectly through
the pipeline's default mode, leaving the other four modes unexercised.
"""
from __future__ import annotations

import pytest

from trench.engine.responses import BLOCK_TTL, build_block, build_rewrite
from trench.filter import Action, Decision
from trench.wire import Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Rcode


def mkquery(name="ads.example.com", rtype=Type.A, txid=7):
    m = Message(id=txid)
    m.set_flag(Flags.RD, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    return m


def test_block_echoes_id_question_and_sets_qr():
    q = mkquery()
    resp = build_block(q, "zero_ip", "1.1.1.1", "::1")
    assert resp.id == q.id
    assert resp.qr is True
    assert resp.questions == q.questions
    assert resp.rd is True


def test_block_without_question_is_refused():
    m = Message(id=1)
    resp = build_block(m, "zero_ip", "1.1.1.1", "::1")
    assert resp.rcode == Rcode.REFUSED
    assert resp.answers == []


@pytest.mark.parametrize("mode,rcode", [("nxdomain", Rcode.NXDOMAIN),
                                        ("refused", Rcode.REFUSED),
                                        ("nodata", Rcode.NOERROR)])
def test_block_rcode_modes_answer_nothing(mode, rcode):
    resp = build_block(mkquery(), mode, "1.1.1.1", "::1")
    assert resp.rcode == rcode
    assert resp.answers == []


def test_block_zero_ip_a():
    resp = build_block(mkquery(rtype=Type.A), "zero_ip", "9.9.9.9", "fe80::1")
    assert resp.rcode == Rcode.NOERROR
    assert len(resp.answers) == 1
    rr = resp.answers[0]
    assert rr.rtype == Type.A and rr.rclass == Class.IN
    assert rr.rdata.address == "0.0.0.0"
    assert rr.ttl == BLOCK_TTL
    assert rr.name == mkquery().question.name


def test_block_zero_ip_aaaa():
    resp = build_block(mkquery(rtype=Type.AAAA), "zero_ip", "9.9.9.9", "fe80::1")
    assert resp.answers[0].rtype == Type.AAAA
    assert resp.answers[0].rdata.address == "::"


def test_block_custom_ip_uses_configured_addresses():
    v4 = build_block(mkquery(rtype=Type.A), "custom_ip", "10.0.0.5", "fd00::5")
    assert v4.answers[0].rdata.address == "10.0.0.5"
    v6 = build_block(mkquery(rtype=Type.AAAA), "custom_ip", "10.0.0.5", "fd00::5")
    assert v6.answers[0].rdata.address == "fd00::5"


def test_block_custom_ttl_is_honoured():
    resp = build_block(mkquery(), "custom_ip", "10.0.0.5", "fd00::5", ttl=7)
    assert resp.answers[0].ttl == 7


@pytest.mark.parametrize("rtype", [Type.TXT, Type.MX, Type.HTTPS, Type.SRV, Type.NS])
def test_block_non_address_qtype_is_nodata(rtype):
    """An address sink has no answer to give for a TXT/MX/HTTPS query."""
    resp = build_block(mkquery(rtype=rtype), "zero_ip", "1.1.1.1", "::1")
    assert resp.rcode == Rcode.NOERROR
    assert resp.answers == []


def test_block_unknown_mode_behaves_like_custom_ip():
    resp = build_block(mkquery(), "something-else", "10.0.0.5", "fd00::5")
    assert resp.answers[0].rdata.address == "10.0.0.5"


def test_rewrite_rcode_short_circuits():
    d = Decision(action=Action.REWRITE, rcode=Rcode.NXDOMAIN)
    resp = build_rewrite(mkquery(), d)
    assert resp.rcode == Rcode.NXDOMAIN
    assert resp.answers == []


def test_rewrite_rdata_infers_the_record_type():
    d = Decision(action=Action.REWRITE, rdata=R.A("192.0.2.7"))
    resp = build_rewrite(mkquery(), d, ttl=42)
    assert len(resp.answers) == 1
    assert resp.answers[0].rtype == Type.A
    assert resp.answers[0].ttl == 42
    assert resp.answers[0].rdata.address == "192.0.2.7"

    d6 = Decision(action=Action.REWRITE, rdata=R.AAAA("2001:db8::1"))
    assert build_rewrite(mkquery(rtype=Type.AAAA), d6).answers[0].rtype == Type.AAAA

    dc = Decision(action=Action.REWRITE, rdata=R.CNAME(Name.from_text("real.example.")))
    assert build_rewrite(mkquery(), dc).answers[0].rtype == Type.CNAME


def test_rewrite_with_neither_rcode_nor_rdata_is_nodata():
    resp = build_rewrite(mkquery(), Decision(action=Action.REWRITE))
    assert resp.rcode == Rcode.NOERROR
    assert resp.answers == []


def test_rewrite_rdata_without_a_question_answers_nothing():
    m = Message(id=3)
    d = Decision(action=Action.REWRITE, rdata=R.A("192.0.2.7"))
    assert build_rewrite(m, d).answers == []


def test_block_preserves_edns_do_bit_from_the_query():
    from trench.wire.edns import Edns
    q = mkquery()
    q.edns = Edns(udp_size=1232)
    q.edns.do = True
    resp = build_block(q, "zero_ip", "1.1.1.1", "::1")
    assert resp.edns is not None and resp.edns.do is True


def test_an_explicit_noerror_rewrite_still_carries_its_record():
    """Regression: `$dnsrewrite=NOERROR;A;1.2.3.4` is the explicit spelling of
    the common case, and returning on the rcode alone dropped the forged record
    from every rule written that way."""
    d = Decision(action=Action.REWRITE, rcode=Rcode.NOERROR, rdata=R.A("192.0.2.7"))
    resp = build_rewrite(mkquery(), d)
    assert resp.rcode == Rcode.NOERROR
    assert len(resp.answers) == 1
    assert resp.answers[0].rdata.address == "192.0.2.7"


@pytest.mark.parametrize("rcode", [Rcode.NXDOMAIN, Rcode.REFUSED, Rcode.SERVFAIL])
def test_a_non_noerror_rewrite_answers_empty(rcode):
    """There is nothing to attach a record to."""
    d = Decision(action=Action.REWRITE, rcode=rcode, rdata=R.A("192.0.2.7"))
    resp = build_rewrite(mkquery(), d)
    assert resp.rcode == rcode and resp.answers == []


def test_an_explicit_noerror_rewrite_through_the_matcher():
    from trench.filter import FilterEngine, iter_rules
    eng = FilterEngine.compile(
        iter_rules("||ads.example.com^$dnsrewrite=NOERROR;A;192.0.2.7", "list"))
    d = eng.match("ads.example.com", int(Type.A))
    resp = build_rewrite(mkquery(), d)
    assert [rr.rdata.address for rr in resp.answers] == ["192.0.2.7"]
