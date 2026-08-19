"""Unsolicited-record filtering (RFC 5452 §6).

Checking the question section proves the *response* is ours; it says nothing
about the records inside it. Before this, an upstream could attach an A record
for someone else's bank to an answer about an ad domain and we relayed it to the
client and cached it.

The risk in fixing this is over-filtering: a resolver that drops legitimate
records is worse than one that passes junk. Most of these tests exist to pin
down what must *survive* — CNAME chains, DNSSEC proofs, delegations, glue.
"""
from __future__ import annotations

import pytest

from dnsguard.resolver.sanitize import MAX_CNAME_CHAIN, sanitize
from dnsguard.wire import Class, Message, Question
from dnsguard.wire.message import RR
from dnsguard.wire.name import Name
from dnsguard.wire.rdata import CNAME, MX, NS, RRSIG, SOA, TXT, A
from dnsguard.wire.rrtypes import Flags, Type


def n(text: str) -> Name:
    return Name.from_text(text)


def rr(name, rtype, rdata, ttl=300):
    return RR(n(name), rtype, Class.IN, ttl, rdata)


def resp_for(qname="www.example.com.", qtype=Type.A):
    m = Message(id=1)
    m.set_flag(Flags.QR, True)
    m.questions.append(Question(n(qname), qtype, Class.IN))
    return m


def owners(rrs):
    return [x.name.to_text() for x in rrs]


# --- what must be removed ---
def test_answer_for_an_unrelated_name_is_dropped():
    m = resp_for()
    m.answers = [rr("www.example.com.", Type.A, A("1.1.1.1")),
                 rr("bank.example.", Type.A, A("6.6.6.6"))]
    cut = sanitize(m, "www.example.com.")
    assert cut.answers == 1
    assert owners(m.answers) == ["www.example.com."]


def test_unreferenced_additional_glue_is_dropped():
    """A forwarder never follows glue, so an address record for a name nothing
    points at has no reason to be in the response."""
    m = resp_for()
    m.answers = [rr("www.example.com.", Type.A, A("1.1.1.1"))]
    m.additional = [rr("mail.google.com.", Type.A, A("6.6.6.6"))]
    cut = sanitize(m, "www.example.com.")
    assert cut.additional == 1 and m.additional == []


def test_authority_for_an_unrelated_zone_is_dropped():
    m = resp_for()
    m.authority = [rr("example.com.", Type.NS, NS(n("ns1.example.com."))),
                   rr("evil.example.", Type.NS, NS(n("ns.evil.example.")))]
    cut = sanitize(m, "www.example.com.")
    assert cut.authority == 1
    assert owners(m.authority) == ["example.com."]


def test_a_descendant_of_the_qname_is_not_authoritative_for_it():
    """Ancestors are expected in the authority section; descendants are not."""
    m = resp_for(qname="example.com.")
    m.authority = [rr("sub.example.com.", Type.NS, NS(n("ns.sub.example.com.")))]
    cut = sanitize(m, "example.com.")
    assert cut.authority == 1 and m.authority == []


def test_cname_chain_that_does_not_start_at_the_qname_is_dropped():
    m = resp_for()
    m.answers = [rr("other.example.", Type.CNAME, CNAME(n("evil.example."))),
                 rr("evil.example.", Type.A, A("6.6.6.6"))]
    cut = sanitize(m, "www.example.com.")
    assert cut.answers == 2 and m.answers == []


# --- what must survive ---
def test_a_legitimate_cname_chain_survives_intact():
    m = resp_for()
    m.answers = [rr("www.example.com.", Type.CNAME, CNAME(n("cdn.example.net."))),
                 rr("cdn.example.net.", Type.CNAME, CNAME(n("edge.cdn.example.net."))),
                 rr("edge.cdn.example.net.", Type.A, A("1.2.3.4"))]
    cut = sanitize(m, "www.example.com.")
    assert not cut, f"broke a valid chain: {cut}"
    assert len(m.answers) == 3


def test_dnssec_signatures_on_kept_records_survive():
    """A validating client cannot verify what it did not receive."""
    m = resp_for()
    m.answers = [rr("www.example.com.", Type.A, A("1.1.1.1")),
                 rr("www.example.com.", Type.RRSIG,
                    RRSIG(Type.A, 13, 3, 300, 0, 0, 1234, n("example.com."), b"sig"))]
    cut = sanitize(m, "www.example.com.")
    assert not cut and len(m.answers) == 2


def test_negative_answer_keeps_its_soa_proof():
    m = resp_for(qname="nope.example.com.")
    m.authority = [rr("example.com.", Type.SOA,
                      SOA(n("ns.example.com."), n("hm.example.com."), 1, 2, 3, 4, 300))]
    cut = sanitize(m, "nope.example.com.")
    assert not cut and len(m.authority) == 1


def test_delegation_keeps_its_ns_records_and_their_glue():
    m = resp_for(qname="deep.sub.example.com.")
    m.authority = [rr("example.com.", Type.NS, NS(n("ns1.example.com.")))]
    m.additional = [rr("ns1.example.com.", Type.A, A("9.9.9.9"))]
    cut = sanitize(m, "deep.sub.example.com.")
    assert not cut, f"broke a delegation: {cut}"
    assert len(m.authority) == 1 and len(m.additional) == 1


def test_mx_target_glue_survives():
    m = resp_for(qname="example.com.", qtype=Type.MX)
    m.answers = [rr("example.com.", Type.MX, MX(10, n("mail.example.com.")))]
    m.additional = [rr("mail.example.com.", Type.A, A("1.2.3.4"))]
    cut = sanitize(m, "example.com.")
    assert not cut and len(m.additional) == 1


def test_case_differences_do_not_cause_drops():
    """Names are case-insensitive; 0x20 randomisation makes mixed case normal."""
    m = resp_for()
    m.answers = [rr("WWW.Example.COM.", Type.A, A("1.1.1.1"))]
    cut = sanitize(m, "www.example.com.")
    assert not cut and len(m.answers) == 1


def test_the_qname_itself_is_always_allowed():
    m = resp_for()
    m.answers = [rr("www.example.com.", Type.TXT, TXT([b"hello"]))]
    assert not sanitize(m, "www.example.com.")


# --- adversarial shapes ---
def test_cname_loop_terminates():
    """A -> B -> A must not spin, and must not smuggle anything in."""
    m = resp_for(qname="a.example.")
    m.answers = [rr("a.example.", Type.CNAME, CNAME(n("b.example."))),
                 rr("b.example.", Type.CNAME, CNAME(n("a.example."))),
                 rr("evil.example.", Type.A, A("6.6.6.6"))]
    cut = sanitize(m, "a.example.")
    assert cut.answers == 1
    assert "evil.example." not in owners(m.answers)


def test_long_chain_is_cut_off():
    """A chain longer than any real configuration is a walk we refuse to finish."""
    m = resp_for(qname="h0.example.")
    depth = MAX_CNAME_CHAIN + 8
    for i in range(depth):
        m.answers.append(rr(f"h{i}.example.", Type.CNAME, CNAME(n(f"h{i+1}.example."))))
    m.answers.append(rr(f"h{depth}.example.", Type.A, A("1.1.1.1")))
    sanitize(m, "h0.example.")
    assert len(m.answers) <= MAX_CNAME_CHAIN + 1
    assert f"h{depth}.example." not in owners(m.answers), "walked past the cap"


def test_empty_response_is_untouched():
    m = resp_for()
    assert not sanitize(m, "www.example.com.")
    assert m.answers == [] and m.authority == [] and m.additional == []


def test_response_without_a_question_is_left_alone():
    """Nothing to judge against; the caller rejects these separately."""
    m = Message(id=1)
    m.set_flag(Flags.QR, True)
    m.answers = [rr("whatever.example.", Type.A, A("1.1.1.1"))]
    assert not sanitize(m, "")
    assert len(m.answers) == 1


# --- end to end through the pipeline ---
@pytest.mark.asyncio
async def test_pipeline_does_not_relay_or_cache_injected_records():
    from dnsguard.cache import Cache
    from dnsguard.config import Config
    from dnsguard.engine import Pipeline
    from dnsguard.filter import FilterEngine
    from dnsguard.stats import Counters

    class Hostile:
        async def resolve(self, q):
            r = Message(id=q.id)
            r.set_flag(Flags.QR, True)
            r.questions = list(q.questions)
            r.answers = [rr("a.example.", Type.A, A("1.1.1.1")),
                         rr("bank.example.", Type.A, A("6.6.6.6"))]
            r.additional = [rr("mail.google.com.", Type.A, A("6.6.6.6"))]
            return r

    cache = Cache()
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=cache,
                    forwarder=Hostile(), counters=Counters(),
                    config=Config.model_validate({"filtering": {"enabled": False}}))

    def q():
        m = Message(id=9)
        m.set_flag(Flags.RD, True)
        m.questions.append(Question(n("a.example."), Type.A, Class.IN))
        return m

    resp = await pipe.resolve(q(), "10.0.0.1")
    assert owners(resp.answers) == ["a.example."]
    assert resp.additional == []

    # and the poison must not have been cached either — the second request is a
    # cache hit, so a dirty entry would resurface here
    resp2 = await pipe.resolve(q(), "10.0.0.1")
    assert owners(resp2.answers) == ["a.example."]
    assert all("bank" not in o for o in owners(resp2.answers) + owners(resp2.additional))
