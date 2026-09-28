"""Records whose rtype and rdata disagree.

`parse_rdata` deliberately keeps a malformed record rather than rejecting the
whole message: a type with no embedded name that fails to decode comes back as
`Unknown`, still carrying the rtype it claimed. So a truncated A record is
`rtype == Type.A` with rdata that has no `.address`, and any code that reads a
typed field after testing the rtype alone raises AttributeError on input a
remote server chooses to send.

Every test here sends one such record and asserts what must happen anyway. The
sharpest is `test_a_malformed_dnskey_cannot_downgrade_a_secure_answer`: the
crash used to escape `Validator.validate`, and the resolver turns an unexpected
validator error into INSECURE — so appending one junk record to a DNSKEY
response suppressed validation instead of failing it.
"""
from __future__ import annotations

import asyncio
import struct

import pytest
from test_dnssec_chain import LEAF, build_hierarchy, make_ask

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.engine.rebinding import scrub
from trench.filter import FilterEngine, compile_rules
from trench.resolver.dnssec import ValidationResult, Validator
from trench.resolver.recursive import Recursive
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire.name import Name
from trench.wire.rdata import Unknown


def _name_wire(text: str) -> bytes:
    out = b""
    for label in text.strip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _rr_wire(name: str, rtype: int, rdata: bytes, ttl: int = 300) -> bytes:
    return (_name_wire(name) + struct.pack(">HHIH", rtype, Class.IN, ttl, len(rdata))
            + rdata)


def _response(qname: str, qtype: int, answers: bytes, ancount: int) -> Message:
    """A response built on the wire and parsed back, exactly as a transport does."""
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, ancount, 0, 0)
    question = _name_wire(qname) + struct.pack(">HH", qtype, Class.IN)
    return Message.parse(header + question + answers)


# --------------------------------------------------------------- the premise
def test_a_truncated_address_record_keeps_its_rtype():
    """The whole problem in one assertion: rtype says A, the rdata is not one."""
    msg = _response("www.example.com.", Type.A,
                    _rr_wire("www.example.com.", Type.A, b"\x01\x02\x03"), 1)
    rr = msg.answers[0]
    assert rr.rtype == Type.A
    assert isinstance(rr.rdata, Unknown)
    assert not hasattr(rr.rdata, "address")


def test_a_four_octet_address_record_always_decodes():
    """Why passing the record through is safe rather than merely convenient: an
    A record that is 4 octets long always parses, so an `Unknown` carrying rtype
    A is by definition not a length an address can have — it cannot state the
    private address the rebinding scrub exists to strip."""
    msg = _response("www.example.com.", Type.A,
                    _rr_wire("www.example.com.", Type.A, b"\xc0\xa8\x01\x01"), 1)
    assert msg.answers[0].rdata.address == "192.168.1.1"


# ------------------------------------------------------------ response path
def test_the_rebinding_scrub_survives_one():
    msg = _response("www.example.com.", Type.A,
                    _rr_wire("www.example.com.", Type.A, b"\x01\x02\x03"), 1)
    assert scrub(msg, "www.example.com.") == 0
    assert len(msg.answers) == 1        # not counted as a rebinding hit


def test_the_rebinding_scrub_still_strips_private_addresses_beside_one():
    """A malformed record must not shield the record next to it."""
    answers = (_rr_wire("www.example.com.", Type.A, b"\x01\x02\x03")
               + _rr_wire("www.example.com.", Type.A, b"\xc0\xa8\x01\x01"))
    msg = _response("www.example.com.", Type.A, answers, 2)
    assert scrub(msg, "www.example.com.") == 1
    assert len(msg.answers) == 1
    assert isinstance(msg.answers[0].rdata, Unknown)


class _Upstream:
    def __init__(self, wire_answers: bytes, count: int):
        self._answers, self._count = wire_answers, count

    async def resolve(self, query: Message, note=None) -> Message:
        q = query.question
        msg = _response(q.name.to_text(), q.rtype, self._answers, self._count)
        msg.id = query.id
        return msg


def _pipeline(upstream) -> Pipeline:
    return Pipeline(filter_engine=FilterEngine.compile(compile_rules("", "test")),
                    cache=Cache(), forwarder=upstream, counters=Counters(),
                    config=Config.model_validate({}))


def test_one_bad_record_does_not_servfail_the_whole_answer():
    """End to end, with the shipped defaults: rebinding protection is on, so the
    scrub reads every A record in every upstream answer. One undecodable record
    used to raise through the pipeline's catch-all and cost the client the good
    records beside it."""
    answers = (_rr_wire("www.example.com.", Type.A, b"\x01\x02\x03")
               + _rr_wire("www.example.com.", Type.A, b"\x5d\xb8\xd8\x22"))
    pipe = _pipeline(_Upstream(answers, 2))
    query = Message(id=0x4242)
    query.set_flag(0x0100, True)
    query.questions.append(Question(Name.from_text("www.example.com."), Type.A, Class.IN))
    response = asyncio.run(pipe.resolve(query, "10.0.0.5", "udp"))
    assert response.rcode == 0
    assert any(getattr(rr.rdata, "address", None) == "93.184.216.34"
               for rr in response.answers)


# ------------------------------------------------------------------- DNSSEC
def _ask_with(extra_owner: Name, extra_rtype: int, zones):
    """`make_ask`, with one undecodable record prepended to a chosen RRset."""
    base = make_ask(zones)

    async def ask(name: Name, rtype: int) -> Message:
        msg = await base(name, rtype)
        if name == extra_owner and rtype == extra_rtype:
            msg.answers.insert(0, RR(name, extra_rtype, Class.IN, 3600,
                                     Unknown(extra_rtype, b"\x01\x02\x03")))
        return msg
    return ask


@pytest.mark.asyncio
async def test_a_malformed_dnskey_cannot_downgrade_a_secure_answer():
    """The attack this file exists for.

    A spoofed DNSKEY response is normally rejected — the keys do not match the
    parent's DS, so validation is bogus and the answer is dropped. Prepending
    one undecodable DNSKEY made the ZONE-flag filter, which runs before any
    signature is checked, raise AttributeError out of `validate`; the resolver
    treats an unexpected validator error as INSECURE and serves the answer. The
    record must simply not be part of the RRset.
    """
    zones, anchors = build_hierarchy()
    leaf = zones["example.test."]
    validator = Validator(_ask_with(LEAF, Type.DNSKEY, zones), anchors=anchors)
    result = await validator.validate(LEAF, Type.A, leaf.records[LEAF][Type.A],
                                      [leaf.rrsigs[(LEAF, Type.A)]])
    assert result == ValidationResult.SECURE


@pytest.mark.asyncio
async def test_a_malformed_ds_cannot_deny_service_for_the_zone():
    """The same record in the DS RRset. Here the signature check came first, so
    the crash did not happen — but the junk record was part of the set being
    verified, so anyone able to append one could force the zone bogus."""
    zones, anchors = build_hierarchy()
    leaf = zones["example.test."]
    validator = Validator(_ask_with(LEAF, Type.DS, zones), anchors=anchors)
    result = await validator.validate(LEAF, Type.A, leaf.records[LEAF][Type.A],
                                      [leaf.rrsigs[(LEAF, Type.A)]])
    assert result == ValidationResult.SECURE


@pytest.mark.asyncio
async def test_dropping_a_record_cannot_make_an_unsigned_set_verify():
    """Why filtering is safe: the surviving records are still what the signature
    is checked against, so removing one the zone really did sign fails."""
    zones, anchors = build_hierarchy()
    leaf = zones["example.test."]
    base = make_ask(zones)

    async def ask(name: Name, rtype: int) -> Message:
        msg = await base(name, rtype)
        if name == LEAF and rtype == Type.DNSKEY:
            # replace a genuine key with an undecodable one
            for i, rr in enumerate(msg.answers):
                if rr.rtype == Type.DNSKEY:
                    msg.answers[i] = RR(name, Type.DNSKEY, Class.IN, 3600,
                                        Unknown(Type.DNSKEY, b"\x01\x02\x03"))
                    break
        return msg

    validator = Validator(ask, anchors=anchors)
    result = await validator.validate(LEAF, Type.A, leaf.records[LEAF][Type.A],
                                      [leaf.rrsigs[(LEAF, Type.A)]])
    assert result == ValidationResult.BOGUS


# ------------------------------------------------------------ referral glue
def test_malformed_glue_does_not_discard_the_addresses_beside_it():
    """`_glue` reads every A/AAAA in the additional section. One undecodable
    record raised, and the handler above it dropped the whole referral — so a
    delegation with one bad glue record became unresolvable."""
    header = struct.pack(">HHHHHH", 0x1234, 0x8000, 1, 0, 1, 2)
    question = _name_wire("www.example.com.") + struct.pack(">HH", Type.A, Class.IN)
    authority = _rr_wire("example.com.", Type.NS, _name_wire("ns1.example.com."), 3600)
    additional = (_rr_wire("ns1.example.com.", Type.A, b"\x01\x02\x03")
                  + _rr_wire("ns1.example.com.", Type.A, b"\x5d\xb8\xd8\x22"))
    msg = Message.parse(header + question + authority + additional)

    ns = Name.from_text("ns1.example.com.")
    glue = Recursive._glue(msg, Name.from_text("example.com."), (ns,))
    assert glue == {ns: ("93.184.216.34",)}
