"""The other half of the attack surface: what comes *back*.

`test_wire_hostile.py` fuzzes the parser, and `test_fastpath_equivalence.py`
fuzzes queries through the pipeline — but both answer with a well-formed reply
built by the test. Nothing drove a *hostile response* through the stages that
read one, and a resolver does not choose who answers it: every upstream, every
authority, and anyone who wins a race against them writes these bytes.

The gap was not theoretical. A malformed A record in an answer section reached
the rebinding scrub, which read `.address` off it, and the AttributeError was
logged as "upstream failed" and served to the client as SERVFAIL — for a query
that was fine and an upstream that was reachable. See
`tests/test_undecodable_rdata.py` for that class of bug in detail.

The property here is deliberately weak and therefore hard to argue with: a
response may be rejected for any reason the resolver likes, but rejecting it
must be a *decision*, not an exception. `Pipeline._resolve_upstream` separates
the two — an upstream fault is a warning, our own code failing is an ERROR with
a traceback — so "no ERROR was logged" is the whole assertion.
"""
from __future__ import annotations

import asyncio
import logging
import random

from test_wire_hostile import _mutate, _seed_corpus

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.filter import FilterEngine, compile_rules
from trench.stats import Counters
from trench.transport.base import process_query
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.edns import Edns
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode

WWW = Name.from_text("www.example.com.")


class _ReplayUpstream:
    """Answers with one fixed response, exactly as a forwarder hands it over:
    parsed from the wire, with the transaction id matched to the query."""

    def __init__(self) -> None:
        self.wire = b""

    async def resolve(self, query: Message, note=None) -> Message:
        msg = Message.parse(self.wire)      # WireError: the transport's problem
        msg.id = query.id
        return msg


def _pipeline(upstream, security=None, filtering=None) -> Pipeline:
    raw = {}
    if security:
        raw["security"] = security
    if filtering:
        raw["filtering"] = filtering
    return Pipeline(filter_engine=FilterEngine.compile(compile_rules("", "test")),
                    cache=Cache(), forwarder=upstream, counters=Counters(),
                    config=Config.model_validate(raw))


#: Types that are not in `_NAME_BEARING`, so a record claiming one and failing
#: to decode survives as `Unknown` carrying that rtype (see `parse_rdata`).
_DEGRADABLE = (Type.A, Type.AAAA, Type.TXT, Type.DS, Type.DNSKEY, Type.NSEC3,
               Type.NSEC3PARAM, Type.TLSA, Type.CAA, Type.SSHFP)


def _undecodable_seeds() -> list[bytes]:
    """Responses carrying a record whose rtype and rdata disagree.

    The byte-level mutator alone does not reach the stages that read a response:
    it scrambles owner names, and `sanitize` rebuilds the answer section from
    the question's CNAME chain, so a corrupted record is dropped long before
    anything looks at its rdata. These keep the owner on the chain and corrupt
    only the rdata, which is the shape that actually gets through.
    """
    out = []
    for rtype in _DEGRADABLE:
        for blob in (b"", b"\x01\x02\x03", bytes(63)):
            m = Message(id=1, flags=0x8180)
            m.questions.append(Question(WWW, rtype, Class.IN))
            m.answers.append(RR(WWW, rtype, Class.IN, 300, R.Unknown(rtype, blob)))
            # a well-formed record beside it: a stage that trips on the bad one
            # must not cost the client this one
            m.answers.append(RR(WWW, Type.A, Class.IN, 300, R.A("93.184.216.34")))
            out.append(m.to_wire())
    return out


def _extra_seeds() -> list[bytes]:
    """Responses the shared corpus does not cover, for the stages that read
    them: a CNAME chain (cloak inspection), and SVCB/HTTPS (the ECH strip)."""
    out = []
    for rtype, rd in ((Type.CNAME, R.CNAME(Name.from_text("cdn.example.net."))),
                      (Type.HTTPS, R.HTTPS(1, Name.from_text("."),
                                           b"\x00\x05\x00\x03abc")),
                      (Type.SVCB, R.SVCB(1, Name.from_text("svc.example.net."),
                                         b"\x00\x01\x00\x03\x02h2"))):
        m = Message(id=1, flags=0x8180)
        m.questions.append(Question(WWW, rtype, Class.IN))
        m.answers.append(RR(WWW, rtype, Class.IN, 300, rd))
        m.answers.append(RR(Name.from_text("cdn.example.net."), Type.A, Class.IN,
                            300, R.A("93.184.216.34")))
        out.append(m.to_wire())
    return out


def _query(qtype: int = Type.A, *, edns: bool = False, do: bool = False) -> bytes:
    m = Message(id=0x2461)
    m.set_flag(0x0100, True)
    m.questions.append(Question(WWW, qtype, Class.IN))
    if edns:
        m.edns = Edns(udp_size=1232)
        m.edns.do = do
    return m.to_wire()


def _drive(caplog, iterations: int, seed: int, security=None, filtering=None) -> int:
    """Run hostile responses through the pipeline.

    Returns how many produced a real answer — NOERROR carrying records — not
    merely how many produced bytes. Two thirds of the byte-level mutations do
    not parse at all, and the SERVFAIL that follows is the resolver working:
    counting those made the coverage assertion below true without any response
    ever reaching the stages it is meant to exercise.
    """
    rng = random.Random(seed)
    corpus = _seed_corpus() + _extra_seeds()
    structured = _undecodable_seeds()
    upstream = _ReplayUpstream()
    pipe = _pipeline(upstream, security, filtering)
    queries = [_query(), _query(Type.AAAA), _query(Type.MX), _query(Type.TXT),
               _query(edns=True), _query(edns=True, do=True)]
    loop = asyncio.new_event_loop()
    answered = 0
    try:
        with caplog.at_level(logging.ERROR, logger="trench"):
            for i in range(iterations):
                if i % 3 == 0:
                    # Verbatim, not mutated: these are already hostile in the
                    # one way that survives sanitizing, and mutating them just
                    # turns them back into noise the earlier stages discard.
                    upstream.wire = structured[(i // 3) % len(structured)]
                else:
                    upstream.wire = _mutate(rng.choice(corpus), rng)
                # A fresh cache per iteration: a response cached from an earlier
                # mutation would answer the next one without the stages under
                # test ever running.
                pipe.cache = Cache()
                out = loop.run_until_complete(
                    process_query(pipe, queries[i % len(queries)],
                                  "10.0.0.5", "udp", stream=False))
                if out is None:
                    continue
                reply = Message.parse(out)  # what we emit must parse back
                if reply.rcode == Rcode.NOERROR and reply.answers:
                    answered += 1
    finally:
        loop.close()
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert not errors, (
        f"{len(errors)} internal error(s) handling a response; first: "
        f"{errors[0].getMessage()}\n{errors[0].exc_text}")
    return answered


def test_no_mutated_response_makes_the_pipeline_raise(caplog):
    assert _drive(caplog, 2_000, 0x5EED) > 0


def test_the_same_holds_with_the_optional_response_stages_on(caplog):
    """The detectors, cookies and the ECH strip each read the response, and the
    shipped defaults leave most of them off — so the default run above never
    reaches them."""
    assert _drive(caplog, 1_500, 0xD15EA5E,
                  security={"rebinding_protection": True, "dga_detection": True,
                            "tunnel_detection": True, "dns_cookies": True},
                  filtering={"ech": "strip"}) > 0


def test_the_hostile_responses_actually_reach_the_stages(caplog):
    """Guards against the assertions above passing vacuously. A response that is
    rejected never reaches the code that reads one, so if every mutation were
    rejected the two tests above would hold no matter what those stages did."""
    answered = _drive(caplog, 600, 0xC0FFEE)
    assert answered > 150, f"only {answered} of 600 hostile responses were answered"
