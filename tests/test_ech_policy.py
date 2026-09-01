"""ECH parameter policy on HTTPS/SVCB answers."""
from __future__ import annotations

import asyncio
import struct

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.filter import FilterEngine
from dnsguard.filter.svcparams import has_ech, iter_params, strip_ech, strip_ech_records
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


def params(*pairs: tuple[int, bytes]) -> bytes:
    return b"".join(struct.pack("!HH", k, len(v)) + v for k, v in pairs)


ALPN = (1, b"\x02h2")
ECH = (5, b"\xab" * 8)
PORT = (3, b"\x01\xbb")


def test_strip_removes_only_the_ech_parameter():
    raw = params(ALPN, PORT, ECH)
    out = strip_ech(raw)
    assert not has_ech(out)
    assert list(iter_params(out)) == [ALPN, PORT]


def test_records_without_ech_are_returned_unchanged():
    raw = params(ALPN, PORT)
    assert strip_ech(raw) is raw


def test_malformed_params_are_left_alone():
    """A blob we cannot parse is not a blob we may rewrite."""
    truncated = struct.pack("!HH", 5, 40) + b"short"
    assert strip_ech(truncated) == truncated


def test_stripping_replaces_records_rather_than_mutating_them():
    """A cached message shares record objects with the copy already served."""
    rd = R.HTTPS(1, Name.from_text("."), params(ALPN, ECH))
    rr = RR(Name.from_text("x.example"), Type.HTTPS, Class.IN, 60, rd)
    msg = Message(id=1)
    msg.answers = [rr]
    assert strip_ech_records(msg) == 1
    assert not has_ech(msg.answers[0].rdata.params)
    assert has_ech(rd.params)                  # the original object is untouched


class Fwd:
    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.HTTPS, Class.IN, 60,
                               R.HTTPS(1, Name.from_text("."), params(ALPN, ECH))))
        return resp


def query_https(pipe: Pipeline) -> Message:
    m = Message(id=5)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text("x.example"), Type.HTTPS, Class.IN))
    return asyncio.run(pipe.resolve(m, "10.0.0.1"))


def pipeline(mode: str) -> Pipeline:
    cfg = Config()
    cfg.filtering.ech = mode
    return Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(enabled=False),
                    forwarder=Fwd(), counters=Counters(), config=cfg)


def test_default_policy_passes_ech_through():
    """ECH hides the TLS server name, not the DNS question — filtering here is
    unaffected, so the default must not downgrade clients."""
    assert Config().filtering.ech == "pass"
    resp = query_https(pipeline("pass"))
    assert has_ech(resp.answers[0].rdata.params)


def test_strip_policy_removes_it_from_served_answers():
    resp = query_https(pipeline("strip"))
    assert not has_ech(resp.answers[0].rdata.params)
    assert list(iter_params(resp.answers[0].rdata.params)) == [ALPN]
