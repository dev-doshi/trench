"""Build synthetic responses: sinkhole / NXDOMAIN / REFUSED / NODATA / rewrite."""
from __future__ import annotations

from ..filter import Decision
from ..wire import RR, Class, Message, Type
from ..wire import rdata as R
from ..wire.rrtypes import Rcode

BLOCK_TTL = 60


def _answer_rr(query: Message, rtype: int, rd: R.Rdata, ttl: int) -> RR:
    q = query.question
    return RR(q.name, rtype, Class.IN, ttl, rd)


def build_block(query: Message, mode: str, ipv4: str, ipv6: str,
                ttl: int = BLOCK_TTL) -> Message:
    resp = query.reply(Rcode.NOERROR)
    q = query.question
    if q is None:
        resp.set_rcode(Rcode.REFUSED)
        return resp
    if mode == "nxdomain":
        resp.set_rcode(Rcode.NXDOMAIN)
        return resp
    if mode == "refused":
        resp.set_rcode(Rcode.REFUSED)
        return resp
    if mode == "nodata":
        return resp  # NOERROR, empty answer
    # zero_ip / custom_ip: answer A/AAAA with the sink address, else NODATA
    v4 = "0.0.0.0" if mode == "zero_ip" else ipv4
    v6 = "::" if mode == "zero_ip" else ipv6
    if q.rtype == Type.A:
        resp.answers.append(_answer_rr(query, Type.A, R.A(v4), ttl))
    elif q.rtype == Type.AAAA:
        resp.answers.append(_answer_rr(query, Type.AAAA, R.AAAA(v6), ttl))
    # other qtypes -> NODATA (authoritative empty)
    return resp


def build_rewrite(query: Message, decision: Decision, ttl: int = 300) -> Message:
    resp = query.reply(Rcode.NOERROR)
    q = query.question
    if decision.rcode is not None:
        resp.set_rcode(decision.rcode)
        return resp
    if decision.rdata is not None and q is not None:
        from ..wire.rdata import rdata_type
        resp.answers.append(_answer_rr(query, rdata_type(decision.rdata), decision.rdata, ttl))
    return resp
