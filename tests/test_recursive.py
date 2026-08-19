"""Iterative resolver + QNAME minimization against a mock authority tree."""
from __future__ import annotations

import pytest

from dnsguard.resolver.recursive import Recursive
from dnsguard.wire import RR, Class, Message, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Flags

ROOT_IP, COM_IP, AUTH_IP = "10.0.0.1", "10.0.0.2", "10.0.0.3"


def referral(zone: str, ns: str, glue_ip: str) -> Message:
    m = Message(id=0, flags=Flags.QR)
    m.authority.append(RR(Name.from_text(zone), Type.NS, Class.IN, 172800,
                          R.NS(Name.from_text(ns))))
    m.additional.append(RR(Name.from_text(ns), Type.A, Class.IN, 172800, R.A(glue_ip)))
    return m


def answer(name: str, ip: str) -> Message:
    m = Message(id=0, flags=Flags.QR | Flags.AA)
    m.answers.append(RR(Name.from_text(name), Type.A, Class.IN, 300, R.A(ip)))
    return m


def nodata(name: str) -> Message:
    m = Message(id=0, flags=Flags.QR | Flags.AA)
    return m


@pytest.mark.asyncio
async def test_iterative_with_qname_min():
    queries = []

    async def transport(ip, query):
        q = query.question
        name = q.name.to_text().rstrip(".")
        queries.append((ip, name, int(q.rtype)))
        if ip == ROOT_IP:
            return referral("com", "ns.com", COM_IP)
        if ip == COM_IP:
            return referral("example.com", "ns.example.com", AUTH_IP)
        if ip == AUTH_IP:
            if name == "www.example.com" and q.rtype == Type.A:
                return answer("www.example.com", "93.184.216.34")
            return nodata(name)
        raise RuntimeError("unknown server")

    rec = Recursive(transport, root_hints=[ROOT_IP], qmin=True)
    resp = await rec.resolve("www.example.com", Type.A)
    assert resp.answers and resp.answers[0].rdata.to_text() == "93.184.216.34"

    # QNAME minimization: root only ever saw "com" (NS), com saw "example.com",
    # never the full leaf until the authoritative server.
    assert (ROOT_IP, "com", int(Type.NS)) in queries
    assert (COM_IP, "example.com", int(Type.NS)) in queries
    assert (AUTH_IP, "www.example.com", int(Type.A)) in queries
    # the full leaf name was never leaked to the root or TLD
    assert not any(s in (ROOT_IP, COM_IP) and n == "www.example.com" for s, n, _ in queries)


@pytest.mark.asyncio
async def test_cname_chase():
    async def transport(ip, query):
        q = query.question
        name = q.name.to_text().rstrip(".")
        if ip == ROOT_IP:
            return referral("com", "ns.com", AUTH_IP)
        # authoritative server for everything under com in this test
        if name in ("alias.com", "com", "example.com"):
            if name == "alias.com" and q.rtype == Type.A:
                m = Message(id=0, flags=Flags.QR | Flags.AA)
                m.answers.append(RR(Name.from_text("alias.com"), Type.CNAME, Class.IN, 300,
                                    R.CNAME(Name.from_text("real.com"))))
                return m
            return referral("com", "ns.com", AUTH_IP) if name == "com" else nodata(name)
        if name == "real.com" and q.rtype == Type.A:
            return answer("real.com", "1.2.3.4")
        return nodata(name)

    rec = Recursive(transport, root_hints=[ROOT_IP], qmin=False)
    resp = await rec.resolve("alias.com", Type.A)
    texts = [rr.rdata.to_text() for rr in resp.answers]
    assert "real.com." in texts and "1.2.3.4" in texts
