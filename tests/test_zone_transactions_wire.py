"""Authoritative zone transactions over real sockets: AXFR over TCP, the
UDP-AXFR truncation nudge, dynamic update, NOTIFY."""
from __future__ import annotations

import asyncio
import socket

import pytest

from trench.auth_zone import Zone, ZoneStore
from trench.auth_zone.handler import AuthHandler
from trench.auth_zone.xfr import zone_from_records
from trench.transport.do53 import Do53Server
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Opcode, Rcode

ORIGIN = Name.from_text("example.com.")


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def _zone():
    z = Zone(ORIGIN)
    z.add(ORIGIN, Type.SOA, R.SOA(Name.from_text("ns.example.com."),
          Name.from_text("host.example.com."), 1, 7200, 3600, 1209600, 3600))
    z.add(ORIGIN, Type.NS, R.NS(Name.from_text("ns.example.com.")))
    z.add(Name.from_text("www.example.com."), Type.A, R.A("192.0.2.1"))
    return z


async def _tcp_roundtrip(port, query: Message) -> list[Message]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    wire = query.to_wire()
    writer.write(len(wire).to_bytes(2, "big") + wire)
    await writer.drain()
    writer.write_eof()
    out = []
    try:
        while True:
            hdr = await reader.readexactly(2)
            data = await reader.readexactly(int.from_bytes(hdr, "big"))
            out.append(Message.parse(data))
    except asyncio.IncompleteReadError:
        pass
    writer.close()
    return out


async def _udp_roundtrip(port, query: Message) -> Message:
    loop = asyncio.get_running_loop()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    await loop.sock_connect(s, ("127.0.0.1", port))
    await loop.sock_sendall(s, query.to_wire())
    data = await asyncio.wait_for(loop.sock_recv(s, 4096), 5)
    s.close()
    return Message.parse(data)


async def _server(zone, *, allow_update=(), allow_transfer=("127.0.0.1",)):
    store = ZoneStore(); store.add(zone)
    auth = AuthHandler(store)
    auth.set_zone_policy(ORIGIN, allow_transfer=allow_transfer, allow_update=allow_update)
    port = _free_port()
    # Pipeline isn't exercised for auth ops, but Do53Server needs one.
    srv = Do53Server(pipeline=_DummyPipeline(), host="127.0.0.1", port=port, auth=auth)
    await srv.start()
    return srv, port, store


class _DummyPipeline:
    async def resolve(self, *a, **k):
        raise AssertionError("auth ops must not reach the resolver pipeline")


def _update(add_name="blog.example.com.", ip="192.0.2.9"):
    m = Message(id=99)
    m.flags |= (Opcode.UPDATE << Flags.OPCODE_SHIFT)
    m.questions.append(Question(ORIGIN, Type.SOA))
    m.authority.append(RR(Name.from_text(add_name), Type.A, Class.IN, 300, R.A(ip)))
    return m


@pytest.mark.asyncio
async def test_axfr_over_tcp():
    srv, port, _ = await _server(_zone())
    try:
        q = Message(id=1); q.questions.append(Question(ORIGIN, Type.AXFR))
        msgs = await _tcp_roundtrip(port, q)
        rrs = [rr for m in msgs for rr in m.answers]
        z2 = zone_from_records(rrs, ORIGIN)
        assert z2.lookup(Name.from_text("www.example.com."), Type.A).answers
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_udp_axfr_truncated():
    srv, port, _ = await _server(_zone())
    try:
        q = Message(id=1); q.questions.append(Question(ORIGIN, Type.AXFR))
        resp = await _udp_roundtrip(port, q)
        assert resp.tc  # client is told to retry over TCP
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_dynamic_update_then_axfr():
    """Over TCP, because an address allow-list only means something there.

    An unsigned UPDATE over UDP is refused (see the companion test below): the
    source address of a datagram is a claim, and acting on it would let anyone
    who knows one allowed address rewrite the zone with a spoofed packet.
    """
    srv, port, store = await _server(_zone(), allow_update=("127.0.0.1",))
    try:
        resp = (await _tcp_roundtrip(port, _update()))[0]
        assert resp.rcode == Rcode.NOERROR and resp.opcode == Opcode.UPDATE
        # the served zone now has the new record and a bumped serial
        z = store.authoritative_for(ORIGIN)
        assert z.soa.serial == 2
        assert z.lookup(Name.from_text("blog.example.com."), Type.A).answers
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_unsigned_update_over_udp_is_refused_even_from_an_allowed_address():
    srv, port, store = await _server(_zone(), allow_update=("127.0.0.1",))
    try:
        resp = await _udp_roundtrip(port, _update())
        assert resp.rcode == Rcode.REFUSED
        assert store.authoritative_for(ORIGIN).soa.serial == 1   # zone untouched
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_update_refused_without_acl():
    srv, port, store = await _server(_zone(), allow_update=())  # empty ACL = deny
    try:
        resp = await _udp_roundtrip(port, _update())
        assert resp.rcode == Rcode.REFUSED
        assert store.authoritative_for(ORIGIN).soa.serial == 1  # unchanged
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_notify_acked_over_udp():
    """A NOTIFY from the zone's own primary is acknowledged.

    It has to be *from the primary*: acting on one from anywhere else turns a
    small UDP packet into a full zone transfer from our own infrastructure
    (RFC 1996 §3.10).
    """
    from trench.auth_zone.secondary import SecondaryZone

    z = _zone()
    store = ZoneStore(); store.add(z)
    auth = AuthHandler(store)
    auth.register_secondary(SecondaryZone(ORIGIN, "127.0.0.1"))
    port = _free_port()
    srv = Do53Server(pipeline=_DummyPipeline(), host="127.0.0.1", port=port, auth=auth)
    await srv.start()
    try:
        m = Message(id=5)
        m.flags |= (Opcode.NOTIFY << Flags.OPCODE_SHIFT)
        m.questions.append(Question(ORIGIN, Type.SOA))
        resp = await _udp_roundtrip(port, m)
        assert resp.qr and resp.opcode == Opcode.NOTIFY and resp.rcode == Rcode.NOERROR
    finally:
        await srv.stop()


@pytest.mark.asyncio
async def test_notify_for_a_zone_we_do_not_slave_is_refused():
    store = ZoneStore(); store.add(_zone())
    auth = AuthHandler(store)                     # no secondary registered
    port = _free_port()
    srv = Do53Server(pipeline=_DummyPipeline(), host="127.0.0.1", port=port, auth=auth)
    await srv.start()
    try:
        m = Message(id=6)
        m.flags |= (Opcode.NOTIFY << Flags.OPCODE_SHIFT)
        m.questions.append(Question(ORIGIN, Type.SOA))
        resp = await _udp_roundtrip(port, m)
        assert resp.rcode == Rcode.REFUSED
    finally:
        await srv.stop()
