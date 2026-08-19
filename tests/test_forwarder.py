"""Forwarder against a local fake upstream: UDP, parallel, TCP truncation fallback."""
from __future__ import annotations

import asyncio

import pytest

from dnsguard.resolver.forwarder import Forwarder, parse_server
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Flags, Rcode


def test_parse_server():
    assert parse_server("1.1.1.1") == ("1.1.1.1", 53)
    assert parse_server("1.1.1.1:5353") == ("1.1.1.1", 5353)
    assert parse_server("udp://9.9.9.9:53") == ("9.9.9.9", 53)
    assert parse_server("[2606:4700:4700::1111]:53") == ("2606:4700:4700::1111", 53)


def _answer_for(data: bytes, ip="4.3.2.1", tc=False) -> bytes:
    q = Message.parse(data)
    resp = q.reply(Rcode.NOERROR)
    if tc:
        resp.set_flag(Flags.TC, True)
    else:
        resp.answers.append(RR(q.question.name, Type.A, Class.IN, 60, R.A(ip)))
    return resp.to_wire()


class _FakeUDP(asyncio.DatagramProtocol):
    def __init__(self, ip, tc_first):
        self.ip = ip
        self.tc_first = tc_first  # truncate the UDP reply to force TCP
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, addr):
        self.transport.sendto(_answer_for(data, self.ip, tc=self.tc_first), addr)


async def _run_udp_server(ip="4.3.2.1", tc_first=False):
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(
        lambda: _FakeUDP(ip, tc_first), local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    return transport, port


async def _run_tcp_server(ip="4.3.2.1"):
    async def handle(reader, writer):
        hdr = await reader.readexactly(2)
        n = int.from_bytes(hdr, "big")
        data = await reader.readexactly(n)
        out = _answer_for(data, ip, tc=False)
        writer.write(len(out).to_bytes(2, "big") + out)
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


def mkquery(name="example.com"):
    m = Message(id=7)
    m.set_flag(Flags.RD, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


@pytest.mark.asyncio
async def test_forward_udp():
    transport, port = await _run_udp_server("4.3.2.1")
    try:
        fwd = Forwarder([f"127.0.0.1:{port}"], strategy="parallel", timeout=2)
        resp = await fwd.resolve(mkquery())
        assert resp.answers[0].rdata.to_text() == "4.3.2.1"
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_forward_tcp_fallback_on_truncation():
    udp_t, uport = await _run_udp_server("9.9.9.9", tc_first=True)
    tcp_s, tport = await _run_tcp_server("9.9.9.9")
    # bind TCP server onto same port as UDP? They differ; forwarder uses same port
    # for both, so run the TCP server on the UDP port by reusing it is not trivial.
    # Instead point both at one port via a combined server.
    udp_t.close(); tcp_s.close()
    # combined server on a single port:
    server, port = await _run_combined("9.9.9.9")
    try:
        fwd = Forwarder([f"127.0.0.1:{port}"], strategy="sequential", timeout=2)
        resp = await fwd.resolve(mkquery())
        assert resp.answers[0].rdata.to_text() == "9.9.9.9"
        assert resp.tc is False  # final answer came over TCP, untruncated
    finally:
        server.close()


async def _run_combined(ip):
    """UDP replies truncated (TC=1); TCP serves the full answer — same port."""
    loop = asyncio.get_running_loop()
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: _FakeUDP(ip, True), local_addr=("127.0.0.1", 0))
    port = udp_transport.get_extra_info("sockname")[1]

    async def handle(reader, writer):
        hdr = await reader.readexactly(2)
        n = int.from_bytes(hdr, "big")
        data = await reader.readexactly(n)
        out = _answer_for(data, ip, tc=False)
        writer.write(len(out).to_bytes(2, "big") + out)
        await writer.drain()
        writer.close()
    tcp_server = await asyncio.start_server(handle, "127.0.0.1", port)

    class _Combined:
        def close(self):
            udp_transport.close()
            tcp_server.close()
    return _Combined(), port
