"""End-to-end transport tests: DoT, DoH (wire GET/POST + JSON), DoQ.

Each spins the real frontend against a pipeline with a fake forwarder, then
queries it with a real client of that protocol.
"""
from __future__ import annotations

import asyncio
import base64
import socket
import ssl
from pathlib import Path

import pytest

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.filter import SimpleEngine
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode

CERT_DIR = Path("./data")


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FakeForwarder:
    async def resolve(self, query: Message) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("93.184.216.34")))
        return resp


def build_pipeline() -> Pipeline:
    return Pipeline(filter_engine=SimpleEngine(blocked={"doubleclick.net"}),
                    cache=Cache(), forwarder=FakeForwarder(),
                    counters=Counters(), config=Config())


def mkquery(name="example.com", rtype=Type.A, do=True):
    from dnsguard.wire.edns import Edns
    m = Message(id=0x4242)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    m.edns = Edns(udp_size=1232)
    m.edns.do = do
    return m


# --- DoT ---
@pytest.mark.asyncio
async def test_dot():
    from dnsguard.transport.dot import DoTServer
    port = free_port()
    srv = DoTServer(build_pipeline(), "127.0.0.1", port, None, None, CERT_DIR)
    await srv.start()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["dot"])
        reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=ctx)
        wire = mkquery().to_wire()
        writer.write(len(wire).to_bytes(2, "big") + wire)
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(2), 5)
        n = int.from_bytes(hdr, "big")
        data = await asyncio.wait_for(reader.readexactly(n), 5)
        resp = Message.parse(data)
        assert resp.answers[0].rdata.to_text() == "93.184.216.34"
        # padded to a 468-byte block boundary
        assert len(data) % 468 == 0
        writer.close()
    finally:
        await srv.stop()


# --- DoH ---
@pytest.mark.asyncio
async def test_doh_wire_and_json():
    import aiohttp

    from dnsguard.transport.doh import DoHServer
    port = free_port()
    srv = DoHServer(build_pipeline(), "127.0.0.1", port, "/dns-query", tls=False)
    await srv.start()
    url = f"http://127.0.0.1:{port}/dns-query"
    try:
        async with aiohttp.ClientSession() as s:
            wire = mkquery().to_wire()
            # POST
            async with s.post(url, data=wire,
                              headers={"Content-Type": "application/dns-message"}) as r:
                assert r.status == 200
                resp = Message.parse(await r.read())
                assert resp.answers[0].rdata.to_text() == "93.184.216.34"
            # GET ?dns=
            b64 = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
            async with s.get(url + "?dns=" + b64) as r:
                assert r.status == 200
                assert Message.parse(await r.read()).answers
            # JSON API
            async with s.get(url + "?name=example.com&type=A") as r:
                j = await r.json(content_type=None)
                assert j["Status"] == 0
                assert any(a["data"] == "93.184.216.34" for a in j["Answer"])
            # blocked via JSON
            async with s.get(url + "?name=doubleclick.net&type=A") as r:
                j = await r.json(content_type=None)
                assert any(a["data"] == "0.0.0.0" for a in j["Answer"])
    finally:
        await srv.stop()


# --- DoQ ---
@pytest.mark.asyncio
async def test_doq():
    from aioquic.asyncio import QuicConnectionProtocol, connect
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import StreamDataReceived

    from dnsguard.transport.doq import DoQServer

    port = free_port()
    srv = DoQServer(build_pipeline(), "127.0.0.1", port, None, None, CERT_DIR)
    await srv.start()

    class _Client(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.fut = asyncio.get_event_loop().create_future()
            self.buf = bytearray()

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                self.buf += event.data
                if event.end_stream and not self.fut.done():
                    self.fut.set_result(bytes(self.buf))

    config = QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    config.verify_mode = ssl.CERT_NONE
    try:
        async with connect("127.0.0.1", port, configuration=config,
                           create_protocol=_Client) as client:
            wire = mkquery().to_wire()
            sid = client._quic.get_next_available_stream_id()
            client._quic.send_stream_data(sid, len(wire).to_bytes(2, "big") + wire,
                                          end_stream=True)
            client.transmit()
            data = await asyncio.wait_for(client.fut, 5)
            resp = Message.parse(data[2:])  # strip 2-byte length prefix
            assert resp.answers[0].rdata.to_text() == "93.184.216.34"
    finally:
        await srv.stop()


# --- DoH3 (HTTP/3) ---
@pytest.mark.asyncio
async def test_doh3():
    from aioquic.asyncio import QuicConnectionProtocol, connect
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration

    from dnsguard.transport.doh3 import DoH3Server

    port = free_port()
    srv = DoH3Server(build_pipeline(), "127.0.0.1", port, "/dns-query", None, None, CERT_DIR)
    await srv.start()

    class _H3Client(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._http = None
            self.fut = asyncio.get_event_loop().create_future()
            self.body = bytearray()

        def quic_event_received(self, event):
            if self._http is None:
                self._http = H3Connection(self._quic)
            for e in self._http.handle_event(event):
                if isinstance(e, DataReceived):
                    self.body += e.data
                    if e.stream_ended and not self.fut.done():
                        self.fut.set_result(bytes(self.body))
                elif isinstance(e, HeadersReceived) and e.stream_ended and not self.fut.done():
                    self.fut.set_result(bytes(self.body))

    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    config.verify_mode = ssl.CERT_NONE
    try:
        async with connect("127.0.0.1", port, configuration=config,
                           create_protocol=_H3Client) as client:
            wire = mkquery().to_wire()
            b64 = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
            sid = client._quic.get_next_available_stream_id()
            client._http = client._http or H3Connection(client._quic)
            client._http.send_headers(sid, [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", f"/dns-query?dns={b64}".encode()),
            ], end_stream=True)
            client.transmit()
            data = await asyncio.wait_for(client.fut, 5)
            resp = Message.parse(data)
            assert resp.answers[0].rdata.to_text() == "93.184.216.34"
    finally:
        await srv.stop()
