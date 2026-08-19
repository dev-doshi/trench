"""DNS-over-HTTP/3 (DoH3): RFC 8484 semantics carried over HTTP/3 / QUIC.

Reuses the DoH request handling (GET ?dns=, POST application/dns-message) but
frames it with aioquic's H3Connection instead of aiohttp.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

from ..engine import Pipeline
from ..log import get
from ..security.tls import ensure_cert
from .base import resolve_wire
from .doh import _b64url_decode

log = get("doh3")


class _Stream:
    __slots__ = ("method", "path", "body", "ended")

    def __init__(self) -> None:
        self.method = ""
        self.path = "/"
        self.body = bytearray()
        self.ended = False


class DoH3Protocol(QuicConnectionProtocol):
    pipeline: Pipeline = None  # type: ignore[assignment]
    doh_path: str = "/dns-query"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http: H3Connection | None = None
        self._streams: dict[int, _Stream] = {}
        self._tasks: set = set()   # strong refs to in-flight handlers

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._http is None:
            self._http = H3Connection(self._quic)
        for h3event in self._http.handle_event(event):
            if isinstance(h3event, HeadersReceived):
                self._on_headers(h3event)
            elif isinstance(h3event, DataReceived):
                self._on_data(h3event)

    def _on_headers(self, event: HeadersReceived) -> None:
        st = self._streams.setdefault(event.stream_id, _Stream())
        for k, v in event.headers:
            if k == b":method":
                st.method = v.decode()
            elif k == b":path":
                st.path = v.decode()
        if event.stream_ended:
            task = asyncio.ensure_future(self._respond(event.stream_id))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    def _on_data(self, event: DataReceived) -> None:
        st = self._streams.setdefault(event.stream_id, _Stream())
        st.body += event.data
        if event.stream_ended:
            task = asyncio.ensure_future(self._respond(event.stream_id))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _respond(self, stream_id: int) -> None:
        st = self._streams.pop(stream_id, None)
        if st is None or self._http is None:
            return
        try:
            wire = self._extract_query(st)
            if wire is None:
                self._send(stream_id, 400, b"bad request", b"text/plain")
                return
            peer = self._quic._network_paths[0].addr[0] if self._quic._network_paths else "?"
            resp = await resolve_wire(self.pipeline, wire, peer, "h3")
            if resp is None:
                self._send(stream_id, 400, b"malformed", b"text/plain")
                return
            self._send(stream_id, 200, resp.to_wire(), b"application/dns-message")
        except Exception:
            log.exception("doh3 respond error")

    def _extract_query(self, st: _Stream) -> bytes | None:
        if st.method == "POST":
            return bytes(st.body)
        q = parse_qs(urlsplit(st.path).query)
        if "dns" in q:
            try:
                return _b64url_decode(q["dns"][0])
            except Exception:
                return None
        return None

    def _send(self, stream_id: int, status: int, body: bytes, ctype: bytes) -> None:
        assert self._http is not None
        self._http.send_headers(stream_id, [
            (b":status", str(status).encode()),
            (b"content-type", ctype),
            (b"content-length", str(len(body)).encode()),
        ])
        self._http.send_data(stream_id, body, end_stream=True)
        self.transmit()


class DoH3Server:
    proto = "h3"

    def __init__(self, pipeline: Pipeline, host: str, port: int, path: str,
                 cert: str | None, key: str | None, data_dir: Path):
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self.path = path
        cert_path, key_path = ensure_cert(cert, key, data_dir, [host, "localhost"])
        self._config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        self._config.load_cert_chain(str(cert_path), str(key_path))
        self._server = None

    async def start(self) -> None:
        pipeline, path = self.pipeline, self.path

        def factory(*args, **kwargs):
            proto = DoH3Protocol(*args, **kwargs)
            proto.pipeline = pipeline
            proto.doh_path = path
            return proto

        self._server = await serve(self.host, self.port, configuration=self._config,
                                   create_protocol=factory)
        log.info("DoH3 listening on %s:%d (udp/h3)", self.host, self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
