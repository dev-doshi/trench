"""DNS-over-QUIC (RFC 9250) via aioquic.

Each DNS exchange uses its own client-initiated bidirectional stream carrying a
2-octet length-prefixed DNS message (same framing as DoT/TCP). The server writes
the length-prefixed response and closes the stream.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

from ..log import get
from ..security.tls import ensure_cert
from .base import Frontend, resolve_wire
from .quiclimits import LimitedQuicProtocol
from .stream import ConnectionTracker, StreamLimits

if TYPE_CHECKING:
    # Type-only. A transport is handed a pipeline; it does not need the
    # engine package at import time, and importing it for real closes a
    # cycle (engine -> resolver -> transport -> engine) that forces the
    # query path to keep every module lazily imported to break it.
    from ..engine import Pipeline

log = get("doq")


class DoQProtocol(LimitedQuicProtocol, QuicConnectionProtocol):
    pipeline: Pipeline = None  # type: ignore[assignment]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._buffers: dict[int, bytearray] = {}
        self._tasks: set = set()   # strong refs to in-flight handlers

    def quic_event_received(self, event: QuicEvent) -> None:
        if not self.note_quic_event(event):
            return
        if isinstance(event, StreamDataReceived):
            buf = self._buffers.setdefault(event.stream_id, bytearray())
            buf += event.data
            if event.end_stream or self._complete(buf):
                data = bytes(buf)
                self._buffers.pop(event.stream_id, None)
                task = asyncio.ensure_future(self._answer(event.stream_id, data))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)

    @staticmethod
    def _complete(buf: bytearray) -> bool:
        if len(buf) < 2:
            return False
        length = int.from_bytes(buf[:2], "big")
        return len(buf) - 2 >= length

    async def _answer(self, stream_id: int, data: bytes) -> None:
        try:
            if len(data) < 2:
                return
            length = int.from_bytes(data[:2], "big")
            wire = data[2:2 + length]
            peer = self._quic._network_paths[0].addr[0] if self._quic._network_paths else "?"
            resp = await resolve_wire(self.pipeline, wire, peer, "quic")
            if resp is not None:
                out = resp.to_wire()
                self._quic.send_stream_data(stream_id, len(out).to_bytes(2, "big") + out,
                                            end_stream=True)
                self.transmit()
        except Exception:
            log.exception("doq answer error")


class DoQServer(Frontend):
    proto = "quic"

    def __init__(self, pipeline: Pipeline, host: str, port: int,
                 cert: str | None, key: str | None, data_dir: Path,
                 limits: StreamLimits | None = None):
        self.pipeline = pipeline
        self.host = host
        self.port = port
        # The same caps the other connection-oriented frontends carry. A QUIC
        # connection holds TLS state and a flow-control window, so "as many as
        # peers ask for" is not a bound.
        self.limits = limits or StreamLimits()
        self.tracker = ConnectionTracker(self.limits)
        cert_path, key_path = ensure_cert(cert, key, data_dir, [host, "localhost"])
        self._config = QuicConfiguration(is_client=False, alpn_protocols=["doq"])
        self._config.load_cert_chain(str(cert_path), str(key_path))
        self._server = None

    async def start(self) -> None:
        pipeline = self.pipeline

        tracker = self.tracker

        def factory(*args, **kwargs):
            proto = DoQProtocol(*args, **kwargs)
            proto.pipeline = pipeline
            proto.tracker = tracker
            return proto

        self._server = await serve(self.host, self.port, configuration=self._config,
                                   create_protocol=factory)
        log.info("DoQ listening on %s:%d (udp)", self.host, self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
