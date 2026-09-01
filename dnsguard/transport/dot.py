"""DNS-over-TLS (RFC 7858): length-prefixed DNS messages over a TLS stream."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from ..log import get
from ..security.tls import server_ssl_context
from .base import Frontend, resolve_wire
from .stream import ConnectionTracker, StreamLimits, serve_stream

if TYPE_CHECKING:
    # Type-only. A transport is handed a pipeline; it does not need the
    # engine package at import time, and importing it for real closes a
    # cycle (engine -> resolver -> transport -> engine) that forces the
    # query path to keep every module lazily imported to break it.
    from ..engine import Pipeline

log = get("dot")


def stream_responder(pipeline: Pipeline, proto: str):
    """One query's bytes -> the wire response, for `serve_stream`."""
    async def respond(data: bytes, client_ip: str) -> list[bytes]:
        resp = await resolve_wire(pipeline, data, client_ip, proto)
        return [resp.to_wire()] if resp is not None else []
    return respond


class DoTServer(Frontend):
    proto = "tls"

    def __init__(self, pipeline: Pipeline, host: str, port: int,
                 cert: str | None, key: str | None, data_dir: Path,
                 limits: StreamLimits | None = None):
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self._ssl = server_ssl_context(cert, key, data_dir=data_dir,
                                       alpn=["dot"], hostnames=[host, "localhost"])
        self._server: asyncio.AbstractServer | None = None
        # An idle DoT connection has already cost a TLS handshake, so the caps
        # matter more here than on plain TCP, not less.
        self.limits = limits or StreamLimits()
        self.tracker = ConnectionTracker(self.limits)

    async def start(self) -> None:
        respond = stream_responder(self.pipeline, "tls")
        self._server = await asyncio.start_server(
            lambda r, w: serve_stream(r, w, respond, proto="tls",
                                      limits=self.limits, tracker=self.tracker),
            self.host, self.port, ssl=self._ssl)
        log.info("DoT listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
