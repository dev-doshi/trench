"""Plain DNS over UDP (:53) and TCP (:53), asyncio."""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from ..errors import WireError
from ..log import get
from ..wire import Message
from .base import Frontend, process_query
from .stream import ConnectionTracker, StreamLimits, serve_stream

if TYPE_CHECKING:
    # Type-only. A transport is handed a pipeline; it does not need the
    # engine package at import time, and importing it for real closes a
    # cycle (engine -> resolver -> transport -> engine) that forces the
    # query path to keep every module lazily imported to break it.
    from ..engine import Pipeline

log = get("do53")


def _try_parse(data: bytes) -> Message | None:
    try:
        return Message.parse(data)
    except WireError:
        return None


class _UDPProtocol(asyncio.DatagramProtocol):
    """UDP listener with a bound on concurrent work.

    Every datagram used to become a task unconditionally. Per-client rate limiting
    runs *inside* the pipeline, so a flood was already allocating a task, a parsed
    message and a context before anything could decide to refuse it — the defence
    sat behind the cost it was meant to avoid. Excess datagrams are now dropped,
    which is also the right answer for UDP: a source address that may be spoofed
    is owed nothing.

    Rate-limited queries still get a REFUSED response rather than a drop. That
    reply is about the size of the query, so it is no use as an amplifier, and a
    real client deserves to be told rather than left to time out.
    """

    def __init__(self, pipeline: Pipeline, auth=None, max_inflight: int = 2048,
                 fast=None):
        self.pipeline = pipeline
        self.auth = auth
        self.max_inflight = max_inflight
        self.inflight = 0
        self.dropped = 0
        self._tasks: set = set()   # strong refs to in-flight handlers
        self.fast = fast
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        # A replayable query is answered here, in the callback, without ever
        # becoming a Task. Spawning one costs ~2.5 us and defers the reply by a
        # whole event-loop turn — which is several times the entire cost of the
        # answer it is scheduling. Anything the fast path declines falls through
        # to the normal asynchronous path untouched.
        fast = self.fast
        if fast is not None and self.transport is not None:
            try:
                out = fast.serve(data, addr[0])
            except Exception:               # never let an optimisation drop a query
                log.exception("fast path error; falling back")
                out = None
            if out is not None:
                self.transport.sendto(out, addr)
                return
        if self.max_inflight and self.inflight >= self.max_inflight:
            self.dropped += 1
            if self.dropped % 1000 == 1:
                log.warning("udp: %d queries in flight, dropping (%d dropped so far)",
                            self.inflight, self.dropped)
            return
        self.inflight += 1
        # Held in a set until done. The loop keeps only a weak reference to a
        # task, so one created and dropped like this can be garbage-collected
        # mid-flight: the query vanishes and `inflight` is never decremented,
        # permanently lowering the effective max_inflight ceiling.
        task = asyncio.ensure_future(self._handle(data, addr))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, data: bytes, addr) -> None:
        try:
            if self.auth is not None:
                query = _try_parse(data)
                if query is not None and self.auth.claims(query):
                    out = self.auth.handle_udp(data, query, addr[0])
                    if out and self.transport is not None:
                        self.transport.sendto(out, addr)
                    return
            out = await process_query(self.pipeline, data, addr[0], "udp",
                                      stream=False, fast=self.fast)
            if out and self.transport is not None:
                self.transport.sendto(out, addr)
        except Exception:
            log.exception("udp handler error")
        finally:
            self.inflight -= 1


def _tcp_responder(pipeline: Pipeline, auth):
    """Turn one query's bytes into the wire responses to send back.

    Zone transfers answer with several messages, which must stay in order and
    consecutive — `serve_stream` emits a returned list in a single write, so an
    AXFR is never broken up by another query's answer.
    """
    async def respond(data: bytes, client_ip: str) -> list[bytes]:
        if auth is not None:
            query = _try_parse(data)
            if query is not None and auth.claims(query):
                return list(auth.handle_tcp(data, query, client_ip))
        out = await process_query(pipeline, data, client_ip, "tcp", stream=True)
        return [out] if out else []
    return respond


class Do53Server(Frontend):
    proto = "do53"

    def __init__(self, pipeline: Pipeline, host: str, port: int,
                 udp: bool = True, tcp: bool = True, reuse_port: bool = False,
                 sock_udp=None, sock_tcp=None, auth=None,
                 limits: StreamLimits | None = None, udp_max_inflight: int = 2048,
                 fast=None):
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self.udp = udp
        self.tcp = tcp
        self.auth = auth               # optional AuthHandler for AXFR/NOTIFY/UPDATE
        self.reuse_port = reuse_port
        self.limits = limits or StreamLimits()
        self.tracker = ConnectionTracker(self.limits)
        self.udp_max_inflight = udp_max_inflight
        self.fast = fast               # optional FastPath (wire-resident replay)
        self.udp_protocol: _UDPProtocol | None = None
        # pre-bound sockets shared across forked workers (portable multi-core)
        self.sock_udp = sock_udp
        self.sock_tcp = sock_tcp
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        if self.udp:
            def make_udp():
                self.udp_protocol = _UDPProtocol(self.pipeline, self.auth,
                                                 self.udp_max_inflight, self.fast)
                return self.udp_protocol
            if self.sock_udp is not None:
                self._udp_transport, _ = await loop.create_datagram_endpoint(
                    make_udp, sock=self.sock_udp)
            else:
                self._udp_transport, _ = await loop.create_datagram_endpoint(
                    make_udp, local_addr=(self.host, self.port),
                    reuse_port=self.reuse_port)
        if self.tcp:
            respond = _tcp_responder(self.pipeline, self.auth)

            def handle(r, w):
                return serve_stream(r, w, respond, proto="tcp",
                                    limits=self.limits, tracker=self.tracker)
            if self.sock_tcp is not None:
                self._tcp_server = await asyncio.start_server(handle, sock=self.sock_tcp)
            else:
                self._tcp_server = await asyncio.start_server(
                    handle, self.host, self.port, reuse_port=self.reuse_port)
        log.info("Do53 listening on %s:%d (udp=%s tcp=%s)",
                 self.host, self.port, self.udp, self.tcp)

    async def stop(self) -> None:
        if self._udp_transport is not None:
            self._udp_transport.close()
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
