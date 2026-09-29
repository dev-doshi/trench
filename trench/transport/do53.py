"""Plain DNS over UDP (:53) and TCP (:53), asyncio."""
from __future__ import annotations

import asyncio
import socket
import struct
import sys
from typing import TYPE_CHECKING

from ..errors import WireError
from ..log import get
from ..wire import Message
from .base import Frontend, not_a_query, process_query
from .stream import ConnectionTracker, StreamLimits, serve_stream

#: `socket.IP_PKTINFO` arrived in Python 3.12, and 3.11 is supported. Read
#: from the module alone, the answer-from-destination listener below was
#: silently off on 3.11 — the Docker bridge losing DNS again. The value is
#: the Linux kernel's; elsewhere there is nothing to fall back to.
_IP_PKTINFO: int | None = getattr(socket, "IP_PKTINFO", 8 if sys.platform == "linux" else None)

if TYPE_CHECKING:
    # Type-only. A transport is handed a pipeline; it does not need the
    # engine package at import time, and importing it for real closes a
    # cycle (engine -> resolver -> transport -> engine) that forces the
    # query path to keep every module lazily imported to break it.
    from ..engine import Pipeline

log = get("do53")

#: Receive buffer asked of the kernel for the UDP listener. The Linux default is
#: around 200 KB, a few hundred datagrams: a burst that arrives while the loop is
#: busy for a few milliseconds overflows it and the kernel drops the excess
#: before trench ever sees it. The kernel clamps this to `net.core.rmem_max`.
UDP_RCVBUF = 4 * 1024 * 1024

#: Replies asyncio may hold for a UDP socket the kernel will not take more from.
#: A datagram transport buffers without limit on EAGAIN, and nothing calls
#: `pause_writing` usefully for UDP, so past this the reply is dropped instead —
#: a UDP client that is not answered retries, a buffer that is not bounded grows.
UDP_MAX_SEND_BUFFER = 1024 * 1024


def _try_parse(data: bytes) -> Message | None:
    try:
        return Message.parse(data)
    except WireError:
        return None


def _limited(pipeline, client_ip: str) -> bool:
    """The pipeline's per-client rate limit, for what bypasses the pipeline.

    Transfers, NOTIFY and UPDATE go to the zone handler before the pipeline,
    and so also before its rate limiter: each one a zone walk, an HMAC or a
    database write, unmetered. Over the limit they are dropped rather than
    refused — a reply to a source that may be spoofed is owed nothing.
    """
    limiter = getattr(pipeline, "ratelimiter", None)
    return bool(limiter is not None and limiter.enabled and not limiter.allow(client_ip))


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
        self.send_dropped = 0      # replies shed because the socket was backed up
        self._tasks: set = set()   # strong refs to in-flight handlers
        self.fast = fast
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def _send(self, out: bytes, addr) -> None:
        transport = self.transport
        if transport is None:
            return
        # Every datagram transport asyncio ships implements this (it is how the
        # loop's own flow control reads the backlog); typeshed only declares it
        # on the write-transport base.
        if transport.get_write_buffer_size() > UDP_MAX_SEND_BUFFER:  # type: ignore[attr-defined]
            self.send_dropped += 1
            if self.send_dropped % 1000 == 1:
                log.warning("udp: send buffer full, dropping replies (%d dropped so far)",
                            self.send_dropped)
            return
        transport.sendto(out, addr)

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
                self._send(out, addr)
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
            if not_a_query(data):
                return
            if self.auth is not None:
                query = _try_parse(data)
                if query is not None and self.auth.claims(query):
                    if _limited(self.pipeline, addr[0]):
                        return
                    out = self.auth.handle_udp(data, query, addr[0])
                    if out:
                        self._send(out, addr)
                    return
            out = await process_query(self.pipeline, data, addr[0], "udp",
                                      stream=False, fast=self.fast)
            if out:
                self._send(out, addr)
        except Exception:
            log.exception("udp handler error")
        finally:
            self.inflight -= 1


def _wildcard(host: str) -> bool:
    return host in ("", "0.0.0.0", "::")


class _AnswerFromDestination(asyncio.DatagramTransport):
    """A UDP listener on the wildcard address that answers from the address
    each query was sent to.

    A wildcard socket replies from whichever local address the kernel picks
    for the route back. On a host with more than one address — a Docker
    bridge, a second IPv6 prefix, a VPN — that is not always the address the
    client asked, and a connected client (glibc's resolver is one) discards the
    reply as coming from a stranger. Every container on a Docker bridge lost DNS
    this way. asyncio's datagram transport drops the ancillary data that says
    where a datagram was sent, so this reads it with `recvmsg` and answers with
    `sendmsg`.

    The protocol sees an address with one extra element, the reply's source
    (as a control message); `addr[0]` is still the client.
    """

    _BATCH = 64            # datagrams per readiness callback, so others get a turn

    def __init__(self, loop, sock: socket.socket, protocol) -> None:
        super().__init__()
        self._loop, self._sock, self._protocol = loop, sock, protocol
        self._buf = bytearray(65535)
        self._cspace = socket.CMSG_SPACE(20)          # in6_pktinfo, the larger
        # A dual-stack socket reports IPv4 destinations as IPv4-mapped IPv6.
        if sock.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        else:
            assert _IP_PKTINFO is not None   # `start` builds this only when it is
            sock.setsockopt(socket.IPPROTO_IP, _IP_PKTINFO, 1)
        sock.setblocking(False)
        loop.add_reader(sock.fileno(), self._readable)
        protocol.connection_made(self)

    def _readable(self) -> None:
        for _ in range(self._BATCH):
            try:
                n, anc, _flags, src = self._sock.recvmsg_into([self._buf], self._cspace)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as e:           # an ICMP error queued on the socket
                log.debug("udp: %s", e)
                return
            self._protocol.datagram_received(bytes(self._buf[:n]),
                                             (*src, _reply_source(anc)))

    def sendto(self, data, addr=None) -> None:
        *dest, source = addr
        try:
            if source is not None:
                self._sock.sendmsg([data], [source], 0, tuple(dest))
            else:
                self._sock.sendto(data, tuple(dest))
        except (BlockingIOError, InterruptedError):
            pass                   # kernel queue full: a UDP client retries
        except OSError as e:
            log.debug("udp: reply to %s failed: %s", dest[0], e)

    def get_write_buffer_size(self) -> int:
        return 0                   # nothing is buffered here; see `sendto`

    def get_extra_info(self, name, default=None):
        return self._sock if name == "socket" else default

    def is_closing(self) -> bool:
        return self._sock.fileno() < 0

    def close(self) -> None:
        if not self.is_closing():
            self._loop.remove_reader(self._sock.fileno())
            self._sock.close()
            self._loop.call_soon(self._protocol.connection_lost, None)


def _reply_source(anc) -> tuple | None:
    """The control message that makes a reply leave from the address the query
    was sent to, or None to let the kernel choose."""
    for level, kind, data in anc:
        if level == socket.IPPROTO_IP and kind == _IP_PKTINFO:
            # in_pktinfo: ifindex, spec_dst, header destination. Reply from the
            # header destination and let routing pick the interface.
            return (level, kind, struct.pack("=I4s4s", 0, data[8:12], bytes(4)))
        if level == socket.IPPROTO_IPV6 and kind == socket.IPV6_PKTINFO:
            # in6_pktinfo: destination, ifindex. Echoed as is; the interface
            # matters for a link-local destination.
            return (level, kind, data[:20])
    return None


def _grow_rcvbuf(sock) -> None:
    """Raise the socket's receive buffer to `UDP_RCVBUF`; never lower it, since
    an operator may already have set it higher."""
    if sock is None:
        return
    try:
        if sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) < UDP_RCVBUF:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RCVBUF)
    except OSError as e:
        log.debug("could not raise the UDP receive buffer: %s", e)


def _bind_udp(host: str, port: int, reuse_port: bool) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if reuse_port:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind((host or "0.0.0.0", port))
    except OSError:
        sock.close()
        raise
    return sock


def _tcp_responder(pipeline: Pipeline, auth):
    """Turn one query's bytes into the wire responses to send back.

    Zone transfers answer with several messages, which must stay in order and
    consecutive — `serve_stream` emits a returned list in a single write, so an
    AXFR is never broken up by another query's answer.
    """
    async def respond(data: bytes, client_ip: str) -> list[bytes]:
        if not_a_query(data):
            return []
        if auth is not None:
            query = _try_parse(data)
            if query is not None and auth.claims(query):
                if _limited(pipeline, client_ip):
                    return []
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
            if _wildcard(self.host) and _IP_PKTINFO is not None:
                sock = self.sock_udp or _bind_udp(self.host, self.port, self.reuse_port)
                self._udp_transport = _AnswerFromDestination(loop, sock, make_udp())
            elif self.sock_udp is not None:
                self._udp_transport, _ = await loop.create_datagram_endpoint(
                    make_udp, sock=self.sock_udp)
            else:
                self._udp_transport, _ = await loop.create_datagram_endpoint(
                    make_udp, local_addr=(self.host, self.port),
                    reuse_port=self.reuse_port)
            _grow_rcvbuf(self._udp_transport.get_extra_info("socket"))
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
        if self.udp_protocol is not None:
            # Nothing is left to send their answers through.
            for task in list(self.udp_protocol._tasks):
                task.cancel()
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
