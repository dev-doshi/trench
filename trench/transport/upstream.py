"""Upstream resolver transports + spec parsing + per-domain routing.

Spec forms:
    1.1.1.1                     plain UDP/TCP (port 53)
    1.1.1.1:5353
    tcp://1.1.1.1
    tls://1.1.1.1#dns.quad9.net          DoT (SNI/verify name after #)
    https://dns.google/dns-query         DoH
    quic://dns.adguard.com               DoQ
    [/example.com/]192.168.1.1           per-domain routing (handled by Router)
"""
from __future__ import annotations

import asyncio
import copy
import random
import secrets
import ssl
from dataclasses import dataclass, field

from ..errors import UpstreamError
from ..log import get
from ..wire import Message
from ..wire.name import suffixes
from ..wire.rrtypes import Flags

log = get("upstream")


@dataclass
class UpstreamSpec:
    scheme: str          # udp | tcp | tls | https | quic
    host: str
    port: int
    sni: str = ""        # TLS server name / verify name
    path: str = "/dns-query"
    domains: tuple[str, ...] = ()   # per-domain routing triggers ([/d/])


def parse_upstream(spec: str) -> UpstreamSpec:
    spec = spec.strip()
    domains: tuple[str, ...] = ()
    if spec.startswith("[/"):
        end = spec.index("]")
        inner = spec[2:end].strip("/")
        domains = tuple(d for d in inner.split("/") if d)
        spec = spec[end + 1:].strip()

    scheme = "udp"
    for s in ("udp", "tcp", "tls", "https", "quic"):
        if spec.startswith(s + "://"):
            scheme = s
            spec = spec[len(s) + 3:]
            break

    sni = ""
    path = "/dns-query"
    if scheme == "https":
        # host[:port]/path
        rest = spec
        if "/" in rest:
            hostport, _, p = rest.partition("/")
            path = "/" + p
        else:
            hostport = rest
        host, port = _split_hostport(hostport, 443)
        sni = host
    else:
        if "#" in spec:
            spec, sni = spec.split("#", 1)
        default_port = 853 if scheme in ("tls", "quic") else 53
        host, port = _split_hostport(spec, default_port)
        if scheme in ("tls", "quic") and not sni:
            sni = host
    return UpstreamSpec(scheme, host, port, sni, path, domains)


def _split_hostport(s: str, default_port: int) -> tuple[str, int]:
    if s.startswith("["):  # [ipv6]:port
        host, _, rest = s[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if s.count(":") == 1:
        host, _, port = s.partition(":")
        return host, int(port)
    return s, default_port


class _UdpSocket(asyncio.DatagramProtocol):
    """One long-lived, connected UDP socket carrying several queries at once.

    Replies are dispatched by transaction id, because more than one query can be
    outstanding on the same socket and UDP does not promise order.
    """

    __slots__ = ("pending", "transport", "pool", "closed")

    def __init__(self, pool: UdpPool | None = None) -> None:
        self.pending: dict[int, asyncio.Future] = {}
        self.transport: asyncio.DatagramTransport | None = None
        self.pool = pool
        self.closed = False

    def connection_made(self, transport) -> None:
        self.transport = transport

    def connection_lost(self, exc: Exception | None) -> None:
        """Take a dead socket out of the pool.

        Without this a socket whose transport closed stayed in the pool and kept
        being selected: `sendto` on it is silently dropped, so every query
        routed there timed out — permanently, for 1/N of all upstream traffic,
        until the process restarted.
        """
        self.closed = True
        if self.pool is not None:
            self.pool.discard(self)
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(UpstreamError("upstream socket closed"))
        self.pending.clear()

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) < 2:
            return
        fut = self.pending.pop((data[0] << 8) | data[1], None)
        if fut is not None and not fut.done():
            fut.set_result(data)

    def error_received(self, exc: Exception) -> None:
        # A connected UDP socket surfaces ICMP errors here. Nothing identifies
        # which query they belong to, so everything waiting on this socket fails
        # and is retried elsewhere.
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(exc)
        self.pending.clear()

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()


class UdpPool:
    """A fixed set of connected UDP sockets, one picked at random per query.

    Opening a socket per query — which is what this replaces — costs 67 us
    measured, and buys the full ~15 bits of ephemeral-port entropy that RFC 5452
    asks for. A pool of N costs 0.2 us and buys log2(N) bits. That is a real
    trade, not a free win, so it is stated rather than buried:

        socket per query   ~15 bits of port entropy + 16 bits of transaction id
        pool of 1024        10 bits + 16
        pool of 4096        12 bits + 16   (what Unbound ships by default)

    `security.use_0x20` is the cheap way to buy the difference back and more: on
    a name like `www.example.com` it adds ~15 bits per query, independently of
    the port. Setting `upstream.udp_source_ports: 0` restores a socket per query
    for anyone who would rather pay the microseconds.

    Sockets are opened all at once on first use, because entropy comes from how
    many exist — a pool that grows on demand would start out predictable.
    """

    def __init__(self, host: str, port: int, size: int):
        self.host = host
        self.port = port
        self.size = size
        self._socks: list[_UdpSocket] = []
        self._lock = asyncio.Lock()
        # What the pool settled for. Lowered if the box runs out of descriptors,
        # so a capped pool refills to the size it can actually reach instead of
        # re-attempting the impossible on every query.
        self._target = size

    def discard(self, sock: _UdpSocket) -> None:
        """Drop a socket that reported its transport gone (see connection_lost)."""
        try:
            self._socks.remove(sock)
        except ValueError:
            pass

    async def _ensure(self) -> None:
        # Refill when sockets have died, not only on first use. Returning as
        # soon as the list was non-empty meant a pool that had lost sockets
        # never recovered them, and its port entropy quietly shrank with it.
        if len(self._socks) >= self._target:
            return
        async with self._lock:
            if len(self._socks) >= self._target:
                return
            loop = asyncio.get_running_loop()
            socks = list(self._socks)
            for _ in range(self.size - len(socks)):
                try:
                    _t, proto = await loop.create_datagram_endpoint(
                        lambda: _UdpSocket(self), remote_addr=(self.host, self.port))
                except OSError as e:
                    if not socks:
                        raise
                    # Ran out of descriptors. A smaller pool is weaker, not
                    # broken, so say so once and carry on with what we have.
                    log.warning("udp pool for %s:%d capped at %d sockets (%s)",
                                self.host, self.port, len(socks), e)
                    self._target = len(socks)
                    break
                socks.append(proto)
            self._socks = socks

    async def query(self, wire: bytes, timeout: float) -> bytes:
        await self._ensure()
        txid = (wire[0] << 8) | wire[1]
        # Pick a socket that is not already waiting on this transaction id;
        # otherwise two replies would be indistinguishable to the dispatcher.
        sock = random.choice(self._socks)
        if txid in sock.pending:
            for cand in random.sample(self._socks, min(8, len(self._socks))):
                if txid not in cand.pending:
                    sock = cand
                    break
            else:
                raise UpstreamError("no free upstream socket for this query id")
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        sock.pending[txid] = fut
        try:
            sock.transport.sendto(wire)          # type: ignore[union-attr]
            return await asyncio.wait_for(fut, timeout)
        finally:
            sock.pending.pop(txid, None)

    def close(self) -> None:
        for s in self._socks:
            s.close()
        self._socks = []


class _StreamConn:
    """One persistent DNS-over-TCP/TLS connection (RFC 7766).

    A fresh TLS handshake per query is both slow and a good way to get reset by
    a public resolver under load, so the connection is kept open and queries are
    multiplexed over it: each gets a connection-local message ID, and a reader
    task dispatches replies back to the right waiter (responses may arrive out
    of order). A dropped connection fails its in-flight waiters and is
    transparently reopened on the next query.
    """

    def __init__(self, up: Upstream):
        self.up = up
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._next_id = 0
        self.closed = True

    async def _open(self) -> None:
        spec = self.up.spec
        ssl_ctx = self.up._tls_ctx(["dot"]) if spec.scheme == "tls" else None
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(
                spec.host, spec.port, ssl=ssl_ctx,
                server_hostname=(spec.sni or spec.host) if ssl_ctx else None),
            self.up.timeout)
        self.closed = False
        self._reader_task = asyncio.ensure_future(self._read_loop())

    async def _read_loop(self) -> None:
        try:
            while True:
                hdr = await self.reader.readexactly(2)          # type: ignore[union-attr]
                n = int.from_bytes(hdr, "big")
                data = await self.reader.readexactly(n)         # type: ignore[union-attr]
                if len(data) >= 2:
                    fut = self._pending.pop(int.from_bytes(data[:2], "big"), None)
                    if fut is not None and not fut.done():
                        fut.set_result(data)
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError, OSError) as e:
            self._abort(e)
        except asyncio.CancelledError:
            self._abort(ConnectionError("connection closed"))
        finally:
            self.closed = True

    def _abort(self, exc: BaseException) -> None:
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(exc)
        self._pending.clear()
        self.closed = True

    def _alloc_id(self) -> int:
        for _ in range(65536):
            self._next_id = (self._next_id + 1) & 0xFFFF
            if self._next_id not in self._pending:
                return self._next_id
        raise RuntimeError("no free DNS message id")

    async def query(self, wire: bytes) -> bytes:
        async with self._lock:
            if self.closed or self.writer is None or self.writer.is_closing():
                await self._open()
        mid = self._alloc_id()
        out = mid.to_bytes(2, "big") + wire[2:]         # rewrite id for multiplexing
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[mid] = fut
        try:
            self.writer.write(len(out).to_bytes(2, "big") + out)   # type: ignore[union-attr]
            await self.writer.drain()                              # type: ignore[union-attr]
            return await asyncio.wait_for(fut, self.up.timeout)
        finally:
            self._pending.pop(mid, None)

    async def close(self) -> None:
        if self._reader_task is not None:
            self._reader_task.cancel()
            self._reader_task = None
        self._abort(ConnectionError("closed"))
        if self.writer is not None:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass
            self.writer = None
        self.closed = True


def _check_response(resp: Message, sent: Message, *, check_id: bool) -> None:
    """Reject an upstream answer that does not answer the question we asked.

    Without this an off-path spoofer only has to win the race, never guess the
    transaction id — and a buggy or hostile upstream could substitute a record
    for an entirely different name. The name is compared case-insensitively;
    strict 0x20 case verification is a separate, stricter check applied further
    up, where the original casing is known.
    """
    if check_id and resp.id != sent.id:
        raise UpstreamError(f"upstream id mismatch (got {resp.id}, sent {sent.id})")
    if not resp.qr:
        raise UpstreamError("upstream reply is not a response")
    want, got = sent.question, resp.question
    if want is None:
        return
    if got is None:
        # A response may legitimately omit the question only when it carries no
        # records at all to attribute (e.g. FORMERR); anything else is
        # unattributable. Checking only `answers` left the authority and
        # additional sections free to carry whatever the sender liked — and
        # sanitize() cannot filter them either, having no question to work from.
        if resp.answers or resp.authority or resp.additional:
            raise UpstreamError("upstream response has records but no question")
        return
    if got.name != want.name or got.rtype != want.rtype or got.rclass != want.rclass:
        raise UpstreamError(f"upstream answered a different question "
                        f"({got.name.to_text()} {got.rtype} vs "
                        f"{want.name.to_text()} {want.rtype})")


class Upstream:
    # Transports where the peer's identity is cryptographically established, so
    # its DNSSEC-validation claim comes from who we think it does.
    AUTHENTICATED_SCHEMES = frozenset({"tls", "https", "quic"})

    def __init__(self, spec: UpstreamSpec, *, timeout: float = 4.0, verify: bool = True,
                 trust_ad: str = "auto", udp_source_ports: int = 0):
        self.spec = spec
        self.timeout = timeout
        self.verify = verify
        self.trust_ad = trust_ad
        self.rtt = 0.05
        self.failures = 0
        self._session = None  # aiohttp session for DoH
        self._conn: _StreamConn | None = None  # persistent TCP/DoT connection
        self._pool: UdpPool | None = None
        if udp_source_ports > 0 and spec.scheme == "udp":
            self._pool = UdpPool(spec.host, spec.port, udp_source_ports)

    def __repr__(self) -> str:
        return f"{self.spec.scheme}://{self.spec.host}:{self.spec.port}"

    async def query(self, msg: Message) -> Message:
        scheme = self.spec.scheme
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        try:
            if scheme == "udp":
                # RFC 5452: a forwarder must not reuse the client's transaction
                # ID upstream. The client picked it and may well be the attacker;
                # reusing it hands away 16 bits an off-path spoofer would
                # otherwise have to guess. Source-port randomisation comes free
                # from opening a fresh socket per query.
                sent = copy.copy(msg)
                sent.id = secrets.randbelow(65536)
                wire = sent.to_wire()
                data = await self._udp(wire)
                resp = Message.parse(data)
                _check_response(resp, sent, check_id=True)
                if resp.tc:
                    resp = Message.parse(await self._tcp(wire))
                    _check_response(resp, sent, check_id=True)
                resp.id = msg.id          # hand the client back its own id
            elif scheme in ("tcp", "tls"):
                wire = msg.to_wire()
                resp = Message.parse(await self._stream(wire))
                # the id is connection-local and already matched by the reader
                _check_response(resp, msg, check_id=False)
                resp.id = msg.id          # undo the connection-local id used to multiplex
            elif scheme == "https":
                resp = Message.parse(await self._doh(msg.to_wire()))
                _check_response(resp, msg, check_id=False)  # RFC 8484: id is 0
            elif scheme == "quic":
                resp = Message.parse(await self._doq(msg.to_wire()))
                _check_response(resp, msg, check_id=False)
            else:
                raise ValueError(f"unknown scheme {scheme}")
            if not self._ad_trusted():
                # We did not validate, and over plaintext anyone can set this.
                resp.set_flag(Flags.AD, False)
            self.rtt = 0.8 * self.rtt + 0.2 * (loop.time() - t0)
            self.failures = 0
            return resp
        except Exception:
            self.failures += 1
            raise

    def _ad_trusted(self) -> bool:
        if self.trust_ad == "always":
            return True
        if self.trust_ad == "never":
            return False
        return self.spec.scheme in self.AUTHENTICATED_SCHEMES

    # --- transports ---
    async def _udp(self, wire: bytes) -> bytes:
        if self._pool is not None:
            return await self._pool.query(wire, self.timeout)
        # udp_source_ports = 0: a fresh socket per query, for the full ~15 bits
        # of ephemeral-port entropy. Costs 67 us; see UdpPool for the arithmetic.
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        proto = _UdpSocket()
        proto.pending[(wire[0] << 8) | wire[1]] = fut
        transport, _ = await loop.create_datagram_endpoint(
            lambda: proto, remote_addr=(self.spec.host, self.spec.port))
        try:
            transport.sendto(wire)
            return await asyncio.wait_for(fut, self.timeout)
        finally:
            transport.close()

    async def _stream(self, wire: bytes) -> bytes:
        """Query over the pooled TCP/DoT connection, reopening once if the peer
        dropped an idle connection between queries."""
        if self._conn is None:
            self._conn = _StreamConn(self)
        try:
            return await self._conn.query(wire)
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError, OSError):
            await self._conn.close()
            return await self._conn.query(wire)

    async def _tcp(self, wire: bytes, ssl_ctx=None) -> bytes:
        """One-shot TCP query on a dedicated connection (used for UDP truncation
        fallback, where the pooled connection may be a different transport)."""
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.spec.host, self.spec.port, ssl=ssl_ctx,
                                    server_hostname=self.spec.sni or None if ssl_ctx else None),
            self.timeout)
        try:
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
            hdr = await asyncio.wait_for(reader.readexactly(2), self.timeout)
            n = int.from_bytes(hdr, "big")
            return await asyncio.wait_for(reader.readexactly(n), self.timeout)
        finally:
            writer.close()

    def _tls_ctx(self, alpn: list[str]) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(alpn)
        if not self.verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _doh(self, wire: bytes) -> bytes:
        import aiohttp
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=False if not self.verify else None)
            self._session = aiohttp.ClientSession(connector=connector)
        url = f"https://{self.spec.host}:{self.spec.port}{self.spec.path}"
        headers = {"Content-Type": "application/dns-message",
                   "Accept": "application/dns-message"}
        async with self._session.post(url, data=wire, headers=headers,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
            r.raise_for_status()
            return await r.read()

    async def _doq(self, wire: bytes) -> bytes:
        from aioquic.asyncio import QuicConnectionProtocol, connect
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import StreamDataReceived

        cfg = QuicConfiguration(is_client=True, alpn_protocols=["doq"])
        if not self.verify:
            cfg.verify_mode = ssl.CERT_NONE

        class _C(QuicConnectionProtocol):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                self.fut = asyncio.get_event_loop().create_future()
                self.buf = bytearray()
            def quic_event_received(self, event):
                if isinstance(event, StreamDataReceived):
                    self.buf += event.data
                    if event.end_stream and not self.fut.done():
                        self.fut.set_result(bytes(self.buf))

        async with connect(self.spec.host, self.spec.port, configuration=cfg,
                           create_protocol=_C) as client:
            sid = client._quic.get_next_available_stream_id()
            client._quic.send_stream_data(sid, len(wire).to_bytes(2, "big") + wire,
                                          end_stream=True)
            client.transmit()
            data = await asyncio.wait_for(client.fut, self.timeout)
            return data[2:]  # strip 2-byte length prefix

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
        if self._pool is not None:
            self._pool.close()


@dataclass
class Router:
    """Routes a qname to an upstream group. Specific domain routes beat default."""
    default: list[Upstream] = field(default_factory=list)
    routes: dict[str, list[Upstream]] = field(default_factory=dict)

    def group_for(self, qname: str) -> list[Upstream]:
        for cand in suffixes(qname):          # longest first: most specific wins
            group = self.routes.get(cand)
            if group:
                return group
        return self.default

    async def close(self) -> None:
        """Release every upstream's persistent connection and HTTP session.

        Reached when a live settings change replaces the whole router. An
        Upstream can be reachable from `default` and from several routes at
        once, so it is closed by identity rather than once per appearance.
        """
        seen: dict[int, Upstream] = {}
        for group in (self.default, *self.routes.values()):
            for up in group:
                seen.setdefault(id(up), up)
        for up in seen.values():
            try:
                await up.close()
            except Exception:  # noqa: BLE001 — teardown must not raise into a reload
                log.debug("closing upstream %r failed", up, exc_info=True)

    @classmethod
    def build(cls, specs: list[str], *, timeout: float = 4.0, verify: bool = True,
              trust_ad: str = "auto", udp_source_ports: int = 0) -> Router:
        default: list[Upstream] = []
        routes: dict[str, list[Upstream]] = {}
        for spec in specs:
            us = parse_upstream(spec)
            up = Upstream(us, timeout=timeout, verify=verify, trust_ad=trust_ad,
                          udp_source_ports=udp_source_ports)
            if us.domains:
                for d in us.domains:
                    routes.setdefault(d.lower(), []).append(up)
            else:
                default.append(up)
        return cls(default=default, routes=routes)
