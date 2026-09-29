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
import secrets
import ssl
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..errors import UpstreamError
from ..log import get
from ..wire import Message
from ..wire.name import suffixes
from ..wire.rrtypes import Flags, Rcode

if TYPE_CHECKING:
    from .quicclient import DoQClient

log = get("upstream")
_SYSRAND = secrets.SystemRandom()

#: The longest a DNS message can be; a DoH body past this is not one.
MAX_DNS_MESSAGE = 65535


@dataclass
class UpstreamSpec:
    scheme: str          # udp | tcp | tls | https | quic
    host: str
    port: int
    sni: str = ""        # TLS server name / verify name
    path: str = "/dns-query"
    domains: tuple[str, ...] = ()   # per-domain routing triggers ([/d/])


def parse_upstream(spec: str) -> UpstreamSpec:
    """Parse an upstream spec. Raises ValueError naming the spec as written.

    `original` is threaded through the split below rather than reconstructed
    afterwards: the scheme and the `[/domain/]` prefix are stripped as this goes,
    so an error raised deeper would otherwise quote a fragment — `'9.9.9.9:xyz'`
    for something the operator wrote as `tls://9.9.9.9:xyz` — and reversing the
    stripping to fix that would be a second copy of it.
    """
    original = spec.strip()
    spec = original
    domains: tuple[str, ...] = ()
    if spec.startswith("[/"):
        end = spec.find("]")
        if end < 0:
            raise ValueError(f"unterminated '[/domain/]' prefix in upstream {original!r}")
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
        host, port = _split_hostport(hostport, 443, original)
        sni = host
    else:
        if "#" in spec:
            spec, sni = spec.split("#", 1)
        default_port = 853 if scheme in ("tls", "quic") else 53
        host, port = _split_hostport(spec, default_port, original)
        if scheme in ("tls", "quic") and not sni:
            sni = host
    return UpstreamSpec(scheme, host, port, sni, path, domains)


def _split_hostport(s: str, default_port: int, original: str = "") -> tuple[str, int]:
    """`host[:port]`, or `[v6addr][:port]`. Raises ValueError on anything else.

    An upstream spec is operator input, and a typo in the port used to reach
    `int()` bare: the daemon died at start-up on
    `invalid literal for int() with base 10: 'abc'`, which names neither the
    setting nor the server. A port outside 1-65535 was accepted outright and
    failed later, somewhere less obvious.
    """
    named = original or s
    if s.startswith("["):                       # [ipv6]:port
        host, close, rest = s[1:].partition("]")
        if not close:
            raise ValueError(f"unterminated '[' in upstream {named!r}")
        return host, (_port(rest[1:], named) if rest.startswith(":") else default_port)
    if s.count(":") == 1:                       # host:port (bare IPv6 has more)
        host, _, port = s.partition(":")
        return host, _port(port, named)
    return s, default_port


def _port(text: str, spec: str) -> int:
    try:
        port = int(text)
    except ValueError:
        raise ValueError(f"upstream {spec!r} has a non-numeric port {text!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"upstream {spec!r} has a port outside 1-65535: {port}")
    return port


def _question_of(wire: bytes) -> bytes:
    """The lowercased question section of a query, or b"" if it has none.

    Lowercased because a 0x20-randomised query may come back in either case.
    A query's question is never compressed, so the labels can be walked plainly.
    """
    if len(wire) < 12 or wire[4:6] == b"\x00\x00":
        return b""
    i = 12
    while i < len(wire) and wire[i] != 0:
        if wire[i] >= 0xC0:
            return b""
        i += wire[i] + 1
    end = i + 5                                  # the root label, qtype, qclass
    return wire[12:end].lower() if end <= len(wire) else b""


class _UdpSocket(asyncio.DatagramProtocol):
    """One long-lived, connected UDP socket carrying several queries at once.

    Replies are dispatched by transaction id, because more than one query can be
    outstanding on the same socket and UDP does not promise order.
    """

    __slots__ = ("pending", "questions", "rejected", "transport", "pool", "closed", "left")

    def __init__(self, pool: UdpPool | None = None) -> None:
        self.pending: dict[int, asyncio.Future] = {}
        self.questions: dict[int, bytes] = {}   # txid -> expected question bytes
        self.rejected: dict[int, bytes] = {}    # txid -> a reply held back, see wait
        self.transport: asyncio.DatagramTransport | None = None
        self.pool = pool
        self.closed = False
        self.left = UdpPool.lifetime() if pool is not None else 1

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
        self.questions.clear()
        self.rejected.clear()

    def expect(self, wire: bytes, fut: asyncio.Future) -> int:
        """Register `fut` for the reply to the query `wire`; return its id."""
        txid = (wire[0] << 8) | wire[1]
        self.pending[txid] = fut
        self.questions[txid] = _question_of(wire)
        return txid

    def forget(self, txid: int) -> None:
        self.pending.pop(txid, None)
        self.questions.pop(txid, None)
        self.rejected.pop(txid, None)

    async def wait(self, txid: int, fut: asyncio.Future, timeout: float) -> bytes:
        """The reply for `txid`, or on timeout the mismatched one held back.

        A held-back reply is handed over only when nothing better came, so the
        caller's own check rejects it with its usual "different question"
        error: an upstream that really answers the wrong question still fails
        clearly rather than as a bare timeout, while a spoofer racing the real
        answer no longer takes its slot.
        """
        try:
            return await asyncio.wait_for(fut, timeout)
        except TimeoutError:
            stray = self.rejected.get(txid)
            if stray is None:
                raise
            return stray

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) < 12:
            return
        txid = (data[0] << 8) | data[1]
        fut = self.pending.get(txid)
        if fut is None or fut.done():
            return
        # RFC 5452 §9.1: a reply whose question does not match is not the
        # answer, and is dropped rather than accepted. Taking the first datagram
        # with the right id let one spoofed packet fail the query outright — the
        # later check rejected it, but the real answer had lost its slot.
        # A reply with no question at all (a bare FORMERR) is let through: the
        # caller's check decides whether that shape is acceptable.
        q = self.questions.get(txid, b"")
        if q and data[4:6] != b"\x00\x00" and data[12:12 + len(q)].lower() != q:
            self.rejected.setdefault(txid, data)
            return
        self.forget(txid)
        fut.set_result(data)

    def error_received(self, exc: Exception) -> None:
        # A connected UDP socket surfaces ICMP errors here. Nothing identifies
        # which query they belong to, so everything waiting on this socket fails
        # and is retried elsewhere.
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(exc)
        self.pending.clear()
        self.questions.clear()
        self.rejected.clear()

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

    Each socket is also retired after a random number of queries and replaced
    by a fresh ephemeral port. A pool that never changed let an attacker who
    learned its ports (by watching, or by probing over time) keep them for the
    life of the process, shrinking the port entropy towards zero; rotation
    bounds how long any learned port stays useful, at an amortised cost of
    about 1 us per query. Selection uses the OS CSPRNG for the same reason the
    transaction id does: Mersenne Twister output is predictable from samples.
    """

    #: Queries a socket carries before it is replaced: uniform in this range,
    #: so an observer cannot tell when a given port will go.
    LIFETIME = (32, 128)

    @classmethod
    def lifetime(cls) -> int:
        lo, hi = cls.LIFETIME
        return lo + secrets.randbelow(hi - lo)

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
        socks = self._socks
        sock = socks[secrets.randbelow(len(socks))]
        if txid in sock.pending:
            for cand in _SYSRAND.sample(socks, min(8, len(socks))):
                if txid not in cand.pending:
                    sock = cand
                    break
            else:
                raise UpstreamError("no free upstream socket for this query id")
        sock.left -= 1
        if sock.left <= 0:
            # Out of the pool now, so no new query picks it; closed once the
            # queries already on it are answered. `_ensure` opens its successor.
            self.discard(sock)
            sock.pool = None
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        sock.expect(wire, fut)
        try:
            sock.transport.sendto(wire)          # type: ignore[union-attr]
            return await sock.wait(txid, fut, timeout)
        finally:
            sock.forget(txid)
            if sock.pool is None and not sock.pending:
                sock.close()

    def close(self) -> None:
        for s in self._socks:
            s.close()
        self._socks = []


class _Link:
    """One TCP/TLS connection and the queries in flight on it.

    Everything that belongs to a connection lives here rather than on
    `_StreamConn`, which outlives many of them. When the pending table and the
    closed flag were shared, the reader of a connection being torn down ran its
    abort *after* the replacement had opened, failing queries that were in flight
    on the new connection; each of those then closed the new one in turn. One
    dropped idle connection became a burst of SERVFAILs.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader, self.writer = reader, writer
        self.pending: dict[int, asyncio.Future] = {}
        self.dead = False
        self.last_rx = 0.0      # loop time of the latest reply read off the wire
        self._next_id = 0
        self._task = asyncio.ensure_future(self._read_loop())

    async def _read_loop(self) -> None:
        try:
            while True:
                n = int.from_bytes(await self.reader.readexactly(2), "big")
                data = await self.reader.readexactly(n)
                self.last_rx = asyncio.get_running_loop().time()
                if len(data) >= 2:
                    fut = self.pending.pop(int.from_bytes(data[:2], "big"), None)
                    if fut is not None and not fut.done():
                        fut.set_result(data)
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError, OSError) as e:
            self._fail(e)
        except asyncio.CancelledError:
            self._fail(ConnectionError("connection closed"))

    def _fail(self, exc: BaseException) -> None:
        self.dead = True
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(exc)
        self.pending.clear()

    @property
    def usable(self) -> bool:
        return not self.dead and not self.writer.is_closing()

    def alloc_id(self) -> int:
        for _ in range(65536):
            self._next_id = (self._next_id + 1) & 0xFFFF
            if self._next_id not in self.pending:
                return self._next_id
        raise RuntimeError("no free DNS message id")

    async def close(self) -> None:
        self._task.cancel()
        self._fail(ConnectionError("closed"))
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass


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
        self._link: _Link | None = None
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._link is None or not self._link.usable

    async def _current(self) -> _Link:
        async with self._lock:
            link = self._link
            if link is None or not link.usable:
                if link is not None:
                    await link.close()
                spec = self.up.spec
                ssl_ctx = self.up._tls_ctx(["dot"]) if spec.scheme == "tls" else None
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        spec.host, spec.port, ssl=ssl_ctx,
                        server_hostname=(spec.sni or spec.host) if ssl_ctx else None),
                    self.up.timeout)
                link = self._link = _Link(reader, writer)
            return link

    async def _drop(self, link: _Link) -> None:
        """Close `link`, and forget it only if it is still the current one: a
        concurrent query may already have replaced it with a healthy one."""
        if self._link is link:
            self._link = None
        await link.close()

    async def query(self, wire: bytes) -> bytes:
        link = await self._current()
        mid = link.alloc_id()
        out = mid.to_bytes(2, "big") + wire[2:]         # rewrite id for multiplexing
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        link.pending[mid] = fut
        sent = loop.time()
        try:
            link.writer.write(len(out).to_bytes(2, "big") + out)
            # `drain` is inside the budget: a peer that stops reading fills the
            # send buffer, and an unbounded drain then held the query forever.
            return await asyncio.wait_for(self._send_and_wait(link, fut), self.up.timeout)
        except TimeoutError:
            if link.last_rx < sent:
                # Not one reply on this connection in a whole timeout, to this
                # query or any other. That is a dead path — a NAT that dropped
                # the mapping, a peer that vanished without a FIN — not a slow
                # answer, and nothing else will ever notice: TCP keepalive
                # takes hours, so every later query would queue behind it and
                # time out too. Drop it so the next query reconnects.
                log.info("closing silent %s connection to %s",
                         self.up.spec.scheme, self.up)
                await self._drop(link)
            raise
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError, OSError):
            await self._drop(link)
            raise
        finally:
            link.pending.pop(mid, None)

    @staticmethod
    async def _send_and_wait(link: _Link, fut: asyncio.Future) -> bytes:
        await link.writer.drain()
        return await fut

    async def close(self) -> None:
        if self._link is not None:
            await self._drop(self._link)


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
    if resp.opcode != sent.opcode:
        # RFC 1035 §4.1.1: the opcode is copied into the response. One that
        # differs is an answer to some other message.
        raise UpstreamError(f"upstream reply has opcode {resp.opcode}")
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
        # Nor may it be an answer. An empty NOERROR or NXDOMAIN is a negative
        # answer that gets cached, and with no question it also escapes the
        # 0x20 check further up: a spoofer needed only the id to erase a name.
        if resp.rcode in (Rcode.NOERROR, Rcode.NXDOMAIN):
            raise UpstreamError("upstream answer has no question")
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
        self.failed_at = 0.0   # loop time of the latest failure; see Forwarder._fastest
        self._session = None  # aiohttp session for DoH
        self._conn: _StreamConn | None = None  # persistent TCP/DoT connection
        self._pool: UdpPool | None = None
        self._doq_client: DoQClient | None = None   # persistent DoQ connection
        self._ssl: dict[tuple[str, ...], ssl.SSLContext] = {}
        if udp_source_ports > 0 and spec.scheme == "udp":
            self._pool = UdpPool(spec.host, spec.port, udp_source_ports)
        # 0x20 on plain UDP, learned per upstream (see `_case_sent`/`_case_got`).
        # None = still learning, True = echoes case (enforced), False = does not.
        self._case_echo: bool | None = None
        self._case_misses = 0

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
                self._case_sent(sent)
                wire = sent.to_wire()
                data = await self._udp(wire)
                resp = Message.parse(data)
                _check_response(resp, sent, check_id=True)
                if resp.tc:
                    resp = Message.parse(await self._tcp(wire))
                    _check_response(resp, sent, check_id=True)
                self._case_got(resp, sent, msg)
                resp.id = msg.id          # hand the client back its own id
            elif scheme in ("tcp", "tls"):
                wire = msg.to_wire()
                resp = Message.parse(await self._stream(wire))
                # the id is connection-local and already matched by the reader
                _check_response(resp, msg, check_id=False)
                resp.id = msg.id          # undo the connection-local id used to multiplex
            elif scheme in ("https", "quic"):
                # RFC 9250 §4.2.1 (MUST) and RFC 8484 §4.1 (SHOULD): the
                # message ID is 0 on these transports — the stream or HTTP
                # exchange already pairs query with response, and a fixed ID
                # keeps DoH GETs cacheable. A conforming DoQ server treats a
                # non-zero ID as a protocol error and aborts, so passing the
                # client's ID through failed every query to one.
                sent = copy.copy(msg)
                sent.id = 0
                wire = sent.to_wire()
                if scheme == "https":
                    raw = await self._doh(wire)
                else:
                    # The whole exchange is bounded, handshake included. Only the
                    # read used to be: aioquic's `connect` waits for the handshake
                    # until its idle timeout — 60 s by default — so a black-holed
                    # DoQ upstream held every query routed to it for a minute,
                    # far past any client's patience and the stale-serving timer.
                    raw = await self._doq(wire)
                resp = Message.parse(raw)
                _check_response(resp, sent, check_id=False)
                resp.id = msg.id          # hand the client back its own id
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
            self.failed_at = loop.time()
            raise

    #: Mismatched echoes, with no match ever seen, before concluding that an
    #: upstream rewrites case and giving up 0x20 on it.
    CASE_LEARN = 3

    def _case_sent(self, sent: Message) -> None:
        """Randomise the case of a plain-UDP query name (RFC 5452 §9.1, 0x20).

        Plain UDP is the one transport where an off-path spoofer only has to
        guess the transaction id and port: ~26 bits against the default pool.
        On a name like `www.example.com` this adds ~13 more, per query, with
        nothing to configure. It is on for every plain-UDP upstream —
        forwarders and the recursive resolver's authoritative servers alike —
        because it is learned rather than assumed: see `_case_got`.
        """
        q = sent.question
        if self._case_echo is False or q is None:
            return
        from ..engine.zerox20 import randomize_name  # engine imports transport
        sent.questions = [q.__class__(randomize_name(q.name), q.rtype, q.rclass),
                          *sent.questions[1:]]

    def _case_got(self, resp: Message, sent: Message, msg: Message) -> None:
        """Check the echoed case, then hand back the case the caller sent.

        A mismatch that got this far carried the right id from the right port,
        so it is either a spoof that won a ~26-bit guess or an upstream that
        does not echo case. The first matching echo settles which kind of
        upstream this is, and from then on a mismatch is refused. Until then a
        mismatch is accepted and counted. `CASE_LEARN` mismatches in a row,
        learning or not, mean the upstream rewrites case, and 0x20 is turned
        off for it rather than failing every query it answers.
        """
        q, got = sent.question, resp.question
        orig = msg.question
        if q is None or got is None or orig is None or q.name.labels == orig.name.labels:
            return
        if got.name.labels == q.name.labels:
            self._case_misses = 0
            # Only a mixed-case echo is evidence: an upstream that folds case
            # to lower (or upper) also "echoes" a name that came out that way.
            text = b"".join(q.name.labels)
            if self._case_echo is None and text != text.lower() and text != text.upper():
                self._case_echo = True
        else:
            self._case_misses += 1
            if self._case_misses >= self.CASE_LEARN:
                # That many in a row is not a spoofer winning ~26-bit guesses
                # back to back; it is an upstream that (now) rewrites case.
                if self._case_echo is not False:
                    log.info("upstream %r does not echo query-name case; "
                             "0x20 off for it", self)
                self._case_echo = False
            elif self._case_echo:
                raise UpstreamError("0x20 case mismatch from upstream (possible spoof)")
        from ..engine.zerox20 import restore
        restore(resp, orig.name)

    def _ad_trusted(self) -> bool:
        if self.trust_ad == "always":
            return True
        if self.trust_ad == "never":
            return False
        # Encrypted is not authenticated: with `verify` off anyone on the path
        # can terminate the TLS session and set AD on a forged answer.
        return self.verify and self.spec.scheme in self.AUTHENTICATED_SCHEMES

    # --- transports ---
    async def _udp(self, wire: bytes) -> bytes:
        if self._pool is not None:
            return await self._pool.query(wire, self.timeout)
        # udp_source_ports = 0: a fresh socket per query, for the full ~15 bits
        # of ephemeral-port entropy. Costs 67 us; see UdpPool for the arithmetic.
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        proto = _UdpSocket()
        txid = proto.expect(wire, fut)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: proto, remote_addr=(self.spec.host, self.spec.port))
        try:
            transport.sendto(wire)
            return await proto.wait(txid, fut, self.timeout)
        finally:
            transport.close()

    #: Times a stream query may (re)open the connection before giving up.
    #: One reopen covers the ordinary case, a peer dropping an idle connection
    #: between queries. It does not cover a peer that refuses connections
    #: intermittently: Quad9 measured a 33-67% TLS accept rate from one
    #: deployment, resetting during the handshake, which made a single retry a
    #: coin flip. With both configured upstreams at that provider, the two lost
    #: the toss together often enough to SERVFAIL real clients.
    _STREAM_ATTEMPTS = 3

    async def _stream(self, wire: bytes) -> bytes:
        """Query over the pooled TCP/DoT connection, reopening if the peer drops
        or refuses it. The connection drops the link that failed itself."""
        if self._conn is None:
            self._conn = _StreamConn(self)
        last: Exception = UpstreamError("no attempt was made")
        for _ in range(self._STREAM_ATTEMPTS):
            try:
                return await self._conn.query(wire)
            except TimeoutError:
                # `upstream.timeout` is the budget for answering this query, not
                # for each attempt at it. TimeoutError subclasses OSError, so it
                # fell into the reconnect branch below and a merely slow upstream
                # cost the caller two full timeouts before it heard anything.
                # Nothing about a timeout says the connection is broken, either.
                raise
            except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError,
                    OSError) as e:
                last = e
        raise last

    async def _tcp(self, wire: bytes, ssl_ctx=None) -> bytes:
        """One-shot TCP query on a dedicated connection (used for UDP truncation
        fallback, where the pooled connection may be a different transport).

        One budget for the whole exchange. Connect, length prefix and body each
        used to get a full `timeout` of their own, so a peer that trickled its
        reply could hold a truncated query for three timeouts on top of the UDP
        one — long past the point any client was still waiting.
        """
        return await asyncio.wait_for(self._tcp_exchange(wire, ssl_ctx), self.timeout)

    async def _tcp_exchange(self, wire: bytes, ssl_ctx=None) -> bytes:
        reader, writer = await asyncio.open_connection(
            self.spec.host, self.spec.port, ssl=ssl_ctx,
            # Parenthesised for the reader: the conditional binds loosest, so
            # the unparenthesised form meant the same but read like a bug.
            server_hostname=(self.spec.sni or None) if ssl_ctx else None)
        try:
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
            n = int.from_bytes(await reader.readexactly(2), "big")
            return await reader.readexactly(n)
        finally:
            writer.close()

    def _tls_ctx(self, alpn: list[str]) -> ssl.SSLContext:
        """One context per ALPN set, built once. `create_default_context` loads
        the system CA store, about 23 ms of blocking work on the event loop, and
        this ran on every reconnect — up to three times for one query while an
        upstream was flapping."""
        ctx = self._ssl.get(tuple(alpn))
        if ctx is None:
            ctx = self._ssl[tuple(alpn)] = self._new_tls_ctx(alpn)
        return ctx

    def _new_tls_ctx(self, alpn: list[str]) -> ssl.SSLContext:
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
            # No DNS message is longer than 65535 octets. `read()` buffered
            # whatever the far end streamed, so a hostile or broken upstream
            # could grow this process without bound.
            if (r.content_length or 0) > MAX_DNS_MESSAGE:
                raise UpstreamError("DoH upstream reply is larger than any DNS message")
            body = bytearray()
            async for chunk in r.content.iter_any():
                body += chunk
                if len(body) > MAX_DNS_MESSAGE:
                    raise UpstreamError("DoH upstream reply is larger than any DNS message")
            return bytes(body)

    async def _doq(self, wire: bytes) -> bytes:
        # The whole exchange, handshake included. `connect` waits for the
        # handshake with no deadline of its own, so an unreachable upstream held
        # the query for aioquic's 60-second idle timeout rather than ours.
        return await asyncio.wait_for(self._doq_exchange(wire), self.timeout)

    async def _doq_exchange(self, wire: bytes) -> bytes:
        # One connection, reused with a stream per query (RFC 9250 §5.5): a
        # connection per query paid a TLS 1.3 handshake on every lookup.
        if self._doq_client is None:
            from aioquic.quic.configuration import QuicConfiguration

            from .quicclient import DoQClient

            # Idle timeout outlives a single query's deadline so the connection
            # survives the gaps between queries; each query keeps its own bound.
            cfg = QuicConfiguration(is_client=True, alpn_protocols=["doq"],
                                    idle_timeout=max(self.timeout, 30.0))
            if not self.verify:
                cfg.verify_mode = ssl.CERT_NONE
            self._doq_client = DoQClient(self.spec.host, self.spec.port, cfg)
        try:
            return await self._doq_client.query(wire)
        except ConnectionError as e:
            raise UpstreamError(str(e)) from e

    async def close(self) -> None:
        if self._doq_client is not None:
            await self._doq_client.close()
            self._doq_client = None
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

    def routed(self, qname: str) -> bool:
        """True if the operator configured a domain route covering `qname`."""
        return bool(self.routes) and any(self.routes.get(c) for c in suffixes(qname))

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
