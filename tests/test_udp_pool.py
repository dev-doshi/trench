"""The upstream source-port pool.

Opening a socket per upstream query costs 67 us measured and caps forwarding at
about 15k queries/s. The pool costs 0.2 us. It is not a free win, though: the
socket is where source-port entropy comes from, and RFC 5452 wants that entropy
because it is half of what an off-path spoofer has to guess. So these tests hold
the pool to both halves of the deal — it must be fast, and it must actually
spread queries across the ports it claims to have.
"""
from __future__ import annotations

import asyncio
import socket

import pytest

from trench.transport.upstream import UdpPool, Upstream, parse_upstream
from trench.wire import Class, Message, Question, Type
from trench.wire.name import Name


class Echo:
    """An upstream that echoes a valid reply and records the source port of
    every query it sees."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.setblocking(False)
        self.ports: list[int] = []
        self._task: asyncio.Task | None = None

    @property
    def port(self) -> int:
        return self.sock.getsockname()[1]

    async def _serve(self):
        loop = asyncio.get_running_loop()
        while True:
            data, addr = await loop.sock_recvfrom(self.sock, 4096)
            self.ports.append(addr[1])
            got = Message.parse(data)
            r = Message(id=got.id)
            r.set_flag(0x8000, True)
            r.questions = list(got.questions)
            await loop.sock_sendto(self.sock, r.to_wire(), addr)

    async def __aenter__(self):
        self._task = asyncio.ensure_future(self._serve())
        return self

    async def __aexit__(self, *exc):
        if self._task:
            self._task.cancel()
        self.sock.close()


def _query(name="example.com.", qid=0x1234) -> Message:
    q = Message(id=qid)
    q.set_flag(0x0100, True)
    q.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return q


@pytest.mark.asyncio
async def test_the_pool_actually_spreads_queries_over_its_ports():
    """The entropy claim, checked rather than asserted in a comment.

    A pool that always reached for the same socket would be as guessable as a
    fixed source port while looking exactly as fast.
    """
    async with Echo() as srv:
        up = Upstream(parse_upstream(f"127.0.0.1:{srv.port}"), timeout=2.0,
                      udp_source_ports=32)
        try:
            for i in range(200):
                await up.query(_query(qid=i + 1))
        finally:
            await up.close()
        distinct = set(srv.ports)
        assert len(srv.ports) == 200
        # 200 draws from 32 sockets: seeing far fewer than 32 means the choice
        # is not really random.
        assert len(distinct) >= 24, f"only {len(distinct)} source ports used"


@pytest.mark.asyncio
async def test_zero_means_a_fresh_socket_per_query():
    """The escape hatch has to work: 0 restores full ephemeral-port entropy for
    anyone who would rather pay the microseconds.

    The claim under test is "a socket per query", not "30 distinct port
    numbers". Nothing promises the second: the kernel is free to hand back a
    port it reclaimed from a socket closed microseconds earlier, and it does —
    this assertion failed about one run in three when the suite ran hot. So the
    contract is checked against the pooled case, which is what it is the escape
    hatch from.
    """
    async with Echo() as srv:
        pooled = Upstream(parse_upstream(f"127.0.0.1:{srv.port}"), timeout=2.0,
                          udp_source_ports=1)
        try:
            for i in range(30):
                await pooled.query(_query(qid=i + 1))
        finally:
            await pooled.close()
        assert len(set(srv.ports)) == 1          # one pooled socket, one port

        srv.ports.clear()
        up = Upstream(parse_upstream(f"127.0.0.1:{srv.port}"), timeout=2.0,
                      udp_source_ports=0)
        assert up._pool is None
        try:
            for i in range(30):
                await up.query(_query(qid=i + 101))
        finally:
            await up.close()
        # a fresh socket every time: the ports move around, rather than being
        # the single fixed one the pool gives
        assert len(set(srv.ports)) > 1


@pytest.mark.asyncio
async def test_concurrent_queries_get_their_own_answers():
    """Several queries share a socket, and UDP does not promise order, so
    replies are matched by transaction id. Getting this wrong would hand one
    query another's answer — the exact failure the id is there to prevent."""
    async with Echo() as srv:
        up = Upstream(parse_upstream(f"127.0.0.1:{srv.port}"), timeout=3.0,
                      udp_source_ports=4)
        try:
            names = [f"n{i}.example.com." for i in range(40)]
            results = await asyncio.gather(*(up.query(_query(n, i + 1))
                                             for i, n in enumerate(names)))
        finally:
            await up.close()
        for name, resp in zip(names, results, strict=True):
            assert resp.question.name.to_text() == name


@pytest.mark.asyncio
async def test_a_reply_with_an_unknown_id_is_discarded():
    """A socket carrying several queries must ignore anything that answers none
    of them, rather than handing it to whichever waiter happens to be first."""
    pool = UdpPool("127.0.0.1", 9, 2)
    await pool._ensure()
    try:
        sock = pool._socks[0]
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        sock.pending[0x1111] = fut
        sock.datagram_received(b"\x22\x22" + b"\x00" * 10, ("127.0.0.1", 9))
        assert not fut.done(), "a reply for another id must not resolve this query"
        sock.datagram_received(b"\x11\x11" + b"\x00" * 10, ("127.0.0.1", 9))
        assert fut.done() and fut.result()[:2] == b"\x11\x11"
    finally:
        pool.close()


@pytest.mark.asyncio
async def test_the_pool_opens_every_socket_before_serving_anything():
    """Entropy comes from how many sockets exist. A pool that grew on demand
    would start out predictable — one socket for the first query, two for the
    next — which is worst at exactly the moment a resolver is coldest."""
    pool = UdpPool("127.0.0.1", 9, 16)
    assert pool._socks == []
    await pool._ensure()
    try:
        assert len(pool._socks) == 16
    finally:
        pool.close()
    assert pool._socks == []


# --- the dispatcher's own edges ---
@pytest.mark.asyncio
async def test_a_datagram_too_short_to_carry_an_id_is_dropped():
    from trench.transport.upstream import _UdpSocket
    pool = UdpPool("127.0.0.1", 53, size=1)
    sock = _UdpSocket(pool)
    sock.datagram_received(b"\x12", ("127.0.0.1", 53))   # must not raise
    assert sock.pending == {}


@pytest.mark.asyncio
async def test_closing_a_socket_fails_everything_waiting_on_it():
    """A pending future left unresolved is a query that never returns and never
    times out at this layer."""
    from trench.errors import UpstreamError
    from trench.transport.upstream import _UdpSocket
    pool = UdpPool("127.0.0.1", 53, size=1)
    sock = _UdpSocket(pool)
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    sock.pending[0x1234] = fut
    sock.connection_lost(None)
    assert sock.closed is True and sock.pending == {}
    with pytest.raises(UpstreamError, match="socket closed"):
        await fut


@pytest.mark.asyncio
async def test_a_socket_error_does_not_leave_queries_hanging():
    from trench.transport.upstream import _UdpSocket
    pool = UdpPool("127.0.0.1", 53, size=1)
    sock = _UdpSocket(pool)
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    sock.pending[0x1234] = fut
    sock.error_received(OSError("connection refused"))
    with pytest.raises(OSError, match="connection refused"):
        await asyncio.wait_for(fut, 1)


@pytest.mark.asyncio
async def test_a_late_reply_for_an_already_settled_query_is_ignored():
    from trench.transport.upstream import _UdpSocket
    pool = UdpPool("127.0.0.1", 53, size=1)
    sock = _UdpSocket(pool)
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    fut.set_result(b"first")
    sock.pending[0x1234] = fut
    sock.datagram_received(b"\x12\x34rest", ("127.0.0.1", 53))
    assert await fut == b"first"


@pytest.mark.asyncio
async def test_two_queries_with_the_same_id_do_not_share_a_socket():
    """Otherwise two replies would be indistinguishable to the dispatcher."""
    async with Echo() as echo:
        pool = UdpPool("127.0.0.1", echo.port, size=4)
        try:
            await pool._ensure()
            first, second = _query(qid=0x4242), _query(qid=0x4242)
            a, b = await asyncio.gather(pool.query(first.to_wire(), 5),
                                        pool.query(second.to_wire(), 5))
            assert Message.parse(a).id == 0x4242
            assert Message.parse(b).id == 0x4242
        finally:
            pool.close()


@pytest.mark.asyncio
async def test_a_pool_with_every_socket_busy_on_one_id_refuses():
    from trench.errors import UpstreamError
    async with Echo() as echo:
        pool = UdpPool("127.0.0.1", echo.port, size=2)
        try:
            await pool._ensure()
            loop = asyncio.get_running_loop()
            for sock in pool._socks:
                sock.pending[0x4242] = loop.create_future()
            with pytest.raises(UpstreamError, match="no free upstream socket"):
                await pool.query(_query(qid=0x4242).to_wire(), 1)
        finally:
            for sock in pool._socks:
                sock.pending.clear()
            pool.close()


@pytest.mark.asyncio
async def test_running_out_of_descriptors_caps_the_pool_rather_than_failing(caplog,
                                                                           monkeypatch):
    """A smaller pool is weaker, not broken."""
    async with Echo() as echo:
        pool = UdpPool("127.0.0.1", echo.port, size=8)
        loop = asyncio.get_running_loop()
        real = loop.create_datagram_endpoint
        made = []

        async def limited(factory, **kw):
            if len(made) >= 3:
                raise OSError(24, "Too many open files")
            got = await real(factory, **kw)
            made.append(got)
            return got

        monkeypatch.setattr(loop, "create_datagram_endpoint", limited)
        try:
            await pool._ensure()
            assert 0 < len(pool._socks) <= 3
            assert any("capped at" in r.getMessage() for r in caplog.records)
            # And it still answers with what it has.
            resp = await pool.query(_query().to_wire(), 5)
            assert Message.parse(resp).id == 0x1234
        finally:
            pool.close()


@pytest.mark.asyncio
async def test_a_pool_that_cannot_open_its_first_socket_raises(monkeypatch):
    pool = UdpPool("127.0.0.1", 53, size=4)
    loop = asyncio.get_running_loop()

    async def refuse(factory, **kw):
        raise OSError(24, "Too many open files")

    monkeypatch.setattr(loop, "create_datagram_endpoint", refuse)
    with pytest.raises(OSError):
        await pool._ensure()
