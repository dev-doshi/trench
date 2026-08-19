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

from dnsguard.transport.upstream import UdpPool, Upstream, parse_upstream
from dnsguard.wire import Class, Message, Question, Type
from dnsguard.wire.name import Name


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
    anyone who would rather pay the microseconds."""
    async with Echo() as srv:
        up = Upstream(parse_upstream(f"127.0.0.1:{srv.port}"), timeout=2.0,
                      udp_source_ports=0)
        assert up._pool is None
        try:
            for i in range(30):
                await up.query(_query(qid=i + 1))
        finally:
            await up.close()
        # every query came from its own socket, so every port is different
        assert len(set(srv.ports)) == 30


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
