"""Pooled DNS-over-TCP/TLS upstream: connection reuse, out-of-order response
multiplexing, and transparent recovery when the peer drops the connection.

A fresh handshake per query is what public resolvers reset under load, so these
tests assert the connection really is reused rather than reopened.
"""
from __future__ import annotations

import asyncio

import pytest

from dnsguard.transport.upstream import Upstream, UpstreamSpec
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


class FakeTcpDns:
    """Minimal DNS-over-TCP server. Counts connections so tests can prove reuse."""

    def __init__(self, *, delay_first: float = 0.0, drop_after: int | None = None,
                 reverse: bool = False):
        self.connections = 0
        self.queries = 0
        self.delay_first = delay_first
        self.drop_after = drop_after
        self.reverse = reverse
        self.server: asyncio.AbstractServer | None = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader, writer):
        self.connections += 1
        served = 0
        batch: list[bytes] = []
        try:
            while True:
                hdr = await reader.readexactly(2)
                data = await reader.readexactly(int.from_bytes(hdr, "big"))
                self.queries += 1
                served += 1
                if self.drop_after is not None and served > self.drop_after:
                    writer.close()          # simulate an idle connection being reaped
                    return
                q = Message.parse(data)
                resp = q.reply(Rcode.NOERROR)
                resp.answers.append(
                    RR(q.question.name, Type.A, Class.IN, 60, R.A("192.0.2.1")))
                out = resp.to_wire()
                frame = len(out).to_bytes(2, "big") + out
                if self.reverse:
                    # hold responses and flush reversed -> forces id-based matching
                    batch.append(frame)
                    if len(batch) >= 3:
                        for f in reversed(batch):
                            writer.write(f)
                        batch.clear()
                        await writer.drain()
                    continue
                if self.delay_first and served == 1:
                    await asyncio.sleep(self.delay_first)
                writer.write(frame)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


def _query(name: str, msgid: int = 0x1234) -> Message:
    m = Message(id=msgid)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


async def _upstream(port: int) -> Upstream:
    return Upstream(UpstreamSpec("tcp", "127.0.0.1", port), timeout=5.0)


@pytest.mark.asyncio
async def test_connection_is_reused_across_queries():
    srv = FakeTcpDns()
    port = await srv.start()
    up = await _upstream(port)
    try:
        for i in range(8):
            r = await up.query(_query(f"host{i}.example."))
            assert r.answers[0].rdata.address == "192.0.2.1"
        assert srv.queries == 8
        assert srv.connections == 1, "each query opened a new connection"
    finally:
        await up.close(); await srv.stop()


@pytest.mark.asyncio
async def test_response_id_is_restored_for_caller():
    srv = FakeTcpDns()
    port = await srv.start()
    up = await _upstream(port)
    try:
        r = await up.query(_query("a.example.", msgid=0xBEEF))
        assert r.id == 0xBEEF        # multiplexing id must not leak to the caller
    finally:
        await up.close(); await srv.stop()


@pytest.mark.asyncio
async def test_concurrent_queries_multiplex_on_one_connection():
    srv = FakeTcpDns(reverse=True)   # replies flushed out of order
    port = await srv.start()
    up = await _upstream(port)
    try:
        names = [f"c{i}.example." for i in range(6)]
        results = await asyncio.gather(*(up.query(_query(n)) for n in names))
        assert len(results) == 6
        assert all(r.answers for r in results)
        # every reply routed back to its own waiter despite reversed delivery
        got = {r.questions[0].name.to_text() for r in results}
        assert got == set(names)
        assert srv.connections == 1
    finally:
        await up.close(); await srv.stop()


@pytest.mark.asyncio
async def test_reconnects_when_peer_drops_connection():
    srv = FakeTcpDns(drop_after=2)
    port = await srv.start()
    up = await _upstream(port)
    try:
        assert (await up.query(_query("one.example."))).answers
        assert (await up.query(_query("two.example."))).answers
        # third query hits a closed connection: must reopen and succeed, not raise
        assert (await up.query(_query("three.example."))).answers
        assert srv.connections >= 2
    finally:
        await up.close(); await srv.stop()


@pytest.mark.asyncio
async def test_dead_upstream_raises_rather_than_hanging():
    up = Upstream(UpstreamSpec("tcp", "127.0.0.1", 1), timeout=1.0)
    try:
        # OSError covers both shapes this can take: a refused connection on a
        # closed port, and a TimeoutError (an OSError subclass) where the
        # packet is dropped instead. Anything else is a bug, not the scenario.
        with pytest.raises(OSError):
            await up.query(_query("nope.example."))
        assert up.failures >= 1
    finally:
        await up.close()


@pytest.mark.asyncio
async def test_close_releases_the_connection():
    srv = FakeTcpDns()
    port = await srv.start()
    up = await _upstream(port)
    try:
        await up.query(_query("x.example."))
        await up.close()
        assert up._conn is None
        # usable again afterwards (fresh connection)
        await up.query(_query("y.example."))
        assert srv.connections == 2
    finally:
        await up.close(); await srv.stop()
