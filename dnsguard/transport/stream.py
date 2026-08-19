"""Length-prefixed DNS over a stream — the shared half of TCP and DoT (RFC 7766).

Three properties a stream frontend owes its operator, none of which asyncio gives
for free. Each of these was missing, and each was verified missing against a
running server before being fixed:

  * **Idle connections are reclaimed** (RFC 7766 §6.2.3). A read with no deadline
    is a connection an attacker can open and then abandon; 300 of them stayed
    open indefinitely without a single byte of DNS being sent. On TLS the cost is
    worse, since each one has already bought a handshake.
  * **Connections are capped**, globally and per client, so one peer cannot take
    every slot — and so the limit is a number the operator chose rather than
    whatever the file-descriptor ceiling happens to be.
  * **Queries are answered as they finish** (RFC 7766 §6.2.1.1). Stub resolvers
    and browsers pipeline. Answering strictly in arrival order makes every query
    on a connection wait behind the slowest one ahead of it: 20 pipelined queries
    took 568 ms in series where the slowest single one took 114 ms.

Out-of-order answering needs back-pressure to not become its own denial of
service, so a connection reads no further once `max_inflight` queries are
outstanding. If it cannot make progress within the idle timeout — the usual cause
being a client that stopped reading — the connection is dropped rather than held.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from ..log import get

log = get("stream")


@dataclass(frozen=True)
class StreamLimits:
    """Operator-visible bounds for stream connections."""
    idle_timeout: float = 10.0       # RFC 7766 §6.2.3; 0 disables
    max_connections: int = 512       # across the whole worker
    max_per_client: int = 32         # so one peer cannot take every slot
    max_inflight: int = 16           # concurrent queries on one connection


class ConnectionTracker:
    """Counts open connections so the caps mean something server-wide.

    Single event loop per worker, so plain dict arithmetic is safe. The per-client
    count is keyed on address only: a NAT gateway therefore counts as one client,
    which is the conservative direction — it may hit the per-client cap early, but
    a single host behind it can never exhaust the server.
    """

    def __init__(self, limits: StreamLimits):
        self.limits = limits
        self.total = 0
        self.per_client: dict[str, int] = {}
        self.rejected = 0

    def admit(self, client_ip: str) -> bool:
        lim = self.limits
        if lim.max_connections and self.total >= lim.max_connections:
            self.rejected += 1
            return False
        if lim.max_per_client and self.per_client.get(client_ip, 0) >= lim.max_per_client:
            self.rejected += 1
            return False
        self.total += 1
        self.per_client[client_ip] = self.per_client.get(client_ip, 0) + 1
        return True

    def release(self, client_ip: str) -> None:
        self.total = max(0, self.total - 1)
        left = self.per_client.get(client_ip, 0) - 1
        if left > 0:
            self.per_client[client_ip] = left
        else:
            self.per_client.pop(client_ip, None)


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


async def _read(reader: asyncio.StreamReader, n: int, timeout: float) -> bytes | None:
    """Read exactly n bytes, or None if the peer went away or fell silent."""
    try:
        coro = reader.readexactly(n)
        return await (asyncio.wait_for(coro, timeout) if timeout else coro)
    except (TimeoutError, asyncio.IncompleteReadError, ConnectionResetError, OSError):
        return None


async def serve_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       respond, *, proto: str, limits: StreamLimits,
                       tracker: ConnectionTracker) -> None:
    """Serve one connection. `respond(data, client_ip)` awaits a list of wire
    responses to frame and send — several for a zone transfer, usually one, none
    when the query is to be dropped."""
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "?"
    if not tracker.admit(client_ip):
        log.warning("%s connection from %s refused: at capacity (%d open)",
                    proto, client_ip, tracker.total)
        await _close(writer)
        return

    slots = asyncio.Semaphore(limits.max_inflight)
    inflight: set[asyncio.Task] = set()
    timeout = limits.idle_timeout
    try:
        while True:
            hdr = await _read(reader, 2, timeout)
            if hdr is None:
                break
            length = int.from_bytes(hdr, "big")
            if length == 0:
                break
            data = await _read(reader, length, timeout)
            if data is None:
                break
            # back-pressure: stop reading while saturated. A client that has
            # stopped draining will not free a slot, so give up rather than hold
            # the connection open forever.
            try:
                acquire = slots.acquire()
                await (asyncio.wait_for(acquire, timeout) if timeout else acquire)
            except TimeoutError:
                log.warning("%s connection from %s dropped: %d queries outstanding "
                            "and no progress", proto, client_ip, limits.max_inflight)
                break
            task = asyncio.ensure_future(
                _answer(data, client_ip, respond, writer, slots, timeout, proto))
            inflight.add(task)
            task.add_done_callback(inflight.discard)
    except Exception:
        log.exception("%s stream error", proto)
    finally:
        for task in inflight:
            task.cancel()
        tracker.release(client_ip)
        await _close(writer)


async def _answer(data: bytes, client_ip: str, respond, writer: asyncio.StreamWriter,
                  slots: asyncio.Semaphore, timeout: float, proto: str) -> None:
    try:
        outs = await respond(data, client_ip)
        if not outs:
            return
        # One write call for the whole response, so a query answered concurrently
        # with this one cannot land between a length prefix and its body, or
        # between the messages of a zone transfer. Concatenating makes that
        # structural rather than a property of there happening to be no await
        # between the writes.
        writer.write(b"".join(len(out).to_bytes(2, "big") + out for out in outs))
        drain = writer.drain()
        await (asyncio.wait_for(drain, timeout) if timeout else drain)
    except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
        writer.close()               # the peer stopped reading; the loop will notice
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("%s query handler error for %s", proto, client_ip)
    finally:
        slots.release()
