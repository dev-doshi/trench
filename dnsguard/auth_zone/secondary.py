"""Secondary (slave) zone support: pull a zone from a primary via AXFR/IXFR,
send/handle NOTIFY, and drive the refresh timer off the SOA.

Transfers run over TCP and may be authenticated with TSIG. Our transfers sign
every envelope with the previous MAC chained in, so verification is a simple
running chain (interoperates with any peer that signs each message).
"""
from __future__ import annotations

import asyncio
import contextlib
import random
import time

from ..log import get
from ..wire import Message, Type
from ..wire.name import Name
from ..wire.rrtypes import Rcode
from .tsig import TSIGKey, sign_wire, verify_wire
from .xfr import apply_ixfr, build_xfr_query, ixfr_complete, zone_from_records
from .zone import Zone

log = get("secondary")


async def _read_tcp_message(reader: asyncio.StreamReader) -> bytes:
    hdr = await reader.readexactly(2)
    length = int.from_bytes(hdr, "big")
    return await reader.readexactly(length)


async def transfer_records(host: str, port: int, origin: Name, *,
                           key: TSIGKey | None = None, timeout: float = 30.0,
                           qtype: int = Type.AXFR,
                           client_serial: int | None = None) -> list:
    """Run an AXFR/IXFR against a primary; return the raw RR stream (TSIG
    stripped, envelopes verified). Interpretation (full zone vs delta) is the
    caller's job via `apply_ixfr`."""
    msgid = random.getrandbits(16)
    query = build_xfr_query(origin, qtype, client_serial=client_serial, msgid=msgid)
    wire = query.to_wire()
    req_mac: bytes | None = None
    if key is not None:
        wire, req_mac = sign_wire(wire, key)
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(len(wire).to_bytes(2, "big") + wire)
        await writer.drain()
        records = []
        while not ixfr_complete(records):
            data = await asyncio.wait_for(_read_tcp_message(reader), timeout)
            if key is not None:
                req_mac, _, _ = verify_wire(data, {key.name: key}, request_mac=req_mac)
            msg = Message.parse(data)
            if msg.rcode != Rcode.NOERROR:
                raise TransferError(f"transfer refused: rcode {msg.rcode}")
            records.extend(rr for rr in msg.answers if rr.rtype != Type.TSIG)
            if not records:  # primary sent an empty first message = error
                raise TransferError("empty transfer")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return records


async def axfr_in(host: str, port: int, origin: Name, *, key: TSIGKey | None = None,
                  timeout: float = 30.0) -> Zone:
    """Pull the full `origin` zone from a primary and return the assembled Zone."""
    records = await transfer_records(host, port, origin, key=key, timeout=timeout)
    zone = zone_from_records(records, origin)
    log.info("AXFR of %s complete: %d names, serial %s",
             origin.to_text(), len(zone.records), zone.soa.serial if zone.soa else "?")
    return zone


class TransferError(Exception):
    pass


async def send_notify(host: str, port: int, origin: Name, *,
                      key: TSIGKey | None = None, timeout: float = 5.0) -> bool:
    """Send a DNS NOTIFY (RFC 1996) to a secondary; return True on ack."""
    from ..wire import Question
    from ..wire.rrtypes import Flags, Opcode
    m = Message(id=random.getrandbits(16))
    m.flags |= (Opcode.NOTIFY << Flags.OPCODE_SHIFT) | Flags.AA
    m.questions.append(Question(origin, Type.SOA))
    wire = m.to_wire()
    if key is not None:
        wire, _ = sign_wire(wire, key)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (TimeoutError, OSError):
        return False
    try:
        writer.write(len(wire).to_bytes(2, "big") + wire)
        await writer.drain()
        data = await asyncio.wait_for(_read_tcp_message(reader), timeout)
        resp = Message.parse(data)
        return resp.qr and resp.opcode == Opcode.NOTIFY
    except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        return False
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


class SecondaryZone:
    """A zone we mirror from a primary, refreshed on the SOA timers or on NOTIFY."""

    def __init__(self, origin: Name, primary: str, *, port: int = 53,
                 key: TSIGKey | None = None, min_refresh: float = 60.0,
                 on_refresh=None):
        self.origin = origin
        self.primary = primary
        self.port = port
        self.key = key
        self.min_refresh = min_refresh
        self.on_refresh = on_refresh          # callback(zone) when a fresh copy lands
        self.zone: Zone | None = None
        self.last_refresh: float = 0.0
        self._task: asyncio.Task | None = None
        self._wake = asyncio.Event()

    @property
    def serial(self) -> int:
        return self.zone.soa.serial if self.zone and self.zone.soa else 0

    async def refresh_once(self) -> bool:
        """Pull the zone. Uses IXFR when we already hold a copy (the response may
        be an up-to-date SOA, a delta we apply, or a full AXFR-style zone), AXFR
        otherwise. Returns True if the zone changed."""
        try:
            if self.zone is not None:
                records = await transfer_records(
                    self.primary, self.port, self.origin, key=self.key,
                    qtype=Type.IXFR, client_serial=self.serial)
                new = apply_ixfr(self.zone, records, self.origin)
            else:
                new = await axfr_in(self.primary, self.port, self.origin, key=self.key)
        except Exception as e:
            log.warning("refresh of %s failed: %s", self.origin.to_text(), e)
            return False
        changed = self.zone is None or new.soa.serial != self.serial
        self.zone, self.last_refresh = new, time.time()
        if self.on_refresh is not None:
            self.on_refresh(new)
        return changed

    def notify(self) -> None:
        """Wake the refresh loop (called when a NOTIFY arrives from the primary)."""
        self._wake.set()

    async def run(self) -> None:
        """Background refresh loop honouring SOA refresh/retry."""
        while True:
            ok = await self.refresh_once()
            soa = self.zone.soa if self.zone else None
            delay = max(self.min_refresh, soa.refresh if (ok and soa) else
                        (soa.retry if soa else self.min_refresh))
            self._wake.clear()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._wake.wait(), delay)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self.run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
