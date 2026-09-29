"""Inbound zone transfer: the limits, the refresh loop, and NOTIFY.

A primary is not necessarily benign — TSIG is optional per secondary and the
connection can be in the middle — so the caps on an inbound transfer are the
only thing between a hostile or broken primary and a process that grows until
it is OOM-killed. None of them was exercised.
"""
from __future__ import annotations

import asyncio
import contextlib

import pytest

from trench.auth_zone import Zone
from trench.auth_zone.secondary import (
    SecondaryZone,
    TransferError,
    axfr_in,
    send_notify,
    transfer_records,
)
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Opcode, Rcode

ORIGIN = Name.from_text("example.com.")


def n(s):
    return Name.from_text(s)


def _soa(serial=1, refresh=7200, retry=3600):
    return R.SOA(n("ns.example.com."), n("hm.example.com."),
                 serial, refresh, retry, 1209600, 3600)


def _envelope(records, rcode=Rcode.NOERROR):
    m = Message(id=0, flags=Flags.QR | Flags.AA)
    m.set_rcode(rcode)
    m.questions.append(Question(ORIGIN, Type.AXFR, Class.IN))
    m.answers.extend(records)
    return m.to_wire()


def _answering(query_wire, wire, wrong_id=False):
    """`wire` rewritten to answer `query_wire`: its id and its question, as a
    real primary echoes them. Bytes that do not parse are sent as they are."""
    try:
        query, msg = Message.parse(query_wire), Message.parse(wire)
    except Exception:
        return wire
    msg.id = query.id ^ 1 if wrong_id else query.id
    if msg.questions:
        msg.questions[:] = query.questions
    return msg.to_wire()


async def _serve(envelopes, host="127.0.0.1", hang=False, wrong_id=False):
    """A primary that replies with `envelopes` (a list of wire messages)."""
    state = {"requests": []}

    async def handle(reader, writer):
        try:
            while True:
                hdr = await reader.readexactly(2)
                data = await reader.readexactly(int.from_bytes(hdr, "big"))
                state["requests"].append(data)
                if hang:
                    await asyncio.sleep(60)
                for wire in envelopes:
                    wire = _answering(data, wire, wrong_id)
                    writer.write(len(wire).to_bytes(2, "big") + wire)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    server = await asyncio.start_server(handle, host, 0)
    return server, server.sockets[0].getsockname()[1], state


def _full_axfr(serial=1, extra=()):
    soa = RR(ORIGIN, Type.SOA, Class.IN, 3600, _soa(serial))
    body = [RR(n("www.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.1")), *extra]
    return _envelope([soa, *body, soa])


# --- a well-behaved transfer ---
@pytest.mark.asyncio
async def test_a_complete_axfr_assembles_a_zone():
    server, port, _ = await _serve([_full_axfr(42)])
    try:
        zone = await axfr_in("127.0.0.1", port, ORIGIN)
        assert zone.soa.serial == 42
        assert n("www.example.com.") in zone.records
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_a_transfer_split_across_envelopes_is_reassembled():
    soa = RR(ORIGIN, Type.SOA, Class.IN, 3600, _soa(9))
    first = _envelope([soa, RR(n("a.example.com."), Type.A, Class.IN, 300,
                               R.A("192.0.2.1"))])
    second = _envelope([RR(n("b.example.com."), Type.A, Class.IN, 300,
                           R.A("192.0.2.2")), soa])
    server, port, _ = await _serve([first, second])
    try:
        zone = await axfr_in("127.0.0.1", port, ORIGIN)
        assert n("a.example.com.") in zone.records
        assert n("b.example.com.") in zone.records
    finally:
        server.close()
        await server.wait_closed()


# --- refusals and limits ---
@pytest.mark.asyncio
async def test_a_refused_transfer_is_reported():
    server, port, _ = await _serve([_envelope([], rcode=Rcode.REFUSED)])
    try:
        with pytest.raises(TransferError, match="refused"):
            await axfr_in("127.0.0.1", port, ORIGIN)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_an_empty_first_envelope_is_an_error():
    server, port, _ = await _serve([_envelope([]), _full_axfr()])
    try:
        with pytest.raises(TransferError, match="empty transfer"):
            await axfr_in("127.0.0.1", port, ORIGIN)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_too_many_records_stops_the_transfer():
    """An endless stream used to be accepted forever, because every envelope
    reset the per-message timeout."""
    soa = RR(ORIGIN, Type.SOA, Class.IN, 3600, _soa(1))
    chunk = _envelope([soa] + [RR(n(f"h{i}.example.com."), Type.A, Class.IN, 300,
                                  R.A("192.0.2.1")) for i in range(20)])
    server, port, _ = await _serve([chunk] * 50)
    try:
        with pytest.raises(TransferError, match="exceeded its limits"):
            await transfer_records("127.0.0.1", port, ORIGIN, max_records=50)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_too_many_bytes_stops_the_transfer():
    soa = RR(ORIGIN, Type.SOA, Class.IN, 3600, _soa(1))
    chunk = _envelope([soa] + [RR(n(f"h{i}.example.com."), Type.A, Class.IN, 300,
                                  R.A("192.0.2.1")) for i in range(20)])
    server, port, _ = await _serve([chunk] * 50)
    try:
        with pytest.raises(TransferError, match="exceeded its limits"):
            await transfer_records("127.0.0.1", port, ORIGIN, max_bytes=200)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_too_many_envelopes_stops_the_transfer():
    soa = RR(ORIGIN, Type.SOA, Class.IN, 3600, _soa(1))
    chunk = _envelope([soa, RR(n("a.example.com."), Type.A, Class.IN, 300,
                               R.A("192.0.2.1"))])
    server, port, _ = await _serve([chunk] * 50)
    try:
        with pytest.raises(TransferError, match="exceeded its limits"):
            await transfer_records("127.0.0.1", port, ORIGIN, max_envelopes=3)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_a_primary_that_never_answers_times_out():
    server, port, _ = await _serve([], hang=True)
    try:
        with pytest.raises((TimeoutError, TransferError, asyncio.TimeoutError)):
            await transfer_records("127.0.0.1", port, ORIGIN, timeout=0.2)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_a_primary_that_is_not_listening_fails_rather_than_hanging():
    with pytest.raises(OSError):
        await transfer_records("127.0.0.1", 1, ORIGIN, timeout=1)


# --- the reply has to answer our query ---
@pytest.mark.asyncio
async def test_a_reply_with_another_id_is_not_loaded():
    server, port, _ = await _serve([_full_axfr()], wrong_id=True)
    try:
        with pytest.raises(TransferError):
            await transfer_records("127.0.0.1", port, ORIGIN, timeout=2)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_a_reply_for_another_zone_is_not_loaded():
    other = n("evil.example.")

    async def handle(reader, writer):
        hdr = await reader.readexactly(2)
        query = Message.parse(await reader.readexactly(int.from_bytes(hdr, "big")))
        m = Message.parse(_full_axfr())
        m.id = query.id
        m.questions[:] = [Question(other, Type.AXFR, Class.IN)]
        wire = m.to_wire()
        writer.write(len(wire).to_bytes(2, "big") + wire)
        await writer.drain()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        with pytest.raises(TransferError):
            await transfer_records("127.0.0.1", port, ORIGIN, timeout=2)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_a_notify_ack_with_another_id_is_not_an_ack():
    async def handle(reader, writer):
        hdr = await reader.readexactly(2)
        resp = Message.parse(await reader.readexactly(int.from_bytes(hdr, "big"))).reply()
        resp.id ^= 0xFFFF
        wire = resp.to_wire()
        writer.write(len(wire).to_bytes(2, "big") + wire)
        await writer.drain()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        assert await send_notify("127.0.0.1", port, ORIGIN, timeout=1) is False
    finally:
        server.close()
        await server.wait_closed()


# --- NOTIFY ---
@pytest.mark.asyncio
async def test_a_notify_that_is_acked_reports_success():
    async def handle(reader, writer):
        hdr = await reader.readexactly(2)
        data = await reader.readexactly(int.from_bytes(hdr, "big"))
        query = Message.parse(data)
        resp = query.reply()
        resp.set_flag(Flags.AA, True)
        wire = resp.to_wire()
        writer.write(len(wire).to_bytes(2, "big") + wire)
        await writer.drain()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        assert await send_notify("127.0.0.1", port, ORIGIN) is True
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_a_notify_to_nothing_reports_failure():
    assert await send_notify("127.0.0.1", 1, ORIGIN, timeout=1) is False


@pytest.mark.asyncio
async def test_a_notify_that_is_not_answered_reports_failure():
    async def handle(reader, writer):
        await asyncio.sleep(30)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        assert await send_notify("127.0.0.1", port, ORIGIN, timeout=0.2) is False
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_a_notify_carries_the_right_opcode_and_question():
    seen = {}

    async def handle(reader, writer):
        hdr = await reader.readexactly(2)
        data = await reader.readexactly(int.from_bytes(hdr, "big"))
        seen["msg"] = Message.parse(data)
        resp = seen["msg"].reply()
        wire = resp.to_wire()
        writer.write(len(wire).to_bytes(2, "big") + wire)
        await writer.drain()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        await send_notify("127.0.0.1", port, ORIGIN)
    finally:
        server.close()
        await server.wait_closed()
    msg = seen["msg"]
    assert msg.opcode == Opcode.NOTIFY and msg.aa is True
    assert msg.question.name == ORIGIN and msg.question.rtype == Type.SOA


# --- SecondaryZone ---
@pytest.mark.asyncio
async def test_a_first_refresh_pulls_a_full_zone():
    server, port, state = await _serve([_full_axfr(11)])
    sec = SecondaryZone(ORIGIN, "127.0.0.1", port=port)
    try:
        assert await sec.refresh_once() is True
        assert sec.zone is not None and sec.zone.soa.serial == 11
        assert sec.last_refresh > 0
        # A first pull is an AXFR: there is nothing to compute a delta from.
        assert Message.parse(state["requests"][0]).question.rtype == Type.AXFR
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_a_later_refresh_asks_for_a_delta():
    server, port, state = await _serve([_full_axfr(11)])
    sec = SecondaryZone(ORIGIN, "127.0.0.1", port=port)
    try:
        await sec.refresh_once()
        await sec.refresh_once()
        assert Message.parse(state["requests"][1]).question.rtype == Type.IXFR
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_a_failed_refresh_is_reported_not_raised(caplog):
    sec = SecondaryZone(ORIGIN, "127.0.0.1", port=1)
    assert await sec.refresh_once() is False
    assert sec.zone is None
    assert any("refresh of" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_a_refresh_notifies_its_callback():
    server, port, _ = await _serve([_full_axfr(11)])
    seen = []
    sec = SecondaryZone(ORIGIN, "127.0.0.1", port=port, on_refresh=seen.append)
    try:
        await sec.refresh_once()
        assert len(seen) == 1 and isinstance(seen[0], Zone)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_the_refresh_loop_can_be_started_and_stopped():
    server, port, _ = await _serve([_full_axfr(11)])
    sec = SecondaryZone(ORIGIN, "127.0.0.1", port=port, min_refresh=3600)
    try:
        sec.start()
        sec.start()                     # idempotent
        for _ in range(200):
            await asyncio.sleep(0.01)
            if sec.zone is not None:
                break
        assert sec.zone is not None
    finally:
        await sec.stop()
        await sec.stop()                # also idempotent
        server.close()
        await server.wait_closed()
    assert sec._task is None


@pytest.mark.asyncio
async def test_a_notify_wakes_the_refresh_loop():
    server, port, state = await _serve([_full_axfr(11)])
    sec = SecondaryZone(ORIGIN, "127.0.0.1", port=port, min_refresh=3600)
    try:
        sec.start()
        for _ in range(200):
            await asyncio.sleep(0.01)
            if sec.zone is not None:
                break
        before = len(state["requests"])
        sec.notify()
        for _ in range(200):
            await asyncio.sleep(0.01)
            if len(state["requests"]) > before:
                break
        assert len(state["requests"]) > before, "NOTIFY did not wake the loop"
    finally:
        await sec.stop()
        server.close()
        await server.wait_closed()
