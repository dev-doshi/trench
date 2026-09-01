"""Authoritative zone transactions: AXFR/IXFR, secondary pull, NOTIFY,
RFC 2136 UPDATE, NSEC3 online signing, CDS/CDNSKEY."""
from __future__ import annotations

import asyncio
import base64

import pytest

from trench.auth_zone import Zone
from trench.auth_zone.secondary import TransferError, axfr_in, send_notify
from trench.auth_zone.sign import sign_zone
from trench.auth_zone.store import ZoneStore
from trench.auth_zone.tsig import TSIGKey
from trench.auth_zone.update import UpdatePolicy, apply_update
from trench.auth_zone.xfr import (
    axfr_records,
    ixfr_messages,
    serial_gt,
    zone_from_records,
)
from trench.auth_zone.xfr_service import TransferService, ZoneTransferPolicy, is_notify
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Opcode, Rcode

ORIGIN = Name.from_text("example.com.")
SECRET = base64.b64encode(b"k" * 32).decode()


def _zone(serial=1):
    z = Zone(ORIGIN)
    z.add(ORIGIN, Type.SOA, R.SOA(Name.from_text("ns.example.com."),
          Name.from_text("hostmaster.example.com."), serial, 7200, 3600, 1209600, 3600))
    z.add(ORIGIN, Type.NS, R.NS(Name.from_text("ns.example.com.")))
    z.add(Name.from_text("www.example.com."), Type.A, R.A("192.0.2.1"))
    z.add(Name.from_text("mail.example.com."), Type.A, R.A("192.0.2.2"))
    return z


# --- serial arithmetic (RFC 1982) ---
def test_serial_gt_wraparound():
    assert serial_gt(2, 1)
    assert not serial_gt(1, 2)
    assert serial_gt(0, 2**32 - 1)          # wraps forward
    assert not serial_gt(2**32 - 1, 0)


# --- AXFR generation + reassembly ---
def test_axfr_roundtrip():
    z = _zone(5)
    recs = axfr_records(z)
    assert recs[0].rtype == Type.SOA and recs[-1].rtype == Type.SOA
    z2 = zone_from_records(recs, ORIGIN)
    assert z2.soa.serial == 5
    ans = z2.lookup(Name.from_text("www.example.com."), Type.A)
    assert ans.answers[0].rdata.address == "192.0.2.1"


def test_axfr_carries_dnssec():
    z = _zone()
    sign_zone(z)
    recs = axfr_records(z)
    assert any(rr.rtype == Type.RRSIG for rr in recs)
    z2 = zone_from_records(recs, ORIGIN)
    assert z2.signed and z2.rrsigs


# --- IXFR ---
def test_ixfr_uptodate_returns_soa_only():
    z = _zone(10)
    q = Message(id=1)
    q.questions.append(Question(ORIGIN, Type.IXFR))
    msgs = ixfr_messages(q, z, client_serial=10)
    assert len(msgs) == 1 and len(msgs[0].answers) == 1
    assert msgs[0].answers[0].rtype == Type.SOA


def test_ixfr_delta_from_journal():
    z = _zone(1)
    # simulate an update that produced a journal entry
    add = RR(Name.from_text("new.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.9"))
    z.journal = [{"from": 1, "to": 2, "delete": [], "add": [add]}]
    z.soa.serial = 2
    q = Message(id=1)
    q.questions.append(Question(ORIGIN, Type.IXFR))
    msgs = ixfr_messages(q, z, client_serial=1)
    rrs = [rr for m in msgs for rr in m.answers]
    # delta stream contains the added record
    assert any(rr.name == Name.from_text("new.example.com.") for rr in rrs)


# --- dynamic UPDATE (RFC 2136) ---
def _update_msg(authority, prereqs=None):
    m = Message(id=7)
    m.flags |= (Opcode.UPDATE << Flags.OPCODE_SHIFT)
    m.questions.append(Question(ORIGIN, Type.SOA))
    m.answers = prereqs or []
    m.authority = authority
    return m


def test_update_add_record():
    z = _zone(1)
    rr = RR(Name.from_text("blog.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.5"))
    rc = apply_update(z, _update_msg([rr]))
    assert rc == Rcode.NOERROR
    assert z.soa.serial == 2  # bumped
    assert z.lookup(Name.from_text("blog.example.com."), Type.A).answers


def test_update_delete_rrset():
    z = _zone(1)
    delete = RR(Name.from_text("www.example.com."), Type.ANY, Class.ANY, 0,
                R.Unknown(Type.ANY, b""))
    rc = apply_update(z, _update_msg([delete]))
    assert rc == Rcode.NOERROR
    assert z.lookup(Name.from_text("www.example.com."), Type.A).rcode == Rcode.NXDOMAIN


def test_update_prereq_nxrrset_blocks():
    z = _zone(1)
    prereq = RR(Name.from_text("absent.example.com."), Type.A, Class.ANY, 0,
                R.Unknown(Type.A, b""))
    add = RR(Name.from_text("x.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.7"))
    rc = apply_update(z, _update_msg([add], prereqs=[prereq]))
    assert rc == Rcode.NXRRSET
    assert z.soa.serial == 1  # unchanged


def test_update_out_of_zone_refused():
    z = _zone(1)
    rr = RR(Name.from_text("evil.other.net."), Type.A, Class.IN, 300, R.A("6.6.6.6"))
    assert apply_update(z, _update_msg([rr])) == Rcode.NOTZONE


def test_update_policy_denies():
    z = _zone(1)
    rr = RR(Name.from_text("blog.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.5"))
    pol = UpdatePolicy(names={Name.from_text("allowed.example.com.")})
    assert apply_update(z, _update_msg([rr]), pol) == Rcode.REFUSED


def test_update_resigns_signed_zone():
    z = _zone(1)
    sign_zone(z)
    rr = RR(Name.from_text("blog.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.5"))
    assert apply_update(z, _update_msg([rr])) == Rcode.NOERROR
    assert z.signed
    assert (Name.from_text("blog.example.com."), Type.A) in z.rrsigs


# --- NSEC3 online signing ---
def test_nsec3_signing():
    z = _zone(1)
    sign_zone(z, nsec3=True, nsec3_salt=b"\xaa\xbb", nsec3_iterations=5)
    assert z.records[ORIGIN].get(Type.NSEC3PARAM)
    nsec3s = [n for n, node in z.records.items() if Type.NSEC3 in node]
    assert nsec3s
    # every NSEC3 RR is signed
    for owner in nsec3s:
        assert (owner, Type.NSEC3) in z.rrsigs


def test_cds_cdnskey_published():
    z = _zone(1)
    res = sign_zone(z)
    cds = z.records[ORIGIN].get(Type.CDS)
    cdnskey = z.records[ORIGIN].get(Type.CDNSKEY)
    assert cds and cdnskey
    assert cds[0].key_tag == res.key_tag


# --- NOTIFY detection ---
def test_is_notify():
    m = Message(id=1)
    m.flags |= (Opcode.NOTIFY << Flags.OPCODE_SHIFT)
    m.questions.append(Question(ORIGIN, Type.SOA))
    assert is_notify(m)


# --- full loopback: secondary pulls from a TransferService primary ---
async def _serve_transfer(svc: TransferService, host="127.0.0.1"):
    async def handle(reader, writer):
        try:
            while True:
                hdr = await reader.readexactly(2)
                data = await reader.readexactly(int.from_bytes(hdr, "big"))
                query = Message.parse(data)
                if svc.is_transfer(query):
                    for wire in svc.handle_transfer(data, query, "127.0.0.1"):
                        writer.write(len(wire).to_bytes(2, "big") + wire)
                    await writer.drain()
                elif is_notify(query):
                    resp = query.reply()
                    resp.set_flag(Flags.AA, True)
                    w = resp.to_wire()
                    writer.write(len(w).to_bytes(2, "big") + w)
                    await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()
    server = await asyncio.start_server(handle, host, 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


@pytest.mark.asyncio
async def test_secondary_axfr_in_plain():
    z = _zone(42)
    store = ZoneStore(); store.add(z)
    svc = TransferService(store)
    svc.set_policy(ORIGIN, ZoneTransferPolicy(allow_transfer={"127.0.0.1"}))
    server, port = await _serve_transfer(svc)
    try:
        pulled = await axfr_in("127.0.0.1", port, ORIGIN)
        assert pulled.soa.serial == 42
        assert pulled.lookup(Name.from_text("mail.example.com."), Type.A).answers
    finally:
        server.close(); await server.wait_closed()


@pytest.mark.asyncio
async def test_secondary_axfr_in_tsig():
    z = _zone(7)
    store = ZoneStore(); store.add(z)
    key = TSIGKey.from_base64("xfr.", SECRET)
    svc = TransferService(store, keyring={"xfr.": key})
    svc.set_policy(ORIGIN, ZoneTransferPolicy(allow_transfer={"127.0.0.1"}, tsig_key="xfr."))
    server, port = await _serve_transfer(svc)
    try:
        pulled = await axfr_in("127.0.0.1", port, ORIGIN, key=key)
        assert pulled.soa.serial == 7
    finally:
        server.close(); await server.wait_closed()


@pytest.mark.asyncio
async def test_transfer_refused_without_tsig():
    z = _zone(7)
    store = ZoneStore(); store.add(z)
    key = TSIGKey.from_base64("xfr.", SECRET)
    svc = TransferService(store, keyring={"xfr.": key})
    svc.set_policy(ORIGIN, ZoneTransferPolicy(allow_transfer={"127.0.0.1"}, tsig_key="xfr."))
    server, port = await _serve_transfer(svc)
    try:
        with pytest.raises(TransferError):
            await axfr_in("127.0.0.1", port, ORIGIN)  # no key -> primary rejects
    finally:
        server.close(); await server.wait_closed()


@pytest.mark.asyncio
async def test_send_notify_acked():
    z = _zone(1)
    store = ZoneStore(); store.add(z)
    svc = TransferService(store)
    server, port = await _serve_transfer(svc)
    try:
        assert await send_notify("127.0.0.1", port, ORIGIN) is True
    finally:
        server.close(); await server.wait_closed()
