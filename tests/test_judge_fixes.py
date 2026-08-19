"""Judge-pass regressions: transfer ACL default-deny, IXFR delta handling,
re-sign stability (stable DS, no artifact duplication), reload keeping DB
clients, TSIG-signed UPDATE responses."""
from __future__ import annotations

import asyncio
import base64

import pytest

from dnsguard.auth_zone import Zone
from dnsguard.auth_zone.secondary import SecondaryZone
from dnsguard.auth_zone.sign import sign_zone
from dnsguard.auth_zone.store import ZoneStore
from dnsguard.auth_zone.tsig import TSIGKey, sign_wire, verify_wire
from dnsguard.auth_zone.update import apply_update
from dnsguard.auth_zone.xfr import apply_ixfr, axfr_records, ixfr_complete, ixfr_messages
from dnsguard.auth_zone.xfr_service import TransferService, ZoneTransferPolicy
from dnsguard.resolver.dnssec.keys import key_tag
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Flags, Opcode, Rcode

ORIGIN = Name.from_text("example.com.")
SECRET = base64.b64encode(b"j" * 32).decode()


def _zone(serial=1):
    z = Zone(ORIGIN)
    z.add(ORIGIN, Type.SOA, R.SOA(Name.from_text("ns.example.com."),
          Name.from_text("host.example.com."), serial, 7200, 3600, 1209600, 3600))
    z.add(ORIGIN, Type.NS, R.NS(Name.from_text("ns.example.com.")))
    z.add(Name.from_text("www.example.com."), Type.A, R.A("192.0.2.1"))
    return z


def _update_msg(authority):
    m = Message(id=7)
    m.flags |= (Opcode.UPDATE << Flags.OPCODE_SHIFT)
    m.questions.append(Question(ORIGIN, Type.SOA))
    m.authority = authority
    return m


# --- fix 1: empty allow_transfer denies everyone ---
def test_empty_allow_transfer_denies():
    z = _zone()
    store = ZoneStore(); store.add(z)
    svc = TransferService(store)
    # a policy exists (e.g. because allow_update was configured) but transfer
    # list is empty -> transfers must be REFUSED, not open to the world
    svc.set_policy(ORIGIN, ZoneTransferPolicy(allow_transfer=set()))
    q = Message(id=1); q.questions.append(Question(ORIGIN, Type.AXFR))
    out = svc.handle_transfer(q.to_wire(), q, "10.9.9.9")
    resp = Message.parse(out[0])
    assert resp.rcode == Rcode.REFUSED and not resp.answers


# --- fix 2: IXFR delta interpretation on the secondary ---
def _delta_records(zone_new, steps):
    """Assemble a raw IXFR delta RR stream the way a primary would."""
    soa_new = RR(ORIGIN, Type.SOA, Class.IN, 7200, zone_new.soa)
    out = [soa_new]
    for frm, to, dels, adds in steps:
        s = zone_new.soa
        out.append(RR(ORIGIN, Type.SOA, Class.IN, 7200,
                      R.SOA(s.mname, s.rname, frm, s.refresh, s.retry, s.expire, s.minimum)))
        out.extend(dels)
        out.append(RR(ORIGIN, Type.SOA, Class.IN, 7200,
                      R.SOA(s.mname, s.rname, to, s.refresh, s.retry, s.expire, s.minimum)))
        out.extend(adds)
    out.append(soa_new)
    return out


def test_apply_ixfr_delta_mutates_not_replaces():
    old = _zone(1)
    newz = _zone(2)
    add = RR(Name.from_text("new.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.9"))
    delete = RR(Name.from_text("www.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.1"))
    records = _delta_records(newz, [(1, 2, [delete], [add])])
    assert ixfr_complete(records)
    result = apply_ixfr(old, records, ORIGIN)
    assert result.soa.serial == 2
    # delta applied on top of the existing zone: NS survived, www gone, new added
    assert result.lookup(ORIGIN, Type.NS).answers
    assert result.lookup(Name.from_text("new.example.com."), Type.A).answers
    assert result.lookup(Name.from_text("www.example.com."), Type.A).rcode == Rcode.NXDOMAIN
    # the original zone object is untouched
    assert old.soa.serial == 1


def test_apply_ixfr_uptodate_and_full():
    cur = _zone(5)
    soa_only = [RR(ORIGIN, Type.SOA, Class.IN, 7200, cur.soa)]
    assert apply_ixfr(cur, soa_only, ORIGIN) is cur          # up to date
    full = axfr_records(_zone(9))
    rebuilt = apply_ixfr(cur, full, ORIGIN)                  # AXFR-style
    assert rebuilt.soa.serial == 9


def test_ixfr_complete_multi_step_not_early():
    newz = _zone(3)
    a1 = RR(Name.from_text("a.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.10"))
    a2 = RR(Name.from_text("b.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.11"))
    records = _delta_records(newz, [(1, 2, [], [a1]), (2, 3, [], [a2])])
    # stream truncated before the closing SOA(new) must NOT look complete
    assert not ixfr_complete(records[:-1])
    assert ixfr_complete(records)
    result = apply_ixfr(_zone(1), records, ORIGIN)
    assert result.soa.serial == 3
    assert result.lookup(Name.from_text("a.example.com."), Type.A).answers
    assert result.lookup(Name.from_text("b.example.com."), Type.A).answers


def test_signed_zone_never_serves_journal_delta():
    z = _zone(1)
    sign_zone(z)
    rr = RR(Name.from_text("blog.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.5"))
    assert apply_update(z, _update_msg([rr])) == Rcode.NOERROR
    assert z.journal                                          # journal exists...
    q = Message(id=1); q.questions.append(Question(ORIGIN, Type.IXFR))
    msgs = ixfr_messages(q, z, client_serial=1)
    rrs = [rr for m in msgs for rr in m.answers]
    # ...but the response is a full AXFR-style zone (with RRSIGs), not a delta
    assert rrs[1].rtype != Type.SOA
    assert any(r.rtype == Type.RRSIG for r in rrs)


@pytest.mark.asyncio
async def test_secondary_full_ixfr_cycle_over_wire():
    primary_zone = _zone(1)
    store = ZoneStore(); store.add(primary_zone)
    svc = TransferService(store)
    svc.set_policy(ORIGIN, ZoneTransferPolicy(allow_transfer={"127.0.0.1"}))

    async def handle(reader, writer):
        try:
            while True:
                hdr = await reader.readexactly(2)
                data = await reader.readexactly(int.from_bytes(hdr, "big"))
                query = Message.parse(data)
                for wire in svc.handle_transfer(data, query, "127.0.0.1"):
                    writer.write(len(wire).to_bytes(2, "big") + wire)
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        sec = SecondaryZone(ORIGIN, "127.0.0.1", port=port)
        assert await sec.refresh_once() is True               # initial AXFR
        assert sec.serial == 1
        # primary changes -> journal delta
        rr = RR(Name.from_text("new.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.9"))
        assert apply_update(primary_zone, _update_msg([rr])) == Rcode.NOERROR
        assert await sec.refresh_once() is True               # IXFR delta applied
        assert sec.serial == 2
        assert sec.zone.lookup(Name.from_text("new.example.com."), Type.A).answers
        assert sec.zone.lookup(ORIGIN, Type.NS).answers       # old data intact
        assert await sec.refresh_once() is False              # up to date now
    finally:
        server.close(); await server.wait_closed()


# --- fix 3+4: re-sign stability ---
def test_resign_keeps_ds_and_no_duplicates():
    z = _zone(1)
    res = sign_zone(z)
    kt0 = res.key_tag
    for i in range(3):                                        # several updates
        rr = RR(Name.from_text(f"u{i}.example.com."), Type.A, Class.IN, 300,
                R.A(f"192.0.2.{50 + i}"))
        assert apply_update(z, _update_msg([rr])) == Rcode.NOERROR
    apex = z.records[ORIGIN]
    assert len(apex[Type.DNSKEY]) == 1
    assert len(apex[Type.CDS]) == 1 and len(apex[Type.CDNSKEY]) == 1
    # the SAME key: DS/key_tag unchanged across re-signs
    assert key_tag(apex[Type.DNSKEY][0]) == kt0
    assert apex[Type.CDS][0].key_tag == kt0


def test_resign_nsec3_no_stale_hashed_names():
    z = _zone(1)
    sign_zone(z, nsec3=True, nsec3_salt=b"\x01\x02", nsec3_iterations=2)
    n_hashed_before = sum(1 for _, node in z.records.items() if Type.NSEC3 in node)
    rr = RR(Name.from_text("blog.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.5"))
    assert apply_update(z, _update_msg([rr])) == Rcode.NOERROR
    n_hashed_after = sum(1 for _, node in z.records.items() if Type.NSEC3 in node)
    # exactly one new hashed owner (the new name); no stale leftovers
    assert n_hashed_after == n_hashed_before + 1
    assert z.records[ORIGIN].get(Type.NSEC3PARAM) and len(z.records[ORIGIN][Type.NSEC3PARAM]) == 1
    # denial flavor preserved (still NSEC3, not NSEC)
    assert not any(Type.NSEC in node for node in z.records.values())


def test_apex_bitmap_includes_cds():
    from dnsguard.resolver.dnssec.nsec import bitmap_has
    z = _zone(1)
    sign_zone(z)
    nsec = z.records[ORIGIN][Type.NSEC][0]
    assert bitmap_has(nsec.type_bitmap, Type.CDS)
    assert bitmap_has(nsec.type_bitmap, Type.CDNSKEY)
    assert bitmap_has(nsec.type_bitmap, Type.DNSKEY)


# --- fix 6: signed UPDATE gets a signed response ---
def test_update_response_is_tsig_signed():
    from dnsguard.auth_zone.handler import AuthHandler
    z = _zone(1)
    store = ZoneStore(); store.add(z)
    key = TSIGKey.from_base64("upd.", SECRET)
    handler = AuthHandler(store, {"upd.": key})
    handler.set_zone_policy(ORIGIN, allow_update=["127.0.0.1"], tsig_key="upd.")
    rr = RR(Name.from_text("blog.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.5"))
    signed_query, req_mac = sign_wire(_update_msg([rr]).to_wire(), key)
    out = handler.handle_udp(signed_query, Message.parse(signed_query), "127.0.0.1")
    resp = Message.parse(out)
    assert resp.rcode == Rcode.NOERROR
    assert resp.additional and resp.additional[-1].rtype == Type.TSIG
    # response MAC chains to the request MAC and verifies
    verify_wire(out, {"upd.": key}, request_mac=req_mac)
