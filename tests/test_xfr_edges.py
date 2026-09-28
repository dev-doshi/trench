"""Zone-transfer assembly: envelope chunking and interpreting an IXFR reply.

`apply_ixfr` interprets bytes from a primary against the zone we currently
serve, so every malformed shape it can be handed has to fail loudly rather than
produce a half-applied zone. The chunker matters for a different reason: an
envelope that does not fit the wire is one no secondary can read.
"""
from __future__ import annotations

import copy

import pytest

from trench.auth_zone import Zone
from trench.auth_zone.xfr import (
    MAX_MSG_BYTES,
    RRS_PER_MSG,
    apply_ixfr,
    axfr_messages,
    ixfr_complete,
    ixfr_messages,
    serial_gt,
    zone_from_records,
)
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name

ORIGIN = Name.from_text("example.com.")


def n(s):
    return Name.from_text(s)


def _soa(serial=1):
    return R.SOA(n("ns.example.com."), n("hm.example.com."), serial,
                 7200, 3600, 1209600, 3600)


def _zone(serial=1, hosts=1):
    z = Zone(ORIGIN)
    z.add(ORIGIN, Type.SOA, _soa(serial))
    z.add(ORIGIN, Type.NS, R.NS(n("ns.example.com.")))
    for i in range(hosts):
        z.add(n(f"h{i}.example.com."), Type.A, R.A(f"192.0.2.{i % 250 + 1}"))
    return z


def _query(rtype=Type.AXFR):
    m = Message(id=1)
    m.questions.append(Question(ORIGIN, rtype, Class.IN))
    return m


def _soa_rr(serial):
    return RR(ORIGIN, Type.SOA, Class.IN, 3600, _soa(serial))


# --- serial arithmetic ---
@pytest.mark.parametrize("a,b,gt", [
    (2, 1, True), (1, 2, False), (1, 1, False),
    (0, 0xFFFFFFFF, True),              # wraps forward
    (0xFFFFFFFF, 0, False),
])
def test_serial_comparison(a, b, gt):
    assert serial_gt(a, b) is gt


# --- envelope chunking ---
def test_an_axfr_opens_and_closes_with_the_same_soa():
    msgs = axfr_messages(_query(), _zone(serial=5))
    records = [rr for m in msgs for rr in m.answers]
    assert records[0].rtype == Type.SOA and records[-1].rtype == Type.SOA
    assert records[0].rdata.serial == records[-1].rdata.serial == 5


def test_every_envelope_is_authoritative():
    msgs = axfr_messages(_query(), _zone(hosts=300))
    assert msgs and all(m.aa for m in msgs)


def test_a_large_zone_is_split_into_several_envelopes():
    msgs = axfr_messages(_query(), _zone(hosts=RRS_PER_MSG * 3))
    assert len(msgs) > 1


def test_no_envelope_exceeds_the_wire_limit():
    """An envelope a secondary cannot read is not a transfer."""
    zone = Zone(ORIGIN)
    zone.add(ORIGIN, Type.SOA, _soa(1))
    for i in range(400):
        zone.add(n(f"{'x' * 60}{i}.example.com."), Type.TXT,
                 R.TXT([b"y" * 250]))
    for m in axfr_messages(_query(), zone):
        assert len(m.to_wire()) <= MAX_MSG_BYTES or len(m.answers) == 1


def test_a_zone_holding_only_its_soa_still_transfers():
    """A secondary is owed a reply even when there is nothing else to send."""
    bare = Zone(ORIGIN)
    bare.add(ORIGIN, Type.SOA, _soa(1))
    records = [rr for m in axfr_messages(_query(), bare) for rr in m.answers]
    assert [rr.rtype for rr in records] == [Type.SOA, Type.SOA]


def test_a_zone_with_no_soa_is_not_transferable():
    """Regression: it serialised an RR whose rdata is None and took the
    connection down with an AttributeError instead of answering."""
    from trench.auth_zone.store import ZoneStore
    from trench.auth_zone.xfr_service import TransferService, ZoneTransferPolicy
    from trench.wire.rrtypes import Rcode
    store = ZoneStore()
    store.add(Zone(ORIGIN))                 # a bare local record, no apex SOA
    svc = TransferService(store)
    svc.set_policy(ORIGIN, ZoneTransferPolicy(allow_transfer={"127.0.0.1"}))
    query = _query()
    out = svc.handle_transfer(query.to_wire(), query, "127.0.0.1")
    assert len(out) == 1
    assert Message.parse(out[0]).rcode == Rcode.NOTAUTH


def test_every_record_in_the_zone_survives_the_round_trip():
    zone = _zone(serial=3, hosts=40)
    records = [rr for m in axfr_messages(_query(), zone) for rr in m.answers]
    rebuilt = zone_from_records(records, ORIGIN)
    assert rebuilt.soa.serial == 3
    for i in range(40):
        assert n(f"h{i}.example.com.") in rebuilt.records


# --- completion detection ---
def test_a_transfer_is_complete_at_its_closing_soa():
    records = [rr for m in axfr_messages(_query(), _zone()) for rr in m.answers]
    assert ixfr_complete(records) is True
    assert ixfr_complete(records[:-1]) is False
    assert ixfr_complete([]) is False


def test_an_up_to_date_reply_is_a_single_soa():
    zone = _zone(serial=5)
    msgs = ixfr_messages(_query(Type.IXFR), zone, client_serial=5)
    records = [rr for m in msgs for rr in m.answers]
    assert len(records) == 1 and records[0].rtype == Type.SOA
    assert ixfr_complete(records) is True


# --- apply_ixfr ---
def test_an_up_to_date_reply_returns_the_zone_unchanged():
    current = _zone(serial=5)
    assert apply_ixfr(current, [_soa_rr(5)], ORIGIN) is current


def test_an_up_to_date_reply_with_nothing_held_is_an_error():
    with pytest.raises(ValueError, match="no current zone"):
        apply_ixfr(None, [_soa_rr(5)], ORIGIN)


def test_a_reply_with_no_leading_soa_is_malformed():
    with pytest.raises(ValueError, match="no leading SOA"):
        apply_ixfr(None, [RR(n("www.example.com."), Type.A, Class.IN, 300,
                             R.A("192.0.2.1"))], ORIGIN)


def test_an_empty_reply_is_malformed():
    with pytest.raises(ValueError, match="no leading SOA"):
        apply_ixfr(None, [], ORIGIN)


def test_an_axfr_style_reply_replaces_the_zone_wholesale():
    records = [rr for m in axfr_messages(_query(), _zone(serial=9, hosts=2))
               for rr in m.answers]
    rebuilt = apply_ixfr(_zone(serial=1), records, ORIGIN)
    assert rebuilt.soa.serial == 9
    assert n("h1.example.com.") in rebuilt.records


def test_a_delta_with_nothing_to_apply_it_to_is_an_error():
    delta = [_soa_rr(6), _soa_rr(5),
             RR(n("gone.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.1")),
             _soa_rr(6),
             RR(n("new.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.2")),
             _soa_rr(6)]
    with pytest.raises(ValueError, match="hold no zone"):
        apply_ixfr(None, delta, ORIGIN)


def test_a_delta_adds_and_removes_and_bumps_the_serial():
    current = _zone(serial=5, hosts=2)
    delta = [_soa_rr(6), _soa_rr(5),
             RR(n("h0.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.1")),
             _soa_rr(6),
             RR(n("new.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.9")),
             _soa_rr(6)]
    before = copy.deepcopy(current.records)
    updated = apply_ixfr(current, delta, ORIGIN)
    assert updated.soa.serial == 6
    assert n("h0.example.com.") not in updated.records
    assert n("new.example.com.") in updated.records
    assert current.records == before, "the delta must not mutate the held zone"


def test_a_truncated_delta_is_refused():
    current = _zone(serial=5, hosts=1)
    delta = [_soa_rr(6), _soa_rr(5),
             RR(n("h0.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.1"))]
    with pytest.raises(ValueError, match="truncated"):
        apply_ixfr(current, delta, ORIGIN)


def test_removing_a_record_that_is_not_there_is_harmless():
    current = _zone(serial=5, hosts=1)
    delta = [_soa_rr(6), _soa_rr(5),
             RR(n("never.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.1")),
             _soa_rr(6),
             RR(n("new.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.9")),
             _soa_rr(6)]
    updated = apply_ixfr(current, delta, ORIGIN)
    assert updated.soa.serial == 6
    assert n("new.example.com.") in updated.records


def test_removing_one_of_several_records_keeps_the_rest():
    current = _zone(serial=5)
    current.add(n("multi.example.com."), Type.A, R.A("192.0.2.1"))
    current.add(n("multi.example.com."), Type.A, R.A("192.0.2.2"))
    delta = [_soa_rr(6), _soa_rr(5),
             RR(n("multi.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.1")),
             _soa_rr(6), _soa_rr(6)]
    updated = apply_ixfr(current, delta, ORIGIN)
    got = {rd.to_text() for rd in updated.records[n("multi.example.com.")][Type.A]}
    assert got == {"192.0.2.2"}


def test_several_deltas_are_applied_in_order():
    current = _zone(serial=5, hosts=2)
    delta = [
        _soa_rr(7),
        _soa_rr(5), RR(n("h0.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.1")),
        _soa_rr(6), RR(n("mid.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.5")),
        _soa_rr(6), RR(n("mid.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.5")),
        _soa_rr(7), RR(n("last.example.com."), Type.A, Class.IN, 300, R.A("192.0.2.6")),
        _soa_rr(7),
    ]
    updated = apply_ixfr(current, delta, ORIGIN)
    assert updated.soa.serial == 7
    assert n("h0.example.com.") not in updated.records
    assert n("mid.example.com.") not in updated.records
    assert n("last.example.com.") in updated.records


# --- the primary's side of IXFR ---
def test_a_journal_that_does_not_reach_back_falls_back_to_a_full_transfer():
    """A secondary that has fallen far behind is owed the whole zone."""
    zone = _zone(serial=9, hosts=2)
    zone.journal = [{"from": 8, "to": 9, "delete": [], "add": []}]
    msgs = ixfr_messages(_query(Type.IXFR), zone, client_serial=3)
    records = [rr for m in msgs for rr in m.answers]
    assert len(records) > 2, "an AXFR-style reply, not a delta"


def test_a_zone_with_no_journal_falls_back_to_a_full_transfer():
    zone = _zone(serial=9, hosts=2)
    zone.journal = []
    records = [rr for m in ixfr_messages(_query(Type.IXFR), zone, client_serial=8)
               for rr in m.answers]
    assert len(records) > 2
