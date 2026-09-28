"""The last uncovered branches across several small subsystems.

Each of these is a failure path: a services catalogue that will not parse, a
safe-browsing list file that is empty, a shared-memory slot whose key does not
match, a ring-log frame that is torn. None of them should ever cost an answer.
"""
from __future__ import annotations

import json
import time

import pytest

from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.edns import Edns
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Rcode


# --- the blocked-services catalogue ---
def test_the_builtin_catalogue_is_used_when_there_is_no_file(tmp_path):
    from trench.filter.services import Services
    svc = Services.load(tmp_path)
    assert svc.table, "the shipped catalogue should not be empty"


def test_a_catalogue_file_is_read(tmp_path):
    from trench.filter.services import Services
    (tmp_path / "services.json").write_text(
        json.dumps({"custom": ["custom.example.com"]}))
    svc = Services.load(tmp_path)
    assert svc.service_for("www.custom.example.com") == "custom"


def test_a_catalogue_that_will_not_parse_falls_back_to_the_builtin(tmp_path,
                                                                   caplog):
    from trench.filter.services import Services
    (tmp_path / "services.json").write_text("{not json")
    svc = Services.load(tmp_path)
    assert svc.table
    assert any("bad services.json" in r.getMessage() for r in caplog.records)


def test_a_name_in_no_service_matches_nothing():
    from trench.filter.services import Services
    assert Services({"tiktok": ["tiktok.com"]}).service_for("example.com") is None


def test_a_subdomain_of_a_service_matches_it():
    from trench.filter.services import Services
    svc = Services({"tiktok": ["tiktok.com"]})
    assert svc.service_for("cdn.tiktok.com") == "tiktok"


def test_nothing_selected_blocks_nothing():
    from trench.filter.services import Services
    svc = Services({"tiktok": ["tiktok.com"]})
    assert svc.is_blocked("tiktok.com", frozenset()) is None


def test_a_selected_service_blocks_its_names():
    from trench.filter.services import Services
    svc = Services({"tiktok": ["tiktok.com"]})
    assert svc.is_blocked("tiktok.com", frozenset({"tiktok"})) == "tiktok"
    assert svc.is_blocked("example.com", frozenset({"tiktok"})) is None
    assert svc.is_blocked("tiktok.com", frozenset({"other"})) is None


def test_an_unscheduled_service_is_blocked_whenever_it_is_selected():
    from trench.filter.services import Services
    svc = Services({"tiktok": ["tiktok.com"]})
    assert svc.blocked_now("tiktok") is True
    assert svc.has_schedule(frozenset({"tiktok"})) is False


def test_a_scheduled_service_is_blocked_only_inside_its_window():
    """A scheduled verdict is a function of the clock, not of the query."""
    from trench.filter.services import Services
    svc = Services({"tiktok": ["tiktok.com"]},
                   schedules={"tiktok": [(0, 9 * 60, 17 * 60)]})   # Monday 09-17
    assert svc.has_schedule(frozenset({"tiktok"})) is True

    monday_noon = time.mktime((2026, 1, 5, 12, 0, 0, 0, 5, -1))
    monday_night = time.mktime((2026, 1, 5, 22, 0, 0, 0, 5, -1))
    tuesday_noon = time.mktime((2026, 1, 6, 12, 0, 0, 1, 6, -1))
    assert svc.blocked_now("tiktok", monday_noon) is True
    assert svc.blocked_now("tiktok", monday_night) is False
    assert svc.blocked_now("tiktok", tuesday_noon) is False
    assert svc.is_blocked("tiktok.com", frozenset({"tiktok"}), monday_night) is None


# --- safe browsing lists ---
def test_a_missing_list_file_falls_back_to_the_builtin(tmp_path):
    from trench.filter.safebrowse import _read
    assert _read(tmp_path / "nope.txt", {"builtin.example"}) == {"builtin.example"}


def test_a_list_file_is_read_ignoring_comments_and_blanks(tmp_path):
    from trench.filter.safebrowse import _read
    path = tmp_path / "list.txt"
    path.write_text("# a comment\n\nBad.Example.COM\nother.example  # trailing\n")
    assert _read(path, set()) == {"bad.example.com", "other.example"}


def test_a_file_with_nothing_usable_falls_back_to_the_builtin(tmp_path):
    from trench.filter.safebrowse import _read
    path = tmp_path / "list.txt"
    path.write_text("# only comments\n\n")
    assert _read(path, {"builtin.example"}) == {"builtin.example"}


def test_invalid_bytes_in_a_list_file_do_not_stop_the_read(tmp_path):
    from trench.filter.safebrowse import _read
    path = tmp_path / "list.txt"
    path.write_bytes(b"bad.example.com\n\xff\xfe\n")
    assert "bad.example.com" in _read(path, set())


# --- the shared L2 cache ---
def _shared(slots=64, payload=512):
    from trench.cache.shared import SharedCache
    return SharedCache.create(slots=slots, payload=payload)


def test_a_slot_whose_key_does_not_match_is_a_miss():
    c = _shared()
    c.put(1234, b"\x00wire", 60)
    assert c.get(1234) is not None
    assert c.get(9999) is None


def test_an_expired_slot_is_a_miss(monkeypatch):
    import trench.cache.shared as mod
    c = _shared()
    c.put(1234, b"\x00wire", 1)
    real = mod.time.monotonic
    monkeypatch.setattr(mod.time, "monotonic", lambda: real() + 10)
    assert c.get(1234) is None


def test_a_payload_that_does_not_fit_is_not_stored():
    c = _shared(slots=8, payload=16)
    c.put(1, b"x" * 64, 60)
    assert c.get(1) is None


def test_an_empty_payload_or_a_dead_ttl_is_not_stored():
    c = _shared()
    c.put(2, b"", 60)
    assert c.get(2) is None
    c.put(3, b"ok", 0)
    assert c.get(3) is None


def test_deleting_a_slot_stops_it_being_read_back():
    """Otherwise a targeted flush is undone by the next L1 miss reading the
    flushed answer straight back out of L2."""
    c = _shared()
    c.put(1234, b"wire", 60)
    c.delete(1234)
    assert c.get(1234) is None
    c.delete(9999)              # a key that was never there


def test_clearing_invalidates_everything():
    c = _shared()
    for i in range(5):
        c.put(i + 1, b"wire", 60)
    c.clear()
    assert all(c.get(i + 1) is None for i in range(5))


# --- the cross-worker ring log ---
def _ring(lanes=2):
    from trench.store.ringlog import RecordRing
    return RecordRing.create(lanes)


def test_a_row_that_cannot_be_encoded_is_dropped():
    lane = _ring().for_lane(1)
    assert lane.push([object()]) is False


def test_a_row_too_large_for_a_slot_is_shrunk_or_dropped():
    lane = _ring().for_lane(1)
    assert lane.push(["x" * (lane.slot_bytes * 2)]) in (True, False)


def test_rows_published_by_a_worker_are_drained_by_the_primary():
    ring = _ring()
    worker = ring.for_lane(1)
    assert worker.push(["a", 1]) is True
    assert worker.push(["b", 2]) is True
    primary = ring.for_lane(0)
    assert primary.drain(10) == [["a", 1], ["b", 2]]
    assert primary.drain(10) == [], "a drained row is not drained twice"


def test_the_primarys_own_lane_is_not_drained_back_into_itself():
    """Its records go straight to SQLite."""
    ring = _ring()
    primary = ring.for_lane(0)
    primary.push(["mine", 1])
    assert primary.drain(10) == []


def test_a_torn_frame_costs_one_row_not_the_lane():
    ring = _ring()
    worker = ring.for_lane(1)
    worker.push(["good", 1])
    worker.push(["also-good", 2])
    off = worker._slot_off(1, 0)
    ring.mm[off + 8:off + 12] = b"\xff\xff\xff\xff"
    got = ring.for_lane(0).drain(10)
    assert ["also-good", 2] in got


def test_the_drain_honours_its_limit():
    ring = _ring()
    worker = ring.for_lane(1)
    for i in range(6):
        worker.push(["row", i])
    assert len(ring.for_lane(0).drain(3)) == 3


def test_a_full_lane_drops_rather_than_blocking_the_resolver():
    ring = _ring()
    worker = ring.for_lane(1)
    for i in range(worker.slots * 3):
        worker.push(["row", i, "x" * 100])
    assert worker.dropped() > 0


# --- Message edges ---
def test_a_message_shorter_than_a_header_is_refused():
    from trench.errors import WireError
    with pytest.raises(WireError, match="short header"):
        Message.parse(b"\x00" * 11)


def test_the_extended_rcode_is_carried_in_the_opt():
    m = Message(id=1)
    m.edns = Edns()
    m.set_rcode(Rcode.BADVERS)
    assert m.rcode == Rcode.BADVERS
    assert m.edns.ext_rcode != 0


def test_a_stale_extended_rcode_does_not_leak_into_a_plain_one():
    """The `rcode` property ORs those bits back in, so a stale ext_rcode left
    over from a parsed message made a plain NOERROR read back as BADVERS."""
    m = Message(id=1)
    m.edns = Edns()
    m.edns.ext_rcode = 1
    m.set_rcode(Rcode.NOERROR)
    assert m.rcode == Rcode.NOERROR
    assert m.edns.ext_rcode == 0


def test_the_minimum_ttl_ignores_the_opt_pseudo_record():
    q = Message(id=1)
    q.questions.append(Question(Name.from_text("example.com."), Type.A, Class.IN))
    resp = q.reply(Rcode.NOERROR)
    resp.answers.append(RR(Name.from_text("example.com."), Type.A, Class.IN, 300,
                           R.A("192.0.2.1")))
    resp.authority.append(RR(Name.from_text("example.com."), Type.NS, Class.IN, 60,
                             R.NS(Name.from_text("ns.example.com."))))
    resp.edns = Edns(udp_size=1232)
    assert resp.min_ttl() == 60


def test_a_message_with_no_records_has_no_minimum_ttl():
    assert Message(id=1).min_ttl() is None


def test_a_reply_copies_the_opcode_and_the_recursion_flag():
    q = Message(id=1, flags=Flags.RD | (5 << Flags.OPCODE_SHIFT))
    r = q.reply(Rcode.NOERROR)
    assert r.opcode == 5 and r.rd is True and r.qr is True
