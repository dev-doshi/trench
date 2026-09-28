"""RFC 2136 UPDATE: prerequisites, authorization, and the deletes that must not
be honoured.

The zone-transaction suite covers the happy paths. What is tested here is every
way an update is supposed to be refused — because a dynamic UPDATE is remote
input that rewrites the zone this server is authoritative for, and each refusal
below is the only thing standing between an authorised-but-wrong message and a
zone that cannot be served.
"""
from __future__ import annotations

from trench.auth_zone import Zone
from trench.auth_zone.update import (
    MAX_JOURNAL,
    UpdatePolicy,
    apply_update,
    check_prerequisites,
)
from trench.wire import RR, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Class, Flags, Opcode, Rcode

ORIGIN = Name.from_text("example.com.")


def n(s):
    return Name.from_text(s)


def _zone(serial=1):
    z = Zone(ORIGIN)
    z.add(ORIGIN, Type.SOA, R.SOA(n("ns.example.com."), n("hostmaster.example.com."),
                                  serial, 7200, 3600, 1209600, 3600))
    z.add(ORIGIN, Type.NS, R.NS(n("ns.example.com.")))
    z.add(n("www.example.com."), Type.A, R.A("192.0.2.1"))
    z.add(n("www.example.com."), Type.A, R.A("192.0.2.9"))
    z.add(n("mail.example.com."), Type.MX, R.MX(10, n("mail.example.com.")))
    return z


def _update(prereqs=(), changes=(), zone_name=ORIGIN, qtype=Type.SOA):
    m = Message(id=1, flags=Opcode.UPDATE << Flags.OPCODE_SHIFT)
    m.questions.append(Question(zone_name, qtype, Class.IN))
    m.answers.extend(prereqs)
    m.authority.extend(changes)
    return m


def _rr(name, rtype, rdata=None, rclass=Class.IN, ttl=300):
    return RR(n(name), rtype, rclass, ttl, rdata or R.A("192.0.2.55"))


# --- shape of the message ---
def test_an_update_must_name_a_zone():
    assert apply_update(_zone(), Message(id=1)) == Rcode.FORMERR


def test_the_question_type_must_be_soa():
    assert apply_update(_zone(), _update(qtype=Type.A)) == Rcode.FORMERR


def test_an_update_for_another_zone_is_notauth():
    msg = _update(zone_name=n("elsewhere.test."))
    assert apply_update(_zone(), msg) == Rcode.NOTAUTH


def test_a_zone_without_an_soa_cannot_be_updated():
    z = Zone(ORIGIN)
    assert apply_update(z, _update(changes=[_rr("new.example.com.", Type.A)])) \
        == Rcode.SERVFAIL


# --- prerequisites (RFC 2136 §3.2) ---
def test_a_prerequisite_with_a_ttl_is_malformed():
    pre = [_rr("www.example.com.", Type.A, rclass=Class.ANY, ttl=1)]
    assert check_prerequisites(_zone(), pre) == Rcode.FORMERR


def test_name_in_use_prerequisite():
    z = _zone()
    ok = [RR(n("www.example.com."), Type.ANY, Class.ANY, 0, R.A("0.0.0.0"))]
    assert check_prerequisites(z, ok) == Rcode.NOERROR
    missing = [RR(n("nope.example.com."), Type.ANY, Class.ANY, 0, R.A("0.0.0.0"))]
    assert check_prerequisites(z, missing) == Rcode.NXDOMAIN


def test_rrset_exists_prerequisite_is_value_independent():
    z = _zone()
    ok = [RR(n("www.example.com."), Type.A, Class.ANY, 0, R.A("10.10.10.10"))]
    assert check_prerequisites(z, ok) == Rcode.NOERROR
    missing = [RR(n("www.example.com."), Type.MX, Class.ANY, 0, R.A("0.0.0.0"))]
    assert check_prerequisites(z, missing) == Rcode.NXRRSET


def test_name_not_in_use_prerequisite():
    z = _zone()
    ok = [RR(n("free.example.com."), Type.ANY, Class.NONE, 0, R.A("0.0.0.0"))]
    assert check_prerequisites(z, ok) == Rcode.NOERROR
    taken = [RR(n("www.example.com."), Type.ANY, Class.NONE, 0, R.A("0.0.0.0"))]
    assert check_prerequisites(z, taken) == Rcode.YXDOMAIN


def test_rrset_does_not_exist_prerequisite():
    z = _zone()
    ok = [RR(n("www.example.com."), Type.TXT, Class.NONE, 0, R.A("0.0.0.0"))]
    assert check_prerequisites(z, ok) == Rcode.NOERROR
    present = [RR(n("www.example.com."), Type.A, Class.NONE, 0, R.A("0.0.0.0"))]
    assert check_prerequisites(z, present) == Rcode.YXRRSET


def test_a_value_dependent_prerequisite_needs_the_exact_rrset():
    z = _zone()
    exact = [RR(n("www.example.com."), Type.A, Class.IN, 0, R.A("192.0.2.1")),
             RR(n("www.example.com."), Type.A, Class.IN, 0, R.A("192.0.2.9"))]
    assert check_prerequisites(z, exact) == Rcode.NOERROR

    partial = [RR(n("www.example.com."), Type.A, Class.IN, 0, R.A("192.0.2.1"))]
    assert check_prerequisites(z, partial) == Rcode.NXRRSET

    extra = [*exact, RR(n("www.example.com."), Type.A, Class.IN, 0, R.A("192.0.2.7"))]
    assert check_prerequisites(z, extra) == Rcode.NXRRSET


def test_no_prerequisites_always_passes():
    assert check_prerequisites(_zone(), []) == Rcode.NOERROR


def test_a_failing_prerequisite_stops_the_update_changing_anything():
    z = _zone()
    before = {k: dict(v) for k, v in z.records.items()}
    msg = _update(prereqs=[RR(n("nope.example.com."), Type.ANY, Class.ANY, 0,
                              R.A("0.0.0.0"))],
                  changes=[_rr("new.example.com.", Type.A)])
    assert apply_update(z, msg) == Rcode.NXDOMAIN
    assert n("new.example.com.") not in z.records
    assert set(z.records) == set(before)


# --- authorization ---
def test_a_change_outside_the_zone_is_notzone():
    msg = _update(changes=[_rr("evil.test.", Type.A)])
    assert apply_update(_zone(), msg) == Rcode.NOTZONE


def test_a_policy_that_forbids_everything_refuses():
    msg = _update(changes=[_rr("new.example.com.", Type.A)])
    assert apply_update(_zone(), msg, UpdatePolicy(allow=False)) == Rcode.REFUSED


def test_a_policy_scoped_to_named_records():
    allowed = UpdatePolicy(names={n("dyn.example.com.")})
    z = _zone()
    ok = _update(changes=[_rr("dyn.example.com.", Type.A)])
    assert apply_update(z, ok, allowed) == Rcode.NOERROR
    denied = _update(changes=[_rr("other.example.com.", Type.A)])
    assert apply_update(z, denied, allowed) == Rcode.REFUSED


def test_the_policy_itself_refuses_out_of_zone_names():
    pol = UpdatePolicy()
    assert pol.permits(_zone(), n("elsewhere.test.")) is False
    assert pol.permits(_zone(), n("www.example.com.")) is True


# --- record class validation ---
def test_an_update_record_of_a_foreign_class_is_malformed():
    """It used to fall through into the add branch, so a record of a foreign
    class was stored and then served as IN."""
    z = _zone()
    msg = _update(changes=[_rr("new.example.com.", Type.A, rclass=Class.CH)])
    assert apply_update(z, msg) == Rcode.FORMERR
    assert n("new.example.com.") not in z.records


def test_one_bad_class_rejects_the_whole_update():
    """Checked before anything is applied, so a bad update changes nothing
    rather than half of the zone."""
    z = _zone()
    msg = _update(changes=[_rr("good.example.com.", Type.A),
                           _rr("bad.example.com.", Type.A, rclass=Class.CH)])
    assert apply_update(z, msg) == Rcode.FORMERR
    assert n("good.example.com.") not in z.records


# --- adds ---
def test_an_add_bumps_the_serial_and_journals_the_change():
    z = _zone(serial=5)
    msg = _update(changes=[_rr("new.example.com.", Type.A, R.A("192.0.2.30"))])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert z.soa.serial == 6
    entry = z.journal[-1]
    assert entry["from"] == 5 and entry["to"] == 6
    assert [rr.name for rr in entry["add"]] == [n("new.example.com.")]
    assert entry["delete"] == []


def test_adding_a_record_that_is_already_there_is_a_no_op():
    z = _zone(serial=5)
    msg = _update(changes=[_rr("www.example.com.", Type.A, R.A("192.0.2.1"))])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert z.soa.serial == 5, "a no-op must not bump the serial"
    assert z.journal == []


def test_an_update_with_no_changes_at_all_is_a_no_op():
    z = _zone(serial=5)
    assert apply_update(z, _update()) == Rcode.NOERROR
    assert z.soa.serial == 5


def test_an_add_to_an_existing_rrset_appends():
    z = _zone()
    msg = _update(changes=[_rr("www.example.com.", Type.A, R.A("192.0.2.44"))])
    apply_update(z, msg)
    got = {rd.to_text() for rd in z.records[n("www.example.com.")][Type.A]}
    assert got == {"192.0.2.1", "192.0.2.9", "192.0.2.44"}


# --- deletes ---
def test_deleting_one_record_leaves_the_rest_of_the_rrset():
    z = _zone()
    msg = _update(changes=[RR(n("www.example.com."), Type.A, Class.NONE, 0,
                              R.A("192.0.2.1"))])
    assert apply_update(z, msg) == Rcode.NOERROR
    got = {rd.to_text() for rd in z.records[n("www.example.com.")][Type.A]}
    assert got == {"192.0.2.9"}
    assert z.journal[-1]["delete"]


def test_deleting_the_last_record_removes_the_name():
    z = _zone()
    msg = _update(changes=[
        RR(n("mail.example.com."), Type.MX, Class.NONE, 0,
           R.MX(10, n("mail.example.com.")))])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert n("mail.example.com.") not in z.records


def test_deleting_a_record_that_is_not_there_changes_nothing():
    z = _zone(serial=5)
    msg = _update(changes=[RR(n("www.example.com."), Type.A, Class.NONE, 0,
                              R.A("10.10.10.10"))])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert z.soa.serial == 5
    assert len(z.records[n("www.example.com.")][Type.A]) == 2


def test_deleting_at_a_name_that_does_not_exist_changes_nothing():
    z = _zone(serial=5)
    msg = _update(changes=[RR(n("ghost.example.com."), Type.A, Class.NONE, 0,
                              R.A("10.10.10.10"))])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert z.soa.serial == 5


def test_an_individual_soa_delete_is_ignored():
    """Regression: an authorised updater could delete the apex SOA, which left
    the zone SOA-less in memory and then crashed `_bump_serial` on the way out —
    no reply, no journal entry, no NOTIFY, and SERVFAIL for every update after
    it."""
    z = _zone(serial=5)
    msg = _update(changes=[RR(ORIGIN, Type.SOA, Class.NONE, 0, z.soa)])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert z.soa is not None
    assert z.soa.serial == 5
    # And the zone still works afterwards.
    assert apply_update(z, _update(changes=[_rr("after.example.com.", Type.A)])) \
        == Rcode.NOERROR


def test_the_last_apex_ns_cannot_be_deleted_individually():
    z = _zone()
    msg = _update(changes=[RR(ORIGIN, Type.NS, Class.NONE, 0,
                              R.NS(n("ns.example.com.")))])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert z.records[ORIGIN][Type.NS]


def test_one_of_several_apex_ns_records_can_be_deleted():
    z = _zone()
    z.add(ORIGIN, Type.NS, R.NS(n("ns2.example.com.")))
    msg = _update(changes=[RR(ORIGIN, Type.NS, Class.NONE, 0,
                              R.NS(n("ns2.example.com.")))])
    assert apply_update(z, msg) == Rcode.NOERROR
    got = {rd.to_text() for rd in z.records[ORIGIN][Type.NS]}
    assert got == {"ns.example.com."}


def test_deleting_a_whole_rrset_by_type():
    z = _zone()
    msg = _update(changes=[RR(n("www.example.com."), Type.A, Class.ANY, 0,
                              R.A("0.0.0.0"))])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert n("www.example.com.") not in z.records
    assert len(z.journal[-1]["delete"]) == 2


def test_an_rrset_delete_cannot_take_the_apex_soa_or_ns():
    z = _zone(serial=5)
    for rtype in (Type.SOA, Type.NS):
        msg = _update(changes=[RR(ORIGIN, rtype, Class.ANY, 0, R.A("0.0.0.0"))])
        assert apply_update(z, msg) == Rcode.NOERROR
    assert z.soa is not None and z.records[ORIGIN][Type.NS]
    assert z.soa.serial == 5


def test_deleting_every_rrset_at_a_name():
    z = _zone()
    z.add(n("www.example.com."), Type.TXT, R.TXT([b"hello"]))
    msg = _update(changes=[RR(n("www.example.com."), Type.ANY, Class.ANY, 0,
                              R.A("0.0.0.0"))])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert n("www.example.com.") not in z.records
    assert len(z.journal[-1]["delete"]) == 3


def test_deleting_everything_at_the_apex_spares_soa_and_ns():
    z = _zone()
    z.add(ORIGIN, Type.TXT, R.TXT([b"v=spf1 -all"]))
    msg = _update(changes=[RR(ORIGIN, Type.ANY, Class.ANY, 0, R.A("0.0.0.0"))])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert z.soa is not None
    assert Type.NS in z.records[ORIGIN]
    assert Type.TXT not in z.records[ORIGIN]


def test_deleting_every_rrset_at_a_name_that_does_not_exist():
    z = _zone(serial=5)
    msg = _update(changes=[RR(n("ghost.example.com."), Type.ANY, Class.ANY, 0,
                              R.A("0.0.0.0"))])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert z.soa.serial == 5


# --- the journal ---
def test_the_journal_is_bounded():
    """A secondary that has fallen far behind falls back to AXFR; keeping every
    delta forever would grow without limit."""
    z = _zone()
    for i in range(MAX_JOURNAL + 20):
        msg = _update(changes=[_rr(f"host{i}.example.com.", Type.A,
                                   R.A(f"192.0.2.{i % 250 + 1}"))])
        assert apply_update(z, msg) == Rcode.NOERROR
    assert len(z.journal) == MAX_JOURNAL
    # The oldest entries went, the newest stayed.
    assert z.journal[-1]["to"] == z.soa.serial


def test_the_serial_wraps_rather_than_overflowing():
    z = _zone(serial=0xFFFFFFFF)
    apply_update(z, _update(changes=[_rr("new.example.com.", Type.A)]))
    assert z.soa.serial == 0


# --- signed zones ---
def test_an_update_to_a_signed_zone_re_signs_it():
    from trench.auth_zone.sign import sign_zone
    z = _zone()
    sign_zone(z)
    assert z.signed
    before = set(z.rrsigs)
    msg = _update(changes=[_rr("new.example.com.", Type.A, R.A("192.0.2.60"))])
    assert apply_update(z, msg) == Rcode.NOERROR
    assert (n("new.example.com."), Type.A) in z.rrsigs
    assert set(z.rrsigs) > before, "the new record must be signed too"
    # The apex DNSKEY survives, so the DS at the parent stays valid.
    assert Type.DNSKEY in z.records[ORIGIN]
