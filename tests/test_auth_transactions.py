"""Adversarial tests for the authoritative transactions: NOTIFY, UPDATE, TSIG.

These are the opcodes that *change* things or *read out* whole zones, so they are
the ones worth attacking. Each test is a specific capability an attacker has, and
the assertion is what the server must refuse:

  * being able to send a UDP packet at all (source addresses are unauthenticated)
  * knowing which addresses appear in an allow-list
  * having captured one legitimately signed message
"""
from __future__ import annotations

import base64

import pytest

from dnsguard.auth_zone import Zone, ZoneStore
from dnsguard.auth_zone.handler import AuthHandler
from dnsguard.auth_zone.secondary import SecondaryZone
from dnsguard.auth_zone.tsig import TSIGError, TSIGKey, sign_wire, verify_wire
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Flags, Opcode, Rcode

ORIGIN = Name.from_text("example.com")
SECRET = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
PRIMARY = "192.0.2.10"


def _key(name="xfr-key."):
    return TSIGKey.from_base64(name, SECRET)


def _zone() -> Zone:
    z = Zone(ORIGIN)
    z.add(ORIGIN, Type.SOA, R.SOA(Name.from_text("ns.example.com"),
                                  Name.from_text("hostmaster.example.com"),
                                  2024010101, 7200, 3600, 1209600, 3600))
    z.add(ORIGIN, Type.NS, R.NS(Name.from_text("ns.example.com")))
    z.add(ORIGIN, Type.A, R.A("93.184.216.34"))
    return z


def _handler(*, allow_update=(), tsig_key=None, with_secondary=False):
    store = ZoneStore()
    store.add(_zone())
    keyring = {"xfr-key.": _key()}
    h = AuthHandler(store, keyring)
    h.set_zone_policy(ORIGIN, allow_update=allow_update, tsig_key=tsig_key)
    if with_secondary:
        h.register_secondary(SecondaryZone(ORIGIN, PRIMARY, key=None))
    return h


def _update_msg(add_ip="6.6.6.6", name="evil.example.com") -> Message:
    m = Message(id=0x2001)
    m.flags |= (Opcode.UPDATE << Flags.OPCODE_SHIFT)
    m.questions.append(Question(ORIGIN, Type.SOA, Class.IN))
    m.answers = []                                   # prerequisites: none
    m.authority.append(RR(Name.from_text(name), Type.A, Class.IN, 300, R.A(add_ip)))
    return m


def _notify_msg() -> Message:
    m = Message(id=0x3001)
    m.flags |= (Opcode.NOTIFY << Flags.OPCODE_SHIFT)
    m.set_flag(Flags.AA, True)
    m.questions.append(Question(ORIGIN, Type.SOA, Class.IN))
    return m


# ------------------------------------------------------------------ NOTIFY
def test_notify_from_a_stranger_does_not_trigger_a_transfer():
    """RFC 1996 §3.10: the secondary checks the NOTIFY source against its primary.

    Without that check, anything able to send one UDP packet makes us pull the
    whole zone from our own primary — a 60-octet packet amplified into a full
    zone transfer, repeatable, and spoofable because nothing about a UDP source
    address is authenticated.
    """
    h = _handler(with_secondary=True)
    sec = h.secondaries[ORIGIN.to_text().lower()]
    wire = _notify_msg().to_wire()

    h.handle_udp(wire, Message.parse(wire), "198.51.100.66")     # not the primary
    assert not sec._wake.is_set(), "a stranger's NOTIFY scheduled a refresh"

    h.handle_udp(wire, Message.parse(wire), PRIMARY)             # the real primary
    assert sec._wake.is_set(), "the primary's own NOTIFY must still work"


def test_notify_from_a_stranger_is_refused_not_silently_accepted():
    h = _handler(with_secondary=True)
    wire = _notify_msg().to_wire()
    out = h.handle_udp(wire, Message.parse(wire), "198.51.100.66")
    assert out is not None
    assert Message.parse(out).rcode == Rcode.REFUSED


def test_notify_for_a_zone_we_do_not_mirror_is_harmless():
    h = _handler()                                   # no secondary registered
    wire = _notify_msg().to_wire()
    out = h.handle_udp(wire, Message.parse(wire), PRIMARY)
    assert out is not None and Message.parse(out).rcode == Rcode.REFUSED


# ------------------------------------------------------------------ UPDATE
def test_update_with_no_acl_is_refused():
    """A zone is never writable by default."""
    h = _handler()
    wire = _update_msg().to_wire()
    out = h.handle_tcp(wire, Message.parse(wire), "192.0.2.1")[0]
    assert Message.parse(out).rcode == Rcode.REFUSED


def test_update_from_an_address_outside_the_acl_is_refused():
    h = _handler(allow_update=["192.0.2.1"])
    wire = _update_msg().to_wire()
    out = h.handle_tcp(wire, Message.parse(wire), "198.51.100.66")[0]
    assert Message.parse(out).rcode == Rcode.REFUSED


def test_an_ip_only_update_over_udp_is_refused():
    """The sharpest one. An allow-list of addresses is a real control over TCP,
    where the peer had to complete a handshake to get there. Over UDP the source
    address is a claim, not evidence — so an off-path attacker who knows (or
    guesses) one allowed address can rewrite the zone with a single spoofed
    packet and never needs to see the reply.

    So an unsigned UPDATE arriving over UDP is refused even from an allowed
    address; over TCP, or with TSIG, it is honoured.
    """
    h = _handler(allow_update=["192.0.2.1"])
    wire = _update_msg().to_wire()

    out = h.handle_udp(wire, Message.parse(wire), "192.0.2.1")
    assert Message.parse(out).rcode == Rcode.REFUSED
    assert not h.zonestore.authoritative_for(
        Name.from_text("evil.example.com")).records.get(Name.from_text("evil.example.com"))

    # the same update over TCP is a legitimate, if old-fashioned, configuration
    out = h.handle_tcp(wire, Message.parse(wire), "192.0.2.1")[0]
    assert Message.parse(out).rcode == Rcode.NOERROR


def test_a_tsig_signed_update_over_udp_is_honoured():
    """TSIG proves the sender holds the key, which is evidence a spoofed source
    address is not. Signed updates therefore need no transport privilege."""
    h = _handler(allow_update=["192.0.2.1"], tsig_key="xfr-key.")
    wire, _ = sign_wire(_update_msg().to_wire(), _key())
    out = h.handle_udp(wire, Message.parse(wire), "192.0.2.1")
    assert Message.parse(out).rcode == Rcode.NOERROR


def test_an_update_signed_with_the_wrong_key_is_refused():
    h = _handler(allow_update=["192.0.2.1"], tsig_key="xfr-key.")
    other = TSIGKey.from_base64("other-key.", SECRET)
    h.keyring["other-key."] = other
    wire, _ = sign_wire(_update_msg().to_wire(), other)
    out = h.handle_udp(wire, Message.parse(wire), "192.0.2.1")
    assert Message.parse(out).rcode == Rcode.NOTAUTH


def test_an_update_for_someone_elses_zone_is_notauth():
    h = _handler(allow_update=["192.0.2.1"])
    m = _update_msg()
    m.questions = [Question(Name.from_text("other.test"), Type.SOA, Class.IN)]
    wire = m.to_wire()
    out = h.handle_tcp(wire, Message.parse(wire), "192.0.2.1")[0]
    assert Message.parse(out).rcode == Rcode.NOTAUTH


# -------------------------------------------------------------------- TSIG
def test_the_accepted_clock_skew_is_ours_not_the_senders():
    """The MAC covers the fudge, so a peer's choice cannot be *tampered with* —
    but it is still the peer's choice. A signer that writes the maximum fudge
    gives anyone who captures that message ~18 hours in which to replay it, and
    the receiver is the party that should decide how long a signature stays
    fresh. `fudge_max` existed as a parameter and was never read.
    """
    key = _key()
    m = Message(id=0x1234)
    m.questions.append(Question(ORIGIN, Type.AXFR, Class.IN))
    # fudge is a 16-bit field, so the widest a sender can ask for is ~18 hours
    signed, _ = sign_wire(m.to_wire(), key, time_signed=1_000_000, fudge=65_000)

    # inside the sender's generous window, but far outside ours
    with pytest.raises(TSIGError, match="skew"):
        verify_wire(signed, {"xfr-key.": key}, now=1_000_000 + 3_600, fudge_max=300)
    # and still fine when it really is fresh
    verify_wire(signed, {"xfr-key.": key}, now=1_000_000 + 10, fudge_max=300)


def test_a_sender_may_be_stricter_than_we_are():
    """`fudge_max` is a ceiling, not an override: a peer asking for a tighter
    window than ours gets the tighter window."""
    key = _key()
    m = Message(id=0x1234)
    m.questions.append(Question(ORIGIN, Type.AXFR, Class.IN))
    signed, _ = sign_wire(m.to_wire(), key, time_signed=1_000_000, fudge=5)
    with pytest.raises(TSIGError, match="skew"):
        verify_wire(signed, {"xfr-key.": key}, now=1_000_000 + 60, fudge_max=300)
