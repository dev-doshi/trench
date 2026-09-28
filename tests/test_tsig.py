"""TSIG transaction security (RFC 8945): sign/verify round-trips + error paths."""
from __future__ import annotations

import base64

import pytest

from trench.auth_zone.tsig import TSIGError, TSIGKey, sign_wire, verify_wire
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name

SECRET = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()


def _key(algo="hmac-sha256."):
    return TSIGKey.from_base64("xfr-key.", SECRET, algorithm=algo)


def _msg():
    m = Message(id=0x1234)
    m.questions.append(Question(Name.from_text("example.com"), Type.AXFR, Class.IN))
    m.answers.append(RR(Name.from_text("example.com"), Type.A, Class.IN, 300, R.A("1.2.3.4")))
    return m


def test_sign_verify_roundtrip():
    key = _key()
    signed, mac = sign_wire(_msg().to_wire(), key, time_signed=1_000_000)
    got, vkey, tsig = verify_wire(signed, {"xfr-key.": key}, now=1_000_000)
    assert got == mac and vkey is key and tsig.original_id == 0x1234


def test_tsig_is_parseable_and_last():
    key = _key()
    signed, _ = sign_wire(_msg().to_wire(), key, time_signed=1_000_000)
    parsed = Message.parse(signed)
    assert parsed.additional[-1].rtype == Type.TSIG
    assert parsed.additional[-1].rdata.algorithm == Name.from_text("hmac-sha256.")


@pytest.mark.parametrize("algo", ["hmac-sha256.", "hmac-sha512.", "hmac-sha1."])
def test_multiple_algorithms(algo):
    key = _key(algo)
    signed, mac = sign_wire(_msg().to_wire(), key, time_signed=500)
    got, _, _ = verify_wire(signed, {"xfr-key.": key}, now=500)
    assert got == mac


def test_tampered_message_fails():
    key = _key()
    from trench.auth_zone.tsig import _locate_tsig
    signed, _ = sign_wire(_msg().to_wire(), key, time_signed=1000)
    tsig_start, _, _ = _locate_tsig(signed)
    bad = bytearray(signed)
    bad[tsig_start - 1] ^= 0xFF  # flip last byte of the answer rdata (the A address)
    with pytest.raises(TSIGError) as e:
        verify_wire(bytes(bad), {"xfr-key.": key}, now=1000)
    assert e.value.tsig_error == 16  # BADSIG


def test_unknown_key_badkey():
    key = _key()
    signed, _ = sign_wire(_msg().to_wire(), key, time_signed=1000)
    with pytest.raises(TSIGError) as e:
        verify_wire(signed, {}, now=1000)
    assert e.value.tsig_error == 17  # BADKEY


def test_clock_skew_badtime():
    key = _key()
    signed, _ = sign_wire(_msg().to_wire(), key, time_signed=1000, fudge=300)
    with pytest.raises(TSIGError) as e:
        verify_wire(signed, {"xfr-key.": key}, now=99999)
    assert e.value.tsig_error == 18  # BADTIME


def test_response_chains_to_request_mac():
    key = _key()
    _, req_mac = sign_wire(_msg().to_wire(), key, time_signed=1000)
    resp = Message(id=0x1234)
    resp.questions.append(Question(Name.from_text("example.com"), Type.AXFR, Class.IN))
    signed, mac = sign_wire(resp.to_wire(), key, request_mac=req_mac, time_signed=1001)
    got, _, _ = verify_wire(signed, {"xfr-key.": key}, request_mac=req_mac, now=1001)
    assert got == mac
    # verifying without the request MAC must fail
    with pytest.raises(TSIGError):
        verify_wire(signed, {"xfr-key.": key}, now=1001)


# ------------------------------------------------------------------ replay
def test_a_signed_message_cannot_be_replayed():
    """A valid MAC proves the sender knew the key, never that this is the first
    time they said it. On UDP the datagram can simply be sent again, spoofing
    the ACL'd source address, for the whole fudge window."""
    from trench.auth_zone.tsig import ReplayWindow, TSIGError, sign_wire, verify_wire

    key = TSIGKey(name="k.", secret=b"s" * 32, algorithm="hmac-sha256.")
    msg = Message(id=1234)
    msg.questions.append(Question(Name.from_text("example.com."), Type.SOA, Class.IN))
    wire, _ = sign_wire(msg.to_wire(), key)

    replay = ReplayWindow()
    verify_wire(wire, {"k.": key}, replay=replay)          # first time: fine
    for _ in range(3):
        with pytest.raises(TSIGError):
            verify_wire(wire, {"k.": key}, replay=replay)

    # a separate window (a fresh process) has no memory, which is why the
    # window belongs on the long-lived handler rather than per request
    verify_wire(wire, {"k.": key}, replay=ReplayWindow())


def test_key_names_match_regardless_of_case_or_trailing_dot():
    """Config may spell a key name either way. Matching only the exact
    lowercased-absolute form failed every transfer with BADKEY, and the failure
    was swallowed, so the secondary silently served a stale zone."""
    from trench.auth_zone.tsig import sign_wire, verify_wire

    key = TSIGKey(name="XFR-Key.", secret=b"s" * 32, algorithm="hmac-sha256.")
    msg = Message(id=7)
    msg.questions.append(Question(Name.from_text("example.com."), Type.SOA, Class.IN))
    wire, _ = sign_wire(msg.to_wire(), key)
    _, got, _ = verify_wire(wire, {"XFR-Key.": key})
    assert got is key


# --- the replay window, directly ---
def test_the_replay_window_refuses_the_same_mac_twice():
    from trench.auth_zone.tsig import ReplayWindow
    w = ReplayWindow()
    w.check("k.", 1000, b"mac-a", window=300, now=1000)
    with pytest.raises(TSIGError, match="replayed"):
        w.check("k.", 1000, b"mac-a", window=300, now=1000)


def test_a_legitimate_sender_may_sign_several_messages_in_one_second():
    """The high-water mark alone would reject the second one."""
    from trench.auth_zone.tsig import ReplayWindow
    w = ReplayWindow()
    w.check("k.", 1000, b"mac-a", window=300, now=1000)
    w.check("k.", 1000, b"mac-b", window=300, now=1000)


def test_a_mac_that_has_aged_out_of_the_window_is_forgotten():
    from trench.auth_zone.tsig import ReplayWindow
    w = ReplayWindow()
    w.check("k.", 1000, b"mac-a", window=300, now=1000)
    w.check("k.", 2000, b"mac-a", window=300, now=2000)      # far past the window


def test_an_old_message_is_refused_once_a_newer_one_is_accepted():
    """A captured UDP dynamic UPDATE could otherwise be resent for the whole
    fudge window to revert a later legitimate change."""
    from trench.auth_zone.tsig import ReplayWindow
    w = ReplayWindow()
    w.check("k.", 5000, b"new", window=300, now=5000)
    with pytest.raises(TSIGError, match="older than the last one"):
        w.check("k.", 1000, b"old", window=300, now=5000)


def test_a_message_inside_the_window_of_the_watermark_is_accepted():
    from trench.auth_zone.tsig import ReplayWindow
    w = ReplayWindow()
    w.check("k.", 5000, b"new", window=300, now=5000)
    w.check("k.", 4900, b"slightly-older", window=300, now=5000)


def test_keys_are_tracked_independently():
    from trench.auth_zone.tsig import ReplayWindow
    w = ReplayWindow()
    w.check("a.", 1000, b"mac", window=300, now=1000)
    w.check("b.", 1000, b"mac", window=300, now=1000)        # a different key


def test_the_replay_table_is_bounded():
    from trench.auth_zone.tsig import ReplayWindow
    w = ReplayWindow(max_keys=8)
    for i in range(40):
        w.check(f"k{i}.", 1000, b"mac", window=300, now=1000)
    assert len(w._seen) <= 8


# --- algorithms and key material ---
def test_an_unknown_algorithm_is_badkey():
    key = TSIGKey.from_base64("k.", SECRET, algorithm="hmac-md5.")
    with pytest.raises(TSIGError) as e:
        _ = key._hashmod
    assert e.value.tsig_error == 17


def test_signing_with_an_unknown_algorithm_fails_rather_than_forging():
    key = TSIGKey.from_base64("k.", SECRET, algorithm="hmac-nonsense.")
    with pytest.raises(TSIGError):
        sign_wire(_msg().to_wire(), key)


def test_a_key_whose_algorithm_does_not_match_the_message_is_badkey():
    signed, _ = sign_wire(_msg().to_wire(), _key("hmac-sha256."),
                          time_signed=1_000_000)
    other = TSIGKey.from_base64("xfr-key.", SECRET, algorithm="hmac-sha512.")
    with pytest.raises(TSIGError) as e:
        verify_wire(signed, {"xfr-key.": other}, now=1_000_000)
    assert e.value.tsig_error == 17


# --- locating the TSIG record ---
def test_a_message_with_no_tsig_is_refused():
    with pytest.raises(TSIGError, match="no TSIG"):
        verify_wire(_msg().to_wire(), {"xfr-key.": _key()})


def test_a_truncated_message_is_refused():
    from trench.errors import WireError
    with pytest.raises((WireError, TSIGError)):
        verify_wire(b"\x00\x01", {"xfr-key.": _key()})


def test_a_tsig_that_is_not_the_final_record_is_refused():
    """RFC 8945 §5.1: anything after it is unauthenticated."""
    key = _key()
    signed, _ = sign_wire(_msg().to_wire(), key, time_signed=1_000_000)
    msg = Message.parse(signed)
    msg.additional.append(RR(Name.from_text("example.com"), Type.A, Class.IN, 300,
                             R.A("6.6.6.6")))
    with pytest.raises(TSIGError, match="final record"):
        verify_wire(msg.to_wire(), {"xfr-key.": key}, now=1_000_000)


# --- MAC handling ---
def test_a_truncated_mac_within_the_legal_range_still_verifies():
    """RFC 8945 §5.2.2.1 allows truncation to half length, floor 80 bits."""
    key = _key()
    signed, _ = sign_wire(_msg().to_wire(), key, time_signed=1_000_000)
    msg = Message.parse(signed)
    tsig = msg.additional[-1].rdata
    tsig.mac = tsig.mac[:16]                       # 128 bits of a 256-bit MAC
    verify_wire(msg.to_wire(), {"xfr-key.": key}, now=1_000_000)


@pytest.mark.parametrize("length", [0, 4, 9])
def test_a_mac_truncated_below_the_floor_is_refused(length):
    key = _key()
    signed, _ = sign_wire(_msg().to_wire(), key, time_signed=1_000_000)
    msg = Message.parse(signed)
    msg.additional[-1].rdata.mac = msg.additional[-1].rdata.mac[:length]
    with pytest.raises(TSIGError, match="bad MAC length"):
        verify_wire(msg.to_wire(), {"xfr-key.": key}, now=1_000_000)


def test_a_mac_longer_than_the_algorithm_produces_is_refused():
    key = _key()
    signed, _ = sign_wire(_msg().to_wire(), key, time_signed=1_000_000)
    msg = Message.parse(signed)
    msg.additional[-1].rdata.mac += b"\x00" * 8
    with pytest.raises(TSIGError, match="bad MAC length"):
        verify_wire(msg.to_wire(), {"xfr-key.": key}, now=1_000_000)


# --- error replies ---
def test_a_badtime_error_reply_carries_our_own_clock():
    """That 48-bit field is the whole mechanism by which a skewed peer
    discovers the skew."""
    from trench.auth_zone.tsig import sign_error
    key = _key()
    signed, _ = sign_wire(_msg().to_wire(), key, time_signed=1_000_000)
    with pytest.raises(TSIGError) as e:
        verify_wire(signed, {"xfr-key.": key}, now=2_000_000)
    err = e.value
    assert err.tsig_error == 18
    reply = sign_error(_msg().to_wire(), err, now=2_000_000)
    tsig = Message.parse(reply).additional[-1].rdata
    assert tsig.error == 18
    assert int.from_bytes(tsig.other, "big") == 2_000_000


def test_an_error_with_no_identified_key_goes_back_unsigned():
    """BADKEY means we never identified a key, so there is nothing to sign
    with."""
    from trench.auth_zone.tsig import sign_error
    wire = _msg().to_wire()
    assert sign_error(wire, TSIGError("unknown key", tsig_error=17)) == wire


def test_signing_an_error_never_raises():
    from trench.auth_zone.tsig import sign_error
    key = _key()
    signed, _ = sign_wire(_msg().to_wire(), key, time_signed=1_000_000)
    with pytest.raises(TSIGError) as e:
        verify_wire(signed, {"xfr-key.": key}, now=2_000_000)
    err = e.value
    err.key = TSIGKey.from_base64("k.", SECRET, algorithm="hmac-nonsense.")
    assert sign_error(b"\x00" * 12, err) == b"\x00" * 12
