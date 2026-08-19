"""TSIG transaction security (RFC 8945): sign/verify round-trips + error paths."""
from __future__ import annotations

import base64

import pytest

from dnsguard.auth_zone.tsig import TSIGError, TSIGKey, sign_wire, verify_wire
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name

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
    from dnsguard.auth_zone.tsig import _locate_tsig
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
