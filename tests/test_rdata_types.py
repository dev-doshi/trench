"""Every record type Trench encodes: wire round-trip and presentation form.

The wire suite covers the types the resolver handles constantly. The rest —
HINFO, NAPTR, URI, SSHFP, TLSA, the DNSSEC family, TSIG — are encoded and
rendered by code that no test called, and each is served verbatim to clients out
of an authoritative zone or a cache.
"""
from __future__ import annotations

import pytest

from trench.errors import WireError
from trench.wire import Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rdata import Unknown, parse_rdata, rdata_type
from trench.wire.reader import Reader
from trench.wire.writer import Writer


def n(s):
    return Name.from_text(s)


def roundtrip(rd):
    """Emit `rd`, parse it back, and return the result."""
    w = Writer()
    rd.emit(w)
    raw = w.getvalue()
    back = parse_rdata(Reader(raw), int(rdata_type(rd)), len(raw))
    return back


CASES = [
    R.A("192.0.2.1"),
    R.AAAA("2001:db8::1"),
    R.NS(n("ns.example.com.")),
    R.CNAME(n("real.example.com.")),
    R.PTR(n("host.example.com.")),
    R.DNAME(n("other.example.com.")),
    R.SOA(n("ns.example.com."), n("hostmaster.example.com."),
          2026010101, 7200, 3600, 1209600, 3600),
    R.MX(10, n("mail.example.com.")),
    R.SRV(1, 5, 443, n("svc.example.com.")),
    R.TXT([b"v=spf1 -all"]),
    R.TXT([b"chunk one", b"chunk two"]),
    R.SPF([b"v=spf1 -all"]),
    R.HINFO(b"AMD64", b"LINUX"),
    R.CAA(0, b"issue", b"letsencrypt.org"),
    R.SSHFP(4, 2, bytes(range(32))),
    R.TLSA(3, 1, 1, bytes(range(32))),
    R.DS(12345, 13, 2, bytes(range(32))),
    R.CDS(12345, 13, 2, bytes(range(32))),
    R.DNSKEY(257, 3, 13, bytes(range(64))),
    R.CDNSKEY(257, 3, 13, bytes(range(64))),
    R.RRSIG(type_covered=int(Type.A), algorithm=13, labels=3,
            original_ttl=3600, expiration=1800000000, inception=1700000000,
            key_tag=12345, signer=n("example.com."), signature=bytes(range(64))),
    R.NSEC(next_name=n("b.example.com."), type_bitmap=b"\x00\x01\x40"),
    R.NSEC3PARAM(hash_algorithm=1, flags=0, iterations=5, salt=b"\xaa\xbb"),
    R.NSEC3(hash_algorithm=1, flags=1, iterations=5, salt=b"\xaa\xbb",
            next_hashed=bytes(range(20)), type_bitmap=b"\x00\x01\x40"),
    R.NAPTR(100, 10, b"S", b"SIP+D2U", b"!^.*$!sip:x@example.com!",
            n("_sip._udp.example.com.")),
    R.URI(10, 1, b"https://example.com/"),
    R.SVCB(1, n("svc.example.com."), b"\x00\x01\x00\x03\x02h2"),
    R.HTTPS(1, n("svc.example.com."), b"\x00\x01\x00\x03\x02h2"),
]


@pytest.mark.parametrize("rd", CASES, ids=lambda rd: type(rd).__name__)
def test_every_type_survives_a_wire_round_trip(rd):
    assert roundtrip(rd) == rd


@pytest.mark.parametrize("rd", CASES, ids=lambda rd: type(rd).__name__)
def test_every_type_renders_a_non_empty_presentation_form(rd):
    text = rd.to_text()
    assert isinstance(text, str) and text.strip()


@pytest.mark.parametrize("rd", CASES, ids=lambda rd: type(rd).__name__)
def test_the_presentation_form_survives_a_round_trip(rd):
    assert roundtrip(rd).to_text() == rd.to_text()


# --- specific presentation forms an operator reads ---
def test_txt_quotes_each_chunk_and_escapes_quotes():
    assert R.TXT([b"a", b"b"]).to_text() == '"a" "b"'
    assert R.TXT([b'say "hi"']).to_text() == r'"say \"hi\""'


def test_a_txt_chunk_over_255_bytes_is_refused():
    w = Writer()
    with pytest.raises(WireError, match="TXT chunk"):
        R.TXT([b"x" * 256]).emit(w)


def test_hinfo_quotes_both_fields():
    assert R.HINFO(b"AMD64", b"LINUX").to_text() == '"AMD64" "LINUX"'


def test_sshfp_and_tlsa_render_hex():
    assert R.SSHFP(4, 2, b"\xde\xad").to_text() == "4 2 dead"
    assert R.TLSA(3, 1, 1, b"\xbe\xef").to_text() == "3 1 1 beef"


def test_dnskey_and_ds_render_the_way_a_zone_file_does():
    assert R.DNSKEY(257, 3, 13, b"\x00\x01").to_text().startswith("257 3 13 ")
    # DS digests are upper-case in a zone file; SSHFP and TLSA are not.
    assert R.DS(12345, 13, 2, b"\xab\xcd").to_text() == "12345 13 2 ABCD"


def test_rrsig_names_the_type_it_covers():
    rd = R.RRSIG(type_covered=int(Type.A), algorithm=13, labels=2,
                 original_ttl=3600, expiration=2, inception=1, key_tag=9,
                 signer=n("example.com."), signature=b"\x00")
    text = rd.to_text()
    assert text.startswith("A 13 2 3600 2 1 9 example.com. ")


def test_nsec3_params_render_a_dash_for_an_empty_salt():
    empty = R.NSEC3PARAM(hash_algorithm=1, flags=0, iterations=0, salt=b"")
    assert empty.to_text() == "1 0 0 -"
    salted = R.NSEC3PARAM(hash_algorithm=1, flags=0, iterations=0, salt=b"\xab")
    assert salted.to_text() == "1 0 0 AB"


def test_nsec3_renders_base32_without_padding():
    rd = R.NSEC3(hash_algorithm=1, flags=0, iterations=0, salt=b"",
                 next_hashed=b"\x00" * 20, type_bitmap=b"")
    text = rd.to_text()
    assert "=" not in text
    assert text.startswith("1 0 0 - ")


def test_naptr_quotes_its_three_character_strings():
    text = R.NAPTR(100, 10, b"S", b"SIP+D2U", b"!x!", n("t.example.com.")).to_text()
    assert text == '100 10 "S" "SIP+D2U" "!x!" t.example.com.'


def test_uri_quotes_its_target():
    assert R.URI(10, 1, b"https://x/").to_text() == '10 1 "https://x/"'


def test_svcb_and_https_share_a_form_but_not_a_type():
    svcb = R.SVCB(1, n("svc.example.com."), b"")
    https = R.HTTPS(1, n("svc.example.com."), b"")
    assert svcb.to_text() == https.to_text()
    assert rdata_type(svcb) == int(Type.SVCB)
    assert rdata_type(https) == int(Type.HTTPS)


def test_svcb_alias_form_has_priority_zero():
    rd = R.SVCB(0, n("svc.example.com."), b"")
    assert roundtrip(rd) == rd


def test_tsig_renders_its_algorithm_and_mac():
    rd = R.TSIG(algorithm=n("hmac-sha256."), time_signed=1700000000, fudge=300,
                mac=b"\x01\x02", original_id=42, error=0, other=b"")
    text = rd.to_text()
    assert text.startswith("hmac-sha256. 1700000000 300 ")
    assert text.endswith(" 42 0")
    assert roundtrip(rd) == rd


def test_a_tsig_with_an_other_field_round_trips():
    rd = R.TSIG(algorithm=n("hmac-sha256."), time_signed=1, fudge=300,
                mac=b"\x01", original_id=1, error=18, other=b"\x00\x01\x02")
    assert roundtrip(rd) == rd


# --- the RFC 3597 fallback ---
def test_an_unknown_type_keeps_its_octets():
    raw = b"\xde\xad\xbe\xef"
    rd = parse_rdata(Reader(raw), 65280, len(raw))
    assert isinstance(rd, Unknown)
    assert rd.rtype == 65280 and rd.type == 65280
    assert rd.data == raw
    assert rdata_type(rd) == 65280


def test_an_unknown_type_renders_the_generic_form():
    assert Unknown(65280, b"\xde\xad").to_text() == r"\# 2 dead"
    assert Unknown(65280, b"").to_text() == r"\# 0"


def test_an_unknown_type_re_emits_verbatim():
    rd = Unknown(65280, b"\xde\xad\xbe\xef")
    w = Writer()
    rd.emit(w)
    assert w.getvalue() == b"\xde\xad\xbe\xef"


def test_a_malformed_record_without_a_name_falls_back_to_raw():
    """One malformed record must not cost the rest of the message."""
    # A TLSA needs at least three octets; one is not enough for its fields.
    rd = parse_rdata(Reader(b"\x03"), int(Type.TLSA), 1)
    assert isinstance(rd, Unknown)
    assert rd.data == b"\x03"


def test_a_malformed_name_bearing_record_is_refused_outright():
    """`Unknown` re-emits octets verbatim at whatever offset it lands on, so a
    name that failed to parse because it held a compression pointer would have
    that pointer re-resolved against a different message — decoding as an
    entirely different, attacker-chosen name."""
    with pytest.raises(WireError, match="undecodable rdata"):
        parse_rdata(Reader(b"\xc0"), int(Type.NS), 1)


def test_the_reader_is_left_at_the_end_of_the_rdata_on_a_fallback():
    raw = b"\x03" + b"trailing"
    r = Reader(raw)
    parse_rdata(r, int(Type.TLSA), 1)
    assert r.tell() == 1


# --- inheritance relationships that matter on the wire ---
@pytest.mark.parametrize("cls,parent,rtype", [
    (R.SPF, R.TXT, Type.SPF),
    (R.CDS, R.DS, Type.CDS),
    (R.CDNSKEY, R.DNSKEY, Type.CDNSKEY),
    (R.HTTPS, R.SVCB, Type.HTTPS),
])
def test_a_derived_type_keeps_its_own_type_code(cls, parent, rtype):
    assert issubclass(cls, parent)
    assert int(cls.TYPE) == int(rtype)
