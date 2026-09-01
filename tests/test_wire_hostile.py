"""The parser is what a hostile packet reaches first.

Nothing here has authenticated, rate-limited or been policy-checked yet: these
bytes arrive on an open UDP port from anyone. The tests are the properties that
have to hold for every possible input, plus the specific packets a fuzz run
found that broke them.
"""
from __future__ import annotations

import random

import pytest

from trench.errors import WireError
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.message import HEADER_LEN
from trench.wire.name import Name, read_name
from trench.wire.rdata import parse_rdata
from trench.wire.reader import Reader
from trench.wire.rrtypes import Flags

WWW = Name.from_text("www.example.com.")


def _hdr(qd=0, an=0, ns=0, ar=0, flags=0x8180) -> bytes:
    return (b"\x00\x01" + flags.to_bytes(2, "big") + qd.to_bytes(2, "big")
            + an.to_bytes(2, "big") + ns.to_bytes(2, "big") + ar.to_bytes(2, "big"))


def _name(text: str) -> bytes:
    out = b""
    for label in text.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _rr(name: bytes, rtype: int, rdata: bytes, *, rdlen: int | None = None) -> bytes:
    n = len(rdata) if rdlen is None else rdlen
    return (name + rtype.to_bytes(2, "big") + b"\x00\x01" + b"\x00\x00\x01\x2c"
            + n.to_bytes(2, "big") + rdata)


# ------------------------------------------------------------ rdlength
def _borrowing_packet(rdlen: int, rdata: bytes) -> bytes:
    """One NS record claiming `rdlen` octets, followed by a valid A record.

    The two are laid out so that the resync to start+rdlen lands exactly on the
    A record: without the rdlength rule the whole message parses cleanly, which
    is the point — the damage is invisible from the outside.
    """
    return (_hdr(an=2)
            + _name("example.com.") + Type.NS.to_bytes(2, "big") + b"\x00\x01"
            + b"\x00\x00\x01\x2c" + rdlen.to_bytes(2, "big") + rdata
            # owner is a pointer back to "example.com." at offset 12
            + b"\xc0\x0c" + Type.A.to_bytes(2, "big") + b"\x00\x01"
            + b"\x00\x00\x01\x2c" + b"\x00\x04" + b"\x01\x02\x03\x04")


def test_a_record_may_not_read_past_its_own_rdlength():
    """Found by fuzzing: a SOA declaring rdlength 0 parsed 77 octets of the
    records that followed it, and the resync afterwards hid it completely.

    Here the NS record is allotted two octets — one label, "a". The parser
    reads on into the *next* record's owner pointer and comes back with
    `a.example.com`, a nameserver name the sender never wrote. That record is
    what gets cached, re-emitted to clients, and signed over.
    """
    buf = _borrowing_packet(2, b"\x01a")
    with pytest.raises(WireError):
        Message.parse(buf)


def test_a_record_may_not_stop_short_of_its_rdlength():
    """The mirror image, and the reason the rule is `!=` rather than `>`:
    octets inside the record that the codec never looked at are still octets a
    signature covers, and dropping them silently is how a validator and a
    resolver end up disagreeing about what arrived."""
    buf = _borrowing_packet(10, b"\x01a\x00" + bytes(7))
    with pytest.raises(WireError):
        Message.parse(buf)


def test_an_unknown_type_keeps_exactly_its_rdlength():
    """The fallback path has to stay lossless: bytes we cannot interpret are
    still bytes a signature covers and a client asked for."""
    body = bytes(range(20))
    buf = _hdr(an=1) + _rr(_name("example.com."), 64999, body)
    msg = Message.parse(buf)
    assert msg.answers[0].rdata.data == body


def test_an_undecodable_known_type_falls_back_without_borrowing():
    """A short DS is not decodable, but it is also not licence to read on."""
    buf = _hdr(an=2) + _rr(_name("example.com."), Type.DS, b"\x01") \
        + _rr(_name("example.com."), Type.A, b"\x01\x02\x03\x04")
    msg = Message.parse(buf)
    assert msg.answers[0].rdata.data == b"\x01"
    assert msg.answers[1].rdata.address == "1.2.3.4"


# ------------------------------------------------------------ names
def test_a_compression_pointer_may_not_point_forward_or_at_itself():
    for ptr in (0x0C, 0x0E, 0xFF):
        buf = _hdr(qd=1) + b"\xc0" + bytes([ptr]) + b"\x00\x01\x00\x01"
        with pytest.raises(WireError):
            Message.parse(buf)


def test_a_name_may_not_exceed_255_octets():
    label = b"\x3f" + b"a" * 63
    buf = _hdr(qd=1) + label * 5 + b"\x00" + b"\x00\x01\x00\x01"
    with pytest.raises(WireError):
        Message.parse(buf)


def test_reserved_label_types_are_refused():
    for high in (0x40, 0x80):
        buf = _hdr(qd=1) + bytes([high | 1]) + b"a\x00\x00\x01\x00\x01"
        with pytest.raises(WireError):
            Message.parse(buf)


# ------------------------------------------------------------ truncation
def test_a_response_that_already_says_tc_is_still_capped():
    """The cap is about the datagram, not about the flag.

    An upstream can return TC set *and* a full answer section. Trusting the
    flag as evidence of size turned a 512-byte UDP limit into a 16 KB datagram
    — a reflector, sitting on an open port.
    """
    m = Message(id=1, flags=Flags.QR | Flags.TC)
    m.questions.append(Question(WWW, Type.TXT, Class.IN))
    for _ in range(60):
        m.answers.append(RR(WWW, Type.TXT, Class.IN, 300, R.TXT([bytes(255)])))
    out = m.to_wire(max_size=512)
    assert len(out) <= 512
    assert Message.parse(out).tc is True


def test_truncation_keeps_the_question_and_the_opt():
    m = Message(id=1, flags=Flags.QR)
    m.questions.append(Question(WWW, Type.TXT, Class.IN))
    from trench.wire.edns import Edns
    m.edns = Edns(udp_size=1232)
    for _ in range(60):
        m.answers.append(RR(WWW, Type.TXT, Class.IN, 300, R.TXT([bytes(255)])))
    got = Message.parse(m.to_wire(max_size=512))
    assert got.tc and got.questions[0].name == WWW and got.edns is not None
    assert not got.answers


# ------------------------------------------------------------ the property
def _seed_corpus() -> list[bytes]:
    seeds = [
        (Type.A, R.A("1.2.3.4")),
        (Type.AAAA, R.AAAA("2001:db8::1")),
        (Type.NS, R.NS(Name.from_text("ns.example.com."))),
        (Type.SOA, R.SOA(Name.from_text("ns.example.com."),
                         Name.from_text("a.example.com."), 1, 2, 3, 4, 5)),
        (Type.MX, R.MX(10, Name.from_text("mx.example.com."))),
        (Type.TXT, R.TXT([b"hello", b"world"])),
        (Type.SRV, R.SRV(1, 2, 443, Name.from_text("svc.example.com."))),
        (Type.DS, R.DS(1234, 13, 2, bytes(32))),
        (Type.RRSIG, R.RRSIG(1, 13, 2, 3600, 100, 1, 1234,
                             Name.from_text("example.com."), bytes(64))),
        (Type.NSEC3, R.NSEC3(1, 1, 12, b"\xaa\xbb", bytes(20), b"\x00\x06@\x00\x00\x00\x00\x03")),
    ]
    out = []
    for rtype, rd in seeds:
        m = Message(id=1, flags=0x8180)
        m.questions.append(Question(WWW, rtype, Class.IN))
        m.answers.append(RR(WWW, rtype, Class.IN, 300, rd))
        m.authority.append(RR(Name.from_text("example.com."), Type.NS, Class.IN, 300,
                              R.NS(Name.from_text("ns.example.com."))))
        out.append(m.to_wire())
    return out


def _mutate(buf: bytes, rng: random.Random) -> bytes:
    b = bytearray(buf)
    for _ in range(rng.randint(1, 6)):
        if not b:
            break
        i = rng.randrange(len(b))
        op = rng.randint(0, 3)
        if op == 0:
            b[i] = rng.randrange(256)
        elif op == 1:
            b[i:i + 2] = bytes([0xC0 | rng.randrange(0x40), rng.randrange(256)])
        elif op == 2:
            b = b[:rng.randrange(len(b) + 1)]
        else:
            j = rng.randrange(len(b))
            b[i:i] = b[j:j + rng.randint(1, 8)]
    return bytes(b)


def _rdlength_walk(buf: bytes) -> None:
    """Re-walk a parsed message asserting each record's own arithmetic."""
    r = Reader(buf)
    r.seek(4)
    qd, an, ns, ar = r.u16(), r.u16(), r.u16(), r.u16()
    assert r.tell() == HEADER_LEN
    for _ in range(qd):
        read_name(r)
        r.u16(), r.u16()
    for _ in range(an + ns + ar):
        read_name(r)
        rtype, _rclass, _ttl = r.u16(), r.u16(), r.u32()
        rdlen = r.u16()
        start = r.tell()
        parse_rdata(r, rtype, rdlen)
        assert r.tell() - start == rdlen, f"type {rtype} used {r.tell()-start} of {rdlen}"
        r.seek(start + rdlen)


def test_no_mutation_escapes_wireerror_or_borrows_octets():
    """A short deterministic fuzz run kept in the suite.

    The point is not coverage — it is that the three properties below are
    stated as properties, so a future codec that reads one byte too many fails
    here rather than in production.
    """
    rng = random.Random(0xD1)
    corpus = _seed_corpus()
    parsed = 0
    for _ in range(20_000):
        buf = _mutate(rng.choice(corpus), rng)
        try:
            msg = Message.parse(buf)
        except WireError:
            continue
        except Exception as e:                       # noqa: BLE001 - that is the test
            pytest.fail(f"{type(e).__name__} on {buf.hex()}: {e}")
        parsed += 1
        _rdlength_walk(buf)
        try:
            Message.parse(msg.to_wire())             # re-encoding stays parseable
        except WireError:
            pytest.fail(f"re-encoded message no longer parses: {buf.hex()}")
    assert parsed > 1000, f"corpus degenerated: only {parsed} parsed"
