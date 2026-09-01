"""Wire codec: round-trip, cross-check vs dnspython, and fuzz-safety."""
from __future__ import annotations

import random

import dns.message
import dns.rdatatype
import pytest

from trench.errors import WireError
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name


def mkquery(name="example.com", rtype=Type.A, do=False):
    m = Message(id=0x1234)
    m.set_flag(0x0100, True)  # RD
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    from trench.wire.edns import Edns
    m.edns = Edns(udp_size=1232)
    m.edns.do = do
    return m


def test_query_roundtrip():
    m = mkquery(do=True)
    wire = m.to_wire()
    back = Message.parse(wire)
    assert back.id == 0x1234
    assert back.rd is True
    assert back.question.name == Name.from_text("example.com")
    assert back.question.rtype == Type.A
    assert back.edns is not None and back.edns.do is True


@pytest.mark.parametrize("rd,text_type", [
    (R.A("1.2.3.4"), "A"),
    (R.AAAA("2001:db8::1"), "AAAA"),
    (R.NS(Name.from_text("ns1.example.com")), "NS"),
    (R.CNAME(Name.from_text("cdn.example.net")), "CNAME"),
    (R.MX(10, Name.from_text("mail.example.com")), "MX"),
    (R.TXT([b"v=spf1 -all"]), "TXT"),
    (R.SRV(0, 5, 443, Name.from_text("svc.example.com")), "SRV"),
    (R.SOA(Name.from_text("ns.example.com"), Name.from_text("hostmaster.example.com"),
           2024010100, 7200, 3600, 1209600, 3600), "SOA"),
    (R.CAA(0, b"issue", b"letsencrypt.org"), "CAA"),
    (R.DS(12345, 13, 2, bytes(range(32))), "DS"),
])
def test_rr_roundtrip_and_dnspython(rd, text_type):
    m = Message(id=1)
    m.set_flag(0x8000, True)  # QR
    m.questions.append(Question(Name.from_text("example.com"), rd.TYPE, Class.IN))
    m.answers.append(RR(Name.from_text("example.com"), int(rd.TYPE), Class.IN, 300, rd))
    wire = m.to_wire()

    # ours -> wire -> ours
    back = Message.parse(wire)
    assert len(back.answers) == 1
    assert back.answers[0].rdata.to_text() == rd.to_text()

    # ours -> wire -> dnspython (proves wire correctness against a reference)
    dmsg = dns.message.from_wire(wire)
    ans = dmsg.answer[0]
    assert dns.rdatatype.to_text(ans.rdtype) == text_type


def test_dnspython_to_ours_with_compression():
    # dnspython aggressively compresses; verify we decompress correctly
    q = dns.message.make_query("www.example.com", "A")
    r = dns.message.make_response(q)
    r.answer.append(dns.rrset.from_text("www.example.com.", 300, "IN", "CNAME", "example.com."))
    r.answer.append(dns.rrset.from_text("example.com.", 300, "IN", "A", "93.184.216.34"))
    wire = r.to_wire()
    ours = Message.parse(wire)
    assert ours.answers[0].rdata.to_text() == "example.com."
    assert ours.answers[1].rdata.to_text() == "93.184.216.34"


def test_unknown_type_roundtrips_raw():
    rd = R.Unknown(9999, b"\xde\xad\xbe\xef")
    m = Message(id=2)
    m.answers.append(RR(Name.from_text("x.test"), 9999, Class.IN, 60, rd))
    m.questions.append(Question(Name.from_text("x.test"), 9999, Class.IN))
    back = Message.parse(m.to_wire())
    assert isinstance(back.answers[0].rdata, R.Unknown)
    assert back.answers[0].rdata.data == b"\xde\xad\xbe\xef"


def test_truncation_sets_tc():
    m = Message(id=3)
    m.set_flag(0x8000, True)
    m.questions.append(Question(Name.from_text("example.com"), Type.A, Class.IN))
    for i in range(100):
        m.answers.append(RR(Name.from_text("example.com"), Type.A, Class.IN, 300, R.A(f"10.0.0.{i}")))
    small = m.to_wire(max_size=200)
    back = Message.parse(small)
    assert back.tc is True
    assert len(back.answers) == 0
    assert len(back.questions) == 1


def test_fuzz_never_crashes():
    rng = random.Random(1337)
    for _ in range(8000):
        n = rng.randint(0, 80)
        buf = bytes(rng.getrandbits(8) for _ in range(n))
        try:
            msg = Message.parse(buf)
            msg.to_wire()  # whatever parsed must also serialize
        except WireError:
            pass  # expected for malformed input
        # any other exception fails the test
