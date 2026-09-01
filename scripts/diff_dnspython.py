"""Differential test of the wire codec against dnspython.

Usage: python3 scripts/diff_dnspython.py

Fuzzing proves the parser does not crash; this proves it does not silently
*misread* a record. Every rdata is re-emitted and compared byte for byte with
the reference implementation. Needs dnspython (dev dependency).
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import dns.flags
import dns.message
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from trench.wire import Message
from trench.wire.writer import Writer

RECORDS = [
    ("A", "93.184.216.34"),
    ("AAAA", "2606:2800:220:1:248:1893:25c8:1946"),
    ("AAAA", "::1"),
    ("AAAA", "2001:db8::"),
    ("NS", "ns1.example.com."),
    ("CNAME", "target.example.com."),
    ("PTR", "host.example.com."),
    ("MX", "10 mail.example.com."),
    ("MX", "0 ."),
    ("TXT", '"simple"'),
    ("TXT", '"one" "two" "three"'),
    ("TXT", '"' + "x" * 255 + '" "' + "y" * 255 + '"'),
    ("TXT", '""'),
    ("SOA", "ns.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300"),
    ("SRV", "10 20 8080 target.example.com."),
    ("SRV", "0 0 0 ."),
    ("CAA", '0 issue "letsencrypt.org"'),
    ("CAA", '128 iodef "mailto:a@b.c"'),
    ("NAPTR", '100 10 "S" "SIP+D2U" "!^.*$!sip:x@y.com!" _sip._udp.example.com.'),
    ("TLSA", "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
    ("SSHFP", "1 1 0123456789abcdef0123456789abcdef01234567"),
    ("DS", "12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
    ("DNSKEY", "256 3 13 aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/=="),
    ("NSEC", "next.example.com. A AAAA RRSIG NSEC"),
    ("NSEC", "next.example.com. A NS SOA MX TXT AAAA RRSIG NSEC DNSKEY TLSA CAA"),
    ("NSEC3PARAM", "1 0 12 aabbccdd"),
    ("SVCB", "1 . alpn=h2,h3"),
    ("SVCB", "0 svc.example.com."),
    ("HTTPS", "1 . alpn=h2 ipv4hint=1.2.3.4"),
    ("HINFO", '"amd64" "linux"'),
    ("DNAME", "target.example.com."),
    ("LOC", "42 21 54 N 71 6 18 W -24m 30m"),
    ("SPF", '"v=spf1 -all"'),
    ("URI", '10 1 "https://example.com/"'),
]

WEIRD_NAMES = [
    "example.com.", "a.b.c.d.e.f.g.example.com.", "xn--bcher-kva.example.com.",
    "UPPER.Example.COM.", "_dmarc.example.com.", "*.example.com.",
    ("l" * 63) + ".example.com.",
]


def our_rdata_wire(rr_rdata):
    w = Writer()
    rr_rdata.emit(w)
    return bytes(w.getvalue()) if hasattr(w, "getvalue") else bytes(w.buf)


def check(label, name, rtype, text):
    try:
        rrs = dns.rrset.from_text(name, 300, "IN", rtype, text)
    except Exception as e:
        return f"corpus build failed: {e}"
    q = dns.message.make_query(name, rtype)
    ref = dns.message.make_response(q)
    ref.flags |= dns.flags.QR | dns.flags.AA
    ref.answer.append(rrs)
    raw = ref.to_wire()

    try:
        ours = Message.parse(raw)
    except Exception as e:
        return f"PARSE FAILED: {type(e).__name__}: {e}"

    problems = []
    if ours.id != ref.id:
        problems.append(f"id {ours.id} != {ref.id}")
    if ours.flags != ref.flags:
        problems.append(f"flags {ours.flags:#06x} != {ref.flags:#06x}")
    if len(ours.questions) != 1:
        problems.append(f"question count {len(ours.questions)}")
    else:
        qn = ours.questions[0]
        if qn.name.to_text().lower() != ref.question[0].name.to_text().lower():
            problems.append(f"qname {qn.name.to_text()} != {ref.question[0].name}")
        if qn.rtype != ref.question[0].rdtype:
            problems.append(f"qtype {qn.rtype} != {ref.question[0].rdtype}")

    ref_rds = list(rrs)
    if len(ours.answers) != len(ref_rds):
        problems.append(f"answer count {len(ours.answers)} != {len(ref_rds)}")
    else:
        for got, want in zip(ours.answers, ref_rds, strict=True):
            if got.rtype != want.rdtype:
                problems.append(f"rtype {got.rtype} != {want.rdtype}")
            if got.ttl != 300:
                problems.append(f"ttl {got.ttl} != 300")
            if got.name.to_text().lower() != name.lower():
                problems.append(f"owner {got.name.to_text()} != {name}")
            try:
                mine = our_rdata_wire(got.rdata)
            except Exception as e:
                problems.append(f"rdata emit failed: {type(e).__name__}: {e}")
                continue
            theirs = want.to_wire()
            if mine != theirs:
                problems.append(f"rdata bytes differ\n      ours  : {mine.hex()}"
                                f"\n      theirs: {theirs.hex()}"
                                f"\n      text  : {got.rdata.to_text()!r} vs {want.to_text()!r}")

    # our own round trip must be stable too
    try:
        again = Message.parse(ours.to_wire())
        if len(again.answers) != len(ours.answers):
            problems.append("round-trip lost answers")
        elif ours.answers and our_rdata_wire(again.answers[0].rdata) != our_rdata_wire(ours.answers[0].rdata):
            problems.append("round-trip changed rdata")
    except Exception as e:
        problems.append(f"round-trip failed: {type(e).__name__}: {e}")

    return "; ".join(problems) if problems else None


def main():
    fails = 0
    for rtype, text in RECORDS:
        err = check(rtype, "example.com.", rtype, text)
        if err:
            fails += 1
            print(f"[{rtype}] {text[:60]!r}\n    {err}")
    for nm in WEIRD_NAMES:
        err = check("name", nm, "A", "93.184.216.34")
        if err:
            fails += 1
            print(f"[name {nm[:40]}]\n    {err}")
    print(f"\n{len(RECORDS) + len(WEIRD_NAMES)} cases, {fails} mismatches")
    return fails


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
