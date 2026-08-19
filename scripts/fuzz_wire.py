"""Mutation fuzzer for the wire codec.

Usage: BUDGET=30 SEED=1 python3 scripts/fuzz_wire.py

Parsing untrusted packets is the most security-critical path in a resolver, so
this is kept in the tree rather than run once: any parse that raises something
other than WireError, any re-encode that blows up, or any parse slower than
250ms is reported as a defect. Needs dnspython (dev dependency) to build the
seed corpus.
"""
import os
import pathlib
import random
import struct
import sys
import time
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import dns.message
import dns.rdatatype

from dnsguard.errors import WireError
from dnsguard.wire import Message

SEED = int(os.environ.get("SEED", "1"))
BUDGET = float(os.environ.get("BUDGET", "20"))

# a spread of realistic messages to mutate, built with the reference library so
# the corpus is not biased by our own encoder's habits
CORPUS_TEXT = [
    ("example.com.", "A"), ("example.com.", "AAAA"), ("example.com.", "MX"),
    ("example.com.", "TXT"), ("example.com.", "SOA"), ("example.com.", "NS"),
    ("_sip._tcp.example.com.", "SRV"), ("example.com.", "CAA"),
    ("example.com.", "DNSKEY"), ("example.com.", "DS"), ("example.com.", "RRSIG"),
    ("example.com.", "NSEC"), ("example.com.", "NSEC3"), ("example.com.", "SVCB"),
    ("example.com.", "HTTPS"), ("example.com.", "PTR"), ("example.com.", "CNAME"),
    ("example.com.", "NAPTR"), ("example.com.", "TLSA"), ("example.com.", "ANY"),
]


def corpus():
    out = []
    for name, rtype in CORPUS_TEXT:
        try:
            q = dns.message.make_query(name, rtype, want_dnssec=True)
            out.append(q.to_wire())
            r = dns.message.make_response(q)
            r.flags |= dns.flags.QR | dns.flags.RA
            out.append(r.to_wire())
        except Exception:
            pass
    # a couple of hand-built responses with real rdata
    zone = [
        "example.com. 300 IN A 93.184.216.34",
        "example.com. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946",
        "example.com. 300 IN MX 10 mail.example.com.",
        "example.com. 300 IN TXT \"v=spf1 -all\" \"second\"",
        "example.com. 300 IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 5",
        "example.com. 300 IN SRV 1 2 3 target.example.com.",
        "example.com. 300 IN CAA 0 issue \"letsencrypt.org\"",
        "example.com. 300 IN NAPTR 100 10 \"S\" \"SIP+D2U\" \"!^.*$!sip:x@y.com!\" _sip._udp.example.com.",
        "example.com. 300 IN TLSA 3 1 1 0123456789ABCDEF",
        "example.com. 300 IN SVCB 1 . alpn=h2,h3 port=8443",
        "example.com. 300 IN NSEC a.example.com. A AAAA RRSIG NSEC",
    ]
    for rec in zone:
        try:
            q = dns.message.make_query("example.com.", "A")
            r = dns.message.make_response(q)
            r.answer.append(dns.rrset.from_text_list(
                rec.split()[0], 300, "IN", rec.split()[3],
                [" ".join(rec.split()[4:])]))
            out.append(r.to_wire())
        except Exception:
            pass
    return out


def mutate(buf, rng):
    b = bytearray(buf)
    if not b:
        return bytes(b)
    for _ in range(rng.randint(1, 6)):
        op = rng.randrange(6)
        i = rng.randrange(len(b))
        if op == 0:
            b[i] = rng.randrange(256)
        elif op == 1:
            b[i] ^= 1 << rng.randrange(8)
        elif op == 2:                      # inject a compression pointer
            if i + 1 < len(b):
                b[i] = 0xC0 | rng.randrange(0x40)
                b[i + 1] = rng.randrange(256)
        elif op == 3:                      # truncate
            b = b[:rng.randrange(1, len(b) + 1)]
            if not b:
                b = bytearray(b"\0")
        elif op == 4:                      # lie about the counts
            if len(b) >= 12:
                struct.pack_into(">H", b, rng.choice([4, 6, 8, 10]), rng.randrange(65536))
        elif op == 5:                      # oversized label / bad length byte
            b[i] = rng.choice([0x3F, 0x40, 0x80, 0xFF, 0x00])
    return bytes(b)


def main():
    rng = random.Random(SEED)
    base = corpus()
    print(f"corpus: {len(base)} messages, budget {BUDGET}s, seed {SEED}")

    crashes, n = {}, 0
    deadline = time.monotonic() + BUDGET
    while time.monotonic() < deadline:
        raw = mutate(rng.choice(base), rng)
        n += 1
        t0 = time.monotonic()
        try:
            m = Message.parse(raw)
        except WireError:
            pass
        except Exception as e:                       # any other exception = defect
            key = (type(e).__name__, traceback.extract_tb(e.__traceback__)[-1].lineno,
                   traceback.extract_tb(e.__traceback__)[-1].filename.split("/")[-1])
            if key not in crashes:
                crashes[key] = (repr(e), raw.hex(),
                                "".join(traceback.format_tb(e.__traceback__)[-2:]))
        else:
            # re-encoding a parsed message must not blow up either
            try:
                m.to_wire()
            except WireError:
                pass
            except Exception as e:
                key = ("REENCODE:" + type(e).__name__,
                       traceback.extract_tb(e.__traceback__)[-1].lineno,
                       traceback.extract_tb(e.__traceback__)[-1].filename.split("/")[-1])
                if key not in crashes:
                    crashes[key] = (repr(e), raw.hex(),
                                    "".join(traceback.format_tb(e.__traceback__)[-2:]))
        slow = time.monotonic() - t0
        if slow > 0.25:
            crashes[("SLOW", int(slow * 1000), "")] = (
                f"parse took {slow*1000:.0f}ms", raw.hex(), "")

    print(f"\n{n} mutations, {len(crashes)} distinct defects\n")
    for (kind, line, fname), (msg, hexbuf, tb) in sorted(crashes.items(), key=lambda x: str(x[0])):
        print(f"--- {kind} at {fname}:{line}: {msg}")
        print(f"    input: {hexbuf[:160]}")
        if tb:
            print("    " + tb.strip().replace("\n", "\n    "))
    return len(crashes)


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
