"""DNS protocol constants and enums."""
from __future__ import annotations

from enum import IntEnum


class Type(IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    HINFO = 13
    MX = 15
    TXT = 16
    RP = 17
    AAAA = 28
    LOC = 29
    SRV = 33
    NAPTR = 35
    CERT = 37
    DNAME = 39
    OPT = 41
    DS = 43
    SSHFP = 44
    IPSECKEY = 45
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    SMIMEA = 53
    CDS = 59
    CDNSKEY = 60
    OPENPGPKEY = 61
    SVCB = 64
    HTTPS = 65
    SPF = 99
    URI = 256
    CAA = 257
    ANY = 255
    AXFR = 252
    IXFR = 251
    TKEY = 249
    TSIG = 250

    @classmethod
    def _missing_(cls, value):  # unknown types stay usable
        return None


def type_to_text(t: int) -> str:
    try:
        return Type(t).name
    except ValueError:
        return f"TYPE{t}"


def type_from_text(s: str) -> int:
    s = s.upper()
    if s.startswith("TYPE"):
        return int(s[4:])
    return int(Type[s])


class Class(IntEnum):
    IN = 1
    CH = 3
    HS = 4
    NONE = 254
    ANY = 255


class Opcode(IntEnum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2
    NOTIFY = 4
    UPDATE = 5


class Rcode(IntEnum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5
    YXDOMAIN = 6
    YXRRSET = 7
    NXRRSET = 8
    NOTAUTH = 9
    NOTZONE = 10
    BADVERS = 16  # also BADSIG; lives in EDNS extended rcode
    BADKEY = 17
    BADTIME = 18


class Flags:
    """16-bit header flags field, bit masks (after the 16-bit id)."""
    QR = 0x8000
    AA = 0x0400
    TC = 0x0200
    RD = 0x0100
    RA = 0x0080
    AD = 0x0020
    CD = 0x0010
    OPCODE_MASK = 0x7800
    OPCODE_SHIFT = 11
    RCODE_MASK = 0x000F
    Z_MASK = 0x0040  # reserved


class EDNSOption(IntEnum):
    LLQ = 1
    NSID = 3
    DAU = 5
    DHU = 6
    N3U = 7
    ECS = 8           # EDNS Client Subnet (RFC 7871)
    EXPIRE = 9
    COOKIE = 10       # DNS Cookies (RFC 7873)
    TCP_KEEPALIVE = 11
    PADDING = 12      # RFC 7830
    EXTENDED_ERROR = 15

    @classmethod
    def _missing_(cls, value):
        return None


# DNSSEC algorithm numbers (subset we sign/validate with)
class DNSSECAlgo(IntEnum):
    RSASHA1 = 5
    RSASHA256 = 8
    RSASHA512 = 10
    ECDSAP256SHA256 = 13
    ECDSAP384SHA384 = 14
    ED25519 = 15
    ED448 = 16
