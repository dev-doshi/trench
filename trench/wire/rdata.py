"""RDATA codecs.

Explicit structured codecs for common, name-bearing, and DNSSEC record types;
a raw fallback (RFC 3597) for everything else. The message parser resyncs the
cursor to rdata_start+rdlength after every record, so even a codec that misreads
cannot desync the stream — and any unknown type round-trips byte-for-byte.
"""
from __future__ import annotations

import base64
import socket
from dataclasses import dataclass

from ..errors import WireError
from .name import Name, read_name, write_name
from .reader import Reader
from .rrtypes import Type, type_to_text
from .writer import Writer


class Rdata:
    """Base class. Subclasses set TYPE and implement emit()/to_text()."""
    TYPE: int = -1

    def emit(self, w: Writer) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def to_text(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError


# --- address types -----------------------------------------------------------
@dataclass
class A(Rdata):
    TYPE = Type.A
    address: str

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> A:
        if rdlen != 4:
            raise WireError("A rdata != 4 bytes")
        return cls(socket.inet_ntop(socket.AF_INET, r.read(4)))

    def emit(self, w: Writer) -> None:
        w.raw(socket.inet_pton(socket.AF_INET, self.address))

    def to_text(self) -> str:
        return self.address


@dataclass
class AAAA(Rdata):
    TYPE = Type.AAAA
    address: str

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> AAAA:
        if rdlen != 16:
            raise WireError("AAAA rdata != 16 bytes")
        return cls(socket.inet_ntop(socket.AF_INET6, r.read(16)))

    def emit(self, w: Writer) -> None:
        w.raw(socket.inet_pton(socket.AF_INET6, self.address))

    def to_text(self) -> str:
        return self.address


# --- single-name types -------------------------------------------------------
@dataclass
class _NameRdata(Rdata):
    name: Name

    @classmethod
    def parse(cls, r: Reader, rdlen: int):
        return cls(read_name(r))

    def emit(self, w: Writer) -> None:
        write_name(w, self.name, compress=False)

    def to_text(self) -> str:
        return self.name.to_text()


class NS(_NameRdata):
    TYPE = Type.NS


class CNAME(_NameRdata):
    TYPE = Type.CNAME


class PTR(_NameRdata):
    TYPE = Type.PTR


class DNAME(_NameRdata):
    TYPE = Type.DNAME


@dataclass
class SOA(Rdata):
    TYPE = Type.SOA
    mname: Name
    rname: Name
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> SOA:
        mname = read_name(r)
        rname = read_name(r)
        serial, refresh, retry, expire, minimum = (r.u32(), r.u32(), r.u32(), r.u32(), r.u32())
        return cls(mname, rname, serial, refresh, retry, expire, minimum)

    def emit(self, w: Writer) -> None:
        write_name(w, self.mname, compress=False)
        write_name(w, self.rname, compress=False)
        for v in (self.serial, self.refresh, self.retry, self.expire, self.minimum):
            w.u32(v)

    def to_text(self) -> str:
        return (f"{self.mname.to_text()} {self.rname.to_text()} {self.serial} "
                f"{self.refresh} {self.retry} {self.expire} {self.minimum}")


@dataclass
class MX(Rdata):
    TYPE = Type.MX
    preference: int
    exchange: Name

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> MX:
        return cls(r.u16(), read_name(r))

    def emit(self, w: Writer) -> None:
        w.u16(self.preference)
        write_name(w, self.exchange, compress=False)

    def to_text(self) -> str:
        return f"{self.preference} {self.exchange.to_text()}"


@dataclass
class SRV(Rdata):
    TYPE = Type.SRV
    priority: int
    weight: int
    port: int
    target: Name

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> SRV:
        return cls(r.u16(), r.u16(), r.u16(), read_name(r))

    def emit(self, w: Writer) -> None:
        w.u16(self.priority)
        w.u16(self.weight)
        w.u16(self.port)
        write_name(w, self.target, compress=False)

    def to_text(self) -> str:
        return f"{self.priority} {self.weight} {self.port} {self.target.to_text()}"


# --- character-string types --------------------------------------------------
@dataclass
class TXT(Rdata):
    TYPE = Type.TXT
    strings: list[bytes]

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> TXT:
        end = r.tell() + rdlen
        out = []
        while r.tell() < end:
            ln = r.u8()
            out.append(r.read(ln))
        return cls(out)

    def emit(self, w: Writer) -> None:
        for s in self.strings:
            if len(s) > 255:
                raise WireError("TXT chunk > 255")
            w.u8(len(s))
            w.raw(s)

    def to_text(self) -> str:
        return " ".join('"' + s.decode("latin-1").replace('"', '\\"') + '"' for s in self.strings)


class SPF(TXT):
    TYPE = Type.SPF


@dataclass
class HINFO(Rdata):
    TYPE = Type.HINFO
    cpu: bytes
    os: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> HINFO:
        cpu = r.read(r.u8())
        os = r.read(r.u8())
        return cls(cpu, os)

    def emit(self, w: Writer) -> None:
        w.u8(len(self.cpu)); w.raw(self.cpu)
        w.u8(len(self.os)); w.raw(self.os)

    def to_text(self) -> str:
        return f'"{self.cpu.decode("latin-1")}" "{self.os.decode("latin-1")}"'


# --- TLS / crypto helper types ----------------------------------------------
@dataclass
class CAA(Rdata):
    TYPE = Type.CAA
    flags: int
    tag: bytes
    value: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> CAA:
        end = r.tell() + rdlen
        flags = r.u8()
        tag = r.read(r.u8())
        value = r.read(end - r.tell())
        return cls(flags, tag, value)

    def emit(self, w: Writer) -> None:
        w.u8(self.flags)
        w.u8(len(self.tag)); w.raw(self.tag)
        w.raw(self.value)

    def to_text(self) -> str:
        return f'{self.flags} {self.tag.decode("ascii")} "{self.value.decode("latin-1")}"'


@dataclass
class SSHFP(Rdata):
    TYPE = Type.SSHFP
    algorithm: int
    fp_type: int
    fingerprint: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> SSHFP:
        return cls(r.u8(), r.u8(), r.read(rdlen - 2))

    def emit(self, w: Writer) -> None:
        w.u8(self.algorithm); w.u8(self.fp_type); w.raw(self.fingerprint)

    def to_text(self) -> str:
        return f"{self.algorithm} {self.fp_type} {self.fingerprint.hex()}"


@dataclass
class TLSA(Rdata):
    TYPE = Type.TLSA
    usage: int
    selector: int
    mtype: int
    cert: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> TLSA:
        return cls(r.u8(), r.u8(), r.u8(), r.read(rdlen - 3))

    def emit(self, w: Writer) -> None:
        w.u8(self.usage); w.u8(self.selector); w.u8(self.mtype); w.raw(self.cert)

    def to_text(self) -> str:
        return f"{self.usage} {self.selector} {self.mtype} {self.cert.hex()}"


# --- DNSSEC types ------------------------------------------------------------
@dataclass
class DS(Rdata):
    TYPE = Type.DS
    key_tag: int
    algorithm: int
    digest_type: int
    digest: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> DS:
        return cls(r.u16(), r.u8(), r.u8(), r.read(rdlen - 4))

    def emit(self, w: Writer) -> None:
        w.u16(self.key_tag); w.u8(self.algorithm); w.u8(self.digest_type); w.raw(self.digest)

    def to_text(self) -> str:
        return f"{self.key_tag} {self.algorithm} {self.digest_type} {self.digest.hex().upper()}"


class CDS(DS):
    TYPE = Type.CDS


@dataclass
class DNSKEY(Rdata):
    TYPE = Type.DNSKEY
    flags: int
    protocol: int
    algorithm: int
    public_key: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> DNSKEY:
        return cls(r.u16(), r.u8(), r.u8(), r.read(rdlen - 4))

    def emit(self, w: Writer) -> None:
        w.u16(self.flags); w.u8(self.protocol); w.u8(self.algorithm); w.raw(self.public_key)

    def to_text(self) -> str:
        return f"{self.flags} {self.protocol} {self.algorithm} {base64.b64encode(self.public_key).decode()}"


class CDNSKEY(DNSKEY):
    TYPE = Type.CDNSKEY


@dataclass
class RRSIG(Rdata):
    TYPE = Type.RRSIG
    type_covered: int
    algorithm: int
    labels: int
    original_ttl: int
    expiration: int
    inception: int
    key_tag: int
    signer: Name
    signature: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> RRSIG:
        end = r.tell() + rdlen
        tc = r.u16(); algo = r.u8(); labels = r.u8()
        ottl = r.u32(); exp = r.u32(); inc = r.u32(); tag = r.u16()
        signer = read_name(r)
        sig = r.read(end - r.tell())
        return cls(tc, algo, labels, ottl, exp, inc, tag, signer, sig)

    def emit(self, w: Writer) -> None:
        w.u16(self.type_covered); w.u8(self.algorithm); w.u8(self.labels)
        w.u32(self.original_ttl); w.u32(self.expiration); w.u32(self.inception)
        w.u16(self.key_tag)
        write_name(w, self.signer, compress=False)
        w.raw(self.signature)

    def to_text(self) -> str:
        return (f"{type_to_text(self.type_covered)} {self.algorithm} {self.labels} "
                f"{self.original_ttl} {self.expiration} {self.inception} {self.key_tag} "
                f"{self.signer.to_text()} {base64.b64encode(self.signature).decode()}")


@dataclass
class NSEC(Rdata):
    TYPE = Type.NSEC
    next_name: Name
    type_bitmap: bytes  # raw window-encoded bitmap

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> NSEC:
        end = r.tell() + rdlen
        nxt = read_name(r)
        return cls(nxt, r.read(end - r.tell()))

    def emit(self, w: Writer) -> None:
        write_name(w, self.next_name, compress=False)
        w.raw(self.type_bitmap)

    def to_text(self) -> str:
        return f"{self.next_name.to_text()} {self.type_bitmap.hex()}"


@dataclass
class NSEC3PARAM(Rdata):
    TYPE = Type.NSEC3PARAM
    hash_algorithm: int
    flags: int
    iterations: int
    salt: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> NSEC3PARAM:
        ha = r.u8(); fl = r.u8(); it = r.u16(); salt = r.read(r.u8())
        return cls(ha, fl, it, salt)

    def emit(self, w: Writer) -> None:
        w.u8(self.hash_algorithm); w.u8(self.flags); w.u16(self.iterations)
        w.u8(len(self.salt)); w.raw(self.salt)

    def to_text(self) -> str:
        salt = self.salt.hex().upper() if self.salt else "-"
        return f"{self.hash_algorithm} {self.flags} {self.iterations} {salt}"


@dataclass
class NSEC3(Rdata):
    TYPE = Type.NSEC3
    hash_algorithm: int
    flags: int
    iterations: int
    salt: bytes
    next_hashed: bytes
    type_bitmap: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> NSEC3:
        end = r.tell() + rdlen
        ha = r.u8(); fl = r.u8(); it = r.u16()
        salt = r.read(r.u8())
        nh = r.read(r.u8())
        return cls(ha, fl, it, salt, nh, r.read(end - r.tell()))

    def emit(self, w: Writer) -> None:
        w.u8(self.hash_algorithm); w.u8(self.flags); w.u16(self.iterations)
        w.u8(len(self.salt)); w.raw(self.salt)
        w.u8(len(self.next_hashed)); w.raw(self.next_hashed)
        w.raw(self.type_bitmap)

    def to_text(self) -> str:
        salt = self.salt.hex().upper() if self.salt else "-"
        b32 = base64.b32encode(self.next_hashed).decode().rstrip("=")
        return f"{self.hash_algorithm} {self.flags} {self.iterations} {salt} {b32} {self.type_bitmap.hex()}"


@dataclass
class NAPTR(Rdata):
    TYPE = Type.NAPTR
    order: int
    preference: int
    flags: bytes
    service: bytes
    regexp: bytes
    replacement: Name

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> NAPTR:
        order = r.u16(); pref = r.u16()
        flags = r.read(r.u8())
        service = r.read(r.u8())
        regexp = r.read(r.u8())
        return cls(order, pref, flags, service, regexp, read_name(r))

    def emit(self, w: Writer) -> None:
        w.u16(self.order); w.u16(self.preference)
        for s in (self.flags, self.service, self.regexp):
            w.u8(len(s)); w.raw(s)
        write_name(w, self.replacement, compress=False)

    def to_text(self) -> str:
        return (f'{self.order} {self.preference} "{self.flags.decode("latin-1")}" '
                f'"{self.service.decode("latin-1")}" "{self.regexp.decode("latin-1")}" '
                f"{self.replacement.to_text()}")


@dataclass
class URI(Rdata):
    TYPE = Type.URI
    priority: int
    weight: int
    target: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> URI:
        return cls(r.u16(), r.u16(), r.read(rdlen - 4))

    def emit(self, w: Writer) -> None:
        w.u16(self.priority); w.u16(self.weight); w.raw(self.target)

    def to_text(self) -> str:
        return f'{self.priority} {self.weight} "{self.target.decode("latin-1")}"'


@dataclass
class SVCB(Rdata):
    """SVCB / HTTPS (RFC 9460). SvcParams kept raw (round-trips); target is a name."""
    TYPE = Type.SVCB
    priority: int
    target: Name
    params: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int):
        end = r.tell() + rdlen
        prio = r.u16()
        target = read_name(r)
        return cls(prio, target, r.read(end - r.tell()))

    def emit(self, w: Writer) -> None:
        w.u16(self.priority)
        write_name(w, self.target, compress=False)
        w.raw(self.params)

    def to_text(self) -> str:
        return f"{self.priority} {self.target.to_text()} {self.params.hex()}"


class HTTPS(SVCB):
    TYPE = Type.HTTPS


# --- meta types (transaction security) --------------------------------------
@dataclass
class TSIG(Rdata):
    """TSIG transaction signature (RFC 8945). Owner=key name, class=ANY, ttl=0."""
    TYPE = Type.TSIG
    algorithm: Name
    time_signed: int          # 48-bit seconds since epoch
    fudge: int
    mac: bytes
    original_id: int
    error: int
    other: bytes

    @classmethod
    def parse(cls, r: Reader, rdlen: int) -> TSIG:
        algo = read_name(r)
        time_signed = (r.u16() << 32) | r.u32()
        fudge = r.u16()
        mac = r.read(r.u16())
        original_id = r.u16()
        error = r.u16()
        other = r.read(r.u16())
        return cls(algo, time_signed, fudge, mac, original_id, error, other)

    def emit(self, w: Writer) -> None:
        write_name(w, self.algorithm, compress=False)
        w.u16((self.time_signed >> 32) & 0xFFFF)
        w.u32(self.time_signed & 0xFFFFFFFF)
        w.u16(self.fudge)
        w.u16(len(self.mac)); w.raw(self.mac)
        w.u16(self.original_id)
        w.u16(self.error)
        w.u16(len(self.other)); w.raw(self.other)

    def to_text(self) -> str:
        return (f"{self.algorithm.to_text()} {self.time_signed} {self.fudge} "
                f"{base64.b64encode(self.mac).decode()} {self.original_id} {self.error}")


# --- generic fallback (RFC 3597) --------------------------------------------
@dataclass
class Unknown(Rdata):
    rtype: int
    data: bytes
    TYPE = -1

    @property
    def type(self) -> int:
        return self.rtype

    def emit(self, w: Writer) -> None:
        w.raw(self.data)

    def to_text(self) -> str:
        return rf"\# {len(self.data)} {self.data.hex()}" if self.data else r"\# 0"


_REGISTRY: dict[int, type] = {}
for _cls in (A, AAAA, NS, CNAME, PTR, DNAME, SOA, MX, SRV, TXT, SPF, HINFO,
             CAA, SSHFP, TLSA, DS, CDS, DNSKEY, CDNSKEY, RRSIG, NSEC,
             NSEC3, NSEC3PARAM, NAPTR, URI, SVCB, HTTPS, TSIG):
    _REGISTRY[int(_cls.TYPE)] = _cls


#: Types whose RDATA embeds a domain name, and which therefore may carry a
#: compression pointer that is only meaningful against the message it arrived
#: in. See the fallback in parse_rdata.
_NAME_BEARING = frozenset(
    getattr(Type, n) for n in
    ("NS", "CNAME", "SOA", "PTR", "MX", "SRV", "NAPTR", "DNAME", "RRSIG",
     "NSEC", "SVCB", "HTTPS", "KX", "RP")
    if hasattr(Type, n))


def parse_rdata(r: Reader, rtype: int, rdlen: int) -> Rdata:
    """Parse rdata of `rdlen` bytes. Unknown / undecodable types fall back to raw."""
    codec = _REGISTRY.get(rtype)
    if codec is None:
        return Unknown(rtype, r.read(rdlen))
    start = r.tell()
    try:
        rd = codec.parse(r, rdlen)
    except WireError as e:
        if rtype in _NAME_BEARING:
            # No raw fallback for a type whose rdata contains a name. Unknown
            # keeps the octets and re-emits them verbatim at whatever offset it
            # lands on next, so a name that failed to parse *because* it held a
            # compression pointer would have that pointer re-resolved against a
            # different message — decoding as an entirely different,
            # attacker-chosen name. Types with no embedded name are inert as raw
            # bytes and still fall back, so one malformed record does not cost
            # the rest of the message.
            raise WireError(f"undecodable rdata for type {rtype}: {e}") from e
        r.seek(start)
        return Unknown(rtype, r.read(rdlen))
    used = r.tell() - start
    if used != rdlen:
        # rdlength is the record's own statement of where it ends, and every
        # type here is fixed- or self-delimiting, so a codec that stops anywhere
        # else was reading a record that does not exist. The caller resyncs to
        # start+rdlen regardless, which keeps *parsing* on track but leaves the
        # record holding bytes borrowed from its neighbours: fuzzing produced a
        # SOA declaring rdlength 0 and carrying 77 bytes lifted from the records
        # after it. That record then gets cached, re-emitted, and signed over.
        # A message whose records do not add up is not one to answer.
        raise WireError(f"rdata for type {rtype} used {used} of {rdlen} octets")
    return rd


def rdata_type(rd: Rdata) -> int:
    return rd.rtype if isinstance(rd, Unknown) else int(rd.TYPE)
