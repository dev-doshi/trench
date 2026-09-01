"""The DNS message model + parse/serialize.

`Message.parse` never raises on malformed input except `WireError`, which the
network layer catches. `to_wire` handles name compression and UDP truncation.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import WireError
from .edns import Edns, build_opt_ttl, emit_options, parse_opt_ttl, parse_options
from .name import Name, read_name, write_name
from .rdata import Rdata, parse_rdata
from .reader import Reader
from .rrtypes import Class, Flags, Rcode, Type
from .writer import Writer

HEADER_LEN = 12


@dataclass
class Question:
    name: Name
    rtype: int = Type.A
    rclass: int = Class.IN


@dataclass
class RR:
    name: Name
    rtype: int
    rclass: int
    ttl: int
    rdata: Rdata


@dataclass
class Message:
    id: int = 0
    flags: int = 0
    questions: list[Question] = field(default_factory=list)
    answers: list[RR] = field(default_factory=list)
    authority: list[RR] = field(default_factory=list)
    additional: list[RR] = field(default_factory=list)
    edns: Edns | None = None

    # --- flag accessors ---
    @property
    def qr(self) -> bool: return bool(self.flags & Flags.QR)
    @property
    def opcode(self) -> int: return (self.flags & Flags.OPCODE_MASK) >> Flags.OPCODE_SHIFT
    @property
    def aa(self) -> bool: return bool(self.flags & Flags.AA)
    @property
    def tc(self) -> bool: return bool(self.flags & Flags.TC)
    @property
    def rd(self) -> bool: return bool(self.flags & Flags.RD)
    @property
    def ra(self) -> bool: return bool(self.flags & Flags.RA)
    @property
    def ad(self) -> bool: return bool(self.flags & Flags.AD)
    @property
    def cd(self) -> bool: return bool(self.flags & Flags.CD)

    @property
    def rcode(self) -> int:
        """Full 12-bit rcode (EDNS extended upper bits + header lower bits)."""
        base = self.flags & Flags.RCODE_MASK
        if self.edns:
            return (self.edns.ext_rcode << 4) | base
        return base

    def set_rcode(self, rcode: int) -> None:
        self.flags = (self.flags & ~Flags.RCODE_MASK) | (rcode & 0x0F)
        if rcode > 0x0F:
            if self.edns is None:
                self.edns = Edns()
            self.edns.ext_rcode = (rcode >> 4) & 0xFF
        elif self.edns is not None:
            # The `rcode` property ORs these bits back in, so a stale ext_rcode
            # left over from a parsed message makes a plain NOERROR read back
            # as 16 (BADVERS) to every downstream check.
            self.edns.ext_rcode = 0

    def set_flag(self, mask: int, on: bool = True) -> None:
        self.flags = (self.flags | mask) if on else (self.flags & ~mask)

    @property
    def question(self) -> Question | None:
        return self.questions[0] if self.questions else None

    def wants_dnssec(self) -> bool:
        return bool(self.edns and self.edns.do)

    # --- parse ---
    @classmethod
    def parse(cls, buf: bytes) -> Message:
        if len(buf) < HEADER_LEN:
            raise WireError("short header")
        r = Reader(buf)
        msgid = r.u16()
        flags = r.u16()
        qd, an, ns, ar = r.u16(), r.u16(), r.u16(), r.u16()
        msg = cls(id=msgid, flags=flags)
        for _ in range(qd):
            name = read_name(r)
            rtype = r.u16()
            rclass = r.u16()
            msg.questions.append(Question(name, rtype, rclass))
        msg.answers = _read_rrs(r, an, msg)
        msg.authority = _read_rrs(r, ns, msg)
        msg.additional = _read_rrs(r, ar, msg, owner=msg)  # OPT siphoned into msg.edns
        return msg

    # --- serialize ---
    def to_wire(self, max_size: int | None = None, compress: bool = True) -> bytes:
        data = self._encode(compress)
        if max_size is not None and len(data) > max_size:
            # The cap is about the datagram, not about the flag. Skipping this
            # when TC is already set treats "the sender said TC" as "the sender
            # sent something small", and a message that says TC can carry a full
            # answer section — an upstream handing one back turned a 512-byte
            # limit into a 16 KB datagram in testing.
            # truncate: keep question (+OPT), drop answer/authority/extra RRs, set TC
            #
            # The OPT is rebuilt without its options rather than carried over.
            # An option is arbitrary-length attacker- or upstream-controlled
            # payload, so keeping them made the "truncated" form larger than the
            # cap it exists to respect — a 60 KB option answered a 512-byte
            # limit with a 60 KB datagram carrying TC=1.
            edns = None if self.edns is None else Edns(
                udp_size=self.edns.udp_size, ext_rcode=self.edns.ext_rcode,
                version=self.edns.version, flags=self.edns.flags)
            trunc = Message(self.id, self.flags | Flags.TC, list(self.questions),
                            [], [], [], edns)
            data = trunc._encode(compress)
            if len(data) > max_size:
                # A question long enough to overrun the cap on its own. Drop the
                # OPT, then the question: the client learns to retry over TCP
                # from TC alone, and never from a datagram we refused to send.
                data = Message(self.id, self.flags | Flags.TC,
                               list(self.questions), [], [], [], None)._encode(compress)
                if len(data) > max_size:
                    data = Message(self.id, self.flags | Flags.TC,
                                   [], [], [], [], None)._encode(compress)
        return data

    def _encode(self, compress: bool) -> bytes:
        w = Writer()
        additional = list(self.additional)
        if self.edns is not None:
            additional = [rr for rr in additional if rr.rtype != Type.OPT]
        arcount = len(additional) + (1 if self.edns is not None else 0)
        w.u16(self.id)
        w.u16(self.flags)
        w.u16(len(self.questions))
        w.u16(len(self.answers))
        w.u16(len(self.authority))
        w.u16(arcount)
        for q in self.questions:
            write_name(w, q.name, compress)
            w.u16(q.rtype)
            w.u16(q.rclass)
        for rr in self.answers:
            _write_rr(w, rr, compress)
        for rr in self.authority:
            _write_rr(w, rr, compress)
        for rr in additional:
            _write_rr(w, rr, compress)
        if self.edns is not None:
            _write_opt(w, self.edns)
        return w.getvalue()

    # --- helpers ---
    def reply(self, rcode: int = Rcode.NOERROR) -> Message:
        """Skeleton response: echo id + question, QR/RA set, RD copied."""
        m = Message(id=self.id, flags=Flags.QR | Flags.RA)
        if self.rd:
            m.set_flag(Flags.RD, True)
        m.set_flag(Flags.OPCODE_MASK, False)
        m.flags |= (self.opcode << Flags.OPCODE_SHIFT)
        m.questions = list(self.questions)
        if self.edns is not None:
            m.edns = Edns(udp_size=self.edns.udp_size)
            m.edns.do = self.edns.do
        m.set_rcode(rcode)
        return m

    def min_ttl(self) -> int | None:
        ttls = [rr.ttl for rr in (self.answers + self.authority) if rr.rtype != Type.OPT]
        return min(ttls) if ttls else None



def _read_rrs(r: Reader, count: int, msg: Message, owner: Message | None = None) -> list[RR]:
    out: list[RR] = []
    for _ in range(count):
        name = read_name(r)
        rtype = r.u16()
        rclass = r.u16()
        ttl = r.u32()
        rdlen = r.u16()
        start = r.tell()
        if rtype == Type.OPT and owner is not None:
            ext_rcode, version, flags = parse_opt_ttl(ttl)
            owner.edns = Edns(udp_size=rclass, ext_rcode=ext_rcode, version=version,
                              flags=flags, options=parse_options(r.read(rdlen)))
            r.seek(start + rdlen)
            continue
        rd = parse_rdata(r, rtype, rdlen)
        r.seek(start + rdlen)  # authoritative resync, immune to codec bugs
        out.append(RR(name, rtype, rclass, ttl, rd))
    return out


def _write_rr(w: Writer, rr: RR, compress: bool) -> None:
    write_name(w, rr.name, compress)
    w.u16(rr.rtype)
    w.u16(rr.rclass)
    w.u32(rr.ttl)
    lenpos = w.reserve_u16()
    body_start = w.tell()
    rr.rdata.emit(w)
    w.patch_u16(lenpos, w.tell() - body_start)


def _write_opt(w: Writer, edns: Edns) -> None:
    w.u8(0)  # root name
    w.u16(Type.OPT)
    w.u16(edns.udp_size)               # CLASS field = requestor UDP size
    w.u32(build_opt_ttl(edns.ext_rcode, edns.version, edns.flags))
    lenpos = w.reserve_u16()
    body_start = w.tell()
    emit_options(w, edns.options)
    w.patch_u16(lenpos, w.tell() - body_start)
