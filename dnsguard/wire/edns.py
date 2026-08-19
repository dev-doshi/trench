"""EDNS(0) / OPT pseudo-record: UDP size negotiation, DO bit, and options
(ECS, COOKIE, PADDING, NSID, ...). The OPT RR is parsed out of the additional
section into a structured `Edns` and re-synthesized on the way out."""
from __future__ import annotations

import socket
from dataclasses import dataclass, field

from .reader import Reader
from .rrtypes import EDNSOption
from .writer import Writer

DO_BIT = 0x8000  # DNSSEC OK, in the OPT TTL flags field


@dataclass
class Edns:
    udp_size: int = 1232           # sensible default (avoids fragmentation)
    ext_rcode: int = 0             # upper 8 bits of the 12-bit extended rcode
    version: int = 0
    flags: int = 0                 # DO_BIT etc.
    options: list[tuple[int, bytes]] = field(default_factory=list)

    @property
    def do(self) -> bool:
        return bool(self.flags & DO_BIT)

    @do.setter
    def do(self, on: bool) -> None:
        self.flags = (self.flags | DO_BIT) if on else (self.flags & ~DO_BIT)

    def get_option(self, code: int) -> bytes | None:
        for c, data in self.options:
            if c == code:
                return data
        return None

    def set_option(self, code: int, data: bytes) -> None:
        self.options = [(c, d) for c, d in self.options if c != code]
        self.options.append((code, data))

    def remove_option(self, code: int) -> None:
        self.options = [(c, d) for c, d in self.options if c != code]

    # --- ECS (RFC 7871) ---
    def get_ecs(self) -> ECS | None:
        raw = self.get_option(EDNSOption.ECS)
        return ECS.from_bytes(raw) if raw is not None else None

    def set_ecs(self, ecs: ECS) -> None:
        self.set_option(EDNSOption.ECS, ecs.to_bytes())

    # --- PADDING (RFC 7830 / 8467) ---
    def set_padding(self, target_block: int = 468, current_len: int = 0) -> None:
        """Pad the OPT so the whole message length is a multiple of target_block.
        `current_len` is the serialized length *without* the padding option; the
        4-byte padding option header is accounted for here."""
        self.remove_option(EDNSOption.PADDING)
        total_wo_pad = current_len + 4  # option code + length header
        pad = (target_block - (total_wo_pad % target_block)) % target_block
        self.set_option(EDNSOption.PADDING, b"\x00" * pad)


@dataclass
class ECS:
    family: int          # 1 = IPv4, 2 = IPv6
    source_prefix: int
    scope_prefix: int
    address: bytes       # truncated to source_prefix bits

    @classmethod
    def from_client(cls, ip: str, v4_prefix: int = 24, v6_prefix: int = 56) -> ECS:
        if ":" in ip:
            raw = socket.inet_pton(socket.AF_INET6, ip)
            prefix = v6_prefix
            fam = 2
        else:
            raw = socket.inet_pton(socket.AF_INET, ip)
            prefix = v4_prefix
            fam = 1
        nbytes = (prefix + 7) // 8
        return cls(fam, prefix, 0, raw[:nbytes])

    @classmethod
    def from_bytes(cls, b: bytes) -> ECS | None:
        if len(b) < 4:
            return None
        family = int.from_bytes(b[0:2], "big")
        src = b[2]
        scope = b[3]
        return cls(family, src, scope, b[4:])

    def to_bytes(self) -> bytes:
        return (self.family.to_bytes(2, "big") + bytes([self.source_prefix, self.scope_prefix])
                + self.address)

    def network_text(self) -> str:
        fam = socket.AF_INET if self.family == 1 else socket.AF_INET6
        full = (4 if self.family == 1 else 16)
        padded = self.address + b"\x00" * (full - len(self.address))
        return f"{socket.inet_ntop(fam, padded)}/{self.source_prefix}"


def parse_opt_ttl(ttl: int) -> tuple[int, int, int]:
    """Decompose the OPT RR TTL field -> (ext_rcode, version, flags)."""
    ext_rcode = (ttl >> 24) & 0xFF
    version = (ttl >> 16) & 0xFF
    flags = ttl & 0xFFFF
    return ext_rcode, version, flags


def build_opt_ttl(ext_rcode: int, version: int, flags: int) -> int:
    return ((ext_rcode & 0xFF) << 24) | ((version & 0xFF) << 16) | (flags & 0xFFFF)


def parse_options(data: bytes) -> list[tuple[int, bytes]]:
    r = Reader(data)
    out: list[tuple[int, bytes]] = []
    while r.remaining() >= 4:
        code = r.u16()
        length = r.u16()
        out.append((code, r.read(length)))
    return out


def emit_options(w: Writer, options: list[tuple[int, bytes]]) -> None:
    for code, data in options:
        w.u16(code)
        w.u16(len(data))
        w.raw(data)
