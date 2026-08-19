"""Append-only write buffer with name-compression state and length back-patching."""
from __future__ import annotations

import struct

_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")


class Writer:
    __slots__ = ("buf", "names")

    def __init__(self) -> None:
        self.buf = bytearray()
        # case-insensitive suffix -> offset, for DNS name compression
        self.names: dict[tuple[bytes, ...], int] = {}

    def tell(self) -> int:
        return len(self.buf)

    def u8(self, v: int) -> None:
        self.buf.append(v & 0xFF)

    def u16(self, v: int) -> None:
        self.buf += _U16.pack(v & 0xFFFF)

    def u32(self, v: int) -> None:
        self.buf += _U32.pack(v & 0xFFFFFFFF)

    def raw(self, b: bytes) -> None:
        self.buf += b

    def reserve_u16(self) -> int:
        """Write a 0 placeholder u16, return its offset for later patch_u16."""
        pos = len(self.buf)
        self.buf += b"\x00\x00"
        return pos

    def patch_u16(self, pos: int, v: int) -> None:
        _U16.pack_into(self.buf, pos, v & 0xFFFF)

    def getvalue(self) -> bytes:
        return bytes(self.buf)
