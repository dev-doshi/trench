"""Bounds-checked read cursor over a DNS message. Every read validates length
and raises WireError rather than IndexError, so the parser is fuzz-safe."""
from __future__ import annotations

import struct

from ..errors import WireError

_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")


class Reader:
    __slots__ = ("buf", "pos")

    def __init__(self, buf: bytes, pos: int = 0):
        self.buf = buf
        self.pos = pos

    def remaining(self) -> int:
        return len(self.buf) - self.pos

    def eof(self) -> bool:
        return self.pos >= len(self.buf)

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.buf):
            raise WireError(f"read past end (need {n} at {self.pos}, len {len(self.buf)})")
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        if self.pos + 1 > len(self.buf):
            raise WireError("u8 past end")
        v = self.buf[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        if self.pos + 2 > len(self.buf):
            raise WireError("u16 past end")
        v = _U16.unpack_from(self.buf, self.pos)[0]
        self.pos += 2
        return v

    def u32(self) -> int:
        if self.pos + 4 > len(self.buf):
            raise WireError("u32 past end")
        v = _U32.unpack_from(self.buf, self.pos)[0]
        self.pos += 4
        return v

    def tell(self) -> int:
        return self.pos

    def seek(self, pos: int) -> None:
        if pos < 0 or pos > len(self.buf):
            raise WireError("seek out of range")
        self.pos = pos
