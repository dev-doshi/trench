"""DNS wire-format layer: bounds-checked, fuzz-safe codec for the full RR zoo.

Public surface:
    Message, Question, RR, Rdata        -- message model
    Name                                -- domain names
    Type, Class, Opcode, Rcode, Flags   -- enums/constants
    Edns, EDNSOption                    -- EDNS(0) / OPT handling
    WireError                           -- raised on malformed input
"""
from __future__ import annotations

from ..errors import WireError
from .edns import Edns
from .message import RR, Message, Question
from .name import Name
from .rdata import Rdata, parse_rdata
from .rrtypes import Class, EDNSOption, Flags, Opcode, Rcode, Type

__all__ = [
    "Message", "Question", "RR", "Rdata", "parse_rdata",
    "Name", "Edns", "EDNSOption",
    "Type", "Class", "Opcode", "Rcode", "Flags", "WireError",
]
