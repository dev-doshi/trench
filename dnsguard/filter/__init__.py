"""Filtering engine surface.

P0 ships `SimpleEngine` (exact + suffix + allow/deny), exposing the same
`match() -> Decision` contract that the full adblock/regex/RPZ engine in P2
will implement, so the pipeline never changes.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass

from ..wire.rdata import Rdata


class Action(enum.Enum):
    NONE = "none"
    BLOCK = "block"
    ALLOW = "allow"
    REWRITE = "rewrite"


@dataclass
class Decision:
    action: Action = Action.NONE
    rdata: Rdata | None = None       # for REWRITE
    rcode: int | None = None         # for BLOCK via REFUSED/NXDOMAIN
    rule: str = ""                   # human-readable matched rule
    source: str = ""                 # which list/source it came from
    reason: str = ""                 # explainability

    @property
    def blocked(self) -> bool:
        return self.action == Action.BLOCK


from .engine import FilterEngine  # noqa: E402
from .simple import SimpleEngine  # noqa: E402


def compile_rules(text: str, source: str = ""):
    """Parse a list (any dialect, RPZ autodetected) into Rule objects."""
    from .parser import parse_list
    from .rpz import looks_like_rpz, parse_rpz
    if looks_like_rpz(text):
        return parse_rpz(text, source)
    return parse_list(text, source)


__all__ = ["Action", "Decision", "FilterEngine", "SimpleEngine", "compile_rules"]
