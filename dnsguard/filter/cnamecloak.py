"""CNAME-cloaking defense: re-check every CNAME target in a resolved answer
against the filter. Trackers hide behind first-party CNAMEs that resolve to a
blocked tracking domain; this catches them after resolution."""
from __future__ import annotations

from ..wire import Message, Type
from . import Decision
from .engine import FilterEngine


def inspect(engine: FilterEngine, response: Message, qtype: int) -> Decision | None:
    for rr in response.answers:
        if rr.rtype == Type.CNAME:
            target = rr.rdata.name.to_text().rstrip(".")
            d = engine.match(target, qtype)
            if d.blocked:
                d.reason = f"CNAME cloak: {target} {d.reason}"
                return d
    return None
