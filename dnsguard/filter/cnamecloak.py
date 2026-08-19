"""CNAME-cloaking defense: re-check every CNAME target in a resolved answer
against the filter. Trackers hide behind first-party CNAMEs that resolve to a
blocked tracking domain; this catches them after resolution."""
from __future__ import annotations

from ..wire import Message, Type
from . import Decision
from .engine import FilterEngine


def inspect(engine: FilterEngine, response: Message, qtype: int, *,
            ctags: frozenset[str] = frozenset(), client: str = "",
            client_names: frozenset[str] = frozenset()) -> Decision | None:
    """Re-match every CNAME target under the *same* client context as the query.

    Calling `match` with the defaults evaluated the target against a different
    rule set than the name that led to it: every `$client`, `$ctag` and
    client-name rule was inert here, so a rule that blocked `tracker.net`
    directly for a tagged device let `first-party.example.com CNAME tracker.net`
    through untouched — which is the exact evasion this module exists to stop.
    """
    for rr in response.answers:
        if rr.rtype == Type.CNAME:
            target = rr.rdata.name.to_text().rstrip(".")
            d = engine.match(target, qtype, ctags=ctags, client=client,
                             client_names=client_names)
            if d.blocked:
                d.reason = f"CNAME cloak: {target} {d.reason}"
                return d
    return None
