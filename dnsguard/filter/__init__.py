"""Filtering engine surface.

`FilterEngine` is the matcher: adblock syntax, hosts and dnsmasq dialects, RPZ,
regex, and the `$`-modifiers on top. It is the only one — an earlier
`SimpleEngine` (exact + suffix + allow/deny) survived here long after it stopped
being used by anything but tests, where its different precedence and missing
modifiers meant four suites were checking the pipeline against a matcher no
deployment ran.
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


def compile_rules(text: str, source: str = ""):
    """Parse a list (any dialect, RPZ autodetected) into Rule objects."""
    return list(iter_rules(text, source))


def iter_rules(text: str, source: str = ""):
    """As `compile_rules`, one Rule at a time.

    What `FilterEngine.compile` consumes, so a source is routed into the
    compiled form as it is read rather than materialised in full first.
    """
    from .parser import iter_list
    from .rpz import looks_like_rpz, parse_rpz
    if looks_like_rpz(text):
        yield from parse_rpz(text, source)
        return
    yield from iter_list(text, source)


def badfilter_keys(texts) -> frozenset:
    """The pattern identities disabled by `$badfilter` anywhere in `texts`.

    Worked out up front so the corpus itself can be compiled in one streaming
    pass — see `FilterEngine._live_rules`. `texts` is an iterable of
    (source, text) pairs.
    """
    from .engine import _pattern_id
    from .parser import iter_badfilter
    from .rpz import looks_like_rpz
    keys = set()
    for source, text in texts:
        if looks_like_rpz(text):
            continue          # RPZ has no $badfilter
        for r in iter_badfilter(text, source):
            keys.add(_pattern_id(r))
    return frozenset(keys)


__all__ = ["Action", "Decision", "FilterEngine",
           "badfilter_keys", "compile_rules", "iter_rules"]
