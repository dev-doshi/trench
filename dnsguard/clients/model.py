"""Client + effective Policy data model."""
from __future__ import annotations

from dataclasses import dataclass, field, replace


@dataclass(frozen=True)
class Policy:
    name: str = "default"
    block: bool = True                       # gravity/custom filtering on
    ctags: frozenset[str] = frozenset()      # client tags for $ctag rules
    safe_search: bool = False                # force safe search
    safe_browse: bool = False                # malware/phishing protection
    parental: bool = False                   # adult-content protection
    services: frozenset[str] = frozenset()   # blocked service ids
    upstream_group: str = ""                 # named upstream set (P5)

    def merged_with(self, **overrides) -> Policy:
        clean = {k: v for k, v in overrides.items() if v is not None}
        return replace(self, **clean)


@dataclass
class Client:
    ident: str
    ident_type: str = "ip"        # ip | cidr | mac | clientid | token
    name: str = ""
    policy: Policy = field(default_factory=Policy)
