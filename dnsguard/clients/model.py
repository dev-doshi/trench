"""Client + effective Policy data model."""
from __future__ import annotations

from dataclasses import dataclass, field


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
    group: str = ""                          # filtering group (its own lists)



@dataclass
class Client:
    ident: str
    ident_type: str = "ip"        # ip | cidr | mac | clientid | token
    name: str = ""
    policy: Policy = field(default_factory=Policy)
