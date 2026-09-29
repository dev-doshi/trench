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



#: Identifier types that are presented by the client as a secret — the DoH
#: path segment or the DoT/DoQ SNI label. Whoever knows one *is* that client.
SECRET_IDENT_TYPES = frozenset({"clientid", "token"})


def mask_client_id(value: str) -> str:
    """A client id fit for a log line or a read-only screen.

    The last four characters stay so devices can still be told apart; the
    rest is a credential and is not repeated anywhere a viewer can read it.
    """
    if not value:
        return value
    return "\u2022\u2022\u2022\u2022" + (value[-4:] if len(value) >= 12 else "")


def mask_ident(ident: str, ident_type: str) -> str:
    """`mask_client_id`, for identifiers of a type that is a credential."""
    return mask_client_id(ident) if str(ident_type) in SECRET_IDENT_TYPES else ident


@dataclass
class Client:
    ident: str
    ident_type: str = "ip"        # ip | cidr | mac | clientid | token
    name: str = ""
    policy: Policy = field(default_factory=Policy)
