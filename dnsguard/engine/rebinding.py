"""DNS rebinding protection: strip private/loopback addresses from answers to
public names (a public domain resolving to 192.168.x.x is a rebinding attack)."""
from __future__ import annotations

import ipaddress

from ..wire import Message, Type


def _is_private(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_unspecified or ip.is_reserved)


def is_local_name(qname: str, local_suffixes: tuple[str, ...]) -> bool:
    name = qname.rstrip(".").lower()
    return any(name == s or name.endswith("." + s) for s in local_suffixes)


def scrub(response: Message, qname: str, *, local_suffixes: tuple[str, ...] = ()) -> int:
    """Remove A/AAAA answers pointing at private space for non-local names.
    Returns the number of records stripped."""
    if is_local_name(qname, local_suffixes):
        return 0
    kept = []
    removed = 0
    for rr in response.answers:
        if rr.rtype in (Type.A, Type.AAAA) and _is_private(rr.rdata.address):
            removed += 1
            continue
        kept.append(rr)
    if removed:
        response.answers = kept
    return removed
