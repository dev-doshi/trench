"""DNS rebinding protection: strip private/loopback addresses from answers to
public names (a public domain resolving to 192.168.x.x is a rebinding attack)."""
from __future__ import annotations

import functools
import ipaddress

from ..wire import Message, Type
from ..wire import rdata as R

#: Distinct answer addresses to remember the verdict for. A household resolves
#: the same few hundred services all day, so the table is small and the hit rate
#: is high; it is bounded because the addresses come from answers, which means a
#: caller can choose them.
_VERDICT_CACHE = 4096


@functools.lru_cache(maxsize=_VERDICT_CACHE)
def _is_private(addr: str) -> bool:
    """Whether an answer address is one a public name has no business returning.

    Memoised because this is the most expensive thing on the uncached forward
    path: profiled, `scrub` was about half of it, and `ipaddress._parse_octet`
    the single largest entry — the five `is_*` properties each walk a list of
    networks, and CPython recomputes them per call. The verdict is a pure
    function of the string, so it can be remembered.

    Measured at 8.8 us -> 0.17 us for four repeating addresses (53x). Addresses
    that never repeat cost 5% more than not caching at all, which is the right
    side of that trade and is bounded by `_VERDICT_CACHE` either way.
    """
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
        # A record claiming an address type whose rdata did not decode has no
        # `.address` (see `parse_rdata`), and this runs on every answer under
        # the default config: one raised AttributeError, and the pipeline turned
        # the whole response into SERVFAIL. Such a record is passed through
        # rather than stripped — its rdlength cannot be 4 or 16, so it states no
        # address at all and is not a rebinding hit to count.
        if (rr.rtype in (Type.A, Type.AAAA)
                and isinstance(rr.rdata, (R.A, R.AAAA))
                and _is_private(rr.rdata.address)):
            removed += 1
            continue
        kept.append(rr)
    if removed:
        response.answers = kept
    return removed
