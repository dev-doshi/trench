"""DNS rebinding protection: strip private/loopback addresses from answers to
public names (a public domain resolving to 192.168.x.x is a rebinding attack)."""
from __future__ import annotations

import dataclasses
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


#: SvcParamKeys that carry addresses (RFC 9460 §7.3). A client may connect to
#: these instead of looking up A/AAAA, so a private hint is as much a rebinding
#: vector as a private A record.
_HINT_KEYS = {4: 4, 6: 16}      # ipv4hint, ipv6hint -> address length


def _scrub_hints(params: bytes) -> bytes | None:
    """`params` without any address hint that names private space, or None when
    nothing needed removing. Malformed params come back unchanged (None): they
    state no address a client could use."""
    out, i, changed = [], 0, False
    while i < len(params):
        if i + 4 > len(params):
            return None
        key = int.from_bytes(params[i:i + 2], "big")
        ln = int.from_bytes(params[i + 2:i + 4], "big")
        val = params[i + 4:i + 4 + ln]
        if len(val) != ln:
            return None
        size = _HINT_KEYS.get(key)
        if size is not None:
            if ln % size:
                return None
            addrs = [val[j:j + size] for j in range(0, ln, size)]
            good = [a for a in addrs
                    if not _is_private(str(ipaddress.ip_address(a)))]
            if len(good) != len(addrs):
                changed = True
                if good:        # an empty hint list is invalid: drop the key
                    blob = b"".join(good)
                    out.append(params[i:i + 2] + len(blob).to_bytes(2, "big") + blob)
            else:
                out.append(params[i:i + 4 + ln])
        else:
            out.append(params[i:i + 4 + ln])
        i += 4 + ln
    return b"".join(out) if changed else None


def is_local_name(qname: str, local_suffixes: tuple[str, ...]) -> bool:
    name = qname.rstrip(".").lower()
    return any(name == s or name.endswith("." + s) for s in local_suffixes)


def scrub(response: Message, qname: str, *, local_suffixes: tuple[str, ...] = ()) -> int:
    """Remove A/AAAA answers pointing at private space for non-local names, and
    private address hints from SVCB/HTTPS answers. Returns the number of
    records stripped or rewritten."""
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
        if rr.rtype in (Type.SVCB, Type.HTTPS) and isinstance(rr.rdata, R.SVCB):
            params = _scrub_hints(rr.rdata.params)
            if params is not None:
                # A copy, not an edit: the record may be shared with a cache.
                rr = dataclasses.replace(
                    rr, rdata=dataclasses.replace(rr.rdata, params=params))
                removed += 1
        kept.append(rr)
    if removed:
        response.answers = kept
    return removed
