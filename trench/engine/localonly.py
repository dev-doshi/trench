"""Names a resolver answers itself and never forwards.

Asked of a public resolver these cannot resolve, and the question alone
publishes the household's addresses and device names: a PTR sweep of
192.168.x.x, `wpad.<search domain>`, a container's probe of `*.invalid`.
"""
from __future__ import annotations

#: RFC 6303 reverse zones for private and special address space, and the
#: special-use names of RFC 6761 (`invalid`, `localhost`), RFC 6762 (`local`),
#: RFC 8375 (`home.arpa`) and RFC 9462 (`resolver.arpa`).
SPECIAL_USE: frozenset[str] = frozenset({
    "0.in-addr.arpa", "10.in-addr.arpa", "127.in-addr.arpa",
    "254.169.in-addr.arpa", "168.192.in-addr.arpa",
    *(f"{i}.172.in-addr.arpa" for i in range(16, 32)),
    *(f"{i}.100.in-addr.arpa" for i in range(64, 128)),      # RFC 6598 CGNAT
    "d.f.ip6.arpa",                                             # fc00::/7 ULA
    *(f"{c}.e.f.ip6.arpa" for c in "89ab"),                     # fe80::/10
    "0." * 31 + "0.ip6.arpa", "1." + "0." * 31 + "ip6.arpa",   # :: and ::1
    "invalid", "localhost", "local", "home.arpa", "resolver.arpa",
})


def is_local_only(qname: str, local_suffixes: tuple[str, ...] = ()) -> bool:
    """True if `qname` is, or sits under, a special-use or operator-local zone."""
    name = qname.rstrip(".").lower()
    while name:
        if name in SPECIAL_USE or name in local_suffixes:
            return True
        _, _, name = name.partition(".")
    return False
