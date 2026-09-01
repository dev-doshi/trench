"""Test helpers shared across suites.

`blocked_engine` exists because the pipeline suites used to build their filter
from `SimpleEngine`, a second matcher that no deployment ever ran. Its semantics
differed from the real one — no `$ctag`, no `$client`, no regex, a different
precedence order — so a change to `FilterEngine` could break every deployment
while the transport, multicore and upstream suites stayed green. This builds the
engine that actually serves queries, from the rule text an operator would write.
"""
from __future__ import annotations

from dnsguard.filter import FilterEngine, iter_rules


def blocked_engine(*domains: str, allow: tuple[str, ...] = ()) -> FilterEngine:
    """A FilterEngine blocking `domains` and their subdomains, allowing `allow`."""
    lines = [f"||{d}^" for d in domains] + [f"@@||{d}^$important" for d in allow]
    return FilterEngine.compile(iter_rules("\n".join(lines), "test"))
