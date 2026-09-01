"""Assertions the filtering policy has to satisfy before a refresh is adopted.

A blocklist refresh is an unreviewed deploy to the most load-bearing service in
the building, and every product in this category performs it silently. This
module is the missing gate: the operator writes down what must be true —

    filtering:
      assertions:
        - "bank.example must resolve"
        - "doubleclick.net must block"
        - "*.internal.lan must resolve"

— and a candidate rule set that violates any of them is not adopted. The lists
keep being fetched; what changes is that a refresh which would have broken
online banking is reported instead of served.

Deliberately narrow. Assertions run against the compiled rules only: they ask
"what verdict would this policy reach", not "is that host up". A resolver test
that needs the network would turn every refresh into an outage-sensitive
operation, which is the opposite of the point.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..log import get
from ..wire.rrtypes import Type

log = get("contract")

BLOCK, RESOLVE = "block", "resolve"


class ContractError(ValueError):
    """An assertion that cannot be parsed. Raised at config load, never later."""


@dataclass(frozen=True)
class Assertion:
    name: str
    expect: str                    # "block" | "resolve"
    qtype: int = Type.A
    source: str = ""               # the text it was written as, for reporting

    def describe(self) -> str:
        return self.source or f"{self.name} must {self.expect}"


@dataclass(frozen=True)
class Failure:
    assertion: Assertion
    verdict: str                   # what the candidate rules actually did
    rule: str = ""                 # the rule responsible, when there is one
    list_source: str = ""

    def describe(self) -> str:
        detail = f" ({self.rule} from {self.list_source})" if self.rule else ""
        return f"{self.assertion.describe()} — but it would {self.verdict}{detail}"


def parse_assertion(text: str) -> Assertion:
    """`"ads.example must block"` -> Assertion. Also accepts an explicit type:
    `"mail.example MX must resolve"`.
    """
    raw = text.strip()
    parts = raw.split()
    if len(parts) < 3 or parts[-2].lower() != "must":
        raise ContractError(
            f"cannot read assertion {raw!r}; expected \"<name> [type] must "
            f"block|resolve\"")
    expect = parts[-1].lower().rstrip(".")
    if expect not in (BLOCK, RESOLVE):
        raise ContractError(f"assertion {raw!r} must end in 'block' or 'resolve'")
    name = parts[0].strip(".").lower()
    if not name:
        raise ContractError(f"assertion {raw!r} names nothing")
    qtype = Type.A
    if len(parts) == 4:
        try:
            qtype = Type[parts[1].upper()]
        except KeyError as e:
            raise ContractError(
                f"assertion {raw!r} names an unknown record type") from e
    elif len(parts) > 4:
        raise ContractError(f"cannot read assertion {raw!r}: too many words")
    return Assertion(name=name, expect=expect, qtype=qtype, source=raw)


def parse_all(texts) -> list[Assertion]:
    return [parse_assertion(t) for t in texts or ()]


def check(engine, assertions) -> list[Failure]:
    """Every assertion `engine` violates, in the order they were written.

    A wildcard assertion (`*.example`) is checked on a representative name
    under it, which is what the operator means by writing one: "nothing in
    here may be blocked".
    """
    failures: list[Failure] = []
    for a in assertions:
        probe = a.name.replace("*.", "assert-probe.", 1) if a.name.startswith("*.") \
            else a.name
        try:
            d = engine.match(probe, a.qtype)
        except Exception:
            log.exception("assertion %s could not be evaluated", a.describe())
            continue
        blocked = bool(getattr(d, "blocked", False))
        if blocked and a.expect == RESOLVE:
            failures.append(Failure(a, "be blocked", getattr(d, "rule", ""),
                                    getattr(d, "source", "")))
        elif not blocked and a.expect == BLOCK:
            failures.append(Failure(a, "resolve"))
    return failures


def summarise(failures: list[Failure]) -> str:
    head = "; ".join(f.describe() for f in failures[:3])
    more = f" (+{len(failures) - 3} more)" if len(failures) > 3 else ""
    return head + more
