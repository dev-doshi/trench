"""Per-group filtering: different lists for the kids, the TV and the laptops.

The database has modelled this since the beginning — a `group` table, and a
`group_id` on both `adlist` and `custom_rule` — and nothing read those columns,
so a group could be created and lists assigned to it with no effect on any
verdict. This is the missing half.

The shape is Pi-hole's, because that is the one every operator already knows:
clients belong to a group, groups own list subscriptions and rules, and a client
in no group gets the default set.

What is deliberately *not* done here is compiling the whole corpus again per
group. A household's blocklists are hundreds of thousands of rules and the box
this runs on has under a gigabyte; three groups would be three copies of the same
600k names. Instead a group holds only its own extra rules and is layered over
the shared default:

    group verdict wins if it has one (block *or* allow — an allow rule in a
    group is exactly how "the kids' tablet may reach this one site" is written)
    otherwise fall through to the default rules, unless the group is declared
    `inherit: false`, which means the group's list is the whole policy.

The memory cost of a group is therefore its own rules and nothing else.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..log import get
from . import Action, Decision

log = get("filter.groups")


@dataclass
class GroupSpec:
    """One group's sources, as configured."""
    name: str
    sources: list[str]
    allow: list[str]
    deny: list[str]
    inherit: bool = True


class LayeredFilter:
    """A group's own rules in front of the shared default rules.

    Reads the default engine through a callable rather than holding it, because
    a blocklist refresh replaces that engine and every group has to follow it —
    holding a reference is how a group ends up filtering against last week's
    rules for the life of the process.
    """

    __slots__ = ("name", "own", "_base", "inherit")

    def __init__(self, name: str, own, base_getter, inherit: bool = True):
        self.name = name
        self.own = own                  # FilterEngine with this group's rules
        self._base = base_getter        # () -> FilterEngine (the default set)
        self.inherit = inherit

    @property
    def base(self):
        return self._base()

    # -- the FilterEngine surface the pipeline uses --------------------------
    def match(self, qname: str, qtype: int = 1, **kw) -> Decision:
        d = self.own.match(qname, qtype, **kw)
        if d.action != Action.NONE:
            return d
        if not self.inherit:
            return Decision()
        return self.base.match(qname, qtype, **kw)

    @property
    def ips(self):
        """Address lists stay shared: they come from the same feeds and a group
        has no reason to disagree about which networks are hostile."""
        return self.base.ips

    @property
    def has_client_rules(self) -> bool:
        return bool(self.own.has_client_rules or self.base.has_client_rules)

    @property
    def size(self) -> int:
        return self.own.size + (self.base.size if self.inherit else 0)

    def suffixes(self, name: str):
        return self.own.suffixes(name)
