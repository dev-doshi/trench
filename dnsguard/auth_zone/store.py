"""Holds authoritative zones and answers queries we're authoritative for."""
from __future__ import annotations

from ..wire import Message
from ..wire.name import Name
from ..wire.rrtypes import Flags
from .zone import Zone


class ZoneStore:
    def __init__(self) -> None:
        self.zones: list[Zone] = []

    def add(self, zone: Zone) -> None:
        self.zones.append(zone)

    def replace(self, zone: Zone) -> None:
        """Swap in a new copy of a zone by origin (used by secondary refresh)."""
        self.zones = [z for z in self.zones if z.origin != zone.origin]
        self.zones.append(zone)

    @property
    def empty(self) -> bool:
        return not self.zones

    def authoritative_for(self, qname: Name) -> Zone | None:
        best: Zone | None = None
        best_len = -1
        for z in self.zones:
            if qname.is_subdomain_of(z.origin) and len(z.origin) > best_len:
                best, best_len = z, len(z.origin)
        return best

    def resolve(self, query: Message) -> Message | None:
        q = query.question
        if q is None:
            return None
        zone = self.authoritative_for(q.name)
        if zone is None:
            return None
        ans = zone.lookup(q.name, q.rtype, do=query.wants_dnssec())
        resp = query.reply(ans.rcode)
        resp.set_flag(Flags.AA, ans.aa)
        resp.answers = ans.answers
        resp.authority = ans.authority
        resp.additional = ans.additional
        return resp
