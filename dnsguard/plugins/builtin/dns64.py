"""DNS64 (RFC 6147): synthesize AAAA from A using a NAT64 prefix when a name
has no native IPv6, so IPv6-only clients can reach IPv4-only services."""
from __future__ import annotations

import socket

from ...wire import RR, Class, Message, Question, Type
from ...wire import rdata as R
from ...wire.rrtypes import Flags
from ..api import Plugin

DEFAULT_PREFIX = "64:ff9b::"   # the well-known NAT64 prefix


class Dns64Plugin(Plugin):
    name = "dns64"

    def configure(self, options: dict) -> None:
        self.prefix = options.get("prefix", DEFAULT_PREFIX)
        self._pfx = socket.inet_pton(socket.AF_INET6, self.prefix)[:12]

    async def on_answer(self, ctx) -> None:
        q = ctx.query.question
        resp = ctx.response
        if q is None or resp is None or q.rtype != Type.AAAA:
            return
        if any(rr.rtype == Type.AAAA for rr in resp.answers):
            return  # already has native IPv6
        a_records = await self._fetch_a(q.name)
        if not a_records:
            return
        for a in a_records:
            v4 = socket.inet_pton(socket.AF_INET, a)
            v6 = socket.inet_ntop(socket.AF_INET6, self._pfx + v4)
            resp.answers.append(RR(q.name, Type.AAAA, Class.IN, 60, R.AAAA(v6)))
        ctx.reason = "dns64 synthesized"

    async def _fetch_a(self, name) -> list[str]:
        sub = Message(id=0)
        sub.set_flag(Flags.RD, True)
        sub.questions.append(Question(name, Type.A, Class.IN))
        try:
            up = await self.app.forwarder.resolve(sub)
            return [rr.rdata.address for rr in up.answers if rr.rtype == Type.A]
        except Exception:
            return []
