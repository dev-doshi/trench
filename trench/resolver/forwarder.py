"""Forwarding resolver over a Router of upstreams (any transport), with
selectable strategy and per-domain routing.
"""
from __future__ import annotations

import asyncio

from ..errors import UpstreamError
from ..log import get
from ..transport.upstream import Router, Upstream, parse_upstream  # noqa: F401
from ..wire import Message

log = get("forwarder")


def parse_server(spec: str) -> tuple[str, int]:
    """Back-compat helper: return (host, port) for a plain spec."""
    us = parse_upstream(spec)
    return us.host, us.port


class Forwarder:
    def __init__(self, servers: list[str], *, strategy: str = "parallel",
                 timeout: float = 4.0, verify: bool = True, trust_ad: str = "auto",
                 udp_source_ports: int = 0):
        self.router = Router.build(servers, timeout=timeout, verify=verify,
                                   trust_ad=trust_ad,
                                   udp_source_ports=udp_source_ports)
        self.strategy = strategy
        self.timeout = timeout

    def _qname(self, query: Message) -> str:
        q = query.question
        return q.name.to_text() if q else "."

    async def resolve(self, query: Message, note=None) -> Message:
        """Resolve `query`. `note(str)` — if given — is called with the upstream
        that answered.

        Which server produced an answer is not cosmetic: a warning about an
        upstream attaching records it was never asked for is not actionable
        without it, and the operator's per-upstream stats are otherwise empty.
        Passed as a callback rather than returned, so the many existing callers
        that only want the answer are unaffected.
        """
        group = self.router.group_for(self._qname(query))
        if not group:
            raise UpstreamError("no upstreams configured")
        if self.strategy == "sequential":
            return await self._sequential(group, query, note)
        if self.strategy in ("fastest", "weighted"):
            return await self._fastest(group, query, note)
        return await self._parallel(group, query, note)

    @staticmethod
    async def _ask(up: Upstream, query: Message) -> tuple[Message, str]:
        """The label travels back with the answer rather than being reported from
        inside the task: in a parallel race a loser can finish after the winner
        has been picked, and would otherwise take the credit."""
        return await up.query(query), repr(up)

    @staticmethod
    def _won(resp_who: tuple[Message, str], note) -> Message:
        resp, who = resp_who
        if note is not None:
            note(who)
        return resp

    async def _sequential(self, group: list[Upstream], query: Message, note=None) -> Message:
        last: Exception | None = None
        for up in group:
            try:
                return self._won(await self._ask(up, query), note)
            except Exception as e:
                last = e
        raise UpstreamError(f"all upstreams failed: {last}")

    async def _parallel(self, group: list[Upstream], query: Message, note=None) -> Message:
        tasks = [asyncio.ensure_future(self._ask(up, query)) for up in group]
        err: Exception | None = None
        try:
            for fut in asyncio.as_completed(tasks):
                try:
                    return self._won(await fut, note)
                except Exception as e:
                    err = e
            raise UpstreamError(f"all upstreams failed: {err}")
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()

    async def _fastest(self, group: list[Upstream], query: Message, note=None) -> Message:
        ordered = sorted(group, key=lambda u: (u.failures, u.rtt))
        if len(ordered) == 1:
            return self._won(await self._ask(ordered[0], query), note)
        # try the two fastest in parallel, rest as fallback
        head, tail = ordered[:2], ordered[2:]
        try:
            return await self._parallel(head, query, note)
        except UpstreamError:
            if tail:
                return await self._parallel(tail, query, note)
            raise

    async def close(self) -> None:
        """Drop every upstream connection this forwarder owns.

        Also reached when a live settings change builds a replacement forwarder:
        without it the old router's DoT connections and DoH sessions stay open
        for the life of the process, one leaked set per change.
        """
        await self.router.close()
