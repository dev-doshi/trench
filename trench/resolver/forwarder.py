"""Forwarding resolver over a Router of upstreams (any transport), with
selectable strategy and per-domain routing.
"""
from __future__ import annotations

import asyncio

from ..errors import UpstreamError
from ..log import get
from ..transport.upstream import Router, Upstream, parse_upstream  # noqa: F401
from ..wire import Message
from ..wire.rrtypes import Rcode

log = get("forwarder")

#: Replies that describe the upstream, not the name. RFC 8767 §4 and every
#: mainstream forwarder treat these as "try somewhere else": a validating
#: upstream answering SERVFAIL for a name whose signatures it could not check,
#: or one that has stopped serving us (REFUSED), says nothing about what the
#: next upstream will answer.
_FAILOVER_RCODES = frozenset({Rcode.SERVFAIL, Rcode.REFUSED})

#: How long a failure demotes an upstream in the `fastest` ranking, in seconds.
#: A failure has to be forgotten eventually: a demoted upstream is only asked
#: when the head fails, so nothing else would ever clear it.
_FAILURE_MEMORY = 30.0


def _recent_failures(up, now: float) -> int:
    """Failures within `_FAILURE_MEMORY`, else 0.

    An upstream that does not say when it last failed is taken to have failed
    just now — the conservative reading.
    """
    failures = getattr(up, "failures", 0)
    if failures and now - getattr(up, "failed_at", now) >= _FAILURE_MEMORY:
        return 0
    return failures


def _rank(up, now: float) -> tuple[int, float]:
    """Sort key for `fastest`: recent failures first, then smoothed RTT."""
    return _recent_failures(up, now), up.rtt


def parse_server(spec: str) -> tuple[str, int]:
    """Back-compat helper: return (host, port) for a plain spec."""
    us = parse_upstream(spec)
    return us.host, us.port


def _retrieved(task) -> None:
    """Consume a cancelled loser's outcome so asyncio does not report it.

    A task cancelled *after* it already failed still holds that exception, and
    the cancel does not clear it.
    """
    if not task.cancelled():
        task.exception()


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
        resp = await up.query(query)
        if resp.rcode in _FAILOVER_RCODES:
            # Accepted as a success, this ended the whole resolution: the
            # sequential and fastest strategies never asked the next upstream,
            # a parallel race was won by whichever server failed quickest, and
            # the pipeline handed the SERVFAIL to the client even while it held
            # a stale copy it could have served. Counted as a failure too, so
            # `fastest` stops ranking a server that only ever refuses.
            up.failures = getattr(up, "failures", 0) + 1
            up.failed_at = asyncio.get_running_loop().time()
            raise UpstreamError(f"{up!r} answered rcode {resp.rcode}")
        return resp, repr(up)

    @staticmethod
    def _won(resp_who: tuple[Message, str], note) -> Message:
        resp, who = resp_who
        if note is not None:
            note(who)
        return resp

    async def _sequential(self, group: list[Upstream], query: Message, note=None) -> Message:
        """Ask in configured order, with recently failed upstreams moved last.

        Strict order made a dead first upstream cost every query the full
        timeout before the second was asked — four seconds a lookup, for as long
        as it stayed down. The sort is stable, so the operator's order still
        holds among the healthy ones, and a failure is forgotten after
        `_FAILURE_MEMORY`: the first upstream gets one query to prove itself
        and takes the lead back as soon as it answers.
        """
        now = asyncio.get_running_loop().time()
        last: Exception | None = None
        for up in sorted(group, key=lambda u: _recent_failures(u, now) > 0):
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
            # Retrieve every loser's outcome. A race leaves tasks nobody awaits,
            # and asyncio logs "Task exception was never retrieved" with a full
            # traceback when one of them is collected — so an upstream that
            # merely reset an idle TLS connection, while the other upstream
            # answered the query perfectly well, printed a traceback into the
            # log of a resolver that had done nothing wrong.
            for t in tasks:
                if t.done():
                    if not t.cancelled():
                        t.exception()
                else:
                    t.cancel()
                    t.add_done_callback(_retrieved)

    async def _fastest(self, group: list[Upstream], query: Message, note=None) -> Message:
        """Ask the upstream that has been answering fastest; fall back to the rest.

        The head used to be the *two* fastest, raced in parallel, with everything
        after them as the fallback tier. At the group size people actually
        configure — two upstreams — that made `fastest` an alias for `parallel`:
        the head was the whole group, the fallback tier was empty, and the sort
        above it decided nothing. Both servers were queried for every name, which
        is the cost `parallel` exists to pay on purpose and `fastest` exists to
        avoid; on the deployment this was found on it meant two resolver
        operators saw every query instead of one.

        One head and everyone else as fallback makes the strategy mean what it
        says at every group size, and leaves the fallback tier non-empty whenever
        there is anywhere to fall back to. Recent failures lead the sort key
        (see `_rank`), so an upstream that just failed is tried last rather than
        being asked again first.
        """
        # Recent failures only. Ranked on the lifetime count, one timeout left an
        # upstream behind a peer that never failed for good — however slow that
        # peer became — because the demoted one was never asked again and so
        # never had the success that resets the count. Once its failure is old
        # it competes on RTT again: one query probes it, and a second failure
        # demotes it for another window.
        now = asyncio.get_running_loop().time()
        ordered = sorted(group, key=lambda u: _rank(u, now))
        head, tail = ordered[:1], ordered[1:]
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
