"""Plugin interface.

A plugin observes/mutates queries via two async hooks:

    on_query(ctx)  -> bool | None    return True to short-circuit (ctx.response set)
    on_answer(ctx) -> None           mutate ctx.response after resolution

Plugins receive the App on `setup()` so they can reach the forwarder, cache,
zones, etc. Exceptions in a plugin are isolated and never break resolution.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..wire import Message


@runtime_checkable
class Resolver(Protocol):
    """What the pipeline needs from whatever resolves a query upstream.

    Both shipped implementations satisfy it (`resolver.forwarder.Forwarder` and
    `resolver.recursive.RecursiveForwarder`), and a plugin may supply its own.

    `note` is how the answering server gets reported: `ctx.upstream` feeds the
    query log, the per-upstream statistics and the warning about an upstream
    attaching records nobody asked for, none of which are actionable without it.
    It is a required parameter rather than a discovered one — the pipeline used
    to read `inspect.signature` to find out whether an implementation accepted
    it, which meant a third-party forwarder that simply forgot it was silently
    demoted to reporting nothing at all.
    """

    async def resolve(self, query: Message, note=None) -> Message:
        ...


class Plugin:
    name: str = "plugin"

    def setup(self, app) -> None:
        """Called once with the App instance before serving."""
        self.app = app

    def configure(self, options: dict) -> None:
        """Called with this plugin's config block."""

    async def on_query(self, ctx) -> bool | None:
        return None

    async def on_answer(self, ctx) -> None:
        return None
