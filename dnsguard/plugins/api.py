"""Plugin interface.

A plugin observes/mutates queries via two async hooks:

    on_query(ctx)  -> bool | None    return True to short-circuit (ctx.response set)
    on_answer(ctx) -> None           mutate ctx.response after resolution

Plugins receive the App on `setup()` so they can reach the forwarder, cache,
zones, etc. Exceptions in a plugin are isolated and never break resolution.
"""
from __future__ import annotations


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
