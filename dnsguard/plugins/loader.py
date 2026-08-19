"""Discover, configure, and run plugins. Builtins are referenced by short name;
external plugins by dotted path 'package.module:ClassName'."""
from __future__ import annotations

import importlib

from ..log import get
from .api import Plugin

log = get("plugins")

_BUILTINS = {
    "dns64": "dnsguard.plugins.builtin.dns64:Dns64Plugin",
    "block_tld": "dnsguard.plugins.builtin.block_tld:BlockTldPlugin",
}


def _load_class(ref: str) -> type[Plugin]:
    ref = _BUILTINS.get(ref, ref)
    module, _, cls = ref.partition(":")
    mod = importlib.import_module(module)
    return getattr(mod, cls)


class PluginManager:
    def __init__(self) -> None:
        self.plugins: list[Plugin] = []

    @classmethod
    def from_config(cls, app, specs: list) -> PluginManager:
        mgr = cls()
        for spec in specs:
            name = spec if isinstance(spec, str) else spec.get("name", "")
            options = {} if isinstance(spec, str) else spec.get("options", {})
            try:
                klass = _load_class(name)
                plugin = klass()
                plugin.setup(app)
                plugin.configure(options)
                mgr.plugins.append(plugin)
                log.info("loaded plugin %s", getattr(plugin, "name", name))
            except Exception:
                log.exception("failed to load plugin %s", name)
        return mgr

    @property
    def active(self) -> bool:
        return bool(self.plugins)

    async def on_query(self, ctx) -> bool:
        for p in self.plugins:
            try:
                if await p.on_query(ctx):
                    return True
            except Exception:
                log.exception("plugin %s on_query error", p.name)
        return False

    async def on_answer(self, ctx) -> None:
        for p in self.plugins:
            try:
                await p.on_answer(ctx)
            except Exception:
                log.exception("plugin %s on_answer error", p.name)
