"""Block entire TLDs (e.g. .zip, .mov, .xyz) — example of an on_query plugin."""
from __future__ import annotations

from ...wire.rrtypes import Rcode
from ..api import Plugin


class BlockTldPlugin(Plugin):
    name = "block_tld"

    def configure(self, options: dict) -> None:
        self.tlds = {t.strip(".").lower() for t in options.get("tlds", [])}

    async def on_query(self, ctx) -> bool | None:
        labels = ctx.qname.rstrip(".").lower().split(".")
        if labels and labels[-1] in self.tlds:
            ctx.response = ctx.query.reply(Rcode.NXDOMAIN)
            ctx.action = "blocked"
            ctx.reason = f"TLD .{labels[-1]} blocked"
            ctx.source = "block_tld"
            return True
        return None
