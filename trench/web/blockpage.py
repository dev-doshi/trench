"""Block page: a tiny HTTP server that explains why a site was blocked.

When `filtering.block_mode: custom_ip` points blocked domains at this host, a
browser hitting the blocked site lands here instead of a confusing timeout.
"""
from __future__ import annotations

from aiohttp import web

from ..log import get
from ..version import __version__

log = get("blockpage")

_PAGE = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Blocked</title>
<style>body{{background:#0b0f17;color:#e6edf3;font:16px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}}
.box{{max-width:520px;padding:40px;text-align:center}}
h1{{font-size:54px;margin:0}}h1 b{{color:#5aa6ff}}.s{{color:#f7556a;font-size:20px;font-weight:700;margin:14px 0}}
p{{color:#8b98ad}}code{{color:#e0b341;font-family:ui-monospace,monospace}}</style></head>
<body><div class="box"><h1>🛡 Tre<b>nch</b></h1>
<div class="s">This site is blocked</div>
<p>The domain <code id="host"></code> was blocked by your network's Trench filter
(ads, trackers, malware, or a custom rule).</p>
<p style="margin-top:24px;font-size:13px">Trench {__version__}</p></div>
<script>document.getElementById('host').textContent=location.host||'(this domain)';</script>
</body></html>"""


class BlockPageServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._runner: web.AppRunner | None = None

    async def _handle(self, request: web.Request) -> web.Response:
        return web.Response(text=_PAGE, content_type="text/html", status=200)

    async def start(self) -> None:
        app = web.Application()
        app.router.add_route("GET", "/{tail:.*}", self._handle)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        await web.TCPSite(self._runner, self.host, self.port).start()
        log.info("block page on http://%s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
