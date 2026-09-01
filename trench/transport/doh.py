"""DNS-over-HTTPS (RFC 8484) + JSON API (Google/Cloudflare-compatible).

Endpoints (path configurable, default /dns-query):
    GET  ?dns=<base64url>                      application/dns-message
    POST  body=<wire>                          application/dns-message
    GET  ?name=&type=&do=&cd=  (Accept json)   application/dns-json

ClientID is taken from a trailing path segment (/dns-query/<token>) for P4
per-client policy over encrypted transports; client IP honors X-Forwarded-For.
"""
from __future__ import annotations

import base64
from pathlib import Path
from typing import TYPE_CHECKING

from aiohttp import web

from ..log import get
from ..wire import Class, Message, Question, Type
from ..wire.edns import Edns
from ..wire.name import Name
from ..wire.rrtypes import type_from_text
from .base import Frontend, apply_padding

if TYPE_CHECKING:
    # Type-only. A transport is handed a pipeline; it does not need the
    # engine package at import time, and importing it for real closes a
    # cycle (engine -> resolver -> transport -> engine) that forces the
    # query path to keep every module lazily imported to break it.
    from ..engine import Pipeline

log = get("doh")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _client_ip(request: web.Request) -> str:
    """The querying client's address, trusting X-Forwarded-For only from a
    configured proxy. This value selects the client's filtering policy, its
    rate-limit bucket and the ECS subnet sent upstream, so an unvalidated
    header let a filtered device inherit an unfiltered device's policy."""
    from ..security.clientaddr import client_ip
    return client_ip(request)


def message_to_json(msg: Message) -> dict:
    def rrs(section):
        out = []
        for rr in section:
            if rr.rtype == Type.OPT:
                continue
            out.append({"name": rr.name.to_text(), "type": int(rr.rtype),
                        "TTL": rr.ttl, "data": rr.rdata.to_text()})
        return out
    return {
        "Status": msg.rcode,
        "TC": msg.tc, "RD": msg.rd, "RA": msg.ra, "AD": msg.ad, "CD": msg.cd,
        "Question": [{"name": q.name.to_text(), "type": int(q.rtype)} for q in msg.questions],
        "Answer": rrs(msg.answers),
        "Authority": rrs(msg.authority),
    }


class DoHServer(Frontend):
    proto = "https"

    def __init__(self, pipeline: Pipeline, host: str, port: int, path: str = "/dns-query",
                 *, tls: bool = False, cert: str | None = None, key: str | None = None,
                 data_dir: Path | None = None):
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self.path = path.rstrip("/")
        self._ssl = None
        if tls:
            from ..security.tls import server_ssl_context
            self._ssl = server_ssl_context(cert, key, data_dir=data_dir or Path("./data"),
                                           alpn=["h2", "http/1.1"], hostnames=[host, "localhost"])
        self._runner: web.AppRunner | None = None
        from ..security.clientaddr import TrustedProxies
        sec = getattr(getattr(pipeline, "config", None), "security", None)
        self.trusted = TrustedProxies(getattr(sec, "trusted_proxies", ()))

    def _build_app(self) -> web.Application:
        app = web.Application()
        from ..security.clientaddr import TRUSTED_KEY
        app[TRUSTED_KEY] = self.trusted
        app.router.add_get(self.path, self._handle)
        app.router.add_post(self.path, self._handle)
        app.router.add_get(self.path + "/{clientid}", self._handle)
        app.router.add_post(self.path + "/{clientid}", self._handle)
        return app

    async def _handle(self, request: web.Request) -> web.Response:
        client_ip = _client_ip(request)
        client_id = request.match_info.get("clientid", "")
        # JSON API
        if request.method == "GET" and "name" in request.query:
            return await self._json(request, client_ip, client_id)
        # wire API
        if request.method == "GET":
            dns_param = request.query.get("dns")
            if not dns_param:
                return web.Response(status=400, text="missing ?dns")
            try:
                data = _b64url_decode(dns_param)
            except Exception:
                return web.Response(status=400, text="bad base64url")
        else:
            if request.headers.get("Content-Type") != "application/dns-message":
                return web.Response(status=415, text="expected application/dns-message")
            data = await request.read()

        resp = await self._resolve(data, client_ip, client_id)
        if resp is None:
            return web.Response(status=400, text="malformed query")
        body = resp.to_wire()
        ttl = resp.min_ttl() or 0
        return web.Response(body=body, content_type="application/dns-message",
                            headers={"Cache-Control": f"max-age={ttl}"})

    async def _json(self, request: web.Request, client_ip: str, client_id: str) -> web.Response:
        name = request.query["name"]
        qtype = request.query.get("type", "A")
        try:
            rtype = int(qtype) if qtype.isdigit() else type_from_text(qtype)
        except Exception:
            return web.json_response({"error": "bad type"}, status=400)
        q = Message(id=0)
        q.set_flag(0x0100, True)  # RD
        q.questions.append(Question(Name.from_text(name), rtype, Class.IN))
        q.edns = Edns(udp_size=1232)
        q.edns.do = request.query.get("do", "").lower() in ("1", "true")
        if request.query.get("cd", "").lower() in ("1", "true"):
            q.set_flag(0x0010, True)
        resp = await self.pipeline.resolve(q, client_ip, "https", client_id)
        return web.json_response(message_to_json(resp),
                                 content_type="application/dns-json")

    async def _resolve(self, data: bytes, client_ip: str, client_id: str) -> Message | None:
        try:
            query = Message.parse(data)
        except Exception:
            return None
        resp = await self.pipeline.resolve(query, client_ip, "https", client_id)
        if query.edns is not None:
            apply_padding(resp)
        return resp

    async def start(self) -> None:
        self._runner = web.AppRunner(self._build_app(), access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port, ssl_context=self._ssl)
        await site.start()
        log.info("DoH listening on %s:%d%s (tls=%s)", self.host, self.port, self.path,
                 self._ssl is not None)

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
