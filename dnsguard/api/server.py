"""REST API + WebSocket + static SPA (aiohttp).

Endpoints live under /api/v1. Auth is cookie-session or Bearer token; mutations
require the `editor` role, reads require `viewer`. /metrics, /healthz and the
login endpoint are public.
"""
from __future__ import annotations

import asyncio
import json
import time

from aiohttp import web

from ..log import get
from ..ops import metrics
from ..version import __version__
from .auth import AuthManager

log = get("api")


def _config_writable(path) -> tuple[bool, str]:
    """Can settings actually be saved, and if not, why not — in one sentence.

    Worth probing rather than assuming: the shipped container mounts the config
    as a single read-only file, so the honest answer on a default install is no.
    """
    import os
    from pathlib import Path
    if not path:
        return False, ("This instance was started without a config file, so there "
                       "is nowhere to save changes.")
    p = Path(path)
    if not p.exists():
        return (True, "") if os.access(p.parent, os.W_OK) else (
            False, f"{p.parent} is not writable.")
    if not os.access(p, os.W_OK):
        return False, (f"{p} is read-only. In the shipped container it is bind-mounted "
                       f"with ':ro' — drop that flag to edit settings from here.")
    return True, ""


def _write_config(src, text: str) -> None:
    """Write the config, preferring an atomic replace.

    A rename cannot cross a bind mount, and the container mounts this file
    individually — `os.replace` fails with EBUSY there. So the atomic path is
    tried first and the in-place write is the fallback, rather than the other way
    round: on a normal filesystem a half-written config is never observable.
    """
    from pathlib import Path
    src = Path(src)
    tmp = src.with_suffix(src.suffix + ".tmp")
    try:
        tmp.write_text(text)
        tmp.replace(src)
        return
    except OSError:
        tmp.unlink(missing_ok=True)
    src.write_text(text)
API = "/api/v1"

#: Ceiling on one inbound WebSocket message. The console's own frames are a
#: handful of bytes; this is generous for them and finite for everyone else.
WS_MAX_MSG_BYTES = 64 * 1024


class _NoUpdater(Exception):
    """`updates.mode` is off, so there is no updater to ask. Not an error the
    caller did anything to cause, so the handlers turn it into an explanation
    rather than a 500."""


class APIServer:
    def __init__(self, app, host: str, port: int, *, ssl_context=None):
        self.app = app                      # dnsguard.app.App
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.auth = AuthManager(app.db)
        self.start_ts = time.time()
        self._runner: web.AppRunner | None = None
        self._ws: set[web.WebSocketResponse] = set()
        # Secrets offered for enrolment but not yet proven. Held here rather
        # than written straight to the user row: a secret stored before the
        # operator's authenticator has produced one matching code is a lockout
        # waiting for the next login. Lost on restart, which is the right way
        # for an unfinished enrolment to end.
        self._pending_totp: dict[str, str] = {}
        from ..security.clientaddr import TrustedProxies
        self.trusted = TrustedProxies(
            getattr(app.config.security, "trusted_proxies", ()))

    # ---- lifecycle ----
    async def start(self) -> None:
        await self.auth.ensure_admin(self.app.config.web.admin_password,
                                     data_dir=self.app.config.data_path)
        webapp = web.Application(middlewares=[self._auth_mw, self._headers_mw])
        from ..security.clientaddr import TRUSTED_KEY
        webapp[TRUSTED_KEY] = self.trusted
        self._add_routes(webapp)
        self._runner = web.AppRunner(webapp, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port, ssl_context=self.ssl_context)
        await site.start()
        log.info("admin/API on %s://%s:%d", "https" if self.ssl_context else "http",
                 self.host, self.port)

    async def stop(self) -> None:
        for ws in list(self._ws):
            await ws.close()
        if self._runner is not None:
            await self._runner.cleanup()

    # ---- routing ----
    def _add_routes(self, a: web.Application) -> None:
        r = a.router
        r.add_post(f"{API}/auth/login", self.login)
        r.add_post(f"{API}/auth/logout", self.logout)
        r.add_get(f"{API}/auth/me", self.me)
        r.add_get(f"{API}/auth/tokens", self.tokens_list)
        r.add_post(f"{API}/auth/tokens", self.tokens_create)
        r.add_delete(f"{API}/auth/tokens/{{tid}}", self.tokens_delete)
        r.add_post(f"{API}/auth/totp/enrol", self.totp_enrol)
        r.add_post(f"{API}/auth/totp/confirm", self.totp_confirm)
        r.add_delete(f"{API}/auth/totp", self.totp_disable)
        r.add_get(f"{API}/stats", self.stats)
        r.add_get(f"{API}/querylog", self.querylog)
        r.add_get(f"{API}/querylog/facets", self.querylog_facets)
        r.add_get(f"{API}/querylog/export", self.querylog_export)
        r.add_post(f"{API}/querylog/purge", self.querylog_purge)
        r.add_get(f"{API}/timeseries", self.timeseries)
        r.add_get(f"{API}/analytics", self.analytics)
        r.add_get(f"{API}/privacy", self.privacy)
        r.add_get(f"{API}/rules", self.rules_get)
        r.add_post(f"{API}/rules", self.rules_post)
        r.add_post(f"{API}/toggle", self.toggle)
        r.add_get(f"{API}/explain", self.explain)
        r.add_get(f"{API}/history", self.history)
        r.add_get(f"{API}/notary", self.notary)
        r.add_get(f"{API}/silence", self.silence)
        r.add_get(f"{API}/pause", self.pause_get)
        r.add_post(f"{API}/pause", self.pause_post)
        r.add_get(f"{API}/settings", self.settings_get)
        r.add_put(f"{API}/settings", self.settings_put)
        r.add_post(f"{API}/cache/flush", self.cache_flush)
        r.add_post(f"{API}/gravity/refresh", self.gravity_refresh)
        r.add_get(f"{API}/update", self.update_status)
        r.add_post(f"{API}/update/check", self.update_check)
        r.add_post(f"{API}/update/apply", self.update_apply)
        r.add_post(f"{API}/update/rollback", self.update_rollback)
        r.add_get(f"{API}/clients", self.clients)
        r.add_get(f"{API}/clients/manage", self.clients_list)
        r.add_post(f"{API}/clients/manage", self.clients_create)
        r.add_put(f"{API}/clients/manage/{{cid}}", self.clients_update)
        r.add_delete(f"{API}/clients/manage/{{cid}}", self.clients_delete)
        r.add_get(f"{API}/groups", self.groups)
        r.add_get(f"{API}/services", self.services)
        r.add_post(f"{API}/whatif", self.whatif)
        r.add_get(f"{API}/collateral", self.collateral)
        r.add_get(f"{API}/lists", self.lists_roi)
        r.add_get(f"{API}/list-reviews", self.list_reviews)
        r.add_get(f"{API}/audit", self.audit)
        r.add_get(f"{API}/system", self.system)
        r.add_get(f"{API}/openapi.json", self.openapi)
        r.add_get("/metrics", self.prometheus)
        r.add_get("/healthz", self.healthz)
        r.add_get("/readyz", self.readyz)
        r.add_get(f"{API}/ws", self.websocket)
        # static SPA (built to dnsguard/web/dist). Fallback to index.html.
        from pathlib import Path
        dist = Path(__file__).resolve().parent.parent / "web" / "dist"
        if (dist / "index.html").exists():
            r.add_get("/", self._spa_index)
            r.add_static("/assets", dist / "assets")
            a.router.add_route("GET", "/{tail:.*}", self._spa_index)

    # ---- auth middleware ----
    @web.middleware
    async def _auth_mw(self, request: web.Request, handler):
        token = request.cookies.get("dgsession", "")
        bearer = request.headers.get("Authorization", "")
        user = None
        if token:
            user = self.auth.session_user(token)
        if user is None and bearer.startswith("Bearer "):
            user = await self.auth.token_user(bearer[7:])
        request["user"] = user
        return await handler(request)

    @web.middleware
    async def _headers_mw(self, request: web.Request, handler):
        """Anti-framing and sniffing headers on every response.

        None of these were set anywhere. The session cookie is SameSite=Strict,
        but that is still sent on a top-level framed navigation — so an attacker
        page a logged-in admin visits could frame the console, overlay bait on
        the filtering toggle, and disable network-wide filtering in one click.
        """
        resp = await handler(request)
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
            "object-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            # `ws:`/`wss:` as bare schemes are not scoped to this origin: they
            # permit a socket to anywhere. The console's only socket is its own
            # /api/v1/ws, and 'self' already covers it for both schemes.
            "connect-src 'self'")
        return resp

    def _require(self, request: web.Request, role: str) -> dict:
        user = request.get("user")
        if user is None:
            raise web.HTTPUnauthorized(text="login required")
        if not AuthManager.has_role(user, role):
            raise web.HTTPForbidden(text=f"requires {role}")
        return user

    # ---- auth routes ----
    async def login(self, request: web.Request) -> web.Response:
        body = await _json(request)
        ip = _client_ip(request)
        token = await self.auth.login(body.get("name", ""), body.get("password", ""),
                                      body.get("code", ""), ip)
        if token is None:
            return web.json_response({"error": "invalid credentials"}, status=401)
        resp = web.json_response({"ok": True})
        resp.set_cookie("dgsession", token, httponly=True, samesite="Strict",
                        max_age=8 * 3600, secure=self.ssl_context is not None)
        if self.ssl_context is None and self.host not in ("127.0.0.1", "::1", "localhost"):
            log.warning("admin session issued over plaintext on %s — the cookie and "
                        "password cross the network in the clear; set web.tls or "
                        "bind web.host to 127.0.0.1", self.host)
        return resp

    async def logout(self, request: web.Request) -> web.Response:
        token = request.cookies.get("dgsession", "")
        self.auth.logout(token)
        resp = web.json_response({"ok": True})
        resp.del_cookie("dgsession")
        return resp

    async def me(self, request: web.Request) -> web.Response:
        user = request.get("user")
        totp_on = False
        if user is not None:
            totp_on = bool(await self.auth.totp_secret(user["name"]))
        return web.json_response({"user": user, "totp": totp_on})

    # ---- API tokens ----
    # The console issues a session cookie; a script cannot use one. Tokens are
    # how everything that is not a browser talks to this API — `dnsguard status`
    # and the rest of the CLI's control commands take one — and until this
    # existed there was no way to obtain one at all: the table, the validation
    # path and the CLI flag were all in place around a hole where the minting
    # should have been.
    async def tokens_list(self, request: web.Request) -> web.Response:
        self._require(request, "admin")
        return web.json_response({"tokens": await self.auth.list_api_tokens()})

    async def tokens_create(self, request: web.Request) -> web.Response:
        user = self._require(request, "admin")
        body = await _json(request)
        name = (body.get("name") or "").strip()
        scope = body.get("scope", "viewer")
        days = int(body.get("expires_days") or 0)
        if not name:
            return web.json_response({"error": "name required"}, status=400)
        expires = int(time.time() + days * 86400) if days > 0 else 0
        try:
            raw = await self.auth.create_api_token(user["id"], name, scope, expires)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        await self._audit(request, "token.create", name, scope)
        # The only time the token itself is ever readable. Nothing stores it.
        return web.json_response({"token": raw, "name": name, "scope": scope,
                                  "expires": expires})

    async def tokens_delete(self, request: web.Request) -> web.Response:
        self._require(request, "admin")
        tid = request.match_info["tid"]
        if not await self.auth.revoke_api_token(int(tid)):
            return web.json_response({"error": "not found"}, status=404)
        await self._audit(request, "token.revoke", str(tid))
        return web.json_response({"ok": True})

    # ---- TOTP enrolment ----
    # Verification has always been here; enrolling had no route, so the second
    # factor the README advertises could not be switched on by any supported
    # means. Enrol hands back a secret, confirm proves the operator's
    # authenticator agrees before anything is stored — without that step a
    # mistyped setup locks the account out on the next login.
    async def totp_enrol(self, request: web.Request) -> web.Response:
        user = self._require(request, "admin")
        from ..security import totp
        secret = totp.new_secret()
        self._pending_totp[user["name"]] = secret
        return web.json_response({
            "secret": secret,
            "uri": totp.provisioning_uri(secret, user["name"], issuer="DNSGuard"),
        })

    async def totp_confirm(self, request: web.Request) -> web.Response:
        user = self._require(request, "admin")
        from ..security import totp
        body = await _json(request)
        secret = self._pending_totp.get(user["name"], "")
        if not secret:
            return web.json_response({"error": "start enrolment first"}, status=400)
        if not totp.verify(secret, str(body.get("code", ""))):
            return web.json_response({"error": "that code does not match"}, status=400)
        await self.auth.set_totp(user["name"], secret)
        self._pending_totp.pop(user["name"], None)
        await self._audit(request, "totp.enable", user["name"])
        return web.json_response({"ok": True})

    async def totp_disable(self, request: web.Request) -> web.Response:
        user = self._require(request, "admin")
        await self.auth.set_totp(user["name"], "")
        self._pending_totp.pop(user["name"], None)
        await self._audit(request, "totp.disable", user["name"])
        return web.json_response({"ok": True})

    # ---- data routes ----
    async def stats(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        return web.json_response(self._stats_payload())

    def _stats_payload(self) -> dict:
        snap = self.app.counters.snapshot()
        snap.update({
            "enabled": self.app.pipeline.enabled,
            "blocklist_size": self.app.filter.size,
            "cache_size": self.app.cache.size,
            "cache_stats": self.app.cache.stats,
            "version": __version__,
        })
        return snap

    async def querylog(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        if self.app.querylog is None:
            return web.json_response({"rows": [], "total": 0})
        q = request.query
        f = {"qname": q.get("qname"), "client": q.get("client"), "action": q.get("action"),
             "rcode": q.get("rcode"), "upstream": q.get("upstream"),
             "since": int(q["since"]) if q.get("since") else None,
             "until": int(q["until"]) if q.get("until") else None}
        rows = await self.app.querylog.search(
            **f, limit=min(int(q.get("limit", 100)), 1000), offset=int(q.get("offset", 0)))
        total = await self.app.querylog.search_count(**f)
        return web.json_response({"rows": rows, "total": total})

    async def querylog_facets(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        if self.app.querylog is None:
            return web.json_response({"clients": [], "actions": [], "rcodes": [], "upstreams": []})
        return web.json_response(await self.app.querylog.facets())

    async def querylog_purge(self, request: web.Request) -> web.Response:
        self._require(request, "editor")
        if self.app.querylog is None:
            return web.json_response({"purged": 0})
        n = await self.app.querylog.purge()
        await self._audit(request, "querylog.purge", str(n))
        return web.json_response({"purged": n})

    async def timeseries(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        minutes = min(int(request.query.get("minutes", 60)), self.app.counters.SERIES_BUCKETS)
        return web.json_response({"series": self.app.counters.series(minutes)})

    # column/expression whitelists for /analytics — never interpolate user
    # input into SQL beyond these fixed fragments
    _AN_GROUPS = {"client_ip": "client_ip", "action": "action", "qtype": "qtype",
                  "rcode": "rcode", "upstream": "upstream", "qname": "qname"}
    _AN_BUCKETS = {"minute": 60, "hour": 3600, "day": 86400}
    _AN_METRICS = {"count": "COUNT(*)",
                   "avg_latency": "ROUND(AVG(elapsed_us) / 1000.0, 2)",
                   "max_latency": "ROUND(MAX(elapsed_us) / 1000.0, 2)"}

    async def analytics(self, request: web.Request) -> web.Response:
        """Flexible aggregation over the persisted query log (the Explore UI).

        Params: since/until (µs) · bucket=minute|hour|day|dow_hour|none ·
        group=<whitelist>|none · metric=count|avg_latency|max_latency ·
        qname (substring) · client · action · top (max groups, ≤12).
        Shapes returned: bucketed → {series:[{group,points:[[t,v],…]}]};
        dow_hour → {cells:[[dow,hour,v],…]}; plain group → {rows:[[g,v],…]}.
        """
        self._require(request, "viewer")
        if self.app.querylog is None:
            return web.json_response({"error": "query log disabled"}, status=400)
        q = request.query
        bucket = q.get("bucket", "none")
        group = q.get("group", "none")
        metric = q.get("metric", "count")
        if metric not in self._AN_METRICS or \
           (bucket not in self._AN_BUCKETS and bucket not in ("none", "dow_hour")) or \
           (group != "none" and group not in self._AN_GROUPS):
            return web.json_response({"error": "invalid bucket/group/metric"}, status=400)
        mexpr = self._AN_METRICS[metric]

        where, args = ["1=1"], []
        if q.get("since"):
            where.append("ts >= ?"); args.append(int(q["since"]))
        if q.get("until"):
            where.append("ts <= ?"); args.append(int(q["until"]))
        if q.get("qname"):
            where.append("qname LIKE ?"); args.append(f"%{q['qname']}%")
        if q.get("client"):
            where.append("client_ip = ?"); args.append(q["client"])
        if q.get("action"):
            where.append("action = ?"); args.append(q["action"])
        w = " AND ".join(where)
        top = min(int(q.get("top", 8)), 12)

        gcol = self._AN_GROUPS.get(group)
        if gcol:  # keep only the busiest groups so charts stay legible
            rows = await self.app.db.fetchall(
                f"SELECT {gcol} FROM querylog WHERE {w} GROUP BY {gcol} "
                f"ORDER BY COUNT(*) DESC LIMIT ?", (*args, top))
            keep = [r[0] for r in rows]
            if not keep:
                return web.json_response({"series": [], "rows": [], "cells": []})
            w += f" AND {gcol} IN ({','.join('?' * len(keep))})"
            args = [*args, *keep]

        if bucket == "dow_hour":
            rows = await self.app.db.fetchall(
                "SELECT CAST(strftime('%w', ts/1000000, 'unixepoch') AS INTEGER), "
                "CAST(strftime('%H', ts/1000000, 'unixepoch') AS INTEGER), "
                f"{mexpr} FROM querylog WHERE {w} GROUP BY 1, 2", tuple(args))
            return web.json_response({"cells": [list(r) for r in rows]})
        if bucket == "none":
            if gcol:
                rows = await self.app.db.fetchall(
                    f"SELECT {gcol}, {mexpr} v FROM querylog WHERE {w} "
                    f"GROUP BY {gcol} ORDER BY v DESC", tuple(args))
                return web.json_response({"rows": [list(r) for r in rows]})
            rows = await self.app.db.fetchall(
                f"SELECT {mexpr} FROM querylog WHERE {w}", tuple(args))
            return web.json_response({"rows": [["all", rows[0][0] if rows else 0]]})

        step = self._AN_BUCKETS[bucket]
        bexpr = f"(ts / {step * 1_000_000}) * {step}"
        if gcol:
            rows = await self.app.db.fetchall(
                f"SELECT {bexpr} b, {gcol} g, {mexpr} FROM querylog WHERE {w} "
                f"GROUP BY b, g ORDER BY b", tuple(args))
            series: dict[str, list] = {}
            for b, g, v in rows:
                series.setdefault(str(g), []).append([b, v])
            return web.json_response(
                {"series": [{"group": g, "points": p} for g, p in series.items()]})
        rows = await self.app.db.fetchall(
            f"SELECT {bexpr} b, {mexpr} FROM querylog WHERE {w} GROUP BY b ORDER BY b",
            tuple(args))
        return web.json_response({"series": [{"group": "all", "points": [list(r) for r in rows]}]})

    async def privacy(self, request: web.Request) -> web.Response:
        """What is actually stored, where, and what survives a reboot — legibly."""
        self._require(request, "viewer")
        ql = self.app.querylog
        levels = {
            0: ("Full logging", "Every query stored with client IP, domain, and answer."),
            1: ("Hide clients", "Queries stored, but client IPs are dropped before disk."),
            2: ("Anonymous", "Client IPs and domains are replaced with a salted "
                              "hash before disk, and answers are dropped. Counts "
                              "and repeat visits still add up; the names do not "
                              "survive."),
            3: ("No logging", "Nothing is written to disk; only in-memory live stats exist."),
        }
        level = ql.privacy_level if ql else 3
        name, desc = levels.get(level, levels[3])
        return web.json_response({
            "enabled": ql is not None,
            "level": level,
            "level_name": name,
            "level_description": desc,
            "retention_days": ql.retention_days if ql else 0,
            "stored_count": (await ql.count()) if ql else 0,
            "db_path": str(self.app.config.data_path / self.app.config.querylog.db),
            "survives_reboot": level < 3,
            "levels": [{"level": k, "name": v[0], "description": v[1]} for k, v in levels.items()],
        })

    # StreamResponse, not Response: this one streams the log out rather than
    # buffering it. Response is a subclass, so the wider type is the accurate one.
    async def querylog_export(self, request: web.Request) -> web.StreamResponse:
        self._require(request, "viewer")
        if self.app.querylog is None:
            return web.Response(text="", content_type="application/x-ndjson")
        # Streamed a line at a time. Building the whole export first held the
        # rows, their JSON strings, the joined text and aiohttp's copy of it all
        # at once — one authenticated request was enough to OOM the resolver.
        resp = web.StreamResponse(headers={
            "Content-Type": "application/x-ndjson",
            "Content-Disposition": "attachment; filename=querylog.ndjson"})
        await resp.prepare(request)
        async for line in self.app.querylog.iter_ndjson():
            await resp.write(line.encode() + b"\n")
        await resp.write_eof()
        return resp

    async def rules_get(self, request: web.Request) -> web.Response:
        """Operator-managed rules only. Imported blocklists are reported as a
        count — serialising ~600K gravity domains would be a useless payload."""
        self._require(request, "viewer")
        f = self.app.filter
        deny, allow = f.custom_rules()
        return web.json_response({
            "deny": deny,
            "allow": allow,
            "imported": max(f.size - len(deny), 0),
        })

    async def rules_post(self, request: web.Request) -> web.Response:
        self._require(request, "editor")
        body = await _json(request)
        domain = (body.get("domain") or "").strip().lower()
        action = body.get("action")
        f = self.app.filter
        if not domain or action not in ("deny", "allow", "remove"):
            return web.json_response({"error": "bad request"}, status=400)
        if action == "deny":
            f.add_deny(domain)
            await self._persist_rule(domain, "block")
        elif action == "allow":
            f.add_allow(domain)
            await self._persist_rule(domain, "allow")
        else:
            f.remove_rule(domain)
            await self._unpersist_rule(domain)
        self.app.cache.flush()
        await self._audit(request, f"rule.{action}", domain)
        return web.json_response({"ok": True})

    async def _audit(self, request: web.Request, action: str, target: str = "",
                     detail: str = "") -> None:
        if self.app.db is None:
            return
        user = request.get("user") or {}
        try:
            await self.app.db.execute(
                "INSERT INTO audit(ts, actor, action, target, detail, ip) VALUES(?,?,?,?,?,?)",
                (int(time.time()), user.get("name", ""), action, target, detail,
                 _client_ip(request)))
        except Exception:
            log.exception("audit write failed")

    async def audit(self, request: web.Request) -> web.Response:
        self._require(request, "admin")
        rows = await self.app.db.fetchall(
            "SELECT ts, actor, action, target, ip FROM audit ORDER BY ts DESC LIMIT 200") \
            if self.app.db is not None else []
        return web.json_response({"audit": [dict(r) for r in rows]})

    async def _persist_rule(self, domain: str, kind: str) -> None:
        if self.app.db is not None:
            await self.app.db.execute(
                "INSERT INTO custom_rule(raw, kind, created) VALUES(?,?,?)",
                (domain, kind, int(time.time())))

    async def _unpersist_rule(self, domain: str) -> None:
        if self.app.db is not None:
            await self.app.db.execute("DELETE FROM custom_rule WHERE raw=?", (domain,))

    async def toggle(self, request: web.Request) -> web.Response:
        self._require(request, "editor")
        self.app.pipeline.enabled = not self.app.pipeline.enabled
        await self._audit(request, "toggle", str(self.app.pipeline.enabled))
        return web.json_response({"enabled": self.app.pipeline.enabled})

    async def explain(self, request: web.Request) -> web.Response:
        """Why did this name do what it did? `?name=` plus optional `client=`,
        `type=` and `resolve=1` to try it live."""
        self._require(request, "viewer")
        q = request.query
        name = (q.get("name") or "").strip()
        if not name:
            return web.json_response({"error": "name is required"}, status=400)
        from ..ops.explain import explain as run_explain
        report = await run_explain(self.app, name, q.get("type", "A"),
                                   q.get("client", ""),
                                   resolve=q.get("resolve", "") in ("1", "true", "yes"))
        return web.json_response(report)

    async def history(self, request: web.Request) -> web.Response:
        """What a name has resolved to over time, from this household's own log."""
        self._require(request, "viewer")
        name = (request.query.get("name") or "").strip()
        if not name:
            return web.json_response({"error": "name is required"}, status=400)
        if self.app.querylog is None:
            return web.json_response({"name": name, "history": []})
        try:
            days = int(request.query.get("days", "0"))
        except ValueError:
            days = 0
        since = int((time.time() - days * 86400) * 1_000_000) if days > 0 else None
        rows = await self.app.querylog.history(name, since=since)
        return web.json_response({"name": name, "history": rows})

    async def notary(self, request: web.Request) -> web.Response:
        """Pinned names whose upstreams disagreed, or that moved network."""
        self._require(request, "viewer")
        notary = getattr(self.app, "notary", None)
        if notary is None:
            return web.json_response({"enabled": False, "findings": []})
        return web.json_response({
            "enabled": True,
            "names": notary.names,
            "findings": [f.to_json() for f in reversed(notary.findings)],
        })

    async def silence(self, request: web.Request) -> web.Response:
        """Devices that have stopped asking this resolver anything."""
        self._require(request, "viewer")
        ledger = getattr(self.app, "ledger", None)
        if ledger is None:
            return web.json_response({"enabled": False, "devices": []})
        rows = ledger.report()
        only = request.query.get("status", "")
        if only:
            rows = [r for r in rows if r["status"] == only]
        return web.json_response({"enabled": True, "devices": rows})

    async def pause_get(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        return web.json_response(self.app.pipeline.pause_state())

    async def pause_post(self, request: web.Request) -> web.Response:
        """Suspend filtering for a while, for everyone or for one device.

        `{"seconds": 300}` pauses everything for five minutes;
        `{"seconds": 300, "client": "192.168.1.50"}` pauses that device only;
        `{"seconds": 0}` resumes. Unlike the toggle this expires by itself,
        which is the difference between letting one download through and
        leaving the network unfiltered until somebody notices.
        """
        self._require(request, "editor")
        body = await _json(request)
        try:
            seconds = float(body.get("seconds", 300))
        except (TypeError, ValueError):
            return web.json_response({"error": "seconds must be a number"}, status=400)
        if seconds < 0 or seconds > 86_400:
            return web.json_response({"error": "seconds must be 0..86400"}, status=400)
        client = str(body.get("client", "") or "")
        pipe = self.app.pipeline
        if seconds == 0:
            pipe.resume(client)
            await self._audit(request, "resume", client or "all")
        else:
            pipe.pause(seconds, client)
            await self._audit(request, "pause", f"{client or 'all'} {seconds:g}s")
        return web.json_response(pipe.pause_state())

    # ---- settings ----
    async def settings_get(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        from . import settings as st
        body = st.describe(self.app.config)
        path = self.app._config_path
        body["config_path"] = str(path or "")
        body["writable"], body["why"] = _config_writable(path)
        return web.json_response(body)

    async def settings_put(self, request: web.Request) -> web.Response:
        """Apply a settings change: validate, persist to the config file, reload.

        The file stays the source of truth — this writes YAML and then reloads
        it, so a change made here is identical to one made by hand, and anything
        already in the file that this form does not cover is preserved.
        """
        self._require(request, "admin")
        from . import settings as st
        body = await request.json()
        changes = body.get("changes") or {}
        if not isinstance(changes, dict) or not changes:
            raise web.HTTPBadRequest(text="no changes")

        path = self.app._config_path
        ok, why = _config_writable(path)
        if not ok:
            raise web.HTTPBadRequest(text=why)

        from pathlib import Path

        import yaml

        from ..config import Config
        src = Path(path)
        try:
            tree = yaml.safe_load(src.read_text()) or {} if src.exists() else {}
        except Exception as e:
            raise web.HTTPBadRequest(text=f"the config file could not be read: {e}") from e

        try:
            for key, raw in changes.items():
                st.merge(tree, key, st.coerce(key, raw))
        except KeyError as e:
            raise web.HTTPBadRequest(text=f"unknown setting {e}") from e
        except (ValueError, TypeError) as e:
            raise web.HTTPBadRequest(text=str(e)) from e

        # Validate before writing: a config file that fails to parse would take
        # the resolver down on its next start, from a form submission.
        try:
            Config.model_validate(tree)
        except Exception as e:
            raise web.HTTPBadRequest(text=f"rejected: {e}") from e

        text = yaml.safe_dump(tree, sort_keys=False, allow_unicode=True)
        try:
            _write_config(src, text)
        except OSError as e:
            raise web.HTTPBadRequest(
                text=f"the config file could not be written: {e}") from e
        await self._audit(request, "settings.write", ",".join(sorted(changes)))
        try:
            # Apply, do not "reload": a full reload re-downloads and recompiles
            # every blocklist, which is several seconds of the interface sitting
            # frozen because somebody changed the log level. Passing the changed
            # paths means only the appliers those settings name actually run —
            # and `filtering.sources` is the one that rebuilds the lists, in the
            # background, so this request is not holding the browser open for it.
            await self.app.apply_config(list(changes))
        except Exception:
            log.exception("settings saved but could not be applied")
            return web.json_response({"ok": True, "reloaded": False,
                                      "restart": st.needs_restart(list(changes))})
        return web.json_response({"ok": True, "reloaded": True,
                                  "restart": st.needs_restart(list(changes))})

    async def cache_flush(self, request: web.Request) -> web.Response:
        self._require(request, "editor")
        n = self.app.cache.flush()
        await self._audit(request, "cache.flush", str(n))
        return web.json_response({"flushed": n})

    async def gravity_refresh(self, request: web.Request) -> web.Response:
        self._require(request, "editor")
        asyncio.ensure_future(self.app.refresh_blocklists())
        await self._audit(request, "gravity.refresh")
        return web.json_response({"ok": True})

    # ── updates ─────────────────────────────────────────────────────────────
    # Reading is a viewer's business; installing code on the box is an admin's,
    # and is deliberately a heavier permission than editing a setting.
    def _updater(self):
        up = getattr(self.app, "updater", None)
        if up is None:
            raise _NoUpdater
        return up

    async def update_status(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        try:
            return web.json_response(self._updater().status())
        except _NoUpdater:
            return web.json_response({"mode": self.app.config.updates.mode,
                                      "current_version": __version__,
                                      "update_available": False,
                                      "why_not": "update checking is off"})

    async def update_check(self, request: web.Request) -> web.Response:
        """Check now. Never installs anything, whatever the mode is."""
        self._require(request, "editor")
        try:
            updater = self._updater()
        except _NoUpdater:
            return web.json_response({"error": "update checking is off"}, status=409)
        await updater.check()
        await self._audit(request, "update.check", updater.state.latest_version)
        return web.json_response(updater.status())

    async def update_apply(self, request: web.Request) -> web.Response:
        """Install a release. Long-running on purpose: the caller waits for the
        verdict rather than being told 'started' and having to guess."""
        self._require(request, "admin")
        try:
            updater = self._updater()
        except _NoUpdater:
            return web.json_response({"error": "update checking is off"}, status=409)
        body = await _json(request)
        version = (body.get("version") or "").strip() or None
        from ..ops.update import UpdateError
        try:
            status = await updater.apply(version=version)
        except UpdateError as e:
            await self._audit(request, "update.apply.failed", version or "", str(e))
            return web.json_response({"error": str(e)}, status=409)
        await self._audit(request, "update.apply", status.get("applied_version", ""),
                          f"from {status.get('previous_version', '')}")
        return web.json_response(status)

    async def update_rollback(self, request: web.Request) -> web.Response:
        self._require(request, "admin")
        try:
            updater = self._updater()
        except _NoUpdater:
            return web.json_response({"error": "update checking is off"}, status=409)
        from ..ops.update import UpdateError
        try:
            status = await updater.rollback()
        except UpdateError as e:
            return web.json_response({"error": str(e)}, status=409)
        await self._audit(request, "update.rollback", status.get("applied_version", ""))
        return web.json_response(status)

    async def clients(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        top = self.app.counters.clients.most_common(50)
        return web.json_response({"top_clients": top})

    async def whatif(self, request: web.Request) -> web.Response:
        """Dry-run a proposed rule change against the recorded query history:
        which domains would flip block/allow, weighted by how often they were
        actually queried. Nothing is applied."""
        self._require(request, "viewer")          # read-only: it changes nothing
        if self.app.db is None:
            return web.json_response({"error": "no query log"}, status=503)
        body = await _json(request)
        from ..ops.whatif import compile_delta, whatif_from_querylog
        delta = compile_delta(deny=body.get("deny") or [],
                              allow=body.get("allow") or [],
                              list_text=body.get("list_text") or "")
        result = await whatif_from_querylog(
            self.app.db, self.app.filter, delta,
            hours=min(float(body.get("hours", 24)), 24 * 30),
            limit=min(int(body.get("limit", 5000)), 50_000))
        return web.json_response(result.to_json())

    async def collateral(self, request: web.Request) -> web.Response:
        """Blocked domains that client behaviour suggests are breaking a real
        service. Read-only: it reports suspects with evidence and never edits
        policy — auto-unblocking on observed traffic would be exploitable."""
        self._require(request, "viewer")
        if self.app.querylog is None:
            return web.json_response({"findings": [], "reason": "query log disabled"})
        from ..analyze import collateral_from_querylog
        hours = min(float(request.query.get("hours", 24)), 24 * 30)
        _, allowed = self.app.filter.custom_rules()
        findings = await collateral_from_querylog(
            self.app.querylog, hours=hours, exclude=set(allowed),
            limit=min(int(request.query.get("limit", 25)), 200))
        return web.json_response({
            "findings": [f.to_json() for f in findings],
            "hours": hours,
            "high": sum(1 for f in findings if f.severity == "high"),
        })

    async def lists_roi(self, request: web.Request) -> web.Response:
        """What each blocklist contributes versus what it costs to hold."""
        self._require(request, "viewer")
        from ..analyze import list_effectiveness, lists_from_querylog
        hours = min(float(request.query.get("hours", 24)), 24 * 30)
        hints = tuple(self.app.config.filtering.protective_sources)
        if self.app.querylog is None:
            stats, observed = list_effectiveness(self.app.filter, [], protective_hints=hints), 0.0
        else:
            stats, observed = await lists_from_querylog(
                self.app.filter, self.app.querylog, hours=hours, protective_hints=hints)
        return web.json_response({
            "lists": [s.to_json() for s in stats],
            "hours": hours,
            "observed_hours": observed,
            "total_domains": self.app.filter.size,
            "est_total_mb": round(sum(s.est_bytes for s in stats) / 1_048_576, 1),
            "dead_weight_mb": round(
                sum(s.est_bytes for s in stats if s.verdict == "dead weight") / 1_048_576, 1),
            "protective_mb": round(
                sum(s.est_bytes for s in stats if s.protective) / 1_048_576, 1),
        })

    async def list_reviews(self, request: web.Request) -> web.Response:
        """History of blocklist updates and what each one changed.

        A list update is normally invisible; this is the record of what the last
        few actually decided differently for this network.
        """
        self._require(request, "viewer")
        limit = min(int(request.query.get("limit", 20)), 200)
        if self.app.db is None:
            return web.json_response({"reviews": []})
        rows = await self.app.db.fetchall(
            "SELECT ts, domains_before, domains_after, high_risk, detail"
            "  FROM list_review ORDER BY ts DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            try:
                detail = json.loads(r["detail"])
            except (TypeError, ValueError):
                continue   # unreadable row is not worth failing the request over
            detail["ts"] = r["ts"]
            out.append(detail)
        return web.json_response({"reviews": out})

    # ---- clients CRUD (DB-managed, applied live) ----
    _IDENT_TYPES = ("ip", "cidr", "mac", "clientid", "token")

    async def clients_list(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        rows = await self.app.db.fetchall(
            "SELECT id, ident, ident_type, name, comment, policy FROM client ORDER BY id")
        return web.json_response({"clients": [dict(r) for r in rows]})

    async def clients_create(self, request: web.Request) -> web.Response:
        self._require(request, "editor")
        body = await _json(request)
        ident = (body.get("ident") or "").strip()
        itype = body.get("ident_type", "ip")
        if not ident or itype not in self._IDENT_TYPES:
            return web.json_response({"error": "ident and valid ident_type required"}, status=400)
        policy = json.dumps(body.get("policy") or {})
        await self.app.db.execute(
            "INSERT INTO client(ident, ident_type, name, comment, policy) VALUES(?,?,?,?,?)",
            (ident, itype, body.get("name", ""), body.get("comment", ""), policy))
        await self.app.reload_clients()
        await self._audit(request, "client.create", ident)
        return web.json_response({"ok": True})

    async def clients_update(self, request: web.Request) -> web.Response:
        self._require(request, "editor")
        cid = request.match_info["cid"]
        body = await _json(request)
        row = await self.app.db.fetchone("SELECT id FROM client WHERE id=?", (cid,))
        if row is None:
            return web.json_response({"error": "not found"}, status=404)
        if body.get("ident_type") not in (None, *self._IDENT_TYPES):
            return web.json_response({"error": "invalid ident_type"}, status=400)
        fields, params = [], []
        for col in ("ident", "ident_type", "name", "comment"):
            if col in body:
                fields.append(f"{col}=?"); params.append(body[col])
        if "policy" in body:
            fields.append("policy=?"); params.append(json.dumps(body["policy"]))
        if fields:
            params.append(cid)
            await self.app.db.execute(f"UPDATE client SET {', '.join(fields)} WHERE id=?", params)
            await self.app.reload_clients()
        await self._audit(request, "client.update", str(cid))
        return web.json_response({"ok": True})

    async def clients_delete(self, request: web.Request) -> web.Response:
        self._require(request, "editor")
        cid = request.match_info["cid"]
        await self.app.db.execute("DELETE FROM client WHERE id=?", (cid,))
        await self.app.reload_clients()
        await self._audit(request, "client.delete", str(cid))
        return web.json_response({"ok": True})

    # ---- groups CRUD ----
    async def services(self, request: web.Request) -> web.Response:
        """The blocked-services catalogue: ids, categories and domain counts.

        The console cannot offer "block TikTok for this device" without knowing
        what the ids are, and the categories existed with nothing able to read
        them.
        """
        self._require(request, "viewer")
        from ..filter.services import CATEGORIES
        table = self.app.services.table if self.app.services is not None else {}
        rows = [{"id": sid, "category": CATEGORIES.get(sid, "other"),
                 "domains": len(domains)}
                for sid, domains in sorted(table.items())]
        return web.json_response({"services": rows})

    async def groups(self, request: web.Request) -> web.Response:
        """The filtering groups that actually decide verdicts.

        Read-only, and derived from what the pipeline is running rather than
        from a table: this used to be create/list/delete over a `group` table no
        verdict ever consulted, so a group made here changed nothing. Groups are
        declared in `filtering.groups` and enforced per client; what the console
        needs is to see them, including whether their lists compiled.
        """
        self._require(request, "viewer")
        pipe = self.app.pipeline
        configured = self.app.config.filtering.groups or {}
        members: dict[str, list[str]] = {}
        for c in self.app.config.clients:
            if c.group:
                members.setdefault(c.group, []).append(c.name or c.ident)
        out = []
        for name, spec in configured.items():
            live = pipe.group_filters.get(name)
            out.append({
                "name": name,
                "inherit": spec.inherit,
                "sources": len(spec.sources),
                "rules": getattr(getattr(live, "own", None), "size", 0),
                "compiled": live is not None,
                "clients": sorted(members.get(name, [])),
            })
        return web.json_response({"groups": out})

    async def system(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        return web.json_response({
            "version": __version__,
            "uptime": int(time.time() - self.start_ts),
            "upstream": self.app.config.upstream.servers,
            "mode": self.app.config.upstream.mode,
        })

    async def openapi(self, request: web.Request) -> web.Response:
        return web.json_response(_OPENAPI)

    # ---- ops ----
    async def prometheus(self, request: web.Request) -> web.Response:
        text = metrics.render(self.app.counters, self.app.cache, self.app.filter.size,
                              getattr(self.app, "fast", None), self.app.pipeline)
        return web.Response(text=text, content_type="text/plain")

    async def healthz(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def readyz(self, request: web.Request) -> web.Response:
        ready = self.app.filter is not None
        return web.json_response({"ready": ready}, status=200 if ready else 503)

    async def websocket(self, request: web.Request) -> web.WebSocketResponse:
        """Multiplexed live channel: an initial snapshot, per-query events as they
        happen, and a stats/series refresh every 2s — all typed JSON frames."""
        from aiohttp import WSMsgType
        # Gate before the upgrade: this feed carries client IPs and queried
        # domains straight out of the in-memory ring, so it needs at least the
        # same role as the REST routes that serve the same data.
        self._require(request, "viewer")
        # Bound what one client may buffer here. `max_msg_size=0` disables
        # aiohttp's reassembly limit entirely, so a viewer — the lowest role
        # there is — could stream unbounded continuation frames into the primary
        # worker, which is the same process as the resolver. Nothing this
        # console sends upstream is larger than a control frame.
        ws = web.WebSocketResponse(heartbeat=30, max_msg_size=WS_MAX_MSG_BYTES)
        await ws.prepare(request)
        self._ws.add(ws)
        loop = asyncio.get_running_loop()
        live: asyncio.Queue = asyncio.Queue(maxsize=2000)

        def on_event(ev: dict) -> None:            # called from the resolve path
            try:
                live.put_nowait(ev)
            except asyncio.QueueFull:
                pass
        self.app.counters.subscribe(on_event)
        try:
            # 1) hydrate: current stats + the recent ring so the feed isn't empty
            await ws.send_str(json.dumps({"type": "hello", "data": {
                "stats": self._stats_payload(),
                "series": self.app.counters.series(60),
                "recent": self.app.counters.recent_events(200),
            }}))
            last_stats = loop.time()
            while not ws.closed:
                try:
                    ev = await asyncio.wait_for(live.get(), timeout=0.5)
                    await ws.send_str(json.dumps({"type": "query", "data": ev}))
                except TimeoutError:
                    pass
                # detect client close without blocking the stream
                try:
                    msg = await asyncio.wait_for(ws.receive(), timeout=0.001)
                    if msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.ERROR):
                        break
                except TimeoutError:
                    pass
                if loop.time() - last_stats >= 2.0:
                    await ws.send_str(json.dumps({"type": "stats", "data": self._stats_payload(),
                                                  "series": self.app.counters.series(60)}))
                    last_stats = loop.time()
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        finally:
            self.app.counters.unsubscribe(on_event)
            self._ws.discard(ws)
        return ws

    async def _spa_index(self, request: web.Request) -> web.Response:
        from pathlib import Path
        index = Path(__file__).resolve().parent.parent / "web" / "dist" / "index.html"
        return web.FileResponse(index)


async def _json(request: web.Request) -> dict:
    try:
        return await request.json()
    except Exception:
        return {}


def _client_ip(request: web.Request) -> str:
    """The requesting address, trusting X-Forwarded-For only from a configured
    proxy. This value keys the login-failure counter, so believing the header
    unconditionally let one client rotate it per attempt and never trip the
    lockout at all."""
    from ..security.clientaddr import client_ip
    return client_ip(request)


_OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "DNSGuard API", "version": __version__},
    "paths": {
        f"{API}/stats": {"get": {"summary": "Realtime stats", "responses": {"200": {"description": "ok"}}}},
        f"{API}/querylog": {"get": {"summary": "Search the query log"}},
        f"{API}/rules": {"get": {"summary": "List allow/deny rules"},
                         "post": {"summary": "Add/remove an allow/deny rule"}},
        f"{API}/toggle": {"post": {"summary": "Toggle global blocking"}},
        f"{API}/notary": {
            "get": {"summary": "Quorum findings for the pinned names"}},
        f"{API}/history": {
            "get": {"summary": "What a name has resolved to over time"}},
        f"{API}/services": {
            "get": {"summary": "Blocked-services catalogue by category"}},
        f"{API}/groups": {
            "get": {"summary": "Filtering groups in force, and their members"}},
        f"{API}/explain": {
            "get": {"summary": "Explain what this resolver did with a name"}},
        f"{API}/silence": {
            "get": {"summary": "Devices that stopped querying this resolver"}},
        f"{API}/pause": {
            "get": {"summary": "Current pause state"},
            "post": {"summary": "Pause filtering for N seconds (optionally one client)"},
        },
        f"{API}/auth/tokens": {
            "get": {"summary": "List API tokens (admin)"},
            "post": {"summary": "Create an API token; returned once (admin)"}},
        f"{API}/auth/totp/enrol": {"post": {"summary": "Begin TOTP enrolment (admin)"}},
        f"{API}/auth/totp/confirm": {"post": {"summary": "Confirm and enable TOTP (admin)"}},
        f"{API}/gravity/refresh": {"post": {"summary": "Refresh blocklists"}},
        "/metrics": {"get": {"summary": "Prometheus metrics"}},
    },
}
