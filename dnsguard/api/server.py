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

    # ---- lifecycle ----
    async def start(self) -> None:
        await self.auth.ensure_admin(self.app.config.web.admin_password)
        webapp = web.Application(middlewares=[self._auth_mw])
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
        r.add_get(f"{API}/settings", self.settings_get)
        r.add_put(f"{API}/settings", self.settings_put)
        r.add_post(f"{API}/cache/flush", self.cache_flush)
        r.add_post(f"{API}/gravity/refresh", self.gravity_refresh)
        r.add_get(f"{API}/clients", self.clients)
        r.add_get(f"{API}/clients/manage", self.clients_list)
        r.add_post(f"{API}/clients/manage", self.clients_create)
        r.add_put(f"{API}/clients/manage/{{cid}}", self.clients_update)
        r.add_delete(f"{API}/clients/manage/{{cid}}", self.clients_delete)
        r.add_get(f"{API}/groups", self.groups_list)
        r.add_post(f"{API}/groups", self.groups_create)
        r.add_delete(f"{API}/groups/{{gid}}", self.groups_delete)
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
        return resp

    async def logout(self, request: web.Request) -> web.Response:
        token = request.cookies.get("dgsession", "")
        self.auth.logout(token)
        resp = web.json_response({"ok": True})
        resp.del_cookie("dgsession")
        return resp

    async def me(self, request: web.Request) -> web.Response:
        return web.json_response({"user": request.get("user")})

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
            2: ("Anonymous", "Client IPs and domains are hashed before disk."),
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

    async def querylog_export(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        if self.app.querylog is None:
            return web.Response(text="", content_type="application/x-ndjson")
        data = await self.app.querylog.export_ndjson()
        return web.Response(text=data, content_type="application/x-ndjson",
                            headers={"Content-Disposition": "attachment; filename=querylog.ndjson"})

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
            # frozen because somebody changed the log level. Lists are only
            # refetched when the list of sources is itself what changed.
            self.app.apply_config()
            if "filtering.sources" in changes:
                asyncio.ensure_future(self.app.refresh_blocklists())
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
    async def groups_list(self, request: web.Request) -> web.Response:
        self._require(request, "viewer")
        rows = await self.app.db.fetchall(
            'SELECT id, name, enabled, comment FROM "group" ORDER BY id')
        return web.json_response({"groups": [dict(r) for r in rows]})

    async def groups_create(self, request: web.Request) -> web.Response:
        self._require(request, "editor")
        body = await _json(request)
        name = (body.get("name") or "").strip()
        if not name:
            return web.json_response({"error": "name required"}, status=400)
        try:
            await self.app.db.execute(
                'INSERT INTO "group"(name, enabled, comment) VALUES(?,?,?)',
                (name, int(body.get("enabled", True)), body.get("comment", "")))
        except Exception:
            return web.json_response({"error": "group exists"}, status=409)
        await self._audit(request, "group.create", name)
        return web.json_response({"ok": True})

    async def groups_delete(self, request: web.Request) -> web.Response:
        self._require(request, "editor")
        gid = request.match_info["gid"]
        await self.app.db.execute('DELETE FROM "group" WHERE id=?', (gid,))
        await self._audit(request, "group.delete", str(gid))
        return web.json_response({"ok": True})

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
                              getattr(self.app, "fast", None))
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
        ws = web.WebSocketResponse(heartbeat=30, max_msg_size=0)
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
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    peer = request.transport.get_extra_info("peername") if request.transport else None
    return peer[0] if peer else "?"


_OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "DNSGuard API", "version": __version__},
    "paths": {
        f"{API}/stats": {"get": {"summary": "Realtime stats", "responses": {"200": {"description": "ok"}}}},
        f"{API}/querylog": {"get": {"summary": "Search the query log"}},
        f"{API}/rules": {"get": {"summary": "List allow/deny rules"},
                         "post": {"summary": "Add/remove an allow/deny rule"}},
        f"{API}/toggle": {"post": {"summary": "Toggle global blocking"}},
        f"{API}/gravity/refresh": {"post": {"summary": "Refresh blocklists"}},
        "/metrics": {"get": {"summary": "Prometheus metrics"}},
    },
}
