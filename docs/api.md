# API

REST API under `/api/v1`, plus Prometheus and health endpoints. The OpenAPI 3
document is served at `/api/v1/openapi.json`.

## Authentication

Log in to obtain a session cookie, or use an API token as a Bearer header.
Tokens are created in the console under **Settings → Access** (or via
`POST /api/v1/auth/tokens`, admin only) and are shown exactly once — only a
keyed digest is stored. A token's scope caps its owner's role, so an admin
can issue a read-only token without creating a second account:

```bash
curl -c jar -X POST http://host:8089/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"name":"admin","password":"…"}'
curl -b jar http://host:8089/api/v1/stats
```

Roles: `viewer` (reads), `editor` (mutations), `admin` (everything). Optional TOTP
2FA; failed logins are rate-limited with exponential backoff.

## Endpoints

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/stats` | viewer | realtime counters |
| GET | `/querylog?qname=&action=&limit=` | viewer | search the query log |
| GET | `/querylog/export` | viewer | NDJSON export |
| GET/POST | `/rules` | viewer/editor | list / add / remove allow-deny |
| POST | `/toggle` | editor | global blocking on/off |
| POST | `/cache/flush` | editor | clear the cache |
| POST | `/gravity/refresh` | editor | re-fetch blocklists |
| GET | `/clients` | viewer | top clients |
| GET | `/system` | viewer | version / uptime / upstreams |
| GET | `/ws` | viewer | WebSocket live stream (see below) |
| GET | `/metrics` | — | Prometheus exposition |
| GET | `/healthz`, `/readyz` | — | liveness / readiness |

## Errors

Every refusal under `/api/v1` is JSON of one shape, `{"error": "…"}`, with the
status carrying the meaning: 400 for a malformed or wrongly typed request, 401
without credentials, 403 for a role too low, 404 for an unknown id or path,
405 for a method the path does not take. The OpenAPI document declares each
operation's security and parameters, and gives it a stable `operationId`.

## Live stream

`/api/v1/ws` sends typed JSON frames: one `hello` (`stats`, `series`, `recent`)
on connect, a `query` per resolved query, and a `stats` snapshot every two
seconds. A client that cannot keep up is not buffered without bound; the server
skips events for it and reports the running count in the `dropped` field of
`stats` frames. The query log keeps every event.
