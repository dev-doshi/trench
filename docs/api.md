# API

REST API under `/api/v1`, plus Prometheus and health endpoints. The OpenAPI 3
document is served at `/api/v1/openapi.json`.

## Authentication

Log in to obtain a session cookie, or use an API token as a Bearer header:

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
| GET | `/ws` | — | WebSocket live stats stream |
| GET | `/metrics` | — | Prometheus exposition |
| GET | `/healthz`, `/readyz` | — | liveness / readiness |
