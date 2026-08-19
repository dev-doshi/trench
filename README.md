# DNSGuard

[![CI](https://github.com/dev-doshi/dnsguard/actions/workflows/ci.yml/badge.svg)](https://github.com/dev-doshi/dnsguard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/dnsguard)](https://pypi.org/project/dnsguard/)
[![Python](https://img.shields.io/pypi/pyversions/dnsguard)](https://pypi.org/project/dnsguard/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**[Documentation](https://dev-doshi.github.io/dnsguard/)** ·
[Installation](https://dev-doshi.github.io/dnsguard/installation/) ·
[Security](https://dev-doshi.github.io/dnsguard/security/) ·
[Changelog](CHANGELOG.md)

A self-hosted DNS server in **pure Python** (asyncio): an ad/tracker
**sinkhole**, a validating **recursive resolver**, an **authoritative** server with
**online DNSSEC signing**, and an integrated (opt-in) **DHCP** server — a superset of
PiHole, AdGuard Home, and Technitium.

```
            ┌──────── transports in ─────────┐        ┌──── resolution ────┐
 clients ──▶│ Do53  DoT  DoH  DoQ  DoH3       │──▶ pipeline ──▶ forward / recursive
            └────────────────────────────────┘        │     DNSSEC validate
                      │ filter · clients · safe-search │     cache (serve-stale)
                      │ services · safe-browse · zones │
                      ▼                                 ▼
                 SQLite query log              authoritative + DNSSEC sign
                 Prometheus /metrics           DHCP (default-off)
                 admin SPA + REST/WS API       plugins (dns64, …)
```

## Highlights

- **Every transport, in and out:** Do53 (UDP/TCP), DoT, DoH (RFC 8484 + JSON API),
  DoQ, DoH3. Upstreams over plain/TCP/DoT/DoH/DoQ with per-domain routing and
  parallel / fastest / sequential strategies.
- **Filtering engine:** Adblock-DNS syntax (`||d^`, `@@`, `$important`, `$badfilter`,
  `$dnstype`, `$denyallow`, `$dnsrewrite`, `$ctag/$client`), regex, hosts, dnsmasq,
  RPZ, and CNAME-cloaking inspection.
- **Per-client policy:** identify by IP / CIDR / MAC / ClientID; groups, tags,
  blocked-services (scheduled), forced safe-search, safe-browsing & parental controls.
- **Recursive resolver:** iterative from the root with QNAME minimization, plus
  **DNSSEC validation** (RSA / ECDSA P-256/P-384 / Ed25519 / Ed448).
- **Authoritative + DNSSEC signing:** zones, all common RR types, BIND zonefile
  import, online signing (RRSIG / NSEC / DNSKEY / DS).
- **Cache:** LRU + negative + serve-stale (RFC 8767) + prefetch, ECS/DO-aware keys.
- **Platform:** SQLite query log (search / export / retention / privacy levels),
  REST `/api/v1` + OpenAPI + WebSocket, RBAC + API tokens + TOTP 2FA + lockout,
  Prometheus `/metrics`, admin SPA, CLI, PiHole/AdGuard config import.
- **Hardening:** rate limiting, DNS-rebinding protection, EDNS padding on encrypted
  transports, fuzz-hardened wire parser, systemd sandboxing.

## Install & run

```bash
pip install dnsguard
dnsguardd --config dnsguard.example.yaml
# or, without a config file at all:
python3 -m dnsguard --dns-port 5354 --upstream 1.1.1.1:53 \
                    --source data/default_blocklist.txt
```

From a checkout, `pip install -e ".[dev]"` instead.

Then:

```bash
dig @127.0.0.1 -p 5354 doubleclick.net    # -> 0.0.0.0 (blocked)
dig @127.0.0.1 -p 5354 example.com        # -> forwarded
open http://127.0.0.1:8089                # admin UI (initial admin password is logged on first run)
```

### Docker

```bash
docker compose up -d        # host networking; binds :53, :853, :8443, :8089
```

### Production (port 53)

Port 53 needs privileges. Use the provided `dnsguard.service` (grants
`CAP_NET_BIND_SERVICE`, sandboxed) and set DNSGuard as your router's DHCP DNS server.

## CLI

```bash
dnsguard query doubleclick.net A            # built-in dig over @udp/@tcp/@tls/@https/@quic
dnsguard query example.com A @tls --server 9.9.9.9:853
dnsguard status --token <api-token>         # talk to a running daemon
dnsguard import pihole /etc/pihole/setupVars.conf
```

## Configuration

See [`dnsguard.example.yaml`](dnsguard.example.yaml). Highlights:

| Section | What |
|---|---|
| `server` | enable/port for `do53`, `dot`, `doh`, `doq`, `doh3` |
| `upstream` | `servers`, `strategy`, `mode: forward\|recursive`, `verify`, `dnssec` |
| `filtering` | `sources`, `allow`/`deny`, `block_mode`, safe-search/browse/services defaults |
| `clients` | per-client identity + policy overrides |
| `zones` / `local_records` | authoritative zones (`dnssec: true` to sign) + local A/CNAME |
| `plugins` | `["dns64", {name: block_tld, options: {tlds: [zip, mov]}}]` |
| `security` | `rate_limit`, `rebinding_protection`, `local_suffixes`, `use_0x20` |
| `dhcp` | integrated DHCP — **disabled by default**, needs `--allow-dhcp` to bind |
| `querylog` | `retention_days`, `privacy_level` (0 all … 3 none) |
| `web` | admin UI host/port, `admin_password`, TLS |

## API

`GET /api/v1/openapi.json` for the spec. Auth via login cookie or `Authorization: Bearer`.
Key routes: `/stats`, `/querylog`, `/rules`, `/toggle`, `/cache/flush`, `/gravity/refresh`,
`/clients`, `/system`, `/ws` (live), plus `/metrics`, `/healthz`, `/readyz`.

## Architecture

```
dnsguard/
  wire/        DNS message codec (RR zoo, EDNS, fuzz-safe)
  transport/   Do53 / DoT / DoH / DoQ / DoH3 frontends + upstream clients
  engine/      pipeline (validate→ratelimit→client→zones→filter→cache→resolve→rebinding)
  filter/      adblock parser + compiled index + matcher + RPZ + safe-search/services
  gravity/     blocklist fetch/compile + scheduler (ETag conditional)
  resolver/    forwarder, recursive (QNAME-min), dnssec (validate)
  cache/       TTL + LRU + negative + serve-stale + prefetch
  clients/     identification + effective policy
  auth_zone/   zones, zonefile, online DNSSEC signing
  store/       SQLite (migrations, query log, retention)
  stats/       realtime counters
  api/         REST + WebSocket + static SPA + auth/RBAC
  security/    TLS, scrypt hashing, TOTP
  plugins/     plugin API + builtins (dns64, block_tld)
  dhcp/        DHCPv4 (default-off, triple-guarded)
  ops/         Prometheus metrics, PiHole/AdGuard import
```

## Testing

```bash
pytest -q          # unit + fuzz + cross-transport integration + DNSSEC sign/validate
ruff check dnsguard/
```

The suite covers the wire codec (with `hypothesis` fuzzing and a `dnspython` oracle),
the filter matcher truth tables, the cache, every transport end-to-end, the
recursive algorithm (mock authority tree), DNSSEC sign↔validate, the API + auth,
DHCP, plugins, and the hardening layer.

## Not implemented

Deliberately out of scope for 2.0, with clean seams left for each: a GeoIP
plugin, DoH over HTTP/2 multiplexing, and automated DNSSEC key rollover
(signing, NSEC3 and the full chain are implemented; rotating keys on a
schedule is not).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go through the private
process in [SECURITY.md](SECURITY.md) — never a public issue.

## License

[MIT](LICENSE)
