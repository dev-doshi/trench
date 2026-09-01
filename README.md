# Trench

[![CI](https://github.com/dev-doshi/trench/actions/workflows/ci.yml/badge.svg)](https://github.com/dev-doshi/trench/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/trench)](https://pypi.org/project/trench/)
[![Python](https://img.shields.io/pypi/pyversions/trench)](https://pypi.org/project/trench/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**[Documentation](https://dev-doshi.github.io/trench/)** ·
[Installation](https://dev-doshi.github.io/trench/installation/) ·
[Security](https://dev-doshi.github.io/trench/security/) ·
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
  RPZ (including `rpz-ip`), CNAME-cloaking inspection, and **address lists** —
  an answer pointing into a listed network is blocked whatever its name was.
- **Per-client policy:** identify by IP / CIDR / MAC / ClientID; **filtering
  groups** with their own lists, **per-group upstreams**, tags, 89 blocked
  services (scheduled), forced safe-search, safe-browsing & parental controls,
  and timed pauses — global or for one device.
- **Clients upgrade themselves:** DDR (RFC 9462) answers the
  `_dns.resolver.arpa` query Windows 11 and Apple devices already send, and DNR
  (RFC 9463) puts the same designation in the DHCP lease — so devices move to
  DoT/DoH/DoQ without being configured. Off until `server.discovery.hostname`
  names something clients can authenticate.
- **Answers you can interrogate:** `trench why <name>` composes every stage
  that had an opinion — rules, services, protection, cache, the log, whether the
  device is even still asking this resolver — into one verdict.
- **Recursive resolver:** iterative from the root with QNAME minimization, plus
  **DNSSEC validation** (RSA / ECDSA P-256/P-384 / Ed25519 / Ed448).
- **Authoritative + DNSSEC signing:** zones, all common RR types, BIND zonefile
  import, online signing (RRSIG / NSEC / DNSKEY / DS).
- **Cache:** LRU + negative + serve-stale (RFC 8767) + prefetch, ECS/DO-aware keys.
- **Guards nobody else ships:** policy **assertions** that reject a blocklist
  refresh which would break a name you declared must work; a **silence ledger**
  that names devices still on the network but no longer asking this resolver;
  a **notary** that resolves pinned names through every upstream and reports
  disagreement; DGA and tunnelling detection.
- **Platform:** SQLite query log (search / CSV / JSON-lines stream / retention /
  privacy levels), REST `/api/v1` + OpenAPI + WebSocket, RBAC + API tokens +
  TOTP 2FA + lockout, labelled Prometheus `/metrics` with a latency histogram and
  a [Grafana dashboard](deploy/grafana-dashboard.json), admin SPA, CLI,
  PiHole/AdGuard config import.
- **Hardening:** rate limiting, DNS-rebinding protection, EDNS padding on encrypted
  transports, fuzz-hardened wire parser, systemd sandboxing.

## Install & run

```bash
pip install trench
trenchd --config trench.example.yaml
# or, without a config file at all:
python3 -m trench --dns-port 5354 --upstream 1.1.1.1:53 \
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

Port 53 needs privileges. Use the provided `trench.service` (grants
`CAP_NET_BIND_SERVICE`, sandboxed) and set Trench as your router's DHCP DNS server.

## CLI

```bash
trench query doubleclick.net A            # built-in dig over @udp/@tcp/@tls/@https/@quic
trench query example.com A @tls --server 9.9.9.9:853
trench why ads.example --client 192.168.1.50 --resolve   # what happened, and why
trench pause 5m --client 192.168.1.50     # let one device through for a bit
trench upgrade status                     # what is installed, what is available
trench status --token <api-token>         # talk to a running daemon
                                            # (Settings -> Access mints one)
trench import pihole /etc/pihole/setupVars.conf
```

## Configuration

See [`trench.example.yaml`](trench.example.yaml). Highlights:

| Section | What |
|---|---|
| `server` | enable/port for `do53`, `dot`, `doh`, `doq`, `doh3`; `user`/`group` to shed root; `discovery` (DDR/DNR) |
| `upstream` | `servers`, `strategy`, `mode: forward\|recursive`, `verify`, `dnssec`, `groups` (named upstream sets), `trust_anchors` (`root.key`) |
| `filtering` | `sources`, `ip_sources`, `allow`/`deny`, `block_mode`, `groups` (per-group lists), `assertions`, `ech`, safe-search/browse/services defaults |
| `clients` | per-client identity + policy overrides, `group`, `upstream_group` |
| `zones` / `local_records` | authoritative zones (`dnssec: true` to sign) + local A/CNAME |
| `plugins` | `["dns64", {name: block_tld, options: {tlds: [zip, mov]}}]` |
| `security` | `rate_limit`, `rebinding_protection`, `local_suffixes`, `use_0x20`, `silence_ledger`, `notary` |
| `dhcp` | integrated DHCP — **disabled by default**, needs `--allow-dhcp` to bind |
| `querylog` | `retention_days`, `privacy_level` (0 all … 3 none), `export` (JSON lines) |
| `updates` | `mode: off\|notify\|auto`, channel, index, maintenance `window`, `restart` |
| `web` | admin UI host/port, `admin_password`, TLS |

## API

`GET /api/v1/openapi.json` for the spec. Auth via login cookie or `Authorization: Bearer`.
Key routes: `/stats`, `/querylog`, `/rules`, `/toggle`, `/pause`, `/explain`,
`/history`, `/silence`, `/notary`, `/groups`, `/services`, `/update`, `/cache/flush`, `/gravity/refresh`,
`/clients`, `/system`, `/ws` (live), plus `/metrics`, `/healthz`, `/readyz`.

## Architecture

```
trench/
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
ruff check trench/
```

The suite covers the wire codec (with `hypothesis` fuzzing and a `dnspython` oracle),
the filter matcher truth tables, the cache, every transport end-to-end, the
recursive algorithm (mock authority tree), DNSSEC sign↔validate, the API + auth,
DHCP, plugins, and the hardening layer.

## Not implemented

Deliberately out of scope, and stated here rather than half-built:

- **dnstap.** The query log streams JSON lines instead. dnstap is Frame Streams
  plus protobuf, and a hand-rolled encoder with no conformance test against a
  real consumer would look present without being it.
- **Automated DNSSEC key rollover.** Signing, NSEC3 and the full chain are
  implemented; rotating keys on a schedule is not. Root *trust anchors* can be
  read from a `root.key`, so validation survives a root roll without a release.
- **A GeoIP plugin**, and ASN-accurate comparison in the notary — both need a
  data feed this project does not carry, so the notary compares /24 and /48
  networks and says so.
- **DoH over HTTP/2 multiplexing**, DNSCrypt, DHCPv6, clustering, and OIDC
  single sign-on.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go through the private
process in [SECURITY.md](SECURITY.md) — never a public issue.

## License

[MIT](LICENSE)
