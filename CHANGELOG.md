# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] — 2026-08-19

First public release.

### Added

- **Transports.** Do53 (UDP and TCP), DoT, DoH (RFC 8484 plus the JSON API),
  DoQ and DoH3 on the serving side. Upstreams over plain, TCP, DoT, DoH and
  DoQ, with per-domain routing and parallel, fastest-first or sequential
  strategies.
- **Filtering engine.** Adblock-DNS syntax (`||domain^`, `@@`, `$important`,
  `$badfilter`, `$dnstype`, `$denyallow`, `$dnsrewrite`, `$ctag`, `$client`),
  regex rules, hosts and dnsmasq formats, RPZ, and CNAME-cloaking inspection.
- **Per-client policy.** Identification by IP, CIDR, MAC or ClientID; groups,
  tags, scheduled blocked-services, forced safe-search, safe-browsing and
  parental controls.
- **Recursive resolver.** Iterative resolution from the root with QNAME
  minimization, a delegation cache, and bailiwick enforcement.
- **DNSSEC validation.** RSA, ECDSA P-256 and P-384, Ed25519 and Ed448, with
  NSEC and NSEC3 denial-of-existence proofs. A covering NSEC3 with Opt-Out set
  is not accepted as proof a name is absent (RFC 5155 §8.4) — it asserts only
  that no *signed* name falls in the gap, so under an opt-out parent the
  zone's own genuine chain would otherwise deny names that plainly exist. A
  parent-side delegation record (NS set, SOA clear) likewise proves nothing
  about types at the child's apex (§8.5).
- **Authoritative server.** Zones, the common RR types, BIND zonefile import,
  online signing (RRSIG, NSEC, DNSKEY, DS), AXFR/IXFR in and out, NOTIFY, and
  RFC 2136 dynamic update — all transaction types authenticated with TSIG.
- **Cache.** LRU with negative caching, serve-stale (RFC 8767), prefetch and
  query coalescing (RFC 5452 §9.2); keys are ECS- and DO-aware, and the table
  can be shared across worker processes.
- **Hot path.** A wire-resident replay path that answers repeat queries from
  recorded response bytes, measured at 2.4x on a Raspberry Pi.
- **Hardening.** Per-client rate limiting, DNS-rebinding protection, 0x20
  query-name randomization, DNS cookies, EDNS padding on encrypted
  transports, a response sanitizer that rebuilds answer sections (RFC 5452
  §6), DGA and DNS-tunnel detection, and privilege drop after binding.
- **Platform.** SQLite query log with search, export, retention and privacy
  levels; REST `/api/v1` with OpenAPI and a WebSocket feed; RBAC with API
  tokens, TOTP 2FA and login lockout; Prometheus `/metrics`; a `/healthz`
  endpoint; the Bailiwick admin console; a CLI; and config import from Pi-hole
  and AdGuard Home.
- **DHCP.** An integrated IPv4 DHCP server, off by default.
- **Plugins.** A loader and a stable plugin API, with DNS64 as the worked
  example.
- **Deployment.** Multi-architecture Docker image (amd64 and arm64), Compose
  files, a sandboxed systemd unit, and a Raspberry Pi deployment guide.

### Notes for operators

- DNS listeners bind to the LAN and rate-limit by default. Exposing port 53 to
  the internet turns DNSGuard into an open resolver; see
  [SECURITY.md](SECURITY.md).
- The admin console generates an administrator password on first start and
  prints it once. Serve the console over TLS, or keep it on a management
  interface.
- DGA and tunnel detection are scored, not absolute. Raise the thresholds
  before enabling blocking on a network with unusual traffic — WiFi calling
  and some CDNs produce genuinely high-entropy names.

[Unreleased]: https://github.com/dev-doshi/dnsguard/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/dev-doshi/dnsguard/releases/tag/v2.0.0
