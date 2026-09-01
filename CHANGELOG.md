# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Filtering groups.** `filtering.groups` declares named list sets and
  `clients[].group` puts a device in one. A group holds only its own rules and is
  layered over the household's, so it costs its own list and not a second copy of
  the corpus; `inherit: false` makes the group's list the whole policy. The
  database has modelled this since the beginning — a `group` table and a
  `group_id` on `adlist` and `custom_rule` — and nothing ever read those columns.
- **Per-client upstreams, for real.** `upstream.groups` names upstream sets and
  `clients[].upstream_group` selects one. Answers are cached per group, so the
  group pointed at a family filter can never be served the answer another device
  got from the default resolver. The setting itself is not new; being obeyed is.
- **Blocking on the answer's address.** `filtering.ip_sources` takes lists of
  IPs and CIDRs, and RPZ `rpz-ip` triggers — previously parsed and discarded —
  now land in the same matcher. The name in a question is disposable; the network
  behind it usually is not.
- **Policy assertions.** `filtering.assertions` states what the policy must
  always do (`"bank.example must resolve"`). Every candidate rule set is checked
  before adoption, and a refresh that would violate one is reported and refused
  rather than served. Unparseable assertions are refused at config load, not at
  the 3am refresh they were written to guard.
- **Timed pauses.** `trench pause 5m`, optionally `--client`, and
  `POST /api/v1/pause`. Expires by itself, so the network cannot be left
  unfiltered by someone who forgot; the replay table stands down while one runs.
- **`trench why <name>`** and `GET /api/v1/explain`. One verdict composed from
  every stage that had an opinion — local zones and leases, the global switch,
  services, protection, rules, the contract, the cache, the log, whether the
  device is even still asking this resolver, and optionally a live resolution
  with its RFC 8914 reason.
- **Silence ledger.** Devices still present on the network (DHCP lease, ARP) that
  have stopped asking this resolver anything, cross-referenced with the plaintext
  bootstrap names a client must resolve before it can switch to its own encrypted
  resolver. `GET /api/v1/silence`. It reports; it never blocks.
- **Notary.** `security.notary` resolves pinned names through every configured
  upstream and compares the networks they land in, reporting disagreement and
  first sightings. `GET /api/v1/notary`.
- **DHCP leases become DNS.** `dhcp.register_dns` publishes `laptop.lan` and the
  matching PTR from the hostname a client offers, reduced to one sanitised label
  inside the scope's own domain — a device may not claim `www.bank.com`, a name
  outside the scope network, or a name the operator configured statically. The
  `dns_register` hook existed and was never called.
- **Root trust anchors from disk.** `upstream.trust_anchors`, or
  `<data_dir>/root.key`: IANA DS records or a BIND `trust-anchors` block, with
  DNSKEY entries converted to DS. The compiled-in pins remain the fallback.
- **Query-log streaming.** `querylog.export` writes one JSON object per query to
  a file or stdout, rotating at 64 MB. A failure disables the export and never
  touches the log or DNS.
- **Name history.** `GET /api/v1/history` groups what a name has resolved to over
  time out of the query log that already holds it — passive DNS for one
  household, with no second store to keep and prune.
- **ECH policy.** `filtering.ech: pass|strip` for the `ech` parameter in
  HTTPS/SVCB answers, tested both ways. `pass` is the default: ECH hides the TLS
  server name, not the DNS question.
- **89 blocked services**, up from 12, in ten categories including the AI
  assistants, listed at `GET /api/v1/services`; and a Grafana dashboard in
  `deploy/`.
- **Update checking, with optional automatic installation** (`updates.mode`).
  The default is `notify`: Trench tells you a release exists and installs
  nothing. Automatic installation verifies the artifact's sha256 against the
  index, proves the new build imports and validates the live configuration in a
  throwaway environment before touching the live one, refuses on installations
  Trench does not own (containers, distribution packages, source checkouts),
  defers while a blocklist build is running, and honours a maintenance window.
  Applying stages code on disk and leaves the running process serving; the
  restart is delegated to the supervisor, and is short rather than absent —
  sockets are pre-bound and the compiled table is mapped from disk, and systemd
  socket activation closes the gap entirely. New: `trench upgrade`, and
  `/api/v1/update`. (`trench update` still refreshes the blocklists.)
- **Encrypted-DNS discovery.** `server.discovery` publishes this resolver's own
  DoT/DoH/DoQ endpoints two ways: a SVCB answer for `_dns.resolver.arpa`
  (RFC 9462 DDR), which Windows 11 and Apple devices already ask for, and the
  RFC 9463 DNR option in the DHCP lease. Both designate by name, because a
  client only uses a designation it can authenticate and no CA will certify a
  private address — so it stays off until `discovery.hostname` names something
  real, and says why in the log if it cannot work.

### Changed

- **Metrics are usable.** Labelled series for rcode, upstream and detection kind,
  a real latency histogram (an average cannot show a p99 regression), gauges for
  the filtering switch and any running pause, and escaped label values — one raw
  quote in an upstream label broke the whole scrape, not just its line.

### Removed

- **The `group` table and its create/delete endpoints.** They stored groups no
  verdict ever consulted: a group made in the console could not change what any
  client resolved. Groups are now declared in `filtering.groups` and enforced;
  `GET /api/v1/groups` reports what is in force and creates nothing.
- **The `ts_stat` table**, written by nothing and read by nothing.

### Fixed

- **Startup failures are fatal again.** Nothing awaited the task running
  `App.run()`, so anything it raised — a missing certificate, a port in use, the
  refusal to keep running as root — vanished into an unretrieved exception while
  the already-bound Do53 listener went on answering the LAN and systemd saw a
  healthy process. A worker that fails to start now exits non-zero.
- **The process's own audit records are written.** `_record_contract_failure`
  and the notary named a `user` column the table does not have, so every write
  raised and was swallowed by its own `except`.
- **Tracebacks appear in the default log format.** `_HumanFormatter` dropped
  `exc_info`, so every `log.exception` in the package printed one bare sentence
  unless `json_logs` was on. That is what hid the bug above.
- **A trust anchor file cannot install an anchor for another zone.** The
  presentation-format branch never checked the owner name, so a `dig DS` line
  for any zone became a *root* anchor — and whoever held that key could sign the
  root, and from there anything. Revoked and non-zone DNSKEY anchors are refused
  too, and a corrupted key line is skipped rather than decoded into a
  confidently wrong anchor.
- **X-Forwarded-For is read from the right.** nginx and HAProxy append, so the
  left-most entry is whatever the client sent: a client could pick its own
  address and with it the login-lockout counter, the per-client policy, the
  rate-limit bucket and the ECS subnet. The header is now walked from the right
  past hops that are themselves trusted proxies.
- **The WebSocket feed is bounded.** `max_msg_size=0` disabled aiohttp's
  reassembly limit, so any viewer could stream unbounded continuation frames
  into the process that also serves DNS.
- **RFC 2136 deletes cannot brick a zone.** The class-NONE branch had none of
  the SOA/NS guards the class-ANY branches have, so an authorised updater could
  delete the apex SOA — which left the zone SOA-less and then crashed on the way
  out, with no reply, no journal entry and SERVFAIL for every update after it.
  An update record of a foreign class is now FORMERR instead of being stored and
  served as IN.
- **Blocklist compilation is off the event loop, and serialised.** Compiling the
  corpus and writing the shared table is tens of seconds of synchronous work
  that ran inside the resolver's loop, dropping UDP and stalling TCP timers on
  every refresh; and the three ways in — the schedule, a settings change and
  SIGHUP — could run two builds at once on a box with a 700 MB ceiling.
- **The database is created 0600.** It holds password hashes, TOTP secrets,
  API-token digests, the query-log salt and the household's DNS history, and was
  created at the process umask.
- **Shutdown finishes.** One frontend failing to close skipped the query-log
  drain and the database close, and turned SIGTERM into a traceback.
- **The query-log writer survives a bad tick**, retention is scheduled once
  rather than twice, and the JSON-lines export no longer writes from inside the
  flush tick.
- **Replay keeps the ledger honest.** The fast path did not record queries with
  the silence ledger, so the busiest devices looked silent — the inverse of the
  signal — and it stood down for `$client` rules only in the default rule set,
  not in a group's. A DHCP registration now also drops recorded answers, so a
  name that was NXDOMAIN before the lease stops being replayed.

- **Settings saved in the console now reach the running resolver.** Eight of the
  nine Resolution settings — upstream servers, strategy, timeout, mode, DNSSEC,
  QNAME minimisation, certificate verification, source-port spread — were
  written to the file, reported as saved with no restart required, and then
  ignored until the next restart, because nothing rebuilt the forwarder. So were
  `server.fast_path`, `querylog.enabled` and the three default client-policy
  toggles. Each setting now declares how it is applied (`live`, `adopt` or
  `restart`), the "restart" badge is derived from that declaration rather than
  maintained beside it, and `tests/test_settings_apply.py` fails if a field is
  ever added without one.
- **`systemctl reload` no longer takes the service down.** With `workers > 1`
  the unit's `ExecReload` sent SIGHUP to the supervisor, which installed no
  handler for it, so the signal killed the supervisor and systemd tore down the
  whole cgroup. The supervisor now forwards SIGHUP to its workers.
- **A settings change reaches every worker.** The console runs in the primary
  only, so a saved change applied to one process out of `workers`, and which
  policy a device met depended on which worker answered it. Siblings now notice
  the rewritten config file on the poll they already run for the block table.
- **The query log records every worker's traffic.** Do53 runs in all workers but
  only the primary may write SQLite, so the log — and Breakage, list ROI, the
  what-if replay and the blocklist review built on it — saw roughly `1/workers`
  of the queries and said nothing about it. Workers now publish records through
  a shared ring that the primary drains.
- **The live chart agrees with the totals above it.** The per-minute series was
  per worker while the headline figures were aggregated, so on four workers the
  graph showed a quarter of the number printed over it, in the same response.
- **Per-client thresholds mean what they say on a multi-worker box.**
  `security.rate_limit` enforced `workers ×` the configured rate (four
  independent token buckets); DGA campaign confirmation needed about three times
  the evidence it was designed for, and the tunnelling volumetric threshold four
  times. All three are now scaled by the worker count.
- **Query-log privacy level 2 hashes, as it has always claimed to.** It replaced
  every domain with the literal string `hidden`, so the log kept its full size
  and retention while carrying nothing; the console and the settings help both
  described it as hashed. It is now a salted digest, so counts and repeat
  visits still add up while the names do not survive, and answers are dropped.
- **API tokens can be created.** The table, the validation path, the CLI's
  `--token` flag and the documentation all existed around a hole where the
  minting should have been: there was no way to obtain one. Settings → Access
  now issues, lists and revokes them.
- **API tokens survive a restart.** Their digest key was regenerated at import,
  so every stored token silently stopped verifying when the process came back.
- **TOTP can be enrolled, and recovered from.** Verification, replay protection
  and the login field were all in place with no way to turn it on. Enrolment now
  requires one matching code before anything is stored, and
  `trench passwd --clear-totp` recovers a lost authenticator — a password
  reset alone left the second factor standing.
- **Unknown configuration keys are refused.** A misspelling or a wrong indent
  (`rate_limit` under `server:` rather than `security:`) was silently dropped,
  leaving the protection the operator configured switched off.
- **`trench.example.yaml` loads.** `ecs: off` unquoted is a YAML 1.1 boolean,
  so the template the documentation points at failed validation. Both the file
  and the model now handle it.
- **`upstream.dnssec` no longer looks active in forward mode.** It reaches only
  the recursive resolver; the shipped `trench.yaml` set it to `true` alongside
  `mode: forward` and described it as validating. Contradictions like this are
  now reported once at start-up.
- **The first-run admin password is not written to the log.** It was printed
  rather than logged on the reasoning that log access reaches more people —
  but under both the systemd unit and the compose file, stdout *is* the log. It
  now goes to a mode-0600 file, and the log records the path.
- **DoQ and DoH3 now carry the connection caps.** They were built without
  limits of any kind, so the number of established QUIC connections one
  worker held was whatever peers asked for — while `server.tcp_max_*` was
  documented as bounding every connection-oriented frontend.
- **Changing the blocklist sources refetches them.** The rebuild went through
  the start-up path, which reuses the cached table while it is inside its
  refresh interval — a table compiled from the sources that were just
  replaced.
- **Passwords are re-hashed at login when the stored cost is out of date.**

### Added

- **Automatic TLS certificates** over ACME dns-01 (`acme:`). The client could
  open an order and had no way to answer a challenge, finalise or download the
  result, so nothing ever called it. The flow is complete, wired to the
  authoritative zone server that makes dns-01 possible here, and renewed on a
  schedule. Off by default; it says once at start-up when the configuration
  cannot work.
- `security.trusted_proxies`, `upstream.verify`, `security.local_suffixes`, the
  detector thresholds and several cache settings are now editable in the
  console.

### Changed

- **Compiling the blocklists peaks at half the memory.** The corpus was
  materialised as ~600k `Rule` objects on the way to a 24 MB table: 296 MB of
  peak, measured, on a box with a 700 MB ceiling that had been OOM-killed.
  Sources are now compiled as a stream — 153 MB for the same output — and
  fetched a few at a time rather than all at once.
- **About 7% off the forwarded query path.** Twelve `from x import y` statements
  were re-executed per query (0.6 µs each, 7.3 µs a query); they are now
  module-level, which is what the import cycle they were working around had been
  hiding.
- The `resolve()` seam a plugin can supply is stated as a Protocol instead of
  being discovered with `inspect.signature`.
- Tests are filed under the subject they cover rather than the batch they were
  written in, and the pipeline suites exercise the real filter engine instead of
  a second matcher that no deployment ran.


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
  the internet turns Trench into an open resolver; see
  [SECURITY.md](SECURITY.md).
- The admin console generates an administrator password on first start and
  prints it once. Serve the console over TLS, or keep it on a management
  interface.
- DGA and tunnel detection are scored, not absolute. Raise the thresholds
  before enabling blocking on a network with unusual traffic — WiFi calling
  and some CDNs produce genuinely high-entropy names.

[Unreleased]: https://github.com/dev-doshi/trench/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/dev-doshi/trench/releases/tag/v2.0.0
