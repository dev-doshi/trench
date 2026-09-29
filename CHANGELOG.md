# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Device names instead of bare addresses.** Trench now asks the router for
  the name of each device in the query log with a reverse (PTR) lookup, the
  way Pi-hole does, and every view that shows a client shows its name: Overview,
  Browse, Log, Live, Devices, History, the inspector and the evidence panel.
  The address stays beside the name, and hovering tells you where the name came
  from. A name you gave a device beats Trench's DHCP lease, which beats the
  router. The query language gains `device:` and free text also matches device
  names. The settings are under **Settings → Devices** (`client_names.*`).
  Only private addresses are looked up, and only against the router's own
  reverse zone when you have routed it (`[/178.168.192.in-addr.arpa/]…`) or a
  `client_names.server` that must itself be a private address, so the list of
  household devices never reaches a public resolver. Lookups run in a bounded
  background sweep, never on the query path. The name a device reports is
  reduced to one plain label, and random-looking names such as Apple's
  per-network UUIDs and MAC-derived names are hidden. At privacy level 1 or
  higher nothing is looked up and only names you set are shown.
- **Overview, the console's front page.** The last 24 hours or 7 days as
  Pi-hole and Technitium show them: totals with sparklines, queries per hour
  stacked by outcome, outcome, record-type and upstream shares, the busiest
  devices and response time over the window, and top names, blocked names and
  devices. Read from the query log, so it survives a restart and agrees with
  History. Line and bar charts now draw at their real width, so their labels
  stay legible in narrow cards. Browse moved to `/browse`; old links carrying
  a query still land there.
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
  assistants, listed at `GET /api/v1/services`.
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

- **The CLI says what went wrong, in sentences.** API commands read
  `TRENCH_URL`/`TRENCH_TOKEN`, answer in prose at a terminal (JSON when piped
  or with `--json`), and tell apart nothing listening, an unresolvable host, a
  missing, rejected or under-scoped token, a non-Trench server and the daemon's
  own refusal. Usage mistakes exit 2 with the accepted values; `query` reports
  its time and server.
- **Console accessibility.** Raised the contrast of the faint ink tokens,
  and added a skip link and focus management for the sheet, palette and
  inspector. Rows are keyboard-operable, and menus, toggles, lists and the
  search input carry ARIA roles and state. See `docs/reviews/ui-ux-review.md`.

- **Rebinding protection costs about a seventh of what it did.** The verdict for
  an answer address is a pure function of the string, and it was recomputed from
  scratch for every record of every answer: profiled, `scrub` was roughly half
  the uncached forward path, with `ipaddress._parse_octet` the single largest
  entry. Memoised behind a bounded table, the project's own `forward (uncached)`
  benchmark goes 64.1 us -> 55.0 us; an address that never repeats costs 5% more
  than not caching, which is the right side of that trade.
- **"upstream failed" means the upstream failed.** Every exception on the answer
  path was logged under that message, so an `AttributeError` in Trench's own
  code sent the operator to debug the wrong host — and since the client sees
  SERVFAIL either way, that log line was the only evidence such a bug existed.
  A `TrenchError`, `OSError` or timeout is still a warning; anything else is now
  an error with a traceback.
- **`trench.example.yaml` documents every setting again.** It says so at the
  top, which made it the one place an operator can find a setting without
  reading `config.py`, and thirty had accreted without being added — every
  stream and UDP bound, the fast path, DoH3, DNS cookies, TSIG keys, secondary
  zones. A test now fails when a setting is added without documenting it. The
  encrypted transports also show their real defaults (8853/8854/8444, so Trench
  runs without root) rather than the production ports.
- **The served OpenAPI document describes the whole API.** It had drifted to 16
  of 47 routes, and the omissions included `/api/v1/auth/login` — so a client
  generated from it could not authenticate to reach the sixteen it did describe.
  Every summary now names the role it needs.
- **Metrics are usable.** Labelled series for rcode, upstream and detection kind,
  a real latency histogram (an average cannot show a p99 regression), gauges for
  the filtering switch and any running pause, and escaped label values — one raw
  quote in an upstream label broke the whole scrape, not just its line.

### Removed

- **Tunnel detection's "encoded characters" signal.** It counted every letter,
  digit and hyphen as encoded, so any subdomain of 20 characters scored it;
  with it, S3 buckets, load balancers and a bank's API crossed the threshold.
  `deploy/raspi.yaml` now flags tunnels rather than blocking them.
- **The `group` table and its create/delete endpoints.** They stored groups no
  verdict ever consulted: a group made in the console could not change what any
  client resolved. Groups are now declared in `filtering.groups` and enforced;
  `GET /api/v1/groups` reports what is in force and creates nothing.
- **The `ts_stat` table**, written by nothing and read by nothing.
- **Volume scoring in the tunnel detector.** On a live home network 96% of its
  blocks scored exactly the threshold, pushed there by query rate alone: a busy
  device is not a tunnel. The detector now scores the name's structure only, and
  an allowed name is no longer screened at all.
- **`FilterEngine.add_deny` / `add_allow` / `remove_rule`**, the runtime rule
  edits the Policy page used to make in one worker's memory.

### Fixed

- **Seven days of charts no longer take the console down with them.** Every
  chart question read the raw query log, and on a Pi a week of it is ~450K rows
  that 1 GB of RAM cannot keep cached: each of the Overview's nine questions
  read ~100 MB off the SD card, 7–10 s apiece on one database connection, so a
  7-day Overview held it for over a minute — refreshed every minute — and
  Browse, Log and every other page queued behind it. Charts now read hourly
  rollups (`querylog_hour`, `querylog_hour_name`), kept by a trigger on insert,
  and only the partial hours at the window's edges from the raw rows; the
  answers are identical. An existing log is counted into them in the
  background after the upgrade, newest hour first. The Overview also skips a
  refresh while the previous one is still loading.

- **Top names over a day read the whole query log.** `/analytics` grouped by
  name or device let SQLite walk that column's index end to end to save one
  sort, ignoring the time range: on a Pi holding two weeks, a day's top names
  took 85 s. Grouping by `+column` keeps the planner on the timestamp index
  (0.8 s). The list-update review and the what-if preview had the same query.
- **Policy-page rules are written to the config file** (`filtering.allow` /
  `filtering.deny`) and reach every worker. They used to live in the database
  and the memory of whichever worker served the request, so with two workers
  roughly half the queries never saw them, and a restart or refresh could drop
  them. Rules left in the old table are moved into the config on start.
- **Private reverse zones and special-use names are answered locally.** PTR
  queries for RFC 1918 / RFC 6303 space, `.local`, `.home.arpa` and the other
  `security.local_suffixes` get NXDOMAIN instead of being forwarded to a public
  resolver that cannot know them, unless an upstream route names the zone.
- **UDP answers leave from the address that was asked.** A listener on
  `0.0.0.0` or `::` replied from whatever address the kernel chose for the way
  back, and a client using a connected socket (glibc's resolver) threw the
  answer away. On a Docker host that was every container on a bridge network;
  on any host, any client asking a second address.
- **One dropped DoT/TCP connection no longer fails the one that replaced it.**
  A slow close of the old stream marked the new connection closed, failing every
  query in flight on it.
- Queries rejected at the header (a router's DNS UPDATE, a bad EDNS version)
  now record why in the query log.
- Plain-text logs carry the date and no colour codes when stderr is not a
  terminal; cache prewarm logs at debug instead of flooding the log at info.
- `deploy/raspi.yaml` runs one worker (the 1 GB board was deep in swap with
  two), routes `fritz.box` and the LAN's reverse zone to the router, and drops
  root after binding.
- Encrypted-DNS discovery follows RFC 9462 §4 and RFC 9463 §5.1: the
  `_dns.resolver.arpa` answer now carries `ipv4hint`/`ipv6hint` and the
  designated name's A/AAAA records, so clients can upgrade without resolving
  it in plaintext first; and with no IPv4 address configured the DHCP DNR
  option is sent in ADN-only form instead of as a malformed instance with a
  zero address length followed by SvcParams.

- **Authoritative wildcards follow RFC 4592.** Only `*.<closest encloser>`
  synthesizes, so `*.example.com` no longer answers `x.foo.example.com` when
  `foo.example.com` exists, and nothing below an empty non-terminal. A
  synthesized answer is owned by the query name rather than by `*`, which stub
  resolvers had been discarding.
- **Signed zones prove their denials.** NXDOMAIN, NODATA, empty non-terminal
  and wildcard answers now carry the NSEC or NSEC3 records that cover the name
  asked for (RFC 4035 §3.1.3, RFC 5155 §7.2). Before, every negative answer got
  the apex NSEC, which proves nothing for almost any name, so validating
  resolvers SERVFAILed them. NSEC3 chains now include empty non-terminals.
  Glue and delegation NS sets are no longer signed or chained (RFC 4035 §2.2).
- **Negative TTLs** in authoritative answers and on NSEC/NSEC3 records are
  min(SOA TTL, MINIMUM) (RFC 2308 §3, RFC 9077).
- **Query header validation.**
  - A message with QR set is never answered. Doing so let a spoofed response
    set two servers replying to each other.
  - A non-QUERY opcode gets NOTIMP instead of REFUSED (RFC 8906).
  - An EDNS version other than 0 gets BADVERS (RFC 6891 §6.1.3).
  - QDCOUNT other than 1 gets FORMERR (RFC 9619), except for a cookie-only probe
    (RFC 7873 §5.4).
  - A second OPT record, or one not owned by the root, is a FORMERR.
- **EDNS sizes.** UDP replies are capped at the smaller of the client's and our
  configured `edns_udp_size` (RFC 6891 §6.2.5), and responses advertise our size
  rather than echoing the client's.
- **Stale answers** are served with a 30-second TTL (RFC 8767 §4) and always
  carry EDE 3, Stale Answer (RFC 8914).
- **DoH** matches `Content-Type` as a media type, ignoring case and parameters.
  DoH over HTTP/3 now sends `Cache-Control: max-age` as HTTP/2 does (RFC 8484
  §5.1).
- **Upstream replies** whose opcode differs from the query's are rejected.
- **Console: no navigation below 900 px.** The places strip was hidden and its
  replacement button never shown; it now takes over at 980 px, and the header
  no longer clips at laptop widths.
- **Console: search.** A half-typed query no longer empties the page (the last
  valid one keeps filtering), changing the server-side part of a query
  reloads, an outcome list is pushed down as `IN`, and Browse's time window
  follows the clock instead of dropping live rows.
- **Console: live feed.** One WebSocket with jittered backoff instead of
  stacked reconnects; an expired session returns to sign-in; the Live tape
  really freezes while hovered or focused; rows beyond the cap are announced.
- **Console: pivots quote their values**, so a domain or client with a quote
  or space no longer breaks or widens the query; CSV export neutralises
  formula-leading cells.
- **`trench why`** said "1 recent queries", crashed on a finding with missing
  fields, and hid why `--resolve` failed.

- **DNSSEC: algorithm 7 validated as BOGUS.** RSASHA1-NSEC3-SHA1 (RFC 5155 §2)
  was missing from the verifier's hash table, so every zone signed with it
  failed validation.
- **DNSSEC: an ancestor's delegation or DNAME record could forge NXDOMAIN.**
  The parent's public NSEC for a delegation sorts every name in the child into
  its gap; it is now refused as a proof for those names (RFC 6840 §4.1), and an
  NSEC3 delegation is no longer accepted as a closest encloser (RFC 5155 §8.3).
- **DoQ and DoH upstreams sent the client's message ID.** RFC 9250 §4.2.1
  requires 0 over DoQ, and a conforming server rejects anything else; DoH
  (RFC 8484 §4.1) now sends 0 too, for cacheability.
- **DHCP options longer than 255 octets crashed the reply.** They are now split
  and rejoined per RFC 3396, which the DNR option (RFC 9463) needs once several
  endpoints and a long hostname are advertised.
- A SERVFAIL or REFUSED from an upstream was accepted as the answer. The
  `sequential` and `fastest` strategies never asked the next upstream, a
  `parallel` race was won by whichever server failed quickest, and a retained
  stale answer was not served in its place. Both rcodes now fail over, count
  against the upstream's `fastest` ranking, and fall back to stale data when
  every upstream fails.
- A DoQ upstream that never completed its handshake held each query for
  aioquic's 60 s idle timeout; the whole exchange is now bounded by
  `upstream.timeout`.
- A `quic://` upstream failed outright on a host with IPv6 disabled
  (`ipv6.disable=1`, some container runtimes), even for an IPv4 server: the
  client socket was always AF_INET6. It is now opened in the family of the
  address the upstream resolved to.
- The Docker image lost its data on every recreate when run on the example
  config. The image's working directory was `/app`, so `data_dir: ./data`
  resolved to `/app/data` in the container layer rather than the `/data`
  volume, and the database, the compiled blocklist and the initial admin
  password went with the container. The working directory is now `/data`, and
  `/data/data` ships group-writable so the account `server.user` drops to can
  write to it.
- Shutdown closes the database even when the admin API, a secondary zone or
  the query log fails to stop. Any of those raising used to skip the close,
  and aiosqlite's worker thread is not a daemon, so the process answered
  SIGTERM by never exiting.
- Schema migrations are applied in one transaction with their bookkeeping row,
  so a failure or a kill mid-upgrade no longer leaves half a migration applied
  and unrecorded. A failed write is rolled back rather than left pending, to be
  committed in part by the next unrelated write.
- The persisted cache is written atomically, restored within `max_entries`, and
  a malformed TTL in it is skipped rather than raising on every later lookup of
  that name.
- Under the `fastest` strategy a single failure demoted an upstream for good:
  it was only asked again when the new head failed, so nothing ever cleared
  the count. A failure now demotes it for 30 seconds.
- A TCP or DoT connection that stopped answering without closing (a dropped NAT
  mapping, a vanished peer) stayed pooled, and every later query to that
  upstream timed out on it. A connection with no reply at all within a query's
  timeout is now closed and reopened, and a peer that stops reading can no
  longer hold a query in an unbounded send.
- The TCP fallback for a truncated UDP reply gave connect, length prefix and
  body a full timeout each; the exchange now has one.
- Query-log retention deleted the whole backlog in one transaction, holding the
  write lock while the log writer queued behind it and shed records. It now
  deletes in chunks of 5,000 and reports the rows it actually removed.
- A TCP client that sent its queries and then half-closed the connection had
  every answer still in flight cancelled when its FIN arrived. Pending answers
  are now sent, within the idle timeout, before the connection is closed.
- A worker killed while holding one of the shared cache's cross-process locks
  left it held forever, and every other worker froze on its next lookup in that
  stripe. Lock waits are now bounded at 50 ms; a lock that times out is logged,
  skipped at no further cost (a cache miss), and re-probed without blocking
  every 5 seconds.
- The same applied to the cross-worker query-log ring: a worker killed
  mid-push froze the primary worker on its next log flush, taking its DNS and
  API with it. Lane locks are bounded the same way.
- The container healthcheck probed a hardcoded port 53 while both `Config`'s
  default and `trench.example.yaml` listen on 5354, so the general-purpose
  Compose deployment marked a container unhealthy while it was resolving
  perfectly. It now reads `server.do53` from the mounted config, resolves the
  address family instead of assuming IPv4, and says so plainly when Do53 is
  disabled rather than timing out. `TRENCH_HEALTH_*` still overrides it.

- **A malformed record could switch DNSSEC validation off.** `parse_rdata` keeps
  a record it cannot decode rather than failing the whole message, so `rr.rtype`
  and the class of `rr.rdata` can disagree — a truncated A record keeps rtype 1
  and arrives as `Unknown`. Sixteen registered types can do this, DS, DNSKEY and
  NSEC3 among them. The DNSKEY RRset is filtered on `k.flags & ZONE_FLAG`
  *before* any signature is checked, so one undecodable key raised
  `AttributeError` out of `Validator.validate`; the resolver treats an
  unexpected validator error as INSECURE and serves the answer. A spoofed DNSKEY
  response that would have been rejected as bogus was served unvalidated
  instead, for the cost of appending one junk record. Every field read off rdata
  now tests the rdata rather than the record's claim about itself.
- **One bad record no longer costs the whole answer.** The same mismatch reached
  the rebinding scrub, which runs on every upstream answer under the shipped
  defaults: reading `.address` off an undecodable A record raised, and the
  client got SERVFAIL for a query that was fine and an upstream that was
  reachable. The referral path did it too, discarding every good glue address
  alongside one bad one and making a delegation unresolvable.
- **`GET /api/v1/querylog?limit=-1` returned the entire query log.** SQLite reads
  a negative LIMIT as *no* limit, so the 1000-row cap was walked straight
  through and every row was materialised and serialised to JSON — one
  authenticated request at viewer role. `POST /api/v1/whatif` had the same hole
  past its own 50,000-row cap.
- **A mistyped number in a query string is no longer a 500.** `history?days=`
  was guarded; its seven neighbours — `top`, `since`, `until`, `limit`,
  `offset`, `minutes`, `hours` — were not, so `int()` raised out of the handler
  and aiohttp turned it into a traceback. They now share one helper that also
  rejects `nan` (which silently defeated every `min()` cap, since comparisons
  against it are false) and bounds values to what SQLite can bind.
- **The DoH JSON API answers 400 for a name it cannot parse.** `?name=` went
  straight to `Name.from_text` unguarded on an open resolver endpoint — a 500
  and a traceback per request, caller's choice. `?type=` three lines above it
  was already guarded.
- **A dot inside a label survives being written out and read back.** `to_text`
  escapes it as `\.` per RFC 1035 §5.1, but `from_text` split on every dot
  before unescaping — cutting the name at the escape that exists to say "this
  dot is not a separator", then reading a fragment ending in a lone backslash.
  `Name.from_text(name.to_text())` raised `IndexError` for any such name. It
  also raised `ValueError` for `\999` and `UnicodeEncodeError` for non-ASCII,
  where every caller catches `WireError`. That reached the blocklist parser (on
  third-party lists fetched on a timer), the zone-file parser, and the DoH query
  parameter above.
- **A bad `$ORIGIN` or `$TTL` names the file and the line.** Both reached
  `line.split()[1]` and `int()` raw, so one typo in a hand-written zone file
  took the daemon down at start-up with a traceback naming neither the zone nor
  the line — the same failure `_rdata` had already been fixed for one level
  down.
- **An unusable `upstream.servers` entry is refused at load.** A non-numeric
  port killed start-up with `invalid literal for int() with base 10`, naming
  neither the setting nor the server; a port of 99999 was accepted outright and
  failed later somewhere with no visible connection to the cause. Specs are now
  checked at config load with the parser the resolver itself calls, so the two
  cannot disagree about what a spec means.
- **A truncated DHCP option is refused rather than stored short.** `_parse_options`
  read the length octet without checking it exists — `IndexError` where `parse`
  documents `ValueError` — and an option claiming more bytes than remained was
  kept at whatever length arrived, so a truncated hostname could be registered
  in DNS as though the client had sent it.
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
