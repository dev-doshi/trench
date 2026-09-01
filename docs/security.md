# Security

Trench sits in the resolution path for every device on the network. This
page is about the settings that decide how much that exposes.

To report a vulnerability, see
[SECURITY.md](https://github.com/dev-doshi/trench/blob/main/SECURITY.md).
Please do not open a public issue for one.

## What the defaults assume

The shipped configuration is loopback-only: DNS on `127.0.0.1:5354`, console
on `127.0.0.1:8089`, rate limiting off, no privilege drop. That is safe
because nothing can reach it. Every real deployment changes `host`, and the
settings that should change with it live elsewhere in the file.

Trench checks for that gap at startup and warns:

```
WARN trench.app: do53 is listening on 0.0.0.0 with security.rate_limit
     disabled: anything that can reach this port can use it for amplification.
WARN trench.app: running as root with server.user unset: Trench will keep
     full privileges after binding.
WARN trench.app: admin console is listening on 0.0.0.0 without TLS: the
     password and every API token cross the network in the clear.
```

It warns and still starts — the operator, not the server, decides. But a
production config should produce none of these.

## Rate limiting

```yaml
security:
  rate_limit: 100      # queries/sec per client
  rate_burst: 200
```

An unlimited resolver reachable by anything on the network is an amplification
source: a small spoofed query returns a much larger answer to a forged victim
address. 100/200 suits a home LAN. Clients over the limit get REFUSED.

## Behind a reverse proxy

```yaml
security:
  trusted_proxies: [10.0.0.5]     # or a CIDR
```

`X-Forwarded-For` is written by whoever sent the request, so it is believed
only when the peer that delivered it is listed here. Left empty — the default
— the socket address always wins, which is correct for every deployment that
has no proxy.

This matters more than a logging detail: the client identity chosen here
selects the per-client filtering policy, the rate-limit bucket, the
login-failure counter behind account lockout, and the subnet sent upstream in
ECS. If the header were trusted unconditionally, one value rotated per request
would defeat all four.

Set it only to the proxy actually in front of DoH or the console. Listing a
range wider than that hands the same free choice to everything inside it.

## Never expose port 53 to the internet

Trench is a resolver for a network you control. A recursive resolver open to
the internet will be found and abused within hours, rate limit or not. If you
need DNS from outside, use an encrypted transport with authentication in front
of it, or a VPN.

## The admin console

Without TLS, the session cookie, the administrator password and every API
token cross the network in cleartext.

```yaml
web:
  host: 127.0.0.1      # or a management interface
  tls: true
  cert: /etc/trench/console.crt
  key: /etc/trench/console.key
```

The console has RBAC (`viewer` / `editor` / `admin`), API tokens, optional
TOTP two-factor, and login lockout after repeated failures. `/metrics`,
`/healthz` and the login endpoint are public by design — keep the port itself
off untrusted networks.

Both are managed under **Settings → Access**. A token is shown once and stored
only as a keyed digest, under a key held in the database, so tokens keep working
across restarts and a copy of the database alone yields nothing precomputable.
A token's scope caps its owner's role: an admin can issue a `viewer` token
without creating a second account.

Enrolling a second factor asks for one matching code before anything is stored —
an unverified secret is a lockout on the next login. If the authenticator is
lost, recovery is `trench passwd <user> --clear-totp`, offline on the box,
because write access to the database is the only proof of ownership left at
that point.

## Automatic TLS certificates

Encrypted transports (DoT, DoH, DoQ) and the console over HTTPS need a
certificate. Without one they self-sign, which every client then has to be told
to trust. `acme:` obtains a real one over ACME dns-01 (RFC 8555):

```yaml
zones:
  - origin: example.org.
    file: /etc/trench/example.org.zone

acme:
  enabled: true
  domains: [dns.example.org]
  email: ops@example.org          # optional; the CA warns you before expiry
```

dns-01 rather than http-01, because Trench is already an authoritative DNS
server: it publishes `_acme-challenge` in its own zone, so nothing has to be
reachable from the internet, port 80 stays closed, and wildcards are possible.

The constraint that comes with that is real: **the name being certified must sit
in a zone this server is authoritative for.** If it does not, Trench says so
once at start-up and does nothing else — it will not retry a setup that cannot
work. An explicitly configured `cert`/`key` pair always takes precedence, so
pointing a listener at your own certificate keeps working.

Renewal is checked twice a day and runs 30 days before expiry, in the primary
worker only. The account key, certificate and private key live in the data
directory as `acme-account.key`, `acme.crt` and `acme.key`; the two keys are
written mode 0600 and replaced atomically.

## Dropping privileges

```yaml
server:
  user: trench
  group: trench
```

Trench binds the privileged ports first, then drops. The drop is verified
rather than assumed: it re-checks that root cannot be regained, and refuses to
run if the saved-set-uid survived. Under systemd the shipped unit avoids root
altogether with `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

## Query-log privacy

The query log records what every device on the network looked up.

```yaml
querylog:
  enabled: true
  retention_days: 90
  privacy_level: 0     # 0 everything .. 3 no logging
```

Level 0 keeps client identity alongside each name. Raise it, or shorten
retention, on any network where that is somebody else's business but yours.

## DNSSEC

```yaml
upstream:
  dnssec: true
```

Validation is off by default because in `forward` mode the upstream is usually
already validating, and a broken or badly signed zone becomes a resolution
failure rather than a warning. Turn it on in `recursive` mode — that is the
mode where nothing else is checking.

## Detectors that score rather than decide

```yaml
security:
  dga_detection: true
  dga_block: false     # flag and count, do not block
  tunnel_detection: true
  tunnel_block: false
```

DGA and tunnel detection score names on lexical features. High-entropy names
are not always malware: WiFi calling, some CDNs, and several consumer devices
produce names that look exactly like a domain-generation algorithm's output.
Run with `*_block: false` first and read what gets flagged on your own network
before letting it block anything.

## Hardening already on by default

- rebinding protection — upstream answers pointing into private address space
  are dropped for names outside the configured local suffixes;
- response sanitizing — answer sections are rebuilt from what was asked rather
  than trusted as received (RFC 5452 §6), so an upstream cannot smuggle extra
  records into cache;
- bailiwick enforcement in the recursive resolver — a nameserver may only
  answer for names it is actually authoritative for;
- EDNS padding on encrypted transports (RFC 8467);
- a fuzz-hardened wire parser, with a standing fuzz job in CI.

Optional, and worth turning on for a resolver doing its own recursion:

```yaml
security:
  use_0x20: true       # query-name case randomisation
  dns_cookies: true    # RFC 7873
```
