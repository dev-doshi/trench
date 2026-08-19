# Security

DNSGuard sits in the resolution path for every device on the network. This
page is about the settings that decide how much that exposes.

To report a vulnerability, see
[SECURITY.md](https://github.com/dev-doshi/dnsguard/blob/main/SECURITY.md).
Please do not open a public issue for one.

## What the defaults assume

The shipped configuration is loopback-only: DNS on `127.0.0.1:5354`, console
on `127.0.0.1:8089`, rate limiting off, no privilege drop. That is safe
because nothing can reach it. Every real deployment changes `host`, and the
settings that should change with it live elsewhere in the file.

DNSGuard checks for that gap at startup and warns:

```
WARN dnsguard.app: do53 is listening on 0.0.0.0 with security.rate_limit
     disabled: anything that can reach this port can use it for amplification.
WARN dnsguard.app: running as root with server.user unset: DNSGuard will keep
     full privileges after binding.
WARN dnsguard.app: admin console is listening on 0.0.0.0 without TLS: the
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

## Never expose port 53 to the internet

DNSGuard is a resolver for a network you control. A recursive resolver open to
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
  cert: /etc/dnsguard/console.crt
  key: /etc/dnsguard/console.key
```

The console has RBAC (`viewer` / `editor` / `admin`), API tokens, optional
TOTP two-factor, and login lockout after repeated failures. `/metrics`,
`/healthz` and the login endpoint are public by design — keep the port itself
off untrusted networks.

## Dropping privileges

```yaml
server:
  user: dnsguard
  group: dnsguard
```

DNSGuard binds the privileged ports first, then drops. The drop is verified
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
