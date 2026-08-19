# Security Policy

DNSGuard sits in the resolution path for every device on a network and, when
the admin console is enabled, holds credentials for it. Bugs here are worth
reporting carefully.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 2.0.x   | ✅ |
| < 2.0   | ❌ |

Security fixes land on the latest minor release. There is no long-term-support
branch.

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Use GitHub's private reporting: *Security → Report a vulnerability* on the
repository. If that is unavailable, email the address listed in the repository
profile.

Please include:

- affected version (`dnsguard --version`) and how DNSGuard is deployed
  (Docker, systemd, source);
- the relevant part of the configuration, with secrets removed;
- a description of the impact, and a reproduction — a packet capture, a
  crafted query, or a short script is ideal;
- whether the issue is reachable from the LAN, from an upstream response, or
  only from an authenticated admin session.

### What to expect

- acknowledgement within 3 working days;
- an assessment, with a severity and a fix target, within 10 working days;
- credit in the release notes and the advisory, unless you would rather not be
  named.

Please give us 90 days before public disclosure, or less if a fix ships
sooner.

## Scope

In scope, and treated as security issues:

- anything that lets an off-path attacker get a forged answer accepted
  (cache poisoning, response spoofing, DNSSEC validation bypass);
- parsing bugs in the wire format reachable from a query or an upstream
  response (crash, hang, out-of-bounds read, unbounded allocation);
- authentication or authorization flaws in the REST API, the WebSocket API or
  the admin console, including privilege escalation between roles and token
  handling;
- TSIG, zone-transfer, dynamic-update and NOTIFY authentication flaws;
- amplification or reflection made possible by DNSGuard's own defaults;
- leaks of query-log data or credential material to unauthorized parties;
- privilege-drop, sandbox or container-escape failures.

Out of scope:

- an operator deliberately exposing port 53 to the internet as an open
  resolver — DNSGuard ships bound to loopback and warns at startup when it
  finds a network-facing listener with rate limiting off, but it cannot stop
  a configuration that overrides both;
- missing hardening on a deployment where the admin console has been bound to
  a public interface without TLS;
- blocklist content — false positives and false negatives belong to the list
  maintainers, not to DNSGuard (see the collateral-damage report in the
  console for a way to spot them);
- denial of service that needs privileged network position and floods
  DNSGuard the same way it would flood any resolver;
- vulnerabilities in dependencies with no DNSGuard-specific exploit path;
  report those upstream, and open a normal issue here to bump the pin.

## Hardening notes for operators

- set `security.rate_limit` as soon as port 53 is reachable by anything you do
  not control — it is off in the shipped config, which is loopback-only;
- serve the admin console over TLS, or keep it on a management interface;
- `querylog.privacy_level` above 0 reduces what is retained about each client;
- run the systemd unit as shipped — it drops privileges after binding and
  applies a restrictive sandbox.
