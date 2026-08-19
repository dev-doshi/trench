# DNSGuard

A self-hosted DNS server in pure-Python asyncio: ad/tracker sinkhole,
validating recursive resolver, authoritative server with online DNSSEC signing, and
opt-in DHCP — a superset of PiHole, AdGuard Home, and Technitium.

See the [README](https://github.com/OWNER/dnsguard) for the feature matrix.
This site covers installation, deployment, configuration, security and the
API.

New here? Start with [Installation](installation.md), then
[Security](security.md) before you point the network at it.

## Quick start

```bash
pip install dnsguard
python -m dnsguard --dns-port 5354 --upstream 1.1.1.1:53 --source data/default_blocklist.txt
dig @127.0.0.1 -p 5354 doubleclick.net    # 0.0.0.0
```

## Transports

| Protocol | In (server) | Out (upstream) |
|---|---|---|
| Do53 UDP/TCP | ✅ | ✅ |
| DoT (853) | ✅ | ✅ `tls://` |
| DoH (8484 + JSON) | ✅ | ✅ `https://` |
| DoQ | ✅ | ✅ `quic://` |
| DoH3 | ✅ | — |
