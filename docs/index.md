# Trench

![Trench](assets/banner.svg)

A self-hosted DNS server in pure-Python asyncio: ad/tracker sinkhole,
validating recursive resolver, authoritative server with online DNSSEC signing,
and opt-in DHCP — the sinkhole and the resolver that usually sit in front of
each other, in one process.

See the [README](https://github.com/dev-doshi/trench) for the feature matrix.
This site covers installation, deployment, configuration, security and the
API.

New here? Start with [Installation](installation.md), then
[Security](security.md) before you point the network at it.

## Quick start

Nothing is published yet, so install from a checkout:

```bash
git clone https://github.com/dev-doshi/trench && cd trench
pip install -e .
python3 -m trench --dns-port 5354 --upstream 1.1.1.1:53 \
                  --source data/default_blocklist.txt
dig @127.0.0.1 -p 5354 doubleclick.net    # 0.0.0.0
```

Without `--source` nothing is blocked: Trench ships no list it did not
compile, and the bundled seed list is 44 names — enough to prove the path
works, not enough to be coverage.

## How a query moves through it

![Clients reach Trench over Do53, DoT, DoH, DoQ or DoH3; every query runs the same ordered pipeline; answers come from local zones, an upstream, or recursion from the root](assets/architecture.svg)

## Transports

| Protocol | In (server) | Out (upstream) |
|---|---|---|
| Do53 UDP/TCP | ✅ | ✅ |
| DoT (853) | ✅ | ✅ `tls://` |
| DoH (8484 + JSON) | ✅ | ✅ `https://` |
| DoQ | ✅ | ✅ `quic://` |
| DoH3 | ✅ | — |
