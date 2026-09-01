# Installation

Trench is pure Python and needs 3.11 or newer. Nothing else is required —
the admin console ships prebuilt inside the package, so there is no Node
toolchain and no build step.

## pip

```bash
pip install trench
trench --version
```

Two commands are installed: `trenchd` (the server) and `trench` (the CLI
that talks to a running one).

## Docker

```bash
docker run -d --name trench \
  --network host \
  -v /etc/trench/trench.yaml:/data/trench.yaml \
  -v trench-data:/data \
  ghcr.io/dev-doshi/trench:2.0.0
```

Host networking is what lets the container serve DNS to the rest of the LAN.
The image runs as root only long enough to bind port 53; set `server.user` in
the config and it drops to an unprivileged account immediately afterwards.

A Compose file is in the repository. On a Raspberry Pi use
`deploy/docker-compose.raspi.yml` instead — see [Deployment](deployment.md).

## From source

```bash
git clone https://github.com/dev-doshi/trench
cd trench
pip install -e ".[dev]"
pytest -q
```

## First run

The shipped configuration is deliberately harmless: DNS on `127.0.0.1:5354`,
admin console on `127.0.0.1:8089`, nothing exposed to the network.

```bash
cp trench.example.yaml /etc/trench/trench.yaml
trenchd --config /etc/trench/trench.yaml
```

Or without a config file at all, to try it out:

```bash
python3 -m trench --dns-port 5354 --upstream 1.1.1.1:53 \
                    --source data/default_blocklist.txt
dig @127.0.0.1 -p 5354 doubleclick.net     # 0.0.0.0 — blocked
dig @127.0.0.1 -p 5354 example.com         # resolves normally
```

The seed list is small on purpose (a few dozen domains, enough to prove the
sinkhole works offline). Real coverage comes from the remote lists in
`filtering.sources`; see [Configuration](configuration.md).

The admin console generates an administrator password on first start and
prints it **once**, to the log. If you miss it:

```bash
trench passwd            # set one offline, on the box
```

## Serving the network

Two changes turn the loopback default into a LAN resolver, and they belong
together:

```yaml
server:
  do53:
    host: 0.0.0.0
    port: 53
  user: trench         # shed root once :53 is bound

security:
  rate_limit: 100        # queries/sec per client
  rate_burst: 200
```

Without `rate_limit`, anything that can reach port 53 can use the server for
amplification. Trench logs a warning at startup if it finds a network-facing
listener with rate limiting off, but it will still start — see
[Security](security.md).

Point clients at it by setting the DNS server in your router's DHCP settings.
