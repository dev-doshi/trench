# Installation

Trench is pure Python and needs 3.11 or newer. Nothing else is required —
the admin console ships prebuilt inside the package, so there is no Node
toolchain and no build step.

!!! warning "Nothing is published yet"

    There is no tagged release, so **`pip install trench-dns` and
    `docker pull ghcr.io/dev-doshi/trench` both fail today** — the wheel and
    the image do not exist on a registry. The two routes below are the ones
    that work right now, and both start from a checkout.

    `pip install trench` is worse than failing: the name `trench` on PyPI
    belongs to an unrelated deep-learning library, and that is what you get.
    This project publishes as **`trench-dns`**.

## From source

```bash
git clone https://github.com/dev-doshi/trench
cd trench
pip install -e ".[dev]"
pytest -q
```

That installs two commands: `trenchd` (the server) and `trench` (the CLI that
talks to a running one).

```bash
trench --version
python3 -m trench --dns-port 5354 --upstream 1.1.1.1:53 \
                  --source data/default_blocklist.txt
```

`data/default_blocklist.txt` is resolved against the package when there is no
such file in the working directory, so that same line works from a checkout
and from an installed copy. Without `--source` nothing is blocked: Trench
ships no list it did not compile, and the bundled seed list is 44 names —
enough to prove the path works, not enough to be coverage.

## Docker Compose

Also from a checkout — `docker-compose.yml` builds the image locally, so
there is nothing to pull:

```bash
git clone https://github.com/dev-doshi/trench
cd trench
docker compose up -d
```

Run from anywhere else it fails with `no configuration file provided: not
found`, which only means Compose could not see the file.

It uses host networking, which is what lets the container serve DNS to the
rest of the LAN, and mounts the repository's `trench.yaml` — which binds DNS
on `:53` and the console on `:8089`, both on `0.0.0.0`. DoT (`:853`), DoH
(`:8443`) and DoQ are disabled in that file until you give them a certificate.

On macOS and Windows, Docker Desktop does not give a container the host's
network the way Linux does; treat Compose there as a way to build and
smoke-test the image, not as a way to serve your LAN.

On a Raspberry Pi use `deploy/docker-compose.raspi.yml` instead — it adds the
memory ceiling that keeps a blocklist rebuild from being OOM-killed. See
[Deployment](deployment.md).

## After the first release

Neither of these works until a `v*` tag has been pushed and the release
workflow has published the artifacts. They are here so the commands are
written down, not because they will work today.

```bash
pip install trench-dns
```

```bash
docker run -d --name trench \
  --network host \
  -v /etc/trench/trench.yaml:/data/trench.yaml \
  -v trench-data:/data \
  ghcr.io/dev-doshi/trench:2.0.0
```

The image runs as root only long enough to bind port 53; set `server.user` in
the config and it drops to an unprivileged account immediately afterwards.

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
