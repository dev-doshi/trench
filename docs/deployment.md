# Deployment

## systemd

The repository ships `trench.service`. It binds the privileged ports with
`CAP_NET_BIND_SERVICE` rather than running as root, and applies a restrictive
sandbox (`ProtectSystem=strict`, `PrivateDevices`, `RestrictAddressFamilies`,
`NoNewPrivileges`).

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin trench
sudo mkdir -p /etc/trench
sudo cp trench.example.yaml /etc/trench/trench.yaml
sudo cp trench.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now trench
journalctl -u trench -f
```

State lives in `/var/lib/trench` (`StateDirectory=`), which is one of only
two paths the unit can write to.

### Freeing port 53

Most distributions have something on port 53 already:

```bash
sudo ss -ulpn 'sport = :53'                  # find out what
sudo systemctl disable --now systemd-resolved
```

If you disable `systemd-resolved`, replace `/etc/resolv.conf` with a real one
(`nameserver 127.0.0.1`) or the machine loses name resolution for itself.

## Docker Compose

```bash
cp trench.example.yaml trench.yaml
docker compose up -d
docker compose logs -f
```

The image carries its own healthcheck, which sends a real query over loopback
and requires a well-formed reply. It queries a name under `.invalid`, so an
upstream outage cannot turn into a restart loop — it reports on whether
Trench is answering, not on whether the internet is up.

## Raspberry Pi

Use `deploy/docker-compose.raspi.yml`, which adds what a small board needs:

```bash
docker compose -f deploy/docker-compose.raspi.yml up -d
```

The important differences are memory bounds:

```yaml
mem_limit: 700m
memswap_limit: 700m     # equal to mem_limit: no swap for this container
```

Without a limit, the memory spike during a blocklist rebuild lets the kernel's
OOM killer pick a victim anywhere on the host, which is how a 1 GB Pi locks up
instead of restarting one container. With the limit, the container is the only
thing that can die, and `restart: unless-stopped` brings it back. Swap is
disabled for the container deliberately: swapping a resolver onto an SD card
is worse than restarting it.

`deploy/README-raspi.md` has the full walkthrough, including blocklist choices
sized for the board.

### Blocklist size and memory

The list set is the main thing that decides the memory ceiling. HaGeZi's
`ultimate.txt` plus `tif.medium.txt` is roughly 750k rules and comfortable on
a 2 GB Pi; the full `tif.txt` alone is around 1.7M and is not. If Trench is
being OOM-killed, cut lists before anything else.

## Multiple workers

```yaml
server:
  workers: 0        # 0 = one per CPU
```

Do53 runs in every worker, with the kernel distributing datagrams across
pre-bound inherited sockets. The encrypted transports, the API, DHCP and the
scheduler run in the primary worker only. Counters and the block table are
shared across processes, so the console still reports whole-server numbers.

## Backups

```bash
trench backup /path/to/trench-$(date +%F).tar.gz
trench restore /path/to/trench-2026-08-19.tar.gz
```

The archive covers the data directory: the query-log database, users and API
tokens, custom rules, and zone data.

## Monitoring

Prometheus metrics are at `/metrics` and a liveness endpoint at `/healthz`;
neither requires authentication, so keep the console's port on a network you
trust. See [API](api.md).
