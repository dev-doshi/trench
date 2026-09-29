# Raspberry Pi deployment

Live at `/opt/trench/deploy` on the Pi. Console: `http://<pi>:8089`.

```bash
cd /opt/trench/deploy
docker compose -f docker-compose.raspi.yml up -d      # start / apply config
docker compose -f docker-compose.raspi.yml logs -f    # follow logs
docker compose -f docker-compose.raspi.yml restart
```

## Blocklists — why these four

HaGeZi publishes overlapping lists; stacking them wastes memory without
blocking anything extra. Measured overlap against `ultimate.txt`:

| List | Entries | New vs Ultimate | Kept |
|---|---:|---:|:--:|
| `ultimate.txt` | 293k | — (base) | ✅ |
| `tif.medium.txt` | 398k | **+307k (77%)** | ✅ |
| `doh-vpn-proxy-bypass.txt` | 18k | **+16k (91%)** | ✅ |
| `dyndns.txt` | 1.5k | **+1.1k (73%)** | ✅ |
| `pro.plus.txt` | 273k | +5k (2%) | ❌ contained in Ultimate |
| `popupads.txt` | 57k | +768 (1%) | ❌ |
| `fake.txt` | 17k | **+16 domains** | ❌ |
| `native.*.txt` (5 lists) | — | already in Ultimate | ❌ |

Result: **617,530 block domains** from 4 sources instead of 11.

## Memory — the binding constraint

This board has 955 MB. The previous deployment was OOM-killed repeatedly
(`dmesg` showed workers at 592 MB and 793 MB anon-rss). Three causes, all fixed:

1. **`workers: 0` (auto = 4).** Every worker held its own compiled blocklist,
   so worker count multiplied memory. The blocklist is now one file-backed
   shared table, built once by the supervisor before it forks and mapped by
   every worker. Each extra worker still costs its interpreter, caches and
   upstream connections (~100 MB), and on a 1 GB board shared with other
   services that is swap. `raspi.yaml` runs `workers: 1`; a home LAN does not
   need more.
2. **Rule objects per domain.** The filter engine stored a `Rule` object plus a
   list wrapper for every domain (~600 B each). Modifier-free rules — 99.9% of
   any blocklist — are now stored as `suffix -> source` strings and only
   materialized on an actual hit. Retained engine: **385 MB → 54 MB**.
3. **Simultaneous builds.** Every worker ran its own gravity refresh, spiking
   N× together. Now only the primary worker downloads and compiles, one build
   at a time (the refresh schedule, SIGHUP, a settings change and the cold-start
   fetch all share one lock), and the others re-map the table it writes. That
   includes a first boot with no cached table: the siblings serve unfiltered
   until the primary's table lands (they check every 30 s), rather than
   compiling four copies at once.

Verified: triggering a full blocklist refresh dips free memory by only ~75 MB
(446 MB still available) and recovers.

### Hard limit is NOT active
`docker-compose.raspi.yml` sets `mem_limit: 700m`, but this kernel reports
*"Your kernel does not support memory limit capabilities"* — Raspberry Pi OS
ships with the memory cgroup disabled. Without it, an overrun lets the kernel
OOM-killer pick victims anywhere on the host (which is how the Pi froze).

To enable the safety net (**requires a reboot**), append to the single line in
`/boot/firmware/cmdline.txt`:

```
cgroup_enable=memory cgroup_memory=1
```

Then `reboot`. Afterwards `docker inspect trench --format '{{.HostConfig.Memory}}'`
should report `734003200` instead of `0`. Until then, memory safety rests on the
sizing above rather than on enforcement.

## Running as `trench`

`raspi.yaml` sets `server.user: trench`: the process binds :53 as root and then
becomes uid/gid 1000. The container has every capability dropped, so even
before the drop its root cannot open a file it does not own or reach through
its mode. Files in the data volume must therefore be owned by root, group 1000,
and group-writable; the directory is already `root:trench 2775`, so anything
created later inherits the group. After restoring a backup into the volume:

```bash
V=/var/lib/docker/volumes/deploy_trench-data/_data
chown 0:1000 $V/* && chmod 660 $V/*
chown 0:1000 /opt/trench/deploy/raspi.yaml && chmod 664 /opt/trench/deploy/raspi.yaml
```

The database is re-tightened to 0600 on start, which is fine with one worker:
it is opened before the drop and kept open. Sibling workers open it read-only
after the drop and cannot, which is one more reason this board runs one.

## Bootstrap gotcha

The Pi resolves DNS *through this container*, so while it is stopped Docker
cannot reach the registry to pull or build. (Builds used to fail while it was
running too: containers on the Docker bridge were answered from the bridge
address and discarded the reply. Fixed in the Do53 transport.) Before a
rebuild with the container stopped:

```bash
cp /etc/resolv.conf /root/resolv.conf.bak
printf 'nameserver 9.9.9.9\n' > /etc/resolv.conf
# ... build / start ...
cp /root/resolv.conf.bak /etc/resolv.conf
```

(`/etc/resolv.conf` is managed by Tailscale here and will be rewritten anyway.)

## Rollback

```bash
docker tag trench:rollback-20260726-185224 trench:latest
cd /opt/trench/deploy && docker compose -f docker-compose.raspi.yml up -d
```
Previous config: `/root/trench-backups/trench.yaml.*`; previous tree:
`/opt/trench.old-20260726`.
