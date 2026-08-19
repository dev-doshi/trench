# Raspberry Pi deployment

Live at `/opt/dnsguard/deploy` on the Pi. Console: `http://<pi>:8089`.

```bash
cd /opt/dnsguard/deploy
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

1. **`workers: 0` (auto = 4).** Every worker holds its own compiled blocklist,
   so worker count multiplies memory. Now `workers: 1` (~257 MB total). A single
   worker benchmarks ~2.9k qps here — far beyond a home LAN.
2. **Rule objects per domain.** The filter engine stored a `Rule` object plus a
   list wrapper for every domain (~600 B each). Modifier-free rules — 99.9% of
   any blocklist — are now stored as `suffix -> source` strings and only
   materialized on an actual hit. Retained engine: **385 MB → 54 MB**.
3. **Simultaneous refreshes.** Every worker scheduled its own gravity refresh at
   the same moment, spiking N× together. Refreshes are now staggered per worker.

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

Then `reboot`. Afterwards `docker inspect dnsguard --format '{{.HostConfig.Memory}}'`
should report `734003200` instead of `0`. Until then, memory safety rests on the
sizing above rather than on enforcement.

## Bootstrap gotcha

The Pi resolves DNS *through this container*, so while it is stopped Docker
cannot reach the registry to pull or build. Before a rebuild:

```bash
cp /etc/resolv.conf /root/resolv.conf.bak
printf 'nameserver 9.9.9.9\n' > /etc/resolv.conf
# ... build / start ...
cp /root/resolv.conf.bak /etc/resolv.conf
```

(`/etc/resolv.conf` is managed by Tailscale here and will be rewritten anyway.)

## Rollback

```bash
docker tag dnsguard:rollback-20260726-185224 dnsguard:latest
cd /opt/dnsguard/deploy && docker compose -f docker-compose.raspi.yml up -d
```
Previous config: `/root/dnsguard-backups/dnsguard.yaml.*`; previous tree:
`/opt/dnsguard.old-20260726`.
