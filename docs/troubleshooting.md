# Troubleshooting

Turn the log up first — most of these announce themselves:

```yaml
log:
  level: debug
```

## Nothing answers on port 53

Something else already has it:

```bash
sudo ss -ulpn 'sport = :53'
```

On most distributions that is `systemd-resolved`. Disable it, then give the
machine a working `/etc/resolv.conf` (`nameserver 127.0.0.1`) or it loses name
resolution for itself.

Binding port 53 also needs privilege. Run under the shipped systemd unit
(which grants `CAP_NET_BIND_SERVICE` without root), or start as root with
`server.user` set so Trench drops straight after binding.

## Everything resolves but nothing is blocked

Check what actually compiled:

```
INFO trench.app: blocked domains: 0
```

Zero means no list loaded. Either `filtering.sources` is empty, or the fetches
failed — the log names each source and its error. `trench update` forces a
refresh; a local path is resolved relative to the working directory, falling
back to the copy shipped inside the package.

Also confirm the client is actually using Trench. Browsers with DoH enabled
bypass system DNS entirely, and phones roam onto cellular:

```bash
dig @127.0.0.1 -p 5354 doubleclick.net     # expect 0.0.0.0
```

## A site is broken and it is our fault

```bash
trench regex-test '||example.com^' www.example.com
```

The console's collateral-damage view lists names that recently started failing
in a way that looks like a block rather than an outage. Add an allow rule
(`@@||name^`) rather than removing the whole list.

If it appeared right after a list refresh, the list-update review shows the
refresh replayed as a diff over names actually queried on this network, so you
can see what a given update newly blocks.

## Legitimate names flagged as malware

If `dga_block` or `tunnel_block` is on, they will occasionally be wrong: these
are lexical scores, and WiFi calling, some CDNs and several consumer devices
produce names that look exactly like algorithm-generated ones. Set both to
`false`, watch what gets flagged on your own network, then decide.

## Resolution fails after enabling DNSSEC

```yaml
upstream:
  dnssec: true
```

means a badly signed zone is a failure rather than a warning — which is the
point, but some zones really are broken. The log names the zone and the reason.
Confirm with a validator you trust before assuming it is Trench.

## The Pi locks up, or the container keeps restarting

Almost always memory, during a blocklist rebuild. Use
`deploy/docker-compose.raspi.yml`, which caps the container so the OOM killer
cannot pick victims elsewhere on the host, and cut lists: HaGeZi `ultimate` +
`tif.medium` is about 750k rules and fits comfortably; the full `tif` is around
1.7M and does not.

## Locked out of the console

```bash
trench passwd            # offline, on the box
```

The first-start password is written once to `initial-admin-password` in the data
directory, mode 0600, and the log records the path rather than the password —
under systemd and Docker the log *is* stdout, so printing it there would put it
in the journal. Read it, then delete the file.

If two-factor is the problem, add `--clear-totp`: a password reset on its own
leaves the second factor in place, so the reset appears to work and the next
login still fails.

```bash
trench passwd admin --clear-totp
```

## The container reports unhealthy

The healthcheck sends a real query over loopback and requires a well-formed
reply. It queries a `.invalid` name, so an upstream outage does not fail it —
unhealthy means Trench itself has stopped answering.

```bash
docker logs trench
docker exec trench python3 /usr/local/bin/trench-healthcheck; echo $?
```

## Slower than expected

```bash
python3 scripts/bench.py --quick
```

The fast path is skipped entirely when a plugin is active or when ECS is set
to anything but `off`/`strip` — both make a recorded answer unsafe to replay
to another client.

## Reporting a bug

Include the version, how it is deployed, the query that shows it and the
answer you got. For anything on the wire, a packet capture is worth more than
a description. Never report a vulnerability in a public issue — see
[Security](security.md).
