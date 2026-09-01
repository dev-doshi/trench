# CLI

Two commands are installed. `trenchd` is the server; `trench` is the
client, and most of its subcommands talk to a running server's API.

```bash
trench --version
trench --help
```

Subcommands that reach the API take `--url` and `--token`. Create a token in the
console under **Settings → Access**; it is shown once, when you create it.
Choose the narrowest scope that works — `viewer` is enough for `status`, and
`editor` for `toggle`, `flush-cache` and `update`.

## Resolving

```bash
trench query example.com                       # A over Do53
trench query example.com AAAA
trench query example.com A tls --server 9.9.9.9
trench query example.com A https --server https://cloudflare-dns.com/dns-query
```

`--insecure` skips TLS verification, for testing against a self-signed
console or resolver.

## Operating a running server

```bash
trench status --url http://127.0.0.1:8089 --token "$TOKEN"
trench toggle         # blocking on/off
trench flush-cache
trench update         # refresh blocklists now
trench pause 5m       # stop filtering for a while; expires by itself
trench pause 30m --client 192.168.1.50    # just that device
trench pause 0        # resume now
```

## Why did this name do that?

```bash
trench why ads.example
trench why bank.example --client 192.168.1.50 --resolve
trench why shop.example --json
```

One verdict, with the evidence under it: which rule from which list blocked it,
whether a blocked service or a protection category covers it, what is in the
cache, what the log has seen, whether the device that complained is still
asking this resolver at all, and — with `--resolve` — what happens when the
name is resolved right now, including the RFC 8914 reason if one comes back.

## Updating Trench itself

```bash
trench upgrade status        # what is installed, what is available
trench upgrade check         # ask the release index now
trench upgrade apply         # install the newest release
trench upgrade apply --version 2.1.0
trench upgrade rollback      # go back to the previous version
```

These talk to the running daemon rather than doing the work in the shell, so
the daemon's judgement about whether this installation may update itself
cannot be sidestepped by running the command as someone else.

`trench update` still means "refresh the blocklists", as it has since 1.x —
hence `upgrade` for the software.

What applying does and does not do: it downloads the artifact, checks its
sha256 against the index, proves the new build imports and validates the live
configuration inside a throwaway environment, and only then installs. The
running process is not touched, so resolution and filtering continue across
the whole of that, and an install is refused outright while a blocklist build
is in flight. **The restart afterwards is a real restart.** It is short — the
listening sockets are pre-bound and inherited, and the compiled block table is
mapped from disk rather than recompiled, so the server never comes back up
resolving unfiltered — but there is a gap. With systemd socket activation
holding the listeners there is no gap at all, because the kernel queues
datagrams across the restart.

It refuses, with the reason, on any installation Trench does not own: a
container image (rebuild or pull it), a distribution package (that is the
package manager's job) and a source checkout (that is yours).

## Rules

```bash
trench regex-test '||ads.example^' ads.example www.ads.example example.com
```

Prints what each name would do against that rule — the fastest way to check a
rule before committing it.

## Migrating in

```bash
trench import pihole /etc/pihole/setupVars.conf
trench import adguard /opt/AdGuardHome/AdGuardHome.yaml
```

## Zones and transfers

```bash
trench keygen-tsig xfr.example.com.
trench keygen-tsig xfr. --algorithm hmac-sha256 --bytes 32
```

Emits a key in the form both Trench and the other server expect. Zone
transfers, NOTIFY and dynamic updates are all TSIG-authenticated.

## Client configuration

```bash
trench stamp doh dns.example.com --path /dns-query     # sdns://...
trench stamp dot dns.example.com --port 853
trench profile --name "Home DNS" --doh-url https://dns.example.com/dns-query
```

`stamp` emits a DNS stamp for clients that take one. `profile` emits an Apple
`.mobileconfig` that points iOS and macOS at your encrypted resolver.

## On the box

These run against the data directory directly and do not need the server up —
which is the point, since one of them exists for when you cannot log in.

```bash
trench passwd                                  # set the admin password
trench passwd alice --role editor
trench backup /backups/trench-$(date +%F).tar.gz
trench restore /backups/trench-2026-08-19.tar.gz
```

## The server

```bash
trenchd --config /etc/trench/trench.yaml
trenchd --dns-port 5354 --upstream 1.1.1.1:53   # no config file
```

`SIGHUP` reloads the configuration and refreshes the lists without dropping
in-flight queries or rebinding sockets:

```bash
systemctl reload trench      # or: kill -HUP $(pidof trenchd)
```
