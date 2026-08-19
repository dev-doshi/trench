# CLI

Two commands are installed. `dnsguardd` is the server; `dnsguard` is the
client, and most of its subcommands talk to a running server's API.

```bash
dnsguard --version
dnsguard --help
```

Subcommands that reach the API take `--url` and `--token`. Generate a token in
the console under API access.

## Resolving

```bash
dnsguard query example.com                       # A over Do53
dnsguard query example.com AAAA
dnsguard query example.com A tls --server 9.9.9.9
dnsguard query example.com A https --server https://cloudflare-dns.com/dns-query
```

`--insecure` skips TLS verification, for testing against a self-signed
console or resolver.

## Operating a running server

```bash
dnsguard status --url http://127.0.0.1:8089 --token "$TOKEN"
dnsguard toggle         # blocking on/off
dnsguard flush-cache
dnsguard update         # refresh blocklists now
```

## Rules

```bash
dnsguard regex-test '||ads.example^' ads.example www.ads.example example.com
```

Prints what each name would do against that rule — the fastest way to check a
rule before committing it.

## Migrating in

```bash
dnsguard import pihole /etc/pihole/setupVars.conf
dnsguard import adguard /opt/AdGuardHome/AdGuardHome.yaml
```

## Zones and transfers

```bash
dnsguard keygen-tsig xfr.example.com.
dnsguard keygen-tsig xfr. --algorithm hmac-sha256 --bytes 32
```

Emits a key in the form both DNSGuard and the other server expect. Zone
transfers, NOTIFY and dynamic updates are all TSIG-authenticated.

## Client configuration

```bash
dnsguard stamp doh dns.example.com --path /dns-query     # sdns://...
dnsguard stamp dot dns.example.com --port 853
dnsguard profile --name "Home DNS" --doh-url https://dns.example.com/dns-query
```

`stamp` emits a DNS stamp for clients that take one. `profile` emits an Apple
`.mobileconfig` that points iOS and macOS at your encrypted resolver.

## On the box

These run against the data directory directly and do not need the server up —
which is the point, since one of them exists for when you cannot log in.

```bash
dnsguard passwd                                  # set the admin password
dnsguard passwd alice --role editor
dnsguard backup /backups/dnsguard-$(date +%F).tar.gz
dnsguard restore /backups/dnsguard-2026-08-19.tar.gz
```

## The server

```bash
dnsguardd --config /etc/dnsguard/dnsguard.yaml
dnsguardd --dns-port 5354 --upstream 1.1.1.1:53   # no config file
```

`SIGHUP` reloads the configuration and refreshes the lists without dropping
in-flight queries or rebinding sockets:

```bash
systemctl reload dnsguard      # or: kill -HUP $(pidof dnsguardd)
```
