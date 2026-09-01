# Configuration

Trench reads a single pydantic-validated YAML file (`--config`). Every key is
optional; see [`trench.example.yaml`](https://github.com/trench/trench/blob/main/trench.example.yaml)
for the full annotated default.

## Filtering rules

Sources may be hosts files, plain domain lists, dnsmasq `address=/d/`, RPZ zones,
or Adblock-DNS syntax. Supported Adblock modifiers:

| Modifier | Effect |
|---|---|
| `$important` | beats allow exceptions |
| `$badfilter` | disables a matching rule |
| `$dnstype=A\|AAAA` | restrict to record types |
| `$denyallow=d1\|d2` | carve out exceptions |
| `$dnsrewrite=1.2.3.4` | forge a response (`;`-form, `REFUSED`, `NXDOMAIN`, CNAME) |
| `$ctag=` / `$client=` | gate by client tag/identity |

## Per-client policy

```yaml
clients:
  - {ident: 192.168.1.50, type: ip, name: tablet, safe_search: true,
     parental: true, services: [youtube, tiktok]}
  - {ident: 192.168.1.0/24, type: cidr, name: lan, tags: [household]}
```

Identity precedence: ClientID → exact IP → CIDR → MAC → default.

## Authoritative + DNSSEC

```yaml
zones:
  - {origin: home.lan., file: /etc/trench/home.zone, dnssec: true}
local_records:
  - {name: nas.home.lan, type: A, answer: 192.168.1.10}
```

`dnssec: true` online-signs the zone (ECDSA P-256); the DS for the parent is logged.
