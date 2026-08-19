# Upgrading

## Back up first

```bash
dnsguard backup /backups/dnsguard-$(date +%F).tar.gz
```

The archive covers the whole data directory: query log, users and API tokens,
custom rules and zone data. Restoring is `dnsguard restore <archive>`.

## Versioning

DNSGuard follows semantic versioning. Within a major version, configuration
files keep working and the database migrates itself forward on first start.
Anything that changes defaults or on-the-wire behaviour is called out in
[the changelog](https://github.com/dev-doshi/dnsguard/blob/main/CHANGELOG.md).

## pip

```bash
pip install --upgrade dnsguard
systemctl restart dnsguard
journalctl -u dnsguard -n 50
```

## Docker

```bash
docker compose pull
docker compose up -d
```

Pin a version rather than tracking `latest` on anything you depend on:

```yaml
image: ghcr.io/dev-doshi/dnsguard:2.0.0
```

## Database migrations

Migrations run automatically at startup and are logged:

```
INFO dnsguard.db: applied migration 5: blocklist update reviews
```

They only move forward. Downgrading after a migration needs the backup you
took before upgrading — which is why that step is first.

## After upgrading

Check the startup log for warnings. New releases can add checks against your
existing configuration, and those surface as warnings rather than failures:

```bash
journalctl -u dnsguard -n 50 | grep WARN
```
