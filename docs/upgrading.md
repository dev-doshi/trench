# Upgrading

## Back up first

```bash
trench backup /backups/trench-$(date +%F).tar.gz
```

The archive covers the whole data directory: query log, users and API tokens,
custom rules and zone data. Restoring is `trench restore <archive>`.

## Versioning

Trench follows semantic versioning. Within a major version, configuration
files keep working and the database migrates itself forward on first start.
Anything that changes defaults or on-the-wire behaviour is called out in
[the changelog](https://github.com/dev-doshi/trench/blob/main/CHANGELOG.md).

## From GitHub

Let Trench do it — it checks
[GitHub Releases](https://github.com/dev-doshi/trench/releases), verifies the
wheel's sha256 and smoke-tests it before installing:

```bash
trench upgrade apply
systemctl restart trench
journalctl -u trench -n 50
```

Or by hand, into the same virtual environment it was installed into:

```bash
/opt/trench/bin/pip install --upgrade "git+https://github.com/dev-doshi/trench@v2.1.0"
systemctl restart trench
```

From a checkout, `git pull && pip install -e .` instead.

## Docker

```bash
docker compose pull
docker compose up -d
```

Pin a version rather than tracking `latest` on anything you depend on:

```yaml
image: ghcr.io/dev-doshi/trench:2.0.0
```

## Database migrations

Migrations run automatically at startup and are logged:

```
INFO trench.db: applied migration 5: blocklist update reviews
```

They only move forward. Downgrading after a migration needs the backup you
took before upgrading — which is why that step is first.

## After upgrading

Check the startup log for warnings. New releases can add checks against your
existing configuration, and those surface as warnings rather than failures:

```bash
journalctl -u trench -n 50 | grep WARN
```
