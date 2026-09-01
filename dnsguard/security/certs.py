"""Automatic TLS certificates: the lifecycle around the ACME client.

`security/acme.py` speaks the protocol; this decides when to speak it, where to
publish the challenge, and what to do with the result. The two were never joined
up, so a complete RFC 8555 implementation sat in the package with no caller, no
config field and no scheduled job — finished-looking, and unreachable.

dns-01 is the challenge used, and it is the reason this belongs in DNSGuard at
all: the box already runs an authoritative zone server, so it can publish
`_acme-challenge` in its own zone. No inbound port 80, nothing to expose to the
internet, and wildcards are possible. The cost is that it only works for a name
in a zone this server is actually authoritative for — which is why
`AcmeManager.reason_unavailable` exists and why the config is off by default.
"""
from __future__ import annotations

import time
from pathlib import Path

from ..log import get
from ..wire import rdata as R
from ..wire.name import Name
from ..wire.rrtypes import Type
from .acme import ACMEAccount, ACMEClient

log = get("acme")

#: Renew this far before expiry. Let's Encrypt issues for 90 days and recommends
#: renewing at 30 remaining, which leaves a month of failed attempts before
#: anything actually breaks.
RENEW_BEFORE_DAYS = 30

#: How long a challenge TXT record lives. Short, because it is answered by this
#: server directly and is meaningless the moment the order is decided.
CHALLENGE_TTL = 60


class AcmeManager:
    """Owns the account key, the issued certificate, and the renewal decision."""

    def __init__(self, config, zones, data_dir: Path):
        self.config = config
        self.zones = zones
        self.data_dir = Path(data_dir)
        self._running = False

    # ---- paths ----
    @property
    def account_key(self) -> Path:
        return self.data_dir / "acme-account.key"

    @property
    def cert_file(self) -> Path:
        return self.data_dir / "acme.crt"

    @property
    def key_file(self) -> Path:
        return self.data_dir / "acme.key"

    # ---- preconditions ----
    def reason_unavailable(self) -> str | None:
        """Why this cannot work here, in one sentence, or None if it can.

        Checked before anything is attempted and reported once at start-up: a
        misconfigured ACME setup should say so while the operator is looking,
        not fail silently every twelve hours.
        """
        c = self.config.acme
        if not c.domains:
            return "acme.domains is empty"
        for domain in c.domains:
            name = Name.from_text(f"_acme-challenge.{domain}")
            if self.zones.authoritative_for(name) is None:
                return (f"this server is not authoritative for {domain}; dns-01 "
                        f"needs a zone here that can publish "
                        f"_acme-challenge.{domain}")
        return None

    # ---- the zone side of dns-01 ----
    async def _publish(self, name: str, value: str) -> None:
        owner = Name.from_text(name)
        zone = self.zones.authoritative_for(owner)
        if zone is None:
            raise RuntimeError(f"no zone here is authoritative for {name}")
        self._clear(owner, zone)
        zone.add(owner, int(Type.TXT), R.TXT([value.encode()]), ttl=CHALLENGE_TTL)
        log.info("published dns-01 challenge for %s", name)

    async def _unpublish(self, name: str) -> None:
        owner = Name.from_text(name)
        zone = self.zones.authoritative_for(owner)
        if zone is not None:
            self._clear(owner, zone)

    @staticmethod
    def _clear(owner: Name, zone) -> None:
        node = zone.records.get(owner)
        if node is None:
            return
        node.pop(int(Type.TXT), None)
        if not node:
            zone.records.pop(owner, None)
        zone.ttls.pop((owner, int(Type.TXT)), None)

    # ---- certificate state ----
    def expires_in_days(self) -> float | None:
        """Days until the stored certificate expires, or None if there is none."""
        if not self.cert_file.exists():
            return None
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(self.cert_file.read_bytes())
            return (cert.not_valid_after_utc.timestamp() - time.time()) / 86400
        except Exception:  # noqa: BLE001 — an unreadable certificate is a missing one
            log.warning("could not read %s; treating it as absent", self.cert_file)
            return None

    def due(self) -> bool:
        left = self.expires_in_days()
        return left is None or left <= RENEW_BEFORE_DAYS

    # ---- the flow ----
    def _account(self) -> ACMEAccount:
        if self.account_key.exists():
            return ACMEAccount.from_pem(self.account_key.read_bytes())
        account = ACMEAccount()
        self._write_private(self.account_key, account.to_pem())
        log.info("generated a new ACME account key at %s", self.account_key)
        return account

    @staticmethod
    def _write_private(path: Path, data: bytes) -> None:
        """Write key material readable only by this account, and atomically.

        A half-written key is indistinguishable from a corrupt one on the next
        start, and a mode-0644 key is worse than no automation at all.
        """
        import os
        tmp = path.with_suffix(path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)

    async def renew(self, *, force: bool = False) -> bool:
        """Obtain a certificate if one is due. True when a new one was written."""
        why = self.reason_unavailable()
        if why is not None:
            log.warning("automatic certificates are configured but cannot run: %s", why)
            return False
        if not force and not self.due():
            return False
        c = self.config.acme
        client = ACMEClient(self._account(), c.directory)
        try:
            chain, key_pem = await client.obtain(
                list(c.domains), self._publish, email=c.email or None,
                unpublish_txt=self._unpublish, settle=c.settle)
        except Exception:
            log.exception("certificate renewal failed; the existing one is untouched")
            return False
        finally:
            await client.close()
        # The key first: a certificate on disk without its key is the one
        # combination that breaks a restart, and the key alone is harmless.
        self._write_private(self.key_file, key_pem)
        self.cert_file.write_text(chain)
        if client.account.kid and not self.account_key.exists():
            self._write_private(self.account_key, client.account.to_pem())
        left = self.expires_in_days()
        log.info("obtained a certificate for %s (%s days)",
                 ", ".join(c.domains), f"{left:.0f}" if left else "?")
        return True
