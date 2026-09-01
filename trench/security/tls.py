"""TLS context construction + self-signed certificate generation.

DoT/DoH/DoQ all need a server certificate. If the operator hasn't supplied one,
we mint a self-signed cert into <data_dir>/certs so encrypted transports work
out of the box for local/dev use (ACME issuance arrives in P7)."""
from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
from pathlib import Path

from ..log import get

log = get("tls")


def generate_self_signed(cert_path: Path, key_path: Path,
                         hostnames: list[str] | None = None) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    hostnames = hostnames or ["localhost"]
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])

    alt_names: list[x509.GeneralName] = []
    for h in hostnames:
        try:
            alt_names.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            alt_names.append(x509.DNSName(h))

    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    # Created 0600 *before* anything is written to it. This key terminates DoT,
    # DoH, DoQ and the admin console; at the default umask it landed 0644, so
    # after the privilege drop any local account could read it and impersonate
    # the resolver. os.open with the mode avoids the window a later chmod
    # would leave.
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)     # a pre-existing file keeps its old mode otherwise
    log.info("generated self-signed cert at %s", cert_path)


def ensure_cert(cert: str | None, key: str | None, data_dir: Path,
                hostnames: list[str] | None = None) -> tuple[Path, Path]:
    if cert and key:
        return Path(cert), Path(key)
    certs = data_dir / "certs"
    cert_path = certs / "trench.crt"
    key_path = certs / "trench.key"
    if not (cert_path.exists() and key_path.exists()):
        generate_self_signed(cert_path, key_path, hostnames)
    return cert_path, key_path


def server_ssl_context(cert: str | None, key: str | None, *, data_dir: Path,
                       alpn: list[str], hostnames: list[str] | None = None) -> ssl.SSLContext:
    cert_path, key_path = ensure_cert(cert, key, data_dir, hostnames)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx
