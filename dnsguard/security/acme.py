"""ACME v2 (RFC 8555) client for automatic TLS certificates.

Because DNSGuard *is* an authoritative DNS server, it can satisfy the `dns-01`
challenge by publishing the `_acme-challenge` TXT record in its own zone — no
inbound port 80, works behind NAT, and supports wildcards. The JWS/JWK/CSR
machinery here is pure `cryptography` (already a dependency); the network flow
is a thin async layer over aiohttp.

Offline-computable pieces (JWS signing, JWK thumbprint, the dns-01 digest, CSR
generation) are unit-tested directly; the full order dance needs a live ACME CA
(Let's Encrypt / Pebble) and is exercised in integration only.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

LETSENCRYPT = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class ACMEAccount:
    """An ACME account key (ECDSA P-256, JWS alg ES256)."""

    def __init__(self, private_key=None):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.key = private_key or ec.generate_private_key(ec.SECP256R1())
        self.kid: str | None = None            # account URL, set after registration

    @classmethod
    def from_pem(cls, pem: bytes) -> ACMEAccount:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        return cls(load_pem_private_key(pem, password=None))

    def to_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())

    def jwk(self) -> dict:
        nums = self.key.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256",
                "x": b64url(nums.x.to_bytes(32, "big")),
                "y": b64url(nums.y.to_bytes(32, "big"))}

    def thumbprint(self) -> str:
        """RFC 7638 JWK thumbprint (canonical JSON, sorted keys, no whitespace)."""
        jwk = self.jwk()
        canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"],
                            "x": jwk["x"], "y": jwk["y"]},
                           separators=(",", ":"), sort_keys=True).encode()
        return b64url(hashlib.sha256(canon).digest())

    def _sign(self, signing_input: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        der = self.key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")   # JWS wants raw R||S

    def jws(self, url: str, nonce: str, payload: dict | str) -> dict:
        """Build a flattened JWS for `payload` to `url`. Uses `kid` once the
        account is registered, otherwise embeds the `jwk` (for newAccount)."""
        protected = {"alg": "ES256", "nonce": nonce, "url": url}
        if self.kid:
            protected["kid"] = self.kid
        else:
            protected["jwk"] = self.jwk()
        p64 = b64url(json.dumps(protected, separators=(",", ":")).encode())
        if payload == "":
            body64 = ""                                        # POST-as-GET
        else:
            body64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
        sig = self._sign(f"{p64}.{body64}".encode())
        return {"protected": p64, "payload": body64, "signature": b64url(sig)}


def dns01_txt(token: str, thumbprint: str) -> str:
    """The `_acme-challenge` TXT value for a dns-01 challenge."""
    key_auth = f"{token}.{thumbprint}".encode()
    return b64url(hashlib.sha256(key_auth).digest())


def http01_keyauth(token: str, thumbprint: str) -> str:
    """The body served at /.well-known/acme-challenge/<token> for http-01."""
    return f"{token}.{thumbprint}"


def make_csr(domains: list[str], key=None):
    """Generate a PKCS#10 CSR (SAN list) and its private key. Returns
    (csr_der, key_pem)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    if not domains:
        raise ValueError("at least one domain required")
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False)
    csr = builder.sign(key, hashes.SHA256())
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return csr.public_bytes(serialization.Encoding.DER), key_pem


@dataclass
class Challenge:
    typ: str
    url: str
    token: str


class ACMEClient:
    """Async ACME order flow. `set_dns_txt(name, value)` is injected so the
    caller can publish the challenge in whatever zone backend they own."""

    def __init__(self, account: ACMEAccount, directory_url: str = LETSENCRYPT_STAGING,
                 *, session=None):
        self.account = account
        self.directory_url = directory_url
        self._session = session
        self._dir: dict | None = None
        self._nonce: str | None = None

    async def _http(self):
        if self._session is None:
            import aiohttp
            self._session = aiohttp.ClientSession()
        return self._session

    async def directory(self) -> dict:
        if self._dir is None:
            s = await self._http()
            async with s.get(self.directory_url) as r:
                self._dir = await r.json()
        return self._dir

    async def _new_nonce(self) -> str:
        d = await self.directory()
        s = await self._http()
        async with s.head(d["newNonce"]) as r:
            return r.headers["Replay-Nonce"]

    async def _post(self, url: str, payload):
        s = await self._http()
        if self._nonce is None:
            self._nonce = await self._new_nonce()
        body = self.account.jws(url, self._nonce, payload)
        async with s.post(url, json=body,
                          headers={"Content-Type": "application/jose+json"}) as r:
            self._nonce = r.headers.get("Replay-Nonce", self._nonce)
            data = await r.json() if r.content_type.endswith("json") else await r.text()
            return r.status, dict(r.headers), data

    async def register(self, email: str | None = None) -> str:
        d = await self.directory()
        payload = {"termsOfServiceAgreed": True}
        if email:
            payload["contact"] = [f"mailto:{email}"]
        status, headers, body = await self._post(d["newAccount"], payload)
        # The status was fetched and then ignored. A rejection — rate limit, ToS
        # change, bad nonce — left kid None, and every later _post silently fell
        # back to embedding the raw JWK as if this were still newAccount, so the
        # real failure surfaced later as a confusing CA error on the order.
        if status not in (200, 201) or not headers.get("Location"):
            raise RuntimeError(f"ACME account registration refused "
                               f"(status {status}): {body}")
        self.account.kid = headers.get("Location")
        return self.account.kid

    async def new_order(self, domains: list[str]):
        d = await self.directory()
        payload = {"identifiers": [{"type": "dns", "value": x} for x in domains]}
        return await self._post(d["newOrder"], payload)

    def dns_challenge_value(self, token: str) -> str:
        return dns01_txt(token, self.account.thumbprint())

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
