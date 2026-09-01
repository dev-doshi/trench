"""ACME v2 (RFC 8555) client for automatic TLS certificates.

Because Trench *is* an authoritative DNS server, it can satisfy the `dns-01`
challenge by publishing the `_acme-challenge` TXT record in its own zone — no
inbound port 80, works behind NAT, and supports wildcards. The JWS/JWK/CSR
machinery here is pure `cryptography` (already a dependency); the network flow
is a thin async layer over aiohttp.

Offline-computable pieces (JWS signing, JWK thumbprint, the dns-01 digest, CSR
generation) are unit-tested directly; the order dance is exercised end to end
against an in-process directory that speaks the protocol back
(`tests/test_acme_flow.py`), which is what a live CA would do more slowly.

`obtain()` is the entry point. Everything under it was written before the flow
had a second half — the module could open an order and then had no way to answer
a challenge, finalize, or download the result — which is why nothing in the
package called it.
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

    async def new_order(self, domains: list[str]) -> tuple[str, dict]:
        """Open an order. Returns (order_url, order)."""
        d = await self.directory()
        payload = {"identifiers": [{"type": "dns", "value": x} for x in domains]}
        status, headers, body = await self._post(d["newOrder"], payload)
        if status not in (200, 201) or not headers.get("Location"):
            raise RuntimeError(f"ACME order refused (status {status}): {body}")
        return headers["Location"], body

    def dns_challenge_value(self, token: str) -> str:
        return dns01_txt(token, self.account.thumbprint())

    # ---- the rest of the order dance -------------------------------------
    # Everything above stops at "an order exists". Everything below is what
    # turns one into a certificate, and its absence is why nothing in the
    # package ever called any of this.

    async def _get(self, url: str):
        """POST-as-GET (RFC 8555 §6.3): reading an ACME resource is a signed
        POST with an empty body, not a GET."""
        return await self._post(url, "")

    def dns01_challenge(self, authorization: dict) -> Challenge:
        """The dns-01 challenge in one authorization."""
        for c in authorization.get("challenges", ()):
            if c.get("type") == "dns-01":
                return Challenge("dns-01", c["url"], c["token"])
        raise RuntimeError("the CA offered no dns-01 challenge for "
                           f"{authorization.get('identifier', {}).get('value', '?')}")

    async def answer(self, challenge: Challenge) -> None:
        """Tell the CA the record is published and it may check."""
        status, _, body = await self._post(challenge.url, {})
        if status not in (200, 202):
            raise RuntimeError(f"the CA refused the challenge (status {status}): {body}")

    async def poll(self, url: str, *, until: tuple[str, ...] = ("valid",),
                   timeout: float = 120.0, interval: float = 2.0) -> dict:
        """Poll a resource until its status settles.

        Bounded: a CA that never reaches a decision must not leave a renewal job
        pending for the life of the process.
        """
        import asyncio
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            _, _, body = await self._get(url)
            state = body.get("status") if isinstance(body, dict) else None
            if state in until:
                return body
            if state in ("invalid", "revoked", "deactivated", "expired"):
                raise RuntimeError(f"ACME resource {url} became {state}: {body}")
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError(f"ACME resource {url} stayed {state!r}")
            await asyncio.sleep(interval)

    async def finalize(self, order_url: str, order: dict, csr_der: bytes) -> str:
        """Submit the CSR and return the issued chain, PEM."""
        status, _, body = await self._post(order["finalize"], {"csr": b64url(csr_der)})
        if status not in (200, 202):
            raise RuntimeError(f"the CA refused the CSR (status {status}): {body}")
        order = await self.poll(order_url)
        cert_url = order.get("certificate")
        if not cert_url:
            raise RuntimeError("the order is valid but names no certificate")
        _, _, chain = await self._post(cert_url, "")
        if not isinstance(chain, str) or "BEGIN CERTIFICATE" not in chain:
            raise RuntimeError("the CA returned something that is not a certificate")
        return chain

    async def obtain(self, domains: list[str], publish_txt, *,
                     email: str | None = None, unpublish_txt=None,
                     settle: float = 0.0) -> tuple[str, bytes]:
        """Run the whole dns-01 flow. Returns (certificate_chain_pem, key_pem).

        `publish_txt(name, value)` puts the challenge record into whatever zone
        the caller owns — for Trench that is its own authoritative zone, which
        is what makes dns-01 the right challenge here: no inbound port 80, works
        behind NAT, and wildcards are possible.

        `settle` is how long to wait after publishing before telling the CA to
        look. Zero is right when we are the authoritative server being asked;
        a delegated setup with secondaries needs enough for the transfer.
        """
        import asyncio
        if not self.account.kid:
            await self.register(email)
        order_url, order = await self.new_order(domains)
        published: list[str] = []
        try:
            for auth_url in order.get("authorizations", ()):
                _, _, auth = await self._get(auth_url)
                if auth.get("status") == "valid":
                    continue                    # already authorized, still cached
                challenge = self.dns01_challenge(auth)
                name = f"_acme-challenge.{auth['identifier']['value']}"
                value = self.dns_challenge_value(challenge.token)
                await publish_txt(name, value)
                published.append(name)
                if settle:
                    await asyncio.sleep(settle)
                await self.answer(challenge)
                await self.poll(auth_url)
            csr_der, key_pem = make_csr(domains)
            chain = await self.finalize(order_url, order, csr_der)
            return chain, key_pem
        finally:
            # The challenge record proves nothing once the order is decided, and
            # leaving it in a zone that answers the whole LAN is untidy at best.
            if unpublish_txt is not None:
                for name in published:
                    try:
                        await unpublish_txt(name)
                    except Exception:  # noqa: BLE001 — cleanup must not mask the result
                        pass

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
