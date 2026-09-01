"""The ACME order flow, end to end against an in-process directory.

The client could open an order and then stop: there was no way to answer a
challenge, finalize, or download the result, which is why nothing in the package
ever called any of it. A live CA is the only other way to exercise the second
half, and a live CA is slow, rate-limited and unavailable in CI — so the CA is
here, speaking the protocol back.
"""
from __future__ import annotations

import json
import socket

import aiohttp
import pytest
from aiohttp import web

from trench.auth_zone import Zone, ZoneStore
from trench.config import Config
from trench.security.acme import ACMEAccount, ACMEClient, dns01_txt
from trench.security.certs import AcmeManager
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Type

CERT_PEM = ("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


class FakeCA:
    """Enough of RFC 8555 to be answered correctly, and to notice if we are not.

    It checks what a real CA checks: that the account registered, that the
    challenge was answered only after the record was published, and that the
    finalize carried a CSR.
    """

    def __init__(self, base: str, published: dict[str, str]):
        self.base = base
        self.published = published        # the "DNS" the CA resolves against
        self.registered = False
        self.answered: list[str] = []
        self.csr_seen = False
        self.auth_status = "pending"
        self.order_status = "pending"

    def app(self) -> web.Application:
        a = web.Application()
        a.router.add_get("/directory", self.directory)
        a.router.add_route("*", "/nonce", self.nonce)
        a.router.add_post("/new-account", self.new_account)
        a.router.add_post("/new-order", self.new_order)
        a.router.add_post("/authz/1", self.authz)
        a.router.add_post("/chall/1", self.challenge)
        a.router.add_post("/finalize", self.finalize)
        a.router.add_post("/order/1", self.order)
        a.router.add_post("/cert/1", self.cert)
        return a

    @staticmethod
    def _payload(body: dict) -> dict:
        import base64
        raw = body["payload"]
        if raw == "":
            return {}
        pad = "=" * (-len(raw) % 4)
        return json.loads(base64.urlsafe_b64decode(raw + pad))

    def _hdrs(self, **extra):
        return {"Replay-Nonce": "nonce-2", **extra}

    async def directory(self, r):
        return web.json_response({
            "newNonce": f"{self.base}/nonce",
            "newAccount": f"{self.base}/new-account",
            "newOrder": f"{self.base}/new-order",
        })

    async def nonce(self, r):
        return web.Response(headers={"Replay-Nonce": "nonce-1"})

    async def new_account(self, r):
        self.registered = True
        return web.json_response({"status": "valid"}, status=201,
                                 headers=self._hdrs(Location=f"{self.base}/acct/1"))

    async def new_order(self, r):
        payload = self._payload(await r.json())
        assert payload["identifiers"], "an order must name an identifier"
        return web.json_response(
            {"status": "pending",
             "authorizations": [f"{self.base}/authz/1"],
             "finalize": f"{self.base}/finalize"},
            status=201, headers=self._hdrs(Location=f"{self.base}/order/1"))

    async def authz(self, r):
        return web.json_response(
            {"status": self.auth_status,
             "identifier": {"type": "dns", "value": "dns.example.org"},
             "challenges": [
                 {"type": "http-01", "url": f"{self.base}/chall/http",
                  "token": "unused"},
                 {"type": "dns-01", "url": f"{self.base}/chall/1",
                  "token": "tok-abc"},
             ]},
            headers=self._hdrs())

    async def challenge(self, r):
        # A real CA resolves the record now. If it is not there, the
        # authorization fails — which is the bug this ordering prevents.
        name = "_acme-challenge.dns.example.org"
        assert name in self.published, "the challenge was answered before publishing"
        self.answered.append(name)
        self.auth_status = "valid"
        self.order_status = "ready"
        return web.json_response({"status": "valid"}, headers=self._hdrs())

    async def finalize(self, r):
        payload = self._payload(await r.json())
        assert payload.get("csr"), "finalize must carry a CSR"
        self.csr_seen = True
        self.order_status = "valid"
        return web.json_response({"status": "processing"}, headers=self._hdrs())

    async def order(self, r):
        body = {"status": self.order_status, "finalize": f"{self.base}/finalize"}
        if self.order_status == "valid":
            body["certificate"] = f"{self.base}/cert/1"
        return web.json_response(body, headers=self._hdrs())

    async def cert(self, r):
        return web.Response(text=CERT_PEM, content_type="application/pem-certificate-chain",
                            headers=self._hdrs())


async def _serve(ca_factory):
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    published: dict[str, str] = {}
    ca = ca_factory(base, published)
    runner = web.AppRunner(ca.app(), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    return ca, base, published, runner


@pytest.mark.asyncio
async def test_the_whole_order_produces_a_certificate():
    ca, base, published, runner = await _serve(FakeCA)
    try:
        async with aiohttp.ClientSession() as session:
            account = ACMEAccount()
            client = ACMEClient(account, f"{base}/directory", session=session)

            async def publish(name, value):
                published[name] = value

            async def unpublish(name):
                published.pop(name, None)

            chain, key_pem = await client.obtain(
                ["dns.example.org"], publish, email="op@example.org",
                unpublish_txt=unpublish)

        assert ca.registered and ca.csr_seen
        assert ca.answered == ["_acme-challenge.dns.example.org"]
        assert "BEGIN CERTIFICATE" in chain
        assert b"BEGIN PRIVATE KEY" in key_pem
        # the challenge record does not outlive the order
        assert published == {}
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_the_published_value_is_the_one_the_ca_will_check():
    """dns-01 is the SHA-256 of `token.thumbprint`, base64url, unpadded. Getting
    it wrong fails at the CA with nothing local to look at."""
    ca, base, published, runner = await _serve(FakeCA)
    try:
        async with aiohttp.ClientSession() as session:
            account = ACMEAccount()
            client = ACMEClient(account, f"{base}/directory", session=session)
            seen = {}

            async def publish(name, value):
                published[name] = value
                seen[name] = value

            await client.obtain(["dns.example.org"], publish)
        assert seen["_acme-challenge.dns.example.org"] == \
            dns01_txt("tok-abc", account.thumbprint())
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_a_refused_order_is_reported_not_swallowed():
    class Refusing(FakeCA):
        async def new_order(self, r):
            return web.json_response({"detail": "rate limited"}, status=429,
                                     headers=self._hdrs())

    ca, base, published, runner = await _serve(Refusing)
    try:
        async with aiohttp.ClientSession() as session:
            client = ACMEClient(ACMEAccount(), f"{base}/directory", session=session)
            with pytest.raises(RuntimeError, match="order refused"):
                await client.obtain(["dns.example.org"], lambda n, v: None)
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_an_authorization_that_never_settles_times_out():
    class Stuck(FakeCA):
        async def challenge(self, r):
            return web.json_response({"status": "pending"}, headers=self._hdrs())

    ca, base, published, runner = await _serve(Stuck)
    try:
        async with aiohttp.ClientSession() as session:
            client = ACMEClient(ACMEAccount(), f"{base}/directory", session=session)

            async def publish(name, value):
                published[name] = value

            with pytest.raises(TimeoutError):
                await client.poll(f"{base}/authz/1", timeout=0.3, interval=0.05)
    finally:
        await runner.cleanup()


# ------------------------------------------------------- the manager around it

def _zones_for(origin: str) -> ZoneStore:
    from trench.wire.rrtypes import Type as T
    store = ZoneStore()
    z = Zone(Name.from_text(origin))
    z.add(Name.from_text(origin), int(T.SOA),
          R.SOA(Name.from_text(f"ns.{origin}"), Name.from_text(f"hostmaster.{origin}"),
                1, 3600, 600, 604800, 3600))
    store.add(z)
    return store


def test_it_says_why_it_cannot_run_rather_than_failing_quietly(tmp_path):
    cfg = Config.model_validate({"acme": {"enabled": True, "domains": []}})
    m = AcmeManager(cfg, ZoneStore(), tmp_path)
    assert m.reason_unavailable() == "acme.domains is empty"

    cfg = Config.model_validate(
        {"acme": {"enabled": True, "domains": ["dns.example.org"]}})
    m = AcmeManager(cfg, ZoneStore(), tmp_path)
    assert "not authoritative" in m.reason_unavailable()

    m = AcmeManager(cfg, _zones_for("example.org."), tmp_path)
    assert m.reason_unavailable() is None


@pytest.mark.asyncio
async def test_the_challenge_record_goes_into_the_zone_and_comes_back_out(tmp_path):
    cfg = Config.model_validate(
        {"acme": {"enabled": True, "domains": ["dns.example.org"]}})
    zones = _zones_for("example.org.")
    m = AcmeManager(cfg, zones, tmp_path)
    owner = Name.from_text("_acme-challenge.dns.example.org")

    await m._publish("_acme-challenge.dns.example.org", "value-one")
    zone = zones.authoritative_for(owner)
    assert [rd.to_text() for rd in zone.records[owner][int(Type.TXT)]] == ['"value-one"']

    # a second order replaces rather than appends: two TXT values would both be
    # served, and the CA checks for exactly one it recognises
    await m._publish("_acme-challenge.dns.example.org", "value-two")
    assert [rd.to_text() for rd in zone.records[owner][int(Type.TXT)]] == ['"value-two"']

    await m._unpublish("_acme-challenge.dns.example.org")
    assert owner not in zone.records


def test_renewal_is_due_when_there_is_no_certificate_yet(tmp_path):
    cfg = Config.model_validate(
        {"acme": {"enabled": True, "domains": ["dns.example.org"]}})
    m = AcmeManager(cfg, _zones_for("example.org."), tmp_path)
    assert m.expires_in_days() is None
    assert m.due() is True


def test_key_material_is_written_private(tmp_path):
    import stat
    cfg = Config.model_validate({"acme": {"enabled": True}})
    m = AcmeManager(cfg, ZoneStore(), tmp_path)
    m._write_private(m.key_file, b"secret")
    mode = stat.S_IMODE(m.key_file.stat().st_mode)
    assert mode == 0o600, f"key written world-readable: {oct(mode)}"
