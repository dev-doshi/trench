"""The ACME order flow, end to end against an in-process directory.

The client could open an order and then stop: there was no way to answer a
challenge, finalize, or download the result, which is why nothing in the package
ever called any of it. A live CA is the only other way to exercise the second
half, and a live CA is slow, rate-limited and unavailable in CI — so the CA is
here, speaking the protocol back.
"""
from __future__ import annotations

import json

import aiohttp
import pytest
from aiohttp import web
from support import free_port

from trench.auth_zone import Zone, ZoneStore
from trench.config import Config
from trench.security.acme import ACMEAccount, ACMEClient, dns01_txt
from trench.security.certs import AcmeManager
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Type

CERT_PEM = ("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")




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
    port = free_port()
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


# --- certificate state and the renewal decision ---
def _self_signed_pem(days: float) -> bytes:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dns.example.org")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=max(1.0, -days + 1)))
            .not_valid_after(now + datetime.timedelta(days=days))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def _manager(tmp_path, domains=("dns.example.org",)):
    cfg = Config.model_validate(
        {"acme": {"enabled": True, "domains": list(domains)}})
    return AcmeManager(cfg, _zones_for("example.org."), tmp_path)


def test_manager_paths_live_under_the_data_dir(tmp_path):
    m = _manager(tmp_path)
    assert m.account_key == tmp_path / "acme-account.key"
    assert m.cert_file == tmp_path / "acme.crt"
    assert m.key_file == tmp_path / "acme.key"


def test_expires_in_days_reads_the_stored_certificate(tmp_path):
    m = _manager(tmp_path)
    m.cert_file.write_bytes(_self_signed_pem(60))
    left = m.expires_in_days()
    assert 59 < left < 61
    assert m.due() is False


def test_a_certificate_inside_the_renewal_window_is_due(tmp_path):
    m = _manager(tmp_path)
    m.cert_file.write_bytes(_self_signed_pem(10))
    assert m.due() is True


def test_an_expired_certificate_is_due(tmp_path):
    m = _manager(tmp_path)
    m.cert_file.write_bytes(_self_signed_pem(-5))
    assert m.expires_in_days() < 0
    assert m.due() is True


def test_an_unreadable_certificate_is_treated_as_absent(tmp_path):
    """Better to try to renew over garbage than to trust it and serve nothing."""
    m = _manager(tmp_path)
    m.cert_file.write_text("this is not a certificate")
    assert m.expires_in_days() is None
    assert m.due() is True


def test_the_account_key_is_generated_once_and_then_reused(tmp_path):
    import stat
    m = _manager(tmp_path)
    first = m._account()
    assert m.account_key.exists()
    assert stat.S_IMODE(m.account_key.stat().st_mode) == 0o600
    pem = m.account_key.read_bytes()
    second = m._account()
    # Reused, not regenerated: a new account key abandons the old registration.
    assert m.account_key.read_bytes() == pem
    assert second.to_pem() == first.to_pem()


def test_write_private_replaces_atomically_and_leaves_no_temp(tmp_path):
    m = _manager(tmp_path)
    m._write_private(m.key_file, b"first")
    m._write_private(m.key_file, b"second")
    assert m.key_file.read_bytes() == b"second"
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.asyncio
async def test_publishing_into_a_zone_we_do_not_serve_raises(tmp_path):
    m = AcmeManager(Config.model_validate({"acme": {"enabled": True}}),
                    ZoneStore(), tmp_path)
    with pytest.raises(RuntimeError, match="authoritative"):
        await m._publish("_acme-challenge.elsewhere.test", "v")


@pytest.mark.asyncio
async def test_unpublishing_an_unserved_name_is_a_noop(tmp_path):
    m = AcmeManager(Config.model_validate({"acme": {"enabled": True}}),
                    ZoneStore(), tmp_path)
    await m._unpublish("_acme-challenge.elsewhere.test")     # must not raise


@pytest.mark.asyncio
async def test_unpublishing_a_name_that_was_never_published_is_a_noop(tmp_path):
    m = _manager(tmp_path)
    await m._unpublish("_acme-challenge.dns.example.org")


@pytest.mark.asyncio
async def test_clear_keeps_other_types_at_the_same_owner(tmp_path):
    m = _manager(tmp_path)
    owner = Name.from_text("_acme-challenge.dns.example.org")
    zone = m.zones.authoritative_for(owner)
    zone.add(owner, int(Type.A), R.A("192.0.2.1"), ttl=60)
    await m._publish("_acme-challenge.dns.example.org", "v")
    await m._unpublish("_acme-challenge.dns.example.org")
    assert int(Type.TXT) not in zone.records[owner]
    assert int(Type.A) in zone.records[owner]


@pytest.mark.asyncio
async def test_renew_refuses_when_it_cannot_run(tmp_path):
    cfg = Config.model_validate({"acme": {"enabled": True, "domains": []}})
    m = AcmeManager(cfg, ZoneStore(), tmp_path)
    assert await m.renew(force=True) is False
    assert not m.cert_file.exists()


@pytest.mark.asyncio
async def test_renew_does_nothing_when_the_certificate_is_fresh(tmp_path):
    m = _manager(tmp_path)
    m.cert_file.write_bytes(_self_signed_pem(60))
    before = m.cert_file.read_bytes()
    assert await m.renew() is False
    assert m.cert_file.read_bytes() == before


@pytest.mark.asyncio
async def test_a_failed_renewal_leaves_the_existing_certificate_alone(tmp_path,
                                                                     monkeypatch):
    m = _manager(tmp_path)
    m.cert_file.write_bytes(_self_signed_pem(1))
    m.key_file.write_bytes(b"old-key")
    before = m.cert_file.read_bytes()

    class Boom:
        def __init__(self, *a, **kw):
            self.account = a[0] if a else None
            self.closed = False

        async def obtain(self, *a, **kw):
            raise RuntimeError("CA said no")

        async def close(self):
            self.closed = True

    made: list[Boom] = []
    monkeypatch.setattr("trench.security.certs.ACMEClient",
                        lambda *a, **kw: made.append(Boom(*a, **kw)) or made[-1])
    assert await m.renew() is False
    assert m.cert_file.read_bytes() == before
    assert m.key_file.read_bytes() == b"old-key"
    assert made[0].closed is True, "the HTTP session leaked on the failure path"


@pytest.mark.asyncio
async def test_a_successful_renewal_writes_key_then_cert(tmp_path, monkeypatch):
    import stat
    m = _manager(tmp_path)
    order: list[str] = []

    class Fake:
        def __init__(self, account, directory):
            self.account = account
            self.directory = directory

        async def obtain(self, domains, publish, *, email=None,
                         unpublish_txt=None, settle=None):
            order.append("obtain")
            assert domains == ["dns.example.org"]
            return CERT_PEM, b"-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n"

        async def close(self):
            order.append("close")

    monkeypatch.setattr("trench.security.certs.ACMEClient", Fake)
    assert await m.renew() is True
    assert m.cert_file.read_text() == CERT_PEM
    assert m.key_file.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    # The key is the half whose absence breaks a restart, so it lands first.
    assert stat.S_IMODE(m.key_file.stat().st_mode) == 0o600
    assert order == ["obtain", "close"]


@pytest.mark.asyncio
async def test_force_renews_a_certificate_that_is_not_due(tmp_path, monkeypatch):
    m = _manager(tmp_path)
    m.cert_file.write_bytes(_self_signed_pem(60))

    class Fake:
        def __init__(self, account, directory):
            self.account = account

        async def obtain(self, *a, **kw):
            return CERT_PEM, b"key"

        async def close(self):
            pass

    monkeypatch.setattr("trench.security.certs.ACMEClient", Fake)
    assert await m.renew(force=True) is True
    assert m.cert_file.read_text() == CERT_PEM


# --- the protocol pieces, without a CA ---
def test_a_csr_needs_at_least_one_domain():
    from trench.security.acme import make_csr
    with pytest.raises(ValueError, match="at least one domain"):
        make_csr([])


def test_a_csr_names_every_domain_in_its_san():
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

    from trench.security.acme import make_csr
    der, key_pem = make_csr(["dns.example.org", "www.example.org"])
    csr = x509.load_der_x509_csr(der)
    assert csr.is_signature_valid
    assert csr.subject.rfc4514_string() == "CN=dns.example.org"
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == ["dns.example.org",
                                                           "www.example.org"]
    assert b"BEGIN" in key_pem
    assert ec is not None


def test_a_csr_can_reuse_a_supplied_key():
    from cryptography.hazmat.primitives.asymmetric import ec

    from trench.security.acme import make_csr
    key = ec.generate_private_key(ec.SECP256R1())
    first, pem_a = make_csr(["dns.example.org"], key)
    second, pem_b = make_csr(["dns.example.org"], key)
    assert pem_a == pem_b


def test_the_dns01_value_is_the_hash_the_ca_will_look_for():
    import base64
    import hashlib

    from trench.security.acme import b64url, dns01_txt
    token, thumb = "tok123", "thumb456"
    expect = b64url(hashlib.sha256(f"{token}.{thumb}".encode()).digest())
    assert dns01_txt(token, thumb) == expect
    assert "=" not in dns01_txt(token, thumb), "base64url for ACME is unpadded"
    assert base64 is not None


def test_base64url_is_unpadded_and_url_safe():
    from trench.security.acme import b64url
    got = b64url(bytes(range(20)))
    assert "=" not in got and "+" not in got and "/" not in got


def test_an_authorization_with_no_dns01_challenge_is_refused():
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")
    auth = {"identifier": {"value": "dns.example.org"},
            "challenges": [{"type": "http-01", "url": "u", "token": "t"}]}
    with pytest.raises(RuntimeError, match="no dns-01 challenge"):
        client.dns01_challenge(auth)


def test_an_authorization_with_no_challenges_at_all_is_refused():
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")
    with pytest.raises(RuntimeError, match="no dns-01 challenge"):
        client.dns01_challenge({})


def test_the_dns01_challenge_is_found_among_others():
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")
    auth = {"identifier": {"value": "dns.example.org"},
            "challenges": [{"type": "http-01", "url": "a", "token": "x"},
                           {"type": "dns-01", "url": "b", "token": "y"}]}
    ch = client.dns01_challenge(auth)
    assert ch.typ == "dns-01" and ch.url == "b" and ch.token == "y"


@pytest.mark.asyncio
async def test_polling_stops_on_a_terminal_failure_state():
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")

    async def get(url):
        return 200, {}, {"status": "invalid", "detail": "the CA said no"}

    client._get = get
    with pytest.raises(RuntimeError, match="became invalid"):
        await client.poll("https://ca.invalid/authz/1")


@pytest.mark.asyncio
async def test_polling_gives_up_rather_than_pending_forever():
    """A CA that never reaches a decision must not leave a renewal job pending
    for the life of the process."""
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")

    async def get(url):
        return 200, {}, {"status": "pending"}

    client._get = get
    with pytest.raises(TimeoutError, match="stayed 'pending'"):
        await client.poll("https://ca.invalid/authz/1", timeout=0.05, interval=0.01)


@pytest.mark.asyncio
async def test_polling_returns_as_soon_as_it_settles():
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")
    seen = []

    async def get(url):
        seen.append(1)
        return 200, {}, {"status": "pending" if len(seen) < 2 else "valid"}

    client._get = get
    body = await client.poll("https://ca.invalid/authz/1", interval=0.01)
    assert body["status"] == "valid" and len(seen) == 2


@pytest.mark.asyncio
async def test_a_refused_challenge_answer_is_reported():
    from trench.security.acme import ACMEAccount, ACMEClient, Challenge
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")

    async def post(url, payload):
        return 403, {}, {"detail": "unauthorized"}

    client._post = post
    with pytest.raises(RuntimeError, match="refused the challenge"):
        await client.answer(Challenge("dns-01", "https://ca.invalid/chall/1", "tok"))


@pytest.mark.asyncio
async def test_a_refused_csr_is_reported():
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")

    async def post(url, payload):
        return 400, {}, {"detail": "bad CSR"}

    client._post = post
    with pytest.raises(RuntimeError, match="refused the CSR"):
        await client.finalize("https://ca.invalid/order/1",
                              {"finalize": "https://ca.invalid/finalize/1"}, b"der")


@pytest.mark.asyncio
async def test_an_order_that_names_no_certificate_is_reported():
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")

    async def post(url, payload):
        return 200, {}, {}

    async def poll(url, **kw):
        return {"status": "valid"}

    client._post = post
    client.poll = poll
    with pytest.raises(RuntimeError, match="names no certificate"):
        await client.finalize("https://ca.invalid/order/1",
                              {"finalize": "https://ca.invalid/finalize/1"}, b"der")


@pytest.mark.asyncio
async def test_something_that_is_not_a_certificate_is_refused():
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")

    async def post(url, payload):
        if url.endswith("/cert"):
            return 200, {}, "<html>not a certificate</html>"
        return 200, {}, {}

    async def poll(url, **kw):
        return {"status": "valid", "certificate": "https://ca.invalid/cert"}

    client._post = post
    client.poll = poll
    with pytest.raises(RuntimeError, match="not a certificate"):
        await client.finalize("https://ca.invalid/order/1",
                              {"finalize": "https://ca.invalid/finalize/1"}, b"der")


@pytest.mark.asyncio
async def test_an_account_registration_without_a_kid_is_refused():
    """Left unchecked, every later post fell back to embedding the raw JWK as
    if this were still newAccount, and the real failure surfaced later as a
    confusing CA error on the order."""
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")

    async def directory():
        return {"newAccount": "https://ca.invalid/new-acct"}

    async def post(url, payload, **kw):
        return 200, {}, {}          # 200, but no Location header

    client.directory = directory
    client._post = post
    with pytest.raises(RuntimeError, match="registration refused"):
        await client.register()


@pytest.mark.asyncio
async def test_an_already_valid_authorization_is_not_answered_again(tmp_path):
    """A cached authorization means the CA is already satisfied; publishing a
    record for it is pointless traffic in someone's zone."""
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")
    published = []

    async def register(email=None):
        return "https://ca.invalid/acct/1"

    async def new_order(domains):
        return "https://ca.invalid/order/1", {
            "authorizations": ["https://ca.invalid/authz/1"],
            "finalize": "https://ca.invalid/finalize/1"}

    async def get(url):
        return 200, {}, {"status": "valid"}

    async def finalize(order_url, order, csr):
        return CERT_PEM

    client.register = register
    client.new_order = new_order
    client._get = get
    client.finalize = finalize
    chain, key = await client.obtain(["dns.example.org"],
                                     lambda name, value: published.append(name))
    assert chain == CERT_PEM and b"BEGIN" in key
    assert published == []


@pytest.mark.asyncio
async def test_the_challenge_record_is_withdrawn_even_when_the_order_fails():
    """It proves nothing once the order is decided, and leaving it in a zone
    that answers the whole LAN is untidy at best."""
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")
    published, unpublished = [], []

    async def register(email=None):
        return "https://ca.invalid/acct/1"

    async def new_order(domains):
        return "https://ca.invalid/order/1", {
            "authorizations": ["https://ca.invalid/authz/1"],
            "finalize": "https://ca.invalid/finalize/1"}

    async def get(url):
        return 200, {}, {"status": "pending",
                         "identifier": {"value": "dns.example.org"},
                         "challenges": [{"type": "dns-01", "url": "u",
                                         "token": "tok"}]}

    async def answer(challenge):
        return None

    async def poll(url, **kw):
        raise RuntimeError("the CA said no")

    async def publish(name, value):
        published.append(name)

    async def unpublish(name):
        unpublished.append(name)

    client.register = register
    client.new_order = new_order
    client._get = get
    client.answer = answer
    client.poll = poll
    with pytest.raises(RuntimeError, match="the CA said no"):
        await client.obtain(["dns.example.org"], publish, unpublish_txt=unpublish)
    assert published == ["_acme-challenge.dns.example.org"]
    assert unpublished == published


@pytest.mark.asyncio
async def test_a_failing_withdrawal_does_not_mask_the_result():
    from trench.security.acme import ACMEAccount, ACMEClient
    client = ACMEClient(ACMEAccount(), "https://ca.invalid/directory")

    async def register(email=None):
        return "https://ca.invalid/acct/1"

    async def new_order(domains):
        return "https://ca.invalid/order/1", {
            "authorizations": ["https://ca.invalid/authz/1"],
            "finalize": "https://ca.invalid/finalize/1"}

    async def get(url):
        return 200, {}, {"status": "pending",
                         "identifier": {"value": "dns.example.org"},
                         "challenges": [{"type": "dns-01", "url": "u",
                                         "token": "tok"}]}

    async def publish(name, value):
        return None

    async def unpublish(name):
        raise RuntimeError("the zone is read-only")

    async def answer(challenge):
        return None

    async def poll(url, **kw):
        return {"status": "valid"}

    async def finalize(order_url, order, csr):
        return CERT_PEM

    client.register = register
    client.new_order = new_order
    client._get = get
    client.answer = answer
    client.poll = poll
    client.finalize = finalize
    chain, _ = await client.obtain(["dns.example.org"], publish,
                                   unpublish_txt=unpublish)
    assert chain == CERT_PEM


@pytest.mark.asyncio
async def test_closing_a_client_that_never_opened_a_session_is_harmless():
    from trench.security.acme import ACMEAccount, ACMEClient
    await ACMEClient(ACMEAccount(), "https://ca.invalid/directory").close()
