"""API tokens and TOTP enrolment: the two loops that had no way in.

Both features were built from the consuming end only. `api_token` existed,
`token_user` validated against it and honoured its scope, the CLI took a
`--token` on four commands, and the docs said to generate one in the console —
but nothing anywhere could mint one. TOTP was the same shape: verification,
single-use replay protection, a login field, and no way to enrol.

These tests walk each loop end to end, because a half-loop passes every unit
test its two halves have.
"""
from __future__ import annotations

import asyncio
import socket

import aiohttp
import pytest

from dnsguard.api import APIServer
from dnsguard.app import App
from dnsguard.config import Config
from dnsguard.security import totp


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


async def _app_with_api(tmp_path):
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "web": {"enabled": True, "admin_password": "pw"}})
    app = App(cfg)
    await app.setup_storage()
    port = _free_port()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    return app, f"http://127.0.0.1:{port}"


def _session():
    return aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))


async def _login(s, base, code: str = ""):
    return await s.post(f"{base}/api/v1/auth/login",
                        json={"name": "admin", "password": "pw", "code": code})


async def _shutdown(app):
    await app.api.stop()
    await app.db.close()


@pytest.mark.asyncio
async def test_a_minted_token_authenticates_a_scripted_client(tmp_path):
    app, base = await _app_with_api(tmp_path)
    try:
        async with _session() as s:
            await _login(s, base)
            r = await s.post(f"{base}/api/v1/auth/tokens",
                             json={"name": "home-assistant", "scope": "viewer"})
            assert r.status == 200
            body = await r.json()
            raw = body["token"]
            assert raw and len(raw) > 20

        # A fresh session with no cookie: exactly what `dnsguard status` is.
        async with _session() as s:
            r = await s.get(f"{base}/api/v1/system")
            assert r.status == 401                       # no credentials at all

            r = await s.get(f"{base}/api/v1/system",
                            headers={"Authorization": f"Bearer {raw}"})
            assert r.status == 200
            assert (await r.json())["version"]
    finally:
        await _shutdown(app)


@pytest.mark.asyncio
async def test_a_token_cannot_exceed_the_scope_it_was_minted_with(tmp_path):
    app, base = await _app_with_api(tmp_path)
    try:
        async with _session() as s:
            await _login(s, base)
            r = await s.post(f"{base}/api/v1/auth/tokens",
                             json={"name": "readonly", "scope": "viewer"})
            raw = (await r.json())["token"]

        async with _session() as s:
            h = {"Authorization": f"Bearer {raw}"}
            assert (await s.get(f"{base}/api/v1/stats", headers=h)).status == 200
            # minted viewer from an admin account: it must not inherit admin
            assert (await s.post(f"{base}/api/v1/toggle", headers=h)).status == 403
            assert (await s.get(f"{base}/api/v1/audit", headers=h)).status == 403
    finally:
        await _shutdown(app)


@pytest.mark.asyncio
async def test_tokens_are_listed_without_the_secret_and_can_be_revoked(tmp_path):
    app, base = await _app_with_api(tmp_path)
    try:
        async with _session() as s:
            await _login(s, base)
            raw = (await (await s.post(f"{base}/api/v1/auth/tokens",
                                       json={"name": "cron"})).json())["token"]

            listed = (await (await s.get(f"{base}/api/v1/auth/tokens")).json())["tokens"]
            assert [t["name"] for t in listed] == ["cron"]
            assert raw not in repr(listed)          # nothing usable comes back
            tid = listed[0]["id"]

            assert (await s.delete(f"{base}/api/v1/auth/tokens/{tid}")).status == 200
            assert (await s.delete(f"{base}/api/v1/auth/tokens/{tid}")).status == 404

        async with _session() as s:
            r = await s.get(f"{base}/api/v1/stats",
                            headers={"Authorization": f"Bearer {raw}"})
            assert r.status == 401                   # revoked means revoked
    finally:
        await _shutdown(app)


@pytest.mark.asyncio
async def test_a_token_still_verifies_after_a_restart(tmp_path):
    """The digest key used to be regenerated at import, so every stored token
    stopped verifying the moment the process came back."""
    app, base = await _app_with_api(tmp_path)
    try:
        async with _session() as s:
            await _login(s, base)
            raw = (await (await s.post(f"{base}/api/v1/auth/tokens",
                                       json={"name": "survives"})).json())["token"]
    finally:
        await _shutdown(app)

    app2, base2 = await _app_with_api(tmp_path)      # same data dir, new process state
    try:
        async with _session() as s:
            r = await s.get(f"{base2}/api/v1/stats",
                            headers={"Authorization": f"Bearer {raw}"})
            assert r.status == 200
    finally:
        await _shutdown(app2)


@pytest.mark.asyncio
async def test_minting_a_token_requires_admin(tmp_path):
    app, base = await _app_with_api(tmp_path)
    try:
        async with _session() as s:
            r = await s.post(f"{base}/api/v1/auth/tokens", json={"name": "x"})
            assert r.status == 401
    finally:
        await _shutdown(app)


# ------------------------------------------------------------------ TOTP

@pytest.mark.asyncio
async def test_totp_enrolment_round_trip(tmp_path):
    app, base = await _app_with_api(tmp_path)
    try:
        async with _session() as s:
            await _login(s, base)
            assert (await (await s.get(f"{base}/api/v1/auth/me")).json())["totp"] is False

            body = await (await s.post(f"{base}/api/v1/auth/totp/enrol")).json()
            secret = body["secret"]
            assert body["uri"].startswith("otpauth://totp/")

            # a wrong code must not enable anything: storing an unproven secret
            # is a lockout on the next login
            r = await s.post(f"{base}/api/v1/auth/totp/confirm", json={"code": "000000"})
            assert r.status == 400
            assert await app.api.auth.totp_secret("admin") == ""

            r = await s.post(f"{base}/api/v1/auth/totp/confirm",
                             json={"code": totp.totp(secret)})
            assert r.status == 200
            assert await app.api.auth.totp_secret("admin") == secret
            assert (await (await s.get(f"{base}/api/v1/auth/me")).json())["totp"] is True

        # the second factor is now actually required
        async with _session() as s:
            assert (await _login(s, base)).status == 401
            assert (await _login(s, base, totp.totp(secret))).status == 200
    finally:
        await _shutdown(app)


@pytest.mark.asyncio
async def test_confirm_without_enrolling_is_refused(tmp_path):
    app, base = await _app_with_api(tmp_path)
    try:
        async with _session() as s:
            await _login(s, base)
            r = await s.post(f"{base}/api/v1/auth/totp/confirm", json={"code": "123456"})
            assert r.status == 400
    finally:
        await _shutdown(app)


@pytest.mark.asyncio
async def test_a_lost_authenticator_is_recoverable_offline(tmp_path):
    """`dnsguard passwd --clear-totp`. The console is what you cannot reach, so
    the recovery path cannot go through it — and resetting only the password
    left the second factor standing, which is not a recovery at all."""
    from dnsguard.cli.main import main as cli_main

    app, base = await _app_with_api(tmp_path)
    try:
        async with _session() as s:
            await _login(s, base)
            secret = (await (await s.post(f"{base}/api/v1/auth/totp/enrol")).json())["secret"]
            await s.post(f"{base}/api/v1/auth/totp/confirm", json={"code": totp.totp(secret)})
            assert await app.api.auth.totp_secret("admin") == secret
    finally:
        await _shutdown(app)

    # off-thread: the CLI owns its own event loop, and this test is already in one
    rc = await asyncio.to_thread(
        cli_main, ["passwd", "admin", "--data-dir", str(tmp_path),
                   "--password", "newpw", "--clear-totp"])
    assert rc == 0

    app2, base2 = await _app_with_api(tmp_path)
    try:
        async with _session() as s:
            r = await s.post(f"{base2}/api/v1/auth/login",
                             json={"name": "admin", "password": "newpw"})
            assert r.status == 200
        assert await app2.api.auth.totp_secret("admin") == ""
    finally:
        await _shutdown(app2)
