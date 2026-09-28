"""AuthManager: lockout, session sweeping, first-run password, token scopes.

The pieces that were never exercised are the ones that decide who gets in — the
per-username lockout an attacker who can vary their address would otherwise
walk past, the TOTP replay window, the rehash-on-login, and the 0600 file the
first-run password goes to instead of the log.
"""
from __future__ import annotations

import stat
import time

import pytest

from trench.api.auth import LOCKOUT_THRESHOLD, SESSION_TTL, AuthManager
from trench.security import hashutil, totp
from trench.store import Database


@pytest.fixture
async def auth(tmp_path):
    db = Database(tmp_path / "trench.db")
    await db.connect()
    yield AuthManager(db)
    await db.close()


# --- first-run admin ---
@pytest.mark.asyncio
async def test_a_configured_password_is_used_and_nothing_is_written(auth, tmp_path):
    assert await auth.ensure_admin("from-config", data_dir=tmp_path) is None
    assert await auth.login("admin", "from-config")
    assert not (tmp_path / "initial-admin-password").exists()


@pytest.mark.asyncio
async def test_a_generated_password_goes_to_a_private_file_not_the_log(auth,
                                                                      tmp_path,
                                                                      capsys):
    """Under the shipped unit stdout is journald and under compose it is the
    json-file driver; both are the log. A 0600 file is where they differ."""
    pw = await auth.ensure_admin(None, data_dir=tmp_path)
    where = tmp_path / "initial-admin-password"
    assert where.read_text().strip() == pw
    assert stat.S_IMODE(where.stat().st_mode) == 0o600
    out = capsys.readouterr().out
    assert str(where) in out
    assert pw not in out, "the password itself must not be printed"
    assert await auth.login("admin", pw)


@pytest.mark.asyncio
async def test_without_a_writable_data_dir_the_password_is_printed(auth, capsys):
    pw = await auth.ensure_admin(None, data_dir=None)
    assert pw in capsys.readouterr().out


@pytest.mark.asyncio
async def test_an_unwritable_data_dir_falls_back_to_printing(auth, tmp_path, capsys):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        pw = await auth.ensure_admin(None, data_dir=locked)
        assert pw in capsys.readouterr().out
    finally:
        locked.chmod(0o700)


@pytest.mark.asyncio
async def test_ensure_admin_is_a_no_op_once_a_user_exists(auth, tmp_path):
    await auth.create_user("someone", "pw", "viewer")
    assert await auth.ensure_admin("would-be-admin", data_dir=tmp_path) is None
    assert await auth.login("admin", "would-be-admin") is None


# --- login ---
@pytest.mark.asyncio
async def test_a_good_login_returns_a_session_and_stamps_last_login(auth):
    await auth.create_user("admin", "pw")
    token = await auth.login("admin", "pw", ip="10.0.0.1")
    assert token and auth.session_user(token)["name"] == "admin"
    row = await auth.db.fetchone("SELECT last_login FROM app_user WHERE name='admin'")
    assert row["last_login"] > 0


@pytest.mark.asyncio
async def test_a_wrong_password_is_refused(auth):
    await auth.create_user("admin", "pw")
    assert await auth.login("admin", "nope") is None


@pytest.mark.asyncio
async def test_a_disabled_account_cannot_log_in(auth):
    await auth.create_user("admin", "pw")
    await auth.db.execute("UPDATE app_user SET disabled=1 WHERE name='admin'")
    assert await auth.login("admin", "pw") is None


@pytest.mark.asyncio
async def test_a_missing_account_costs_the_same_work_as_a_real_one(auth,
                                                                   monkeypatch):
    """Short-circuiting made a missing account answer instantly and a real one
    take 50-100 ms, which enumerates valid operator names."""
    await auth.create_user("admin", "pw")
    verifications = []
    real = hashutil.verify_password
    monkeypatch.setattr("trench.api.auth.hashutil.verify_password",
                        lambda p, h: verifications.append(h) or real(p, h))
    assert await auth.login("nosuchuser", "pw") is None
    assert len(verifications) == 1, "the dummy hash must still be verified"


# --- lockout ---
@pytest.mark.asyncio
async def test_repeated_failures_lock_the_address_out(auth):
    await auth.create_user("admin", "pw")
    for _ in range(LOCKOUT_THRESHOLD):
        assert await auth.login("admin", "wrong", ip="10.0.0.1") is None
    assert auth._locked("10.0.0.1") > 0
    # Even the correct password is refused while the lockout stands.
    assert await auth.login("admin", "pw", ip="10.0.0.1") is None


@pytest.mark.asyncio
async def test_the_username_is_locked_out_independently_of_the_address(auth):
    """The address comes from the request; an attacker who can vary it would
    otherwise never trip the counter."""
    await auth.create_user("admin", "pw")
    for i in range(LOCKOUT_THRESHOLD):
        await auth.login("admin", "wrong", ip=f"10.0.0.{i}")
    assert auth._locked("user:admin") > 0
    assert await auth.login("admin", "pw", ip="10.0.0.200") is None


def test_the_lockout_backs_off_exponentially(auth):
    """Measured on the delay, not the remaining wait: `_locked` counts down in
    real time, so two live readings a few milliseconds apart are not
    comparable."""
    from trench.api.auth import LOCKOUT_BASE
    now = time.time()
    delays = []
    for extra in range(4):
        auth._fails["10.0.0.1"] = (LOCKOUT_THRESHOLD + extra, now)
        delays.append(auth._locked("10.0.0.1"))
    assert delays == sorted(delays)
    assert delays[0] == pytest.approx(LOCKOUT_BASE, abs=0.5)
    assert delays[1] > delays[0]


def test_the_lockout_delay_is_capped(auth):
    from trench.api.auth import LOCKOUT_MAX
    auth._fails["10.0.0.1"] = (LOCKOUT_THRESHOLD + 40, time.time())
    assert auth._locked("10.0.0.1") <= LOCKOUT_MAX


@pytest.mark.asyncio
async def test_a_successful_login_clears_both_counters(auth):
    await auth.create_user("admin", "pw")
    await auth.login("admin", "wrong", ip="10.0.0.1")
    assert auth._fails
    assert await auth.login("admin", "pw", ip="10.0.0.1")
    assert "10.0.0.1" not in auth._fails and "user:admin" not in auth._fails


def test_an_address_below_the_threshold_is_not_locked(auth):
    auth._fails["10.0.0.1"] = (LOCKOUT_THRESHOLD - 1, time.time())
    assert auth._locked("10.0.0.1") == 0.0


def test_a_lockout_that_has_elapsed_is_over(auth):
    auth._fails["10.0.0.1"] = (LOCKOUT_THRESHOLD, time.time() - 10_000)
    assert auth._locked("10.0.0.1") == 0.0


# --- sweeping ---
def test_expired_sessions_and_stale_counters_are_swept(auth):
    """Neither table was ever swept: a login loop grew an 8-hour entry per
    call."""
    now = time.time()
    auth.sessions["live"] = ({"name": "a"}, now + 100)
    auth.sessions["dead"] = ({"name": "b"}, now - 1)
    auth._fails["recent"] = (1, now)
    auth._fails["ancient"] = (1, now - 1_000_000)
    auth._sweep(now)
    assert set(auth.sessions) == {"live"}
    assert set(auth._fails) == {"recent"}


@pytest.mark.asyncio
async def test_a_failed_login_sweeps(auth):
    await auth.create_user("admin", "pw")
    auth.sessions["dead"] = ({"name": "x"}, time.time() - 1)
    await auth.login("admin", "wrong", ip="10.0.0.1")
    assert "dead" not in auth.sessions


def test_an_expired_session_token_stops_working(auth):
    auth.sessions["tok"] = ({"name": "admin"}, time.time() - 1)
    assert auth.session_user("tok") is None
    assert "tok" not in auth.sessions


def test_an_unknown_session_token_is_rejected(auth):
    assert auth.session_user("nope") is None
    assert auth.session_user("") is None


def test_logout_drops_the_session(auth):
    auth.sessions["tok"] = ({"name": "admin"}, time.time() + SESSION_TTL)
    auth.logout("tok")
    assert auth.session_user("tok") is None
    auth.logout("tok")               # idempotent


# --- TOTP ---
@pytest.mark.asyncio
async def test_a_totp_code_works_once_and_not_twice(auth):
    """`totp.verify` accepts a +/-1 step window, so without single use a code
    stayed valid for ~90 seconds and could be replayed by anyone who saw it."""
    await auth.create_user("admin", "pw")
    secret = totp.new_secret()
    await auth.set_totp("admin", secret)
    code = totp.totp(secret)
    assert await auth.login("admin", "pw", code)
    assert await auth.login("admin", "pw", code) is None


@pytest.mark.asyncio
async def test_a_wrong_totp_code_is_refused(auth):
    await auth.create_user("admin", "pw")
    await auth.set_totp("admin", totp.new_secret())
    assert await auth.login("admin", "pw", "000000") is None


@pytest.mark.asyncio
async def test_removing_the_secret_removes_the_second_factor(auth):
    await auth.create_user("admin", "pw")
    await auth.set_totp("admin", totp.new_secret())
    assert await auth.login("admin", "pw") is None
    await auth.set_totp("admin", "")
    assert await auth.login("admin", "pw")


def test_the_used_code_set_is_bounded(auth):
    secret = "S" * 16
    for i in range(40):
        assert auth._consume_totp(1, secret, f"{i:06d}") is True
    assert len(auth._totp_used[1]) <= 16


@pytest.mark.asyncio
async def test_totp_secret_of_an_unknown_user_is_empty(auth):
    assert await auth.totp_secret("nobody") == ""


# --- rehash on login ---
@pytest.mark.asyncio
async def test_an_old_cheap_hash_is_upgraded_on_a_successful_login(auth,
                                                                   monkeypatch):
    """This is the only moment the password is in hand and verified."""
    await auth.create_user("admin", "pw")
    monkeypatch.setattr("trench.api.auth.hashutil.needs_rehash", lambda h: True)
    rehashed = []
    real = auth.set_password

    async def note(name, password):
        rehashed.append(name)
        await real(name, password)

    auth.set_password = note
    assert await auth.login("admin", "pw")
    assert rehashed == ["admin"]


@pytest.mark.asyncio
async def test_a_failed_rehash_does_not_fail_the_login(auth, monkeypatch, caplog):
    await auth.create_user("admin", "pw")
    monkeypatch.setattr("trench.api.auth.hashutil.needs_rehash", lambda h: True)

    async def boom(name, password):
        raise RuntimeError("database is locked")

    auth.set_password = boom
    assert await auth.login("admin", "pw")
    assert any("could not re-hash" in r.getMessage() for r in caplog.records)


# --- API tokens ---
@pytest.mark.asyncio
async def test_a_tokens_scope_caps_the_owners_role(auth):
    """A token minted 'viewer' from an admin account carried full admin rights
    to every endpoint."""
    uid = await auth.create_user("admin", "pw", "admin")
    raw = await auth.create_api_token(uid, "readonly", "viewer")
    user = await auth.token_user(raw)
    assert user["role"] == "viewer"


@pytest.mark.asyncio
async def test_a_scope_cannot_widen_the_owners_role(auth):
    uid = await auth.create_user("ro", "pw", "viewer")
    raw = await auth.create_api_token(uid, "wide", "admin")
    assert (await auth.token_user(raw))["role"] == "viewer"


@pytest.mark.asyncio
async def test_an_unknown_scope_is_refused(auth):
    uid = await auth.create_user("admin", "pw")
    with pytest.raises(ValueError, match="unknown scope"):
        await auth.create_api_token(uid, "bad", "superuser")


@pytest.mark.asyncio
async def test_an_expired_token_stops_working(auth):
    uid = await auth.create_user("admin", "pw")
    raw = await auth.create_api_token(uid, "short", "admin",
                                      expires=int(time.time()) - 1)
    assert await auth.token_user(raw) is None


@pytest.mark.asyncio
async def test_a_token_without_an_expiry_keeps_working(auth):
    uid = await auth.create_user("admin", "pw")
    raw = await auth.create_api_token(uid, "forever", "admin", expires=0)
    assert (await auth.token_user(raw))["name"] == "admin"


@pytest.mark.asyncio
async def test_an_unknown_token_is_rejected(auth):
    await auth.create_user("admin", "pw")
    assert await auth.token_user("not-a-real-token") is None


@pytest.mark.asyncio
async def test_using_a_token_stamps_last_used(auth):
    uid = await auth.create_user("admin", "pw")
    raw = await auth.create_api_token(uid, "t", "admin")
    await auth.token_user(raw)
    rows = await auth.list_api_tokens()
    assert rows[0]["last_used"] > 0


@pytest.mark.asyncio
async def test_listing_tokens_never_returns_anything_usable_as_one(auth):
    uid = await auth.create_user("admin", "pw")
    raw = await auth.create_api_token(uid, "t", "viewer")
    rows = await auth.list_api_tokens()
    assert rows[0]["name"] == "t" and rows[0]["scopes"] == "viewer"
    assert rows[0]["owner"] == "admin"
    assert raw not in str(rows)
    assert "token_hash" not in rows[0]


@pytest.mark.asyncio
async def test_revoking_a_token_stops_it_working(auth):
    uid = await auth.create_user("admin", "pw")
    raw = await auth.create_api_token(uid, "t", "admin")
    tid = (await auth.list_api_tokens())[0]["id"]
    assert await auth.revoke_api_token(tid) is True
    assert await auth.token_user(raw) is None
    assert await auth.revoke_api_token(tid) is False


@pytest.mark.asyncio
async def test_the_pepper_is_read_once_and_reused(auth):
    reads = []
    real = auth.db.secret

    async def note(name):
        reads.append(name)
        return await real(name)

    auth.db.secret = note
    first = await auth.pepper()
    assert await auth.pepper() == first
    assert reads == ["api_token"]


# --- roles ---
@pytest.mark.parametrize("role,required,ok", [
    ("admin", "viewer", True), ("admin", "editor", True), ("admin", "admin", True),
    ("editor", "viewer", True), ("editor", "editor", True), ("editor", "admin", False),
    ("viewer", "viewer", True), ("viewer", "editor", False), ("viewer", "admin", False),
    ("", "viewer", False), ("nonsense", "viewer", False),
])
def test_the_role_ranking(role, required, ok):
    assert AuthManager.has_role({"role": role}, required) is ok


def test_no_user_has_no_role():
    assert AuthManager.has_role(None, "viewer") is False


def test_an_unknown_requirement_is_never_satisfied():
    assert AuthManager.has_role({"role": "admin"}, "wizard") is False
