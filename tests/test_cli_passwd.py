"""Offline password reset.

The first-run admin password is only printed to the log. Once that rotates, the
operator's remaining proof of ownership is write access to the data directory —
that is what this command trades on, so it must work with the daemon's API
completely unreachable.
"""
from __future__ import annotations

import pytest

from trench.api.auth import AuthManager
from trench.cli.main import _build_parser, _do_passwd, main
from trench.store import Database


async def run(*argv) -> int:
    """Drive the command the way the CLI does, minus asyncio.run (already in a loop)."""
    return await _do_passwd(_build_parser().parse_args(["passwd", *argv]))


async def _db(tmp_path):
    db = Database(tmp_path / "trench.db")
    await db.connect()
    return db


@pytest.mark.asyncio
async def test_reset_existing_user(tmp_path, capsys):
    db = await _db(tmp_path)
    auth = AuthManager(db)
    await auth.create_user("admin", "old-one")
    await db.close()

    assert await run("admin", "--data-dir", str(tmp_path), "--password", "new-one") == 0

    db = await _db(tmp_path)
    auth = AuthManager(db)
    try:
        assert await auth.login("admin", "new-one")
        assert not await auth.login("admin", "old-one")
    finally:
        await db.close()
    assert "password reset" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_generated_password_is_printed_and_works(tmp_path, capsys):
    db = await _db(tmp_path)
    await AuthManager(db).create_user("admin", "old-one")
    await db.close()

    assert await run("--data-dir", str(tmp_path)) == 0
    out = capsys.readouterr().out
    generated = next(ln.split(": ", 1)[1].strip()
                     for ln in out.splitlines() if ln.startswith("password: "))
    assert len(generated) >= 12

    db = await _db(tmp_path)
    try:
        assert await AuthManager(db).login("admin", generated)
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_creates_the_user_when_missing(tmp_path):
    db = await _db(tmp_path)
    await db.close()  # schema exists, no users

    assert await run("ops", "--data-dir", str(tmp_path),
                     "--password", "pw", "--role", "viewer") == 0

    db = await _db(tmp_path)
    try:
        row = await db.fetchone("SELECT role FROM app_user WHERE name=?", ("ops",))
        assert row["role"] == "viewer"
        assert await AuthManager(db).login("ops", "pw")
    finally:
        await db.close()


def test_missing_database_is_an_error_not_a_new_one(tmp_path, capsys):
    """Silently creating a fresh database on a typo'd --data-dir would report
    success while leaving the real one untouched."""
    assert main(["passwd", "--data-dir", str(tmp_path / "nope")]) == 1
    assert not (tmp_path / "nope").exists()
    assert "no database" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_clear_totp_removes_the_second_factor(tmp_path, capsys):
    """Resetting the password alone leaves the authenticator standing, so the
    reset appears to work and the next login still fails."""
    db = await _db(tmp_path)
    auth = AuthManager(db)
    await auth.create_user("admin", "old-one")
    await auth.set_totp("admin", "JBSWY3DPEHPK3PXP")
    await db.close()

    assert await run("admin", "--data-dir", str(tmp_path),
                     "--password", "new-one", "--clear-totp") == 0

    db = await _db(tmp_path)
    auth = AuthManager(db)
    try:
        assert await auth.totp_secret("admin") == ""
        assert await auth.login("admin", "new-one")
    finally:
        await db.close()
    out = capsys.readouterr().out
    assert "two-factor removed" in out


@pytest.mark.asyncio
async def test_a_reset_without_clear_totp_keeps_the_second_factor(tmp_path):
    db = await _db(tmp_path)
    auth = AuthManager(db)
    await auth.create_user("admin", "old-one")
    await auth.set_totp("admin", "JBSWY3DPEHPK3PXP")
    await db.close()

    await run("admin", "--data-dir", str(tmp_path), "--password", "new-one")

    db = await _db(tmp_path)
    try:
        assert await AuthManager(db).totp_secret("admin") == "JBSWY3DPEHPK3PXP"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_clear_totp_on_a_newly_created_user(tmp_path, capsys):
    db = await _db(tmp_path)
    await db.close()
    assert await run("newop", "--data-dir", str(tmp_path), "--password", "pw",
                     "--role", "viewer", "--clear-totp") == 0
    out = capsys.readouterr().out
    assert "user created (viewer)" in out and "two-factor removed" in out


@pytest.mark.asyncio
async def test_the_message_says_sessions_are_not_dropped(tmp_path, capsys):
    """Sessions live in the daemon's memory: anyone already logged in stays
    logged in until it restarts, and the operator has to be told."""
    db = await _db(tmp_path)
    await AuthManager(db).create_user("admin", "old-one")
    await db.close()
    await run("admin", "--data-dir", str(tmp_path), "--password", "new-one")
    assert "restart the daemon" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_a_custom_database_filename_is_honoured(tmp_path):
    db = Database(tmp_path / "other.db")
    await db.connect()
    await AuthManager(db).create_user("admin", "old-one")
    await db.close()
    assert await run("admin", "--data-dir", str(tmp_path), "--db", "other.db",
                     "--password", "new-one") == 0


@pytest.mark.asyncio
async def test_main_runs_passwd_through_asyncio(tmp_path, capsys):
    """`main` dispatches this one through `asyncio.run`; it must not be called
    from inside a running loop, so it is driven in a thread."""
    import asyncio
    db = await _db(tmp_path)
    await AuthManager(db).create_user("admin", "old-one")
    await db.close()
    rc = await asyncio.to_thread(
        main, ["passwd", "admin", "--data-dir", str(tmp_path), "--password", "new"])
    assert rc == 0


@pytest.mark.asyncio
async def test_password_from_stdin_stays_off_the_command_line(tmp_path, capsys,
                                                              monkeypatch):
    import io
    db = await _db(tmp_path)
    await AuthManager(db).create_user("admin", "old-one")
    await db.close()

    monkeypatch.setattr("sys.stdin", io.StringIO("from-stdin\n"))
    assert await run("--data-dir", str(tmp_path), "--password-stdin") == 0
    # Not echoed back: the caller already has it, and stdout may be a log.
    assert "from-stdin" not in capsys.readouterr().out
    db = await _db(tmp_path)
    try:
        assert await AuthManager(db).login("admin", "from-stdin")
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_empty_stdin_is_refused_not_turned_into_an_empty_password(
        tmp_path, capsys, monkeypatch):
    import io
    db = await _db(tmp_path)
    await AuthManager(db).create_user("admin", "old-one")
    await db.close()
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert await run("--data-dir", str(tmp_path), "--password-stdin") == 1
    assert "no password on stdin" in capsys.readouterr().err
