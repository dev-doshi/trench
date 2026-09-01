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
