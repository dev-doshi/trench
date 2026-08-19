"""Privilege dropping: id resolution + the non-root / no-target no-op paths.

The actual setuid path can't run in an unprivileged test process, so we verify
resolution and the guard rails that decide whether to attempt a drop."""
from __future__ import annotations

import os

import pytest

from dnsguard.security.privdrop import PrivDropError, drop_privileges, resolve_ids


def test_no_target_is_noop():
    assert drop_privileges(None, None) is False


def test_non_root_declines(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    # requested a target but we're not root -> declines without raising
    assert drop_privileges("nobody", None) is False


def test_resolve_current_user():
    import pwd
    me = pwd.getpwuid(os.getuid())
    uid, gid = resolve_ids(me.pw_name, None)
    assert uid == me.pw_uid and gid == me.pw_gid


def test_resolve_numeric():
    uid, _ = resolve_ids(str(os.getuid()), None)
    assert uid == os.getuid()


def test_resolve_unknown_user_raises():
    with pytest.raises(PrivDropError):
        resolve_ids("definitely-not-a-real-user-xyz", None)
