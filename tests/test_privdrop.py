"""Privilege dropping: id resolution + the non-root / no-target no-op paths.

The actual setuid path can't run in an unprivileged test process, so we verify
resolution and the guard rails that decide whether to attempt a drop."""
from __future__ import annotations

import os

import pytest

from trench.security.privdrop import PrivDropError, drop_privileges, resolve_ids


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


def test_resolve_unknown_group_raises():
    with pytest.raises(PrivDropError):
        resolve_ids(None, "definitely-not-a-real-group-xyz")


def test_resolve_group_only():
    import grp
    gr = grp.getgrgid(os.getgid())
    uid, gid = resolve_ids(None, gr.gr_name)
    assert uid is None and gid == gr.gr_gid


def test_resolve_numeric_group():
    _, gid = resolve_ids(None, str(os.getgid()))
    assert gid == os.getgid()


def test_group_overrides_the_users_primary_group():
    """`user=` supplies a primary gid; an explicit `group=` must win."""
    import grp
    import pwd
    me = pwd.getpwuid(os.getuid())
    other = next((g for g in grp.getgrall() if g.gr_gid != me.pw_gid), None)
    if other is None:
        pytest.skip("no second group on this host")
    uid, gid = resolve_ids(me.pw_name, str(other.gr_gid))
    assert uid == me.pw_uid and gid == other.gr_gid


# --- the real drop, against a fake os ---
class FakeOS:
    """Enough of `os` to drive `drop_privileges` end to end.

    The drop cannot be performed for real in an unprivileged test process, and
    it is the one code path where a silent partial failure leaves a "dropped"
    resolver running with root's groups — so it is driven against a double
    rather than left untested.
    """
    def __init__(self, *, setgroups_error=None, sticky_gid=False,
                 sticky_uid=False, can_regain=False, leftover_groups=()):
        self.uid = 0
        self.euid = 0
        self.gid = 0
        self.egid = 0
        self.groups = [0]
        self.calls: list[tuple] = []
        self._setgroups_error = setgroups_error
        self._sticky_gid = sticky_gid
        self._sticky_uid = sticky_uid
        self._can_regain = can_regain
        self._leftover = list(leftover_groups)

    def getuid(self): return self.uid
    def geteuid(self): return self.euid
    def getgid(self): return self.gid
    def getegid(self): return self.egid
    def getgroups(self): return list(self.groups)

    def setgroups(self, gs):
        self.calls.append(("setgroups", tuple(gs)))
        if self._setgroups_error:
            raise OSError(self._setgroups_error)
        self.groups = list(gs) + self._leftover

    def setgid(self, g):
        self.calls.append(("setgid", g))
        if not self._sticky_gid:
            self.gid = self.egid = g

    def setuid(self, u):
        self.calls.append(("setuid", u))
        if u == 0 and self.uid != 0:
            if not self._can_regain:
                raise OSError("EPERM")
            self.uid = self.euid = 0
            return
        if not self._sticky_uid:
            self.uid = self.euid = u


def _patch(monkeypatch, fake, uid=1000, gid=2000):
    from trench.security import privdrop
    for name in ("getuid", "geteuid", "getgid", "getegid", "getgroups",
                 "setgroups", "setgid", "setuid"):
        monkeypatch.setattr(privdrop.os, name, getattr(fake, name))
    monkeypatch.setattr(privdrop, "resolve_ids", lambda u, g: (uid, gid))


def test_drop_succeeds_and_orders_the_calls(monkeypatch):
    fake = FakeOS()
    _patch(monkeypatch, fake)
    assert drop_privileges("trench", "trench") is True
    # supplementary groups, then gid, then uid — uid last, because after it the
    # gid can no longer be changed.
    # The trailing setuid(0) is the irreversibility probe, which must fail.
    assert fake.calls == [("setgroups", (2000,)), ("setgid", 2000),
                          ("setuid", 1000), ("setuid", 0)]
    assert fake.uid == 1000 and fake.gid == 2000


def test_drop_user_only_skips_the_group_calls(monkeypatch):
    fake = FakeOS()
    _patch(monkeypatch, fake, uid=1000, gid=None)
    assert drop_privileges("trench", None) is True
    assert fake.calls == [("setuid", 1000), ("setuid", 0)]


def test_drop_group_only_skips_setuid(monkeypatch):
    fake = FakeOS()
    _patch(monkeypatch, fake, uid=None, gid=2000)
    assert drop_privileges(None, "trench") is True
    assert [c[0] for c in fake.calls] == ["setgroups", "setgid"]


def test_setgroups_failure_is_fatal(monkeypatch):
    """Carrying on would keep root's supplementary groups through the setuid."""
    fake = FakeOS(setgroups_error="EPERM")
    _patch(monkeypatch, fake)
    with pytest.raises(PrivDropError, match="setgroups failed"):
        drop_privileges("trench", "trench")
    assert ("setuid", 1000) not in fake.calls


def test_setgid_that_does_not_take_effect_is_fatal(monkeypatch):
    fake = FakeOS(sticky_gid=True)
    _patch(monkeypatch, fake)
    with pytest.raises(PrivDropError, match="setgid"):
        drop_privileges("trench", "trench")
    assert ("setuid", 1000) not in fake.calls


def test_surviving_supplementary_groups_are_fatal(monkeypatch):
    fake = FakeOS(leftover_groups=(0, 27))
    _patch(monkeypatch, fake)
    with pytest.raises(PrivDropError, match="supplementary groups survived"):
        drop_privileges("trench", "trench")


def test_setuid_that_does_not_take_effect_is_fatal(monkeypatch):
    fake = FakeOS(sticky_uid=True)
    _patch(monkeypatch, fake)
    with pytest.raises(PrivDropError, match="setuid"):
        drop_privileges("trench", "trench")


def test_regainable_root_is_fatal(monkeypatch):
    """A botched setuid that leaves saved-set-uid intact is not a drop."""
    fake = FakeOS(can_regain=True)
    _patch(monkeypatch, fake)
    with pytest.raises(PrivDropError, match="regain uid 0"):
        drop_privileges("trench", "trench")


def test_dropping_to_root_skips_the_regain_check(monkeypatch):
    from trench.security.privdrop import _assert_cannot_regain
    # No exception, and no setuid(0) attempt: uid 0 can always "regain" 0.
    _assert_cannot_regain(0)
