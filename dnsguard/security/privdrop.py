"""Privilege dropping: bind privileged ports as root, then become an
unprivileged user for the lifetime of the process.

Order matters — supplementary groups, then gid, then uid — because once uid is
dropped you can no longer change gid. After dropping we assert the uid can't be
restored, catching a botched setuid that left saved-set-uid intact.
"""
from __future__ import annotations

import os

from ..log import get

log = get("privdrop")


class PrivDropError(Exception):
    pass


def resolve_ids(user: str | None, group: str | None) -> tuple[int | None, int | None]:
    """Resolve a user/group name (or numeric string) to (uid, gid)."""
    uid = gid = None
    if user:
        import pwd
        try:
            pw = pwd.getpwuid(int(user)) if user.isdigit() else pwd.getpwnam(user)
        except (KeyError, ValueError) as e:
            raise PrivDropError(f"unknown user {user!r}") from e
        uid, gid = pw.pw_uid, pw.pw_gid
    if group:
        import grp
        try:
            gr = grp.getgrgid(int(group)) if group.isdigit() else grp.getgrnam(group)
        except (KeyError, ValueError) as e:
            raise PrivDropError(f"unknown group {group!r}") from e
        gid = gr.gr_gid
    return uid, gid


def drop_privileges(user: str | None, group: str | None = None) -> bool:
    """Drop to `user`/`group`. Returns True if privileges were dropped, False if
    there was nothing to do (already unprivileged / no target). Raises on a
    partial or unsafe drop."""
    if not user and not group:
        return False
    if os.getuid() != 0:
        # not root: can't (and needn't) drop. Warn if a target was requested.
        log.warning("not running as root; ignoring privilege-drop to %s", user or group)
        return False

    uid, gid = resolve_ids(user, group)
    if gid is not None:
        try:
            os.setgroups([gid])
        except OSError:
            log.warning("setgroups failed; continuing with existing supplementary groups")
        os.setgid(gid)
    if uid is not None:
        os.setuid(uid)
        _assert_cannot_regain(uid)
    log.info("dropped privileges to uid=%s gid=%s", uid, gid)
    return True


def _assert_cannot_regain(dropped_uid: int) -> None:
    if dropped_uid == 0:
        return
    try:
        os.setuid(0)
    except OSError:
        return  # good: the drop is irreversible
    raise PrivDropError("privilege drop failed: was able to regain uid 0")
