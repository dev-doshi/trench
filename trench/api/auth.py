"""Authentication + RBAC: DB-backed users, in-memory sessions, API tokens,
brute-force lockout, TOTP 2FA.
"""
from __future__ import annotations

import asyncio
import ipaddress
import secrets
import time
import weakref

from ..log import get
from ..security import hashutil, totp
from ..store import Database

log = get("auth")

ROLE_RANK = {"viewer": 1, "editor": 2, "admin": 3}
SESSION_TTL = 8 * 3600
TOTP_MEMORY = 120.0        # longer than any code stays valid (+/-1 step of 30 s)
LOCKOUT_THRESHOLD = 5      # allow this many failures before backoff kicks in
LOCKOUT_BASE = 2.0
LOCKOUT_MAX = 300.0

#: Compared against when the account does not exist, so a bad username costs
#: the same scrypt work as a bad password. Value is irrelevant; only the work is.
_DUMMY_HASH = hashutil.hash_password(secrets.token_urlsafe(16))

#: scrypt jobs allowed to run at once. Each is ~100 ms of CPU and 32 MB of
#: memory; the default thread pool would otherwise run dozens side by side for a
#: burst of login requests.
_SCRYPT_SLOTS = 2
#: One gate per event loop. A single module-level semaphore bound itself to the
#: first loop that contended on it, and every login on any later loop then
#: raised "bound to a different event loop".
_scrypt_gates: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


async def _scrypt(fn, *args):
    """Run a scrypt hash or verify off the event loop.

    The API shares its loop with the DNS listeners in the primary worker, so a
    verify run inline froze DNS for its whole duration — and a login request
    needs no credentials to send.
    """
    loop = asyncio.get_running_loop()
    gate = _scrypt_gates.get(loop)
    if gate is None:
        gate = _scrypt_gates[loop] = asyncio.Semaphore(_SCRYPT_SLOTS)
    async with gate:
        return await asyncio.to_thread(fn, *args)


#: How many address prefixes per account are remembered as ones it logged in from.
KNOWN_PREFIXES = 8


def _addr_key(ip: str) -> str:
    """The lockout key for an address: itself for IPv4, its /64 for IPv6.

    One IPv6 host is routinely handed a whole /64, so counting single addresses
    gave it 2**64 fresh counters to rotate through.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        return ip
    if addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(ipaddress.ip_network(f"{addr}/64", strict=False))


class AuthManager:
    def __init__(self, db: Database):
        self.db = db
        self.sessions: dict[str, tuple[dict, float]] = {}
        self._fails: dict[str, tuple[int, float]] = {}  # key -> (count, last)
        self._totp_used: dict[int, dict[str, float]] = {}  # user id -> code -> when spent
        self._pepper: bytes | None = None               # see `pepper()`
        self._known_from: dict[str, list[str]] = {}     # user -> recent good prefixes

    async def pepper(self) -> bytes:
        """The key API-token digests are computed under, loaded once.

        It lives in the database rather than in this process, so a token issued
        today still verifies tomorrow. Kept out of `__init__` because reading it
        is I/O and every caller of this is already async.
        """
        if self._pepper is None:
            self._pepper = await self.db.secret("api_token")
        return self._pepper

    def _consume_totp(self, user_id: int, secret: str, code: str) -> bool:
        """Spend a TOTP code once. False if it has already been used.

        `totp.verify` accepts a +/-1 step window, so without this a code stayed
        valid for ~90 seconds and could be replayed by anyone who observed it
        once — which is exactly what a one-time code is supposed to prevent.
        """
        now = time.monotonic()
        used = self._totp_used.setdefault(user_id, {})
        # A code is valid for at most three 30-second steps, so one spent more
        # than that ago can never match again and is forgotten. Pruning by age
        # rather than by count: a set trimmed to "the last few" kept arbitrary
        # members, and could drop the code spent a second ago.
        for old in [c for c, at in used.items() if now - at > TOTP_MEMORY]:
            del used[old]
        if code in used:
            return False
        used[code] = now
        return True

    def _sweep(self, now: float) -> None:
        """Drop expired sessions and stale failure counters.

        Neither table was ever swept: a session went only when that exact token
        was presented again, so a login loop grew an 8-hour entry per call, and
        `_fails` grew one entry per distinct key seen.
        """
        for token, (_, exp) in list(self.sessions.items()):
            if exp < now:
                self.sessions.pop(token, None)
        for key, (_, last) in list(self._fails.items()):
            if now - last > LOCKOUT_MAX * 4:
                self._fails.pop(key, None)

    async def ensure_admin(self, password: str | None = None,
                           data_dir=None) -> str | None:
        row = await self.db.fetchone("SELECT COUNT(*) AS n FROM app_user")
        if row and row["n"] > 0:
            return None
        pw = password or secrets.token_urlsafe(12)
        await self.create_user("admin", pw, "admin")
        if password:
            log.warning("created default admin user (password from config)")
            return None
        # Written to a private file, and the *path* is what goes to the log.
        #
        # It used to be printed rather than logged, on the reasoning that log
        # read access reaches a wider set of people than console admin. The
        # reasoning is right and the mechanism did not achieve it: under the
        # shipped systemd unit stdout is journald, and under the shipped compose
        # file it is the json-file driver. Both are the log. A 0600 file beside
        # the database is the first place where the two are actually different.
        where = self._write_first_password(pw, data_dir)
        if where is None:
            log.warning("created default admin user; one-time password printed "
                        "below (no writable data directory to put it in)")
            print(f"\n  Trench admin password: {pw}\n", flush=True)
        else:
            log.warning("created default admin user; the one-time password is in "
                        "%s — read it, then delete it", where)
            print(f"\n  Trench admin password written to {where}\n", flush=True)
        return pw

    @staticmethod
    def _write_first_password(pw: str, data_dir) -> str | None:
        """Drop the first-run password where only this account can read it."""
        if data_dir is None:
            return None
        import os
        from pathlib import Path
        path = Path(data_dir) / "initial-admin-password"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(f"{pw}\n")
            return str(path)
        except OSError:
            return None

    async def create_user(self, name: str, password: str, role: str = "admin") -> int:
        ph = await _scrypt(hashutil.hash_password, password)
        await self.db.execute(
            "INSERT INTO app_user(name, pw_hash, role, created) VALUES(?,?,?,?)",
            (name, ph, role, int(time.time())))
        row = await self.db.fetchone("SELECT id FROM app_user WHERE name=?", (name,))
        return row["id"]

    async def set_password(self, name: str, password: str) -> None:
        ph = await _scrypt(hashutil.hash_password, password)
        await self.db.execute("UPDATE app_user SET pw_hash=? WHERE name=?", (ph, name))

    def _locked(self, ip: str) -> float:
        count, last = self._fails.get(ip, (0, 0.0))
        if count < LOCKOUT_THRESHOLD:
            return 0.0
        delay = min(LOCKOUT_MAX, LOCKOUT_BASE * (2 ** (count - LOCKOUT_THRESHOLD)))
        wait = (last + delay) - time.time()
        return max(0.0, wait)

    async def login(self, name: str, password: str, code: str = "", ip: str = "") -> str | None:
        # Locked out by address *and* by username. The address alone is not a
        # stable identity: an attacker with many of them (a botnet, or any IPv6
        # host) would otherwise never trip the counter. But the per-user lock
        # was global, so five wrong guesses from anywhere shut the real admin
        # out too — indefinitely, if repeated. It is not applied to a prefix
        # this account has logged in from before: that is how its owner still
        # gets in while a stranger is hammering the name.
        where = _addr_key(ip)
        keys = [where]
        if where not in self._known_from.get(name, ()):
            keys.append(f"user:{name}")
        if any(self._locked(k) > 0 for k in keys):
            return None
        # Count the attempt as a failure now, before the first await, and clear
        # it only on success. Recording it after the verify let every request in
        # a concurrent burst pass the check above before any of them had been
        # counted, so the threshold did not limit the guessing rate at all.
        now = time.time()
        for k in keys:
            count, _ = self._fails.get(k, (0, 0.0))
            self._fails[k] = (count + 1, now)
        row = await self.db.fetchone("SELECT * FROM app_user WHERE name=? AND disabled=0", (name,))
        if row is None:
            # Spend the same scrypt work as a real user before failing. Short-
            # circuiting made a missing account answer instantly and a real one
            # take ~50-100 ms, which enumerates valid operator names.
            await _scrypt(hashutil.verify_password, password, _DUMMY_HASH)
            ok = False
        else:
            ok = await _scrypt(hashutil.verify_password, password, row["pw_hash"])
            if ok and row["totp_secret"]:
                ok = totp.verify(row["totp_secret"], code)
                if ok and not self._consume_totp(row["id"], row["totp_secret"], code):
                    ok = False       # already used: a code is good once
        if not ok:
            self._sweep(time.time())
            return None
        for k in keys:
            self._fails.pop(k, None)
        known = self._known_from.setdefault(name, [])
        if where not in known:
            known.append(where)
            del known[:-KNOWN_PREFIXES]
        assert row is not None          # `ok` is only True on the row branch
        if hashutil.needs_rehash(row["pw_hash"]):
            # The password is in hand and verified exactly here and nowhere
            # else, so this is the only moment an old, cheaper hash can be
            # upgraded. Without it a hash written under a lower scrypt cost
            # stayed at that cost for the life of the account.
            try:
                await self.set_password(name, password)
                log.info("re-hashed %s's password at the current cost", name)
            except Exception:
                log.exception("could not re-hash %s's password", name)
        token = secrets.token_urlsafe(32)
        user = {"id": row["id"], "name": row["name"], "role": row["role"]}
        self.sessions[token] = (user, time.time() + SESSION_TTL)
        await self.db.execute("UPDATE app_user SET last_login=? WHERE id=?",
                              (int(time.time()), row["id"]))
        return token

    def session_user(self, token: str) -> dict | None:
        item = self.sessions.get(token)
        if not item:
            return None
        user, exp = item
        if exp < time.time():
            self.sessions.pop(token, None)
            return None
        return user

    def logout(self, token: str) -> None:
        self.sessions.pop(token, None)

    async def token_user(self, raw: str) -> dict | None:
        th = hashutil.hash_token(raw, await self.pepper())
        row = await self.db.fetchone(
            "SELECT u.id, u.name, u.role, t.scopes FROM api_token t "
            "JOIN app_user u ON u.id=t.user_id "
            "WHERE t.token_hash=? AND (t.expires=0 OR t.expires>?)", (th, int(time.time())))
        if not row:
            return None
        await self.db.execute("UPDATE api_token SET last_used=? WHERE token_hash=?",
                              (int(time.time()), th))
        # The token's scope caps the owner's role. It was stored at creation and
        # read by nothing, so a token minted "viewer" from an admin account
        # carried full admin rights to every endpoint.
        role = row["role"]
        scope = (row["scopes"] or "").strip()
        if scope in ROLE_RANK and ROLE_RANK[scope] < ROLE_RANK.get(role, 0):
            role = scope
        return {"id": row["id"], "name": row["name"], "role": role}

    async def create_api_token(self, user_id: int, name: str, scopes: str = "admin",
                               expires: int = 0) -> str:
        """Mint a token and return it once. Only the digest is stored.

        `scopes` is a role name and caps the owner's own role at use time (see
        `token_user`), so an admin can hand out a read-only token without
        creating a second account.
        """
        if scopes not in ROLE_RANK:
            raise ValueError(f"unknown scope {scopes!r}")
        raw = hashutil.new_token()
        await self.db.execute(
            "INSERT INTO api_token(user_id, token_hash, name, scopes, created, expires) "
            "VALUES(?,?,?,?,?,?)",
            (user_id, hashutil.hash_token(raw, await self.pepper()), name, scopes,
             int(time.time()), expires))
        return raw

    async def list_api_tokens(self) -> list[dict]:
        """Every token, without anything that could be used as one."""
        rows = await self.db.fetchall(
            "SELECT t.id, t.name, t.scopes, t.created, t.last_used, t.expires,"
            "       u.name AS owner"
            "  FROM api_token t LEFT JOIN app_user u ON u.id = t.user_id"
            " ORDER BY t.created DESC")
        return [dict(r) for r in rows]

    async def revoke_api_token(self, token_id: int) -> bool:
        row = await self.db.fetchone("SELECT id FROM api_token WHERE id=?", (token_id,))
        if row is None:
            return False
        await self.db.execute("DELETE FROM api_token WHERE id=?", (token_id,))
        return True

    async def set_totp(self, name: str, secret: str) -> None:
        await self.db.execute("UPDATE app_user SET totp_secret=? WHERE name=?", (secret, name))

    async def check_totp(self, name: str, code: str) -> bool:
        """A current code for `name`'s second factor, spent once. True when the
        account has none.

        For changes to the factor itself: a session alone — a stolen cookie, a
        console left open — must not be enough to switch it off. Failures count
        towards the same backoff as logins, so the code cannot be guessed
        through an open session either.
        """
        row = await self.db.fetchone(
            "SELECT id, totp_secret FROM app_user WHERE name=?", (name,))
        if row is None:
            return False
        if not row["totp_secret"]:
            return True
        key = f"totp:{name}"
        if self._locked(key) > 0:
            return False
        if totp.verify(row["totp_secret"], code) and \
                self._consume_totp(row["id"], row["totp_secret"], code):
            self._fails.pop(key, None)
            return True
        count, _ = self._fails.get(key, (0, 0.0))
        self._fails[key] = (count + 1, time.time())
        return False

    def end_other_sessions(self, user_id: int, keep: str = "") -> int:
        """Sign `user_id` out everywhere but the session `keep`.

        Called when the second factor changes: a session that was stolen before
        TOTP went on must not outlive the change that was meant to stop it.
        """
        gone = [t for t, (u, _) in self.sessions.items()
                if u["id"] == user_id and t != keep]
        for t in gone:
            self.sessions.pop(t, None)
        return len(gone)

    async def totp_secret(self, name: str) -> str:
        row = await self.db.fetchone("SELECT totp_secret FROM app_user WHERE name=?", (name,))
        return (row["totp_secret"] or "") if row else ""

    @staticmethod
    def has_role(user: dict | None, required: str) -> bool:
        if user is None:
            return False
        return ROLE_RANK.get(user.get("role", ""), 0) >= ROLE_RANK.get(required, 99)
