"""Authentication + RBAC: DB-backed users, in-memory sessions, API tokens,
brute-force lockout, TOTP 2FA.
"""
from __future__ import annotations

import secrets
import time

from ..log import get
from ..security import hashutil, totp
from ..store import Database

log = get("auth")

ROLE_RANK = {"viewer": 1, "editor": 2, "admin": 3}
SESSION_TTL = 8 * 3600
LOCKOUT_THRESHOLD = 5      # allow this many failures before backoff kicks in
LOCKOUT_BASE = 2.0
LOCKOUT_MAX = 300.0


class AuthManager:
    def __init__(self, db: Database):
        self.db = db
        self.sessions: dict[str, tuple[dict, float]] = {}
        self._fails: dict[str, tuple[int, float]] = {}  # ip -> (count, last)

    async def ensure_admin(self, password: str | None = None) -> str | None:
        row = await self.db.fetchone("SELECT COUNT(*) AS n FROM app_user")
        if row and row["n"] > 0:
            return None
        pw = password or secrets.token_urlsafe(12)
        await self.create_user("admin", pw, "admin")
        log.warning("created default admin user — password: %s", pw if not password else "(from config)")
        return pw if not password else None

    async def create_user(self, name: str, password: str, role: str = "admin") -> int:
        ph = hashutil.hash_password(password)
        await self.db.execute(
            "INSERT INTO app_user(name, pw_hash, role, created) VALUES(?,?,?,?)",
            (name, ph, role, int(time.time())))
        row = await self.db.fetchone("SELECT id FROM app_user WHERE name=?", (name,))
        return row["id"]

    async def set_password(self, name: str, password: str) -> None:
        await self.db.execute("UPDATE app_user SET pw_hash=? WHERE name=?",
                              (hashutil.hash_password(password), name))

    async def set_totp(self, name: str, secret: str) -> None:
        await self.db.execute("UPDATE app_user SET totp_secret=? WHERE name=?", (secret, name))

    def _locked(self, ip: str) -> float:
        count, last = self._fails.get(ip, (0, 0.0))
        if count < LOCKOUT_THRESHOLD:
            return 0.0
        delay = min(LOCKOUT_MAX, LOCKOUT_BASE * (2 ** (count - LOCKOUT_THRESHOLD)))
        wait = (last + delay) - time.time()
        return max(0.0, wait)

    async def login(self, name: str, password: str, code: str = "", ip: str = "") -> str | None:
        if self._locked(ip) > 0:
            return None
        row = await self.db.fetchone("SELECT * FROM app_user WHERE name=? AND disabled=0", (name,))
        ok = bool(row) and hashutil.verify_password(password, row["pw_hash"])
        if ok and row["totp_secret"]:
            ok = totp.verify(row["totp_secret"], code)
        if not ok:
            count, _ = self._fails.get(ip, (0, 0.0))
            self._fails[ip] = (count + 1, time.time())
            return None
        self._fails.pop(ip, None)
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
        th = hashutil.hash_token(raw)
        row = await self.db.fetchone(
            "SELECT u.id, u.name, u.role FROM api_token t JOIN app_user u ON u.id=t.user_id "
            "WHERE t.token_hash=? AND (t.expires=0 OR t.expires>?)", (th, int(time.time())))
        if not row:
            return None
        await self.db.execute("UPDATE api_token SET last_used=? WHERE token_hash=?",
                              (int(time.time()), th))
        return {"id": row["id"], "name": row["name"], "role": row["role"]}

    async def create_api_token(self, user_id: int, name: str, scopes: str = "admin",
                               expires: int = 0) -> str:
        raw = hashutil.new_token()
        await self.db.execute(
            "INSERT INTO api_token(user_id, token_hash, name, scopes, created, expires) "
            "VALUES(?,?,?,?,?,?)",
            (user_id, hashutil.hash_token(raw), name, scopes, int(time.time()), expires))
        return raw

    @staticmethod
    def has_role(user: dict | None, required: str) -> bool:
        if user is None:
            return False
        return ROLE_RANK.get(user.get("role", ""), 0) >= ROLE_RANK.get(required, 99)
