"""Blocked-services engine: block whole apps/sites (YouTube, TikTok, ...) per
client, optionally only during scheduled windows.

Service domain packs load from data/services.json (refreshable); a small builtin
set is used as a fallback so the feature works out of the box.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from ..log import get

log = get("services")

# id -> list of domains (matches domain + subdomains). Builtin fallback.
_BUILTIN: dict[str, list[str]] = {
    "youtube": ["youtube.com", "youtu.be", "youtubei.googleapis.com", "ytimg.com",
                "googlevideo.com", "youtube-nocookie.com"],
    "facebook": ["facebook.com", "fbcdn.net", "fb.com", "fbsbx.com"],
    "instagram": ["instagram.com", "cdninstagram.com", "ig.me"],
    "tiktok": ["tiktok.com", "tiktokcdn.com", "byteoversea.com", "tiktokv.com"],
    "twitter": ["twitter.com", "x.com", "t.co", "twimg.com"],
    "netflix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com"],
    "reddit": ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"],
    "snapchat": ["snapchat.com", "sc-cdn.net"],
    "twitch": ["twitch.tv", "ttvnw.net", "jtvnw.net"],
    "discord": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "spotify": ["spotify.com", "scdn.co", "spotifycdn.com"],
}


class Services:
    def __init__(self, table: dict[str, list[str]] | None = None,
                 schedules: dict[str, list[tuple[int, int, int]]] | None = None):
        # build suffix -> service-id index
        self.table = table or _BUILTIN
        self.suffix_to_service: dict[str, str] = {}
        for sid, domains in self.table.items():
            for d in domains:
                d = d.strip().lower()
                if d:
                    self.suffix_to_service[d] = sid
        # schedule: service -> list of (weekday 0-6, start_minute, end_minute) blocked windows
        self.schedules = schedules or {}

    @classmethod
    def load(cls, data_dir: Path) -> Services:
        path = data_dir / "services.json"
        if path.exists():
            try:
                return cls(json.loads(path.read_text()))
            except Exception:
                log.warning("bad services.json, using builtin")
        return cls()

    def service_for(self, qname: str) -> str | None:
        labels = qname.rstrip(".").lower().split(".")
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            sid = self.suffix_to_service.get(cand)
            if sid:
                return sid
        return None

    def has_schedule(self, services: frozenset[str]) -> bool:
        """True if any of `services` is blocked only during certain windows.

        A scheduled verdict is a function of the clock, not of the query, so a
        recorded reply stops being correct the moment a window opens or closes.
        """
        return any(self.schedules.get(s) for s in services)

    def blocked_now(self, service: str, now: float | None = None) -> bool:
        windows = self.schedules.get(service)
        if not windows:
            return True  # no schedule => blocked whenever the service is selected
        lt = time.localtime(now if now is not None else time.time())
        minute = lt.tm_hour * 60 + lt.tm_min
        return any(day == lt.tm_wday and start <= minute < end for day, start, end in windows)

    def is_blocked(self, qname: str, blocked_services: frozenset[str],
                   now: float | None = None) -> str | None:
        if not blocked_services:
            return None
        sid = self.service_for(qname)
        if sid and sid in blocked_services and self.blocked_now(sid, now):
            return sid
        return None
