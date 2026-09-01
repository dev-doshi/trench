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
from ..wire.name import suffixes

log = get("services")

# id -> list of domains (matches domain + subdomains). Builtin fallback.
#
# The domains are deliberately the ones a client must resolve to *use* the
# service, not every domain the company owns: blocking `google.com` to stop
# YouTube takes the rest of the web with it. Each entry names the app's own
# domains plus the CDN hostnames its media comes from, because a service whose
# player still loads is not blocked in any sense the person asking would accept.
_BUILTIN: dict[str, list[str]] = {
    # --- social ---
    "facebook": ["facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "fb.gg"],
    "messenger": ["messenger.com"],
    "instagram": ["instagram.com", "cdninstagram.com", "ig.me"],
    "threads": ["threads.net", "threads.com"],
    "tiktok": ["tiktok.com", "tiktokcdn.com", "byteoversea.com", "tiktokv.com",
               "tiktokcdn-us.com", "ibytedtos.com"],
    "twitter": ["twitter.com", "x.com", "t.co", "twimg.com"],
    "bluesky": ["bsky.app", "bsky.social", "bsky.network"],
    "snapchat": ["snapchat.com", "sc-cdn.net", "snap.com", "snapkit.com"],
    "reddit": ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"],
    "pinterest": ["pinterest.com", "pinimg.com", "pin.it"],
    "tumblr": ["tumblr.com"],
    "linkedin": ["linkedin.com", "licdn.com", "lnkd.in"],
    "vk": ["vk.com", "vk.ru", "userapi.com", "vkuser.net"],
    "clubhouse": ["clubhouse.com", "joinclubhouse.com"],
    "9gag": ["9gag.com", "9cache.com"],
    "4chan": ["4chan.org", "4channel.org", "4cdn.org"],

    # --- messaging ---
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "telegram": ["telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com"],
    "signal": ["signal.org", "signalusercontent.org", "whispersystems.org"],
    "discord": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net",
                "discordcdn.com"],
    "skype": ["skype.com", "skypeassets.com"],
    "wechat": ["wechat.com", "weixin.qq.com", "wx.qq.com"],
    "line": ["line.me", "line-scdn.net", "line-apps.com"],
    "viber": ["viber.com"],
    "zoom": ["zoom.us", "zoom.com", "zoomgov.com"],
    "teams": ["teams.microsoft.com", "teams.live.com", "teams.cloud.microsoft"],
    "slack": ["slack.com", "slack-edge.com", "slack-msgs.com", "slackb.com"],

    # --- video ---
    "youtube": ["youtube.com", "youtu.be", "youtubei.googleapis.com", "ytimg.com",
                "googlevideo.com", "youtube-nocookie.com", "yt.be"],
    "netflix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com",
                "nflxso.net", "netflix.net"],
    "disneyplus": ["disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com"],
    "hulu": ["hulu.com", "hulustream.com", "huluim.com"],
    "primevideo": ["primevideo.com", "aiv-cdn.net", "aiv-delivery.net"],
    "max": ["max.com", "hbomax.com", "hbomaxcdn.com", "hbo.com"],
    "paramountplus": ["paramountplus.com", "cbsivideo.com", "cbsaavideo.com"],
    "peacock": ["peacocktv.com"],
    "appletv": ["tv.apple.com", "appletvplus.com"],
    "crunchyroll": ["crunchyroll.com", "vrv.co", "crunchyroll.net"],
    "dailymotion": ["dailymotion.com", "dmcdn.net", "dm.gg"],
    "vimeo": ["vimeo.com", "vimeocdn.com"],
    "twitch": ["twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net"],
    "kick": ["kick.com", "kick.tv"],
    "bilibili": ["bilibili.com", "bilivideo.com", "hdslb.com", "biliapi.net"],

    # --- music ---
    "spotify": ["spotify.com", "scdn.co", "spotifycdn.com", "spoti.fi"],
    "applemusic": ["music.apple.com"],
    "soundcloud": ["soundcloud.com", "sndcdn.com"],
    "deezer": ["deezer.com", "dzcdn.net"],
    "tidal": ["tidal.com", "tidalhifi.com"],
    "pandora": ["pandora.com", "p-cdn.us"],

    # --- gaming ---
    "steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com",
              "steamcontent.com", "steamusercontent.com", "valvesoftware.com"],
    "epicgames": ["epicgames.com", "unrealengine.com", "fortnite.com",
                  "epicgames.dev"],
    "roblox": ["roblox.com", "rbxcdn.com", "roblox.dev"],
    "minecraft": ["minecraft.net", "minecraftservices.com", "mojang.com"],
    "riotgames": ["riotgames.com", "leagueoflegends.com", "valorant.com",
                  "riotcdn.net", "rgpub.io"],
    "battlenet": ["battle.net", "blizzard.com", "blzstatic.cn", "battlenet.com.cn"],
    "ea": ["ea.com", "origin.com", "eaassets-a.akamaihd.net", "easports.com"],
    "ubisoft": ["ubisoft.com", "ubi.com", "ubisoftconnect.com", "ubistatic.com"],
    "playstation": ["playstation.com", "playstation.net", "sonyentertainmentnetwork.com"],
    "xbox": ["xbox.com", "xboxlive.com", "xboxservices.com"],
    "nintendo": ["nintendo.com", "nintendo.net", "nintendoswitch.com", "nintendo-europe.com"],
    "geforcenow": ["nvidiagrid.net", "geforcenow.com"],

    # --- AI assistants ---
    # New in the last two years and the most-asked-for category on school and
    # family networks; blocking these is why several households install a
    # resolver at all.
    "chatgpt": ["chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com",
                "chat.openai.com"],
    "claude": ["claude.ai", "anthropic.com"],
    "gemini": ["gemini.google.com", "bard.google.com", "generativelanguage.googleapis.com",
               "aistudio.google.com"],
    "copilot": ["copilot.microsoft.com", "githubcopilot.com"],
    "deepseek": ["deepseek.com", "deepseek.ai"],
    "perplexity": ["perplexity.ai", "pplx.ai", "perplexity.com"],
    "midjourney": ["midjourney.com"],
    "characterai": ["character.ai", "characterai.io"],
    "grok": ["grok.com", "x.ai"],

    # --- shopping ---
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.in",
               "amazon.ca", "amazon.com.au", "media-amazon.com", "ssl-images-amazon.com"],
    "ebay": ["ebay.com", "ebayimg.com", "ebaystatic.com", "ebay.co.uk", "ebay.de"],
    "aliexpress": ["aliexpress.com", "aliexpress.ru", "alicdn.com"],
    "temu": ["temu.com", "kwcdn.com"],
    "shein": ["shein.com", "ltwebstatic.com", "sheincorp.com"],
    "etsy": ["etsy.com", "etsystatic.com"],

    # --- gambling ---
    "bet365": ["bet365.com", "bet365affiliates.com"],
    "betway": ["betway.com", "betway.co.uk"],
    "betfair": ["betfair.com", "betfair.co.uk"],
    "draftkings": ["draftkings.com", "draftkings.co.uk"],
    "fanduel": ["fanduel.com"],
    "pokerstars": ["pokerstars.com", "pokerstars.eu"],
    "stake": ["stake.com", "stake.bet"],

    # --- dating ---
    "tinder": ["tinder.com", "gotinder.com"],
    "bumble": ["bumble.com"],
    "hinge": ["hinge.co"],
    "grindr": ["grindr.com", "grindr.mobi"],

    # --- file sharing ---
    "dropbox": ["dropbox.com", "dropboxusercontent.com", "dropboxstatic.com"],
    "mega": ["mega.nz", "mega.io", "mega.co.nz"],
    "wetransfer": ["wetransfer.com", "wetransfer.net"],
}

#: Service id -> category, for grouping in the console. Purely presentational:
#: nothing in the matcher reads it, and an id missing from here still blocks.
CATEGORIES: dict[str, str] = {
    **dict.fromkeys(("facebook", "messenger", "instagram", "threads", "tiktok", "twitter", "bluesky", "snapchat", "reddit", "pinterest", "tumblr", "linkedin", "vk", "clubhouse", "9gag", "4chan"), "social"),
    **dict.fromkeys(("whatsapp", "telegram", "signal", "discord", "skype", "wechat", "line", "viber", "zoom", "teams", "slack"), "messaging"),
    **dict.fromkeys(("youtube", "netflix", "disneyplus", "hulu", "primevideo", "max", "paramountplus", "peacock", "appletv", "crunchyroll", "dailymotion", "vimeo", "twitch", "kick", "bilibili"), "video"),
    **dict.fromkeys(("spotify", "applemusic", "soundcloud", "deezer", "tidal", "pandora"), "music"),
    **dict.fromkeys(("steam", "epicgames", "roblox", "minecraft", "riotgames", "battlenet", "ea", "ubisoft", "playstation", "xbox", "nintendo", "geforcenow"), "gaming"),
    **dict.fromkeys(("chatgpt", "claude", "gemini", "copilot", "deepseek", "perplexity", "midjourney", "characterai", "grok"), "ai"),
    **dict.fromkeys(("amazon", "ebay", "aliexpress", "temu", "shein", "etsy"), "shopping"),
    **dict.fromkeys(("bet365", "betway", "betfair", "draftkings", "fanduel", "pokerstars", "stake"), "gambling"),
    **dict.fromkeys(("tinder", "bumble", "hinge", "grindr"), "dating"),
    **dict.fromkeys(("dropbox", "mega", "wetransfer"), "files"),
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
        for cand in suffixes(qname):
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
