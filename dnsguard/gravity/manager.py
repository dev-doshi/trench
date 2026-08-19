"""Fetch + parse blocklist sources, compile into a filter engine.

P0 keeps it in-memory and stateless. P3 adds SQLite persistence, ETag/
Last-Modified conditional fetch, per-list groups, and scheduled refresh.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

from ..filter import FilterEngine, compile_rules
from ..filter.rule import Rule
from ..log import get
from ..version import USER_AGENT

log = get("gravity")

_PKG_ROOT = Path(__file__).resolve().parent.parent


def _local_path(src: str) -> Path:
    """Resolve a non-URL source to a readable file.

    A relative source is taken as written first, so a checkout keeps working
    from its own tree. If nothing is there, the same relative path is tried
    against the data shipped inside the package — otherwise the documented
    quickstart (`--source data/default_blocklist.txt`) would only ever work
    for people who cloned the repo, and fail for everyone who pip-installed.
    """
    p = Path(src).expanduser()
    if p.is_absolute() or p.exists():
        return p
    packaged = _PKG_ROOT / p
    # Fall through to `p` when neither exists, so the resulting error names the
    # path the operator actually wrote.
    return packaged if packaged.is_file() else p


@dataclass
class SourceResult:
    src: str
    count: int = 0
    ok: bool = True
    error: str = ""


@dataclass
class GravityReport:
    total: int = 0
    sources: list[SourceResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Gravity:
    def __init__(self, sources: list[str], allow: list[str] | None = None,
                 deny: list[str] | None = None, timeout: float = 30.0, db=None,
                 table_path=None):
        self.sources = sources
        # Where the compiled block table is written, if anywhere. Persisting it
        # lets every worker map one copy and lets a restart skip the reparse.
        self.table_path = table_path
        self.allow = set(allow or [])
        self.deny = set(deny or [])
        self.timeout = timeout
        self.db = db
        self.report = GravityReport()
        self._text_cache: dict[str, str] = {}     # last body per URL (for HTTP 304)
        self._etags: dict[str, tuple[str, str]] = {}  # url -> (etag, last-modified)

    async def _fetch(self, src: str) -> str:
        if src.startswith(("http://", "https://")):
            import aiohttp  # lazy import; only needed for remote lists
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
            etag, modified = self._etags.get(src, ("", ""))
            if etag:
                headers["If-None-Match"] = etag
            if modified:
                headers["If-Modified-Since"] = modified
            async with (
                aiohttp.ClientSession(timeout=timeout, headers=headers) as s,
                s.get(src) as r,
            ):
                if r.status == 304 and src in self._text_cache:
                    return self._text_cache[src]   # unchanged since last fetch
                r.raise_for_status()
                text = await r.text()
                self._etags[src] = (r.headers.get("ETag", ""),
                                    r.headers.get("Last-Modified", ""))
                self._text_cache[src] = text
                return text
        # local file (sync read off-thread to keep the loop responsive)
        return await asyncio.to_thread(_local_path(src).read_text,
                                       encoding="utf-8", errors="replace")

    async def _persist(self, report: GravityReport) -> None:
        if self.db is None:
            return
        import time
        now = int(time.time())
        for s in report.sources:
            etag, modified = self._etags.get(s.src, ("", ""))
            await self.db.execute(
                "INSERT INTO adlist(url, last_update, http_etag, http_modified, rule_count,"
                " status, error) VALUES(?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET"
                " last_update=excluded.last_update, http_etag=excluded.http_etag,"
                " http_modified=excluded.http_modified, rule_count=excluded.rule_count,"
                " status=excluded.status, error=excluded.error",
                (s.src, now, etag, modified, s.count, "ok" if s.ok else "error", s.error))

    async def build(self) -> FilterEngine:
        report = GravityReport()

        def label(s: str) -> str:
            return s.rsplit("/", 1)[-1] or s

        async def one(src: str) -> tuple[str, list[Rule], str | None]:
            try:
                text = await self._fetch(src)
                return src, compile_rules(text, label(src)), None
            except Exception as e:  # network/file errors -> recorded, not fatal
                return src, [], str(e)

        results = await asyncio.gather(*(one(s) for s in self.sources))
        all_rules: list[Rule] = []
        for src, rules, err in results:
            if err:
                report.sources.append(SourceResult(src, 0, False, err))
                report.errors.append(f"{src}: {err}")
                log.warning("blocklist source failed %s: %s", src, err)
                continue
            report.sources.append(SourceResult(src, len(rules)))
            all_rules.extend(rules)

        # config-level allow/deny become important allow rules / block rules
        for d in self.allow:
            all_rules.append(Rule(raw=d, block=False, important=True,
                                  suffix=d.lower(), source="allowlist"))
        for d in self.deny:
            all_rules.append(Rule(raw=d, block=True, suffix=d.lower(), source="denylist"))

        report.total = len(all_rules)
        self.report = report
        engine = FilterEngine.compile(all_rules, self.table_path)
        await self._persist(report)
        log.info("gravity compiled: %d rules (%d block domains) from %d sources",
                 report.total, engine.size, len(self.sources))
        return engine
