"""Fetch + parse blocklist sources, compile into a filter engine.

P0 keeps it in-memory and stateless. P3 adds SQLite persistence, ETag/
Last-Modified conditional fetch, per-list groups, and scheduled refresh.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..filter import FilterEngine, badfilter_keys, iter_rules
from ..filter.ipmatch import IPMatcher
from ..filter.rpz import iter_rpz_ips
from ..filter.rule import operator_rules
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


def cached_table_age(path) -> float | None:
    """Seconds since the compiled block table at `path` was written, or None when
    there is nothing to reuse.

    Asked in two places — by a worker deciding whether to serve the cached table
    while the refresh runs, and by the supervisor deciding whether to compile
    before it forks. They log different things about the answer, but the answer
    has to be the same one.
    """
    try:
        return max(0.0, time.time() - path.stat().st_mtime)
    except OSError:
        return None


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
                 table_path=None, ip_sources: list[str] | None = None,
                 groups: list | None = None):
        self.sources = sources
        self.ip_sources = list(ip_sources or [])
        # `filter.groups.GroupSpec` list. Each is compiled into its own small
        # engine that is layered over the default one, never a second copy of it.
        self.groups = list(groups or [])
        self.group_engines: dict[str, tuple] = {}
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

    #: Ceiling on one downloaded list. The largest lists in normal use are a
    #: few tens of MB; anything past this is a mistake or an attack.
    MAX_LIST_BYTES = 256 * 1024 * 1024
    #: Above this, the body is not retained for HTTP 304 revalidation.
    MAX_CACHED_BODY = 8 * 1024 * 1024

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
                # Read with a ceiling. `await r.text()` buffered whatever the
                # far end chose to send, so a compromised or redirected source
                # streaming gigabytes was fully materialised into a str before
                # anything looked at it — on a box with a hard memory limit.
                chunks: list[bytes] = []
                total = 0
                async for chunk in r.content.iter_chunked(65536):
                    total += len(chunk)
                    if total > self.MAX_LIST_BYTES:
                        raise ValueError(
                            f"list exceeds {self.MAX_LIST_BYTES // 1048576} MB; refusing")
                    chunks.append(chunk)
                text = b"".join(chunks).decode("utf-8", "replace")
                self._etags[src] = (r.headers.get("ETag", ""),
                                    r.headers.get("Last-Modified", ""))
                # Only small bodies are worth keeping for a future 304. A big
                # one stayed resident for the process lifetime *on top of* the
                # compiled table it became; dropping the validators instead
                # costs one full re-download per refresh and nothing else.
                if len(text) <= self.MAX_CACHED_BODY:
                    self._text_cache[src] = text
                else:
                    self._text_cache.pop(src, None)
                    self._etags.pop(src, None)
                return text
        # local file (sync read off-thread to keep the loop responsive)
        return await asyncio.to_thread(_local_path(src).read_text,
                                       encoding="utf-8", errors="replace")

    async def _persist(self, report: GravityReport) -> None:
        if self.db is None:
            return
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

    #: How many sources are fetched at once. Not unbounded: every body in
    #: flight is resident at the same time, and this runs on a box whose
    #: memory ceiling is what the whole design is arranged around. A refresh
    #: is a background job on a 24-hour schedule; there is nothing to win by
    #: downloading ten lists simultaneously.
    FETCH_CONCURRENCY = 3

    async def _fetch_all(self, report: GravityReport) -> list[tuple[str, str]]:
        """Every source's text, in order, with failures recorded rather than raised."""
        sem = asyncio.Semaphore(self.FETCH_CONCURRENCY)

        async def one(src: str) -> tuple[str, str, str | None]:
            async with sem:
                try:
                    return src, await self._fetch(src), None
                except Exception as e:  # network/file errors -> recorded, not fatal
                    return src, "", str(e)

        texts: list[tuple[str, str]] = []
        for src, text, err in await asyncio.gather(*(one(s) for s in self.sources)):
            if err is not None:
                report.sources.append(SourceResult(src, 0, False, err))
                report.errors.append(f"{src}: {err}")
                log.warning("blocklist source failed %s: %s", src, err)
                continue
            texts.append((src, text))
        return texts

    def _stream_rules(self, texts: list[tuple[str, str]], report: GravityReport):
        """Yield every rule in the corpus, dropping each source's text as it goes.

        A generator rather than a list on purpose: `FilterEngine.compile`
        consumes it once and files each rule into its compact form immediately,
        so the corpus never exists as 600k live `Rule` objects. Consumed
        destructively for the same reason — holding the text after it has been
        parsed keeps the largest single allocation alive for no reason.
        """
        def label(src: str) -> str:
            return src.rsplit("/", 1)[-1] or src

        while texts:
            src, text = texts.pop()
            count = 0
            for rule in iter_rules(text, label(src)):
                count += 1
                yield rule
            report.sources.append(SourceResult(src, count))
            report.total += count
        for rule in operator_rules(self.allow, self.deny):
            report.total += 1
            yield rule

    async def _build_ip_matcher(self, texts: list[tuple[str, str]],
                                report: GravityReport) -> IPMatcher:
        """Prefixes from the address lists, plus `rpz-ip` triggers in the name
        sources we have already downloaded."""
        matcher = IPMatcher()
        for src, text in texts:
            label = src.rsplit("/", 1)[-1] or src
            if ".rpz-ip" in text:
                for cidr, source in iter_rpz_ips(text, label):
                    matcher.add(cidr, source)
        for src in self.ip_sources:
            try:
                text = await self._fetch(src)
            except Exception as e:
                report.sources.append(SourceResult(src, 0, False, str(e)))
                report.errors.append(f"{src}: {e}")
                log.warning("address list failed %s: %s", src, e)
                continue
            label = src.rsplit("/", 1)[-1] or src
            report.sources.append(SourceResult(src, matcher.add_many(text, label)))
        if matcher:
            log.info("gravity compiled %d address prefixes", matcher.size)
        return matcher

    async def _build_groups(self, report: GravityReport) -> dict[str, tuple]:
        """One small engine per configured group.

        Fetched separately from the default corpus and compiled on its own, so
        a group costs its own rules and nothing more. A group whose sources all
        fail to fetch keeps no rules rather than half of them — the same
        all-or-nothing rule the default set follows.
        """
        out: dict[str, tuple] = {}
        for spec in self.groups:
            sub = GravityReport()
            fetcher = Gravity(list(spec.sources), spec.allow, spec.deny,
                              timeout=self.timeout)
            fetcher._etags = self._etags        # share HTTP validators
            fetcher._text_cache = self._text_cache
            texts = await fetcher._fetch_all(sub)
            if sub.errors:
                log.warning("group %r: %d source(s) failed (%s); group left empty",
                            spec.name, len(sub.errors), "; ".join(sub.errors[:2]))
                report.errors.extend(f"{spec.name}: {e}" for e in sub.errors)
                continue
            keys = badfilter_keys(texts)
            engine = await asyncio.to_thread(
                FilterEngine.compile, fetcher._stream_rules(texts, sub),
                badfilter_keys=keys)
            report.sources.extend(sub.sources)
            out[spec.name] = (engine, spec.inherit)
            log.info("group %r: %d rules (%s)", spec.name, sub.total,
                     "layered over the default set" if spec.inherit
                     else "used on its own")
        return out

    async def build(self) -> FilterEngine:
        report = GravityReport()
        texts = await self._fetch_all(report)
        matcher = await self._build_ip_matcher(texts, report)
        self.group_engines = await self._build_groups(report)
        # One cheap scan first: a $badfilter in one list disables a rule in
        # another, so the set has to be known before anything is compiled — and
        # knowing it up front is what lets the rules themselves be streamed.
        keys = badfilter_keys(texts)
        # Off the event loop. Compiling a household's corpus and writing the
        # ~24 MB shared table to an SD card is tens of seconds of synchronous
        # work on the hardware this runs on, and it used to run inside the
        # resolver's own loop: UDP piled up against `udp_max_inflight` and was
        # dropped, and TCP idle timers did not fire, every time the lists
        # refreshed. It is CPU- and IO-bound C and syscalls, so a worker thread
        # genuinely yields.
        engine = await asyncio.to_thread(
            FilterEngine.compile, self._stream_rules(texts, report),
            self.table_path, badfilter_keys=keys)
        engine.ips = matcher
        self.report = report
        await self._persist(report)
        log.info("gravity compiled: %d rules (%d block domains) from %d sources",
                 report.total, engine.size, len(self.sources))
        return engine
