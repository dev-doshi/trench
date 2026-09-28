"""Gravity's source fetching: local paths, HTTP caching, and the size ceiling.

`_fetch` is where untrusted bytes enter the process. The ceiling that stops a
redirected source materialising gigabytes on a box with a hard memory limit, the
conditional-request path, and the packaged-data fallback that makes the
documented quickstart work from a wheel were all uncovered.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from trench.gravity.manager import (
    Gravity,
    GravityReport,
    SourceResult,
    _local_path,
    cached_table_age,
)
from trench.wire.rrtypes import Rcode


# --- _local_path ---
def test_an_absolute_path_is_taken_as_written(tmp_path):
    p = tmp_path / "list.txt"
    p.write_text("x")
    assert _local_path(str(p)) == p


def test_an_existing_relative_path_wins(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "local.txt").write_text("x")
    assert _local_path("local.txt") == Path("local.txt")


def test_a_relative_path_falls_back_to_the_packaged_data(tmp_path, monkeypatch):
    """`--source data/default_blocklist.txt` is the documented quickstart; it
    has to work for someone who pip-installed, not only from a checkout."""
    monkeypatch.chdir(tmp_path)
    resolved = _local_path("data/default_blocklist.txt")
    assert resolved.is_file()
    assert resolved.is_absolute()
    assert "trench" in resolved.parts


def test_a_path_that_exists_nowhere_is_returned_as_written(tmp_path, monkeypatch):
    """So the resulting error names the path the operator actually wrote."""
    monkeypatch.chdir(tmp_path)
    assert _local_path("no/such/list.txt") == Path("no/such/list.txt")


def test_a_tilde_path_is_expanded():
    assert not str(_local_path("~/lists/x.txt")).startswith("~")


# --- cached_table_age ---
def test_the_age_of_a_missing_table_is_none(tmp_path):
    assert cached_table_age(tmp_path / "gravity.table") is None


def test_the_age_of_a_fresh_table_is_near_zero(tmp_path):
    import os
    p = tmp_path / "gravity.table"
    p.write_bytes(b"x")
    assert 0 <= cached_table_age(p) < 5
    old = os.stat(p).st_mtime - 3600
    os.utime(p, (old, old))
    assert 3500 < cached_table_age(p) < 3700


def test_an_age_is_never_negative(tmp_path):
    """A table written by a box whose clock is ahead is stale, not negative."""
    import os
    p = tmp_path / "gravity.table"
    p.write_bytes(b"x")
    future = os.stat(p).st_mtime + 10_000
    os.utime(p, (future, future))
    assert cached_table_age(p) == 0.0


# --- local fetch ---
@pytest.mark.asyncio
async def test_a_local_file_is_read(tmp_path):
    src = tmp_path / "list.txt"
    src.write_text("||ads.example.com^\n")
    g = Gravity([str(src)])
    assert await g._fetch(str(src)) == "||ads.example.com^\n"


@pytest.mark.asyncio
async def test_invalid_utf8_in_a_local_file_is_replaced_not_fatal(tmp_path):
    src = tmp_path / "list.txt"
    src.write_bytes(b"||ads.example.com^\n\xff\xfe\n")
    assert "ads.example.com" in await Gravity([str(src)])._fetch(str(src))


@pytest.mark.asyncio
async def test_a_missing_local_file_raises(tmp_path):
    with pytest.raises(OSError):
        await Gravity([])._fetch(str(tmp_path / "nope.txt"))


# --- HTTP fetch ---
class _Handler(BaseHTTPRequestHandler):
    state: dict = {}

    def do_GET(self):
        st = self.state
        st.setdefault("requests", []).append(dict(self.headers))
        if st.get("status") == 304 and self.headers.get("If-None-Match"):
            self.send_response(304)
            self.end_headers()
            return
        body = st.get("body", b"||ads.example.com^\n")
        self.send_response(st.get("status", 200))
        for k, v in st.get("headers", {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def http():
    _Handler.state = {}
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01},
                     daemon=True).start()

    class H:
        url = f"http://127.0.0.1:{srv.server_address[1]}/list.txt"
        state = _Handler.state

    yield H
    srv.shutdown()
    srv.server_close()


@pytest.mark.asyncio
async def test_an_http_source_is_downloaded(http):
    g = Gravity([http.url])
    assert await g._fetch(http.url) == "||ads.example.com^\n"
    assert http.state["requests"][0]["User-Agent"].startswith("trench")


@pytest.mark.asyncio
async def test_validators_are_stored_and_replayed_as_conditional_headers(http):
    http.state["headers"] = {"ETag": '"abc"', "Last-Modified": "Wed, 21 Oct 2020 07:28:00 GMT"}
    g = Gravity([http.url])
    await g._fetch(http.url)
    assert g._etags[http.url] == ('"abc"', "Wed, 21 Oct 2020 07:28:00 GMT")
    await g._fetch(http.url)
    second = http.state["requests"][1]
    assert second["If-None-Match"] == '"abc"'
    assert second["If-Modified-Since"] == "Wed, 21 Oct 2020 07:28:00 GMT"


@pytest.mark.asyncio
async def test_a_304_returns_the_cached_body_without_re_reading(http):
    http.state["headers"] = {"ETag": '"abc"'}
    g = Gravity([http.url])
    first = await g._fetch(http.url)
    http.state["status"] = 304
    assert await g._fetch(http.url) == first


@pytest.mark.asyncio
async def test_an_http_error_is_raised(http):
    import aiohttp
    http.state["status"] = 500
    with pytest.raises(aiohttp.ClientResponseError):
        await Gravity([http.url])._fetch(http.url)


@pytest.mark.asyncio
async def test_a_list_past_the_ceiling_is_refused(http):
    """A compromised or redirected source streaming gigabytes used to be fully
    materialised into a str before anything looked at it."""
    g = Gravity([http.url])
    g.MAX_LIST_BYTES = 1024
    http.state["body"] = b"#" * 4096
    with pytest.raises(ValueError, match="refusing"):
        await g._fetch(http.url)


@pytest.mark.asyncio
async def test_a_large_body_is_not_retained_for_revalidation(http):
    """It would stay resident for the process lifetime on top of the compiled
    table it became."""
    g = Gravity([http.url])
    g.MAX_CACHED_BODY = 8
    http.state["headers"] = {"ETag": '"abc"'}
    http.state["body"] = b"||a.example.com^\n||b.example.com^\n"
    await g._fetch(http.url)
    assert http.url not in g._text_cache
    assert http.url not in g._etags
    # And the next fetch is unconditional, since there is nothing to validate.
    await g._fetch(http.url)
    assert "If-None-Match" not in http.state["requests"][1]


@pytest.mark.asyncio
async def test_a_small_body_is_retained(http):
    g = Gravity([http.url])
    http.state["headers"] = {"ETag": '"abc"'}
    await g._fetch(http.url)
    assert g._text_cache[http.url]


# --- address lists ---
@pytest.mark.asyncio
async def test_address_sources_are_fetched_and_compiled(tmp_path):
    ips = tmp_path / "ips.txt"
    ips.write_text("192.0.2.0/24\n198.51.100.7\n")
    g = Gravity([], ip_sources=[str(ips)])
    report = GravityReport()
    matcher = await g._build_ip_matcher([], report)
    assert matcher.size == 2
    assert report.sources[0].ok is True and report.sources[0].count == 2


@pytest.mark.asyncio
async def test_a_failing_address_source_is_reported_and_skipped(tmp_path, caplog):
    g = Gravity([], ip_sources=[str(tmp_path / "gone.txt")])
    report = GravityReport()
    matcher = await g._build_ip_matcher([], report)
    assert matcher.size == 0
    assert report.errors and report.sources[0].ok is False
    assert any("address list failed" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_rpz_ip_triggers_in_a_name_list_become_prefixes(tmp_path):
    text = ("$TTL 60\n@ SOA localhost. root.localhost. 1 3600 600 86400 60\n"
            "24.0.2.0.192.rpz-ip CNAME .\n")
    g = Gravity([])
    matcher = await g._build_ip_matcher([("badips.rpz", text)], GravityReport())
    assert matcher.size >= 1


@pytest.mark.asyncio
async def test_no_address_sources_yields_an_empty_matcher():
    matcher = await Gravity([])._build_ip_matcher([], GravityReport())
    assert matcher.size == 0
    assert not matcher


# --- report shapes ---
def test_a_source_result_defaults_to_success():
    r = SourceResult("x")
    assert r.ok is True and r.count == 0 and r.error == ""


def test_a_fresh_report_is_empty():
    r = GravityReport()
    assert r.total == 0 and r.sources == [] and r.errors == []


# --- the whole build ---
@pytest.mark.asyncio
async def test_build_reports_per_source_counts_and_errors(tmp_path):
    good = tmp_path / "good.txt"
    good.write_text("||ads.example.com^\n||tracker.example.net^\n")
    g = Gravity([str(good), str(tmp_path / "missing.txt")],
                allow=["ok.example.com"], deny=["extra.example.org"])
    engine = await g.build()
    from trench.filter import Action
    assert engine.match("ads.example.com").action == Action.BLOCK
    assert engine.match("extra.example.org").action == Action.BLOCK
    assert engine.match("ok.example.com").action == Action.ALLOW
    ok = [s for s in g.report.sources if s.ok]
    bad = [s for s in g.report.sources if not s.ok]
    assert ok and bad
    assert g.report.errors


@pytest.mark.asyncio
async def test_build_writes_the_table_when_a_path_is_given(tmp_path):
    src = tmp_path / "list.txt"
    src.write_text("||ads.example.com^\n")
    table = tmp_path / "gravity.table"
    await Gravity([str(src)], table_path=table).build()
    assert table.exists() and table.stat().st_size > 0


@pytest.mark.asyncio
async def test_build_reaches_the_ip_matcher_before_the_texts_are_consumed(tmp_path):
    """`_stream_rules` pops each source's text as it parses it, to keep the
    largest allocation from outliving its use. `_build_ip_matcher` reads the
    same list, and every other test hands it texts directly — so the ordering
    inside `build()` was load-bearing and unguarded: moving the matcher below
    the compile step makes every rpz-ip trigger in a name list silently vanish,
    with the whole suite still green.
    """
    source = tmp_path / "names.rpz"
    source.write_text("$TTL 60\n@ SOA localhost. root.localhost. 1 3600 600 86400 60\n"
                      "24.0.2.0.192.rpz-ip CNAME .\n"
                      "ads.example.com CNAME .\n")   # RPZ for "answer NXDOMAIN"
    gravity = Gravity([str(source)], table_path=tmp_path / "table.bin")
    engine = await gravity.build()

    assert engine.ips is not None and engine.ips.size >= 1, \
        "the rpz-ip trigger did not reach the compiled engine"
    assert engine.ips.match("192.0.2.7") is not None
    # and the name rules still compiled from the same text: RPZ `CNAME .` is
    # "answer NXDOMAIN", which is a rewrite rather than a block
    assert engine.match("ads.example.com").rcode == Rcode.NXDOMAIN
