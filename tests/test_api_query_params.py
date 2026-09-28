"""Numeric query parameters on the read APIs.

Each of these is a pagination or window hint parsed straight out of the query
string, and the console builds those URLs — so a stale bookmark, a hand-edited
link or a UI bug supplies the value. `int()` on a string that is not a number
raises ValueError out of the handler, and aiohttp turns that into a 500 with a
traceback.

One of the eight, `history?days=`, was already wrapped in a try/except falling
back to its default. The other seven were not, so the same typo in `top`,
`since`, `until`, `limit`, `offset`, `minutes` or `hours` was a 500. They now
share one helper, which also applies the cap — so no caller can keep the bound
that makes `limit` honest in one place and forget it in the next.
"""
from __future__ import annotations

import aiohttp
import pytest
from test_api import make_app

# "٣" is an Arabic-Indic digit: `str.isdigit()` is true for it and `int()`
# accepts it, so a guard written as a digit test rather than a try/except would
# let it through and then fail somewhere less convenient.
BAD = ["abc", "", "1e5", "-", "٣", "0x10", " ", "nan", "inf", "-inf",
       "-1", "-99999", "9" * 400]

ENDPOINTS = [
    ("/api/v1/querylog", "limit"),
    ("/api/v1/querylog", "offset"),
    ("/api/v1/querylog", "since"),
    ("/api/v1/querylog", "until"),
    ("/api/v1/timeseries", "minutes"),
    ("/api/v1/analytics", "top"),
    ("/api/v1/analytics", "since"),
    ("/api/v1/analytics", "until"),
    ("/api/v1/history", "days"),
    ("/api/v1/collateral", "hours"),
    ("/api/v1/collateral", "limit"),
    ("/api/v1/list-reviews", "limit"),
]


async def _logged_in(tmp_path):
    app, port = await make_app(tmp_path)
    base = f"http://127.0.0.1:{port}"
    session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    async with session.post(f"{base}/api/v1/auth/login",
                            json={"name": "admin", "password": "secret123"}) as r:
        assert r.status == 200
    return app, session, base


@pytest.mark.asyncio
async def test_no_numeric_parameter_can_be_made_to_return_a_500(tmp_path):
    app, session, base = await _logged_in(tmp_path)
    bad_status = []
    try:
        for path, param in ENDPOINTS:
            for value in BAD:
                params = {param: value}
                if path == "/api/v1/history":
                    params["name"] = "www.example.com"   # required, separately validated
                async with session.get(base + path, params=params) as r:
                    if r.status >= 500:
                        bad_status.append((path, param, value, r.status))
    finally:
        await session.close()
        await app.stop()
    assert not bad_status, f"{len(bad_status)} 5xx response(s): {bad_status[:5]}"


@pytest.mark.asyncio
async def test_a_good_numeric_parameter_is_still_read(tmp_path):
    """So the guard cannot quietly become "ignore the parameter"."""
    app, session, base = await _logged_in(tmp_path)
    try:
        async with session.get(base + "/api/v1/timeseries", params={"minutes": "5"}) as r:
            assert r.status == 200
            assert len((await r.json())["series"]) == 5
    finally:
        await session.close()
        await app.stop()


@pytest.mark.asyncio
async def test_a_parameter_over_its_cap_is_clamped_not_obeyed(tmp_path):
    """The cap moved into the helper; it has to still be applied."""
    app, session, base = await _logged_in(tmp_path)
    try:
        async with session.get(base + "/api/v1/timeseries",
                               params={"minutes": "100000"}) as r:
            assert r.status == 200
            series = (await r.json())["series"]
            assert len(series) == app.counters.SERIES_BUCKETS
    finally:
        await session.close()
        await app.stop()


@pytest.mark.asyncio
async def test_a_negative_limit_cannot_walk_through_the_cap(tmp_path):
    """SQLite reads a negative LIMIT as *no* limit, so `?limit=-1` returned the
    whole query log — every row materialised and serialised to JSON — past a cap
    that says 1000. One authenticated GET, any viewer.
    """
    from trench.store.querylog import QueryRecord

    app, session, base = await _logged_in(tmp_path)
    try:
        log = app.querylog
        for i in range(2_400):
            if i % 300 == 0:
                await log._flush()
            log.enqueue(QueryRecord(
                ts=1_700_000_000_000_000 + i, client_ip="10.0.0.5", client_id="",
                qname=f"h{i}.example.com", qtype="A", proto="udp", action="forwarded",
                reason="", rule="", source="", upstream="u", rcode="NOERROR",
                answers=[], elapsed_us=1000))
        await log._flush()

        async with session.get(base + "/api/v1/querylog", params={"limit": "99999"}) as r:
            assert len((await r.json())["rows"]) == 1_000      # the cap holds
        async with session.get(base + "/api/v1/querylog", params={"limit": "-1"}) as r:
            assert r.status == 200
            rows = (await r.json())["rows"]
        assert len(rows) <= 1_000, f"a negative limit returned {len(rows)} rows"
    finally:
        await session.close()
        await app.stop()


# JSON bodies carry the same kind of number, and `_json` will hand back whatever
# the caller sent — a string, a list, a dict — so the value is not even
# guaranteed to be numeric.
BAD_JSON = ["abc", "", "nan", "-1", -1, None, [], {}, 9 ** 400, True]


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["limit", "hours"])
async def test_a_json_body_number_is_guarded_like_a_query_parameter(tmp_path, field):
    """`whatif`'s `limit` is a SQL LIMIT over the query log, so a negative one
    is the same unbounded read as `querylog?limit=-1`."""
    app, session, base = await _logged_in(tmp_path)
    try:
        for value in BAD_JSON:
            async with session.post(base + "/api/v1/whatif",
                                    json={"deny": ["x.example.com"], field: value}) as r:
                assert r.status < 500, f"whatif {field}={value!r} gave {r.status}"
    finally:
        await session.close()
        await app.stop()


@pytest.mark.asyncio
async def test_an_api_token_expiry_cannot_overflow_the_clock(tmp_path):
    app, session, base = await _logged_in(tmp_path)
    try:
        for value in BAD_JSON:
            async with session.post(base + "/api/v1/auth/tokens",
                                    json={"name": f"t{abs(hash(str(value)))}",
                                          "scope": "viewer",
                                          "expires_days": value}) as r:
                assert r.status < 500, f"expires_days={value!r} gave {r.status}"
    finally:
        await session.close()
        await app.stop()
