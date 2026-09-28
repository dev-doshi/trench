"""The DoH frontend's two GET APIs, driven over a real socket.

The JSON API (RFC 8484's companion, `?name=&type=`) had no test at all, and it
takes both of its parameters straight from the query string of an open resolver
endpoint. `type` was guarded and answered 400; `name` was not, so a name that
did not parse became a 500 and a traceback — once per request, chosen by the
caller.
"""
from __future__ import annotations

import socket

import aiohttp
import pytest

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.filter import FilterEngine, compile_rules
from trench.stats import Counters
from trench.transport.doh import DoHServer
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R


class _Upstream:
    async def resolve(self, query: Message, note=None) -> Message:
        reply = query.reply(0)
        q = query.question
        if q is not None and q.rtype == Type.A:
            reply.answers.append(RR(q.name, Type.A, Class.IN, 300, R.A("93.184.216.34")))
        return reply


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _get(params: dict) -> tuple[int, dict]:
    """Start a DoH frontend, make one GET, and hand back (status, body)."""
    doh, url = await _server()
    try:
        async with (aiohttp.ClientSession() as session,
                    session.get(url, params=params) as response):
            # content_type=None: the JSON API answers `application/dns-json`,
            # which aiohttp will not decode without being told to.
            if response.content_type.endswith("json"):
                return response.status, await response.json(content_type=None)
            return response.status, {}
    finally:
        await doh.stop()


async def _server():
    pipeline = Pipeline(filter_engine=FilterEngine.compile(compile_rules("", "test")),
                        cache=Cache(), forwarder=_Upstream(), counters=Counters(),
                        config=Config.model_validate({}))
    doh = DoHServer(pipeline, "127.0.0.1", _free_port())
    await doh.start()
    return doh, f"http://127.0.0.1:{doh.port}/dns-query"


@pytest.mark.asyncio
async def test_the_json_api_answers_a_good_name():
    status, body = await _get({"name": "www.example.com", "type": "A"})
    assert status == 200
    assert any(a["data"] == "93.184.216.34" for a in body["Answer"])


@pytest.mark.asyncio
@pytest.mark.parametrize("name", [
    "a\\",                                  # trailing backslash
    "a\\999",                               # \DDD out of range
    "x" * 64 + ".com",                      # label too long
    ".".join(["label"] * 60),               # name too long
    "ünicode.com",                     # not punycoded
])
async def test_a_name_that_does_not_parse_is_a_client_error(name):
    status, body = await _get({"name": name})
    assert status == 400, f"{name!r} gave {status}"
    assert body["error"] == "bad name"


@pytest.mark.asyncio
async def test_a_type_that_does_not_parse_is_still_a_client_error():
    """The guard that was already there, so the one added beside it cannot
    quietly replace it."""
    status, body = await _get({"name": "www.example.com", "type": "NOPE"})
    assert status == 400
    assert body["error"] == "bad type"


@pytest.mark.asyncio
async def test_a_name_with_a_dot_inside_a_label_is_answerable():
    """`\\.` is the escape for a literal dot in a label. It used to raise out of
    `from_text` before anything could answer it."""
    status, body = await _get({"name": "ex\\.ample.com", "type": "A"})
    assert status == 200
    assert body["Question"][0]["name"].startswith("ex\\.ample")


@pytest.mark.asyncio
async def test_the_wire_api_still_rejects_bad_base64():
    status, _ = await _get({"dns": "!!!not-base64!!!"})
    assert status == 400
