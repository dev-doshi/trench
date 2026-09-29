"""Zone traffic (AXFR, NOTIFY, UPDATE) is rate limited like any other query.

It is handed to the zone handler before the pipeline runs, so the pipeline's
per-client limit never saw it: every transfer, TSIG check and update was
unmetered.
"""
from __future__ import annotations

import pytest

from trench.engine.ratelimit import RateLimiter
from trench.transport.do53 import _tcp_responder, _UDPProtocol
from trench.wire import Class, Message, Question, Type
from trench.wire.name import Name


class _Pipeline:
    def __init__(self, rate):
        self.ratelimiter = RateLimiter(rate)


class _Auth:
    def __init__(self):
        self.handled = 0

    def claims(self, query):
        return True

    def handle_udp(self, data, query, ip):
        self.handled += 1
        return b"reply"

    def handle_tcp(self, data, query, ip):
        self.handled += 1
        return [b"reply"]


class _Transport:
    def __init__(self):
        self.sent = []

    def get_write_buffer_size(self):
        return 0

    def sendto(self, data, addr):
        self.sent.append(data)


def _axfr() -> bytes:
    m = Message(id=7)
    m.questions.append(Question(Name.from_text("example.com."), Type.AXFR, Class.IN))
    return m.to_wire()


@pytest.mark.asyncio
async def test_zone_traffic_over_tcp_stops_at_the_rate_limit():
    auth = _Auth()
    respond = _tcp_responder(_Pipeline(1), auth)
    answers = [await respond(_axfr(), "10.0.0.5") for _ in range(20)]
    assert auth.handled < 20
    assert [] in answers


@pytest.mark.asyncio
async def test_zone_traffic_over_udp_stops_at_the_rate_limit():
    auth = _Auth()
    proto = _UDPProtocol(_Pipeline(1), auth)
    proto.transport = _Transport()
    for _ in range(20):
        proto.inflight += 1
        await proto._handle(_axfr(), ("10.0.0.5", 5353))
    assert auth.handled < 20
    assert len(proto.transport.sent) == auth.handled


@pytest.mark.asyncio
async def test_without_a_rate_limit_zone_traffic_is_unaffected():
    auth = _Auth()
    respond = _tcp_responder(_Pipeline(0), auth)
    for _ in range(20):
        assert await respond(_axfr(), "10.0.0.5") == [b"reply"]
