"""DoH3's HTTP/3 request handling, driven directly.

The transport suite drives DoH3 over a real QUIC connection for the happy path.
Everything here is the request surface a client controls — the method, the path,
the base64 in it — reached without a handshake, so each refusal has its own
test rather than being reachable only by chance.
"""
from __future__ import annotations

import base64

import pytest
from support import blocked_engine

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.stats import Counters
from trench.transport.doh3 import _Stream
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Rcode


class Fwd:
    async def resolve(self, query, note=None):
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60,
                               R.A("93.184.216.34")))
        return resp


def _pipeline():
    return Pipeline(filter_engine=blocked_engine("doubleclick.net"), cache=Cache(),
                    forwarder=Fwd(), counters=Counters(), config=Config())


def mkquery(name="example.com"):
    m = Message(id=0x4242)
    m.set_flag(Flags.RD, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


def _b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class FakeH3:
    """Records what the protocol tried to send back."""

    def __init__(self):
        self.headers: list = []
        self.data: list = []

    def send_headers(self, stream_id, headers, end_stream=False):
        self.headers.append((stream_id, dict(headers)))

    def send_data(self, stream_id, data, end_stream=False):
        self.data.append((stream_id, data))


def _protocol():
    """A `DoHQuicProtocol` with just enough wired up to answer a request."""
    from trench.transport.doh3 import DoH3Protocol

    proto = DoH3Protocol.__new__(DoH3Protocol)
    proto.pipeline = _pipeline()
    proto._http = FakeH3()
    proto._streams = {}
    proto._tasks = set()

    class Quic:
        _network_paths = []

        def transmit(self):
            pass

    proto._quic = Quic()
    return proto


# --- _extract_query ---
def test_a_post_body_is_the_query():
    from trench.transport.doh3 import DoH3Protocol
    st = _Stream()
    st.method = "POST"
    st.body = bytearray(mkquery().to_wire())
    assert DoH3Protocol._extract_query(None, st) == mkquery().to_wire()


def test_a_get_carries_the_query_in_the_dns_parameter():
    from trench.transport.doh3 import DoH3Protocol
    st = _Stream()
    st.method = "GET"
    st.path = f"/dns-query?dns={_b64(mkquery().to_wire())}"
    assert DoH3Protocol._extract_query(None, st) == mkquery().to_wire()


def test_a_get_with_unparseable_base64_yields_nothing():
    from trench.transport.doh3 import DoH3Protocol
    st = _Stream()
    st.method = "GET"
    st.path = "/dns-query?dns=!!!not base64!!!"
    assert DoH3Protocol._extract_query(None, st) is None


def test_a_get_without_the_parameter_yields_nothing():
    from trench.transport.doh3 import DoH3Protocol
    st = _Stream()
    st.method = "GET"
    st.path = "/dns-query"
    assert DoH3Protocol._extract_query(None, st) is None


def test_a_method_that_carries_no_query_yields_nothing():
    from trench.transport.doh3 import DoH3Protocol
    st = _Stream()
    st.method = "PUT"
    st.path = "/dns-query"
    assert DoH3Protocol._extract_query(None, st) is None


# --- _respond ---
@pytest.mark.asyncio
async def test_a_well_formed_request_is_answered():
    proto = _protocol()
    st = _Stream()
    st.method = "POST"
    st.body = bytearray(mkquery().to_wire())
    proto._streams[4] = st
    await proto._respond(4)
    status = proto._http.headers[0][1][b":status"]
    assert status == b"200"
    assert proto._http.headers[0][1][b"content-type"] == b"application/dns-message"
    resp = Message.parse(proto._http.data[0][1])
    assert resp.answers[0].rdata.address == "93.184.216.34"


@pytest.mark.asyncio
async def test_a_request_with_no_query_in_it_is_a_400():
    proto = _protocol()
    st = _Stream()
    st.method = "GET"
    st.path = "/dns-query"
    proto._streams[4] = st
    await proto._respond(4)
    assert proto._http.headers[0][1][b":status"] == b"400"


@pytest.mark.asyncio
async def test_a_malformed_message_is_a_400():
    proto = _protocol()
    st = _Stream()
    st.method = "POST"
    st.body = bytearray(b"\x00")
    proto._streams[4] = st
    await proto._respond(4)
    assert proto._http.headers[0][1][b":status"] == b"400"


@pytest.mark.asyncio
async def test_a_stream_that_is_already_gone_is_ignored():
    proto = _protocol()
    await proto._respond(99)              # must not raise
    assert proto._http.headers == []


@pytest.mark.asyncio
async def test_an_error_while_answering_is_logged_not_raised(caplog):
    proto = _protocol()
    st = _Stream()
    st.method = "POST"
    st.body = bytearray(mkquery().to_wire())
    proto._streams[4] = st

    def boom(*a, **kw):
        raise RuntimeError("stream reset")

    proto._http.send_headers = boom
    await proto._respond(4)               # must not raise
    assert any("doh3 respond error" in r.getMessage() for r in caplog.records)


# --- header and data events ---
def test_headers_record_the_method_and_path():
    from aioquic.h3.events import HeadersReceived
    proto = _protocol()
    proto._on_headers(HeadersReceived(
        headers=[(b":method", b"GET"), (b":path", b"/dns-query?dns=AAA")],
        stream_id=4, stream_ended=False))
    st = proto._streams[4]
    assert st.method == "GET" and st.path == "/dns-query?dns=AAA"


@pytest.mark.asyncio
async def test_a_header_only_request_is_answered_immediately():
    from aioquic.h3.events import HeadersReceived
    proto = _protocol()
    proto._on_headers(HeadersReceived(
        headers=[(b":method", b"GET"),
                 (b":path", f"/dns-query?dns={_b64(mkquery().to_wire())}".encode())],
        stream_id=4, stream_ended=True))
    assert proto._tasks, "a completed request must be dispatched"
    for task in list(proto._tasks):
        task.cancel()


def test_body_data_accumulates_across_events():
    from aioquic.h3.events import DataReceived
    proto = _protocol()
    wire = mkquery().to_wire()
    proto._on_data(DataReceived(data=wire[:5], stream_id=4, stream_ended=False))
    proto._on_data(DataReceived(data=wire[5:], stream_id=4, stream_ended=False))
    assert bytes(proto._streams[4].body) == wire


@pytest.mark.asyncio
async def test_the_last_data_event_dispatches_the_request():
    from aioquic.h3.events import DataReceived
    proto = _protocol()
    proto._streams[4] = _Stream()
    proto._streams[4].method = "POST"
    proto._on_data(DataReceived(data=mkquery().to_wire(), stream_id=4,
                                stream_ended=True))
    assert proto._tasks
    for task in list(proto._tasks):
        task.cancel()
