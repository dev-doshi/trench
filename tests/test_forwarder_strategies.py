"""Forwarder strategies: sequential, parallel and fastest.

Only the default path was exercised. The strategies decide which upstream a
household's queries actually reach, and each has a failure mode of its own —
a loser taking credit for a race it lost, a fallback tier that never runs, or
connections left open when a settings change swaps the forwarder out.
"""
from __future__ import annotations

import asyncio

import pytest

from trench.errors import UpstreamError
from trench.resolver.forwarder import Forwarder, parse_server
from trench.transport.upstream import parse_upstream
from trench.wire import Class, Message, Question, Type
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


def _query(name="example.com"):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


class FakeUpstream:
    """One upstream, with a controllable delay and outcome."""

    def __init__(self, label, *, delay=0.0, fail=None, failures=0, rtt=0.0):
        self.label = label
        self.delay = delay
        self.fail = fail
        self.failures = failures
        self.rtt = rtt
        self.asked = 0
        self.closed = False

    async def query(self, q):
        self.asked += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise UpstreamError(self.fail)
        resp = q.reply(Rcode.NOERROR)
        return resp

    async def close(self):
        self.closed = True

    def __repr__(self):
        return self.label


def _forwarder(upstreams, strategy="parallel"):
    fwd = Forwarder([], strategy=strategy)

    class Router:
        def __init__(self, ups):
            self.ups = ups
            self.closed = False

        def group_for(self, qname):
            return list(self.ups)

        async def close(self):
            self.closed = True
            for u in self.ups:
                await u.close()

    fwd.router = Router(upstreams)
    return fwd


# --- parse_server ---
@pytest.mark.parametrize("spec,host,port", [
    ("1.1.1.1", "1.1.1.1", 53),
    ("1.1.1.1:5353", "1.1.1.1", 5353),
    ("tls://1.1.1.1", "1.1.1.1", 853),
])
def test_parse_server_returns_host_and_port(spec, host, port):
    assert parse_server(spec) == (host, port)


# --- no upstreams ---
@pytest.mark.asyncio
async def test_no_upstreams_is_an_error_not_a_hang():
    fwd = _forwarder([])
    with pytest.raises(UpstreamError, match="no upstreams configured"):
        await fwd.resolve(_query())


@pytest.mark.asyncio
async def test_a_query_without_a_question_still_routes():
    fwd = _forwarder([FakeUpstream("a")])
    assert await fwd.resolve(Message(id=1)) is not None


# --- sequential ---
@pytest.mark.asyncio
async def test_sequential_asks_in_order_and_stops_at_the_first_answer():
    a, b = FakeUpstream("a"), FakeUpstream("b")
    fwd = _forwarder([a, b], "sequential")
    who = []
    await fwd.resolve(_query(), note=who.append)
    assert a.asked == 1 and b.asked == 0
    assert who == ["a"]


@pytest.mark.asyncio
async def test_sequential_falls_through_to_the_next_upstream():
    a, b = FakeUpstream("a", fail="refused"), FakeUpstream("b")
    fwd = _forwarder([a, b], "sequential")
    who = []
    await fwd.resolve(_query(), note=who.append)
    assert a.asked == 1 and b.asked == 1
    assert who == ["b"]


@pytest.mark.asyncio
async def test_sequential_reports_the_last_failure_when_all_fail():
    fwd = _forwarder([FakeUpstream("a", fail="one"), FakeUpstream("b", fail="two")],
                     "sequential")
    with pytest.raises(UpstreamError, match="two"):
        await fwd.resolve(_query())


# --- parallel ---
@pytest.mark.asyncio
async def test_parallel_asks_everyone_and_takes_the_first_answer():
    slow = FakeUpstream("slow", delay=0.2)
    fast = FakeUpstream("fast")
    fwd = _forwarder([slow, fast])
    who = []
    await fwd.resolve(_query(), note=who.append)
    assert who == ["fast"], "the label must travel with the answer, not be reported by the loser"


@pytest.mark.asyncio
async def test_parallel_cancels_the_losers():
    slow = FakeUpstream("slow", delay=5)
    fwd = _forwarder([slow, FakeUpstream("fast")])
    await fwd.resolve(_query())
    await asyncio.sleep(0)
    # Nothing is left running: the test would otherwise leak a five-second task.
    pending = [t for t in asyncio.all_tasks() if "_ask" in repr(t)]
    assert pending == []


@pytest.mark.asyncio
async def test_parallel_survives_one_failing_upstream():
    fwd = _forwarder([FakeUpstream("bad", fail="refused"), FakeUpstream("good")])
    who = []
    await fwd.resolve(_query(), note=who.append)
    assert who == ["good"]


@pytest.mark.asyncio
async def test_parallel_reports_when_every_upstream_fails():
    fwd = _forwarder([FakeUpstream("a", fail="one"), FakeUpstream("b", fail="two")])
    with pytest.raises(UpstreamError, match="all upstreams failed"):
        await fwd.resolve(_query())


# --- fastest / weighted ---
@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", ["fastest", "weighted"])
async def test_fastest_with_a_single_upstream_asks_it_directly(strategy):
    only = FakeUpstream("only")
    fwd = _forwarder([only], strategy)
    who = []
    await fwd.resolve(_query(), note=who.append)
    assert only.asked == 1 and who == ["only"]


@pytest.mark.asyncio
async def test_fastest_asks_only_the_fastest_and_leaves_the_rest_alone():
    quick = FakeUpstream("quick", rtt=0.01)
    ok = FakeUpstream("ok", rtt=0.05)
    slow = FakeUpstream("slow", rtt=1.0)
    fwd = _forwarder([slow, ok, quick], "fastest")
    await fwd.resolve(_query())
    assert quick.asked == 1
    assert ok.asked == 0 and slow.asked == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", ["fastest", "weighted"])
async def test_fastest_does_not_query_both_of_two_upstreams(strategy):
    """The head used to be the two fastest, so at the group size people actually
    configure `fastest` was an alias for `parallel` — both servers asked for
    every name, and the ranking above it decided nothing."""
    quick = FakeUpstream("quick", rtt=0.01)
    other = FakeUpstream("other", rtt=0.05)
    fwd = _forwarder([other, quick], strategy)
    who = []
    await fwd.resolve(_query(), note=who.append)
    assert who == ["quick"]
    assert other.asked == 0, "the second upstream is a fallback, not a co-winner"


@pytest.mark.asyncio
async def test_an_upstream_with_failures_is_ranked_behind_a_slower_healthy_one():
    broken = FakeUpstream("broken", failures=3, rtt=0.001)
    healthy = FakeUpstream("healthy", failures=0, rtt=0.5)
    third = FakeUpstream("third", failures=0, rtt=0.9)
    fwd = _forwarder([broken, healthy, third], "fastest")
    await fwd.resolve(_query())
    assert broken.asked == 0, "failures outrank round-trip time"


@pytest.mark.asyncio
async def test_fastest_falls_back_to_the_remaining_upstreams():
    a = FakeUpstream("a", rtt=0.01, fail="down")
    b = FakeUpstream("b", rtt=0.02, fail="down")
    c = FakeUpstream("c", rtt=1.0)
    fwd = _forwarder([a, b, c], "fastest")
    who = []
    await fwd.resolve(_query(), note=who.append)
    assert who == ["c"]


@pytest.mark.asyncio
async def test_fastest_raises_when_every_tier_fails():
    a = FakeUpstream("a", rtt=0.01, fail="down")
    b = FakeUpstream("b", rtt=0.02, fail="down")
    fwd = _forwarder([a, b], "fastest")
    with pytest.raises(UpstreamError):
        await fwd.resolve(_query())


@pytest.mark.asyncio
async def test_an_unknown_strategy_falls_back_to_parallel():
    a, b = FakeUpstream("a"), FakeUpstream("b")
    fwd = _forwarder([a, b], "round-robin-ish")
    await fwd.resolve(_query())
    assert a.asked == 1 and b.asked == 1


# --- close ---
@pytest.mark.asyncio
async def test_closing_drops_every_upstream_connection():
    """Without it, a settings change leaks one set of DoT connections and DoH
    sessions per change, for the life of the process."""
    a, b = FakeUpstream("a"), FakeUpstream("b")
    fwd = _forwarder([a, b])
    await fwd.close()
    assert a.closed and b.closed
    assert fwd.router.closed


# --- a real Router, so the wiring is not only tested against a double ---
@pytest.mark.asyncio
async def test_a_real_forwarder_routes_by_qname():
    fwd = Forwarder(["1.1.1.1", "example.com/9.9.9.9"], timeout=0.1)
    try:
        assert fwd.router.group_for("anything.test.") is not None
    finally:
        await fwd.close()


# --- a race must not leave its losers' failures unretrieved -------------------
class ResetOnCancel:
    """An upstream that turns its own cancellation into a connection error.

    Not contrived: cancelling a DoT read raises CancelledError inside
    `readexactly`, and the cleanup around it reports the half-read stream as
    `ConnectionResetError`. The task then ends *failed* rather than cancelled,
    and `cancel()` does not clear that exception — so nobody ever retrieves it.
    """

    failures = 0
    rtt = 0.0

    def __init__(self, label="reset"):
        self.label = label
        self.asked = 0

    async def query(self, q):
        self.asked += 1
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            raise ConnectionResetError(104, "Connection reset by peer") from None

    async def close(self):
        pass

    def __repr__(self):
        return self.label


@pytest.mark.asyncio
async def test_a_loser_cancelled_mid_read_does_not_report_its_own_failure():
    """asyncio logs "Task exception was never retrieved" with a full traceback
    when such a task is collected. The query itself succeeded — the winner
    answered — so that traceback is noise in the operator's log, and noise is
    what hides the tracebacks that matter."""
    import gc
    seen: list = []
    asyncio.get_running_loop().set_exception_handler(lambda loop, ctx: seen.append(ctx))
    fwd = _forwarder([FakeUpstream("winner", delay=0.0), ResetOnCancel()],
                     strategy="parallel")
    resp = await fwd.resolve(_query())
    assert resp.rcode == Rcode.NOERROR          # the winner answered
    for _ in range(3):                          # let the cancellation land
        await asyncio.sleep(0)
    gc.collect()
    await asyncio.sleep(0)
    assert not seen, f"the loser's failure was reported to the operator: {seen}"


# --- malformed upstream specs -------------------------------------------------
@pytest.mark.parametrize("spec,problem", [
    ("1.1.1.1:abc", "non-numeric port"),
    ("1.1.1.1:", "non-numeric port"),
    ("tls://9.9.9.9:xyz", "non-numeric port"),
    ("1.1.1.1:0", "outside 1-65535"),
    ("1.1.1.1:65536", "outside 1-65535"),
    ("1.1.1.1:99999", "outside 1-65535"),
    ("[::1", "unterminated"),
    ("[/corp.example 1.2.3.4", "unterminated"),
])
def test_a_malformed_upstream_spec_says_what_is_wrong_with_it(spec, problem):
    """An upstream is operator input, and a typo in the port used to reach
    `int()` bare: the daemon died at start-up on `invalid literal for int()`,
    naming neither the setting nor the server. A port of 99999 was worse — it
    was accepted, and failed later somewhere with no connection to the cause."""
    with pytest.raises(ValueError) as excinfo:
        parse_upstream(spec)
    assert problem in str(excinfo.value)
    assert spec in str(excinfo.value)


@pytest.mark.parametrize("spec", [
    "1.1.1.1", "1.1.1.1:53", "[::1]:853", "::1", "tcp://1.1.1.1",
    "tls://9.9.9.9#dns.quad9.net", "https://dns.google/dns-query",
    "quic://dns.adguard.com", "[/corp.example/]10.0.0.1", "1.1.1.1:65535",
])
def test_the_specs_that_should_parse_still_do(spec):
    parse_upstream(spec)


def test_the_config_refuses_an_upstream_the_resolver_could_not_use():
    """Checked at load with the parser the resolver itself calls, so a bad
    server is a field error rather than a dead daemon."""
    from pydantic import ValidationError

    from trench.config import Config
    with pytest.raises(ValidationError, match="non-numeric port"):
        Config.model_validate({"upstream": {"servers": ["1.1.1.1:abc"]}})
    with pytest.raises(ValidationError, match="outside 1-65535"):
        Config.model_validate({"upstream": {"groups": {"kids": ["9.9.9.9:99999"]}}})
    # and the shipped defaults still load
    assert Config.model_validate({}).upstream.servers
