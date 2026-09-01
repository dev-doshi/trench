"""Timed pauses: global, per-client, expiry, and the replay table's gate."""
from __future__ import annotations

import asyncio

from dnsguard.cache import Cache
from dnsguard.clients import Client, ClientRegistry, Policy
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.filter import FilterEngine
from dnsguard.filter.parser import parse_line
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


class Fwd:
    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def mkquery(name: str) -> Message:
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


def build() -> Pipeline:
    reg = ClientRegistry([Client("10.0.0.5", "ip", "kid", Policy(name="kid"))],
                         default=Policy(name="default"))
    rules = [parse_line("||ads.example^", "test")]
    return Pipeline(filter_engine=FilterEngine.compile(rules),
                    cache=Cache(enabled=False), forwarder=Fwd(), counters=Counters(),
                    config=Config(), clients=reg)


def answer(pipe: Pipeline, client: str) -> str:
    return asyncio.run(pipe.resolve(mkquery("ads.example"), client)).answers[0].rdata.to_text()


def test_global_pause_lets_blocked_names_through_then_expires():
    pipe = build()
    assert answer(pipe, "9.9.9.9") == "0.0.0.0"
    pipe.pause(300)
    assert answer(pipe, "9.9.9.9") == "1.2.3.4"
    pipe.resume()
    assert answer(pipe, "9.9.9.9") == "0.0.0.0"


def test_pause_expires_on_its_own():
    pipe = build()
    pipe.pause(0.05)
    assert answer(pipe, "9.9.9.9") == "1.2.3.4"
    import time
    time.sleep(0.06)
    assert answer(pipe, "9.9.9.9") == "0.0.0.0"
    assert pipe.paused_until == 0.0      # expired state is cleared, not re-checked forever


def test_client_pause_is_scoped_to_that_client():
    pipe = build()
    pipe.pause(300, "10.0.0.5")
    assert answer(pipe, "10.0.0.5") == "1.2.3.4"
    assert answer(pipe, "10.0.0.6") == "0.0.0.0"
    assert pipe.pause_state()["clients"] == {"10.0.0.5": pipe._client_pause["10.0.0.5"]}


def test_replay_stands_down_while_paused():
    """A recorded reply outlives the pause it was recorded in, so nothing may
    be recorded or replayed while one is running."""
    from dnsguard.engine.fastpath import FastPath
    pipe = build()
    pipe.fast = FastPath(pipe)
    assert pipe.fast.usable
    pipe.pause(300, "10.0.0.5")
    assert not pipe.fast.usable
    pipe.resume("10.0.0.5")
    assert pipe.fast.usable
