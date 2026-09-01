"""A client identified by token, and the policy that follows from it.

The client id arrives from an encrypted transport's path segment, and it has to
reach the policy lookup — otherwise every DoH client resolves as an anonymous
address and per-client policy quietly does not apply to the transports where it
matters most.
"""
from __future__ import annotations

import asyncio

from dnsguard.cache import Cache
from dnsguard.clients import Client, ClientRegistry, Policy
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.filter import FilterEngine
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


# --- Bug 2: ClientID must reach the policy engine ---
class FakeForwarder:
    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def mkquery(name="www.youtube.com"):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


def test_clientid_threaded_to_policy():
    from dnsguard.filter.services import Services
    reg = ClientRegistry([
        Client("phone-token", "clientid", "kid-phone",
               Policy(name="kid", services=frozenset({"youtube"}))),
    ], default=Policy(name="default"))
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder(), counters=Counters(), config=Config(),
                    clients=reg, services=Services())
    # same IP, but the ClientID selects the kid policy -> youtube blocked
    blocked = asyncio.run(pipe.resolve(mkquery(), "8.8.8.8", "https", "phone-token"))
    assert blocked.answers[0].rdata.to_text() == "0.0.0.0"
    # no ClientID -> default policy -> forwarded
    allowed = asyncio.run(pipe.resolve(mkquery(), "8.8.8.8", "https", ""))
    assert allowed.answers[0].rdata.to_text() == "1.2.3.4"
