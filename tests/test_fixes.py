"""Regression tests for correctness fixes (R1)."""
from __future__ import annotations

import asyncio

import pytest

from dnsguard.cache import Cache
from dnsguard.clients import Client, ClientRegistry, Policy
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.filter import FilterEngine
from dnsguard.resolver.recursive import Recursive
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Flags, Rcode


# --- Bug 1: QNAME-min must not mutate shared state ---
@pytest.mark.asyncio
async def test_qmin_not_globally_disabled():
    SERVER = "10.0.0.1"

    async def transport(ip, query):
        q = query.question
        # NS-type (minimized) intermediate queries return NODATA (no referral);
        # this used to flip self.qmin=False forever.
        if q.rtype == Type.NS:
            return Message(id=0, flags=Flags.QR | Flags.AA)
        # full A query gets answered authoritatively
        m = Message(id=0, flags=Flags.QR | Flags.AA)
        m.answers.append(RR(q.name, Type.A, Class.IN, 60, R.A("5.6.7.8")))
        return m

    rec = Recursive(transport, root_hints=[SERVER], qmin=True)
    r1 = await rec.resolve("a.b.example", Type.A)
    assert r1.answers and r1.answers[0].rdata.to_text() == "5.6.7.8"
    # the instance flag must be untouched for the next query
    assert rec.qmin is True


# --- Bug 2: ClientID must reach the policy engine ---
class FakeForwarder:
    async def resolve(self, query: Message) -> Message:
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
