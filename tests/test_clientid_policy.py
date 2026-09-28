"""A client identified by token, and the policy that follows from it.

The client id arrives from an encrypted transport's path segment, and it has to
reach the policy lookup — otherwise every DoH client resolves as an anonymous
address and per-client policy quietly does not apply to the transports where it
matters most.
"""
from __future__ import annotations

import asyncio

from support import blocked_engine

from trench.cache import Cache
from trench.clients import Client, ClientRegistry, Policy
from trench.config import Config
from trench.engine import Pipeline
from trench.filter import FilterEngine
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


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
    from trench.filter.services import Services
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


# --- an exempted client must be exempt from *every* blocking path ---
class CloakingForwarder:
    """Answers with a CNAME onto a blocked tracker, the way a first-party
    subdomain delegated to an analytics vendor does."""

    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        name = query.question.name
        resp.answers.append(RR(name, Type.CNAME, Class.IN, 60,
                               R.CNAME(Name.from_text("tracker.example."))))
        resp.answers.append(RR(Name.from_text("tracker.example."), Type.A,
                               Class.IN, 60, R.A("1.2.3.4")))
        return resp


def _cloak_pipe(policy: Policy) -> Pipeline:
    cfg = Config()
    cfg.filtering.cname_inspect = True
    reg = ClientRegistry([Client("10.0.0.7", "ip", "host", policy)],
                         default=Policy(name="default"))
    return Pipeline(filter_engine=blocked_engine("tracker.example"),
                    cache=Cache(), forwarder=CloakingForwarder(),
                    counters=Counters(), config=cfg, clients=reg)


def test_cname_cloak_still_blocks_a_normal_client():
    pipe = _cloak_pipe(Policy(name="host", block=True))
    resp = asyncio.run(pipe.resolve(mkquery("metrics.shop.example"), "10.0.0.7", "udp"))
    assert resp.answers[0].rdata.to_text() == "0.0.0.0"


def test_a_client_exempt_from_filtering_is_exempt_from_cloak_inspection_too():
    """`block: false` used to turn off only the half of filtering that matches
    on the question. The CNAME-cloak check and the answer-address check ran
    regardless, so an exempted client was still sinkholed by them — which is
    not what "filtering is off for this client" says."""
    pipe = _cloak_pipe(Policy(name="host", block=False))
    resp = asyncio.run(pipe.resolve(mkquery("metrics.shop.example"), "10.0.0.7", "udp"))
    assert resp.answers[0].rdata.to_text() != "0.0.0.0"
    assert resp.answers[-1].rdata.to_text() == "1.2.3.4"
