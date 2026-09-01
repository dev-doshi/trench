"""Firefox's DoH canary: use-application-dns.net.

Firefox resolves this exact name over plain DNS before turning its own
DNS-over-HTTPS on, and treats anything but NOERROR as "this network already
manages DNS, leave it alone" (Mozilla's own wording). Every policy this
resolver applies — blocklists, parental controls, safe search — is a DNS-layer
decision, so a browser update that flips DoH on by default routes around all
of it unless this one name is refused.
"""
from __future__ import annotations

import asyncio

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.filter import FilterEngine
from dnsguard.stats import Counters
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


class FakeForwarder:
    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("9.9.9.9")))
        return resp


def _query(name: str, qtype: int = Type.A) -> Message:
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), qtype, Class.IN))
    return m


def _pipe(**security):
    cfg = Config.model_validate({"security": security} if security else {})
    return Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder(), counters=Counters(), config=cfg)


def test_canary_is_refused_by_default():
    pipe = _pipe()
    r = asyncio.run(pipe.resolve(_query("use-application-dns.net"), "10.0.0.5"))
    assert r.rcode == Rcode.NXDOMAIN
    assert not r.answers


def test_canary_check_is_case_insensitive():
    """A resolver, browser, or middlebox may send any casing; the canary name
    is not one Firefox will retry in lowercase if the mixed-case form slips
    through — RFC 4343 doesn't excuse missing this."""
    pipe = _pipe()
    r = asyncio.run(pipe.resolve(_query("Use-Application-DNS.Net"), "10.0.0.5"))
    assert r.rcode == Rcode.NXDOMAIN


def test_canary_handling_can_be_disabled():
    """A user who wants Firefox's DoH to work exactly as upstream intends can
    opt out; the pipeline must not force the canary in that case."""
    pipe = _pipe(block_doh_canary=False)
    r = asyncio.run(pipe.resolve(_query("use-application-dns.net"), "10.0.0.5"))
    assert r.rcode == Rcode.NOERROR
    assert r.answers[0].rdata.to_text() == "9.9.9.9"


def test_the_canary_check_does_not_catch_lookalike_names():
    """A subdomain or a name that merely contains the canary string is a real
    name someone might own — only the exact canary is special-cased."""
    pipe = _pipe()
    r = asyncio.run(pipe.resolve(_query("sub.use-application-dns.net"), "10.0.0.5"))
    assert r.rcode == Rcode.NOERROR
    r2 = asyncio.run(pipe.resolve(_query("use-application-dns.net.evil.com"), "10.0.0.5"))
    assert r2.rcode == Rcode.NOERROR


def test_canary_is_refused_before_client_specific_policy():
    """The whole point: a client whose policy allows everything (no filtering,
    no parental controls) still gets the canary refused, because this is not a
    blocklist decision — it is keeping every *other* policy enforceable."""
    from dnsguard.clients.model import Client, Policy
    from dnsguard.clients.registry import ClientRegistry

    pipe = _pipe()
    pipe.clients = ClientRegistry(
        [Client(ident="10.0.0.5", ident_type="ip", policy=Policy(block=False))],
        default=Policy())
    r = asyncio.run(pipe.resolve(_query("use-application-dns.net"), "10.0.0.5"))
    assert r.rcode == Rcode.NXDOMAIN
