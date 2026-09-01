"""QNAME minimisation must not disable itself for every later query.

A minimised probe that comes back NODATA says something about one delegation,
not about the resolver: flipping a shared flag on it turned one awkward zone
into a permanent, silent loss of the privacy property for the whole box.
"""
from __future__ import annotations

import pytest

from dnsguard.resolver.recursive import Recursive
from dnsguard.wire import RR, Class, Message, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.rrtypes import Flags


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
