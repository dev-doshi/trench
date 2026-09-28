"""Hostile wire into the authoritative side: UPDATE, NOTIFY, AXFR, IXFR.

These four are the operations that *write* or *export* a zone, and each is
authorised by an address list and optionally a TSIG key. `test_zone_transactions_wire.py`
checks that the happy paths work and that the obvious refusals refuse. This
checks the property underneath: whatever a caller outside the ACL sends, and
however malformed it is, the zone does not move and does not leave.

That is deliberately stronger than "nothing raised". A handler that threw on
every message would satisfy the weaker property while doing nothing, so the
counts below assert the messages really were processed, and the zone snapshot
either side of the run asserts what processing them was not allowed to do.
"""
from __future__ import annotations

import random

from test_wire_hostile import _mutate

from trench.auth_zone import Zone, ZoneStore
from trench.auth_zone.handler import AuthHandler
from trench.errors import WireError
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Opcode

ORIGIN = Name.from_text("example.com.")
NS = Name.from_text("ns.example.com.")
ALLOWED = "10.0.0.5"
STRANGER = "203.0.113.9"


def _soa() -> R.SOA:
    return R.SOA(NS, Name.from_text("admin.example.com."), 1, 7200, 3600, 1209600, 3600)


def _handler() -> AuthHandler:
    zone = Zone(ORIGIN)
    zone.add(ORIGIN, Type.SOA, _soa())
    zone.add(ORIGIN, Type.NS, R.NS(NS))
    zone.add(Name.from_text("www.example.com."), Type.A, R.A("93.184.216.34"))
    store = ZoneStore()
    store.add(zone)
    handler = AuthHandler(store)
    handler.set_zone_policy(ORIGIN, allow_transfer=[ALLOWED], allow_update=[ALLOWED])
    return handler


def _snapshot(handler: AuthHandler) -> dict:
    zone = handler.zonestore.authoritative_for(ORIGIN)
    return {owner.to_text(): {rtype: [rd.to_text() for rd in rds]
                              for rtype, rds in node.items()}
            for owner, node in zone.records.items()}


def _corpus() -> list[bytes]:
    out = []
    for qtype in (Type.AXFR, Type.IXFR):
        m = Message(id=1)
        m.questions.append(Question(ORIGIN, qtype, Class.IN))
        if qtype == Type.IXFR:
            m.authority.append(RR(ORIGIN, Type.SOA, Class.IN, 0, _soa()))
        out.append(m.to_wire())
    update = Message(id=2, flags=Opcode.UPDATE << 11)
    update.questions.append(Question(ORIGIN, Type.SOA, Class.IN))
    update.authority.append(RR(Name.from_text("evil.example.com."), Type.A, Class.IN,
                               60, R.A("203.0.113.1")))
    out.append(update.to_wire())
    delete_all = Message(id=3, flags=Opcode.UPDATE << 11)
    delete_all.questions.append(Question(ORIGIN, Type.SOA, Class.IN))
    delete_all.authority.append(RR(ORIGIN, Type.ANY, Class.ANY, 0, R.Unknown(Type.ANY, b"")))
    out.append(delete_all.to_wire())
    notify = Message(id=4, flags=(Opcode.NOTIFY << 11) | Flags.AA)
    notify.questions.append(Question(ORIGIN, Type.SOA, Class.IN))
    out.append(notify.to_wire())
    return out


def _run(handler: AuthHandler, client_ip: str, iterations: int, seed: int) -> tuple[int, int]:
    """Returns (messages handled, records that came back)."""
    rng = random.Random(seed)
    corpus = _corpus()
    handled = leaked = 0
    for i in range(iterations):
        wire = rng.choice(corpus) if i % 4 == 0 else _mutate(rng.choice(corpus), rng)
        try:
            query = Message.parse(wire)
        except WireError:
            continue                       # the transport drops these before us
        if not handler.claims(query):
            continue
        handled += 1
        for out in handler.handle_tcp(wire, query, client_ip):
            leaked += len(Message.parse(out).answers)
        reply = handler.handle_udp(wire, query, client_ip)
        if reply is not None:
            leaked += len(Message.parse(reply).answers)
    return handled, leaked


def test_a_stranger_cannot_move_or_extract_the_zone():
    handler = _handler()
    before = _snapshot(handler)
    handled, leaked = _run(handler, STRANGER, 8_000, 0xBEEF)
    assert handled > 1_000, f"only {handled} messages reached the handler"
    assert leaked == 0, f"{leaked} record(s) left the zone for an address outside the ACL"
    assert _snapshot(handler) == before


def test_an_allowed_client_sending_garbage_cannot_corrupt_the_zone():
    """Being inside the ACL buys the right to be answered, not the right to
    leave the zone in a state no message asked for: every mutated UPDATE either
    applies as written or is refused whole."""
    handler = _handler()
    before = _snapshot(handler)
    handled, _ = _run(handler, ALLOWED, 8_000, 0xF00D)
    assert handled > 1_000
    after = _snapshot(handler)
    # The SOA and the apex NS are what the zone is; no malformed UPDATE may
    # remove them, whatever else it manages to add.
    assert after[ORIGIN.to_text()][Type.SOA]
    assert after[ORIGIN.to_text()][Type.NS] == before[ORIGIN.to_text()][Type.NS]
