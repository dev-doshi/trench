"""DNS 0x20 query-name case randomization (draft-vixie-dnsext-dns0x20).

Randomizing the case of the forwarded query name adds entropy an off-path
spoofer must guess (on top of txid + source port). A compliant upstream echoes
the exact case back; if the echoed case doesn't match what we sent, the reply is
treated as forged. The client's original case is restored on the way back.
"""
from __future__ import annotations

import copy
import random

from ..wire import RR, Message, Question
from ..wire.name import Name


def randomize_name(name: Name) -> Name:
    labels = []
    for label in name.labels:
        out = bytearray(label)
        for i, b in enumerate(out):
            if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A:  # ascii letter
                out[i] = (b ^ 0x20) if random.getrandbits(1) else b
        labels.append(bytes(out))
    return Name(tuple(labels))


def apply(query: Message) -> tuple[Message, Name]:
    """Return (forward_query_with_randomized_name, original_name)."""
    q = query.question
    rnd = randomize_name(q.name)
    fwd = copy.copy(query)
    fwd.questions = [Question(rnd, q.rtype, q.rclass)]
    return fwd, q.name


def verify(resp: Message, expected: Name) -> bool:
    """True iff the response echoes the exact (case-sensitive) query name."""
    rq = resp.question
    return rq is not None and rq.name.labels == expected.labels


def restore(resp: Message, original: Name) -> None:
    """Reset the question + matching answer owners to the client's original case."""
    if resp.questions:
        q0 = resp.questions[0]
        resp.questions[0] = Question(original, q0.rtype, q0.rclass)
    # Replaced, not edited. Everything else in this resolver treats a record as
    # immutable — `cache.detach` says so in as many words — and this was the one
    # place that did not. It is safe today only because it runs on a fresh
    # upstream response before the cache write; making it a replacement means it
    # stays safe if that ordering ever changes.
    for i, rr in enumerate(resp.answers):
        if rr.name == original:  # case-insensitive match
            resp.answers[i] = RR(original, rr.rtype, rr.rclass, rr.ttl, rr.rdata)
