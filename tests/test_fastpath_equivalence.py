"""The fast path must be indistinguishable from the pipeline, byte for byte.

`engine/fastpath.py` is a second implementation of the response path, and that
is the whole risk of having it. So it is not argued to be equivalent, it is
tested: for every query below, the pipeline is asked once (which records the
reply) and then asked again while the fast path is live, and the two sets of
bytes must be identical.

The corpus is deliberately nasty — it reuses the hostile mutation generator from
`test_wire_hostile.py`, so the inputs include truncated headers, compression
pointers planted in the question, and impossible counts. Anything the fast path
cannot reproduce exactly it must decline, and declining is free.
"""
from __future__ import annotations

import asyncio
import random

import pytest
from test_wire_hostile import _mutate, _seed_corpus

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.engine import Pipeline
from dnsguard.engine.fastpath import FastPath, query_key, ttl_offsets
from dnsguard.filter import FilterEngine, compile_rules
from dnsguard.stats import Counters
from dnsguard.transport.base import process_query
from dnsguard.wire import RR, Class, Message, Question, Type
from dnsguard.wire import rdata as R
from dnsguard.wire.edns import Edns
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode


class Upstream:
    """A deterministic upstream: the same question always gets the same answer,
    so any difference between the two paths is the paths' fault."""

    def __init__(self):
        self.calls = 0

    async def resolve(self, query: Message) -> Message:
        self.calls += 1
        q = query.question
        r = query.reply(Rcode.NOERROR)
        if q.rtype == Type.A:
            for i in range(3):
                r.answers.append(RR(q.name, Type.A, Class.IN, 300, R.A(f"93.184.216.{i}")))
        elif q.rtype == Type.MX:
            r.answers.append(RR(q.name, Type.MX, Class.IN, 120,
                                R.MX(10, Name.from_text("mx.example.com."))))
        elif q.rtype == Type.TXT:
            r.answers.append(RR(q.name, Type.TXT, Class.IN, 60, R.TXT([b"v=spf1 -all"])))
        return r


def _pipe(rules: str = "ads.example.com\n", **security):
    cfg = Config.model_validate({"security": security} if security else {})
    eng = FilterEngine.compile(compile_rules(rules, "test"))
    return Pipeline(filter_engine=eng, cache=Cache(), forwarder=Upstream(),
                    counters=Counters(), config=cfg)


def _wire_query(name: str, qtype: int = Type.A, qid: int = 0x1234,
                *, edns: bool | int = False, do: bool = False, rd: bool = True) -> bytes:
    m = Message(id=qid)
    if rd:
        m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), qtype, Class.IN))
    if edns:
        m.edns = Edns(udp_size=1232 if edns is True else int(edns))
        m.edns.do = do
    return m.to_wire()


def _both(pipe, fast, data: bytes, client: str = "10.0.0.5"):
    """Return (slow_bytes, fast_bytes|None) for the same query."""
    loop = asyncio.new_event_loop()
    try:
        slow = loop.run_until_complete(
            process_query(pipe, data, client, "udp", stream=False, fast=fast))
        served = fast.serve(data, client)
        return slow, (bytes(served) if served is not None else None)
    finally:
        loop.close()


def _flatten(blob: bytes) -> bytes:
    """The message with every TTL zeroed.

    The clock is the one thing the two paths are *supposed* to disagree about:
    a replayed answer has aged, so its TTL is lower. Zeroing the TTL fields
    names that as the only licensed difference, and `assert_same` checks the
    countdown separately rather than letting it hide a real divergence.
    """
    offs = ttl_offsets(blob)
    if not offs:
        return blob
    out = bytearray(blob)
    for off in offs:
        out[off:off + 4] = b"\x00\x00\x00\x00"
    return bytes(out)


def assert_same(fast_bytes: bytes, slow_bytes: bytes) -> None:
    assert _flatten(fast_bytes) == _flatten(slow_bytes), "differ outside the TTLs"
    fo, so = ttl_offsets(fast_bytes), ttl_offsets(slow_bytes)
    assert fo == so
    import struct
    for off in fo or ():
        f = struct.unpack_from(">I", fast_bytes, off)[0]
        s = struct.unpack_from(">I", slow_bytes, off)[0]
        assert s - 1 <= f <= s, f"TTL at {off}: replay {f}, pipeline {s}"


QUERIES = [
    _wire_query("www.example.com"),
    _wire_query("www.example.com", Type.MX),
    _wire_query("www.example.com", Type.TXT),
    _wire_query("www.example.com", Type.AAAA),          # NODATA
    _wire_query("ads.example.com"),                      # blocked
    _wire_query("www.example.com", edns=True),
    _wire_query("www.example.com", edns=True, do=True),
    _wire_query("www.example.com", edns=512),
    _wire_query("www.example.com", rd=False),
    _wire_query("a.b.c.d.e.example.com"),
]


@pytest.mark.parametrize("data", QUERIES, ids=lambda d: d[12:40].hex()[:16])
def test_replay_is_byte_identical_to_the_pipeline(data):
    pipe = _pipe()
    fast = FastPath(pipe)
    slow, served = _both(pipe, fast, data)
    if served is None:
        pytest.skip("declined by the fast path, which is always allowed")
    assert_same(served, slow)


def test_the_transaction_id_is_the_callers_own():
    """The recorded blob carries whatever id the first query used. Replaying it
    without patching would answer every client with a stranger's id, and every
    resolver on earth would discard the reply."""
    pipe = _pipe()
    fast = FastPath(pipe)
    _both(pipe, fast, _wire_query("www.example.com", qid=0x1111))
    other = _wire_query("www.example.com", qid=0xBEEF)
    served = fast.serve(other, "10.0.0.5")
    assert served is not None
    assert bytes(served[:2]) == b"\xbe\xef"
    assert Message.parse(bytes(served)).id == 0xBEEF


def test_the_question_keeps_the_callers_own_capitalisation():
    """0x20 randomisation (RFC 5452) means a client may ask for `wWw.ExAmPle.cOm`
    and will check that the answer echoes exactly that. Case is insignificant for
    *matching* and significant for *echoing*, and the fast path has to honour
    both at once."""
    pipe = _pipe()
    fast = FastPath(pipe)
    _both(pipe, fast, _wire_query("www.example.com"))
    mixed = _wire_query("wWw.ExAmPle.cOm")
    served = fast.serve(mixed, "10.0.0.5")
    assert served is not None
    assert Message.parse(bytes(served)).questions[0].name.labels == (b"wWw", b"ExAmPle", b"cOm")
    assert bytes(served[12:mixed.index(b"\x00\x01\x00\x01")]) == mixed[12:mixed.index(b"\x00\x01\x00\x01")]


def test_ttls_count_down_and_the_entry_stops_being_served():
    pipe = _pipe()
    fast = FastPath(pipe)
    data = _wire_query("www.example.com")
    _both(pipe, fast, data)
    entry = next(iter(fast.table.values()))
    first = Message.parse(bytes(fast.serve(data, "10.0.0.5"))).answers[0].ttl
    entry.inserted -= 100                                # 100s of simulated age
    later = Message.parse(bytes(fast.serve(data, "10.0.0.5"))).answers[0].ttl
    assert later < first, "a replayed answer must age"
    entry.inserted -= 1000                               # past its TTL entirely
    assert fast.serve(data, "10.0.0.5") is None, "an expired entry must be refreshed"


def test_a_different_question_never_hits():
    pipe = _pipe()
    fast = FastPath(pipe)
    _both(pipe, fast, _wire_query("www.example.com"))
    for other in (_wire_query("other.example.com"),
                  _wire_query("www.example.com", Type.MX),
                  _wire_query("www.example.com", edns=True),
                  _wire_query("www.example.com", edns=True, do=True),
                  _wire_query("www.example.com", edns=512),
                  _wire_query("www.example.com", rd=False),
                  _wire_query("www.example.com.evil.com")):
        assert fast.serve(other, "10.0.0.5") is None, other[12:].hex()


def test_two_clients_under_different_policies_are_not_confused():
    """The sharpest way to get this wrong: cache on the query alone, and a
    permitted client's answer gets replayed to a filtered one."""
    from dnsguard.clients.model import Client, Policy
    from dnsguard.clients.registry import ClientRegistry

    pipe = _pipe(rules="ads.example.com\n")
    pipe.clients = ClientRegistry(
        [Client(ident="10.0.0.9", ident_type="ip", policy=Policy(name="off", block=False))],
        default=Policy(name="on", block=True))
    fast = FastPath(pipe)
    data = _wire_query("ads.example.com")

    loop = asyncio.new_event_loop()
    try:
        # the unfiltered client resolves it...
        free = loop.run_until_complete(
            process_query(pipe, data, "10.0.0.9", "udp", stream=False, fast=fast))
        # ...and the filtered client must not be handed that answer
        assert fast.serve(data, "10.0.0.5") is None
        blocked = loop.run_until_complete(
            process_query(pipe, data, "10.0.0.5", "udp", stream=False, fast=fast))
    finally:
        loop.close()

    assert free != blocked
    assert Message.parse(free).answers, "unfiltered client should get an answer"
    assert_same(bytes(fast.serve(data, "10.0.0.9")), free)
    assert_same(bytes(fast.serve(data, "10.0.0.5")), blocked)


def test_hits_are_still_counted_and_logged():
    """A faster path that stops reporting traffic is not faster, it is broken."""
    pipe = _pipe()
    fast = FastPath(pipe)
    data = _wire_query("www.example.com")
    _both(pipe, fast, data)
    before = pipe.counters.total
    for _ in range(5):
        assert fast.serve(data, "10.0.0.5") is not None
    assert pipe.counters.total == before + 5
    assert pipe.counters.queries["www.example.com"] >= 5


def test_features_that_make_a_response_client_specific_disable_replay():
    """These two genuinely cannot be reproduced from the query bytes, so the
    table must not be consulted at all."""
    pipe = _pipe()
    fast = FastPath(pipe)
    data = _wire_query("www.example.com")
    _both(pipe, fast, data)
    assert fast.serve(data, "10.0.0.5") is not None       # baseline: it does hit

    pipe.config.upstream.ecs = "forward"
    assert fast.serve(data, "10.0.0.5") is None
    pipe.config.upstream.ecs = "off"

    pipe.enabled = False
    assert fast.serve(data, "10.0.0.5") is None
    pipe.enabled = True
    assert fast.serve(data, "10.0.0.5") is not None


# --------------------------------------- the features the live config actually has
def _cookie_query(name: str, cookie: bytes, qid: int = 0x2222) -> bytes:
    from dnsguard.engine.cookies import COOKIE
    m = Message(id=qid)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    m.edns = Edns(udp_size=1232)
    m.edns.set_option(COOKIE, cookie)
    return m.to_wire()


def test_dns_cookies_are_recomputed_per_client_not_replayed():
    """The first deployment had cookies, DGA and tunnel detection all enabled,
    and the fast path served exactly nothing — the gates had switched the whole
    optimisation off on the only machine that mattered.

    A server cookie is HMAC(secret, client_cookie || client_ip): a function of
    who is asking. So it is recomputed and patched rather than replayed, and the
    proof is that two clients presenting the same client cookie get different
    server cookies — and each gets the one the pipeline would have given them.
    """
    from dnsguard.engine.cookies import COOKIE, CookieJar

    pipe = _pipe()
    pipe.cookies = CookieJar()
    fast = FastPath(pipe)
    cc = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    data = _cookie_query("www.example.com", cc)

    loop = asyncio.new_event_loop()
    try:
        a_slow = loop.run_until_complete(
            process_query(pipe, data, "10.0.0.1", "udp", stream=False, fast=fast))
        b_slow = loop.run_until_complete(
            process_query(pipe, data, "10.0.0.2", "udp", stream=False, fast=fast))
    finally:
        loop.close()

    # replay for each client must equal what the pipeline gave that client
    assert fast.size >= 1
    assert_same(bytes(fast.serve(data, "10.0.0.1")), a_slow)
    assert_same(bytes(fast.serve(data, "10.0.0.2")), b_slow)

    got_a = Message.parse(bytes(fast.serve(data, "10.0.0.1"))).edns.get_option(COOKIE)
    got_b = Message.parse(bytes(fast.serve(data, "10.0.0.2"))).edns.get_option(COOKIE)
    assert got_a[:8] == cc and got_b[:8] == cc, "the client cookie is echoed"
    assert got_a[8:] != got_b[8:], "the server cookie must differ per client"
    assert pipe.cookies.valid(got_a, "10.0.0.1")
    assert pipe.cookies.valid(got_b, "10.0.0.2")
    assert not pipe.cookies.valid(got_a, "10.0.0.2"), "a cookie must not travel"


def test_cookies_enabled_does_not_exclude_clients_that_send_none():
    """Most clients never send a DNS cookie. Requiring one anyway meant enabling
    cookies switched replay off for nearly all real traffic — the same class of
    mistake as gating on the feature itself, just quieter."""
    from dnsguard.engine.cookies import CookieJar

    pipe = _pipe()
    pipe.cookies = CookieJar()
    fast = FastPath(pipe)
    data = _wire_query("www.example.com")            # no EDNS, so no cookie
    slow, served = _both(pipe, fast, data)
    assert fast.stores == 1, "a cookie-less exchange is still replayable"
    assert served is not None
    assert_same(served, slow)


def test_the_detectors_still_see_every_query():
    """DGA and tunnel detection keep per-client state, so a replay that skipped
    them would degrade detection silently — the worst kind of regression, because
    nothing fails and the resolver just stops noticing things."""
    pipe = _pipe(dga_detection=True, tunnel_detection=True)
    assert pipe.dga is not None and pipe.tunnel is not None
    fast = FastPath(pipe)
    data = _wire_query("www.example.com")
    _both(pipe, fast, data)
    assert fast.usable, "the detectors must not switch replay off"

    seen = []
    real_inspect = pipe.tunnel.inspect
    pipe.tunnel.inspect = lambda *a: (seen.append(a), real_inspect(*a))[1]
    real_note = pipe.dga.note_outcome
    noted = []
    pipe.dga.note_outcome = lambda *a: (noted.append(a), real_note(*a))[1]

    for _ in range(4):
        assert fast.serve(data, "10.0.0.5") is not None
    assert len(seen) == 4, "the tunnel detector saw only some of the queries"
    assert len(noted) == 4, "the DGA detector learned from only some outcomes"


def test_a_flagged_name_is_handed_back_to_the_normal_path():
    """Once a detector fires, the verdict is the pipeline's to make — replay must
    step aside rather than serve the answer it recorded earlier."""
    pipe = _pipe(dga_detection=True)
    fast = FastPath(pipe)
    data = _wire_query("www.example.com")
    _both(pipe, fast, data)
    assert fast.serve(data, "10.0.0.5") is not None

    class Flag:
        suspicious = True
        block = False
        reason = "test"
        label = "x"

    pipe.dga.check = lambda *a: Flag()
    assert fast.serve(data, "10.0.0.5") is None


def test_rate_limited_clients_fall_through_rather_than_being_served():
    pipe = _pipe(rate_limit=1.0, rate_burst=1)
    fast = FastPath(pipe)
    data = _wire_query("www.example.com")
    _both(pipe, fast, data)
    served = [fast.serve(data, "10.0.0.7") for _ in range(20)]
    assert any(s is None for s in served), "the limiter must still bite"


# ------------------------------------------------------------------ the corpus
def _query_corpus() -> list[bytes]:
    """Mutation seeds that are *queries*.

    The hostile corpus in `test_wire_hostile.py` is built from responses (QR
    set), which `query_key` refuses on sight — mutating those exercises the
    rejection branch and nothing else. To attack the replay logic the seeds have
    to be plausible queries, so this mixes the shapes a client really sends.
    """
    out = []
    for name in ("www.example.com", "ads.example.com", "a.b.c.example.com", "example.com"):
        for qtype in (Type.A, Type.AAAA, Type.MX, Type.TXT):
            out.append(_wire_query(name, qtype))
            out.append(_wire_query(name, qtype, edns=True))
            out.append(_wire_query(name, qtype, edns=True, do=True))
    return out


def test_no_hostile_packet_is_ever_replayed_wrongly():
    """The property, over mutated garbage: either the fast path declines, or its
    answer is exactly the pipeline's answer."""
    rng = random.Random(0xFA57)
    corpus = _query_corpus() + _seed_corpus()
    pipe = _pipe()
    fast = FastPath(pipe)
    loop = asyncio.new_event_loop()
    checked = served_count = 0
    try:
        for _ in range(3_000):
            data = _mutate(rng.choice(corpus), rng)
            slow = loop.run_until_complete(
                process_query(pipe, data, "10.0.0.5", "udp", stream=False, fast=fast))
            got = fast.serve(data, "10.0.0.5")
            if got is None:
                continue
            served_count += 1
            assert_same(bytes(got), slow)
            checked += 1
    finally:
        loop.close()
    assert served_count > 50, f"corpus exercised the fast path only {served_count} times"
    assert checked == served_count


def test_query_key_rejects_what_it_cannot_reason_about():
    assert query_key(b"") is None
    assert query_key(b"\x00" * 12) is None                       # QDCOUNT 0
    # a compression pointer as the question name: nothing precedes it
    assert query_key(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                     b"\xc0\x0c\x00\x01\x00\x01") is None
    good = _wire_query("www.example.com")
    assert query_key(good) is not None
    # a response, not a query
    assert query_key(good[:2] + b"\x81\x80" + good[4:]) is None


def test_ttl_offsets_skips_the_opt_pseudo_record():
    """OPT keeps flags where a TTL would be. Counting a clock down over them
    would rewrite the extended rcode and the DO bit."""
    m = Message(id=1, flags=0x8180)
    m.questions.append(Question(Name.from_text("www.example.com."), Type.A, Class.IN))
    m.answers.append(RR(Name.from_text("www.example.com."), Type.A, Class.IN, 300,
                        R.A("1.2.3.4")))
    m.edns = Edns(udp_size=1232)
    m.edns.do = True
    blob = m.to_wire()
    offs = ttl_offsets(blob)
    assert len(offs) == 1, "only the A record has a real TTL"
    import struct
    assert struct.unpack_from(">I", blob, offs[0])[0] == 300
    # patching that one offset must leave the OPT's DO bit alone
    patched = bytearray(blob)
    struct.pack_into(">I", patched, offs[0], 7)
    again = Message.parse(bytes(patched))
    assert again.answers[0].ttl == 7
    assert again.edns is not None and again.edns.do is True
