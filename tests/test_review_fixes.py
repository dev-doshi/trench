"""Regression tests for the findings in docs/reviews/code-review.md."""
from __future__ import annotations

import asyncio

from test_pipeline_paths import Fwd, build, mkanswer, mkquery

from trench.auth_zone.tsig import TSIGError, TSIGKey, sign_error, sign_wire, verify_wire
from trench.transport.base import not_a_query, process_query
from trench.wire import Message
from trench.wire.edns import ECS, Edns
from trench.wire.rrtypes import EDNSOption, Flags, Rcode

COOKIE = EDNSOption.COOKIE


# --- H1: never answer a response ---------------------------------------------
def test_a_response_gets_no_reply():
    pipe = build()
    q = mkquery().to_wire()
    resp = bytearray(q)
    resp[2] |= 0x80                                   # QR=1
    formerr_shaped = q[:2] + b"\x80\x01" + b"\x00" * 8
    for data in (bytes(resp), formerr_shaped, b"\x12\x34\x80"):
        assert not_a_query(data)
        assert asyncio.run(process_query(pipe, data, "10.0.0.1", "udp",
                                          stream=False)) is None
    assert not not_a_query(q)
    assert not not_a_query(q[:11])        # a runt query still gets its FORMERR


def test_a_malformed_query_with_a_full_header_still_gets_formerr():
    pipe = build()
    data = mkquery().to_wire()[:12] + b"\xff"          # QDCOUNT=1, garbage question
    out = asyncio.run(process_query(pipe, data, "10.0.0.1", "udp", stream=False))
    assert out is not None
    assert Message.parse(out).rcode == Rcode.FORMERR


# --- H2: coalesced followers never see the leader's cookie -------------------
def test_a_coalesced_follower_does_not_get_the_leaders_cookie():
    pipe = build(Fwd(delay=0.05), security={"dns_cookies": True})

    def q(txid, cookie=None):
        m = mkquery(txid=txid, edns=True)
        if cookie:
            m.edns.set_option(COOKIE, cookie)
        return m

    async def race():
        return await asyncio.gather(
            pipe.resolve(q(1, b"CLIENTA!"), "10.0.0.1"),
            pipe.resolve(q(2), "10.0.0.2"))

    a, b = asyncio.run(race())
    assert a.edns.get_option(COOKIE) is not None
    assert b.edns.get_option(COOKIE) is None


# --- H3: echo the asker's own letter case ------------------------------------
def test_a_cache_hit_echoes_the_askers_case():
    pipe = build()
    asyncio.run(pipe.resolve(mkquery("Example.COM", txid=1), "10.0.0.1"))
    r = asyncio.run(pipe.resolve(mkquery("eXaMpLe.cOm", txid=2), "10.0.0.2"))
    assert r.questions[0].name.to_text() == "eXaMpLe.cOm."


# --- H4: hop-by-hop EDNS options stay on their hop ---------------------------
class EchoCookie(Fwd):
    async def resolve(self, query, note=None):
        a = await super().resolve(query, note)
        a = mkanswer(query)
        a.edns = Edns()
        a.edns.set_option(COOKIE, b"CLIENTA!" + b"UPSTREAMCOOKIE!!")
        a.edns.set_option(EDNSOption.NSID, b"up1")
        return a


def test_client_cookie_and_ecs_are_not_forwarded_and_upstream_cookie_not_served():
    fwd = EchoCookie()
    pipe = build(fwd)
    q = mkquery(txid=1, edns=True)
    q.edns.set_option(COOKIE, b"CLIENTA!")
    q.edns.set_ecs(ECS.from_client("198.51.100.7"))
    asyncio.run(pipe.resolve(q, "10.0.0.1"))
    sent = fwd.seen[0].edns
    assert sent.get_option(COOKIE) is None
    assert sent.get_option(EDNSOption.ECS) is None
    assert q.edns.get_option(COOKIE) == b"CLIENTA!"     # the client's own copy untouched

    r = asyncio.run(pipe.resolve(mkquery(txid=2, edns=True), "10.0.0.2"))
    assert r.edns.get_option(COOKIE) is None
    assert r.edns.get_option(EDNSOption.NSID) == b"up1"


# --- DNSSEC ------------------------------------------------------------------
def test_rsasha1_nsec3_signatures_verify():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    from trench.resolver.dnssec.validate import _verify_sig

    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    sig = priv.sign(b"data", padding.PKCS1v15(), hashes.SHA1())
    assert _verify_sig(priv.public_key(), 7, sig, b"data")
    assert not _verify_sig(priv.public_key(), 7, sig, b"other")


def test_a_ds_set_of_unsupported_algorithms_makes_the_zone_insecure():
    from trench.resolver.dnssec import chain
    from trench.wire import rdata as R
    from trench.wire.name import Name

    v = chain.Validator(ask=None)
    child, parent = Name.from_text("example."), Name.from_text(".")
    ds = R.DS(1234, 253, 2, b"\x00" * 32)               # PRIVATEOID: not ours

    async def ask(name, rtype):
        m = Message(id=0)
        from trench.wire import RR, Class, Type
        m.answers = [RR(child, Type.DS, Class.IN, 300, ds)]
        return m

    v.ask = ask
    v._verify = lambda *a, **k: (True, None)            # the DS itself is signed
    work = chain._Work(10, 10)
    assert asyncio.run(v._delegation(child, parent, [], work)) == ("insecure", None)


# --- TSIG --------------------------------------------------------------------
KEY = TSIGKey("k.", b"s" * 32)


def test_badsig_is_answered_with_an_empty_mac():
    q = mkquery().to_wire()
    signed, _ = sign_wire(q, TSIGKey("k.", b"x" * 32))    # wrong secret
    try:
        verify_wire(signed, {"k.": KEY})
    except TSIGError as e:
        err = e
    else:
        raise AssertionError("verified with the wrong secret")
    assert err.tsig_error == 16
    reply = mkquery().reply(Rcode.NOTAUTH).to_wire()
    out = sign_error(reply, err)
    from trench.auth_zone.tsig import _locate_tsig
    _, tsig, _ = _locate_tsig(out)
    assert tsig.mac == b"" and tsig.error == 16


def test_multi_message_transfers_use_the_timers_only_digest():
    msgs = [mkquery(txid=7).reply().to_wire() for _ in range(3)]
    req, req_mac = sign_wire(mkquery(txid=7).to_wire(), KEY)
    prev, out = req_mac, []
    for i, m in enumerate(msgs):
        w, prev = sign_wire(m, KEY, request_mac=prev, timers_only=i > 0)
        out.append(w)
    from trench.auth_zone.secondary import _verify_envelope
    prev = req_mac
    for i, w in enumerate(out):
        prev = _verify_envelope(w, KEY, prev, first=i == 0)
    # A later message is *not* valid under the full-variable digest.
    first_mac, _, _ = verify_wire(out[0], {"k.": KEY}, request_mac=req_mac)
    try:
        verify_wire(out[1], {"k.": KEY}, request_mac=first_mac)
    except TSIGError:
        pass
    else:
        raise AssertionError("timers-only MAC accepted as a full one")


def test_the_qr_flag_constant_matches_the_wire_check():
    m = mkquery()
    m.set_flag(Flags.QR, True)
    assert not_a_query(m.to_wire())
