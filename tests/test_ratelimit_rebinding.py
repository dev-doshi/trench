"""Rate limiting and DNS-rebinding protection, in isolation and through the
pipeline."""
from __future__ import annotations

import asyncio

import pytest

from trench.cache import Cache
from trench.config import Config
from trench.engine import Pipeline
from trench.engine.ratelimit import RateLimiter
from trench.engine.rebinding import scrub
from trench.filter import FilterEngine
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


def test_ratelimiter_bucket():
    rl = RateLimiter(rate=10, burst=2)
    t = 1000.0
    assert rl.allow("a", t) and rl.allow("a", t)   # burst of 2
    assert not rl.allow("a", t)                    # empty
    assert rl.allow("a", t + 0.11)                 # ~1 token refilled after 0.1s


def test_ratelimiter_disabled():
    rl = RateLimiter(rate=0)
    assert all(rl.allow("x") for _ in range(1000))


def test_rebinding_scrub():
    m = Message(id=1)
    m.answers = [
        RR(Name.from_text("evil.com"), Type.A, Class.IN, 60, R.A("192.168.1.5")),
        RR(Name.from_text("evil.com"), Type.A, Class.IN, 60, R.A("1.2.3.4")),
    ]
    removed = scrub(m, "evil.com", local_suffixes=("lan",))
    assert removed == 1
    assert [rr.rdata.to_text() for rr in m.answers] == ["1.2.3.4"]


def test_rebinding_keeps_local():
    m = Message(id=1)
    m.answers = [RR(Name.from_text("nas.lan"), Type.A, Class.IN, 60, R.A("192.168.1.5"))]
    assert scrub(m, "nas.lan", local_suffixes=("lan",)) == 0   # local names allowed


class FakeForwarder:
    def __init__(self, ip): self.ip = ip
    async def resolve(self, query, note=None):
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A(self.ip)))
        return resp


def mkquery(name="x.com"):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


def test_pipeline_ratelimit():
    cfg = Config.model_validate({"security": {"rate_limit": 1, "rate_burst": 1}})
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder("1.2.3.4"), counters=Counters(), config=cfg)
    r1 = asyncio.run(pipe.resolve(mkquery(), "10.0.0.1"))
    r2 = asyncio.run(pipe.resolve(mkquery(), "10.0.0.1"))
    assert r1.answers and r2.rcode == Rcode.REFUSED   # 2nd over the limit


def test_pipeline_rebinding():
    cfg = Config.model_validate({"security": {"rebinding_protection": True}})
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder("10.0.0.9"), counters=Counters(), config=cfg)
    r = asyncio.run(pipe.resolve(mkquery("public.com"), "1.1.1.1"))
    assert not r.answers   # private answer to a public name stripped


# --- the memoised private-address verdict -------------------------------------
#: (address, private). Spelled out rather than derived, so the table is the
#: specification: `_is_private` is memoised, and a cache is only as good as the
#: answer it remembers.
#:
#: It also pins the classification itself, which is not Trench's to define —
#: `ipaddress.is_private` is, and it has moved. Measured across 3.10/3.11.2/
#: 3.12/3.13/3.14, `2002::1` (6to4, RFC 3056) is private on every one of them
#: except 3.11.2, so the range Trench strips depends on the interpreter it runs
#: under. That one is left out of the table below because no single value is
#: correct for all supported versions; everything here is stable across them,
#: and a future interpreter that changes any of it fails this test rather than
#: quietly widening or narrowing what rebinding protection covers.
_VERDICTS = [
    ("93.184.216.34", False),      # ordinary public v4
    ("8.8.8.8", False),
    ("10.0.0.1", True),            # RFC 1918
    ("172.16.0.1", True),
    ("172.32.0.1", False),         # just outside 172.16/12
    ("192.168.1.5", True),
    ("127.0.0.1", True),           # loopback
    ("0.0.0.0", True),             # unspecified
    ("169.254.1.1", True),         # link-local
    # RFC 6598 shared address space. Not private per `ipaddress` on any
    # interpreter tested (3.10 through 3.14), so Trench does not strip it —
    # which is what Tailscale users need, since 100.64.0.0/10 is exactly where
    # Tailscale puts its peers.
    ("100.64.0.1", False),
    ("240.0.0.1", True),           # reserved
    ("255.255.255.255", True),
    ("2606:4700::1111", False),    # public v6
    ("::1", True),                 # v6 loopback
    ("fd00::1", True),             # unique local
    ("fe80::1", True),             # v6 link-local
    ("::", True),                  # v6 unspecified
    ("not-an-address", False),     # unparseable: not evidence of anything
    ("", False),
]


@pytest.mark.parametrize("addr,private", _VERDICTS)
def test_the_private_address_verdict(addr, private):
    from trench.engine.rebinding import _is_private
    assert _is_private(addr) is private


def test_the_verdict_is_remembered_not_recomputed():
    """The memoisation is a measured optimisation — `scrub` was about half the
    uncached forward path — so it has to actually take effect, and it has to be
    bounded: the addresses come from answers, which means a caller picks them."""
    from trench.engine.rebinding import _VERDICT_CACHE, _is_private

    _is_private.cache_clear()
    for addr, _ in _VERDICTS:
        _is_private(addr)
    first = _is_private.cache_info()
    assert first.hits == 0 and first.misses == len(_VERDICTS)

    for addr, expected in _VERDICTS:
        assert _is_private(addr) is expected          # same answers, from cache
    assert _is_private.cache_info().hits == len(_VERDICTS)

    for i in range(_VERDICT_CACHE * 2):               # churn it
        _is_private(f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}")
    assert _is_private.cache_info().currsize <= _VERDICT_CACHE


def _svc(params: bytes, rtype=Type.HTTPS):
    cls = R.HTTPS if rtype == Type.HTTPS else R.SVCB
    return RR(Name.from_text("evil.com"), rtype, Class.IN, 60,
              cls(1, Name.from_text("."), params))


def _param(key: int, val: bytes) -> bytes:
    return key.to_bytes(2, "big") + len(val).to_bytes(2, "big") + val


def test_rebinding_scrubs_private_svcb_address_hints():
    """RFC 9460 lets a client connect straight to ipv4hint/ipv6hint without an
    A/AAAA lookup, so a private hint on a public name is a rebinding answer."""
    import ipaddress
    alpn = _param(1, b"\x02h2")
    v4 = _param(4, ipaddress.ip_address("192.168.1.5").packed
                + ipaddress.ip_address("1.2.3.4").packed)
    v6 = _param(6, ipaddress.ip_address("fd00::1").packed)
    m = Message(id=1)
    shared = _svc(alpn + v4 + v6)
    m.answers = [shared, _svc(alpn, Type.SVCB)]
    assert scrub(m, "evil.com") == 1
    assert m.answers[0].rdata.params == alpn + _param(4, bytes([1, 2, 3, 4]))
    assert m.answers[1].rdata.params == alpn
    assert shared.rdata.params == alpn + v4 + v6      # original left intact


def test_rebinding_leaves_public_and_malformed_hints_alone():
    public = _param(4, bytes([1, 2, 3, 4]))
    for params in (public, public[:-1], _param(4, b"\x0a\x00\x00")):
        m = Message(id=1)
        m.answers = [_svc(params)]
        assert scrub(m, "evil.com") == 0
        assert m.answers[0].rdata.params == params
    m = Message(id=1)
    m.answers = [_svc(_param(4, bytes([10, 0, 0, 1])))]
    assert scrub(m, "nas.lan", local_suffixes=("lan",)) == 0
