"""DGA detection must not block real infrastructure.

Measured on live traffic, the lexical randomness score of legitimate services
(WiFi calling, iCloud, CDNs, OCSP) overlaps completely with real malware, so
blocking on the score alone breaks the network. Blocking therefore requires
behavioural confirmation: the client must have been seen cycling through
distinct random-looking names that failed to resolve.
"""
from __future__ import annotations

import pytest

from trench.filter.dga import DGADetector

# Real names observed being blocked on a live deployment by the old scorer.
REAL_INFRASTRUCTURE = [
    "epdg.epc.mnc001.mcc262.pub.3gppnetwork.org",   # VoWiFi / WiFi calling
    "api.apple-cloudkit.com",                        # iCloud
    "d2k3j4h5.cloudfront.net",                       # AWS CDN
    "ocsp.digicert.com",                             # certificate revocation
    "mask.icloud.com",                               # iCloud Private Relay
    "firebaselogging-pa.googleapis.com",
    "graph.facebook.com",
]
DGA_LIKE = ["kq3v9z7x1p2w.info", "x7f2a9b1c3d4e5.biz", "qpwoeirtyalskdjf.com"]


def det(**kw):
    return DGADetector(block=True, **kw)


# --- the core guarantee ---
@pytest.mark.parametrize("name", REAL_INFRASTRUCTURE)
def test_real_infrastructure_is_never_blocked_without_a_campaign(name):
    d = det()
    r = d.check(name, "10.0.0.5")
    assert r.block is False, f"{name} would be blocked on lexical score alone"
    assert r.confirmed is False


@pytest.mark.parametrize("name", REAL_INFRASTRUCTURE)
def test_resolving_names_never_build_a_campaign(name):
    """A name that resolves is real infrastructure; repeating it must never
    push the client toward the blocked state."""
    d = det(burst_min_names=3)
    for _ in range(50):
        d.note_outcome(name, "10.0.0.5", "NOERROR")
    assert d.campaign_size("10.0.0.5") == 0
    assert d.check(name, "10.0.0.5").block is False


# --- but a real campaign is caught ---
def test_failed_random_names_confirm_a_campaign_and_block():
    d = det(burst_min_names=5)
    client = "10.0.0.66"
    # malware cycling generated names; almost all are unregistered -> NXDOMAIN
    for i in range(5):
        name = f"kq3v9z7x1p2w{i}.info"
        assert d.check(name, client).block is False   # early ones pass (and fail anyway)
        d.note_outcome(name, client, "NXDOMAIN")
    assert d.campaign_size(client) == 5
    r = d.check("zx8q4v1n7m2k.info", client)
    assert r.block is True and r.confirmed is True
    assert "campaign" in r.reason


def test_campaign_is_per_client():
    d = det(burst_min_names=3)
    for i in range(4):
        d.note_outcome(f"aq7z3x9v1n{i}.biz", "10.0.0.1", "NXDOMAIN")
    assert d.check("qq8z2x0v4n5.biz", "10.0.0.1").block is True
    assert d.check("qq8z2x0v4n5.biz", "10.0.0.2").block is False   # innocent neighbour


def test_repeating_one_failed_name_is_not_a_campaign():
    """A single dead name retried is a broken app, not a DGA — campaigns are
    made of *distinct* names."""
    d = det(burst_min_names=3)
    for _ in range(30):
        d.note_outcome("kq3v9z7x1p2w.info", "10.0.0.9", "NXDOMAIN")
    assert d.campaign_size("10.0.0.9") == 1
    assert d.check("kq3v9z7x1p2w.info", "10.0.0.9").block is False


def test_campaign_expires_with_its_window():
    d = det(burst_min_names=3, burst_window_s=60)
    for i in range(4):
        d.note_outcome(f"vv9q2x7z1m{i}.biz", "10.0.0.3", "NXDOMAIN", now=1000.0 + i)
    assert d.check("qq7z2x8v3n1k.biz", "10.0.0.3", now=1010.0).block is True
    # long after the window, the client is clean again
    assert d.campaign_size("10.0.0.3", now=5000.0) == 0
    assert d.check("qq7z2x8v3n1k.biz", "10.0.0.3", now=5000.0).block is False


def test_flagging_still_happens_for_visibility():
    """Operators should still see random-looking names, just not have them
    blocked — the signal is useful, the automatic action was not."""
    d = det()
    r = d.check("kq3v9z7x1p2w.info", "10.0.0.5")
    assert r.suspicious is True and r.block is False
    assert "not blocked" in r.reason


def test_block_flag_still_gates_everything():
    d = DGADetector(block=False, burst_min_names=2)
    for i in range(3):
        d.note_outcome(f"zz1q8x3v9n{i}.biz", "10.0.0.4", "NXDOMAIN")
    r = d.check("zz1q8x3v9n9.biz", "10.0.0.4")
    assert r.confirmed is True and r.block is False   # detection on, enforcement off


def test_short_and_ordinary_names_score_zero():
    d = det()
    for name in ("github.com", "apple.com", "bbc.co.uk", "a.io"):
        assert d.check(name, "10.0.0.5").suspicious is False


def test_serverfail_also_counts_toward_a_campaign():
    d = det(burst_min_names=2)
    for i in range(3):
        d.note_outcome(f"pp4q9x2v7n{i}.biz", "10.0.0.8", "SERVFAIL")
    assert d.check("pp4q9x2v7n8.biz", "10.0.0.8").block is True


def test_client_state_is_bounded():
    d = det(burst_min_names=2)
    for i in range(5000):
        d.note_outcome(f"aa1q9x2v7n{i}.biz", f"10.1.{i // 256}.{i % 256}", "NXDOMAIN")
    from trench.filter.dga import BURST_MAX_CLIENTS
    assert len(d._failed) <= BURST_MAX_CLIENTS


# --- end-to-end through the pipeline ---
@pytest.mark.asyncio
async def test_pipeline_does_not_block_wifi_calling():
    from trench.cache import Cache
    from trench.config import Config
    from trench.engine.pipeline import Pipeline
    from trench.filter import FilterEngine
    from trench.stats import Counters
    from trench.wire import RR, Class, Message, Question, Type
    from trench.wire import rdata as R
    from trench.wire.name import Name
    from trench.wire.rrtypes import Rcode

    class Fwd:
        async def resolve(self, q, note=None):
            resp = q.reply(Rcode.NOERROR)
            # a public address: 192.0.2.0/24 reads as private to ipaddress and
            # would be stripped by rebinding protection, masking the result
            resp.answers.append(RR(q.question.name, Type.A, Class.IN, 60, R.A("93.184.216.34")))
            return resp

    cfg = Config.model_validate({"security": {"dga_detection": True, "dga_block": True}})
    p = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                 forwarder=Fwd(), counters=Counters(), config=cfg)
    q = Message(id=1)
    q.set_flag(0x0100, True)
    q.questions.append(Question(
        Name.from_text("epdg.epc.mnc001.mcc262.pub.3gppnetwork.org"), Type.A, Class.IN))
    resp = await p.resolve(q, "10.0.0.5", "udp")
    assert resp.rcode == Rcode.NOERROR
    assert resp.answers, "WiFi calling must resolve, not be sinkholed"
