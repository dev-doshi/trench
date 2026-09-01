"""The silence ledger: who stopped asking, and what they looked up first."""
from __future__ import annotations

import asyncio

from trench.cache import Cache
from trench.clients.activity import QUIET_AFTER, Ledger
from trench.config import Config
from trench.engine import Pipeline
from trench.filter import FilterEngine
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode

NOW = 1_700_000_000.0


def test_an_active_device_is_active():
    led = Ledger()
    led.note("10.0.0.5", "example.com", now=NOW)
    (row,) = led.report(now=NOW + 5)
    assert row["status"] == "active"
    assert row["queries"] == 1


def test_present_and_quiet_is_silent_not_bypassing():
    """A sleeping laptop must not be accused of anything."""
    led = Ledger()
    led.note("10.0.0.5", "example.com", now=NOW)
    led.note_lease("10.0.0.5", "laptop", now=NOW + QUIET_AFTER)
    (row,) = led.report(now=NOW + QUIET_AFTER + 60)
    assert row["status"] == "silent"
    assert "no queries for" in row["evidence"]


def test_bootstrap_lookup_then_silence_reads_as_bypassing():
    led = Ledger()
    led.note("10.0.0.5", "chrome.cloudflare-dns.com", now=NOW)
    led.note_lease("10.0.0.5", "laptop", now=NOW + QUIET_AFTER)
    (row,) = led.report(now=NOW + QUIET_AFTER + 60)
    assert row["status"] == "bypassing"
    assert row["encrypted_resolver"] == "cloudflare-dns.com"
    assert "before going quiet" in row["evidence"]


def test_a_bootstrap_lookup_alone_is_not_an_accusation():
    """Browsers probe their provider all the time; that is not bypass."""
    led = Ledger()
    led.note("10.0.0.5", "dns.google", now=NOW)
    led.note_lease("10.0.0.5", "laptop", now=NOW)
    (row,) = led.report(now=NOW + 5)
    assert row["status"] == "resolver-curious"


def test_a_device_with_no_lease_is_never_called_bypassing():
    """Without evidence the device is still on the network, silence means
    nothing — it may simply have left."""
    led = Ledger()
    led.note("10.0.0.5", "dns.quad9.net", now=NOW)
    (row,) = led.report(now=NOW + QUIET_AFTER * 2)
    assert row["status"] == "active"


def test_report_puts_the_interesting_devices_first():
    led = Ledger()
    led.note("10.0.0.9", "example.com", now=NOW + QUIET_AFTER)      # active
    led.note("10.0.0.5", "dns.nextdns.io", now=NOW)                  # bypassing
    led.note_lease("10.0.0.5", "phone", now=NOW + QUIET_AFTER)
    led.note("10.0.0.7", "example.net", now=NOW)                     # silent
    led.note_lease("10.0.0.7", "tv", now=NOW + QUIET_AFTER)
    statuses = [r["status"] for r in led.report(now=NOW + QUIET_AFTER + 60)]
    assert statuses[0] == "bypassing"
    assert statuses[-1] == "active"


def test_subdomains_match_a_bootstrap_name_and_others_do_not():
    led = Ledger()
    led.note("10.0.0.5", "doh.dns.apple.com", now=NOW)
    led.note("10.0.0.6", "cloudflare-dns.com.evil.example", now=NOW)
    by_ip = {r["ip"]: r for r in led.report(now=NOW)}
    assert by_ip["10.0.0.5"]["encrypted_lookups"] == 1
    assert by_ip["10.0.0.6"]["encrypted_lookups"] == 0


def test_table_is_bounded():
    led = Ledger(max_devices=5)
    for i in range(50):
        led.note(f"10.0.0.{i}", "example.com", now=NOW + i)
    assert len(led.devices) == 5


class Fwd:
    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def test_pipeline_feeds_the_ledger():
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(enabled=False),
                    forwarder=Fwd(), counters=Counters(), config=Config())
    pipe.ledger = Ledger()
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text("dns.google"), Type.A, Class.IN))
    asyncio.run(pipe.resolve(m, "10.0.0.5"))
    (row,) = pipe.ledger.report()
    assert row["ip"] == "10.0.0.5" and row["encrypted_lookups"] == 1


def test_replayed_queries_still_reach_the_ledger():
    """Replay is where a busy device's repeat queries go. Skipping the ledger
    there made the busiest devices look silent — the inverse of the signal."""
    from trench.engine.fastpath import FastPath, WireAnswer

    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(enabled=False),
                    forwarder=Fwd(), counters=Counters(), config=Config())
    pipe.ledger = Ledger()
    fast = FastPath(pipe)
    entry = WireAnswer(b"", (), 0, 0.0, 0, qname="dns.google", qtype="A",
                       action="forwarded", rcode="NOERROR", reason="", rule="",
                       source="", upstream="", proto="udp", answers=[])
    fast._book(entry, "10.0.0.5")

    (row,) = pipe.ledger.report()
    assert row["ip"] == "10.0.0.5"
    assert row["queries"] == 1
    assert row["encrypted_lookups"] == 1      # the corroboration survives too
