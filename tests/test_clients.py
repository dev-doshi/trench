"""Per-client policy, services blocking, safe-search, safe-browse + pipeline wiring."""
from __future__ import annotations

import asyncio

import pytest

from trench.cache import Cache
from trench.clients import Client, ClientRegistry, Policy
from trench.config import Config
from trench.engine import Pipeline
from trench.filter import FilterEngine
from trench.filter.safebrowse import SafeBrowse
from trench.filter.safesearch import safe_target
from trench.filter.services import Services
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


# --- registry ---
def test_identify_ip_cidr_clientid_default():
    reg = ClientRegistry([
        Client("10.0.0.5", "ip", "exact", Policy(name="exact")),
        Client("192.168.1.0/24", "cidr", "lan", Policy(name="lan")),
        Client("phone", "clientid", "phone", Policy(name="phone")),
    ], default=Policy(name="default"))
    assert reg.identify("10.0.0.5").name == "exact"
    assert reg.identify("192.168.1.42").name == "lan"
    assert reg.identify("8.8.8.8").name == "default"
    assert reg.identify("8.8.8.8", "phone").name == "phone"


# --- services ---
def test_services_match_and_schedule():
    s = Services()
    assert s.service_for("www.youtube.com") == "youtube"
    assert s.service_for("googlevideo.com") == "youtube"
    assert s.service_for("example.com") is None
    assert s.is_blocked("youtu.be", frozenset({"youtube"})) == "youtube"
    assert s.is_blocked("youtu.be", frozenset({"tiktok"})) is None
    # scheduled: blocked only Monday 0-60 min; outside -> not blocked
    s2 = Services(schedules={"youtube": [(0, 0, 60)]})
    import time
    monday = time.mktime(time.strptime("2024-01-01 00:30", "%Y-%m-%d %H:%M"))  # Mon
    tuesday = time.mktime(time.strptime("2024-01-02 00:30", "%Y-%m-%d %H:%M"))
    assert s2.blocked_now("youtube", monday) is True
    assert s2.blocked_now("youtube", tuesday) is False


# --- safe search ---
def test_safe_target():
    assert safe_target("www.google.com") == "forcesafesearch.google.com"
    assert safe_target("google.de") == "forcesafesearch.google.com"
    assert safe_target("bing.com") == "strict.bing.com"
    assert safe_target("www.youtube.com") == "restrict.youtube.com"
    assert safe_target("example.com") is None


# --- safe browse ---
def test_safebrowse():
    sb = SafeBrowse()
    assert sb.check("malware.testing.google.test", safe_browse=True, parental=False) == "malware"
    assert sb.check("x.evil.test", safe_browse=True, parental=False) == "malware"  # subdomain
    assert sb.check("adult.example", safe_browse=True, parental=True) == "adult"
    assert sb.check("good.com", safe_browse=True, parental=True) is None


# --- pipeline integration ---
class FakeForwarder:
    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def mkquery(name, rtype=Type.A):
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    return m


def build_pipeline():
    reg = ClientRegistry([
        Client("10.0.0.5", "ip", "kid",
               Policy(name="kid", services=frozenset({"youtube"}),
                      safe_browse=True, parental=True)),
        Client("10.0.0.6", "ip", "filtered", Policy(name="filtered", safe_search=True)),
    ], default=Policy(name="default"))
    return Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=FakeForwarder(), counters=Counters(), config=Config(),
                    clients=reg, services=Services(), safebrowse=SafeBrowse())


def test_pipeline_service_block_per_client():
    pipe = build_pipeline()
    # kid -> youtube blocked
    r = asyncio.run(pipe.resolve(mkquery("www.youtube.com"), "10.0.0.5"))
    assert r.answers[0].rdata.to_text() == "0.0.0.0"
    # default client -> youtube forwarded
    r2 = asyncio.run(pipe.resolve(mkquery("www.youtube.com"), "9.9.9.9"))
    assert r2.answers[0].rdata.to_text() == "1.2.3.4"


def test_pipeline_safe_search_chain():
    pipe = build_pipeline()
    r = asyncio.run(pipe.resolve(mkquery("google.com"), "10.0.0.6"))
    kinds = [(rr.rtype, rr.rdata.to_text()) for rr in r.answers]
    assert (Type.CNAME, "forcesafesearch.google.com.") in kinds
    assert any(rt == Type.A and val == "1.2.3.4" for rt, val in kinds)


def test_pipeline_safe_search_target_is_cached():
    """The rewrite target resolves through the cache: every safe-searched
    lookup used to cost an upstream round trip."""
    pipe = build_pipeline()
    calls = []
    real = pipe.forwarder.resolve

    async def counting(query, note=None):
        calls.append(query.question.name.to_text())
        return await real(query, note)

    pipe.forwarder.resolve = counting

    async def three():
        for name in ("google.com", "www.google.com", "google.de"):
            r = await pipe.resolve(mkquery(name), "10.0.0.6")
            assert any(rr.rtype == Type.A for rr in r.answers)

    asyncio.run(three())
    assert calls == ["forcesafesearch.google.com."]


def test_pipeline_safebrowse_parental():
    pipe = build_pipeline()
    r = asyncio.run(pipe.resolve(mkquery("malware.testing.google.test"), "10.0.0.5"))
    assert r.answers[0].rdata.to_text() == "0.0.0.0"
    r2 = asyncio.run(pipe.resolve(mkquery("adult.example"), "10.0.0.5"))
    assert r2.answers[0].rdata.to_text() == "0.0.0.0"


# --- every worker has to see a console-managed client, not just the primary ---
@pytest.mark.asyncio
async def test_a_non_primary_worker_loads_database_managed_clients(tmp_path):
    """Only the primary opens the database for writing, and `setup_storage`
    returned before `reload_clients` for everyone else — so a client created in
    the console existed in one worker out of `workers`. Behind one SO_REUSEPORT
    socket that does not read as "it did not work": the exemption applies to
    roughly 1/N of the client's queries and looks like flapping.
    """
    from trench.app import App
    from trench.config import Config
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "querylog": {"enabled": True}})
    primary = App(cfg, primary=True)
    await primary.setup_storage()
    try:
        await primary.db.execute(
            "INSERT INTO client(ident, ident_type, name, policy) VALUES(?,?,?,?)",
            ("10.0.0.9", "ip", "unfiltered", '{"block": false}'))
        await primary.reload_clients()
        assert primary.clients.identify("10.0.0.9", None).block is False

        worker = App(cfg, primary=False)
        await worker.setup_storage()
        try:
            assert worker.db is None, "a non-primary worker must not open a writer"
            pol = worker.clients.identify("10.0.0.9", None)
            assert pol.block is False, "this worker never saw the managed client"
        finally:
            if worker.db_ro is not None:
                await worker.db_ro.close()
    finally:
        await primary.db.close()


def test_notify_workers_is_a_no_op_without_a_supervisor():
    """A single-process install has no siblings, and must not signal whatever
    process happens to be its parent."""
    import os
    from unittest.mock import patch

    from trench.app import App
    from trench.config import Config
    app = App(Config())
    assert app.supervisor_pid is None
    with patch.object(os, "kill") as kill:
        app.notify_workers()
        kill.assert_not_called()
        app.supervisor_pid = 4242
        app.notify_workers()
        kill.assert_called_once()


@pytest.mark.asyncio
async def test_a_worker_that_started_before_the_database_existed_recovers(tmp_path):
    """The workers are forked in the same instant, so on a first run a sibling
    can look for the primary's database before the primary has created it. A
    handle opened only at start-up would then be absent for the life of the
    process, and every console-managed client would be invisible in that worker
    until the next restart."""
    from trench.app import App
    from trench.config import Config
    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "querylog": {"enabled": True}})
    worker = App(cfg, primary=False)
    await worker.setup_storage()                 # nothing to open yet
    assert worker.db_ro is None
    assert worker.clients.identify("10.0.0.9", None).block is True

    primary = App(cfg, primary=True)             # …the primary catches up
    await primary.setup_storage()
    try:
        await primary.db.execute(
            "INSERT INTO client(ident, ident_type, name, policy) VALUES(?,?,?,?)",
            ("10.0.0.9", "ip", "unfiltered", '{"block": false}'))
        await worker.reload_clients()            # the next reload finds it
        assert worker.db_ro is not None, "the handle must be retried, not given up on"
        assert worker.clients.identify("10.0.0.9", None).block is False
    finally:
        if worker.db_ro is not None:
            await worker.db_ro.close()
        await primary.db.close()
