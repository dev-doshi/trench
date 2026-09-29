"""Device names from reverse lookups (clients/rdns.py).

What matters here is mostly what must *not* happen: a public address looked up,
a lookup sent to a public resolver, a hostile PTR target shown as-is, or a
spoofed-source flood turned into a flood of lookups.
"""
from __future__ import annotations

import asyncio

import pytest
from support import open_resolver

from trench.cache import Cache
from trench.clients import rdns
from trench.clients.rdns import (
    ClientNames,
    display_name,
    is_private,
    looks_random,
    parse_server,
    ptr_query,
    ptr_targets,
)
from trench.config import Config, ConfigError
from trench.engine import Pipeline
from trench.filter import FilterEngine
from trench.stats import Counters
from trench.transport.upstream import Router
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


def _answer(query: Message, *targets: str, rtype=Type.PTR, rdata=R.PTR) -> Message:
    resp = query.reply(Rcode.NOERROR)
    for t in targets:
        resp.answers.append(RR(query.question.name, rtype, Class.IN, 60,
                               rdata(Name.from_text(t))))
    return resp


class Router_:
    """Answers PTR lookups from a table, recording what it was asked."""

    def __init__(self, table: dict[str, list[str]] | None = None, *, fail=()):
        self.table = table or {}
        self.fail = set(fail)
        self.asked: list[str] = []

    async def __call__(self, query: Message) -> Message:
        name = query.question.name.to_text()
        self.asked.append(name)
        if name in self.fail:
            raise OSError("no reply")
        return _answer(query, *self.table.get(name, []))


def rev(ip: str) -> str:
    return ptr_query(ip).question.name.to_text()


# ── what gets shown ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("target, shown", [
    ("MacBook-Pro-von-Dev.fritz.box.", "MacBook-Pro-von-Dev"),
    ("dev-iphone-13.fritz.box", "dev-iphone-13"),
    ("nas.lan.", "nas"),
    ("printer", "printer"),
    ("www.bank.com.", "www"),                     # never the name it claims
    ("<script>x</script>.lan", "script-x-script"),
    ("Küchen Radio.fritz.box", "K-chen-Radio"),
    ("34.178.168.192.in-addr.arpa.", ""),         # a router echoing the question
    ("7cdc5c78-97e4-4539-90c8-3942de350974.fritz.box.", ""),
    ("a0b1c2d3e4f5.lan", ""),
    ("a0:b1:c2:d3:e4:f5", ""),
    ("PC-192-168-178-34.fritz.box", ""),
    ("", ""),
    ("x" * 80 + ".lan", "x" * 63),
])
def test_what_a_ptr_target_is_shown_as(target, shown):
    assert display_name(target) == shown


def test_random_names_can_be_kept_when_asked_for():
    uuid = "7cdc5c78-97e4-4539-90c8-3942de350974"
    assert display_name(uuid + ".fritz.box", hide_random=False) == uuid
    assert looks_random(uuid) and not looks_random("android-tablet")


@pytest.mark.parametrize("ip, private", [
    ("192.168.178.34", True), ("10.1.2.3", True), ("172.16.0.1", True),
    ("100.64.3.4", True), ("127.0.0.1", True), ("169.254.1.1", True),
    ("fd12::1", True), ("fe80::1", True), ("::ffff:192.168.1.5", True),
    ("8.8.8.8", False), ("172.32.0.1", False), ("2a00:1450::1", False),
    ("224.0.0.1", False), ("0.0.0.0", False), ("::", False), ("nonsense", False),
])
def test_only_private_addresses_are_candidates(ip, private):
    assert is_private(ip) is private


@pytest.mark.parametrize("spec, want", [
    ("192.168.178.1", ("192.168.178.1", 53)),
    ("192.168.178.1:5353", ("192.168.178.1", 5353)),
    ("fd00::1", ("fd00::1", 53)),
    ("[fd00::1]:5300", ("fd00::1", 5300)),
])
def test_a_server_on_this_network_is_accepted(spec, want):
    assert parse_server(spec) == want


@pytest.mark.parametrize("spec", ["9.9.9.9", "1.1.1.1:53", "[2606:4700::1111]:53",
                                  "fritz.box", "tls://192.168.1.1", "192.168.1.1:0",
                                  "192.168.1.1:dns"])
def test_anything_else_is_refused_at_load(spec):
    with pytest.raises(ValueError):
        parse_server(spec)
    with pytest.raises(ConfigError):
        Config.load_dict({"client_names": {"server": spec}})


def test_the_ptr_class_decides_not_the_type_field():
    """`rtype` is a field a hostile answer fills in; the rdata's class is what
    was actually parsed."""
    q = ptr_query("192.168.1.5")
    resp = _answer(q, "evil.lan", rtype=Type.PTR, rdata=R.CNAME)
    resp.answers.append(RR(q.question.name, Type.PTR, Class.IN, 60, R.A("1.2.3.4")))
    assert ptr_targets(resp) == []
    assert ptr_targets(_answer(q, "tv.lan")) == ["tv.lan."]
    nx = q.reply(Rcode.NXDOMAIN)
    assert ptr_targets(nx) == [] and ptr_targets(None) == []


# ── the sweep ───────────────────────────────────────────────────────────────

def test_a_sweep_names_private_addresses_and_never_asks_about_public_ones():
    net = Router_({rev("192.168.178.34"): ["dev-macbook.fritz.box."],
                   rev("192.168.178.49"): ["0a1b2c3d-1111-2222-3333-444455556666.fritz.box.",
                                           "vev.fritz.box."]})
    names = ClientNames(net)
    asked = asyncio.run(names.sweep(["192.168.178.34", "8.8.8.8", "192.168.178.49",
                                     "192.168.178.34", "2a00:1450::1"]))
    assert asked == 2
    assert sorted(net.asked) == sorted([rev("192.168.178.34"), rev("192.168.178.49")])
    assert names.known() == {"192.168.178.34": ("dev-macbook", "dev-macbook.fritz.box"),
                             "192.168.178.49": ("vev", "vev.fritz.box")}


def test_a_name_is_not_asked_for_again_until_it_is_due():
    t = [1000.0]
    net = Router_({rev("10.0.0.2"): ["tv.lan."]})
    names = ClientNames(net, ttl=6 * 3600, clock=lambda: t[0])
    asyncio.run(names.sweep(["10.0.0.2", "10.0.0.3"]))
    asyncio.run(names.sweep(["10.0.0.2", "10.0.0.3"]))
    assert len(net.asked) == 2
    t[0] += rdns.NEGATIVE_TTL + 1         # the nameless one is retried first
    asyncio.run(names.sweep(["10.0.0.2", "10.0.0.3"]))
    assert net.asked[2:] == [rev("10.0.0.3")]
    t[0] += 5 * 3600
    asyncio.run(names.sweep(["10.0.0.2"]))
    assert net.asked[-1] == rev("10.0.0.2")


def test_a_router_that_stops_answering_does_not_erase_a_name():
    t = [0.0]
    net = Router_({rev("10.0.0.2"): ["tv.lan."]})
    names = ClientNames(net, ttl=60, clock=lambda: t[0])
    asyncio.run(names.sweep(["10.0.0.2"]))
    net.fail.add(rev("10.0.0.2"))
    t[0] += 61
    asyncio.run(names.sweep(["10.0.0.2"]))
    assert names.name_for("10.0.0.2") == "tv"
    assert names.failures == 1


def test_a_slow_router_costs_one_timeout_not_the_sweep(monkeypatch):
    monkeypatch.setattr(rdns, "TIMEOUT", 0.05)

    async def hang(query):
        if "2.0.0.10" in query.question.name.to_text():
            await asyncio.sleep(10)
        return _answer(query, "fast.lan.")

    names = ClientNames(hang)
    asyncio.run(names.sweep(["10.0.0.2", "10.0.0.3"]))
    assert names.known() == {"10.0.0.3": ("fast", "fast.lan")}


def test_a_flood_of_sources_is_bounded(monkeypatch):
    monkeypatch.setattr(rdns, "MAX_ENTRIES", 50)
    net = Router_()
    names = ClientNames(net)
    ips = [f"10.{i // 250}.{i % 250}.1" for i in range(1000)]
    assert asyncio.run(names.sweep(ips)) == rdns.PER_SWEEP
    for _ in range(3):
        asyncio.run(names.sweep(ips))
    assert len(names._names) <= 50
    assert len(net.asked) == 4 * rdns.PER_SWEEP


# ── the pipeline's side of it ───────────────────────────────────────────────

class Upstream:
    def __init__(self, routes=None):
        self.asked: list[str] = []
        self.router = Router(routes=routes or {})

    async def resolve(self, query: Message, note=None) -> Message:
        self.asked.append(query.question.name.to_text())
        return _answer(query, "tv.fritz.box.")


def _pipe(fwd):
    cfg = Config.model_validate({})
    return Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=fwd, counters=Counters(), config=open_resolver(cfg))


def test_an_unrouted_private_reverse_zone_is_never_forwarded():
    fwd = Upstream()
    got = asyncio.run(_pipe(fwd).ask_privately(ptr_query("192.168.178.34")))
    assert got is None and fwd.asked == []


def test_a_public_address_is_never_forwarded_even_when_asked_directly():
    fwd = Upstream(routes={"178.168.192.in-addr.arpa": [object()]})
    got = asyncio.run(_pipe(fwd).ask_privately(ptr_query("8.8.8.8")))
    assert got is None and fwd.asked == []


def test_a_routed_reverse_zone_goes_to_its_route_without_a_log_line():
    fwd = Upstream(routes={"178.168.192.in-addr.arpa": [object()]})
    pipe = _pipe(fwd)
    got = asyncio.run(pipe.ask_privately(ptr_query("192.168.178.34")))
    assert ptr_targets(got) == ["tv.fritz.box."]
    assert fwd.asked == [rev("192.168.178.34")]
    assert pipe.counters.total == 0            # not a client query


def test_the_whole_path_names_a_device():
    fwd = Upstream(routes={"178.168.192.in-addr.arpa": [object()]})
    names = ClientNames(_pipe(fwd).ask_privately)
    asyncio.run(names.sweep(["192.168.178.34", "10.0.0.9"]))
    assert names.known() == {"192.168.178.34": ("tv", "tv.fritz.box")}


# ── the console's view of it ────────────────────────────────────────────────

async def _app_with_api(tmp_path, **cfg):
    import aiohttp  # noqa: F401 — imported here so the unit tests above need nothing
    from support import free_port

    from trench.api import APIServer
    from trench.app import App
    config = Config.model_validate({"data_dir": str(tmp_path),
                                    "server": {"do53": {"enabled": False}},
                                    "web": {"enabled": True, "admin_password": "pw"},
                                    **cfg})
    app = App(config)
    await app.setup_storage()
    port = free_port()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    return app, port


async def _names(tmp_path, app, port):
    import aiohttp
    base = f"http://127.0.0.1:{port}"
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
        await s.post(f"{base}/api/v1/auth/login", json={"name": "admin", "password": "pw"})
        r = await s.post(f"{base}/api/v1/clients/manage",
                         json={"ident": "10.0.0.5", "ident_type": "ip", "name": "Kid's tablet"})
        assert r.status == 200
        r = await s.get(f"{base}/api/v1/clients/names")
        assert r.status == 200
        return await r.json()


@pytest.mark.asyncio
async def test_a_name_you_gave_beats_the_routers(tmp_path):
    app, port = await _app_with_api(tmp_path)
    try:
        await app._adopt_names()
        net = Router_({rev("10.0.0.5"): ["tablet.lan."], rev("10.0.0.6"): ["tv.lan."]})
        app.client_names.ask = net
        await app.client_names.sweep(["10.0.0.5", "10.0.0.6"])
        got = await _names(tmp_path, app, port)
        assert got["names"]["10.0.0.5"] == {"name": "Kid's tablet", "source": "manual",
                                            "fqdn": ""}
        assert got["names"]["10.0.0.6"] == {"name": "tv", "source": "network",
                                            "fqdn": "tv.lan"}
        assert got["lookup"] == {"enabled": True, "via": "route"}
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_no_network_names_while_the_log_keeps_no_addresses(tmp_path):
    app, port = await _app_with_api(tmp_path, querylog={"privacy_level": 1})
    try:
        await app._adopt_names()
        net = Router_({rev("10.0.0.6"): ["tv.lan."]})
        app.client_names.ask = net
        await app._names_sweep()
        assert net.asked == []
        app.client_names._store("10.0.0.6", "tv", "tv.lan", 60)
        got = await _names(tmp_path, app, port)
        assert "10.0.0.6" not in got["names"] and "10.0.0.5" in got["names"]
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_switching_it_off_drops_the_sweep_and_the_names(tmp_path):
    app, port = await _app_with_api(tmp_path)
    try:
        await app._adopt_names()
        assert app.scheduler.running("client-names")
        app.config = Config.model_validate({**app.config.model_dump(),
                                            "client_names": {"reverse_lookup": False}})
        await app._adopt_names()
        assert app.client_names is None and not app.scheduler.running("client-names")
    finally:
        await app.stop()


@pytest.mark.asyncio
async def test_a_configured_server_is_asked_directly(tmp_path):
    app, port = await _app_with_api(tmp_path, client_names={"server": "192.168.178.1"})
    try:
        await app._adopt_names()
        assert app._names_ask is not None
        assert app.client_names.ask is not app.pipeline.ask_privately
    finally:
        await app.stop()
