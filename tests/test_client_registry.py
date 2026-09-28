"""Client identification: the match order, the memo, and the neighbour table.

`identify` runs on the hot path for every query, and the pieces that were never
tested are the ones that decide whose policy applies — CIDR and MAC matching,
the DB-managed override, and the bounded memo that a spoofed-source flood used
to be able to evict every real client from.
"""
from __future__ import annotations

import pytest

from trench.clients import registry as reg
from trench.clients.model import Client, Policy
from trench.clients.registry import ClientRegistry, refresh_neighbours
from trench.config import Config


def _pol(name):
    return Policy(name=name)


def _client(ident, itype, name=None):
    return Client(ident, itype, name or ident, _pol(name or ident))


@pytest.fixture(autouse=True)
def _clean_neighbours():
    before = dict(reg._NEIGHBOURS)
    reg._NEIGHBOURS = {}
    yield
    reg._NEIGHBOURS = before


# --- match order ---
def test_an_exact_ip_wins_over_a_containing_cidr():
    r = ClientRegistry([_client("10.0.0.0/8", "cidr", "lan"),
                        _client("10.0.0.5", "ip", "laptop")], _pol("default"))
    assert r.identify("10.0.0.5").name == "laptop"
    assert r.identify("10.0.0.6").name == "lan"


def test_a_client_id_wins_over_the_address():
    """The token comes off an authenticated transport; the address does not."""
    r = ClientRegistry([_client("10.0.0.5", "ip", "by-ip"),
                        _client("tok123", "clientid", "by-token")], _pol("default"))
    assert r.identify("10.0.0.5", "tok123").name == "by-token"
    assert r.identify("10.0.0.5", "").name == "by-ip"
    assert r.identify("10.0.0.5", "unknown-token").name == "by-ip"


def test_token_and_clientid_ident_types_are_equivalent():
    r = ClientRegistry([_client("t1", "token", "a"),
                        _client("t2", "clientid", "b")], _pol("default"))
    assert r.identify("10.0.0.1", "t1").name == "a"
    assert r.identify("10.0.0.1", "t2").name == "b"


def test_ipv6_cidr_matching():
    r = ClientRegistry([_client("2001:db8::/32", "cidr", "v6")], _pol("default"))
    assert r.identify("2001:db8::1").name == "v6"
    assert r.identify("2001:db9::1").name == "default"


def test_a_host_cidr_is_accepted_unstrict():
    """`10.0.0.5/24` has host bits set; an operator meant that host's network."""
    r = ClientRegistry([_client("10.0.0.5/24", "cidr", "net")], _pol("default"))
    assert r.identify("10.0.0.99").name == "net"


def test_a_malformed_cidr_is_dropped_with_a_warning(caplog):
    r = ClientRegistry([_client("not-a-network", "cidr", "bad")], _pol("default"))
    assert r.cidrs == []
    assert any("bad CIDR" in x.getMessage() for x in caplog.records)
    assert r.identify("10.0.0.1").name == "default"


def test_an_unparseable_client_address_falls_through_to_the_default():
    r = ClientRegistry([_client("10.0.0.0/8", "cidr", "lan")], _pol("default"))
    assert r.identify("not-an-address").name == "default"


def test_an_unknown_address_gets_the_default_policy():
    r = ClientRegistry([], _pol("default"))
    assert r.identify("192.0.2.1").name == "default"


def test_an_unknown_ident_type_is_ignored():
    r = ClientRegistry([_client("whatever", "carrier-pigeon", "x")], _pol("default"))
    assert r.identify("whatever").name == "default"


# --- MAC ---
def test_a_mac_client_matches_through_the_neighbour_table():
    reg._NEIGHBOURS = {"10.0.0.9": "aa:bb:cc:dd:ee:ff"}
    r = ClientRegistry([_client("AA:BB:CC:DD:EE:FF", "mac", "phone")], _pol("default"))
    assert r.identify("10.0.0.9").name == "phone"


def test_an_address_with_no_neighbour_entry_falls_through():
    reg._NEIGHBOURS = {}
    r = ClientRegistry([_client("aa:bb:cc:dd:ee:ff", "mac", "phone")], _pol("default"))
    assert r.identify("10.0.0.9").name == "default"


def test_the_neighbour_table_is_not_consulted_without_a_mac_client(monkeypatch):
    """`identify` runs inside the event loop; the old code forked `arp` here."""
    looked = []
    monkeypatch.setattr(reg, "_arp_lookup", lambda ip: looked.append(ip))
    r = ClientRegistry([_client("10.0.0.1", "ip", "a")], _pol("default"))
    r.identify("10.0.0.99")
    assert looked == []


def test_arp_lookup_never_blocks_and_returns_none_for_a_miss():
    reg._NEIGHBOURS = {"10.0.0.1": "aa:bb:cc:dd:ee:ff"}
    assert reg._arp_lookup("10.0.0.1") == "aa:bb:cc:dd:ee:ff"
    assert reg._arp_lookup("10.0.0.2") is None


# --- the memo ---
def test_the_result_is_memoized_per_address_and_token():
    r = ClientRegistry([_client("10.0.0.5", "ip", "laptop")], _pol("default"))
    calls = []
    real = r._resolve
    r._resolve = lambda ip, cid: calls.append((ip, cid)) or real(ip, cid)
    assert r.identify("10.0.0.5").name == "laptop"
    assert r.identify("10.0.0.5").name == "laptop"
    assert calls == [("10.0.0.5", "")]
    r.identify("10.0.0.5", "tok")          # a different key, so a second resolve
    assert len(calls) == 2


def test_the_memo_is_bounded_and_evicts_the_least_recently_used():
    """The old ceiling stopped caching once reached, so a spoofed-source flood
    permanently evicted every real client from the fast path."""
    r = ClientRegistry([], _pol("default"))
    r.max_cache = 3
    for i in range(3):
        r.identify(f"10.0.0.{i}")
    r.identify("10.0.0.0")                 # touch the oldest, making it newest
    r.identify("10.0.0.99")                # forces one eviction
    assert len(r._cache) == 3
    assert ("10.0.0.0", "") in r._cache, "a recently used entry must survive"
    assert ("10.0.0.1", "") not in r._cache


def test_invalidate_clears_the_memo():
    r = ClientRegistry([_client("10.0.0.5", "ip", "laptop")], _pol("default"))
    r.identify("10.0.0.5")
    assert r._cache
    r.invalidate()
    assert r._cache == {}


# --- from_config ---
def _cfg(**over):
    data = {"filtering": {"safe_search": True, "safe_browse": True,
                          "parental": False, "services": ["tiktok"],
                          "ctags": ["household"]}}
    data.update(over)
    return Config.model_validate(data)


def test_the_default_policy_comes_from_the_filtering_section():
    pol = ClientRegistry.default_policy(_cfg())
    assert pol.name == "default" and pol.block is True
    assert pol.safe_search is True and pol.safe_browse is True
    assert pol.parental is False
    assert pol.services == frozenset({"tiktok"})
    assert pol.ctags == frozenset({"household"})


def test_a_client_inherits_the_defaults_it_does_not_override():
    r = ClientRegistry.from_config(_cfg(clients=[{"ident": "10.0.0.5",
                                                  "name": "laptop"}]))
    pol = r.identify("10.0.0.5")
    assert pol.name == "laptop"
    assert pol.safe_search is True             # inherited
    assert pol.services == frozenset({"tiktok"})


def test_a_client_override_wins_over_the_default():
    r = ClientRegistry.from_config(_cfg(
        filtering={"safe_search": True, "safe_browse": True, "parental": False,
                   "services": ["tiktok"], "ctags": ["household"],
                   "groups": {"kids": {"sources": []}}},
        clients=[{
            "ident": "10.0.0.5", "name": "kid", "safe_search": False,
            "parental": True, "services": ["youtube"], "tags": ["child"],
            "block": False, "group": "kids"}]))
    pol = r.identify("10.0.0.5")
    assert pol.safe_search is False and pol.parental is True
    assert pol.services == frozenset({"youtube"})
    assert pol.ctags == frozenset({"child"})
    assert pol.block is False
    assert pol.group == "kids"


def test_a_client_may_name_a_configured_upstream_group():
    r = ClientRegistry.from_config(_cfg(
        upstream={"groups": {"family": ["1.1.1.3"]}},
        clients=[{"ident": "10.0.0.5", "name": "kid", "upstream_group": "family"}]))
    assert r.identify("10.0.0.5").upstream_group == "family"


def test_an_unnamed_client_is_named_by_its_ident():
    r = ClientRegistry.from_config(_cfg(clients=[{"ident": "10.0.0.5"}]))
    assert r.identify("10.0.0.5").name == "10.0.0.5"


def test_database_managed_clients_override_the_config_for_the_same_ident():
    cfg = _cfg(clients=[{"ident": "10.0.0.5", "name": "from-config"}])
    extra = [Client("10.0.0.5", "ip", "from-db", _pol("from-db"))]
    r = ClientRegistry.from_config(cfg, extra)
    assert r.identify("10.0.0.5").name == "from-db"


# --- client_from_row ---
def _row(**over):
    row = {"ident": "10.0.0.7", "ident_type": "ip", "name": "tablet", "policy": "{}"}
    row.update(over)
    return row


def test_a_row_with_an_empty_policy_inherits_the_defaults():
    c = ClientRegistry.client_from_row(_cfg(), _row())
    assert c.ident == "10.0.0.7" and c.ident_type == "ip"
    assert c.policy.name == "tablet" and c.policy.block is True
    assert c.policy.safe_search is True


def test_a_row_policy_overrides_every_field():
    import json
    pol = {"block": False, "tags": ["kid"], "safe_search": False,
           "safe_browse": False, "parental": True, "services": ["tiktok", "snap"],
           "upstream_group": "family", "group": "kids"}   # not validated here
    c = ClientRegistry.client_from_row(_cfg(), _row(policy=json.dumps(pol)))
    assert c.policy.block is False
    assert c.policy.ctags == frozenset({"kid"})
    assert c.policy.parental is True
    assert c.policy.services == frozenset({"tiktok", "snap"})
    assert c.policy.upstream_group == "family" and c.policy.group == "kids"


@pytest.mark.parametrize("policy", ["", None, "{not json"])
def test_an_unreadable_row_policy_falls_back_to_the_defaults(policy):
    c = ClientRegistry.client_from_row(_cfg(), _row(policy=policy))
    assert c.policy.block is True and c.policy.safe_search is True


@pytest.mark.parametrize("policy", ["[]", '"a string"', "5", "null"])
def test_a_non_object_row_policy_is_ignored_rather_than_fatal(policy, caplog):
    """Regression: this raised inside `reload_clients`' single try/except, so
    one malformed row disabled every database-managed client at once."""
    c = ClientRegistry.client_from_row(_cfg(), _row(policy=policy))
    assert c.policy.block is True and c.policy.safe_search is True
    assert any("non-object policy" in r.getMessage() for r in caplog.records)


def test_a_row_without_a_name_is_named_by_its_ident():
    c = ClientRegistry.client_from_row(_cfg(), _row(name=""))
    assert c.policy.name == "10.0.0.7" and c.name == ""


# --- the neighbour table refresh ---
class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def test_refresh_parses_ip_neigh_output(monkeypatch):
    out = ("192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
           "192.168.1.11 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE\n"
           "192.168.1.12 dev eth0  FAILED\n")

    def run(argv, **kw):
        return _Result(out) if argv[0] == "ip" else _Result("", 1)

    monkeypatch.setattr("subprocess.run", run)
    assert refresh_neighbours() == 2
    assert reg._NEIGHBOURS["192.168.1.10"] == "aa:bb:cc:dd:ee:01"
    assert "192.168.1.12" not in reg._NEIGHBOURS


def test_refresh_falls_back_to_arp_when_ip_is_absent(monkeypatch):
    def run(argv, **kw):
        if argv[0] == "ip":
            raise FileNotFoundError("no ip command")
        return _Result("? (192.168.1.20) at aa:bb:cc:dd:ee:03 on en0 ifscope [ethernet]\n")

    monkeypatch.setattr("subprocess.run", run)
    assert refresh_neighbours() == 1
    assert reg._NEIGHBOURS["192.168.1.20"] == "aa:bb:cc:dd:ee:03"


def test_refresh_with_neither_command_leaves_an_empty_table(monkeypatch):
    monkeypatch.setattr("subprocess.run",
                        lambda argv, **kw: (_ for _ in ()).throw(FileNotFoundError))
    assert refresh_neighbours() == 0
    assert reg._NEIGHBOURS == {}


def test_refresh_ignores_a_nonzero_exit(monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda argv, **kw: _Result("junk", 1))
    assert refresh_neighbours() == 0


def test_refresh_ignores_empty_output(monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda argv, **kw: _Result("", 0))
    assert refresh_neighbours() == 0


def test_refresh_stamps_the_time(monkeypatch):
    monkeypatch.setattr("subprocess.run",
                        lambda argv, **kw: _Result("192.168.1.30 dev eth0 lladdr "
                                                   "aa:bb:cc:dd:ee:04 REACHABLE\n"))
    reg._NEIGHBOURS_AT = 0.0
    refresh_neighbours()
    assert reg._NEIGHBOURS_AT > 0
