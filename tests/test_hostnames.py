"""DHCP-learned device names: sanitising, forward + reverse answers, hijack refusal."""
from __future__ import annotations

import asyncio

import pytest

from trench.cache import Cache
from trench.clients.names import HostNames, reverse_name, sanitize_hostname
from trench.config import Config
from trench.dhcp.scope import Scope
from trench.dhcp.server import build_reply
from trench.dhcp.v4 import OPT_HOSTNAME, OPT_MSG_TYPE, OPT_REQUESTED_IP, DhcpPacket, MessageType
from trench.engine import Pipeline
from trench.filter import FilterEngine
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


def names(**kw) -> HostNames:
    return HostNames(domain="lan", network="192.168.1.0/24", **kw)


def mkquery(name: str, rtype=Type.A) -> Message:
    m = Message(id=7)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    return m


# --- sanitising -------------------------------------------------------------
def test_hostname_is_reduced_to_one_safe_label():
    assert sanitize_hostname("Laptop") == "laptop"
    assert sanitize_hostname("kids tablet") == "kids-tablet"
    assert sanitize_hostname("  MacBook-Pro. ") == "macbook-pro"
    assert sanitize_hostname("") == ""
    assert sanitize_hostname("...") == ""
    assert sanitize_hostname("-" * 5) == ""


def test_a_client_cannot_claim_a_name_in_another_zone():
    """Option 12 is written by the device; `www.bank.com` must never become one."""
    n = names()
    fqdn = n.register("192.168.1.5", "www.bank.com")
    assert fqdn == "www.lan"                     # the leaf, inside our domain only
    assert n.ip_for("www.bank.com") == ""


def test_registration_is_confined_to_the_scope_network():
    n = names()
    assert n.register("8.8.8.8", "laptop") == ""
    assert n.name_for("8.8.8.8") == ""


def test_configured_names_are_not_taken_over_by_a_lease():
    n = names(reserved={"nas.lan"})
    assert n.register("192.168.1.9", "nas") == ""
    assert n.ip_for("nas.lan") == ""


def test_first_device_keeps_a_contested_name():
    n = names()
    assert n.register("192.168.1.5", "phone") == "phone.lan"
    assert n.register("192.168.1.6", "phone") == ""
    assert n.ip_for("phone.lan") == "192.168.1.5"


def test_renaming_a_device_drops_its_old_name():
    n = names()
    n.register("192.168.1.5", "laptop")
    n.register("192.168.1.5", "workstation")
    assert n.ip_for("laptop.lan") == ""
    assert n.ip_for("workstation.lan") == "192.168.1.5"


def test_table_is_bounded():
    n = names(max_entries=3)
    for i in range(10, 20):
        n.register(f"192.168.1.{i}", f"host{i}")
    assert len(n.entries()) == 3


# --- resolving --------------------------------------------------------------
def test_forward_and_reverse_answers():
    n = names()
    n.register("192.168.1.50", "kids-tablet")
    resp = n.resolve(mkquery("kids-tablet.lan"))
    assert resp.answers[0].rdata.to_text() == "192.168.1.50"
    rev = n.resolve(mkquery(reverse_name("192.168.1.50"), Type.PTR))
    assert rev.answers[0].rdata.to_text() == "kids-tablet.lan."


def test_unknown_name_in_our_domain_is_nxdomain_not_a_forward():
    """Asking an upstream about `unknown.lan` fails and leaks the naming scheme."""
    n = names()
    resp = n.resolve(mkquery("unknown.lan"))
    assert resp.rcode == Rcode.NXDOMAIN
    assert n.resolve(mkquery("example.com")) is None       # not ours: carry on


def test_reverse_outside_the_scope_is_left_alone():
    n = names()
    assert n.resolve(mkquery(reverse_name("8.8.8.8"), Type.PTR)) is None


# --- wiring -----------------------------------------------------------------
class Fwd:
    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def test_pipeline_answers_learned_names_without_forwarding():
    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=Fwd(), counters=Counters(), config=Config())
    pipe.hostnames = names()
    pipe.hostnames.register("192.168.1.50", "kids-tablet")
    resp = asyncio.run(pipe.resolve(mkquery("kids-tablet.lan"), "192.168.1.2"))
    assert resp.answers[0].rdata.to_text() == "192.168.1.50"


def test_dhcp_ack_registers_the_lease_and_an_offer_does_not():
    scope = Scope("192.168.1.0/24", "192.168.1.100", "192.168.1.200",
                  router="192.168.1.1", domain="lan")
    seen: list[tuple[str, str]] = []

    def register(ip: str, hostname: str) -> None:
        seen.append((ip, hostname))

    def packet(kind: MessageType, requested: str = "") -> DhcpPacket:
        opts = {OPT_MSG_TYPE: bytes([kind]), OPT_HOSTNAME: b"laptop"}
        if requested:
            import ipaddress
            opts[OPT_REQUESTED_IP] = ipaddress.IPv4Address(requested).packed
        return DhcpPacket(op=1, xid=1, chaddr=b"\xaa\xbb\xcc\xdd\xee\xff",
                          options=opts)

    build_reply(packet(MessageType.DISCOVER), scope, "192.168.1.1",
                dns_register=register)
    assert seen == []                                   # an offer is not a lease
    build_reply(packet(MessageType.REQUEST), scope, "192.168.1.1",
                dns_register=register)
    assert seen and seen[0][1] == "laptop"


def test_registering_a_lease_drops_stale_replayed_answers(tmp_path):
    """`laptop.lan` asked before the lease existed was answered NXDOMAIN, and a
    recorded copy would keep being replayed for the whole negative TTL."""
    from trench.app import App
    from trench.engine.fastpath import FastPath

    app = App(Config.load_dict({"data_dir": str(tmp_path)}))
    app.fast = FastPath(app.pipeline)
    app.pipeline.fast = app.fast
    app.hostnames = names()

    app.on_lease("192.168.1.50", "kids-tablet")
    assert app.hostnames.ip_for("kids-tablet.lan") == "192.168.1.50"
    assert app.ledger is not None and "192.168.1.50" in app.ledger.devices

    # A registration that is declined — outside the scope network — leaves the
    # table alone; there is no new name to make room for.
    app.fast.table[b"key"] = object()
    app.on_lease("8.8.8.8", "outside-the-scope")
    assert app.fast.table
    # An accepted one drops the recorded answers, including any stale NXDOMAIN.
    app.on_lease("192.168.1.51", "printer")
    assert not app.fast.table


def test_reverse_name_and_its_inverse_agree():
    """The PTR path used to hand-roll the inverse next to this helper; they must
    not drift."""
    from trench.clients.names import address_from_reverse

    for ip in ("192.168.1.5", "10.0.0.1", "2001:db8::1", "2001:db8:1:2::ffff"):
        assert address_from_reverse(reverse_name(ip)) == ip
    assert address_from_reverse("example.com") is None
    assert address_from_reverse("1.2.in-addr.arpa") is None


# --- the reverse-name shapes ---
def test_an_ipv4_reverse_name_round_trips():
    from trench.clients.names import address_from_reverse
    assert address_from_reverse("1.1.168.192.in-addr.arpa") == "192.168.1.1"
    assert address_from_reverse(reverse_name("192.168.1.50")) == "192.168.1.50"


def test_an_ipv6_reverse_name_round_trips():
    from trench.clients.names import address_from_reverse
    rev = reverse_name("2001:db8::1")
    got = address_from_reverse(rev)
    import ipaddress
    assert ipaddress.ip_address(got) == ipaddress.ip_address("2001:db8::1")


@pytest.mark.parametrize("name", [
    "example.com",                       # not a reverse name at all
    "1.2.in-addr.arpa",                  # too few labels
    "999.1.168.192.in-addr.arpa",        # an octet no address has
    "zz.0.0.0.ip6.arpa",                 # not hex, and too short
    "",
])
def test_something_that_is_not_a_reverse_name_yields_nothing(name):
    from trench.clients.names import address_from_reverse
    assert address_from_reverse(name) is None


# --- resolve() edges ---
def test_a_query_with_no_question_is_not_ours():
    assert names().resolve(Message(id=1)) is None


def test_a_name_outside_our_domain_is_not_ours():
    hn = names()
    hn.register("192.168.1.50", "laptop")
    assert hn.resolve(mkquery("laptop.example.com")) is None


def test_an_any_query_is_answered_for_a_known_name():
    hn = names()
    hn.register("192.168.1.50", "laptop")
    resp = hn.resolve(mkquery("laptop.lan", Type.ANY))
    assert resp.rcode == Rcode.NOERROR
    assert resp.answers[0].rdata.address == "192.168.1.50"


def test_a_mismatched_type_at_a_known_name_is_nodata():
    """The name exists, so NXDOMAIN would be a lie."""
    hn = names()
    hn.register("192.168.1.50", "laptop")
    resp = hn.resolve(mkquery("laptop.lan", Type.AAAA))
    assert resp.rcode == Rcode.NOERROR and resp.answers == []


def test_a_type_we_do_not_serve_is_left_alone():
    hn = names()
    hn.register("192.168.1.50", "laptop")
    assert hn.resolve(mkquery("laptop.lan", Type.MX)) is None


def test_a_reverse_name_that_is_not_an_address_shape_is_left_alone():
    assert names().resolve(mkquery("nonsense.in-addr.arpa", Type.PTR)) is None


def test_a_reverse_query_for_an_unleased_address_in_scope_is_nxdomain():
    """`unknown.lan` has no answer anywhere on the internet, and asking an
    upstream about it publishes the household's naming scheme."""
    resp = names().resolve(mkquery(reverse_name("192.168.1.77"), Type.PTR))
    assert resp is not None and resp.rcode == Rcode.NXDOMAIN


def test_a_reverse_any_query_is_answered():
    hn = names()
    hn.register("192.168.1.50", "laptop")
    resp = hn.resolve(mkquery(reverse_name("192.168.1.50"), Type.ANY))
    assert resp.answers[0].rdata.name.to_text() == "laptop.lan."


def test_a_registration_of_a_name_that_sanitises_to_nothing_is_refused():
    hn = names()
    assert hn.register("192.168.1.50", "!!!") == ""
    assert hn.entries() == []


def test_a_registration_for_something_that_is_not_an_address_is_refused():
    assert names().register("not-an-address", "laptop") == ""


def test_without_a_scope_any_address_may_register():
    hn = HostNames(domain="lan")
    assert hn.register("203.0.113.9", "laptop") == "laptop.lan"


def test_forgetting_an_address_drops_both_directions():
    hn = names()
    hn.register("192.168.1.50", "laptop")
    hn.forget("192.168.1.50")
    assert hn.ip_for("laptop.lan") == ""
    assert hn.name_for("192.168.1.50") == ""


def test_forgetting_an_address_that_was_never_leased_is_harmless():
    names().forget("192.168.1.99")


def test_the_entries_list_reports_both_halves():
    hn = names()
    hn.register("192.168.1.50", "laptop")
    rows = hn.entries()
    assert len(rows) == 1
    assert rows[0]["ip"] == "192.168.1.50"
    assert rows[0]["name"] == "laptop.lan"
