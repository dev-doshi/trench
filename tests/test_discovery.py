"""Encrypted-DNS discovery: the DDR answer, the DNR option, and the guard rails."""
from __future__ import annotations

import asyncio
import ipaddress
import struct

from dnsguard.cache import Cache
from dnsguard.config import Config
from dnsguard.dhcp.scope import Scope
from dnsguard.dhcp.server import build_reply
from dnsguard.dhcp.v4 import (
    OPT_DNR,
    OPT_HOSTNAME,
    OPT_MSG_TYPE,
    OPT_PARAM_LIST,
    DhcpPacket,
    MessageType,
)
from dnsguard.discovery import DDR_QNAME, Discovery, Endpoint, from_config
from dnsguard.engine import Pipeline
from dnsguard.filter import FilterEngine
from dnsguard.filter.svcparams import iter_params
from dnsguard.stats import Counters
from dnsguard.wire import Class, Message, Question, Type
from dnsguard.wire.name import Name
from dnsguard.wire.rrtypes import Rcode

ALPN, PORT, DOHPATH = 1, 3, 7


def cfg(**server) -> Config:
    base = {"discovery": {"enabled": True, "hostname": "dns.example.com",
                          "addresses": ["192.168.1.2"]}}
    base.update(server)
    return Config.load_dict({"server": base})


def query(name: str, rtype=Type.SVCB) -> Message:
    m = Message(id=4)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), rtype, Class.IN))
    return m


# --- DDR ---
def test_svcb_answer_carries_one_record_per_encrypted_endpoint():
    disc = from_config(cfg(dot={"enabled": True, "port": 853},
                           doh={"enabled": True, "port": 8443, "path": "/dns-query"}))
    resp = disc.answers(query(DDR_QNAME))
    assert [rr.rdata.priority for rr in resp.answers] == [1, 2]
    assert all(rr.rdata.target.to_text() == "dns.example.com." for rr in resp.answers)

    dot = dict(iter_params(resp.answers[0].rdata.params))
    assert dot[ALPN] == b"\x03dot"
    assert PORT not in dot                        # 853 is the default for DoT

    doh = dict(iter_params(resp.answers[1].rdata.params))
    assert doh[ALPN] == b"\x02h2"
    assert doh[PORT] == struct.pack("!H", 8443)   # non-default, so it is sent
    assert doh[DOHPATH] == b"/dns-query{?dns}"    # a template, not a bare path


def test_other_types_under_the_name_are_nodata_not_nxdomain():
    disc = from_config(cfg(dot={"enabled": True}))
    resp = disc.answers(query(DDR_QNAME, Type.A))
    assert resp.rcode == Rcode.NOERROR and resp.answers == []


def test_other_names_are_not_ours():
    disc = from_config(cfg(dot={"enabled": True}))
    assert disc.answers(query("example.com")) is None


def test_without_a_hostname_nothing_is_published():
    """Clients authenticate the designation against that name; a record without
    one is ignored, so publishing it would only look configured."""
    disc = Discovery("", [Endpoint("dot", 853, 1)])
    assert not disc.usable
    assert disc.answers(query(DDR_QNAME)) is None
    assert disc.dhcp_option() == b""
    assert "hostname is empty" in disc.problems()[0]


def test_without_an_encrypted_listener_there_is_nothing_to_advertise():
    disc = Discovery("dns.example.com", [])
    assert not disc.usable
    assert "no encrypted listener" in disc.problems()[0]


def test_pipeline_answers_the_discovery_query():
    class Fwd:
        async def resolve(self, q, note=None):
            raise AssertionError("_dns.resolver.arpa must never be forwarded")

    pipe = Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(enabled=False),
                    forwarder=Fwd(), counters=Counters(), config=Config())
    pipe.discovery = from_config(cfg(dot={"enabled": True}))
    resp = asyncio.run(pipe.resolve(query(DDR_QNAME), "10.0.0.1"))
    assert resp.answers and resp.answers[0].rtype == Type.SVCB


# --- DNR ---
def decode_dnr(option: bytes) -> list[dict]:
    """Decode the option the way a client would, per RFC 9463 §3.1."""
    out, pos = [], 0
    while pos < len(option):
        (length,) = struct.unpack_from("!H", option, pos)
        pos += 2
        end = pos + length
        (priority,) = struct.unpack_from("!H", option, pos)
        pos += 2
        adn_len = option[pos]
        pos += 1
        adn = option[pos:pos + adn_len]
        pos += adn_len
        addr_len = option[pos]
        pos += 1
        addrs = [str(ipaddress.IPv4Address(option[pos + i:pos + i + 4]))
                 for i in range(0, addr_len, 4)]
        pos += addr_len
        out.append({"priority": priority, "adn": adn, "addresses": addrs,
                    "params": dict(iter_params(option[pos:end]))})
        pos = end
    return out


def test_dnr_option_round_trips():
    disc = from_config(cfg(dot={"enabled": True}, doq={"enabled": True, "port": 8854}))
    (dot, doq) = decode_dnr(disc.dhcp_option())
    assert dot["adn"] == b"\x03dns\x07example\x03com\x00"     # wire form, not text
    assert dot["addresses"] == ["192.168.1.2"]
    assert dot["params"][ALPN] == b"\x03dot"
    assert doq["params"][ALPN] == b"\x03doq"
    assert doq["params"][PORT] == struct.pack("!H", 8854)
    # ipv4hint/ipv6hint are forbidden here: the addresses field supersedes them
    assert 4 not in dot["params"] and 6 not in dot["params"]


def packet(kind: MessageType, *, request_dnr: bool) -> DhcpPacket:
    opts = {OPT_MSG_TYPE: bytes([kind]), OPT_HOSTNAME: b"laptop"}
    if request_dnr:
        opts[OPT_PARAM_LIST] = bytes([1, 3, 6, OPT_DNR])
    return DhcpPacket(op=1, xid=1, chaddr=b"\xaa\xbb\xcc\xdd\xee\xff", options=opts)


def test_the_option_is_sent_only_when_the_client_asks_for_it():
    scope = Scope("192.168.1.0/24", "192.168.1.100", "192.168.1.200",
                  router="192.168.1.1")
    disc = from_config(cfg(dot={"enabled": True}))
    option = disc.dhcp_option()

    asked = build_reply(packet(MessageType.REQUEST, request_dnr=True), scope,
                        "192.168.1.1", dnr_option=option)
    assert asked.options[OPT_DNR] == option

    quiet = build_reply(packet(MessageType.REQUEST, request_dnr=False), scope,
                        "192.168.1.1", dnr_option=option)
    assert OPT_DNR not in quiet.options


def test_discovery_is_off_unless_configured():
    assert from_config(Config()) is None
