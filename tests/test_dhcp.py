"""DHCPv4 codec, scope allocation, reply building, and the safety guard."""
from __future__ import annotations

import asyncio

import pytest

from dnsguard.dhcp.scope import Scope
from dnsguard.dhcp.server import DhcpServer, build_reply
from dnsguard.dhcp.v4 import OPT_MSG_TYPE, OPT_REQUESTED_IP, DhcpPacket, MessageType, opt_ip
from dnsguard.errors import DNSGuardError

MAC = bytes.fromhex("aabbccddeeff")


def discover(xid=1):
    return DhcpPacket(op=1, chaddr=MAC, xid=xid, options={OPT_MSG_TYPE: bytes([MessageType.DISCOVER])})


def test_packet_roundtrip():
    p = discover(0x1234)
    p.options[12] = b"laptop"  # hostname
    back = DhcpPacket.parse(p.to_wire())
    assert back.xid == 0x1234
    assert back.mac == "aa:bb:cc:dd:ee:ff"
    assert back.msg_type == MessageType.DISCOVER
    assert back.hostname() == "laptop"


def test_scope_allocation():
    s = Scope("192.168.1.0/24", "192.168.1.100", "192.168.1.110", router="192.168.1.1",
              dns=["192.168.1.1"])
    a = s.allocate("aa:bb:cc:00:00:01")
    b = s.allocate("aa:bb:cc:00:00:02")
    assert a.ip == "192.168.1.100" and b.ip == "192.168.1.101"
    # same mac -> same lease
    assert s.allocate("aa:bb:cc:00:00:01").ip == "192.168.1.100"
    # reservation honored
    s.reservations["aa:bb:cc:00:00:09"] = "192.168.1.105"
    assert s.allocate("aa:bb:cc:00:00:09").ip == "192.168.1.105"


def test_scope_exhaustion():
    s = Scope("10.0.0.0/24", "10.0.0.5", "10.0.0.6")
    assert s.allocate("a").ip == "10.0.0.5"
    assert s.allocate("b").ip == "10.0.0.6"
    assert s.allocate("c") is None  # pool of 2 exhausted


def test_build_reply_offer_and_ack():
    s = Scope("192.168.1.0/24", "192.168.1.100", "192.168.1.110",
              router="192.168.1.1", dns=["192.168.1.1", "9.9.9.9"])
    offer = build_reply(discover(), s, "192.168.1.1")
    assert offer.msg_type == MessageType.OFFER
    assert offer.yiaddr == "192.168.1.100"
    # client requests the offered IP
    req = DhcpPacket(op=1, chaddr=MAC, xid=1, options={
        OPT_MSG_TYPE: bytes([MessageType.REQUEST]),
        OPT_REQUESTED_IP: opt_ip("192.168.1.100")})
    ack = build_reply(req, s, "192.168.1.1")
    assert ack.msg_type == MessageType.ACK and ack.yiaddr == "192.168.1.100"


def test_build_reply_nak_on_wrong_request():
    s = Scope("192.168.1.0/24", "192.168.1.100", "192.168.1.110")
    req = DhcpPacket(op=1, chaddr=MAC, xid=1, options={
        OPT_MSG_TYPE: bytes([MessageType.REQUEST]),
        OPT_REQUESTED_IP: opt_ip("10.9.9.9")})  # outside scope
    nak = build_reply(req, s, "192.168.1.1")
    assert nak.msg_type == MessageType.NAK


def test_guard_refuses_without_optin():
    s = Scope("192.168.1.0/24", "192.168.1.100", "192.168.1.110")
    srv = DhcpServer(s, "192.168.1.1")
    # disabled -> no-op, no bind
    asyncio.run(srv.start(enabled=False, allow_dhcp=True, dev=False))
    assert srv.transport is None
    # dev mode -> refuse
    with pytest.raises(DNSGuardError):
        asyncio.run(srv.start(enabled=True, allow_dhcp=True, dev=True))
    # enabled but no --allow-dhcp -> refuse
    with pytest.raises(DNSGuardError):
        asyncio.run(srv.start(enabled=True, allow_dhcp=False, dev=False))
