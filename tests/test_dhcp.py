"""DHCPv4 codec, scope allocation, reply building, and the safety guard."""
from __future__ import annotations

import asyncio

import pytest

from trench.dhcp.scope import Scope
from trench.dhcp.server import DhcpServer, build_reply
from trench.dhcp.v4 import (
    MAGIC_COOKIE,
    OPT_MSG_TYPE,
    OPT_REQUESTED_IP,
    DhcpPacket,
    MessageType,
    opt_ip,
)
from trench.errors import TrenchError

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
    with pytest.raises(TrenchError):
        asyncio.run(srv.start(enabled=True, allow_dhcp=True, dev=True))
    # enabled but no --allow-dhcp -> refuse
    with pytest.raises(TrenchError):
        asyncio.run(srv.start(enabled=True, allow_dhcp=False, dev=False))


def test_release_requires_the_holder_to_name_its_own_address():
    """RELEASE is unauthenticated and carries whatever chaddr the sender picked.
    Honouring it on that alone let any host on the LAN delete a neighbour's
    lease while the neighbour was still using the address, then take it."""
    scope = Scope(network="192.168.1.0/24", range_start="192.168.1.100",
                  range_end="192.168.1.200")
    victim = scope.allocate("aa:bb:cc:dd:ee:ff")
    assert victim is not None

    scope.release("aa:bb:cc:dd:ee:ff", "192.168.1.250")   # not the held address
    assert [lease.ip for lease in scope.active_leases()] == [victim.ip]

    scope.release("aa:bb:cc:dd:ee:ff", victim.ip)          # the real holder
    assert scope.active_leases() == []


def test_expired_leases_do_not_accumulate_without_bound():
    scope = Scope(network="192.168.1.0/24", range_start="192.168.1.100",
                  range_end="192.168.1.200", lease_time=1, max_leases=16)
    for i in range(200):
        scope.allocate(f"02:00:00:00:{i // 256:02x}:{i % 256:02x}", now=1000.0)
    scope.allocate("02:00:00:00:ff:ff", now=2000.0)        # everything above expired
    assert len(scope._leases) <= scope.max_leases + 1


# --- the rest of the reply machine ---
def _scope():
    return Scope("192.168.9.0/24", "192.168.9.100", "192.168.9.110",
                 router="192.168.9.1", dns=["192.168.9.1"], domain="lan")


def _pkt(mtype, **over):
    opts = {OPT_MSG_TYPE: bytes([mtype])}
    opts.update(over.pop("options", {}))
    return DhcpPacket(op=1, chaddr=MAC, xid=7, options=opts, **over)


def test_a_discover_with_no_free_address_is_not_answered():
    scope = Scope("192.168.9.0/24", "192.168.9.100", "192.168.9.100")
    scope.allocate(bytes.fromhex("000000000001"), "other")
    assert build_reply(_pkt(MessageType.DISCOVER), scope, "192.168.9.1") is None


def test_a_request_naming_another_server_is_left_to_that_server():
    """Replying anyway hands the client an ACK for an address out of our pool,
    so two servers ACK the same client and the addresses collide."""
    from trench.dhcp.v4 import OPT_SERVER_ID
    req = _pkt(MessageType.REQUEST,
               options={OPT_SERVER_ID: opt_ip("192.168.9.99")})
    assert build_reply(req, _scope(), "192.168.9.1") is None


def test_a_request_naming_this_server_is_answered():
    from trench.dhcp.v4 import OPT_SERVER_ID
    req = _pkt(MessageType.REQUEST,
               options={OPT_SERVER_ID: opt_ip("192.168.9.1")})
    reply = build_reply(req, _scope(), "192.168.9.1")
    assert reply is not None and reply.msg_type == MessageType.ACK


def test_an_ack_registers_the_lease_in_dns_and_an_offer_does_not():
    """An OFFER is not a lease; registering one puts a name in DNS for an
    address the client may never take."""
    registered = []
    scope = _scope()
    req = _pkt(MessageType.DISCOVER, options={12: b"laptop"})
    build_reply(req, scope, "192.168.9.1", dns_register=lambda ip, h: registered.append((ip, h)))
    assert registered == []

    ack = _pkt(MessageType.REQUEST, options={12: b"laptop"})
    build_reply(ack, scope, "192.168.9.1",
                dns_register=lambda ip, h: registered.append((ip, h)))
    assert registered and registered[0][1] == "laptop"


def test_a_dns_registration_failure_does_not_break_the_lease(caplog):
    def boom(ip, hostname):
        raise RuntimeError("zone is read-only")

    req = _pkt(MessageType.REQUEST, options={12: b"laptop"})
    reply = build_reply(req, _scope(), "192.168.9.1", dns_register=boom)
    assert reply is not None and reply.msg_type == MessageType.ACK
    assert any("could not register" in r.getMessage() for r in caplog.records)


def test_a_lease_without_a_hostname_registers_nothing():
    registered = []
    build_reply(_pkt(MessageType.REQUEST), _scope(), "192.168.9.1",
                dns_register=lambda ip, h: registered.append(ip))
    assert registered == []


def test_an_unknown_message_type_is_ignored():
    assert build_reply(_pkt(MessageType.INFORM), _scope(), "192.168.9.1") is None


def test_a_reply_carries_the_scope_options():
    from trench.dhcp.v4 import (
        OPT_DNS,
        OPT_LEASE_TIME,
        OPT_REBIND,
        OPT_RENEWAL,
        OPT_ROUTER,
        OPT_SUBNET,
    )
    reply = build_reply(_pkt(MessageType.DISCOVER), _scope(), "192.168.9.1")
    assert reply.options[OPT_ROUTER] == opt_ip("192.168.9.1")
    assert reply.options[OPT_DNS] == opt_ip("192.168.9.1")
    assert reply.options[OPT_SUBNET] == opt_ip("255.255.255.0")
    lease = int.from_bytes(reply.options[OPT_LEASE_TIME], "big")
    assert int.from_bytes(reply.options[OPT_RENEWAL], "big") == lease // 2
    assert int.from_bytes(reply.options[OPT_REBIND], "big") == lease * 7 // 8


def test_a_scope_without_a_router_or_dns_omits_those_options():
    from trench.dhcp.v4 import OPT_DNS, OPT_ROUTER
    scope = Scope("192.168.9.0/24", "192.168.9.100", "192.168.9.110")
    reply = build_reply(_pkt(MessageType.DISCOVER), scope, "192.168.9.1")
    assert OPT_ROUTER not in reply.options and OPT_DNS not in reply.options


def test_the_encrypted_endpoint_option_is_only_sent_when_asked_for():
    """An unsolicited option is wasted space in a packet with a small budget,
    and some clients are unhappy about options they did not request."""
    from trench.dhcp.v4 import OPT_DNR, OPT_PARAM_LIST
    plain = build_reply(_pkt(MessageType.DISCOVER), _scope(), "192.168.9.1",
                        dnr_option=b"\x01\x02")
    assert OPT_DNR not in plain.options

    asked = _pkt(MessageType.DISCOVER,
                 options={OPT_PARAM_LIST: bytes([OPT_DNR])})
    reply = build_reply(asked, _scope(), "192.168.9.1", dnr_option=b"\x01\x02")
    assert reply.options[OPT_DNR] == b"\x01\x02"


def test_a_nak_names_this_server_and_offers_no_address():
    req = _pkt(MessageType.REQUEST,
               options={OPT_REQUESTED_IP: opt_ip("10.9.9.9")})
    reply = build_reply(req, _scope(), "192.168.9.1")
    assert reply.msg_type == MessageType.NAK
    assert reply.yiaddr in ("0.0.0.0", "")


# --- the datagram protocol ---
class _FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def close(self):
        self.sent.append(("closed", None))


def _server_with_transport():
    srv = DhcpServer(_scope(), "192.168.9.1")
    srv.transport = _FakeTransport()
    return srv


def test_a_discover_is_answered_by_broadcast():
    from trench.dhcp.server import _Proto
    srv = _server_with_transport()
    _Proto(srv).datagram_received(discover().to_wire(), ("0.0.0.0", 68))
    data, addr = srv.transport.sent[0]
    assert addr == ("255.255.255.255", 68)
    reply = DhcpPacket.parse(data)
    assert reply.msg_type == MessageType.OFFER
    assert reply.yiaddr.startswith("192.168.9.")


def test_an_unparseable_datagram_is_dropped():
    from trench.dhcp.server import _Proto
    srv = _server_with_transport()
    _Proto(srv).datagram_received(b"\x00", ("0.0.0.0", 68))
    assert srv.transport.sent == []


def test_a_bootreply_on_this_port_is_not_ours_to_act_on():
    from trench.dhcp.server import _Proto
    srv = _server_with_transport()
    pkt = discover()
    pkt.op = 2
    _Proto(srv).datagram_received(pkt.to_wire(), ("0.0.0.0", 68))
    assert srv.transport.sent == []


def test_nothing_is_sent_when_there_is_no_reply_to_make():
    from trench.dhcp.server import _Proto
    srv = DhcpServer(Scope("192.168.9.0/24", "192.168.9.100", "192.168.9.100"),
                     "192.168.9.1")
    srv.transport = _FakeTransport()
    srv.scope.allocate(bytes.fromhex("000000000001"), "other")
    _Proto(srv).datagram_received(discover().to_wire(), ("0.0.0.0", 68))
    assert srv.transport.sent == []


@pytest.mark.asyncio
async def test_a_disabled_server_binds_nothing(caplog):
    srv = DhcpServer(_scope(), "192.168.9.1")
    await srv.start(enabled=False, allow_dhcp=True, dev=False)
    assert srv.transport is None
    await srv.stop()             # idempotent with nothing bound


@pytest.mark.asyncio
async def test_stopping_closes_the_transport():
    srv = _server_with_transport()
    await srv.stop()
    assert ("closed", None) in srv.transport.sent


def test_an_option_code_with_no_length_octet_is_a_value_error():
    """`parse` promises ValueError for a packet it cannot read. This one raised
    IndexError, which only looked the same because the datagram handler catches
    everything — any other caller would have crashed on a LAN packet."""
    with pytest.raises(ValueError):
        DhcpPacket.parse(bytes(236) + MAGIC_COOKIE + b"\x35")


def test_an_option_longer_than_the_packet_is_refused():
    """It used to be stored short: an option claiming 12 octets with 3 left
    became a 3-octet value, and a truncated hostname went into DNS as if the
    client had sent it."""
    with pytest.raises(ValueError):
        DhcpPacket.parse(bytes(236) + MAGIC_COOKIE + b"\x0c\x0cabc")


def test_a_well_formed_option_list_still_parses():
    pkt = DhcpPacket.parse(bytes(236) + MAGIC_COOKIE
                           + b"\x35\x01\x01" + b"\x0c\x03abc" + b"\xff")
    assert pkt.msg_type == 1
    assert pkt.hostname() == "abc"
