"""DHCPv4 server. Refuses to bind unless explicitly authorized.

The request handler (`build_reply`) is a pure function so it can be tested
without ever touching the network.
"""
from __future__ import annotations

import asyncio
import socket

from ..errors import DNSGuardError
from ..log import get
from .scope import Scope
from .v4 import (
    OPT_DNS,
    OPT_LEASE_TIME,
    OPT_MSG_TYPE,
    OPT_REBIND,
    OPT_RENEWAL,
    OPT_ROUTER,
    OPT_SERVER_ID,
    OPT_SUBNET,
    DhcpPacket,
    MessageType,
    opt_ip,
    opt_ips,
    opt_u32,
)

log = get("dhcp")


def _subnet_mask(network: str) -> str:
    import ipaddress
    return str(ipaddress.ip_network(network, strict=False).netmask)


def build_reply(req: DhcpPacket, scope: Scope, server_ip: str,
                now: float | None = None) -> DhcpPacket | None:
    mt = req.msg_type
    if mt == MessageType.DISCOVER:
        lease = scope.allocate(req.mac, req.hostname(), now=now)
        if lease is None:
            return None
        return _reply(req, scope, server_ip, lease.ip, MessageType.OFFER)
    if mt == MessageType.REQUEST:
        # A REQUEST naming a different server is that server's to answer.
        # Replying anyway hands the client an ACK for an address out of our
        # pool, so two servers ACK the same client and the addresses collide.
        chosen = req.server_id()
        if chosen and chosen != server_ip:
            return None
        lease = scope.allocate(req.mac, req.hostname(), requested=req.requested_ip(), now=now)
        if lease is None or (req.requested_ip() and req.requested_ip() != lease.ip):
            return _nak(req, server_ip)
        return _reply(req, scope, server_ip, lease.ip, MessageType.ACK)
    if mt == MessageType.RELEASE:
        # Only the holder of the address may release it: ciaddr carries the
        # address the client claims to be giving up, and it has to be the one
        # we actually granted to this chaddr.
        scope.release(req.mac, req.ciaddr)
        return None
    return None


def _reply(req: DhcpPacket, scope: Scope, server_ip: str, yiaddr: str,
           mtype: MessageType) -> DhcpPacket:
    opts = {
        OPT_MSG_TYPE: bytes([mtype]),
        OPT_SERVER_ID: opt_ip(server_ip),
        OPT_LEASE_TIME: opt_u32(scope.lease_time),
        OPT_RENEWAL: opt_u32(scope.lease_time // 2),
        OPT_REBIND: opt_u32(scope.lease_time * 7 // 8),
        OPT_SUBNET: opt_ip(_subnet_mask(scope.network)),
    }
    if scope.router:
        opts[OPT_ROUTER] = opt_ip(scope.router)
    if scope.dns:
        opts[OPT_DNS] = opt_ips(scope.dns)
    return DhcpPacket(op=2, htype=req.htype, hlen=req.hlen, xid=req.xid,
                      flags=req.flags, yiaddr=yiaddr, siaddr=server_ip,
                      giaddr=req.giaddr, chaddr=req.chaddr, options=opts)


def _nak(req: DhcpPacket, server_ip: str) -> DhcpPacket:
    return DhcpPacket(op=2, htype=req.htype, hlen=req.hlen, xid=req.xid,
                      flags=req.flags, chaddr=req.chaddr,
                      options={OPT_MSG_TYPE: bytes([MessageType.NAK]),
                               OPT_SERVER_ID: opt_ip(server_ip)})


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, server: DhcpServer):
        self.server = server

    def datagram_received(self, data, addr):
        try:
            req = DhcpPacket.parse(data)
        except Exception:
            return
        if req.op != 1:      # BOOTREQUEST; a reply on this port is not ours to act on
            return
        reply = build_reply(req, self.server.scope, self.server.server_ip)
        if reply is not None and self.server.transport is not None:
            # broadcast the reply (clients have no IP yet)
            self.server.transport.sendto(reply.to_wire(), ("255.255.255.255", 68))
            log.info("DHCP %s -> %s for %s", MessageType(req.msg_type).name,
                     reply.yiaddr, req.mac)


class DhcpServer:
    def __init__(self, scope: Scope, server_ip: str, *, dns_register=None):
        self.scope = scope
        self.server_ip = server_ip
        self.dns_register = dns_register
        self.transport = None

    async def start(self, *, enabled: bool, allow_dhcp: bool, dev: bool) -> None:
        # triple safety gate — never hand out leases on a LAN by accident
        if not enabled:
            log.info("DHCP disabled")
            return
        if dev:
            raise DNSGuardError("refusing to start DHCP in --dev mode")
        if not allow_dhcp:
            raise DNSGuardError("DHCP enabled in config but --allow-dhcp not passed; refusing")
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", 67))
        self.transport, _ = await loop.create_datagram_endpoint(lambda: _Proto(self), sock=sock)
        log.warning("DHCP server ACTIVE on :67 (scope %s)", self.scope.network)

    async def stop(self) -> None:
        if self.transport is not None:
            self.transport.close()
