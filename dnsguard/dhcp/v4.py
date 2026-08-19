"""DHCPv4 packet codec (RFC 2131/2132)."""
from __future__ import annotations

import enum
import socket
import struct
from dataclasses import dataclass, field

MAGIC_COOKIE = b"\x63\x82\x53\x63"

# common option codes
OPT_SUBNET = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_PARAM_LIST = 55
OPT_RENEWAL = 58
OPT_REBIND = 59
OPT_CLIENT_ID = 61
OPT_END = 255


class MessageType(enum.IntEnum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8


@dataclass
class DhcpPacket:
    op: int = 1                 # 1=request, 2=reply
    htype: int = 1             # ethernet
    hlen: int = 6
    hops: int = 0
    xid: int = 0
    secs: int = 0
    flags: int = 0
    ciaddr: str = "0.0.0.0"
    yiaddr: str = "0.0.0.0"
    siaddr: str = "0.0.0.0"
    giaddr: str = "0.0.0.0"
    chaddr: bytes = b"\x00" * 6
    options: dict[int, bytes] = field(default_factory=dict)

    # --- convenience ---
    @property
    def mac(self) -> str:
        return ":".join(f"{b:02x}" for b in self.chaddr[:self.hlen])

    @property
    def msg_type(self) -> int | None:
        v = self.options.get(OPT_MSG_TYPE)
        return v[0] if v else None

    def requested_ip(self) -> str | None:
        v = self.options.get(OPT_REQUESTED_IP)
        return socket.inet_ntoa(v) if v and len(v) == 4 else None

    def hostname(self) -> str:
        v = self.options.get(OPT_HOSTNAME)
        return v.decode("latin-1") if v else ""

    # --- codec ---
    @classmethod
    def parse(cls, data: bytes) -> DhcpPacket:
        if len(data) < 240:
            raise ValueError("short DHCP packet")
        (op, htype, hlen, hops, xid, secs, flags) = struct.unpack(">BBBBIHH", data[:12])
        ciaddr, yiaddr, siaddr, giaddr = (socket.inet_ntoa(data[i:i + 4])
                                          for i in (12, 16, 20, 24))
        chaddr = data[28:28 + 16]
        if data[236:240] != MAGIC_COOKIE:
            raise ValueError("bad magic cookie")
        options = _parse_options(data[240:])
        return cls(op, htype, hlen, hops, xid, secs, flags,
                   ciaddr, yiaddr, siaddr, giaddr, chaddr[:hlen] + chaddr[hlen:], options)

    def to_wire(self) -> bytes:
        out = bytearray()
        out += struct.pack(">BBBBIHH", self.op, self.htype, self.hlen, self.hops,
                           self.xid, self.secs, self.flags)
        for ip in (self.ciaddr, self.yiaddr, self.siaddr, self.giaddr):
            out += socket.inet_aton(ip)
        chaddr = (self.chaddr + b"\x00" * 16)[:16]
        out += chaddr
        out += b"\x00" * 64    # sname
        out += b"\x00" * 128   # file
        out += MAGIC_COOKIE
        for code, val in self.options.items():
            out += bytes([code, len(val)]) + val
        out += bytes([OPT_END])
        # pad to BOOTP minimum
        if len(out) < 300:
            out += b"\x00" * (300 - len(out))
        return bytes(out)


def _parse_options(data: bytes) -> dict[int, bytes]:
    opts: dict[int, bytes] = {}
    i = 0
    while i < len(data):
        code = data[i]
        if code == OPT_END:
            break
        if code == 0:  # pad
            i += 1
            continue
        length = data[i + 1]
        opts[code] = data[i + 2:i + 2 + length]
        i += 2 + length
    return opts


def opt_ip(ip: str) -> bytes:
    return socket.inet_aton(ip)


def opt_ips(ips: list[str]) -> bytes:
    return b"".join(socket.inet_aton(i) for i in ips)


def opt_u32(v: int) -> bytes:
    return struct.pack(">I", v)
