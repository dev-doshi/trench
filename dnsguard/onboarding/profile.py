"""Encrypted-DNS onboarding artifacts.

- Apple `.mobileconfig` (a signed-or-plain configuration profile) that installs
  a system-wide DoH or DoT resolver on iOS/iPadOS/macOS.
- DNS stamps (`sdns://…`, dnscrypt.info spec) that dnscrypt-proxy / AdGuard /
  many mobile clients import from a single string or QR code.

No third-party dependencies — the plist is emitted directly and the stamp is
assembled from the documented binary layout.
"""
from __future__ import annotations

import base64
import struct
import uuid
from xml.sax.saxutils import escape

# DNS stamp property bits (dnscrypt.info)
STAMP_DNSSEC = 1 << 0
STAMP_NO_LOG = 1 << 1
STAMP_NO_FILTER = 1 << 2


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _lp(data: bytes) -> bytes:
    """Length-prefixed (single-byte length) field used throughout stamps."""
    if len(data) > 255:
        raise ValueError("stamp field too long")
    return bytes([len(data)]) + data


def doh_stamp(host: str, path: str = "/dns-query", *, addr: str = "",
              hashes: list[bytes] | None = None,
              props: int = STAMP_DNSSEC | STAMP_NO_LOG) -> str:
    """DNS-over-HTTPS stamp (protocol 0x02)."""
    out = bytearray([0x02])
    out += struct.pack("<Q", props)
    out += _lp(addr.encode())                       # server address (may be empty => use hostname)
    # VLP set of cert hashes: each length-prefixed; high bit of length chains more
    hs = hashes or []
    if not hs:
        out += _lp(b"")
    else:
        for i, h in enumerate(hs):
            length = len(h) | (0x80 if i + 1 < len(hs) else 0)
            out += bytes([length]) + h
    out += _lp(host.encode())                        # hostname [:port]
    out += _lp(path.encode())
    return "sdns://" + _b64url(bytes(out))


def dot_stamp(host: str, *, addr: str = "", port: int = 853,
              hashes: list[bytes] | None = None,
              props: int = STAMP_DNSSEC | STAMP_NO_LOG) -> str:
    """DNS-over-TLS stamp (protocol 0x03)."""
    out = bytearray([0x03])
    out += struct.pack("<Q", props)
    out += _lp(addr.encode())
    hs = hashes or []
    if not hs:
        out += _lp(b"")
    else:
        for i, h in enumerate(hs):
            length = len(h) | (0x80 if i + 1 < len(hs) else 0)
            out += bytes([length]) + h
    hostport = host if port == 853 else f"{host}:{port}"
    out += _lp(hostport.encode())
    return "sdns://" + _b64url(bytes(out))


def _uuid() -> str:
    return str(uuid.uuid4()).upper()


def apple_mobileconfig(*, display_name: str = "DNSGuard",
                       server_name: str = "dns.example.com",
                       doh_url: str | None = None,
                       dot_host: str | None = None,
                       server_addresses: list[str] | None = None,
                       identifier: str = "guard.dnsguard",
                       on_demand: bool = True) -> str:
    """Build an Apple configuration profile installing an encrypted resolver.

    Provide `doh_url` (https://host/dns-query) for DoH, or `dot_host` for DoT.
    `server_addresses` optionally pins the resolver IPs (bootstrap)."""
    if not doh_url and not dot_host:
        raise ValueError("one of doh_url or dot_host is required")
    proto = "HTTPS" if doh_url else "TLS"
    payload_uuid, top_uuid = _uuid(), _uuid()

    settings = [f"<key>DNSProtocol</key><string>{proto}</string>"]
    if doh_url:
        settings.append(f"<key>ServerURL</key><string>{escape(doh_url)}</string>")
    if dot_host:
        settings.append(f"<key>ServerName</key><string>{escape(dot_host)}</string>")
    if server_addresses:
        addrs = "".join(f"<string>{escape(a)}</string>" for a in server_addresses)
        settings.append(f"<key>ServerAddresses</key><array>{addrs}</array>")
    dns_settings = "".join(settings)

    on_demand_xml = ("<key>OnDemandRules</key><array><dict>"
                     "<key>Action</key><string>Connect</string></dict></array>"
                     if on_demand else "")

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadDisplayName</key><string>{escape(display_name)}</string>
  <key>PayloadIdentifier</key><string>{identifier}</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{top_uuid}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
      <key>PayloadIdentifier</key><string>{identifier}.dns</string>
      <key>PayloadUUID</key><string>{payload_uuid}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>{escape(server_name)}</string>
      <key>DNSSettings</key>
      <dict>{dns_settings}</dict>
      {on_demand_xml}
    </dict>
  </array>
</dict>
</plist>
"""
