"""Onboarding artifacts: Apple .mobileconfig (parse with plistlib) and DNS
stamps (decode back to fields per the dnscrypt.info spec)."""
from __future__ import annotations

import base64
import plistlib
import struct

import pytest

from trench.onboarding import apple_mobileconfig, doh_stamp, dot_stamp


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _read_lp(buf, i):
    n = buf[i]
    return buf[i + 1:i + 1 + n], i + 1 + n


# --- mobileconfig ---
def test_mobileconfig_doh_parses():
    xml = apple_mobileconfig(display_name="Trench Home", server_name="dns.home",
                             doh_url="https://dns.home/dns-query",
                             server_addresses=["192.0.2.1"])
    plist = plistlib.loads(xml.encode())
    assert plist["PayloadType"] == "Configuration"
    dns = plist["PayloadContent"][0]
    assert dns["PayloadType"] == "com.apple.dnsSettings.managed"
    assert dns["DNSSettings"]["DNSProtocol"] == "HTTPS"
    assert dns["DNSSettings"]["ServerURL"] == "https://dns.home/dns-query"
    assert dns["DNSSettings"]["ServerAddresses"] == ["192.0.2.1"]


def test_mobileconfig_dot_parses():
    xml = apple_mobileconfig(dot_host="dns.home", doh_url=None)
    dns = plistlib.loads(xml.encode())["PayloadContent"][0]["DNSSettings"]
    assert dns["DNSProtocol"] == "TLS" and dns["ServerName"] == "dns.home"


def test_mobileconfig_requires_a_transport():
    with pytest.raises(ValueError):
        apple_mobileconfig()


def test_mobileconfig_escapes_xml():
    xml = apple_mobileconfig(display_name="A & B <test>", doh_url="https://x/y?a=1&b=2")
    plist = plistlib.loads(xml.encode())  # must still parse
    assert plist["PayloadDisplayName"] == "A & B <test>"


# --- DNS stamps ---
def test_doh_stamp_roundtrip():
    stamp = doh_stamp("dns.example.com", "/dns-query")
    assert stamp.startswith("sdns://")
    raw = _b64url_decode(stamp[len("sdns://"):])
    assert raw[0] == 0x02                                  # DoH protocol id
    props = struct.unpack_from("<Q", raw, 1)[0]
    assert props & 0b11                                    # dnssec+nolog set
    i = 9
    addr, i = _read_lp(raw, i)
    hashfield, i = _read_lp(raw, i)
    host, i = _read_lp(raw, i)
    path, i = _read_lp(raw, i)
    assert host == b"dns.example.com" and path == b"/dns-query"


def test_dot_stamp_roundtrip():
    stamp = dot_stamp("dns.example.com", port=8530)
    raw = _b64url_decode(stamp[len("sdns://"):])
    assert raw[0] == 0x03                                  # DoT protocol id
    i = 9
    _, i = _read_lp(raw, i)   # addr
    _, i = _read_lp(raw, i)   # hashes
    host, i = _read_lp(raw, i)
    assert host == b"dns.example.com:8530"


def test_dot_stamp_default_port_omitted():
    raw = _b64url_decode(dot_stamp("dns.example.com")[len("sdns://"):])
    i = 9
    _, i = _read_lp(raw, i); _, i = _read_lp(raw, i)
    host, _ = _read_lp(raw, i)
    assert host == b"dns.example.com"  # no :853 suffix
