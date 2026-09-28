"""DNS stamps, Apple configuration profiles, and the address matcher.

A stamp and a .mobileconfig are what an operator hands to a device, so a wrong
byte in either is a device that silently keeps using its old resolver. The
address matcher is on the answer path, where a wrong longest-prefix decision
either blocks something it should not or lets a listed network through.
"""
from __future__ import annotations

import base64
import struct

import pytest

from trench.filter.ipmatch import IPMatcher, answer_addresses, rpz_ip_prefix
from trench.filter.rpz import iter_rpz_ips
from trench.onboarding.profile import (
    STAMP_DNSSEC,
    STAMP_NO_FILTER,
    STAMP_NO_LOG,
    _lp,
    apple_mobileconfig,
    doh_stamp,
    dot_stamp,
)
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.name import Name


def _decode(stamp):
    assert stamp.startswith("sdns://")
    body = stamp[len("sdns://"):]
    return base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))


# --- stamp framing ---
def test_a_length_prefixed_field_carries_its_own_length():
    assert _lp(b"abc") == b"\x03abc"
    assert _lp(b"") == b"\x00"


def test_a_field_too_long_to_frame_is_refused():
    with pytest.raises(ValueError, match="too long"):
        _lp(b"x" * 256)


def test_a_doh_stamp_names_its_protocol_host_and_path():
    raw = _decode(doh_stamp("dns.example.org", "/dns-query"))
    assert raw[0] == 0x02
    assert b"dns.example.org" in raw and b"/dns-query" in raw


def test_a_dot_stamp_names_its_protocol_and_host():
    raw = _decode(dot_stamp("dns.example.org"))
    assert raw[0] == 0x03
    assert b"dns.example.org" in raw


def test_the_default_port_is_left_out_of_a_dot_stamp():
    assert b"dns.example.org:853" not in _decode(dot_stamp("dns.example.org"))
    assert b"dns.example.org:8853" in _decode(dot_stamp("dns.example.org", port=8853))


def test_the_properties_word_is_little_endian():
    props = STAMP_DNSSEC | STAMP_NO_LOG | STAMP_NO_FILTER
    raw = _decode(doh_stamp("dns.example.org", props=props))
    assert struct.unpack_from("<Q", raw, 1)[0] == props


def test_a_pinned_address_is_carried_in_the_stamp():
    raw = _decode(doh_stamp("dns.example.org", addr="192.0.2.1"))
    assert b"192.0.2.1" in raw
    assert b"192.0.2.1" not in _decode(doh_stamp("dns.example.org"))


@pytest.mark.parametrize("build", [doh_stamp, dot_stamp])
def test_certificate_hashes_are_chained_by_the_high_bit(build):
    """The VLP set marks "one more follows" in the top bit of each length."""
    one = _decode(build("dns.example.org", hashes=[b"\xaa" * 32]))
    assert one.count(b"\xaa" * 32) == 1

    two = _decode(build("dns.example.org", hashes=[b"\xaa" * 32, b"\xbb" * 32]))
    assert two.count(b"\xaa" * 32) == 1 and two.count(b"\xbb" * 32) == 1
    # The first length has the continuation bit set; the last does not.
    first = two.index(b"\xaa" * 32) - 1
    assert two[first] & 0x80
    last = two.index(b"\xbb" * 32) - 1
    assert not two[last] & 0x80


@pytest.mark.parametrize("build", [doh_stamp, dot_stamp])
def test_a_stamp_is_url_safe_and_unpadded(build):
    stamp = build("dns.example.org")
    body = stamp[len("sdns://"):]
    assert "=" not in body and "+" not in body and "/" not in body


# --- Apple configuration profiles ---
def test_a_doh_profile_names_the_url_and_a_unique_identifier():
    a = apple_mobileconfig(display_name="Trench", doh_url="https://dns.example.org/dns-query")
    b = apple_mobileconfig(display_name="Trench", doh_url="https://dns.example.org/dns-query")
    assert a.startswith("<?xml")
    assert "https://dns.example.org/dns-query" in a
    assert "HTTPS" in a
    assert a != b, "each profile needs its own UUIDs or a device cannot hold two"


def test_a_dot_profile_names_the_server():
    out = apple_mobileconfig(display_name="Trench", dot_host="dns.example.org")
    assert "dns.example.org" in out and "TLS" in out


def test_pinned_addresses_appear_in_the_profile():
    out = apple_mobileconfig(display_name="Trench", dot_host="dns.example.org",
                             server_addresses=["192.0.2.1", "2001:db8::1"])
    assert "192.0.2.1" in out and "2001:db8::1" in out


def test_the_display_name_is_carried_through():
    out = apple_mobileconfig(display_name="Home DNS", dot_host="dns.example.org")
    assert "Home DNS" in out


# --- IPMatcher ---
def test_an_empty_matcher_matches_nothing():
    m = IPMatcher()
    assert m.size == 0 and not m
    assert m.match("192.0.2.1") is None


def test_a_prefix_matches_the_addresses_inside_it():
    m = IPMatcher()
    m.add("192.0.2.0/24", "badnets")
    assert m.match("192.0.2.7") == "badnets"
    assert m.match("192.0.3.7") is None


def test_the_most_specific_prefix_wins():
    m = IPMatcher()
    m.add("10.0.0.0/8", "broad")
    m.add("10.1.2.0/24", "narrow")
    assert m.match("10.1.2.3") == "narrow"
    assert m.match("10.9.9.9") == "broad"


def test_an_unlabelled_source_matches_as_an_empty_string():
    """Callers must test `is not None` rather than truthiness."""
    m = IPMatcher()
    m.add("192.0.2.0/24", "")
    assert m.match("192.0.2.7") == ""
    assert m.match("192.0.2.7") is not None


def test_a_default_route_matches_everything():
    m = IPMatcher()
    m.add("0.0.0.0/0", "all")
    assert m.match("8.8.8.8") == "all"


def test_ipv6_prefixes_are_matched_separately():
    m = IPMatcher()
    m.add("2001:db8::/32", "v6")
    assert m.match("2001:db8::1") == "v6"
    assert m.match("2001:db9::1") is None
    assert m.match("192.0.2.1") is None


def test_an_address_that_is_not_an_address_matches_nothing():
    m = IPMatcher()
    m.add("192.0.2.0/24", "badnets")
    assert m.match("not-an-address") is None
    assert m.match("") is None


def test_a_matcher_with_only_v6_declines_a_v4_address():
    m = IPMatcher()
    m.add("2001:db8::/32", "v6")
    assert m.match("192.0.2.1") is None


def test_a_malformed_prefix_is_ignored():
    m = IPMatcher()
    m.add("not-a-network", "bad")
    assert m.size == 0


def test_bare_addresses_are_read_as_host_routes():
    m = IPMatcher()
    assert m.add_many("192.0.2.1\n2001:db8::1\n# a comment\n\n", "list") == 2
    assert m.match("192.0.2.1") == "list"
    assert m.match("192.0.2.2") is None
    assert m.match("2001:db8::1") == "list"


def test_add_many_skips_what_it_cannot_read():
    m = IPMatcher()
    assert m.add_many("192.0.2.0/24\nnonsense\n999.1.1.1\n", "list") == 1


# --- rpz-ip triggers ---
def test_an_rpz_ip_trigger_becomes_a_prefix():
    text = "24.0.2.0.192.rpz-ip CNAME .\n"
    got = list(iter_rpz_ips(text, "badips"))
    assert got and got[0][0] == "192.0.2.0/24"
    assert got[0][1] == "badips"


def test_a_host_route_rpz_trigger():
    got = list(iter_rpz_ips("32.1.2.0.192.rpz-ip CNAME .\n", "list"))
    assert got[0][0] == "192.0.2.1/32"


def test_an_ipv6_rpz_trigger_expands_its_zero_run():
    text = "32.zz.db8.2001.rpz-ip CNAME .\n"
    got = list(iter_rpz_ips(text, "list"))
    assert got and got[0][0].startswith("2001:db8:")


def test_lines_that_are_not_rpz_ip_triggers_are_skipped():
    text = ("; a comment\n"
            "ads.example.com CNAME .\n"
            "not.an.rpz-ip.at.all\n")
    assert list(iter_rpz_ips(text, "list")) == []


def test_a_malformed_rpz_ip_trigger_is_skipped():
    text = "999.0.2.0.192.rpz-ip CNAME .\nnotanumber.0.2.0.192.rpz-ip CNAME .\n"
    assert list(iter_rpz_ips(text, "list")) == []


# --- answer_addresses ---
def test_every_address_in_the_answer_is_listed_in_order():
    m = Message(id=1)
    name = Name.from_text("example.com.")
    m.answers.append(RR(name, Type.A, Class.IN, 60, R.A("192.0.2.1")))
    m.answers.append(RR(name, Type.AAAA, Class.IN, 60, R.AAAA("2001:db8::1")))
    m.answers.append(RR(name, Type.TXT, Class.IN, 60, R.TXT([b"ignored"])))
    assert answer_addresses(m) == ["192.0.2.1", "2001:db8::1"]


def test_an_answer_with_no_addresses_yields_nothing():
    assert answer_addresses(Message(id=1)) == []


def test_a_record_that_cannot_be_rendered_is_skipped():
    class Broken:
        def to_text(self):
            raise ValueError("not renderable")

    m = Message(id=1)
    m.answers.append(RR(Name.from_text("example.com."), Type.A, Class.IN, 60, Broken()))
    assert answer_addresses(m) == []


# --- rpz_ip_prefix directly ---
@pytest.mark.parametrize("owner,cidr", [
    ("24.0.2.0.192.rpz-ip", "192.0.2.0/24"),
    ("32.1.2.0.192.rpz-ip", "192.0.2.1/32"),
    ("8.0.0.0.10.rpz-ip", "10.0.0.0/8"),
    ("24.0.2.0.192.rpz-ip.", "192.0.2.0/24"),
    ("24.0.2.0.192.RPZ-IP", "192.0.2.0/24"),
])
def test_an_encoded_prefix_is_read_back(owner, cidr):
    assert rpz_ip_prefix(owner) == cidr


@pytest.mark.parametrize("owner", [
    "ads.example.com",            # not a trigger at all
    "notanumber.0.2.0.192.rpz-ip",
    "999.0.2.0.192.rpz-ip",       # a prefix length no address has
    "24.0.2.0.999.rpz-ip",        # an octet no address has
    "",
])
def test_something_that_is_not_an_encoded_prefix_yields_nothing(owner):
    assert rpz_ip_prefix(owner) is None


def test_an_ipv6_trigger_uses_zz_for_the_zero_run():
    """Exactly as BIND writes it."""
    assert rpz_ip_prefix("32.zz.db8.2001.rpz-ip") == "2001:db8::/32"


def test_an_ipv6_trigger_with_no_zero_run():
    got = rpz_ip_prefix("128.1.0.0.0.0.0.db8.2001.rpz-ip")
    assert got is not None and got.endswith("/128")


def test_directives_and_comments_are_skipped_by_the_iterator():
    text = ("$TTL 60\n"
            "; 24.0.2.0.192.rpz-ip in a comment\n"
            "24.0.2.0.192.rpz-ip CNAME .\n")
    assert [c for c, _ in iter_rpz_ips(text, "list")] == ["192.0.2.0/24"]
