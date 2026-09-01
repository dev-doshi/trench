"""Which address a request is credited to.

`X-Forwarded-For` is written by the sender. The address it carries picks the
filtering policy, the rate-limit bucket, the login-lockout counter and the ECS
subnet sent upstream — so believing it from an arbitrary peer hands the client
a free choice of identity in four subsystems at once.
"""
from __future__ import annotations

from dnsguard.security.clientaddr import TrustedProxies, client_ip


class _FakeTransport:
    def __init__(self, peer):
        self._peer = peer

    def get_extra_info(self, _name):
        return self._peer


class _FakeRequest:
    def __init__(self, peer, headers=None):
        self.transport = _FakeTransport((peer, 12345))
        self.headers = headers or {}
        self.app = {}


def test_forwarded_header_is_ignored_from_an_untrusted_peer():
    req = _FakeRequest("192.168.1.55", {"X-Forwarded-For": "10.0.0.1"})
    assert client_ip(req, TrustedProxies()) == "192.168.1.55"
    assert client_ip(req, TrustedProxies(["172.16.0.0/12"])) == "192.168.1.55"


def test_forwarded_header_is_honoured_from_a_configured_proxy():
    """The right-most entry the trusted chain did not write is the client: the
    proxies in front of us append rather than overwrite, so the left-most entry
    is whatever the client chose to send."""
    req = _FakeRequest("172.16.4.2", {"X-Forwarded-For": "10.0.0.1, 203.0.113.9"})
    assert client_ip(req, TrustedProxies(["172.16.0.0/12"])) == "203.0.113.9"


def test_a_single_entry_from_an_overwriting_proxy_is_the_client():
    req = _FakeRequest("172.16.4.2", {"X-Forwarded-For": "203.0.113.9"})
    assert client_ip(req, TrustedProxies(["172.16.0.0/12"])) == "203.0.113.9"


def test_a_trusted_proxy_sending_garbage_falls_back_to_the_socket():
    req = _FakeRequest("172.16.4.2", {"X-Forwarded-For": "not-an-address"})
    assert client_ip(req, TrustedProxies(["172.16.4.2"])) == "172.16.4.2"
    empty = _FakeRequest("172.16.4.2", {"X-Forwarded-For": "  "})
    assert client_ip(empty, TrustedProxies(["172.16.4.2"])) == "172.16.4.2"


def test_rotating_the_header_cannot_mint_new_identities():
    """The lockout counter keys on this. One client rotating the header must
    stay one client, or brute-force protection never engages."""
    trusted = TrustedProxies()
    seen = {client_ip(_FakeRequest("192.168.1.55",
                                   {"X-Forwarded-For": f"10.0.0.{i}"}), trusted)
            for i in range(50)}
    assert seen == {"192.168.1.55"}


def test_unparseable_config_entries_are_dropped_not_fatal():
    t = TrustedProxies(["172.16.0.0/12", "nonsense", ""])
    assert "172.16.0.1" in t and "192.168.1.1" not in t


def test_a_client_cannot_forge_its_address_through_an_appending_proxy():
    """nginx and HAProxy append, so a client-sent header ends up on the LEFT.
    Trusting the left-most entry let any client pick its own identity — and with
    it the lockout counter, the policy and the rate-limit bucket."""
    trusted = TrustedProxies(["10.0.0.1"])
    req = _FakeRequest("10.0.0.1", {"X-Forwarded-For": "6.6.6.6, 203.0.113.9"})
    assert client_ip(req, trusted) == "203.0.113.9"


def test_chained_trusted_proxies_are_walked_past():
    trusted = TrustedProxies(["10.0.0.1", "10.0.0.2"])
    req = _FakeRequest("10.0.0.1",
                       {"X-Forwarded-For": "6.6.6.6, 203.0.113.9, 10.0.0.2"})
    assert client_ip(req, trusted) == "203.0.113.9"


def test_a_header_that_is_all_trusted_hops_tells_us_nothing():
    trusted = TrustedProxies(["10.0.0.1", "10.0.0.2"])
    req = _FakeRequest("10.0.0.1", {"X-Forwarded-For": "10.0.0.2"})
    assert client_ip(req, trusted) == "10.0.0.1"
