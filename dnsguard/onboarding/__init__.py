"""Client onboarding: encrypted-DNS configuration profiles and DNS stamps.

Emits the artifacts a user needs to point a device at this resolver over
encrypted transport: an Apple `.mobileconfig` and dnscrypt-style `sdns://`
stamps. QR rendering is left to the web UI (browsers have well-tested QR
libraries); these payloads are what gets encoded.
"""
from __future__ import annotations

from .profile import apple_mobileconfig, doh_stamp, dot_stamp

__all__ = ["apple_mobileconfig", "doh_stamp", "dot_stamp"]
