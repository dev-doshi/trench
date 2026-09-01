"""DNSGuard exception hierarchy."""
from __future__ import annotations


class DNSGuardError(Exception):
    """Base for all DNSGuard errors."""


class WireError(DNSGuardError):
    """Malformed DNS wire data. Never propagates to the network — callers
    catch it and drop / FORMERR the offending packet."""


class ConfigError(DNSGuardError):
    """Invalid configuration."""


class UpstreamError(DNSGuardError):
    """All upstreams failed / timed out."""

