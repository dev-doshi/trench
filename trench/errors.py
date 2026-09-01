"""Trench exception hierarchy."""
from __future__ import annotations


class TrenchError(Exception):
    """Base for all Trench errors."""


class WireError(TrenchError):
    """Malformed DNS wire data. Never propagates to the network — callers
    catch it and drop / FORMERR the offending packet."""


class ConfigError(TrenchError):
    """Invalid configuration."""


class UpstreamError(TrenchError):
    """All upstreams failed / timed out."""

