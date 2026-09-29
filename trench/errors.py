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

    #: The servers that were asked, as the query log names them. A failure
    #: that could not say where it went logged "upstream not recorded", which
    #: left a dead route indistinguishable from a question never sent.
    tried: tuple[str, ...] = ()

