"""Resolution back-ends: forwarder (P0/P5) and recursive (P5)."""
from .forwarder import Forwarder, parse_server

__all__ = ["Forwarder", "parse_server"]
