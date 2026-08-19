"""Integrated DHCP server. SHIPS DISABLED — never binds without explicit opt-in
(config `dhcp.enabled` AND the --allow-dhcp CLI flag AND not --dev)."""
from .scope import Scope
from .v4 import DhcpPacket, MessageType

__all__ = ["DhcpPacket", "MessageType", "Scope"]
