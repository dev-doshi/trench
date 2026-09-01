"""Per-client identification and effective-policy resolution."""
from .model import Client, Policy
from .registry import ClientRegistry

__all__ = ["Client", "Policy", "ClientRegistry"]
