"""Online DNSSEC signing of authoritative zones."""
from .signer import sign_zone

__all__ = ["sign_zone"]
