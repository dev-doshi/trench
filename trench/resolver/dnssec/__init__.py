"""DNSSEC validation: key parsing, RRSIG verification, NSEC/NSEC3 denial.

Implements the cryptographic core (RFC 4034/4035/6605/8080). Chain building to
the IANA root trust anchor lives in chain.py; the recursive resolver drives it.
"""
from .chain import ROOT_ANCHORS, Validator
from .keys import dnskey_to_public_key, ds_digest, key_tag
from .validate import ValidationResult, verify_rrset

__all__ = ["dnskey_to_public_key", "key_tag", "ds_digest",
           "verify_rrset", "ValidationResult", "Validator", "ROOT_ANCHORS"]
