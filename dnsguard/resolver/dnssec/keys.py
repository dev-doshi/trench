"""DNSKEY parsing, key-tag computation, and DS digest (RFC 4034 / 6605 / 8080)."""
from __future__ import annotations

import hashlib
import struct

from ...wire import rdata as R
from ...wire.name import Name
from ...wire.rrtypes import DNSSECAlgo
from ...wire.writer import Writer

_RSA_ALGOS = {5, 7, 8, 10}
_ECDSA_CURVE = {13: "P-256", 14: "P-384"}


def key_tag(dnskey: R.DNSKEY) -> int:
    """RFC 4034 Appendix B key tag over the DNSKEY RDATA."""
    rdata = _dnskey_rdata(dnskey)
    if dnskey.algorithm == 1:  # RSA/MD5 legacy (unused)
        return (rdata[-3] << 8) | rdata[-2]
    # RFC 4034 App. B: even byte index << 8, odd byte index plain.
    acc = 0
    for i, b in enumerate(rdata):
        acc += (b << 8) if (i & 1) == 0 else b
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


def _dnskey_rdata(dnskey: R.DNSKEY) -> bytes:
    w = Writer()
    dnskey.emit(w)
    return w.getvalue()


def ds_digest(owner: Name, dnskey: R.DNSKEY, digest_type: int) -> bytes:
    """DS digest = H(canonical owner name | DNSKEY RDATA). type 2=SHA-256, 4=SHA-384."""
    w = Writer()
    for label in owner.canonicalize().labels:
        w.u8(len(label))
        w.raw(label)
    w.u8(0)
    data = w.getvalue() + _dnskey_rdata(dnskey)
    if digest_type == 2:
        return hashlib.sha256(data).digest()
    if digest_type == 4:
        return hashlib.sha384(data).digest()
    if digest_type == 1:
        return hashlib.sha1(data).digest()
    raise ValueError(f"unsupported DS digest type {digest_type}")


def dnskey_to_public_key(dnskey: R.DNSKEY):
    """Return a cryptography public-key object for the DNSKEY."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

    algo = dnskey.algorithm
    key = dnskey.public_key
    if algo in _RSA_ALGOS:
        return _rsa_from_wire(key, rsa)
    if algo in _ECDSA_CURVE:
        half = len(key) // 2
        x = int.from_bytes(key[:half], "big")
        y = int.from_bytes(key[half:], "big")
        curve = ec.SECP256R1() if algo == 13 else ec.SECP384R1()
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    if algo == 15:
        return ed25519.Ed25519PublicKey.from_public_bytes(key)
    if algo == 16:
        return ed448.Ed448PublicKey.from_public_bytes(key)
    raise ValueError(f"unsupported DNSSEC algorithm {algo}")


def _rsa_from_wire(key: bytes, rsa):
    # RFC 3110: exponent length prefix (1 or 3 bytes), exponent, modulus
    if not key:
        raise ValueError("empty RSA key")
    if key[0] == 0:
        explen = struct.unpack(">H", key[1:3])[0]
        off = 3
    else:
        explen = key[0]
        off = 1
    exponent = int.from_bytes(key[off:off + explen], "big")
    modulus = int.from_bytes(key[off + explen:], "big")
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


def algo_name(algo: int) -> str:
    try:
        return DNSSECAlgo(algo).name
    except ValueError:
        return f"ALGO{algo}"
