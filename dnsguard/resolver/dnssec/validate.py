"""RRSIG verification over an RRset (RFC 4034 §3.1.8.1, RFC 6605/8080)."""
from __future__ import annotations

import enum
import time

from ...wire import rdata as R
from ...wire.name import Name
from ...wire.writer import Writer
from .keys import dnskey_to_public_key, key_tag


class ValidationResult(enum.StrEnum):
    SECURE = "secure"
    INSECURE = "insecure"
    BOGUS = "bogus"
    INDETERMINATE = "indeterminate"


def _canon_rdata(rd: R.Rdata) -> bytes:
    """Canonical RDATA: names within RDATA lowercased (RFC 4034 §6.2)."""
    w = Writer()
    if isinstance(rd, (R.NS, R.CNAME, R.PTR, R.DNAME)):
        type(rd)(rd.name.canonicalize()).emit(w)
    elif isinstance(rd, R.MX):
        R.MX(rd.preference, rd.exchange.canonicalize()).emit(w)
    elif isinstance(rd, R.SRV):
        R.SRV(rd.priority, rd.weight, rd.port, rd.target.canonicalize()).emit(w)
    elif isinstance(rd, R.SOA):
        R.SOA(rd.mname.canonicalize(), rd.rname.canonicalize(), rd.serial,
              rd.refresh, rd.retry, rd.expire, rd.minimum).emit(w)
    else:
        rd.emit(w)
    return w.getvalue()


def _canon_name_bytes(name: Name) -> bytes:
    w = Writer()
    for label in name.canonicalize().labels:
        w.u8(len(label))
        w.raw(label)
    w.u8(0)
    return w.getvalue()


def _signed_data(owner: Name, rtype: int, rclass: int, rrsig: R.RRSIG,
                 rdatas: list[R.Rdata]) -> bytes:
    # RRSIG RDATA without the signature field
    w = Writer()
    w.u16(rrsig.type_covered)
    w.u8(rrsig.algorithm)
    w.u8(rrsig.labels)
    w.u32(rrsig.original_ttl)
    w.u32(rrsig.expiration)
    w.u32(rrsig.inception)
    w.u16(rrsig.key_tag)
    w.raw(_canon_name_bytes(rrsig.signer))
    out = bytearray(w.getvalue())

    name_bytes = _canon_name_bytes(owner)
    prefix = (name_bytes + rtype.to_bytes(2, "big") + rclass.to_bytes(2, "big")
              + rrsig.original_ttl.to_bytes(4, "big"))
    # RFC 4034 §6.3 orders the RRs by their RDATA alone. Sorting by the whole
    # encoded RR looks equivalent — every other field is identical across an
    # RRset — but it is not, because the rdlength sits between them: a shorter
    # RDATA then sorts first whatever it contains. Every RRset whose members
    # differ in length (MX, NS, TXT, and most of the interesting ones) gets a
    # different order from the signer's and fails to verify. Fixed-length types
    # such as A are unaffected, which is exactly why this survives unit tests
    # and only shows up against real zones.
    bodies = sorted(_canon_rdata(rd) for rd in rdatas)
    for body in bodies:
        out += prefix + len(body).to_bytes(2, "big") + body
    return bytes(out)


def verify_rrset(owner: Name, rtype: int, rclass: int, rdatas: list[R.Rdata],
                 rrsig: R.RRSIG, dnskey: R.DNSKEY, *, now: float | None = None) -> bool:
    """True iff `rrsig` is a valid signature over the RRset by `dnskey`,
    and within its validity period."""
    if rrsig.algorithm != dnskey.algorithm:
        return False
    if rrsig.key_tag != key_tag(dnskey):
        return False
    now = now if now is not None else time.time()
    if not (rrsig.inception <= now <= rrsig.expiration):
        return False

    data = _signed_data(owner, rtype, rclass, rrsig, rdatas)
    try:
        pub = dnskey_to_public_key(dnskey)
    except Exception:
        return False
    return _verify_sig(pub, rrsig.algorithm, rrsig.signature, data)


def _verify_sig(pub, algo: int, signature: bytes, data: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
    try:
        if algo in (5, 7, 8, 10):
            halg = {5: hashes.SHA1(), 8: hashes.SHA256(), 10: hashes.SHA512()}[algo]
            pub.verify(signature, data, padding.PKCS1v15(), halg)
            return True
        if algo in (13, 14):
            halg = hashes.SHA256() if algo == 13 else hashes.SHA384()
            half = len(signature) // 2
            r = int.from_bytes(signature[:half], "big")
            s = int.from_bytes(signature[half:], "big")
            der = utils.encode_dss_signature(r, s)
            pub.verify(der, data, ec.ECDSA(halg))
            return True
        if algo in (15, 16):  # Ed25519 / Ed448
            pub.verify(signature, data)
            return True
    except InvalidSignature:
        return False
    except Exception:
        return False
    return False
