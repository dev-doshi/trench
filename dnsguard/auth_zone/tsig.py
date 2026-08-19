"""TSIG transaction security (RFC 8945).

Signs/verifies DNS messages with a shared secret and an HMAC. Operates on raw
wire bytes so the MAC is computed over exactly what goes on the wire — no
re-encoding, no name-compression surprises. Used to authenticate AXFR/IXFR,
NOTIFY, and RFC 2136 dynamic UPDATE between primary and secondary servers.

The TSIG RR is always the last record in the additional section; its presence
bumps ARCOUNT by one but the MAC is computed over the message *without* it.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
import time
from dataclasses import dataclass

from ..errors import WireError
from ..wire import rdata as R
from ..wire.name import Name
from ..wire.reader import Reader
from ..wire.rrtypes import Class, Rcode, Type
from ..wire.writer import Writer

# algorithm name -> hashlib constructor
_ALGOS = {
    "hmac-sha256.": hashlib.sha256,
    "hmac-sha512.": hashlib.sha512,
    "hmac-sha384.": hashlib.sha384,
    "hmac-sha224.": hashlib.sha224,
    "hmac-sha1.": hashlib.sha1,
    "hmac-md5.sig-alg.reg.int.": hashlib.md5,
}
DEFAULT_ALGO = "hmac-sha256."
DEFAULT_FUDGE = 300


class TSIGError(Exception):
    """Verification failed. `.rcode` carries the TSIG error to echo back."""
    def __init__(self, msg: str, rcode: int = Rcode.NOTAUTH, tsig_error: int = 0):
        super().__init__(msg)
        self.rcode = rcode
        self.tsig_error = tsig_error


@dataclass
class TSIGKey:
    name: str                 # key name, e.g. "xfr-key."
    secret: bytes             # raw shared secret
    algorithm: str = DEFAULT_ALGO

    @classmethod
    def from_base64(cls, name: str, secret_b64: str, algorithm: str = DEFAULT_ALGO) -> TSIGKey:
        import base64
        return cls(name, base64.b64decode(secret_b64), algorithm)

    @property
    def _hashmod(self):
        mod = _ALGOS.get(self.algorithm.lower())
        if mod is None:
            raise TSIGError(f"unknown TSIG algorithm {self.algorithm}", tsig_error=17)  # BADKEY
        return mod


def _canon_name(name: Name) -> bytes:
    w = Writer()
    # canonical: lowercase, uncompressed
    for label in name.canonicalize().labels:
        w.u8(len(label))
        w.raw(label)
    w.u8(0)
    return w.getvalue()


def _digest(key: TSIGKey, msg_wire: bytes, algo_name: Name, time_signed: int,
            fudge: int, error: int, other: bytes, request_mac: bytes | None) -> bytes:
    """Compute the TSIG MAC (RFC 8945 §4.3.3)."""
    h = hmac.new(key.secret, digestmod=key._hashmod)
    if request_mac is not None:                       # signing/verifying a response
        h.update(struct.pack(">H", len(request_mac)) + request_mac)
    h.update(msg_wire)                                # DNS message, no TSIG, ARCOUNT unbumped
    # TSIG variables
    h.update(_canon_name(Name.from_text(key.name)))
    h.update(struct.pack(">H", Class.ANY))
    h.update(struct.pack(">I", 0))                    # TTL = 0
    h.update(_canon_name(algo_name))
    h.update(struct.pack(">HI", (time_signed >> 32) & 0xFFFF, time_signed & 0xFFFFFFFF))
    h.update(struct.pack(">H", fudge))
    h.update(struct.pack(">H", error))
    h.update(struct.pack(">H", len(other)))
    h.update(other)
    return h.digest()


def _append_tsig_rr(msg_wire: bytes, key: TSIGKey, tsig: R.TSIG) -> bytes:
    """Append a TSIG RR to `msg_wire` and bump ARCOUNT."""
    hdr = bytearray(msg_wire[:12])
    arcount = struct.unpack_from(">H", hdr, 10)[0]
    struct.pack_into(">H", hdr, 10, (arcount + 1) & 0xFFFF)
    w = Writer()
    for label in Name.from_text(key.name).labels:     # owner = key name (uncompressed)
        w.u8(len(label)); w.raw(label)
    w.u8(0)
    w.u16(Type.TSIG)
    w.u16(Class.ANY)
    w.u32(0)
    lenpos = w.reserve_u16()
    start = w.tell()
    tsig.emit(w)
    w.patch_u16(lenpos, w.tell() - start)
    return bytes(hdr) + msg_wire[12:] + w.getvalue()


def sign_wire(msg_wire: bytes, key: TSIGKey, *, request_mac: bytes | None = None,
              time_signed: int | None = None, fudge: int = DEFAULT_FUDGE,
              original_id: int | None = None, error: int = 0,
              other: bytes = b"") -> tuple[bytes, bytes]:
    """Sign a fully-built (TSIG-less) wire message. Returns (signed_wire, mac).
    Pass `request_mac` to sign a *response* (chains to the request's MAC)."""
    if time_signed is None:
        time_signed = int(time.time())
    if original_id is None:
        original_id = struct.unpack_from(">H", msg_wire, 0)[0]
    algo_name = Name.from_text(key.algorithm)
    mac = _digest(key, msg_wire, algo_name, time_signed, fudge, error, other, request_mac)
    tsig = R.TSIG(algo_name, time_signed, fudge, mac, original_id, error, other)
    return _append_tsig_rr(msg_wire, key, tsig), mac


def _locate_tsig(wire: bytes) -> tuple[int, R.TSIG, Name]:
    """Walk the message; return (byte offset where TSIG RR starts, TSIG rdata,
    owner name). Raises WireError/TSIGError if TSIG is absent or not last."""
    if len(wire) < 12:
        raise WireError("short message")
    _id, _flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", wire, 0)
    total = qd + an + ns + ar
    if ar == 0:
        raise TSIGError("no TSIG present")
    r = Reader(wire, 12)
    from ..wire.name import read_name
    last_start = None
    last_rtype = None
    last_rd = None
    last_owner = None
    for i in range(total):
        start = r.tell()
        is_question = i < qd
        owner = read_name(r)
        rtype = r.u16()
        r.u16()  # class
        if is_question:
            continue
        r.u32()  # ttl
        rdlen = r.u16()
        rd_start = r.tell()
        if rtype == Type.TSIG:
            last_rd = R.TSIG.parse(r, rdlen)
        r.seek(rd_start + rdlen)
        last_start, last_rtype, last_owner = start, rtype, owner
    if last_rtype != Type.TSIG or last_rd is None:
        raise TSIGError("TSIG is not the final record")
    return last_start, last_rd, last_owner


def verify_wire(wire: bytes, keyring: dict[str, TSIGKey], *,
                request_mac: bytes | None = None, now: int | None = None,
                fudge_max: int = DEFAULT_FUDGE) -> tuple[bytes, TSIGKey, R.TSIG]:
    """Verify a TSIG-signed message. Returns (received_mac, key, tsig_rr) on
    success, else raises TSIGError with the appropriate TSIG error code."""
    tsig_start, tsig, owner = _locate_tsig(wire)
    key = keyring.get(owner.to_text().lower())
    if key is None or Name.from_text(key.algorithm) != tsig.algorithm:
        raise TSIGError(f"unknown key {owner.to_text()}", tsig_error=17)  # BADKEY
    # reconstruct the message as signed: strip TSIG, decrement ARCOUNT, restore original id
    hdr = bytearray(wire[:12])
    arcount = struct.unpack_from(">H", hdr, 10)[0]
    struct.pack_into(">H", hdr, 10, (arcount - 1) & 0xFFFF)
    struct.pack_into(">H", hdr, 0, tsig.original_id)
    msg_no_tsig = bytes(hdr) + wire[12:tsig_start]
    expected = _digest(key, msg_no_tsig, tsig.algorithm, tsig.time_signed,
                       tsig.fudge, tsig.error, tsig.other, request_mac)
    # truncated MACs are legal (RFC 8945 §5.2.2.1) down to half length / 80 bits
    got = tsig.mac
    full = len(expected)
    if len(got) > full or len(got) < max(10, full // 2):
        raise TSIGError("bad MAC length", tsig_error=16)  # BADSIG
    if not hmac.compare_digest(expected[:len(got)], got):
        raise TSIGError("MAC verification failed", tsig_error=16)  # BADSIG
    if now is None:
        now = int(time.time())
    # The narrower of what the sender asked for and what we are willing to
    # accept. `fudge` is inside the MAC, so a peer's choice cannot be tampered
    # with — but it is still the peer's choice, and the fudge field is 16 bits, so
    # a signer may legitimately ask for a replay window of ~18 hours. How long a
    # signature stays fresh is the verifier's policy to set, so `fudge_max` caps
    # it. (It was a parameter here and was never read.)
    window = min(tsig.fudge, fudge_max)
    if abs(now - tsig.time_signed) > window:
        raise TSIGError("clock skew outside fudge", tsig_error=18)  # BADTIME
    return got, key, tsig
