"""SvcParams in SVCB/HTTPS answers, and what to do about the `ech` one.

An HTTPS record (RFC 9460) can carry an `ech` parameter: the key a client uses
to encrypt the TLS ClientHello, so the server name it is connecting to is not
visible on the wire. That is a privacy win for the client and a blind spot for
anything downstream that inspects SNI.

A filtering resolver has to have a position on it. This module makes that
position explicit and testable instead of accidental:

  * `pass` (the default) leaves the parameter alone. DNS-level filtering is not
    weakened by ECH at all — the name is still in the question, which is where
    every decision here is made — so stripping it would cost the household's
    privacy and buy this resolver nothing.
  * `strip` removes the parameter, which downgrades clients to a plaintext SNI.
    It exists because some deployments do inspect SNI elsewhere on the network,
    and a knob that is documented and tested is better than the same effect
    arrived at by accident. It is a downgrade, and the config comment says so.

Only parameter 5 is touched; everything else round-trips byte for byte, and a
malformed parameter list is left untouched rather than rewritten into a
different shape.
"""
from __future__ import annotations

import struct

#: SvcParamKey 5 = ech (RFC 9460 §14.3.2 / draft-ietf-tls-esni).
ECH_KEY = 5

_U16 = struct.Struct("!HH")


def iter_params(raw: bytes):
    """Yield `(key, value)` for a SvcParams blob, or nothing if it is malformed.

    SvcParams are required to be in ascending key order with no duplicates; this
    does not enforce that, because the job here is to reproduce what was sent
    minus one parameter, not to police the sender.
    """
    pos, end = 0, len(raw)
    while pos + 4 <= end:
        key, length = _U16.unpack_from(raw, pos)
        pos += 4
        if pos + length > end:
            return                      # truncated: stop, report nothing more
        yield key, raw[pos:pos + length]
        pos += length


def has_ech(raw: bytes) -> bool:
    return any(key == ECH_KEY for key, _ in iter_params(raw))


def strip_ech(raw: bytes) -> bytes:
    """`raw` without the ech parameter. Returns the input unchanged when there
    is none, or when the blob does not parse cleanly."""
    if not raw:
        return raw
    out = bytearray()
    consumed = 0
    found = False
    for key, value in iter_params(raw):
        consumed += 4 + len(value)
        if key == ECH_KEY:
            found = True
            continue
        out += _U16.pack(key, len(value))
        out += value
    if not found or consumed != len(raw):
        # Nothing to do, or trailing bytes we did not understand — in which case
        # rewriting would corrupt a record we merely failed to parse.
        return raw
    return bytes(out)


def strip_ech_records(response) -> int:
    """Remove `ech` from every HTTPS/SVCB record in a response, in place.

    Returns how many records were rewritten. Records are replaced rather than
    mutated: a cached message and the copy handed to a client share record
    objects, so editing one in place would rewrite answers already served.
    """
    from dataclasses import replace as _replace

    from ..wire import Type

    changed = 0
    for section in ("answers", "authority", "additional"):
        records = getattr(response, section, None)
        if not records:
            continue
        out = []
        for rr in records:
            if rr.rtype in (Type.SVCB, Type.HTTPS) and has_ech(
                    getattr(rr.rdata, "params", b"")):
                params = strip_ech(rr.rdata.params)
                out.append(_replace(rr, rdata=_replace(rr.rdata, params=params)))
                changed += 1
            else:
                out.append(rr)
        if changed:
            setattr(response, section, out)
    return changed
