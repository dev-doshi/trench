"""Shared frontend machinery: parse wire -> pipeline -> serialize.

`process_query` is the single choke point every transport funnels through, so
size limits, FORMERR handling, and (later) padding live in one place.
"""
from __future__ import annotations

import abc

from ..engine import Pipeline
from ..errors import WireError
from ..log import get
from ..wire import Message
from ..wire.edns import Edns
from ..wire.rrtypes import Flags, Rcode

log = get("transport")

# encrypted transports get EDNS padding (RFC 8467) to blunt traffic analysis
PADDED = {"tls", "https", "quic", "h3"}
PAD_BLOCK = 468


def udp_response_limit(query: Message | None) -> int:
    if query is not None and query.edns is not None:
        return max(512, min(query.edns.udp_size, 4096))
    return 512


def apply_padding(response: Message) -> None:
    """Pad an (encrypted-transport) response up to a 468-byte block boundary."""
    if response.edns is None:
        response.edns = Edns(udp_size=1232)
    base = len(response.to_wire())  # serialized length without a padding option
    response.edns.set_padding(PAD_BLOCK, base)


async def resolve_wire(pipeline: Pipeline, data: bytes, client_ip: str,
                       proto: str, client_id: str = "") -> Message | None:
    """Parse a wire query and run the pipeline, returning the response Message
    (or None to drop). Transports serialize/frame it themselves."""
    try:
        query = Message.parse(data)
    except WireError:
        return _formerr_msg(data)
    response = await pipeline.resolve(query, client_ip, proto, client_id)
    if proto in PADDED and query.edns is not None:
        apply_padding(response)
    return response


async def process_query(pipeline: Pipeline, data: bytes, client_ip: str,
                        proto: str, *, stream: bool, fast=None) -> bytes | None:
    """Convenience for Do53: returns framed wire bytes (UDP applies 512/EDNS cap).

    `fast` is a `FastPath` to record the result in, so the next identical query
    can be answered from these very bytes without coming through here at all.
    """
    try:
        query = Message.parse(data)
    except WireError:
        if len(data) >= 2:
            return _formerr(data)
        return None
    # The verdict is only needed to decide whether the reply may be recorded, so
    # only ask for it when something is recording. Anything pipeline-shaped keeps
    # working with just `resolve`.
    if fast is None:
        response = await pipeline.resolve(query, client_ip, proto)
        ctx = None
    else:
        ctx = await pipeline.resolve_ctx(query, client_ip, proto)
        response = ctx.response
    if stream:
        return response.to_wire()
    out = response.to_wire(max_size=udp_response_limit(query))
    if ctx is not None:
        fast.store(data, out, ctx)
    return out


def _formerr(data: bytes) -> bytes:
    txid = data[:2]
    # QR=1, opcode copied is unknown; emit minimal FORMERR header, no sections
    flags = (Flags.QR | Rcode.FORMERR).to_bytes(2, "big")
    return txid + flags + b"\x00\x00\x00\x00\x00\x00\x00\x00"


def _formerr_msg(data: bytes) -> Message | None:
    if len(data) < 2:
        return None
    m = Message(id=int.from_bytes(data[:2], "big"), flags=Flags.QR)
    m.set_rcode(Rcode.FORMERR)
    return m


class Frontend(abc.ABC):
    proto: str = "?"

    @abc.abstractmethod
    async def start(self) -> None: ...

    @abc.abstractmethod
    async def stop(self) -> None: ...
