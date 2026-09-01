"""Per-query state carried through the pipeline stages."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..wire import Message


@dataclass
class QueryContext:
    query: Message
    client_ip: str
    proto: str = "udp"           # udp|tcp|tls|https|quic|h3
    client_id: str = ""          # encrypted-transport ClientID (P4)
    recv_monotonic: float = field(default_factory=time.monotonic)
    # outputs / annotations
    response: Message | None = None
    action: str = ""             # blocked|cached|forwarded|local|failed|...
    reason: str = ""
    rule: str = ""
    source: str = ""
    upstream: str = ""
    policy: object | None = None   # resolved clients.Policy (P4)

    # Derived once per query, not once per read. `qname` alone is read from a
    # dozen places in the pipeline, and each read used to re-render the name
    # from its wire labels.
    _qname: str | None = field(default=None, repr=False, compare=False)
    _labels: tuple[str, ...] | None = field(default=None, repr=False, compare=False)

    @property
    def qname(self) -> str:
        name = self._qname
        if name is None:
            q = self.query.question
            name = self._qname = q.name.to_text().rstrip(".").lower() if q else ""
        return name

    @property
    def labels(self) -> tuple[str, ...]:
        """`qname` split into labels, computed once.

        Six independent consumers — the filter engine, services, safe browsing,
        safe search, DGA and tunnel detection — each used to redo
        `rstrip(".").lower().split(".")` for themselves.
        """
        labels = self._labels
        if labels is None:
            name = self.qname
            labels = self._labels = tuple(name.split(".")) if name else ()
        return labels

    @property
    def qtype(self) -> int:
        q = self.query.question
        return q.rtype if q else 0

    def elapsed_us(self) -> int:
        return int((time.monotonic() - self.recv_monotonic) * 1_000_000)
