"""Connection bounds for the QUIC frontends.

`StreamLimits` and `ConnectionTracker` bound Do53-TCP and DoT, and the config
comments describe those caps as belonging to every connection-oriented
frontend. DoQ and DoH3 never received them: they were constructed without
limits, so the number of established QUIC connections one worker would hold was
whatever peers asked for. aioquic supplies a 60-second idle timeout and
per-connection flow control, which bounds each connection's memory but not how
many there are.

Admission happens at handshake completion rather than on the first packet. That
is deliberate: it bounds *established* connections, which are the ones holding
TLS state and a flow-control window, and leaves half-open handshakes to
aioquic's own address validation, which is where they belong. A refused
connection is closed rather than dropped, so the peer is told rather than left
waiting.

The mixin also owns the connection's handler tasks. A task spawned for a query
belongs to the connection it arrived on: when that connection terminates there
is nobody left to answer, so the task is cancelled rather than left to run a
full resolve for a peer that has gone. `MAX_INFLIGHT` bounds how many can be
outstanding on one connection at once.
"""
from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import TYPE_CHECKING, Any

from aioquic.quic import events

from ..log import get
from .stream import ConnectionTracker

log = get("quic")

#: Handlers one QUIC connection may have running at once. aioquic's own stream
#: limit bounds this only while every query occupies a stream of its own, so it
#: is enforced here as well rather than inferred from the peer's behaviour.
MAX_INFLIGHT = 128


class LimitedQuicProtocol:
    """Mixin: admit on handshake, release on termination.

    Both QUIC frontends receive every connection event through
    `quic_event_received`, including `ConnectionTerminated`, so the whole
    lifecycle is visible without reaching into aioquic's callback attributes.
    """

    tracker: ConnectionTracker | None = None

    if TYPE_CHECKING:
        # Supplied by QuicConnectionProtocol, which this is always mixed into.
        # Declared as attributes rather than as methods: a stub signature here
        # would be a second, narrower declaration of `close` competing with
        # aioquic's in the MRO, which is a worse lie than `Any`.
        _quic: Any
        close: Any
        transmit: Any

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._admitted: str | None = None
        self._tasks: set[asyncio.Task] = set()   # strong refs to in-flight handlers
        self._peer: str | None = None

    def datagram_received(self, data, addr) -> None:
        # The client's address, from the public callback rather than aioquic's
        # private `_network_paths`, which would turn every client into "?" —
        # one policy, one rate-limit bucket — the day it is renamed. Pinned to
        # the first datagram: that is where the handshake is sent, so a
        # completed handshake proves the peer receives there, whereas a later
        # datagram's source is unauthenticated until aioquic decrypts it and
        # a spoofed one must not rebind the connection to someone else's IP.
        if getattr(self, "_peer", None) is None and addr:
            self._peer = addr[0]
        super().datagram_received(data, addr)  # type: ignore[misc]

    def peer_ip(self) -> str:
        return getattr(self, "_peer", None) or "?"

    def note_quic_event(self, event) -> bool:
        """Track this event. False when the connection was refused and closed."""
        if isinstance(event, events.HandshakeCompleted) and self.tracker is not None:
            client = self.peer_ip()
            if not self.tracker.admit(client):
                log.warning("refusing QUIC connection from %s: at the configured "
                            "connection limit", client)
                self.close()
                self.transmit()
                return False
            self._admitted = client
        elif isinstance(event, events.ConnectionTerminated):
            self.release()
            self.cancel_tasks()
        return True

    def spawn(self, coro: Coroutine) -> bool:
        """Run a handler for this connection. False, with `coro` closed unrun,
        when the connection already has `MAX_INFLIGHT` handlers outstanding."""
        if len(self._tasks) >= MAX_INFLIGHT:
            coro.close()
            return False
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return True

    def cancel_tasks(self) -> None:
        for task in list(getattr(self, "_tasks", ())):
            task.cancel()

    def release(self) -> None:
        if self._admitted is not None and self.tracker is not None:
            self.tracker.release(self._admitted)
            self._admitted = None
