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
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from aioquic.quic import events

from ..log import get
from .stream import ConnectionTracker

log = get("quic")


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

    def peer_ip(self) -> str:
        paths = getattr(self._quic, "_network_paths", None)
        return paths[0].addr[0] if paths else "?"

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
        return True

    def release(self) -> None:
        if self._admitted is not None and self.tracker is not None:
            self.tracker.release(self._admitted)
            self._admitted = None
