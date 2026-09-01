"""Authoritative transaction handler for the transport layer.

Sits in front of the normal resolve pipeline and claims the DNS opcodes/qtypes
that aren't ordinary queries: AXFR/IXFR (zone transfer out), NOTIFY (secondary
refresh trigger), and UPDATE (RFC 2136 dynamic update). Everything else it
declines, so the transport falls through to the resolver.
"""
from __future__ import annotations

import asyncio

from ..log import get
from ..wire import Message, Type
from ..wire.rrtypes import Flags, Opcode, Rcode
from .secondary import SecondaryZone
from .tsig import (
    ReplayWindow,
    TSIGError,
    TSIGKey,
    sign_error,
    sign_wire,
    verify_wire,
)
from .update import UpdatePolicy, apply_update
from .xfr_service import TransferService, ZoneTransferPolicy, is_notify

log = get("auth")


class AuthHandler:
    def __init__(self, zonestore, keyring: dict[str, TSIGKey] | None = None):
        self.zonestore = zonestore
        self.keyring = keyring or {}
        self.xfr = TransferService(zonestore, self.keyring)
        self.update_acl: dict[str, list[str]] = {}     # origin -> allowed client IPs
        self.update_key: dict[str, str] = {}           # origin -> required TSIG key name
        self.secondaries: dict[str, SecondaryZone] = {}
        # Shared across UPDATE and NOTIFY: a valid MAC proves the sender knew
        # the key, not that this is the first time they sent this message.
        self.replay = ReplayWindow()

    # --- configuration ---
    def set_zone_policy(self, origin, *, allow_transfer=(), also_notify=(),
                        allow_update=(), tsig_key=None) -> None:
        notify = [_hostport(x) for x in also_notify]
        self.xfr.set_policy(origin, ZoneTransferPolicy(
            allow_transfer=set(allow_transfer), also_notify=notify, tsig_key=tsig_key))
        key = origin.to_text().lower()
        self.update_acl[key] = list(allow_update)
        if tsig_key:
            self.update_key[key] = tsig_key

    def register_secondary(self, sec: SecondaryZone) -> None:
        self.secondaries[sec.origin.to_text().lower()] = sec

    # --- classification ---
    def claims(self, query: Message) -> bool:
        if query.opcode in (Opcode.UPDATE, Opcode.NOTIFY):
            return True
        q = query.question
        return q is not None and q.rtype in (Type.AXFR, Type.IXFR)

    # --- TCP: AXFR/IXFR stream + UPDATE/NOTIFY single reply ---
    def handle_tcp(self, query_wire: bytes, query: Message, client_ip: str) -> list[bytes]:
        if self.xfr.is_transfer(query):
            return self.xfr.handle_transfer(query_wire, query, client_ip)
        single = self._handle_short(query_wire, query, client_ip, udp=False)
        return [single] if single is not None else []

    # --- UDP: UPDATE/NOTIFY (transfers are TCP-only; AXFR over UDP => use TCP) ---
    def handle_udp(self, query_wire: bytes, query: Message, client_ip: str) -> bytes | None:
        q = query.question
        if q is not None and q.rtype in (Type.AXFR, Type.IXFR):
            r = query.reply(Rcode.NOERROR)
            r.set_flag(Flags.TC, True)                 # force the client onto TCP
            return r.to_wire()
        return self._handle_short(query_wire, query, client_ip, udp=True)

    def _handle_short(self, query_wire: bytes, query: Message, client_ip: str,
                      *, udp: bool) -> bytes | None:
        if query.opcode == Opcode.UPDATE:
            return self._handle_update(query_wire, query, client_ip, udp=udp)
        if is_notify(query):
            return self._handle_notify(query, client_ip, query_wire)
        return None

    def _handle_update(self, query_wire: bytes, query: Message, client_ip: str,
                       *, udp: bool = False) -> bytes:
        q = query.question
        if q is None:
            return self._reply(query, Rcode.NOTAUTH)   # unchanged: q None fell
                                                       # through to this before
        zone = self.zonestore.authoritative_for(q.name)
        if zone is None or zone.origin != q.name:
            return self._reply(query, Rcode.NOTAUTH)
        key = zone.origin.to_text().lower()
        acl = self.update_acl.get(key, [])
        if not acl or client_ip not in acl:
            log.warning("UPDATE of %s from %s refused (ACL)", key, client_ip)
            return self._reply(query, Rcode.REFUSED)
        # An address allow-list is a real control over TCP, where the peer had to
        # complete a handshake to be talking to us at all. Over UDP a source
        # address is a claim, so an off-path attacker who knows one allowed
        # address can rewrite the zone with a single spoofed packet and never
        # needs to see the reply. TSIG is evidence; an address is not.
        if udp and not self.update_key.get(key):
            log.warning("unsigned UPDATE of %s over UDP from %s refused "
                        "(configure a tsig_key, or send it over TCP)", key, client_ip)
            return self._reply(query, Rcode.REFUSED)
        tkey = req_mac = None
        if self.update_key.get(key):
            try:
                req_mac, tkey, _ = verify_wire(query_wire, self.keyring,
                                               replay=self.replay)
            except TSIGError as e:
                return sign_error(self._reply(query, e.rcode), e)
            if tkey.name.lower() != self.update_key[key].lower():
                return self._reply(query, Rcode.NOTAUTH)
        rc = apply_update(zone, query, UpdatePolicy())
        if rc == Rcode.NOERROR:
            self._schedule_notify(zone)
        out = self._reply(query, rc)
        if tkey is not None:   # a signed request MUST get a signed response (RFC 8945 §5.3)
            out, _ = sign_wire(out, tkey, request_mac=req_mac)
        return out

    def _schedule_notify(self, zone) -> None:
        """Fire NOTIFY to secondaries in the background (no-op outside a loop)."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self.xfr.notify_secondaries(zone))

    def _handle_notify(self, query: Message, client_ip: str,
                       query_wire: bytes = b"") -> bytes:
        """RFC 1996 §3.10: only the zone's primary may tell us the zone changed.

        A NOTIFY costs the sender one small UDP packet and costs us a full zone
        transfer from our own primary. Acting on one from an unverified source is
        therefore an amplifier pointed at our own infrastructure, and the source
        address of a UDP packet is a claim rather than evidence — so anything but
        the configured primary is refused.
        """
        q = query.question
        sec = self.secondaries.get(q.name.to_text().lower()) if q else None
        if sec is None:
            return self._reply(query, Rcode.REFUSED)
        if client_ip != sec.primary:
            log.warning("NOTIFY for %s from %s refused (not the primary %s)",
                        q.name.to_text(), client_ip, sec.primary)
            return self._reply(query, Rcode.REFUSED)
        # A source address is a claim. Where the secondary holds a key, require
        # the sender to prove it too: otherwise one spoofed UDP packet — the
        # cheapest thing an off-path attacker can send — drives a full zone
        # transfer from our own primary, and a flood of them is an amplifier
        # aimed at our own infrastructure.
        key = getattr(sec, "key", None)
        if key is not None:
            try:
                verify_wire(query_wire, {key.name: key}, replay=self.replay)
            except TSIGError as e:
                log.warning("NOTIFY for %s from %s refused: %s",
                            q.name.to_text(), client_ip, e)
                return sign_error(self._reply(query, e.rcode), e)
        log.info("NOTIFY for %s -> scheduling refresh", q.name.to_text())
        sec.notify()
        r = query.reply(Rcode.NOERROR)
        r.set_flag(Flags.AA, True)
        return r.to_wire()

    def _reply(self, query: Message, rcode: int) -> bytes:
        r = query.reply(rcode)
        if query.opcode == Opcode.UPDATE:
            r.set_flag(Flags.OPCODE_MASK, False)
            r.flags |= (Opcode.UPDATE << Flags.OPCODE_SHIFT)
        r.set_flag(Flags.AA, True)
        return r.to_wire()


def _hostport(spec: str) -> tuple[str, int]:
    if ":" in spec and spec.count(":") == 1:
        h, p = spec.rsplit(":", 1)
        return h, int(p)
    return spec, 53
