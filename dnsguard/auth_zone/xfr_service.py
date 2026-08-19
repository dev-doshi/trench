"""Primary-side transfer service: answer AXFR/IXFR requests (TCP, optional TSIG,
IP allow-lists) and push NOTIFY to configured secondaries when a zone changes.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from ..log import get
from ..wire import Message, Type
from ..wire.name import Name
from ..wire.rrtypes import Flags, Opcode, Rcode
from .secondary import send_notify
from .tsig import TSIGError, TSIGKey, sign_wire, verify_wire
from .xfr import axfr_messages, ixfr_messages
from .zone import Zone

log = get("xfr")


@dataclass
class ZoneTransferPolicy:
    allow_transfer: set[str] = field(default_factory=set)   # secondary IPs (empty = deny all)
    also_notify: list[tuple[str, int]] = field(default_factory=list)
    tsig_key: str | None = None                             # required key name, or None


class TransferService:
    def __init__(self, zonestore, keyring: dict[str, TSIGKey] | None = None):
        self.zonestore = zonestore
        self.keyring = keyring or {}
        self.policies: dict[str, ZoneTransferPolicy] = {}   # origin text -> policy

    def set_policy(self, origin: Name, policy: ZoneTransferPolicy) -> None:
        self.policies[origin.to_text().lower()] = policy

    def _policy_for(self, origin: Name) -> ZoneTransferPolicy | None:
        return self.policies.get(origin.to_text().lower())

    def is_transfer(self, query: Message) -> bool:
        q = query.question
        return q is not None and q.rtype in (Type.AXFR, Type.IXFR)

    def handle_transfer(self, query_wire: bytes, query: Message, client_ip: str) -> list[bytes]:
        """Return the framed... no — return raw wire messages the TCP frontend
        will length-prefix. Empty list => connection should send REFUSED."""
        q = query.question
        zone = self.zonestore.authoritative_for(q.name) if q else None
        if zone is None or zone.origin != q.name:
            return [self._err(query, Rcode.NOTAUTH)]
        policy = self._policy_for(zone.origin)
        # empty allow_transfer = deny all (a zone is never transferable by default)
        if policy is None or client_ip not in policy.allow_transfer:
            log.warning("AXFR of %s from %s refused by policy", q.name.to_text(), client_ip)
            return [self._err(query, Rcode.REFUSED)]
        request_mac = None
        key = None
        if policy.tsig_key:
            try:
                request_mac, key, _ = verify_wire(query_wire, self.keyring)
            except TSIGError as e:
                log.warning("AXFR TSIG failed from %s: %s", client_ip, e)
                return [self._err(query, e.rcode)]
            if key.name.lower() != policy.tsig_key.lower():
                return [self._err(query, Rcode.NOTAUTH)]
        if q.rtype == Type.IXFR:
            client_serial = self._ixfr_client_serial(query)
            msgs = ixfr_messages(query, zone, client_serial)
        else:
            msgs = axfr_messages(query, zone)
        out: list[bytes] = []
        prev_mac = request_mac
        for m in msgs:
            wire = m.to_wire()
            if key is not None:
                wire, prev_mac = sign_wire(wire, key, request_mac=prev_mac)
            out.append(wire)
        return out

    def _ixfr_client_serial(self, query: Message) -> int:
        for rr in query.authority:
            if rr.rtype == Type.SOA:
                return rr.rdata.serial
        return 0

    def _err(self, query: Message, rcode: int) -> bytes:
        r = query.reply(rcode)
        r.set_flag(Flags.AA, True)
        return r.to_wire()

    async def notify_secondaries(self, zone: Zone) -> None:
        policy = self._policy_for(zone.origin)
        if not policy or not policy.also_notify:
            return
        key = self.keyring.get(policy.tsig_key.lower()) if policy.tsig_key else None
        results = await asyncio.gather(
            *(send_notify(h, p, zone.origin, key=key) for h, p in policy.also_notify),
            return_exceptions=True)
        acked = sum(1 for r in results if r is True)
        log.info("NOTIFY for %s: %d/%d secondaries acked",
                 zone.origin.to_text(), acked, len(policy.also_notify))


def is_notify(query: Message) -> bool:
    return query.opcode == Opcode.NOTIFY and not query.qr
