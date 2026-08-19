"""Zone transfer: AXFR (RFC 5936) and IXFR (RFC 1995) message generation,
plus the serial arithmetic (RFC 1982) both rely on.

AXFR streams the whole zone bracketed by the apex SOA. IXFR streams only the
delta between the client's serial and ours (falling back to AXFR when we can't
serve the delta from the journal).
"""
from __future__ import annotations

from collections.abc import Iterator

from ..wire import RR, Class, Message, Type
from ..wire import rdata as R
from ..wire.name import Name
from ..wire.rrtypes import Flags
from .zone import Zone

# how many RRs to pack per transfer message before flushing (RFC 5936 allows many)
RRS_PER_MSG = 100


def serial_gt(a: int, b: int) -> bool:
    """RFC 1982 serial-number 'a is strictly newer than b' (mod 2^32)."""
    if a == b:
        return False
    return ((a < b) and (b - a > 2**31)) or ((a > b) and (a - b < 2**31))


def _soa_rr(zone: Zone) -> RR:
    return RR(zone.origin, Type.SOA, Class.IN, zone.ttl_of(zone.origin, Type.SOA), zone.soa)


def axfr_records(zone: Zone) -> list[RR]:
    """Full zone as an RR list: SOA, every RRset (+RRSIGs), closing SOA."""
    soa = _soa_rr(zone)
    out: list[RR] = [soa]
    for name in zone.names():
        node = zone.records.get(name, {})
        for rtype in sorted(node):
            if name == zone.origin and rtype == Type.SOA:
                continue
            ttl = zone.ttl_of(name, rtype)
            for rd in node[rtype]:
                out.append(RR(name, rtype, Class.IN, ttl, rd))
            sig = zone.rrsigs.get((name, rtype))
            if sig is not None:
                out.append(RR(name, Type.RRSIG, Class.IN, ttl, sig))
    # apex SOA's own RRSIG, then the closing SOA
    apex_sig = zone.rrsigs.get((zone.origin, Type.SOA))
    if apex_sig is not None:
        out.append(RR(zone.origin, Type.RRSIG, Class.IN,
                      zone.ttl_of(zone.origin, Type.SOA), apex_sig))
    out.append(soa)
    return out


def _chunk_into_messages(query: Message, records: list[RR]) -> Iterator[Message]:
    for i in range(0, len(records), RRS_PER_MSG):
        m = query.reply()
        m.set_flag(Flags.AA, True)
        m.answers = records[i:i + RRS_PER_MSG]
        yield m
    # never yield zero messages (empty zone still needs the SOA pair)
    if not records:
        yield query.reply()


def axfr_messages(query: Message, zone: Zone) -> list[Message]:
    return list(_chunk_into_messages(query, axfr_records(zone)))


def ixfr_messages(query: Message, zone: Zone, client_serial: int) -> list[Message]:
    """IXFR: incremental delta from client_serial to current, if the journal
    covers it; otherwise a single AXFR-style full transfer (RFC 1995 §4)."""
    cur = zone.soa.serial if zone.soa else 0
    if not serial_gt(cur, client_serial):
        # client is up to date: reply with just the current SOA
        m = query.reply()
        m.set_flag(Flags.AA, True)
        m.answers = [_soa_rr(zone)]
        return [m]
    # signed zones: the journal records only the explicit adds/deletes, not the
    # RRSIG/NSEC churn from re-signing — a delta would desync the secondary.
    delta = None if zone.signed else _journal_delta(zone, client_serial)
    if delta is None:
        return axfr_messages(query, zone)      # condensation impossible -> full AXFR
    records = _ixfr_records(zone, delta)
    return list(_chunk_into_messages(query, records))


def _journal_delta(zone: Zone, client_serial: int) -> list | None:
    """Return the ordered journal entries from client_serial to now, or None if
    the journal doesn't reach back that far."""
    journal = getattr(zone, "journal", None)
    if not journal:
        return None
    serials = [e["from"] for e in journal]
    if client_serial not in serials:
        return None
    idx = serials.index(client_serial)
    return journal[idx:]


def _ixfr_records(zone: Zone, delta: list) -> list[RR]:
    """Encode an IXFR delta stream: SOA(new), then per step
    SOA(old) + deletions + SOA(new) + additions, closing SOA(new)."""
    out: list[RR] = [_soa_rr(zone)]
    for step in delta:
        out.append(_soa_serial_rr(zone, step["from"]))
        out.extend(step["delete"])
        out.append(_soa_serial_rr(zone, step["to"]))
        out.extend(step["add"])
    out.append(_soa_rr(zone))
    return out


def _soa_serial_rr(zone: Zone, serial: int) -> RR:
    soa = zone.soa
    rd = R.SOA(soa.mname, soa.rname, serial, soa.refresh, soa.retry, soa.expire, soa.minimum)
    return RR(zone.origin, Type.SOA, Class.IN, zone.ttl_of(zone.origin, Type.SOA), rd)


def build_xfr_query(origin: Name, qtype: int = Type.AXFR,
                    client_serial: int | None = None, msgid: int = 0) -> Message:
    """Client-side: build an AXFR or IXFR request."""
    from ..wire import Question
    m = Message(id=msgid)
    m.questions.append(Question(origin, qtype, Class.IN))
    if qtype == Type.IXFR and client_serial is not None:
        # IXFR carries the client's current SOA in the authority section
        soa = R.SOA(Name.from_text("."), Name.from_text("."), client_serial, 0, 0, 0, 0)
        m.authority.append(RR(origin, Type.SOA, Class.IN, 0, soa))
    return m


def zone_from_records(records: list[RR], origin: Name) -> Zone:
    """Assemble a Zone from a completed AXFR stream (strips the bracketing SOAs,
    keeps the first SOA as the zone's SOA)."""
    z = Zone(origin)
    seen_soa = False
    for rr in records:
        if rr.rtype == Type.SOA:
            if not seen_soa:
                z.add(rr.name, rr.rtype, rr.rdata, rr.ttl)
                seen_soa = True
            continue  # skip closing/duplicate SOA
        if rr.rtype == Type.RRSIG:
            z.rrsigs[(rr.name, rr.rdata.type_covered)] = rr.rdata
            z.signed = True
            continue
        z.add(rr.name, rr.rtype, rr.rdata, rr.ttl)
    return z


def axfr_complete(records: list[RR]) -> bool:
    """An AXFR is complete once we've seen the closing SOA (a second SOA RR)."""
    soas = sum(1 for rr in records if rr.rtype == Type.SOA)
    return soas >= 2


def ixfr_complete(records: list[RR]) -> bool:
    """Completion check that also understands IXFR responses (RFC 1995).

    Three shapes: a single SOA (client is up to date); an AXFR-style full zone
    (bracketing SOAs share the new serial — 2 occurrences); or a delta stream,
    where the new serial appears 3 times (opener, the final step's SOA(to), and
    the closer) — counting occurrences avoids stopping early when a chunk
    boundary happens to fall on a mid-stream SOA."""
    if not records or records[0].rtype != Type.SOA:
        return False
    first = records[0].rdata.serial
    n_first = sum(1 for rr in records
                  if rr.rtype == Type.SOA and rr.rdata.serial == first)
    if len(records) == 1:
        return True                                     # up-to-date reply
    if records[-1].rtype != Type.SOA:
        return False
    if records[1].rtype == Type.SOA and records[1].rdata.serial != first:
        return n_first >= 3                             # delta stream
    return n_first >= 2                                 # AXFR-style full zone


def apply_ixfr(current: Zone | None, records: list[RR], origin: Name) -> Zone:
    """Interpret a completed IXFR response against the zone we currently hold.

    Returns `current` unchanged for an up-to-date reply, a freshly assembled
    zone for an AXFR-style response, or a copy of `current` with the delta
    applied step by step."""
    if not records or records[0].rtype != Type.SOA:
        raise ValueError("malformed transfer: no leading SOA")
    if len(records) == 1:
        if current is None:
            raise ValueError("up-to-date reply but no current zone held")
        return current
    if records[1].rtype != Type.SOA or records[1].rdata.serial == records[0].rdata.serial:
        return zone_from_records(records, origin)       # full zone
    if current is None:
        raise ValueError("received a delta but hold no zone to apply it to")

    import copy
    z = copy.deepcopy(current)
    new_serial = records[0].rdata.serial
    i = 1
    while i < len(records):
        rr = records[i]
        if rr.rtype == Type.SOA and rr.rdata.serial == new_serial:
            break                                       # closing SOA(new)
        # deletion section, opened by SOA(from)
        i += 1
        while i < len(records) and records[i].rtype != Type.SOA:
            _remove_rr(z, records[i])
            i += 1
        if i >= len(records):
            raise ValueError("truncated IXFR delta")
        i += 1                                          # SOA(to) opens additions
        while i < len(records) and records[i].rtype != Type.SOA:
            add = records[i]
            z.add(add.name, add.rtype, add.rdata, add.ttl)
            i += 1
    if z.soa is None:
        raise ValueError("delta removed the SOA")
    z.soa.serial = new_serial
    return z


def _remove_rr(z: Zone, rr: RR) -> None:
    node = z.records.get(rr.name)
    if not node or rr.rtype not in node:
        return
    txt = rr.rdata.to_text()
    keep = [rd for rd in node[rr.rtype] if rd.to_text() != txt]
    if keep:
        node[rr.rtype] = keep
    else:
        del node[rr.rtype]
        if not node:
            z.records.pop(rr.name, None)
