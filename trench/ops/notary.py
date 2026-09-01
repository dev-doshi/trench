"""Quorum resolution for the handful of names that must not be tampered with.

DNSSEC proves a signed answer was not altered. Most of the names a household
actually cares about — the bank, the mail provider, the password manager — sit
in unsigned zones or behind CDN chains where the signing stops early, so for
those there is no proof at all, only whatever the upstream said.

For a short, operator-chosen list this asks several independent upstreams the
same question and compares what comes back. Agreement is the normal case and
costs nothing at this volume: a few names on a slow timer. Disagreement is the
interesting case, and it is recorded with every answer that produced it.

Two deliberate limits:

  * Comparison is at network-prefix granularity (/24 and /48), not exact
    addresses. A CDN rotating addresses inside its own network is the ordinary
    case and must stay quiet; a name that starts resolving into a different
    network is the event worth reporting. This is an approximation of "same
    provider" — the accurate version needs an ASN database, which is a
    dependency and a data feed this project deliberately does not carry.
  * It reports. It does not pick a winner, rewrite an answer, or block: acting
    on a disagreement automatically would mean an outage at one upstream could
    take a name away from the household.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field

from ..log import get
from ..wire import Class, Message, Question, Type
from ..wire.name import Name
from ..wire.rrtypes import Rcode

log = get("notary")

V4_PREFIX, V6_PREFIX = 24, 48


def network_of(addr: str) -> str:
    """The /24 or /48 an address sits in, as text; "" if it is not an address."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return ""
    length = V4_PREFIX if ip.version == 4 else V6_PREFIX
    return str(ipaddress.ip_network(f"{addr}/{length}", strict=False))


@dataclass
class Observation:
    upstream: str
    addresses: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    rcode: str = ""
    error: str = ""


@dataclass
class Finding:
    name: str
    at: float
    agreed: bool
    observations: list[Observation]
    note: str = ""
    #: False when there was nothing to compare — one upstream configured, or
    #: only one that answered. Not a finding: an upstream being unreachable is
    #: an absence, and reporting it as a quorum result would cry wolf every time
    #: a server is briefly down.
    comparable: bool = True

    def to_json(self) -> dict:
        return {
            "name": self.name, "at": int(self.at), "agreed": self.agreed,
            "note": self.note, "comparable": self.comparable,
            "observations": [
                {"upstream": o.upstream, "addresses": o.addresses,
                 "networks": o.networks, "rcode": o.rcode, "error": o.error}
                for o in self.observations],
        }


class Notary:
    """Asks each upstream separately about the pinned names and compares."""

    #: Kept per name, so the console can show that today's answer is new rather
    #: than only that two upstreams disagree right now.
    HISTORY = 20

    def __init__(self, forwarder, names, *, timeout: float = 4.0):
        self.forwarder = forwarder
        self.names = [n.strip(".").lower() for n in names if n.strip()]
        self.timeout = timeout
        self.findings: list[Finding] = []
        self.seen_networks: dict[str, set[str]] = {}

    def _upstreams(self) -> list:
        router = getattr(self.forwarder, "router", None)
        if router is None:
            return []
        seen: dict[int, object] = {}
        for up in router.default:
            seen.setdefault(id(up), up)
        return list(seen.values())

    async def _ask(self, up, qname: str) -> Observation:
        query = Message(id=0)
        query.set_flag(0x0100, True)          # RD
        query.questions.append(Question(Name.from_text(qname + "."), Type.A, Class.IN))
        obs = Observation(upstream=repr(up))
        try:
            resp = await asyncio.wait_for(up.query(query), self.timeout)
        except Exception as e:                # an upstream being down is not a
            obs.error = str(e)                # disagreement; it is an absence
            return obs
        obs.rcode = Rcode(resp.rcode).name if resp.rcode in [r.value for r in Rcode] \
            else str(resp.rcode)
        for rr in resp.answers:
            if rr.rtype in (Type.A, Type.AAAA):
                addr = rr.rdata.to_text()
                obs.addresses.append(addr)
                net = network_of(addr)
                if net and net not in obs.networks:
                    obs.networks.append(net)
        return obs

    async def check(self, qname: str) -> Finding | None:
        ups = self._upstreams()
        if len(ups) < 2:
            return Finding(qname, time.time(), True, [],
                           note="fewer than two upstreams configured; "
                                "there is nothing to compare", comparable=False)
        obs = await asyncio.gather(*(self._ask(up, qname) for up in ups))
        answered = [o for o in obs if not o.error and o.networks]
        if len(answered) < 2:
            return Finding(qname, time.time(), True, list(obs),
                           note="not enough upstreams answered to compare",
                           comparable=False)
        sets = [frozenset(o.networks) for o in answered]
        agreed = all(s & sets[0] for s in sets[1:])
        known = self.seen_networks.setdefault(qname, set())
        new = set().union(*sets) - known if known else set()
        known.update(*sets)
        note = ""
        if not agreed:
            note = "upstreams disagree about which network this name resolves into"
        elif new:
            note = ("resolves into a network not seen for this name before: "
                    + ", ".join(sorted(new)))
        finding = Finding(qname, time.time(), agreed, list(obs), note)
        return finding

    async def run_once(self) -> list[Finding]:
        """Check every pinned name. Returns the findings worth reporting."""
        out: list[Finding] = []
        for qname in self.names:
            try:
                finding = await self.check(qname)
            except Exception:
                log.exception("notary check failed for %s", qname)
                continue
            if finding is None or not finding.comparable:
                continue
            if not finding.agreed or finding.note:
                log.warning("notary: %s — %s", qname, finding.note or "disagreement")
                out.append(finding)
                self.findings.append(finding)
        del self.findings[:-self.HISTORY]
        return out
