"""Device names learned from DHCP, and the forward/reverse answers built on them.

A household's query log is a list of addresses until something puts names to
them. The DHCP server already receives the one piece of information that does —
option 12, the hostname the client offers when it takes a lease — and until now
threw it away: `DhcpServer.dns_register` existed as a parameter nothing passed
and nothing called.

What this module adds is small and worth stating precisely, because the input is
client-supplied:

  * `laptop` taking a lease becomes `laptop.lan` (A) and the matching PTR under
    `in-addr.arpa`, so both directions resolve without a hand-written record.
  * The offered name is treated as **one label**. A client that calls itself
    `www.bank.com` gets registered as `wwwbankcom.lan` or rejected — never as
    `www.bank.com`, which is a client on the LAN choosing what a name resolves
    to for everyone else in the building.
  * Names are only served inside the scope's own domain and only for addresses
    inside the scope's own network, so a lease can never shadow a real name or
    answer for an address the DHCP server does not manage.
  * Configured zones and local records win. A registration that would collide
    with one is dropped, with a warning: the operator wrote those on purpose.
"""
from __future__ import annotations

import ipaddress
import re
import time

from ..log import get
from ..wire import RR, Class, Message, Type
from ..wire import rdata as R
from ..wire.name import Name
from ..wire.rrtypes import Flags, Rcode

log = get("names")

#: One DNS label, conservatively: letters, digits and inner hyphens. Anything a
#: client sends that does not survive this is sanitised or dropped.
_LABEL_OK = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

DEFAULT_TTL = 60


def sanitize_hostname(raw: str) -> str:
    """A single safe label from whatever the client offered, or "".

    Dots are removed rather than kept: a hostname with a dot in it is either a
    client trying to claim a name in another zone, or a device volunteering its
    FQDN — and in both cases the only name it is entitled to is the leaf.
    """
    trimmed = (raw or "").strip().strip(".").lower()
    if not trimmed:
        return ""
    name = re.sub(r"[^a-z0-9-]", "-", trimmed.split(".")[0]).strip("-")
    if not name or not _LABEL_OK.match(name):
        return ""
    return name[:63]


def reverse_name(ip: str) -> str:
    """`192.168.1.5` -> `5.1.168.192.in-addr.arpa.` (IPv6 -> ip6.arpa).

    The inverse of `address_from_reverse`; the two are tested against each other
    so the PTR path cannot drift from the name it is supposed to answer for.
    """
    addr = ipaddress.ip_address(ip)
    return addr.reverse_pointer + "."


def address_from_reverse(name: str) -> str | None:
    """The address a reverse name points at, or None if it is not one."""
    labels = name.strip(".").lower().split(".")
    try:
        if name.rstrip(".").endswith("in-addr.arpa") and len(labels) == 6:
            return str(ipaddress.IPv4Address(".".join(reversed(labels[:4]))))
        if name.rstrip(".").endswith("ip6.arpa") and len(labels) == 34:
            return str(ipaddress.IPv6Address(
                bytes.fromhex("".join(reversed(labels[:32])))))
    except ValueError:
        return None
    return None


class HostNames:
    """Live IP <-> name map for DHCP clients, and a resolver for it.

    Held in the primary worker (where DHCP runs) and consulted by the pipeline
    before the cache: these names are ours, and asking an upstream about
    `laptop.lan` leaks the household's device names to the internet.
    """

    def __init__(self, domain: str = "lan", network: str = "",
                 *, ttl: int = DEFAULT_TTL, max_entries: int = 4096,
                 reserved=None):
        self.domain = (domain or "lan").strip(".").lower()
        self.network = ipaddress.ip_network(network, strict=False) if network else None
        self.ttl = ttl
        self.max_entries = max_entries
        # A name the operator configured (zone or local record) is never taken
        # over by a device that asks for it.
        self.reserved = {n.strip(".").lower() for n in (reserved or ())}
        self._by_ip: dict[str, str] = {}        # ip -> label
        self._by_name: dict[str, str] = {}      # fqdn -> ip
        self._seen: dict[str, float] = {}       # ip -> last registration time

    # ---------------------------------------------------------------- writing
    def register(self, ip: str, hostname: str) -> str:
        """Record `hostname` for `ip`. Returns the FQDN registered, or "".

        Idempotent, and the last registration for an address wins: a device that
        renews with a new name has renamed itself, and the previous name for
        that address must stop resolving or the log grows ghosts.
        """
        label = sanitize_hostname(hostname)
        if not label:
            return ""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ""
        if self.network is not None and addr not in self.network:
            log.warning("refusing to register %s for %s: outside the DHCP scope",
                        label, ip)
            return ""
        fqdn = f"{label}.{self.domain}"
        if fqdn in self.reserved:
            log.warning("refusing to register %s for %s: name is configured "
                        "statically", fqdn, ip)
            return ""
        taken = self._by_name.get(fqdn)
        if taken is not None and taken != ip:
            # Two devices offering the same name is ordinary (two phones from
            # the same vendor), not an attack. First one keeps the name; the
            # other stays addressable by IP.
            log.info("%s already resolves to %s; not moving it to %s",
                     fqdn, taken, ip)
            return ""
        old = self._by_ip.get(ip)
        if old and old != label:
            self._by_name.pop(f"{old}.{self.domain}", None)
        self._by_ip[ip] = label
        self._by_name[fqdn] = ip
        self._seen[ip] = time.time()
        self._evict()
        return fqdn

    def forget(self, ip: str) -> None:
        label = self._by_ip.pop(ip, None)
        if label:
            self._by_name.pop(f"{label}.{self.domain}", None)
        self._seen.pop(ip, None)

    def _evict(self) -> None:
        """Drop the least recently registered entries past the cap.

        The table is keyed on addresses a client can influence, so it is only as
        bounded as the sender chooses to be — the same reason `Scope` reaps.
        """
        while len(self._by_ip) > self.max_entries:
            oldest = min(self._seen, key=self._seen.get)   # type: ignore[arg-type]
            self.forget(oldest)

    # ---------------------------------------------------------------- reading
    def name_for(self, ip: str) -> str:
        label = self._by_ip.get(ip)
        return f"{label}.{self.domain}" if label else ""

    def ip_for(self, fqdn: str) -> str:
        return self._by_name.get(fqdn.strip(".").lower(), "")

    def entries(self) -> list[dict]:
        return [{"ip": ip, "name": f"{label}.{self.domain}",
                 "since": int(self._seen.get(ip, 0))}
                for ip, label in sorted(self._by_ip.items())]

    # -------------------------------------------------------------- resolving
    def resolve(self, query: Message) -> Message | None:
        """An authoritative answer for a learned name, or None to carry on.

        Returns NXDOMAIN for unknown names *inside our own domain* rather than
        None: `unknown.lan` has no answer anywhere on the internet, and asking
        an upstream about it publishes the household's naming scheme.
        """
        q = query.question
        if q is None:
            return None
        name = q.name.to_text().strip(".").lower()
        if q.rtype in (Type.A, Type.AAAA, Type.ANY) and name.endswith("." + self.domain):
            ip = self.ip_for(name)
            if not ip:
                return self._reply(query, Rcode.NXDOMAIN)
            addr = ipaddress.ip_address(ip)
            want = Type.AAAA if addr.version == 6 else Type.A
            resp = self._reply(query, Rcode.NOERROR)
            if q.rtype in (want, Type.ANY):
                rd = R.AAAA(ip) if addr.version == 6 else R.A(ip)
                resp.answers.append(RR(q.name, want, Class.IN, self.ttl, rd))
            return resp
        if q.rtype in (Type.PTR, Type.ANY) and name.endswith(("in-addr.arpa", "ip6.arpa")):
            target = address_from_reverse(name)
            if target is None:
                return None                     # not an address shape we handle
            if (self.network is not None
                    and ipaddress.ip_address(target) not in self.network):
                return None                     # not our scope; let it resolve normally
            fqdn = self.name_for(target)
            if not fqdn:
                return self._reply(query, Rcode.NXDOMAIN)
            resp = self._reply(query, Rcode.NOERROR)
            resp.answers.append(RR(q.name, Type.PTR, Class.IN, self.ttl,
                                   R.PTR(Name.from_text(fqdn + "."))))
            return resp
        return None

    @staticmethod
    def _reply(query: Message, rcode: int) -> Message:
        resp = query.reply(rcode)
        resp.set_flag(Flags.AA, True)
        return resp
