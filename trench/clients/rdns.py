"""Names for the addresses in the query log, from the network itself.

The log is a list of addresses. Trench's own DHCP leases name the devices it
hands addresses to, and the operator can name any device by hand, but on the
usual home network neither applies: the router runs DHCP and nobody has typed
anything in. The router does know every name, though — it answers reverse
(PTR) lookups for the addresses it leased — so this asks it.

Everything here is shaped by what those lookups could leak or break:

  * **Private addresses only.** A PTR lookup of a public client address, sent
    to a public resolver, tells that resolver who uses this one. Loopback,
    RFC 1918, CGNAT, ULA and link-local are the only candidates.
  * **Never to a public upstream.** A lookup goes either to `server`, which the
    config refuses unless it is itself a private address, or through the
    pipeline's `ask_privately`, which answers only names in a special-use zone
    that the operator has routed (`[/178.168.192.in-addr.arpa/]192.168.178.1`).
    With neither, nothing is asked and the device stays an address.
  * **Never on the query path.** A background sweep resolves addresses the
    counters or the query log have seen; the API only reads what the sweep
    wrote, so a page never waits on DNS and a flood of spoofed sources cannot
    turn into a flood of lookups (the sweep is capped per round and the table
    per process).
  * **Untrusted text.** A PTR target is whatever the device told the router its
    name was. It is cut to its first label, stripped of anything but letters,
    digits, `-` and `_`, and length-capped, and the source is kept beside it so
    the console can tell a name the router reported from one the operator set.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass

from ..log import get
from ..wire import Class, Message, Question, Type
from ..wire import rdata as R
from ..wire.name import Name
from ..wire.rrtypes import Flags, Rcode
from .names import reverse_name

log = get("rdns")

_UUID = re.compile(r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$", re.I)
_MAC = re.compile(r"^[0-9a-f]{2}([-:_]?[0-9a-f]{2}){5}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{12,}$", re.I)
#: A router's placeholder for an address it has no name for, e.g.
#: `PC-192-168-178-34` or `192-168-178-34`.
_ADDRESSY = re.compile(r"^(pc|host|client|ip|dhcp|unknown)?-?\d{1,3}(-\d{1,3}){3}$", re.I)

MAX_LABEL = 63
MAX_ENTRIES = 1024          # per process; a spoofed-source flood cannot grow it
PER_SWEEP = 64              # lookups per round, so one round is bounded
CONCURRENCY = 4
TIMEOUT = 2.0
NEGATIVE_TTL = 3600.0       # retry an address that had no name after an hour


def is_private(ip: str) -> bool:
    """True for addresses whose reverse zone belongs to this network."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    if a.is_multicast or a.is_unspecified:
        return False
    if a.is_loopback or a.is_link_local:
        return True
    if isinstance(a, ipaddress.IPv4Address):
        return (a.is_private and not a.is_reserved) or a in _CGNAT
    return a in _ULA


_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_ULA = ipaddress.ip_network("fc00::/7")


def parse_server(spec: str) -> tuple[str, int]:
    """`192.168.178.1`, `192.168.178.1:53`, `fd00::1` or `[fd00::1]:53`.

    Plain DNS to a private address, and nothing else: the one thing this
    server is sent is a list of the household's addresses.
    """
    s = spec.strip()
    host, port = s, 53
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        if rest:
            if not rest.startswith(":"):
                raise ValueError(f"cannot read {spec!r} as an address")
            port = _port(rest[1:], spec)
    elif s.count(":") == 1:
        host, _, p = s.partition(":")
        port = _port(p, spec)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(f"{spec!r} is not an IP address; give the router's "
                         "address, such as 192.168.1.1") from None
    if not is_private(host):
        raise ValueError(f"{host} is a public address; device names may only "
                         "be asked of a server on this network")
    return host, port


def _port(p: str, spec: str) -> int:
    if not p.isdigit() or not 0 < int(p) < 65536:
        raise ValueError(f"{spec!r} has no valid port")
    return int(p)


def looks_random(label: str) -> bool:
    """A name that identifies nothing a person would recognise."""
    return bool(_UUID.match(label) or _MAC.match(label) or _HEX.match(label)
                or _ADDRESSY.match(label))


def display_name(target: str, *, hide_random: bool = True) -> str:
    """The label to show for a PTR target, or "" when it names nothing.

    `MacBook-Pro-von-Dev.fritz.box.` -> `MacBook-Pro-von-Dev`. Only the first
    label is kept: a device cannot register `bank.com` and be shown as it,
    and the router's own zone (`fritz.box`, `lan`) is the same on every row.
    """
    name = (target or "").strip().rstrip(".")
    if not name or name.lower().endswith(("in-addr.arpa", "ip6.arpa")):
        return ""
    label = name.split(".", 1)[0]
    label = re.sub(r"[^A-Za-z0-9_-]+", "-", label).strip("-_")[:MAX_LABEL]
    if not label or (hide_random and looks_random(label)):
        return ""
    return label


@dataclass
class _Entry:
    name: str          # "" means "asked, and there is no usable name"
    fqdn: str
    until: float       # monotonic


def ptr_query(ip: str) -> Message:
    q = Message(id=0)
    q.set_flag(Flags.RD, True)
    q.questions.append(Question(Name.from_text(reverse_name(ip)), Type.PTR, Class.IN))
    return q


def ptr_targets(resp: Message | None) -> list[str]:
    """PTR targets from an answer, by the rdata's own class — never `rtype`,
    which a hostile answer can set to anything."""
    if resp is None or resp.rcode != Rcode.NOERROR:
        return []
    return [rr.rdata.name.to_text() for rr in resp.answers
            if isinstance(rr.rdata, R.PTR)]


Ask = Callable[[Message], Awaitable[Message | None]]


class ClientNames:
    """Reverse-looked-up names for client addresses, refreshed off the query path."""

    def __init__(self, ask: Ask, *, ttl: float = 6 * 3600, hide_random: bool = True,
                 clock=time.monotonic):
        self.ask = ask
        self.ttl = max(60.0, float(ttl))
        self.hide_random = hide_random
        self._clock = clock
        self._names: OrderedDict[str, _Entry] = OrderedDict()
        self._lock = asyncio.Lock()
        self.lookups = 0
        self.failures = 0

    def name_for(self, ip: str) -> str:
        e = self._names.get(ip)
        return e.name if e is not None else ""

    def known(self) -> dict[str, tuple[str, str]]:
        """ip -> (short name, full PTR target), for addresses that have one.

        Entries past their lifetime are still served until the next sweep
        replaces them: an old name is better than a flicker back to an address.
        """
        return {ip: (e.name, e.fqdn) for ip, e in self._names.items() if e.name}

    def forget(self) -> None:
        self._names.clear()

    def due(self, ips: Iterable[str]) -> list[str]:
        now = self._clock()
        out, seen = [], set()
        for ip in ips:
            if ip in seen or not is_private(ip):
                continue
            seen.add(ip)
            e = self._names.get(ip)
            if e is None or e.until <= now:
                out.append(ip)
        return out

    async def sweep(self, ips: Iterable[str]) -> int:
        """Look up the addresses whose name is missing or old. Returns how many
        were asked. One sweep at a time; a second caller waits rather than
        asking the same questions again."""
        async with self._lock:
            todo = self.due(ips)[:PER_SWEEP]
            if not todo:
                return 0
            gate = asyncio.Semaphore(CONCURRENCY)

            async def one(ip: str) -> None:
                async with gate:
                    await self._lookup(ip)

            await asyncio.gather(*(one(ip) for ip in todo))
            return len(todo)

    async def _lookup(self, ip: str) -> None:
        self.lookups += 1
        try:
            resp = await asyncio.wait_for(self.ask(ptr_query(ip)), TIMEOUT)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — one silent device must not end the sweep
            self.failures += 1
            log.debug("reverse lookup of %s failed: %s", ip, e)
            self._store(ip, "", "", NEGATIVE_TTL)
            return
        name = fqdn = ""
        for target in ptr_targets(resp):
            shown = display_name(target, hide_random=self.hide_random)
            if shown:
                name, fqdn = shown, target.rstrip(".")
                break
        self._store(ip, name, fqdn, self.ttl if name else NEGATIVE_TTL)

    def _store(self, ip: str, name: str, fqdn: str, ttl: float) -> None:
        prev = self._names.pop(ip, None)
        if not name and prev is not None and prev.name:
            # A router that briefly does not answer must not erase a name it
            # gave an hour ago; keep it, and ask again sooner.
            name, fqdn = prev.name, prev.fqdn
        self._names[ip] = _Entry(name, fqdn, self._clock() + ttl)
        while len(self._names) > MAX_ENTRIES:
            self._names.popitem(last=False)
