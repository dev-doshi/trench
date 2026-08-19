"""The editable configuration surface, described once so the UI can render it.

The console used to expose a single toggle and explain, at length, that
everything else lived in the config file. That was backwards: the file is where
settings are *stored*, not a reason they cannot be *changed*. Editing here still
writes YAML — the file stays reviewable, diffable and restorable, and anything
written by hand survives — it is just no longer the only way in.

Each field carries enough metadata for a form to be generated from it, so the UI
has no second copy of this list to fall out of date with. `restart` marks a
setting the running process cannot adopt in place (sockets, worker counts); it
is saved and takes effect next start, and the UI says so rather than pretending.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Field_:
    path: str                       # dotted path into the config tree
    label: str
    type: str                       # bool | int | float | text | select | list
    group: str
    help: str = ""
    options: list[str] = field(default_factory=list)
    min: float | None = None
    max: float | None = None
    unit: str = ""
    restart: bool = False
    placeholder: str = ""


# Grouped in the order an operator meets them. Help text is one clause, present
# only where the label genuinely is not enough — this is a form, not a manual.
FIELDS: list[Field_] = [
    # ── resolution ──────────────────────────────────────────────────────────
    Field_("upstream.mode", "Resolution mode", "select", "Resolution",
           options=["forward", "recursive"],
           help="Forward to an upstream resolver, or resolve from the root yourself."),
    Field_("upstream.servers", "Upstream servers", "list", "Resolution",
           placeholder="tls://9.9.9.9#dns.quad9.net",
           help="One per line. Used in forward mode."),
    Field_("upstream.strategy", "Upstream selection", "select", "Resolution",
           options=["sequential", "parallel", "fastest", "weighted"]),
    Field_("upstream.timeout", "Upstream timeout", "float", "Resolution",
           unit="s", min=0.1, max=30),
    Field_("upstream.dnssec", "Validate DNSSEC", "bool", "Resolution",
           help="Recursive mode only. Refuses answers that fail validation."),
    Field_("upstream.qname_min", "QNAME minimisation", "bool", "Resolution",
           help="Recursive mode only. Ask each server only the part of the name it needs."),
    Field_("upstream.ecs", "Client subnet", "select", "Resolution",
           options=["off", "strip", "forward"],
           help="Whether a client's subnet is sent upstream."),
    Field_("upstream.trust_ad", "Trust upstream DNSSEC claims", "select", "Resolution",
           options=["auto", "always", "never"],
           help="'auto' keeps the AD bit only from authenticated transports."),
    Field_("upstream.udp_source_ports", "UDP source ports", "int", "Resolution",
           min=0, max=8192,
           help="Spread upstream queries over this many ports; 0 opens one per query."),

    # ── filtering ───────────────────────────────────────────────────────────
    Field_("filtering.enabled", "Filtering", "bool", "Filtering"),
    Field_("filtering.block_mode", "Blocked answer", "select", "Filtering",
           options=["zero_ip", "nxdomain", "refused", "nodata", "custom_ip"],
           help="What a blocked name resolves to."),
    Field_("filtering.block_ipv4", "Blocked IPv4", "text", "Filtering"),
    Field_("filtering.block_ipv6", "Blocked IPv6", "text", "Filtering"),
    Field_("filtering.cname_inspect", "Inspect CNAME targets", "bool", "Filtering",
           help="Catches trackers hidden behind a first-party CNAME."),
    Field_("filtering.ede", "Explain blocks in-band", "bool", "Filtering",
           help="RFC 8914: attach the reason so dig and browsers can show it."),
    Field_("filtering.sources", "Blocklist sources", "list", "Filtering",
           placeholder="https://example.org/hosts.txt",
           help="One URL or file path per line."),
    Field_("filtering.safe_search", "Force safe search", "bool", "Filtering"),
    Field_("filtering.safe_browse", "Malware and phishing protection", "bool", "Filtering"),
    Field_("filtering.parental", "Adult content protection", "bool", "Filtering"),
    Field_("gravity.refresh_hours", "Refresh blocklists every", "int", "Filtering",
           unit="h", min=0, max=720, help="0 disables automatic refresh."),

    # ── cache ───────────────────────────────────────────────────────────────
    Field_("cache.enabled", "Cache", "bool", "Cache"),
    Field_("cache.max_entries", "Maximum entries", "int", "Cache", min=0, max=10_000_000),
    Field_("cache.min_ttl", "Minimum TTL", "int", "Cache", unit="s", min=0, max=86_400),
    Field_("cache.max_ttl", "Maximum TTL", "int", "Cache", unit="s", min=1, max=604_800),
    Field_("cache.negative_ttl", "Negative TTL", "int", "Cache", unit="s", min=0, max=86_400),
    Field_("cache.serve_stale", "Serve stale on upstream failure", "bool", "Cache",
           help="RFC 8767. Keeps answering from expired data when refresh fails."),
    Field_("cache.prefetch", "Prefetch popular names", "bool", "Cache"),
    Field_("cache.prewarm", "Keep learned names warm", "bool", "Cache"),

    # ── protection ──────────────────────────────────────────────────────────
    Field_("security.rate_limit", "Rate limit per client", "float", "Protection",
           unit="q/s", min=0, max=100_000, help="0 disables."),
    Field_("security.rate_burst", "Burst allowance", "int", "Protection",
           min=0, max=100_000),
    Field_("security.rebinding_protection", "DNS rebinding protection", "bool", "Protection",
           help="Strips private addresses out of public answers."),
    Field_("security.block_doh_canary", "Keep browsers on this resolver", "bool", "Protection",
           help="Refuses Firefox's canary name so it does not switch to its own DNS."),
    Field_("security.use_0x20", "0x20 query randomisation", "bool", "Protection",
           help="Extra spoofing resistance; a few upstreams mishandle it."),
    Field_("security.dns_cookies", "DNS cookies", "bool", "Protection"),
    Field_("security.dga_detection", "Detect generated domains", "bool", "Protection",
           help="Flags algorithmically-generated names used by malware."),
    Field_("security.dga_block", "Block confirmed generated domains", "bool", "Protection"),
    Field_("security.tunnel_detection", "Detect DNS tunnelling", "bool", "Protection"),
    Field_("security.tunnel_block", "Block DNS tunnelling", "bool", "Protection"),

    # ── privacy ─────────────────────────────────────────────────────────────
    Field_("querylog.enabled", "Query log", "bool", "Privacy"),
    Field_("querylog.privacy_level", "What is recorded", "select", "Privacy",
           options=["0", "1", "2", "3"],
           help="0 everything · 1 no client IPs · 2 IPs and names hashed · 3 nothing on disk."),
    Field_("querylog.retention_days", "Keep records for", "int", "Privacy",
           unit="days", min=0, max=3650),

    # ── server ──────────────────────────────────────────────────────────────
    Field_("server.workers", "Worker processes", "int", "Server", min=0, max=64,
           restart=True, help="0 uses one per CPU."),
    Field_("server.fast_path", "Wire-resident fast path", "bool", "Server",
           help="Replays recorded replies for repeat queries."),
    Field_("server.edns_udp_size", "EDNS UDP size", "int", "Server",
           unit="B", min=512, max=4096, restart=True),
    Field_("server.dot.enabled", "DNS-over-TLS", "bool", "Server", restart=True),
    Field_("server.doh.enabled", "DNS-over-HTTPS", "bool", "Server", restart=True),
    Field_("server.doq.enabled", "DNS-over-QUIC", "bool", "Server", restart=True),
    Field_("log.level", "Log level", "select", "Server",
           options=["debug", "info", "warning", "error"]),
]

GROUPS = ["Resolution", "Filtering", "Cache", "Protection", "Privacy", "Server"]


def _dig(obj: Any, path: str) -> Any:
    for part in path.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj


def current(config) -> dict[str, Any]:
    """The value of every editable field, keyed by path."""
    out: dict[str, Any] = {}
    for f in FIELDS:
        v = _dig(config, f.path)
        if f.type == "select" and v is not None:
            v = str(v)
        out[f.path] = v
    return out


def describe(config) -> dict[str, Any]:
    return {
        "groups": GROUPS,
        "fields": [asdict(f) for f in FIELDS],
        "values": current(config),
    }


_BY_PATH = {f.path: f for f in FIELDS}


def coerce(path: str, value: Any) -> Any:
    """Turn one submitted value into what the config model expects.

    Only fields in FIELDS are writable — an unknown path is rejected rather than
    merged, so this endpoint cannot be used to set arbitrary configuration.
    """
    f = _BY_PATH.get(path)
    if f is None:
        raise KeyError(path)
    if f.type == "bool":
        return bool(value)
    if f.type == "int":
        return int(value)
    if f.type == "float":
        return float(value)
    if f.type == "list":
        if isinstance(value, str):
            return [ln.strip() for ln in value.splitlines() if ln.strip()]
        return [str(x) for x in (value or [])]
    if f.type == "select":
        s = str(value)
        if f.options and s not in f.options:
            raise ValueError(f"{path}: {s!r} is not one of {f.options}")
        # selects carrying numbers (privacy level) go back as numbers
        return int(s) if s.lstrip("-").isdigit() else s
    return str(value)


def merge(tree: dict, path: str, value: Any) -> None:
    """Set a dotted path inside a plain dict, creating the branch as needed."""
    parts = path.split(".")
    node = tree
    for p in parts[:-1]:
        nxt = node.get(p)
        if not isinstance(nxt, dict):
            nxt = node[p] = {}
        node = nxt
    node[parts[-1]] = value


def needs_restart(paths: list[str]) -> list[str]:
    return sorted({_BY_PATH[p].label for p in paths if p in _BY_PATH and _BY_PATH[p].restart})
