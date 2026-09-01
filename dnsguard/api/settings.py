"""The editable configuration surface, described once so the UI can render it.

The console used to expose a single toggle and explain, at length, that
everything else lived in the config file. That was backwards: the file is where
settings are *stored*, not a reason they cannot be *changed*. Editing here still
writes YAML — the file stays reviewable, diffable and restorable, and anything
written by hand survives — it is just no longer the only way in.

Each field carries enough metadata for a form to be generated from it, so the UI
has no second copy of this list to fall out of date with.

`applies` is the other half of that, and it is the half that used to be wrong.
Writing a setting to the file is easy; making the *running* process obey it is
not, and the two are separate questions:

    live     nothing to do — the code reads `self.config` when it needs this,
             so the new value is in force the moment the tree is swapped.
    adopt    something has to be rebuilt or re-copied. `adopter` names which of
             `App`'s appliers owns that, and `App.apply_config` dispatches on it.
    restart  the process genuinely cannot adopt it (sockets, worker counts).
             Saved, in force next start, and the UI says so.

`restart` is therefore derived from `applies` rather than declared beside it.
It used to be its own hand-maintained flag, which is how eight of the nine
Resolution settings came to be saved, badged as live, and then ignored by the
process that was supposed to obey them. `tests/test_settings_apply.py` holds the
contract: every field declares a disposition, and every `adopt` field names an
adopter `App` actually has.

Settings deliberately left out of this form: `clients`, `zones`, `tsig_keys`,
`secondaries`, `local_records`, `plugins` and `dhcp.scope` are structured lists
a flat form cannot express (clients have their own CRUD API); `data_dir`,
`dev`, `uvloop`, `querylog.db` and the per-transport host/port/cert triples
belong to the deployment rather than to policy, and are edited in the file.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

#: What `App.apply_config` can adopt into a running process. The names are the
#: appliers themselves; `App.adopters()` maps each to the method that runs it.
ADOPTERS = ("upstream", "cache", "pipeline", "clients", "querylog", "fastpath",
            "prewarm", "gravity", "notary", "sources", "log", "proxies", "updates")


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
    placeholder: str = ""
    applies: str = "adopt"          # live | adopt | restart
    adopter: str = ""               # which App applier owns it, when adopting

    @property
    def restart(self) -> bool:
        return self.applies == "restart"


# Grouped in the order an operator meets them. Help text is one clause, present
# only where the label genuinely is not enough — this is a form, not a manual.
FIELDS: list[Field_] = [
    # ── resolution ──────────────────────────────────────────────────────────
    Field_("upstream.mode", "Resolution mode", "select", "Resolution",
           options=["forward", "recursive"], adopter="upstream",
           help="Forward to an upstream resolver, or resolve from the root yourself."),
    Field_("upstream.servers", "Upstream servers", "list", "Resolution",
           placeholder="tls://9.9.9.9#dns.quad9.net", adopter="upstream",
           help="One per line. Used in forward mode."),
    Field_("upstream.strategy", "Upstream selection", "select", "Resolution",
           options=["sequential", "parallel", "fastest", "weighted"], adopter="upstream"),
    Field_("upstream.timeout", "Upstream timeout", "float", "Resolution",
           unit="s", min=0.1, max=30, adopter="upstream"),
    Field_("upstream.dnssec", "Validate DNSSEC", "bool", "Resolution", adopter="upstream",
           help="Recursive mode only. Refuses answers that fail validation."),
    Field_("upstream.qname_min", "QNAME minimisation", "bool", "Resolution", adopter="upstream",
           help="Recursive mode only. Ask each server only the part of the name it needs."),
    Field_("upstream.verify", "Verify upstream certificates", "bool", "Resolution",
           adopter="upstream",
           help="Applies to DoT, DoH and DoQ upstreams. Turn off only to test."),
    Field_("upstream.ecs", "Client subnet", "select", "Resolution",
           options=["off", "strip", "forward"], applies="live",
           help="Whether a client's subnet is sent upstream."),
    Field_("upstream.trust_ad", "Trust upstream DNSSEC claims", "select", "Resolution",
           options=["auto", "always", "never"], adopter="upstream",
           help="'auto' keeps the AD bit only from authenticated transports."),
    Field_("upstream.udp_source_ports", "UDP source ports", "int", "Resolution",
           min=0, max=8192, adopter="upstream",
           help="Spread upstream queries over this many ports; 0 opens one per query."),

    # ── filtering ───────────────────────────────────────────────────────────
    Field_("filtering.enabled", "Filtering", "bool", "Filtering", applies="live"),
    Field_("filtering.block_mode", "Blocked answer", "select", "Filtering",
           options=["zero_ip", "nxdomain", "refused", "nodata", "custom_ip"], applies="live",
           help="What a blocked name resolves to."),
    Field_("filtering.block_ipv4", "Blocked IPv4", "text", "Filtering", applies="live"),
    Field_("filtering.block_ipv6", "Blocked IPv6", "text", "Filtering", applies="live"),
    Field_("filtering.cname_inspect", "Inspect CNAME targets", "bool", "Filtering",
           applies="live", help="Catches trackers hidden behind a first-party CNAME."),
    Field_("filtering.ede", "Explain blocks in-band", "bool", "Filtering", adopter="pipeline",
           help="RFC 8914: attach the reason so dig and browsers can show it."),
    Field_("filtering.sources", "Blocklist sources", "list", "Filtering",
           placeholder="https://example.org/hosts.txt", adopter="sources",
           help="One URL or file path per line."),
    Field_("filtering.ip_sources", "Address lists", "list", "Filtering",
           placeholder="https://example.org/badnets.txt", adopter="sources",
           help="Lists of IPs/CIDRs. An answer pointing into one is blocked "
                "whatever its name was."),
    Field_("filtering.block_answer_ips", "Block on the answer's address", "bool",
           "Filtering", applies="live",
           help="Applies the address lists above to every answer."),
    Field_("filtering.assertions", "Policy assertions", "list", "Filtering",
           placeholder="bank.example must resolve", applies="live",
           help="Checked against every blocklist refresh. A refresh that would "
                "break one of these is reported and not adopted."),
    Field_("filtering.ech", "Encrypted Client Hello", "select", "Filtering",
           options=["pass", "strip"], applies="live",
           help="Strip downgrades clients to a visible TLS server name; it takes "
                "nothing away from the filtering done here, so pass is the default."),
    Field_("filtering.safe_search", "Force safe search", "bool", "Filtering",
           adopter="clients"),
    Field_("filtering.safe_browse", "Malware and phishing protection", "bool", "Filtering",
           adopter="clients"),
    Field_("filtering.parental", "Adult content protection", "bool", "Filtering",
           adopter="clients"),
    Field_("querylog.export", "Stream the query log", "text", "Privacy",
           placeholder="/var/log/dnsguard/queries.jsonl", adopter="querylog",
           help="One JSON object per query, for a log shipper or jq. '-' writes "
                "to stdout; empty switches it off."),
    Field_("security.notary", "Notarised names", "list", "Security",
           placeholder="bank.example", adopter="notary",
           help="Resolved through every upstream and compared. Disagreement is "
                "reported, never acted on."),
    Field_("security.notary_interval", "Notary interval", "int", "Security",
           unit="s", min=0, max=86400, adopter="notary",
           help="0 switches the comparison off."),
    Field_("security.silence_ledger", "Track devices that stop asking", "bool",
           "Security", applies="restart",
           help="Reports devices still on the network that have gone quiet — the "
                "visible trace of an app using its own encrypted resolver."),
    Field_("upstream.trust_anchors", "Root trust anchors", "text", "Resolution",
           placeholder="/var/lib/unbound/root.key", adopter="upstream",
           help="Empty uses <data_dir>/root.key if present, else the anchors "
                "built into this release."),
    Field_("gravity.refresh_hours", "Refresh blocklists every", "int", "Filtering",
           unit="h", min=0, max=720, adopter="gravity",
           help="0 disables automatic refresh."),
    Field_("filtering.block_page", "Serve an explainer page", "bool", "Filtering",
           applies="restart",
           help="Needs 'Blocked answer' set to custom_ip pointing at this host."),

    # ── cache ───────────────────────────────────────────────────────────────
    Field_("cache.enabled", "Cache", "bool", "Cache", adopter="cache"),
    Field_("cache.max_entries", "Maximum entries", "int", "Cache", min=0, max=10_000_000,
           adopter="cache"),
    Field_("cache.min_ttl", "Minimum TTL", "int", "Cache", unit="s", min=0, max=86_400,
           adopter="cache"),
    Field_("cache.max_ttl", "Maximum TTL", "int", "Cache", unit="s", min=1, max=604_800,
           adopter="cache"),
    Field_("cache.negative_ttl", "Negative TTL", "int", "Cache", unit="s", min=0, max=86_400,
           adopter="cache"),
    Field_("cache.serve_stale", "Serve stale on upstream failure", "bool", "Cache",
           adopter="cache",
           help="RFC 8767. Keeps answering from expired data when refresh fails."),
    Field_("cache.serve_stale_max", "Keep stale entries for", "int", "Cache",
           unit="s", min=0, max=604_800, adopter="cache"),
    Field_("cache.prefetch", "Prefetch popular names", "bool", "Cache", applies="live"),
    Field_("cache.prewarm", "Keep learned names warm", "bool", "Cache", adopter="prewarm"),
    Field_("cache.persist", "Save the cache across restarts", "bool", "Cache", applies="live"),

    # ── protection ──────────────────────────────────────────────────────────
    Field_("security.rate_limit", "Rate limit per client", "float", "Protection",
           unit="q/s", min=0, max=100_000, adopter="pipeline", help="0 disables."),
    Field_("security.rate_burst", "Burst allowance", "int", "Protection",
           min=0, max=100_000, adopter="pipeline"),
    Field_("security.rebinding_protection", "DNS rebinding protection", "bool", "Protection",
           adopter="pipeline", help="Strips private addresses out of public answers."),
    Field_("security.local_suffixes", "Local domain suffixes", "list", "Protection",
           placeholder="lan", adopter="pipeline",
           help="Names under these may return private addresses."),
    Field_("security.block_doh_canary", "Keep browsers on this resolver", "bool", "Protection",
           applies="live",
           help="Refuses Firefox's canary name so it does not switch to its own DNS."),
    Field_("security.use_0x20", "0x20 query randomisation", "bool", "Protection",
           adopter="pipeline",
           help="Extra spoofing resistance; a few upstreams mishandle it."),
    Field_("security.dns_cookies", "DNS cookies", "bool", "Protection", adopter="pipeline"),
    Field_("security.trusted_proxies", "Trusted reverse proxies", "list", "Protection",
           placeholder="10.0.0.0/24", adopter="proxies",
           help="Only these peers' X-Forwarded-For is believed. Empty ignores the header."),
    Field_("security.dga_detection", "Detect generated domains", "bool", "Protection",
           adopter="pipeline",
           help="Flags algorithmically-generated names used by malware."),
    Field_("security.dga_block", "Block confirmed generated domains", "bool", "Protection",
           adopter="pipeline"),
    Field_("security.dga_threshold", "Generated-domain threshold", "float", "Protection",
           min=0, max=1, adopter="pipeline", help="Higher flags fewer names."),
    Field_("security.tunnel_detection", "Detect DNS tunnelling", "bool", "Protection",
           adopter="pipeline"),
    Field_("security.tunnel_block", "Block DNS tunnelling", "bool", "Protection",
           adopter="pipeline"),
    Field_("security.tunnel_threshold", "Tunnelling threshold", "float", "Protection",
           min=0, max=1, adopter="pipeline", help="Higher flags fewer names."),

    # ── privacy ─────────────────────────────────────────────────────────────
    Field_("querylog.enabled", "Query log", "bool", "Privacy", adopter="querylog"),
    Field_("querylog.privacy_level", "What is recorded", "select", "Privacy",
           options=["0", "1", "2", "3"], adopter="querylog",
           help="0 everything · 1 no client IPs · 2 IPs and names salted-hashed, "
                "answers dropped · 3 nothing on disk."),
    Field_("querylog.retention_days", "Keep records for", "int", "Privacy",
           unit="days", min=0, max=3650, adopter="querylog"),

    # ── server ──────────────────────────────────────────────────────────────
    Field_("server.workers", "Worker processes", "int", "Server", min=0, max=64,
           applies="restart", help="0 uses one per CPU."),
    Field_("server.fast_path", "Wire-resident fast path", "bool", "Server", adopter="fastpath",
           help="Replays recorded replies for repeat queries."),
    Field_("server.edns_udp_size", "EDNS UDP size", "int", "Server",
           unit="B", min=512, max=4096, applies="live"),
    Field_("server.dot.enabled", "DNS-over-TLS", "bool", "Server", applies="restart"),
    Field_("server.doh.enabled", "DNS-over-HTTPS", "bool", "Server", applies="restart"),
    Field_("server.doq.enabled", "DNS-over-QUIC", "bool", "Server", applies="restart"),
    Field_("log.level", "Log level", "select", "Server",
           options=["debug", "info", "warning", "error"], adopter="log"),

    # ── updates ─────────────────────────────────────────────────────────────
    # Whether these can be adopted matters more than usual: an operator turning
    # automatic updates *off* must not have to restart the resolver for that to
    # take effect, which is precisely when they would be turning it off.
    Field_("updates.mode", "Updates", "select", "Updates",
           options=["off", "notify", "auto"], adopter="updates",
           help="Notify checks and tells you; auto also installs, inside the window."),
    Field_("updates.channel", "Release channel", "select", "Updates",
           options=["stable", "prerelease"], adopter="updates"),
    Field_("updates.check_interval_hours", "Check for updates every", "int", "Updates",
           unit="hours", min=0, max=720, adopter="updates", help="0 stops checking."),
    Field_("updates.window", "Maintenance window", "text", "Updates",
           placeholder="03:00-05:00", adopter="updates",
           help="Local time; automatic updates wait for it. Empty means any time."),
    Field_("updates.restart", "After installing", "select", "Updates",
           options=["manual", "systemd"], adopter="updates",
           help="Installing stages new code; something has to restart DNSGuard to run it."),
]

GROUPS = ["Resolution", "Filtering", "Cache", "Protection", "Privacy", "Server", "Updates"]


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
        # `restart` is derived, not stored, so the badge the operator sees and
        # the behaviour of the running process cannot say different things.
        "fields": [{**asdict(f), "restart": f.restart} for f in FIELDS],
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
    return sorted({_BY_PATH[p].label for p in paths
                   if p in _BY_PATH and _BY_PATH[p].restart})


def adopters_for(paths) -> list[str]:
    """The appliers that have to run for this set of changed paths, in the fixed
    order of `ADOPTERS` — some depend on others having run first (the client
    registry is rebuilt from a config the upstream applier may have replaced).

    An unknown path contributes nothing: `coerce` has already rejected those.
    """
    wanted = {_BY_PATH[p].adopter for p in paths
              if p in _BY_PATH and _BY_PATH[p].applies == "adopt"}
    return [name for name in ADOPTERS if name in wanted]
