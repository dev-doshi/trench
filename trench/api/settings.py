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

import math
from dataclasses import asdict, dataclass, field
from typing import Any

from ..clients.model import mask_ident

#: What `App.apply_config` can adopt into a running process. The names are the
#: appliers themselves; `App.adopters()` maps each to the method that runs it.
ADOPTERS = ("upstream", "cache", "pipeline", "clients", "querylog", "fastpath",
            "prewarm", "gravity", "notary", "sources", "rules", "log", "proxies",
            "updates")


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
    #: Never sent to the browser. A write-only box the operator can set and
    #: cannot read back — the alternative is serving the console password to
    #: anything that can reach `GET /settings`.
    secret: bool = False
    #: Shown, explained, and refused if submitted. For state the file genuinely
    #: cannot set: an editable-looking control that the process ignores is worse
    #: than no control at all.
    readonly: bool = False

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
           placeholder="/var/log/trench/queries.jsonl", adopter="querylog",
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
           help="Installing stages new code; something has to restart Trench to run it."),

    # ── listeners ───────────────────────────────────────────────────────────
    # Every one of these binds a socket, so none of them can be adopted: the
    # form says "restart" rather than pretending otherwise.
    Field_("server.do53.enabled", "Plain DNS (port 53)", "bool", "Listeners",
           applies="restart", help="The LAN listener. Turning this off leaves "
                                   "only the encrypted transports."),
    Field_("server.do53.host", "Plain DNS address", "text", "Listeners",
           applies="restart", placeholder="0.0.0.0"),
    Field_("server.do53.port", "Plain DNS port", "int", "Listeners",
           min=1, max=65535, applies="restart"),
    Field_("server.do53.udp", "Serve UDP", "bool", "Listeners", applies="restart"),
    Field_("server.do53.tcp", "Serve TCP", "bool", "Listeners", applies="restart"),

    Field_("server.dot.host", "DoT address", "text", "Listeners", applies="restart"),
    Field_("server.dot.port", "DoT port", "int", "Listeners", min=1, max=65535,
           applies="restart"),
    Field_("server.dot.cert", "DoT certificate", "text", "Listeners",
           applies="restart", placeholder="/etc/ssl/certs/trench.pem",
           help="Leave empty to use the certificate ACME obtains below."),
    Field_("server.dot.key", "DoT private key", "text", "Listeners", applies="restart"),

    Field_("server.doh.host", "DoH address", "text", "Listeners", applies="restart"),
    Field_("server.doh.port", "DoH port", "int", "Listeners", min=1, max=65535,
           applies="restart"),
    Field_("server.doh.path", "DoH path", "text", "Listeners", applies="restart",
           placeholder="/dns-query"),
    Field_("server.doh.tls", "DoH serves TLS itself", "bool", "Listeners",
           applies="restart", help="Turn off when a reverse proxy terminates TLS."),
    Field_("server.doh.cert", "DoH certificate", "text", "Listeners", applies="restart"),
    Field_("server.doh.key", "DoH private key", "text", "Listeners", applies="restart"),

    Field_("server.doq.host", "DoQ address", "text", "Listeners", applies="restart"),
    Field_("server.doq.port", "DoQ port", "int", "Listeners", min=1, max=65535,
           applies="restart"),
    Field_("server.doq.cert", "DoQ certificate", "text", "Listeners", applies="restart"),
    Field_("server.doq.key", "DoQ private key", "text", "Listeners", applies="restart"),

    Field_("server.doh3.enabled", "DNS-over-HTTP/3", "bool", "Listeners",
           applies="restart"),
    Field_("server.doh3.host", "DoH3 address", "text", "Listeners", applies="restart"),
    Field_("server.doh3.port", "DoH3 port", "int", "Listeners", min=1, max=65535,
           applies="restart"),
    Field_("server.doh3.path", "DoH3 path", "text", "Listeners", applies="restart"),
    Field_("server.doh3.cert", "DoH3 certificate", "text", "Listeners", applies="restart"),
    Field_("server.doh3.key", "DoH3 private key", "text", "Listeners", applies="restart"),

    Field_("server.discovery.enabled", "Advertise encrypted DNS (DDR)", "bool",
           "Listeners", applies="restart",
           help="RFC 9462: lets clients discover this resolver's DoT/DoH "
                "endpoints and upgrade to them."),
    Field_("server.discovery.hostname", "Advertised hostname", "text", "Listeners",
           applies="restart", placeholder="dns.example.home"),
    Field_("server.discovery.ttl", "Advertisement TTL", "int", "Listeners",
           unit="s", min=0, applies="restart"),
    Field_("server.discovery.addresses", "Advertised addresses", "list", "Listeners",
           applies="restart", placeholder="192.168.1.2",
           help="One per line. Empty means the addresses the listener is bound to."),

    # ── connection limits ───────────────────────────────────────────────────
    Field_("server.tcp_idle_timeout", "TCP idle timeout", "float", "Server",
           unit="s", min=0, applies="restart"),
    Field_("server.tcp_max_connections", "Max TCP connections", "int", "Server",
           min=1, applies="restart", help="Per worker."),
    Field_("server.tcp_max_per_client", "Max TCP per client", "int", "Server",
           min=1, applies="restart"),
    Field_("server.tcp_max_inflight", "Max TCP queries in flight", "int", "Server",
           min=1, applies="restart"),
    Field_("server.udp_max_inflight", "Max UDP queries in flight", "int", "Server",
           min=1, applies="restart"),
    Field_("server.fast_path_entries", "Fast-path table size", "int", "Server",
           min=0, adopter="fastpath", help="Recorded replies held for replay."),
    Field_("server.user", "Drop privileges to user", "text", "Server",
           applies="restart", placeholder="trench",
           help="Shed root once the ports are bound. Empty keeps full privileges."),
    Field_("server.group", "…and group", "text", "Server", applies="restart"),

    # ── recursion ───────────────────────────────────────────────────────────
    Field_("upstream.recursion_budget", "Recursion time budget", "float",
           "Resolution", unit="s", min=0.1, max=60, adopter="upstream",
           help="Recursive mode only."),
    Field_("upstream.recursion_max_queries", "Recursion query ceiling", "int",
           "Resolution", min=1, adopter="upstream",
           help="Caps the work one name may cost, which is what makes a "
                "referral loop finite."),
    Field_("upstream.recursion_query_timeout", "Recursion per-query timeout",
           "float", "Resolution", unit="s", min=0.1, max=30, adopter="upstream"),

    # ── cache ───────────────────────────────────────────────────────────────
    Field_("cache.serve_stale_client_timeout", "Wait before serving stale",
           "float", "Cache", unit="s", min=0, max=10, adopter="pipeline",
           help="RFC 8767 recommends at most 1.8s. 0 waits for the real answer."),
    Field_("cache.shared", "Share one cache across workers", "bool", "Cache",
           applies="restart"),
    Field_("cache.shared_slots", "Shared cache slots", "int", "Cache", min=0,
           applies="restart"),
    Field_("cache.shared_payload", "Shared entry size", "int", "Cache",
           unit="B", min=0, applies="restart"),
    Field_("cache.prewarm_top", "Prewarm this many names", "int", "Cache",
           min=0, adopter="prewarm"),
    Field_("cache.prewarm_interval", "Prewarm every", "int", "Cache", unit="s",
           min=1, adopter="prewarm"),

    # ── filtering ───────────────────────────────────────────────────────────
    Field_("filtering.allow", "Always allow", "list", "Filtering",
           adopter="rules", placeholder="bank.example",
           help="One domain per line; these beat every imported block rule. "
                "Ad-hoc rules made from the Policy page live separately."),
    Field_("filtering.deny", "Always block", "list", "Filtering",
           adopter="rules", placeholder="tracker.example"),
    Field_("filtering.protective_sources", "Protective lists", "list", "Filtering",
           adopter="sources",
           help="Fetched like blocklists, but a name on one is never allowed "
                "to be unblocked by a refresh."),
    Field_("filtering.services", "Blocked services", "list", "Filtering",
           adopter="clients", placeholder="tiktok",
           help="Named services blocked for every client that has no group."),
    Field_("filtering.ctags", "Client tags", "list", "Filtering", adopter="clients",
           help="Tags rules may match with $ctag."),
    Field_("filtering.block_page_host", "Block page address", "text", "Filtering",
           applies="restart"),
    Field_("filtering.block_page_port", "Block page port", "int", "Filtering",
           min=1, max=65535, applies="restart"),

    # ── DHCP ────────────────────────────────────────────────────────────────
    Field_("dhcp.enabled", "DHCP server", "bool", "DHCP", applies="restart",
           help="Also needs --allow-dhcp on the command line."),
    Field_("dhcp.server_ip", "This server's address", "text", "DHCP",
           applies="restart"),
    Field_("dhcp.register_dns", "Publish leased hostnames as DNS", "bool", "DHCP",
           applies="restart"),
    Field_("dhcp.scope.network", "Network", "text", "DHCP", applies="restart",
           placeholder="192.168.1.0/24"),
    Field_("dhcp.scope.range_start", "Pool starts at", "text", "DHCP",
           applies="restart"),
    Field_("dhcp.scope.range_end", "Pool ends at", "text", "DHCP", applies="restart"),
    Field_("dhcp.scope.router", "Gateway", "text", "DHCP", applies="restart"),
    Field_("dhcp.scope.dns", "DNS servers offered", "list", "DHCP",
           applies="restart"),
    Field_("dhcp.scope.lease_time", "Lease time", "int", "DHCP", unit="s",
           min=60, applies="restart"),
    Field_("dhcp.scope.domain", "Domain", "text", "DHCP", applies="restart"),

    # ── certificates ────────────────────────────────────────────────────────
    Field_("acme.enabled", "Obtain certificates automatically", "bool",
           "Certificates", applies="restart"),
    Field_("acme.domains", "Certificate names", "list", "Certificates",
           applies="restart"),
    Field_("acme.email", "Account email", "text", "Certificates", applies="restart"),
    Field_("acme.directory", "ACME directory", "text", "Certificates",
           applies="restart",
           placeholder="https://acme-v02.api.letsencrypt.org/directory"),
    Field_("acme.settle", "Wait before validating", "float", "Certificates",
           unit="s", min=0, applies="restart"),

    # ── console ─────────────────────────────────────────────────────────────
    Field_("web.enabled", "Admin console", "bool", "Console", applies="restart",
           help="Turning this off is the only setting that can lock you out of "
                "this page."),
    Field_("web.host", "Console address", "text", "Console", applies="restart",
           help="127.0.0.1 keeps it off the network."),
    Field_("web.port", "Console port", "int", "Console", min=1, max=65535,
           applies="restart"),
    Field_("web.tls", "Serve the console over HTTPS", "bool", "Console",
           applies="restart"),
    Field_("web.cert", "Console certificate", "text", "Console", applies="restart"),
    Field_("web.key", "Console private key", "text", "Console", applies="restart"),
    Field_("web.admin_password", "Set a new admin password", "text", "Console",
           applies="restart", secret=True,
           help="Write-only: it is never sent back to this page. Leave empty to "
                "keep the current one."),

    # ── deployment ──────────────────────────────────────────────────────────
    Field_("data_dir", "Data directory", "text", "Deployment", applies="restart",
           help="Where the database, the compiled lists and the certificates "
                "live. Changing it starts from an empty state."),
    Field_("querylog.db", "Query-log database", "text", "Deployment",
           applies="restart", help="Relative to the data directory."),
    Field_("uvloop", "Use uvloop", "bool", "Deployment", applies="restart",
           help="A faster event loop, when it is installed."),
    Field_("dev", "Development mode", "bool", "Deployment", applies="restart"),
    Field_("allow_dhcp", "DHCP permitted by the command line", "bool", "DHCP",
           applies="restart", readonly=True,
           help="A safety interlock, not a setting: handing out addresses on "
                "someone else's network is disruptive, so it is armed only by "
                "--allow-dhcp when the daemon starts. The config file cannot "
                "turn it on, and this page will not pretend otherwise."),
    Field_("log.json_logs", "Log as JSON", "bool", "Deployment", adopter="log"),
    Field_("updates.index", "Release index", "text", "Updates", adopter="updates"),
    Field_("updates.timeout", "Update timeout", "float", "Updates", unit="s",
           min=1, adopter="updates"),
    Field_("updates.unit", "systemd unit", "text", "Updates", adopter="updates",
           help="Restarted after an update installs."),
]


# ── structured collections ──────────────────────────────────────────────────
# Lists and maps of objects: zones, keys, local records and the rest. They were
# left out of this form on the grounds that "a flat form cannot express them",
# which was true of the form and not of the settings — the result was that the
# console could configure a resolver but not the authoritative server beside it.
#
# One schema, one generic editor. Each collection says whether it is a list of
# objects or a map keyed by name, and what one row looks like; the console
# renders a table of rows from that, exactly as it renders the flat form from
# FIELDS. Values are written back through the same validate-then-write path, so
# pydantic remains the thing that decides what is legal.


@dataclass
class Col:
    name: str                       # field inside one row
    label: str
    type: str = "text"              # text | int | bool | tri | select | list
    options: list[str] = field(default_factory=list)
    placeholder: str = ""
    help: str = ""
    #: Redacted for anyone below admin; see `collection_values`.
    secret: bool = False


@dataclass
class Collection:
    path: str
    label: str
    group: str
    shape: str                      # "list" of objects, or "map" keyed by name
    columns: list[Col]
    help: str = ""
    key_label: str = "Name"         # heading for a map's key column
    applies: str = "adopt"
    adopter: str = ""

    @property
    def restart(self) -> bool:
        return self.applies == "restart"

    @property
    def scalar(self) -> bool:
        """One unnamed column means each entry is a bare value rather than an
        object — a list of plugin paths, a map of address to address."""
        return len(self.columns) == 1 and not self.columns[0].name


_TRI = ["inherit", "on", "off"]

COLLECTIONS: list[Collection] = [
    Collection(
        "clients", "Devices and their policy", "Filtering", "list",
        adopter="clients",
        help="A device may also be exempted with the switch on the Devices "
             "page; this is the same policy, written out in full.",
        columns=[
            Col("ident", "Identifier", placeholder="192.168.1.10"),
            Col("type", "Identified by", "select",
                options=["ip", "cidr", "mac", "clientid", "token"]),
            Col("name", "Name", placeholder="kitchen tablet"),
            Col("block", "Filtering", "bool"),
            Col("group", "Filter group", placeholder="kids"),
            Col("upstream_group", "Upstream set"),
            Col("tags", "Tags", "list", help="Matched by $ctag rules."),
            Col("services", "Blocked services", "list"),
            Col("safe_search", "Safe search", "tri"),
            Col("safe_browse", "Malware protection", "tri"),
            Col("parental", "Parental", "tri"),
        ]),
    Collection(
        "filtering.groups", "Filter groups", "Filtering", "map",
        adopter="sources", key_label="Group",
        help="A named rule set a device can be put in. Changing these refetches "
             "that group's lists.",
        columns=[
            Col("sources", "Blocklist sources", "list"),
            Col("allow", "Always allow", "list"),
            Col("deny", "Always block", "list"),
            Col("inherit", "Also apply the household's rules", "bool"),
        ]),
    Collection(
        "upstream.groups", "Upstream sets", "Resolution", "map",
        adopter="upstream", key_label="Set",
        help="Named servers a device or filter group can be pointed at.",
        columns=[Col("", "Servers", "list",
                     placeholder="tls://9.9.9.9#dns.quad9.net")]),
    Collection(
        "local_records", "Local DNS records", "Resolution", "list",
        adopter="upstream",
        help="Answered from here instead of being resolved.",
        columns=[
            Col("name", "Name", placeholder="nas.home"),
            Col("type", "Type", "select",
                options=["A", "AAAA", "CNAME", "TXT", "MX", "PTR", "SRV", "NS"]),
            Col("answer", "Answer", placeholder="192.168.1.20"),
        ]),
    Collection(
        "zones", "Authoritative zones", "Zones", "list", applies="restart",
        help="Zones this server answers for itself.",
        columns=[
            Col("origin", "Origin", placeholder="home.example."),
            Col("file", "Zone file", placeholder="/data/zones/home.example"),
            Col("dnssec", "Sign with DNSSEC", "bool"),
            Col("nsec3", "Use NSEC3", "bool"),
            Col("nsec3_iterations", "NSEC3 iterations", "int",
                help="RFC 9276 says 0. Higher costs you more than an attacker."),
            Col("nsec3_salt", "NSEC3 salt"),
            Col("allow_transfer", "Allow transfer to", "list"),
            Col("also_notify", "Also notify", "list"),
            Col("allow_update", "Allow updates from", "list"),
            Col("tsig_key", "TSIG key", placeholder="key name"),
        ]),
    Collection(
        "secondaries", "Secondary zones", "Zones", "list", applies="restart",
        help="Zones transferred in from another primary.",
        columns=[
            Col("origin", "Origin", placeholder="example.com."),
            Col("primary", "Primary server", placeholder="192.0.2.1"),
            Col("port", "Port", "int"),
            Col("tsig_key", "TSIG key"),
        ]),
    Collection(
        "tsig_keys", "TSIG keys", "Zones", "list", applies="restart",
        help="Shared secrets that authenticate transfers, NOTIFY and dynamic "
             "updates. The secret is stored in the config file in the clear.",
        columns=[
            Col("name", "Key name", placeholder="transfer-key."),
            Col("algorithm", "Algorithm", "select",
                options=["hmac-sha256.", "hmac-sha384.", "hmac-sha512.",
                         "hmac-sha1.", "hmac-md5.sig-alg.reg.int."]),
            Col("secret", "Secret (base64)", secret=True),
        ]),
    Collection(
        "dhcp.scope.reservations", "Fixed addresses", "DHCP", "map",
        applies="restart", key_label="MAC address",
        help="A device that should always get the same address.",
        columns=[Col("", "Address", placeholder="192.168.1.50")]),
    Collection(
        "plugins", "Plugins", "Deployment", "list", applies="restart",
        help="Loaded at start-up, in order.",
        columns=[Col("", "Module or path", placeholder="/opt/trench/myplugin.py")]),
]

_COL_BY_PATH = {c.path: c for c in COLLECTIONS}

#: Tab order. A field whose group is missing here renders nowhere at all, so
#: `test_every_field_lands_in_a_group_the_form_renders` holds the two together —
#: three notary settings were declared, saved and displayed by nothing.
GROUPS = ["Resolution", "Filtering", "Cache", "Protection", "Security", "Privacy",
          "Listeners", "Server", "Zones", "DHCP", "Certificates", "Console",
          "Updates", "Deployment"]


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
        if f.secret:
            out[f.path] = ""        # set-only; see Field_.secret
            continue
        v = _dig(config, f.path)
        if f.type == "select" and v is not None:
            v = str(v)
        out[f.path] = v
    return out


def _plain(v: Any) -> Any:
    """A collection value as JSON: pydantic models become dicts."""
    if hasattr(v, "model_dump"):
        return v.model_dump()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    return v


REDACTED = "(hidden)"


def collection_values(config, reveal: bool = False) -> dict[str, Any]:
    """Every collection as JSON. Secrets are only included when `reveal`.

    This used to return everything to the lowest role that can read settings,
    TSIG secrets and DoH client tokens included — so a read-only API token was
    enough to sign zone updates and to impersonate any token-identified client.
    Only an admin, who could overwrite those values anyway, sees them.
    """
    out: dict[str, Any] = {}
    for c in COLLECTIONS:
        v = _dig(config, c.path)
        v = _plain(v) if v is not None else ([] if c.shape == "list" else {})
        if not reveal:
            v = _redact(c, v)
        out[c.path] = v
    return out


def _redact(c: Collection, value: Any) -> Any:
    secret_cols = [col.name for col in c.columns if col.secret]
    rows = value if isinstance(value, list) else list(value.values()) \
        if isinstance(value, dict) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for name in secret_cols:
            if row.get(name):
                row[name] = REDACTED
        if c.path == "clients" and "ident" in row:
            row["ident"] = mask_ident(row["ident"], row.get("type", ""))
    return value


def coerce_collection(path: str, value: Any) -> Any:
    """Shape-check one collection. pydantic does the real validation when the
    whole tree is re-validated before it is written, so this only has to refuse
    what would not survive being merged into YAML."""
    c = _COL_BY_PATH.get(path)
    if c is None:
        raise KeyError(path)
    if c.shape == "list":
        if not isinstance(value, list):
            raise ValueError(f"{path} must be a list")
        if not c.scalar and any(not isinstance(x, dict) for x in value):
            raise ValueError(f"every {path} entry must be an object")
        return value
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    if not c.scalar and any(not isinstance(x, dict) for x in value.values()):
        raise ValueError(f"every {path} entry must be an object")
    return value


def describe(config, reveal: bool = False) -> dict[str, Any]:
    return {
        "groups": GROUPS,
        "collections": [{**asdict(c), "restart": c.restart, "scalar": c.scalar}
                        for c in COLLECTIONS],
        "collection_values": collection_values(config, reveal),
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
    if f.readonly:
        raise ValueError(f"{path} cannot be set here: {f.help}")
    if f.type == "bool":
        # `bool("false")` is True, and so is `bool("0")` — every non-empty
        # string is. The console's checkbox sends a real JSON boolean and was
        # never affected, but every other client of this API could only ever
        # turn a setting *on*: the wrong value was written, and the endpoint
        # honestly reported success because it had in fact saved something.
        if isinstance(value, str):
            s = value.strip().lower()
            if s in ("true", "yes", "on", "1"):
                return True
            if s in ("false", "no", "off", "0", ""):
                return False
            raise ValueError(f"{path}: {value!r} is not a boolean")
        return bool(value)
    if f.type == "int":
        # JSON numbers arrive as floats whenever they carry a point or an
        # exponent. `int(1.7)` would quietly save 1, and `int(1e400)` — which
        # JSON parses to infinity — raised OverflowError past the handler's
        # ValueError/TypeError net as a 500.
        if isinstance(value, float) and not value.is_integer():
            raise ValueError(f"{path}: {value!r} is not a whole number")
        return int(value)
    if f.type == "float":
        # `float("nan")`, `NaN` and `Infinity` all parse, and would be written
        # to the config file as `.nan`/`.inf` for every later start to load.
        v = float(value)
        if not math.isfinite(v):
            raise ValueError(f"{path}: {value!r} is not a finite number")
        return v
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
                   if p in _BY_PATH and _BY_PATH[p].restart}
                  | {_COL_BY_PATH[p].label for p in paths
                     if p in _COL_BY_PATH and _COL_BY_PATH[p].restart})


def adopters_for(paths) -> list[str]:
    """The appliers that have to run for this set of changed paths, in the fixed
    order of `ADOPTERS` — some depend on others having run first (the client
    registry is rebuilt from a config the upstream applier may have replaced).

    An unknown path contributes nothing: `coerce` has already rejected those.
    """
    wanted = {_BY_PATH[p].adopter for p in paths
              if p in _BY_PATH and _BY_PATH[p].applies == "adopt"}
    wanted |= {_COL_BY_PATH[p].adopter for p in paths
               if p in _COL_BY_PATH and _COL_BY_PATH[p].applies == "adopt"}
    return [name for name in ADOPTERS if name in wanted]
