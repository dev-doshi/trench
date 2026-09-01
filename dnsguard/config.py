"""Configuration model (pydantic v2), loaded and validated from one YAML file.

One validated tree is the single source of truth at boot; the live API mutates
a copy and triggers a reload. Extended per phase — fields here cover P0/P1.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .errors import ConfigError


class Section(BaseModel):
    """Base for every configuration section: an unknown key is an error.

    Pydantic drops keys it does not recognise. That turns a misspelling, or a
    wrong indent — `rate_limit` under `server:` rather than `security:` — into a
    setting that is silently absent, so the protection the operator believes they
    configured is simply off and nothing anywhere says otherwise. Refusing the
    file is the only outcome that cannot be misread.
    """

    model_config = ConfigDict(extra="forbid")


class Do53Config(Section):
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 5354
    udp: bool = True
    tcp: bool = True


class DoTConfig(Section):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8853
    cert: str | None = None
    key: str | None = None


class DoHConfig(Section):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8443
    path: str = "/dns-query"
    tls: bool = False
    cert: str | None = None
    key: str | None = None


class DoQConfig(Section):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8854
    cert: str | None = None
    key: str | None = None


class DoH3Config(Section):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8444
    path: str = "/dns-query"
    cert: str | None = None
    key: str | None = None


class DiscoveryConfig(Section):
    """Advertise this resolver's encrypted endpoints (RFC 9462 DDR / 9463 DNR).

    Off by default because it needs one thing that cannot be defaulted: a name
    clients can authenticate. `hostname` must be a name you control, certified
    for this server (the ACME dns-01 flow here can do that from your own zone)
    and resolving to this box. Without it clients ignore the designation, so
    DNSGuard logs a warning rather than publishing something inert.
    """
    enabled: bool = False
    hostname: str = ""                # the authentication-domain-name
    ttl: int = 300
    # Addresses to put in the DHCP (DNR) option, i.e. this server's LAN
    # addresses. Empty is valid: the client then resolves `hostname` itself.
    addresses: list[str] = Field(default_factory=list)


class ServerConfig(Section):
    do53: Do53Config = Field(default_factory=Do53Config)
    dot: DoTConfig = Field(default_factory=DoTConfig)
    doh: DoHConfig = Field(default_factory=DoHConfig)
    doq: DoQConfig = Field(default_factory=DoQConfig)
    doh3: DoH3Config = Field(default_factory=DoH3Config)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    edns_udp_size: int = 1232
    workers: int = 1            # Do53 worker processes (SO_REUSEPORT); 0 = auto (CPU count)
    # Stream (TCP/DoT) connection bounds. Without them, connections opened and
    # then abandoned are held for as long as the peer keeps the socket alive.
    tcp_idle_timeout: float = 10.0   # RFC 7766 §6.2.3; 0 disables
    tcp_max_connections: int = 512   # per worker
    tcp_max_per_client: int = 32
    tcp_max_inflight: int = 16       # pipelined queries answered at once per connection
    # Cap on UDP queries in flight per worker. Rate limiting runs inside the
    # pipeline, so without this a flood pays for a task and a parse before
    # anything can refuse it. 0 disables.
    udp_max_inflight: int = 2048
    # Wire-resident fast path: answer a repeat query by replaying the bytes the
    # pipeline produced for it, patching only the transaction id and the TTLs.
    # It declines anything it cannot reproduce exactly (see engine/fastpath.py),
    # so turning it off changes throughput and nothing else.
    fast_path: bool = True
    fast_path_entries: int = 16_384
    user: str | None = None     # drop to this user after binding privileged ports
    group: str | None = None    # drop to this group (defaults to the user's primary group)


class UpstreamConfig(Section):
    servers: list[str] = Field(default_factory=lambda: ["1.1.1.1:53", "8.8.8.8:53"])
    strategy: Literal["sequential", "parallel", "fastest", "weighted"] = "parallel"
    timeout: float = 4.0
    mode: Literal["forward", "recursive"] = "forward"
    # --- recursive mode only ---
    # QNAME minimization (RFC 9156): ask each server only the part of the name
    # it needs to answer, so the root and the TLDs never see the full name.
    qname_min: bool = True
    # Wall-clock and packet ceilings for one client question, including the
    # side resolutions it spawns to find nameserver addresses. These are what
    # stop a deep or hostile branch of the tree from turning one query into an
    # unbounded amount of traffic; raise them only with a reason.
    recursion_budget: float = 5.0
    recursion_max_queries: int = 40
    # How long to wait on one authoritative server before trying the next. Kept
    # well under the whole-resolution budget on purpose: a delegation usually
    # has several nameservers, and waiting the full budget on the first one
    # means never reaching the ones that work.
    recursion_query_timeout: float = 1.5
    # How many source ports to spread plain-UDP upstream queries over. Opening a
    # socket per query costs 67 us and buys the full ~15 bits of ephemeral-port
    # entropy RFC 5452 asks for; a pool of N costs 0.2 us and buys log2(N) bits,
    # on top of the 16-bit random transaction id. 1024 gives 10 bits, close to
    # the 12 Unbound ships. `security.use_0x20` adds ~15 bits per query on a
    # typical name and more than covers the difference. Set 0 for a socket per
    # query. Only affects `udp://` upstreams — DoT/DoH/DoQ keep one connection.
    udp_source_ports: int = 1024
    ecs: Literal["strip", "forward", "off"] = "off"

    @field_validator("ecs", mode="before")
    @classmethod
    def _ecs_off(cls, v):
        """Accept a bare `off`, which YAML turns into the boolean False.

        YAML 1.1 reads unquoted `off`, `no` and `n` as booleans, so
        `ecs: off` — the obvious way to write it, and what the shipped example
        template said for a long time — produced `False` and a validation error
        naming a type nobody wrote. The value the operator meant is not in
        doubt, so take it.
        """
        return "off" if v is False else v
    verify: bool = True            # verify TLS certs of DoT/DoH/DoQ upstreams
    dnssec: bool = False           # validate DNSSEC (recursive/forward)
    # Root trust anchors, as a path to a `root.key`-style file (IANA DS records
    # or a BIND trust-anchors block). Empty means `<data_dir>/root.key` if that
    # exists, and otherwise the anchors compiled into this build. Those pins are
    # current, but a key roll should not need a new release to survive.
    trust_anchors: str = ""
    # The AD bit is an upstream's claim that it validated DNSSEC. Relaying a
    # claim we did not make and cannot authenticate is how a plaintext-UDP
    # spoofer gets a forged answer marked "verified".
    #   auto   — keep AD only from authenticated transports (DoT/DoH/DoQ)
    #   always — relay it regardless (dnsmasq's `proxy-dnssec`)
    #   never  — always clear it
    trust_ad: Literal["auto", "always", "never"] = "auto"
    # Named upstream sets, selected per client by `clients[].upstream_group`.
    # A group's answers are cached separately from every other group's: pointing
    # the kids at a family-filtering resolver is pointless if the first answer
    # any other device gets is then served to them out of one shared cache.
    #   groups:
    #     family: ["1.1.1.3:53", "1.0.0.3:53"]
    #     work:   ["tls://10.0.0.1#dns.corp"]
    groups: dict[str, list[str]] = Field(default_factory=dict)


class CacheConfig(Section):
    enabled: bool = True
    max_entries: int = 100_000
    min_ttl: int = 0
    max_ttl: int = 86_400
    negative_ttl: int = 900
    # Serve-stale (RFC 8767) is a fallback for an unreachable upstream, not a way
    # to skip refreshing: an expired entry is always refetched. Stale data is
    # used when that refetch fails, or when it outlives the client response timer
    # below — in which case the refresh keeps running and repairs the cache.
    serve_stale: bool = True
    serve_stale_max: int = 86_400
    serve_stale_client_timeout: float = 1.8   # RFC 8767 §6 recommends <= 1.8s; 0 = wait
    prefetch: bool = True
    shared: bool = True            # share the cache across workers (multi-worker mode)
    shared_slots: int = 16384      # shared-cache slots
    shared_payload: int = 1232     # max response bytes cached in shared memory
    persist: bool = False          # save/restore the cache across restarts
    # learned prewarm: track query popularity (EWMA, persisted) and proactively
    # refresh the top names before/after their TTLs lapse
    prewarm: bool = False
    prewarm_top: int = 50          # how many learned names to keep warm
    prewarm_interval: int = 300    # seconds between prewarm sweeps


class FilterGroupCfg(Section):
    """A named set of lists and rules, selected by `clients[].group`."""
    sources: list[str] = Field(default_factory=list)
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    # True: the group's rules sit in front of the default ones (the household
    # blocks ads for everyone; this group also blocks social media).
    # False: the group's rules are the whole policy for its clients.
    inherit: bool = True


class FilterConfig(Section):
    enabled: bool = True
    sources: list[str] = Field(default_factory=list)
    # Substrings marking a source as protective (malware/phishing/threat feeds).
    # These are judged on coverage, not on hit rate: a threat feed that never
    # fires means the network is clean, which is the outcome you paid for.
    # Names matching well-known threat-feed conventions are detected anyway.
    protective_sources: list[str] = Field(default_factory=list)
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    block_mode: Literal["zero_ip", "nxdomain", "refused", "nodata", "custom_ip"] = "zero_ip"
    block_ipv4: str = "0.0.0.0"
    block_ipv6: str = "::"
    cname_inspect: bool = True
    # Address lists (files or URLs of IPs/CIDRs). An answer pointing into one is
    # blocked whatever its name was — the name is disposable, the hosting is
    # not. RPZ `rpz-ip` triggers in any configured source land in the same
    # matcher.
    ip_sources: list[str] = Field(default_factory=list)
    block_answer_ips: bool = True      # apply those lists to answers
    # What to do with the `ech` parameter in HTTPS/SVCB answers.
    #   pass  — leave it alone (default). ECH hides the TLS server name from the
    #           network; it does not hide the DNS question, so it takes nothing
    #           away from the filtering done here.
    #   strip — remove it, downgrading clients to a visible SNI. Only worth
    #           doing when something else on this network inspects SNI, and it
    #           is a privacy downgrade for every device behind this resolver.
    ech: Literal["pass", "strip"] = "pass"
    # What the filtering policy must always do, checked against every candidate
    # rule set before it is adopted. `"bank.example must resolve"`,
    # `"doubleclick.net must block"`, `"mail.example MX must resolve"`. A refresh
    # that would violate one is reported and not served — see filter/contract.py.
    assertions: list[str] = Field(default_factory=list)
    # Named list sets: `groups: {kids: {sources: [...], inherit: true}}`. A group
    # holds only its own rules and is layered over these ones — see
    # filter/groups.py for why it is not a second copy of the corpus.
    groups: dict[str, FilterGroupCfg] = Field(default_factory=dict)
    ede: bool = True                   # RFC 8914: attach the block reason to responses
    block_page: bool = False           # serve an explainer page on the block IP
    block_page_host: str = "0.0.0.0"
    block_page_port: int = 8088
    # default policy applied to all clients (overridable per client)
    safe_search: bool = False
    safe_browse: bool = False
    parental: bool = False
    services: list[str] = Field(default_factory=list)
    ctags: list[str] = Field(default_factory=list)


class ClientCfg(Section):
    ident: str
    type: Literal["ip", "cidr", "mac", "clientid", "token"] = "ip"
    name: str = ""
    tags: list[str] = Field(default_factory=list)
    block: bool = True
    safe_search: bool | None = None
    safe_browse: bool | None = None
    parental: bool | None = None
    services: list[str] = Field(default_factory=list)
    upstream_group: str = ""
    group: str = ""                   # filtering group from `filtering.groups`


class DhcpScopeCfg(Section):
    network: str
    range_start: str
    range_end: str
    router: str = ""
    dns: list[str] = Field(default_factory=list)
    lease_time: int = 86400
    domain: str = "lan"
    reservations: dict[str, str] = Field(default_factory=dict)


class DhcpConfig(Section):
    enabled: bool = False               # ships disabled; needs --allow-dhcp too
    server_ip: str = ""
    scope: DhcpScopeCfg | None = None
    # Publish leased hostnames as local DNS: `laptop.lan` and the matching PTR,
    # so devices resolve by name and the query log reads as names rather than
    # addresses. The name is client-supplied, so it is reduced to a single
    # sanitised label inside the scope's own domain — see clients/names.py.
    register_dns: bool = True


class QueryLogConfig(Section):
    enabled: bool = True
    retention_days: int = 90
    privacy_level: int = 0       # 0 all .. 3 no logging
    db: str = "dnsguard.db"      # relative to data_dir
    # Stream every logged query as JSON lines, for a log shipper or `jq`.
    # A path, or "-" for stdout. Empty disables it. Rotates at 64 MB, keeping
    # one previous generation; whatever consumes the stream owns it after that.
    export: str = ""


class GravityConfig(Section):
    refresh_hours: int = 24      # auto-refresh interval; 0 disables


class ZoneCfg(Section):
    origin: str
    file: str | None = None              # BIND zonefile path
    dnssec: bool = False                  # online-sign this zone
    nsec3: bool = False                   # use NSEC3 denial-of-existence when signing
    nsec3_iterations: int = 0
    nsec3_salt: str = ""                  # hex-encoded salt (empty = no salt)
    allow_transfer: list[str] = Field(default_factory=list)   # secondary IPs (AXFR/IXFR)
    also_notify: list[str] = Field(default_factory=list)      # "ip" or "ip:port"
    # Client IPs permitted to send RFC 2136 UPDATE. An address allow-list is only
    # meaningful over TCP, where the peer completed a handshake to reach us; over
    # UDP a source address is a claim anyone can make, so an *unsigned* UPDATE
    # arriving by UDP is refused even from a listed address. Set `tsig_key` to
    # allow updates over UDP — that proves the sender holds a key, which an
    # address does not.
    allow_update: list[str] = Field(default_factory=list)
    tsig_key: str | None = None           # key name required for transfer/update


class TSIGKeyCfg(Section):
    name: str                             # e.g. "xfr-key."
    secret: str                           # base64-encoded shared secret
    algorithm: str = "hmac-sha256."


class SecondaryCfg(Section):
    origin: str
    primary: str                          # primary server IP
    port: int = 53
    tsig_key: str | None = None


class LocalRecord(Section):
    name: str
    type: str = "A"
    answer: str


class WebConfig(Section):
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8089
    admin_password: str | None = None    # set the initial admin password (else autogenerated)
    tls: bool = False
    cert: str | None = None
    key: str | None = None


class SecurityConfig(Section):
    rate_limit: float = 0.0           # queries/sec per client; 0 disables
    rate_burst: int = 0
    rebinding_protection: bool = True
    local_suffixes: list[str] = Field(
        default_factory=lambda: ["lan", "local", "home.arpa", "internal", "localhost"])
    use_0x20: bool = False            # randomize query-name case (spoof resistance)
    # Peers whose X-Forwarded-For we believe, as IPs or CIDRs. Empty means the
    # header is ignored entirely, which is the only safe default: the client
    # writes it, and the address it carries selects the filtering policy, the
    # rate-limit bucket, the login lockout counter and the ECS subnet sent
    # upstream. Set this only for an actual reverse proxy in front of us.
    trusted_proxies: list[str] = Field(default_factory=list)
    dns_cookies: bool = False         # RFC 7873 server cookies (anti-spoof / anti-amplification)
    # real-time DGA / algorithmically-generated-domain detection
    dga_detection: bool = False       # score every name for DGA-likeness
    dga_block: bool = False           # block flagged names (else just flag/log/metric)
    dga_threshold: float = 0.62
    # DNS tunneling / exfiltration detection
    tunnel_detection: bool = False
    tunnel_block: bool = False
    tunnel_threshold: float = 0.45
    # Firefox asks this exact name over plain DNS before turning its own
    # DNS-over-HTTPS on, and treats anything but NOERROR as "the network
    # already manages DNS, leave it alone" (the use-application-dns.net
    # canary). Answering NXDOMAIN here is the one thing that keeps every
    # policy above this (filtering, parental, safe search) from being routed
    # around the moment a browser update turns DoH on by default.
    block_doh_canary: bool = True
    # Track which devices have stopped asking this resolver anything while still
    # present on the network — the only visible trace of an application that has
    # switched to its own encrypted resolver. Reports; never blocks. See
    # clients/activity.py.
    silence_ledger: bool = True
    # Names to resolve through every configured upstream and compare — the bank,
    # the mail provider, anything whose answer being wrong is worse than it being
    # slow. Reports disagreement; never picks a winner. See ops/notary.py.
    notary: list[str] = Field(default_factory=list)
    notary_interval: int = 3600         # seconds between rounds; 0 disables


class AcmeConfig(Section):
    """Automatic TLS certificates over ACME dns-01 (RFC 8555).

    Off by default, and it needs more than a flag: dns-01 is answered from a
    zone this server is authoritative for, so `zones` has to contain the name
    being certified. That is a real constraint and the reason this is not simply
    on — but it is also what makes it work behind NAT with no inbound port 80,
    which is the situation every deployment of this product is in.
    """
    enabled: bool = False
    domains: list[str] = Field(default_factory=list)
    email: str = ""                       # contact for expiry warnings; optional
    directory: str = "https://acme-v02.api.letsencrypt.org/directory"
    # Seconds to wait after publishing the challenge before asking the CA to
    # look. Zero is right when this server answers the query itself; raise it
    # when a secondary has to pull the zone first.
    settle: float = 0.0


class UpdatesConfig(Section):
    """Whether DNSGuard looks for its own updates, and what it may do about one.

    `notify` is the default on purpose: knowing an update exists is useful to
    everyone, while installing one unattended is a decision only the operator
    can make for their network. `auto` is opt-in, applies only inside the
    maintenance window if one is set, and still refuses on any installation it
    does not own (a container image, a distribution package, a source
    checkout) — see `ops/update.py`.
    """

    mode: Literal["off", "notify", "auto"] = "notify"
    channel: Literal["stable", "prerelease"] = "stable"
    check_interval_hours: int = 24        # 0 disables the periodic check
    # The release index. PyPI's JSON API states a sha256 for every artifact, so
    # the same response that names a version also proves which bytes are it.
    index: str = "https://pypi.org/pypi/dnsguard/json"
    timeout: float = 15.0
    # "HH:MM-HH:MM" local time, may wrap midnight. Empty means any time.
    # Applies to `auto` only; an operator asking for an update gets it now.
    window: str = ""
    # What happens after a successful install. `manual` stages the new code and
    # says so; the running process keeps serving the old code until something
    # restarts it. `systemd` asks systemd to restart the unit below, which
    # requires DNSGuard to still have the privilege to talk to it.
    restart: Literal["manual", "systemd"] = "manual"
    unit: str = "dnsguard"


class LogConfig(Section):
    level: Literal["debug", "info", "warning", "error"] = "info"
    json_logs: bool = False


class Config(Section):
    data_dir: str = "./data"
    dev: bool = False
    uvloop: bool = True
    allow_dhcp: bool = False             # runtime gate set by the --allow-dhcp CLI flag
    server: ServerConfig = Field(default_factory=ServerConfig)
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    filtering: FilterConfig = Field(default_factory=FilterConfig)
    clients: list[ClientCfg] = Field(default_factory=list)
    zones: list[ZoneCfg] = Field(default_factory=list)
    tsig_keys: list[TSIGKeyCfg] = Field(default_factory=list)
    secondaries: list[SecondaryCfg] = Field(default_factory=list)
    local_records: list[LocalRecord] = Field(default_factory=list)
    plugins: list = Field(default_factory=list)   # ["dns64"] or [{name, options}]
    dhcp: DhcpConfig = Field(default_factory=DhcpConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    querylog: QueryLogConfig = Field(default_factory=QueryLogConfig)
    gravity: GravityConfig = Field(default_factory=GravityConfig)
    acme: AcmeConfig = Field(default_factory=AcmeConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    log: LogConfig = Field(default_factory=LogConfig)
    updates: UpdatesConfig = Field(default_factory=UpdatesConfig)

    @field_validator("data_dir")
    @classmethod
    def _abs(cls, v: str) -> str:
        return str(Path(v).expanduser())

    @model_validator(mode="after")
    def _readable_assertions(self) -> Config:
        """Refuse an assertion that cannot be parsed, at load rather than at the
        3am refresh it was written to guard."""
        from .filter.contract import ContractError, parse_all
        try:
            parse_all(self.filtering.assertions)
        except ContractError as e:
            raise ValueError(str(e)) from e
        return self

    @model_validator(mode="after")
    def _known_upstream_groups(self) -> Config:
        """A client may only name an upstream group that exists.

        Falling back to the default resolver for a misspelled group is the one
        wrong answer available: the setting exists precisely to keep those
        clients off the default resolver, so a typo would silently deliver the
        opposite of what was configured.
        """
        known = set(self.upstream.groups or {})
        for c in self.clients:
            if c.upstream_group and c.upstream_group not in known:
                raise ValueError(
                    f"client {c.ident!r} names upstream group "
                    f"{c.upstream_group!r}, which is not in upstream.groups "
                    f"({', '.join(sorted(known)) or 'none configured'})")
        groups = set(self.filtering.groups or {})
        for c in self.clients:
            if c.group and c.group not in groups:
                raise ValueError(
                    f"client {c.ident!r} names filtering group {c.group!r}, "
                    f"which is not in filtering.groups "
                    f"({', '.join(sorted(groups)) or 'none configured'})")
        return self

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir)

    @classmethod
    def load_dict(cls, data: dict) -> Config:
        """Validate an already-parsed tree, reporting failures as ConfigError.

        Same contract as `load`, for callers that already hold the mapping —
        the console's settings save, and tests. Keeping one error type means a
        caller does not have to know whether pydantic or YAML rejected it.
        """
        try:
            return cls.model_validate(data)
        except Exception as e:  # pydantic ValidationError -> ConfigError
            raise ConfigError(str(e)) from e

    @classmethod
    def load(cls, path: str | None) -> Config:
        data: dict = {}
        if path:
            p = Path(path).expanduser()
            if not p.exists():
                raise ConfigError(f"config not found: {p}")
            import yaml  # lazy; only needed when a file is given
            data = yaml.safe_load(p.read_text()) or {}
        return cls.load_dict(data)
