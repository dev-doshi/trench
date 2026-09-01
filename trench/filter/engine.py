"""Compiled filter index + matcher.

Rules are bucketed for O(labels) lookup: suffix/exact hash maps for the common
`||domain^` and hosts rules, plus a small regex list for pattern rules. Matching
honors Adblock precedence: $important > exception(@@) > block, with $badfilter
disabling, $denyallow carving out, and $dnstype/$ctag/$client gating.
"""
from __future__ import annotations

from functools import lru_cache

from ..wire.name import suffixes as name_suffixes
from . import Action, Decision
from .ipmatch import IPMatcher
from .rule import Rule
from .shared import SharedBlockTable

# rule sources that came from an operator rather than an imported blocklist
OPERATOR_SOURCES = frozenset({"custom", "denylist", "allowlist"})


def _is_plain(r: Rule) -> bool:
    """True for a bare `||domain^` / hosts block rule carrying no modifiers.

    These are ~99.9% of a real blocklist, so they get a compact representation
    (see `block_plain`) instead of a full Rule object.
    """
    return (r.block and r.suffix is not None and not r.important and not r.badfilter
            and r.dnstypes is None and r.ctags is None and r.clients is None
            and r.dnstypes_not is None and r.ctags_not is None and r.clients_not is None
            and not r.denyallow and r.rewrite is None)


class FilterEngine:
    """Compiled rule index.

    Memory matters: a large aggregate blocklist is ~600K rules, and a refresh
    holds the old and new engine at once. A `Rule` object plus its per-key list
    wrapper costs ~600 B/rule, so modifier-free block rules — the overwhelming
    majority — never become objects at all. Imported ones go into a
    `SharedBlockTable` (raw bytes in shared memory, ~33 B/domain, and identical
    across forked workers instead of duplicated per worker); operator-set ones
    stay in `block_plain` because the API has to be able to list them back.
    Either way a Rule is materialized only on an actual hit.
    """

    def __init__(self) -> None:
        self.block_plain: dict[str, str] = {}      # operator plain rules: suffix -> source
        self.block_table = SharedBlockTable()      # imported plain rules (shared memory)
        self.block_suffix: dict[str, list[Rule]] = {}
        self.allow_suffix: dict[str, list[Rule]] = {}
        self.block_exact: dict[str, list[Rule]] = {}
        self.allow_exact: dict[str, list[Rule]] = {}
        self.block_regex: list[Rule] = []
        self.allow_regex: list[Rule] = []
        self._n_rules = 0
        #: True once any rule scopes itself to particular clients. Consumers
        #: that key a cache on something coarser than the client address have
        #: to fall back when this is set — see FastPath.usable.
        self.has_client_rules = False
        # Prefixes to reject in an *answer*, from `filtering.ip_sources` and
        # from RPZ `rpz-ip` triggers. Held here rather than beside the engine so
        # that swapping the rules swaps the addresses with them: a refresh that
        # replaced one and not the other would filter names from the new list
        # against addresses from the old.
        self.ips = IPMatcher()

    # --- compilation ---
    @staticmethod
    def _live_rules(rules, badfilter_keys: frozenset | None = None):
        """The rules that survive $badfilter, which disables the rule carrying
        the same pattern. AdGuard matches by raw modifiers; we approximate by
        pattern identity.

        Shared by both constructors on purpose. Applying it in `compile` only
        meant $badfilter worked there and silently did nothing in `from_table`
        — the path every non-primary worker and every restart-from-cache uses.

        `badfilter_keys`, when given, is that set worked out in advance. It is
        what lets `rules` be a one-pass iterator: a $badfilter in one list
        disables a rule in another, so without it every rule in the corpus has
        to be held in memory at once purely to answer a question the raw text
        could have answered for a fraction of the cost. See
        `filter.badfilter_keys`.
        """
        if badfilter_keys is None:
            rules = list(rules)
            badfilter_keys = frozenset(_pattern_id(r) for r in rules if r.badfilter)
        for r in rules:
            if r.badfilter:
                continue
            if _pattern_id(r) in badfilter_keys and not r.rewrite:
                continue
            yield r

    @classmethod
    def compile(cls, rules, table_path=None, *,
                badfilter_keys: frozenset | None = None) -> FilterEngine:
        """`table_path` persists the compiled blocklist so other processes can
        map the same copy, and so a restart does not have to re-parse it.

        `rules` may be any iterable, and is consumed once. That matters at the
        scale this runs at: a `Rule` is ~310 B and an aggregate corpus is ~600k
        of them, so materialising the list first cost 187 MB — twelve times the
        24 MB artifact it was on the way to becoming, on a box with a 700 MB
        ceiling that had already been OOM-killed. Streaming it, and passing
        `badfilter_keys` so nothing has to be held for a second pass, measures
        296 MB of peak down to 153 MB.
        """
        eng = cls()
        imported: list[tuple[str, str]] = []
        for r in cls._live_rules(rules, badfilter_keys):
            eng._add(r, imported)
        # Built in one shot at the end: the table is sized from the final count
        # and is immutable afterwards, which is what makes it shareable.
        eng.block_table = SharedBlockTable.build(imported, table_path)
        return eng

    @classmethod
    def from_table(cls, table: SharedBlockTable, rules) -> FilterEngine:
        """Reuse an already-compiled blocklist, adding only the small rule set
        that is not in it (operator rules, regex and modifier-carrying rules).

        This is how a worker adopts a table another process built: the 600k
        imported domains are mapped, not rebuilt.
        """
        eng = cls()
        for r in cls._live_rules(rules):
            eng._add(r)          # imported=None -> nothing is routed to the table
        eng.block_table = table
        return eng

    def _add(self, r: Rule, imported: list[tuple[str, str]] | None = None) -> None:
        self._n_rules += 1
        if r.clients is not None or r.clients_not is not None:
            self.has_client_rules = True
        if r.regex is not None:
            (self.block_regex if r.block else self.allow_regex).append(r)
        elif r.exact is not None:
            d = self.block_exact if r.block else self.allow_exact
            d.setdefault(r.exact, []).append(r)
        elif r.suffix is not None:
            if _is_plain(r):
                if r.source in OPERATOR_SOURCES or imported is None:
                    # kept enumerable: the API lists operator rules back
                    self.block_plain.setdefault(r.suffix, r.source)
                else:
                    # duplicates across lists are interchangeable; the table
                    # keeps the first source it saw
                    imported.append((r.suffix, r.source))
            else:
                d = self.block_suffix if r.block else self.allow_suffix
                d.setdefault(r.suffix, []).append(r)

    # --- runtime edits (API) ---
    def add_deny(self, domain: str, source: str = "custom") -> None:
        self.block_suffix.setdefault(domain.strip().lower(), []).append(
            Rule(raw=domain, block=True, suffix=domain.strip().lower(), source=source))

    def add_allow(self, domain: str, source: str = "custom") -> None:
        self.allow_suffix.setdefault(domain.strip().lower(), []).append(
            Rule(raw=domain, block=False, important=True,
                 suffix=domain.strip().lower(), source=source))

    def remove_rule(self, domain: str) -> None:
        d = domain.strip().lower()
        self.block_plain.pop(d, None)
        self.block_table.discard(d)
        self.block_suffix.pop(d, None)
        self.allow_suffix.pop(d, None)
        self.block_exact.pop(d, None)
        self.allow_exact.pop(d, None)

    @property
    def size(self) -> int:
        return (len(self.block_plain) + len(self.block_table) + len(self.block_suffix)
                + len(self.block_exact) + len(self.block_regex))

    def custom_rules(self) -> tuple[list[str], list[str]]:
        """Deny/allow domains the operator set (API or config), excluding imported
        blocklists. The API surfaces these; returning the whole gravity corpus
        instead would be a multi-megabyte response nobody can read."""
        def picked(table: dict[str, list[Rule]]) -> list[str]:
            return [d for d, rules in table.items()
                    if any(r.source in OPERATOR_SOURCES for r in rules)]
        deny = picked(self.block_suffix)
        deny += [d for d, s in self.block_plain.items() if s in OPERATOR_SOURCES]
        return sorted(set(deny)), sorted(set(picked(self.allow_suffix)))

    # --- matching ---
    #: Every parent suffix of a name, longest first: the candidate keys a suffix
    #: rule could be filed under. Built once per query and handed to all three
    #: walks below, which used to derive it independently.
    suffixes = staticmethod(name_suffixes)

    @staticmethod
    def _suffix_hits(cands: list[str], table: dict[str, list[Rule]]) -> list[Rule]:
        out: list[Rule] = []
        for cand in cands:
            hit = table.get(cand)
            if hit:
                out.extend(hit)
        return out

    def _plain_hits(self, cands: list[str]) -> list[Rule]:
        """Compact-table lookups, materialized into Rules only when they match."""
        out: list[Rule] = []
        get, tget = self.block_plain.get, self.block_table.get
        for cand in cands:
            src = get(cand) or tget(cand)
            if src is not None:
                out.append(Rule(raw=cand, block=True, suffix=cand, source=src))
        return out

    def plain_source_counts(self) -> dict[str, int]:
        """Domains contributed per source, for the blocklist-ROI report. The
        shared table cannot enumerate its keys, so it counts during build."""
        counts = dict(self.block_table.source_counts)
        for src in self.block_plain.values():
            counts[src] = counts.get(src, 0) + 1
        return counts

    def _applicable(self, rules: list[Rule], qname: str, qtype: int,
                    ctags: frozenset[str], client: str,
                    client_names: frozenset[str] = frozenset()) -> list[Rule]:
        out = []
        for r in rules:
            if r.dnstypes is not None and qtype not in r.dnstypes:
                continue
            if r.dnstypes_not is not None and qtype in r.dnstypes_not:
                continue
            if r.ctags is not None and ctags.isdisjoint(r.ctags):
                continue
            if r.ctags_not is not None and not ctags.isdisjoint(r.ctags_not):
                continue
            if r.clients_not is not None and _client_in(r.clients_not, client, client_names):
                continue
            if r.clients is not None and not _client_in(r.clients, client, client_names):
                continue
            if r.denyallow and _under_any(qname, r.denyallow):
                continue
            out.append(r)
        return out

    def match(self, qname: str, qtype: int = 1,
              ctags: frozenset[str] = frozenset(), client: str = "",
              client_names: frozenset[str] = frozenset()) -> Decision:
        name = qname.rstrip(".").lower()
        if not name:
            return Decision()
        cands = self.suffixes(name)

        block = self._suffix_hits(cands, self.block_suffix) + self._plain_hits(cands)
        allow = self._suffix_hits(cands, self.allow_suffix)
        block += self.block_exact.get(name, [])
        allow += self.allow_exact.get(name, [])
        if self.block_regex:
            block += [r for r in self.block_regex if r.regex and r.regex.search(name)]
        if self.allow_regex:
            allow += [r for r in self.allow_regex if r.regex and r.regex.search(name)]

        block = self._applicable(block, name, qtype, ctags, client, client_names)
        allow = self._applicable(allow, name, qtype, ctags, client, client_names)
        if not block and not allow:
            return Decision()

        block_imp = any(r.important for r in block)
        allow_imp = any(r.important for r in allow)

        # exception wins unless a block rule is $important and no allow is
        if allow and not (block_imp and not allow_imp):
            r = _most_specific(allow)
            return Decision(Action.ALLOW, rule=r.raw, source=r.source,
                            reason=f"allowed by {r.raw}")
        if block:
            r = _most_specific(block)
            if r.rewrite is not None:
                return Decision(Action.REWRITE, rdata=r.rewrite.rdata, rcode=r.rewrite.rcode,
                                rule=r.raw, source=r.source, reason=f"rewritten by {r.raw}")
            return Decision(Action.BLOCK, rule=r.raw, source=r.source,
                            reason=f"blocked by {r.raw}")
        return Decision()


def _pattern_id(r: Rule) -> tuple:
    return (r.suffix, r.exact, r.regex.pattern if r.regex else None, r.block)


@lru_cache(maxsize=4096)
def _net(entry: str):
    """Parsed CIDR, cached. Rebuilt per candidate rule per query otherwise."""
    import ipaddress
    return ipaddress.ip_network(entry, strict=False)


@lru_cache(maxsize=8192)
def _ip(addr: str):
    import ipaddress
    return ipaddress.ip_address(addr)


def _client_in(spec: frozenset[str], client: str, names: frozenset[str]) -> bool:
    """Does the requesting client match any entry of a $client modifier?

    Entries are IPs, CIDRs, or the client's configured name — AdGuard accepts
    all three and lists in the wild use each of them.
    """
    if not spec:
        return False
    if client and client in spec:
        return True
    if names & spec:
        return True
    for entry in spec:
        if "/" not in entry or not client:
            continue
        try:
            if _ip(client) in _net(entry):
                return True
        except ValueError:
            continue
    return False


def _under_any(name: str, domains: tuple[str, ...]) -> bool:
    return any(name == d or name.endswith("." + d) for d in domains)


def _most_specific(rules: list[Rule]) -> Rule:
    # important first, then longest suffix/exact (most specific), then first seen
    def score(r: Rule) -> tuple:
        length = len(r.suffix or r.exact or "")
        return (r.important, length)
    return max(rules, key=score)
