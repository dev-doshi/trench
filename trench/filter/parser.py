"""Parse every supported list dialect into Rule objects.

Dialects: hosts (`0.0.0.0 domain`), plain domain, dnsmasq (`address=/d/ip`),
wildcard (`*.d`), and Adblock DNS syntax (`||d^`, `@@`, `$important`,
`$badfilter`, `$dnstype=`, `$dnsrewrite=`, `$denyallow=`, `$ctag=`, `$client=`).
"""
from __future__ import annotations

import re
import time
from re import _constants as _sre_c  # type: ignore[attr-defined]  # parse tree, for the ReDoS
from re import _parser as _sre_p  # type: ignore[attr-defined]  # check (not in typeshed)

from ..log import get
from ..wire.rrtypes import type_from_text
from .rule import Rule, parse_dnsrewrite

log = get("filter.parser")

# A single label is a valid rule: blocking a whole TLD (`zip`, `mov`) is a real
# thing operators do. Requiring two labels silently dropped every such entry in
# hosts and domain-format lists — with no diagnostic — while the same name in
# adblock form (`||zip^`) was accepted, so the two syntaxes disagreed.
_VALID_DOMAIN = re.compile(r"^[a-z0-9_*-]+(?:\.[a-z0-9_-]+)*\.?$")
_HOSTS_IP = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::)$")
_IGNORE = {"localhost", "localhost.localdomain", "broadcasthost",
           "ip6-localhost", "ip6-loopback", "ip6-allnodes", "ip6-allrouters"}


def detect_format(text: str) -> str:
    ab = hosts = 0
    for line in text.splitlines()[:200]:
        s = line.strip()
        if not s or s[0] in "#!":
            continue
        if s.startswith(("||", "@@")) or "^" in s or "$" in s:
            ab += 1
        elif re.match(r"^\S+\s+\S", s):
            hosts += 1
    if ab > hosts:
        return "adblock"
    return "hosts" if hosts else "domain"


def iter_list(text: str, source: str = ""):
    """Parse a list, yielding one Rule at a time.

    The generator is the primary form: a large corpus is ~600k Rules and each is
    routed into a compact representation the moment it is seen, so holding the
    whole list first is 187 MB spent to produce a 24 MB table.
    """
    for raw in text.splitlines():
        r = parse_line(raw, source)
        if r is not None:
            yield r


def parse_list(text: str, source: str = "") -> list[Rule]:
    """The whole list at once. For callers small enough not to care — tests,
    `trench regex-test`, the what-if delta."""
    return list(iter_list(text, source))


def iter_badfilter(text: str, source: str = ""):
    """Only the `$badfilter` rules in `text`.

    A $badfilter in one list disables a rule in another, so the set has to be
    known before any list is compiled. Finding them needs no parsing for the
    99.99% of lines that cannot be one — the modifier has to appear literally —
    which is what makes a prepass cheap enough to do instead of holding every
    parsed rule in memory for a second look.
    """
    for raw in text.splitlines():
        if "$badfilter" not in raw:
            continue
        r = parse_line(raw, source)
        if r is not None and r.badfilter:
            yield r


def parse_line(raw: str, source: str = "") -> Rule | None:
    line = raw.strip()
    if not line or line[0] in "#!":
        return None
    # dnsmasq address=/domain/ip  (and server=/domain/# for nxdomain-ish)
    if line.startswith("address=/"):
        dom = line.split("/")[1].lower()
        return _suffix_rule(dom, source) if dom else None
    # adblock if it has anchors/modifiers
    if line.startswith(("||", "@@", "|")) or "^" in line or "$" in line or line.startswith("/"):
        return _parse_adblock(line, source)
    # hosts: "ip domain [domain...]" (first domain only)
    parts = line.split()
    if len(parts) >= 2 and (_HOSTS_IP.match(parts[0]) or _is_ip(parts[0])):
        dom = parts[1].lower()
        return _suffix_rule(dom, source)
    # bare domain / wildcard
    dom = parts[0].lower()
    return _suffix_rule(dom, source)


def _is_ip(s: str) -> bool:
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", s)) or ":" in s


def _suffix_rule(dom: str, source: str) -> Rule | None:
    dom = dom.lstrip("*.").rstrip(".").lower()
    if not dom or dom in _IGNORE or not _VALID_DOMAIN.match(dom + "."):
        return None
    return Rule(raw=dom, block=True, suffix=dom, source=source)


def _parse_adblock(line: str, source: str) -> Rule | None:
    block = True
    if line.startswith("@@"):
        block = False
        line = line[2:]
    # Split off modifiers. `$` cannot appear in a domain — but it very much can
    # appear in a regex, as the end anchor. Partitioning first truncated
    # `/^ads[0-9]+\.evil\.com$/` to `/^ads[0-9]+\.evil\.com`, which then failed
    # the trailing-slash test and fell through to the suffix branch as a literal
    # that matches nothing, so the rule silently blocked nothing at all.
    pattern, modstr = _split_modifiers(line)
    rule = Rule(raw=line, block=block, source=source)
    _apply_pattern(rule, pattern.strip())
    if rule.suffix is None and rule.exact is None and rule.regex is None:
        return None
    if modstr:
        try:
            _apply_modifiers(rule, modstr)
        except _DropRule:
            return None
    return rule


def _split_modifiers(line: str) -> tuple[str, str]:
    """`(pattern, modifiers)`, respecting a leading /regex/ literal."""
    body = line[2:] if line.startswith("@@") else line
    if body.startswith("/"):
        end = body.rfind("/")
        if end > 0:
            rest = body[end + 1:]
            if not rest or rest.startswith("$"):
                return body[:end + 1], rest[1:] if rest else ""
    pattern, _, modstr = line.partition("$")
    return pattern, modstr


#: How many unbounded repeats (`*`, `+`, `{n,}`) a list regex may carry. Each
#: one is a nested loop for the backtracker on a failing match: two cost ~50 us
#: on a 253-char name, three ~10 ms, four a quarter of a second — per query.
_MAX_UNBOUNDED = 2
#: A bounded repeat with a bigger ceiling than this is treated as unbounded.
_BIG_REPEAT = 16
#: What one start position may cost the backtracker on a failing name: the
#: product, over every repeat in the pattern, of how many lengths it can try
#: (a name is at most 253 characters, so that is the most an unbounded one
#: can). Counting only the unbounded repeats missed that bounded ones multiply
#: too: `a{0,16}` six times over is 17**6 tries per position, passed the check
#: above, and then hung the probe below — which times a pattern only *after* it
#: returns — for longer than anyone waited. The budget is the two unbounded
#: repeats allowed above times 32, because real lists put a handful of `?`
#: after them (`^(.+[_.-])?adse?rv(er?|ice)?s?[0-9]*`). What it admits is
#: bounded at a couple of seconds on the probes, where the probe refuses it;
#: what it refuses is everything that ran for hours.
_NAME_MAX = 253
_MAX_COST = _NAME_MAX ** _MAX_UNBOUNDED * 32
#: The slowest a list regex may be on the adversarial probes, in seconds.
_PROBE_BUDGET = 0.005

_REPEATS = {_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT, getattr(_sre_c, "POSSESSIVE_REPEAT", None)}
_REFUSED = {_sre_c.GROUPREF, _sre_c.GROUPREF_EXISTS, _sre_c.ASSERT, _sre_c.ASSERT_NOT}


def _redos_reason(pat: str) -> str | None:
    """Why `pat` could backtrack catastrophically, or None if it cannot.

    List regexes are remote input, and `search` runs against an attacker-chosen
    name, synchronously, on the loop the listeners share. This walks the parse
    tree rather than pattern-matching the text: the old textual check saw only
    innermost groups, so `(a|aa)+` (Fibonacci) and `((a+))+` sailed through.
    """
    unbounded = 0
    cost = 1

    def walk(sub, in_repeat: bool) -> str | None:
        nonlocal unbounded, cost
        for op, av in sub:
            if op in _REFUSED:
                return "backreference or lookaround"
            if op in _REPEATS:
                lo, hi, body = av
                if hi == _sre_c.MAXREPEAT or hi > _BIG_REPEAT:
                    unbounded += 1
                    cost *= _NAME_MAX
                else:
                    cost *= hi - lo + 1
                if hi > 1:
                    if in_repeat:
                        return "nested quantifiers"
                    why = walk(body, True)
                    if why:
                        return why
                else:
                    why = walk(body, in_repeat)
                    if why:
                        return why
            elif op is _sre_c.BRANCH:
                for alt in av[1]:
                    # An alternation under a repeat is ambiguous unless every arm
                    # is exactly one character — then it is just a class.
                    if in_repeat and alt.getwidth() != (1, 1):
                        return "alternation under a quantifier"
                    why = walk(alt, in_repeat)
                    if why:
                        return why
            elif op is _sre_c.SUBPATTERN:
                why = walk(av[-1], in_repeat)
                if why:
                    return why
        return None

    try:
        why = walk(_sre_p.parse(pat, re.IGNORECASE), False)
    except (re.error, RecursionError, OverflowError):
        return "does not parse"
    if why:
        return why
    if unbounded > _MAX_UNBOUNDED:
        return f"{unbounded} unbounded quantifiers"
    if cost > _MAX_COST:
        return "too many repeats in sequence"
    return None


def _probes(pat: str) -> list[str]:
    """Names shaped to make a backtracker fail slowly: long runs of the
    pattern's own characters with a character at the end that cannot match."""
    chars = {c for c in pat.lower() if c.isalnum() or c in "-_."} or {"a"}
    out = []
    for c in sorted(chars)[:12]:
        out.append(c * 252 + "!")
    out.append("".join(sorted(chars)) * (252 // max(1, len(chars))) + "!")
    return out


def _safe_regex(pat: str):
    """Compile a list-supplied pattern, refusing shapes that can blow up."""
    if len(pat) > 512:
        log.warning("refusing over-long regex rule (%d chars)", len(pat))
        return None
    why = _redos_reason(pat)
    if why:
        log.warning("refusing regex rule (%s): %s", why, pat)
        return None
    try:
        rx = re.compile(pat, re.IGNORECASE)
    except (re.error, RecursionError, OverflowError):
        return None
    # Belt and braces: the structural check is conservative, but a real engine
    # is the only proof. Time the compiled pattern on hostile names once, here,
    # rather than discovering it on the query path.
    for probe in _probes(pat):
        t = time.perf_counter()
        rx.search(probe)
        if time.perf_counter() - t > _PROBE_BUDGET:
            log.warning("refusing regex rule (slow on a %d-char name): %s",
                        len(probe), pat)
            return None
    return rx


class Glob:
    """A `*` wildcard rule, matched in linear time.

    Wildcard rules used to become `^a.*a.*…b$` for `re`, which backtracks to
    degree k on a failing name: `||a*a*a*a*a*a*a*a*a*b^` did not finish on a
    62-character query. Only `*` is special here, so greedy leftmost matching
    of each literal piece is exact and needs no backtracking at all.
    """
    __slots__ = ("pattern", "_head", "_mid", "_tail")

    def __init__(self, glob: str):
        self.pattern = glob.lower()
        parts = self.pattern.split("*")
        self._head, self._tail = parts[0], parts[-1]
        self._mid = tuple(p for p in parts[1:-1] if p)

    def search(self, name: str) -> bool:
        s = name.lower()
        if "*" not in self.pattern:
            return s == self.pattern
        head, tail = self._head, self._tail
        if len(s) < len(head) + len(tail) or not s.startswith(head) or not s.endswith(tail):
            return False
        pos, stop = len(head), len(s) - len(tail)
        for piece in self._mid:
            at = s.find(piece, pos, stop)
            if at < 0:
                return False
            pos = at + len(piece)
        return True

    match = fullmatch = search     # a glob is anchored at both ends anyway

    def __eq__(self, other):
        return isinstance(other, Glob) and other.pattern == self.pattern

    def __hash__(self):
        return hash(self.pattern)

    def __repr__(self):
        return f"Glob({self.pattern!r})"


def _apply_pattern(rule: Rule, pat: str) -> None:
    if not pat:
        return
    if pat.startswith("/") and pat.endswith("/") and len(pat) > 2:
        rule.regex = _safe_regex(pat[1:-1])
        return
    # |domain| exact
    if pat.startswith("|") and pat.endswith("|") and not pat.startswith("||"):
        # rstrip(".") too: match() compares against qname.rstrip("."), so an
        # absolute-form exact rule was filed under a key it could never produce.
        rule.exact = pat.strip("|").rstrip("^").rstrip(".").lower()
        return
    # ||domain^
    p = pat
    if p.startswith("||"):
        p = p[2:]
    p = p.rstrip("^").rstrip("|").lstrip("|")
    p = p.lstrip("*.")
    # wildcard in the middle -> regex
    if "*" in p:
        rule.regex = Glob(p)
        return
    p = p.rstrip(".").lower()
    if p:
        rule.suffix = p


def _split_negated(value: str) -> tuple[list[str], list[str]]:
    """Split a `a|~b|c` modifier value into (required, excluded).

    `~` is the AdGuard exclusion marker. Dropping it — rather than honouring it —
    inverts the author's intent, so it is parsed rather than stripped.
    """
    req, not_req = [], []
    for part in value.split("|"):
        part = part.strip()
        if not part:
            continue
        if part.startswith("~"):
            rest = part[1:].strip()
            if rest:
                not_req.append(rest)
        else:
            req.append(part)
    return req, not_req


class _DropRule(Exception):
    """Raised by `_apply_modifiers` for a modifier that invalidates the rule."""


def _apply_modifiers(rule: Rule, modstr: str) -> None:
    dnstypes: set[int] = set()
    dnstypes_not: set[int] = set()
    ctags: set[str] = set()
    ctags_not: set[str] = set()
    clients: set[str] = set()
    clients_not: set[str] = set()
    denyallow: list[str] = []
    for mod in modstr.split(","):
        mod = mod.strip()
        if not mod:
            continue
        name, _, value = mod.partition("=")
        name = name.strip().lower()
        if name == "important":
            rule.important = True
        elif name == "badfilter":
            rule.badfilter = True
        elif name == "dnstype":
            req, not_req = _split_negated(value)
            for bucket, items in ((dnstypes, req), (dnstypes_not, not_req)):
                for t in items:
                    try:
                        bucket.add(type_from_text(t))
                    except (KeyError, ValueError):
                        pass
        elif name == "dnsrewrite":
            # A subscribed list is untrusted input, and `iter_list` is a
            # generator feeding a streaming compile: an exception here did not
            # drop one line, it abandoned the rest of the corpus behind it.
            try:
                rule.rewrite = parse_dnsrewrite(value)
            except ValueError as e:
                log.debug("dropping rule with unparseable $dnsrewrite: %s", e)
                raise _DropRule from e
        elif name == "ctag":
            req, not_req = _split_negated(value)
            ctags |= set(req)
            ctags_not |= set(not_req)
        elif name == "client":
            req, not_req = _split_negated(value)
            # quoted forms appear in the wild: $client='Mary\'s laptop'
            clients |= {c.strip("'\"") for c in req}
            clients_not |= {c.strip("'\"") for c in not_req}
        elif name == "denyallow":
            denyallow += [d.strip().rstrip(".").lower() for d in value.split("|") if d.strip()]
        # app=, $third-party, etc. ignored for DNS
    if dnstypes:
        rule.dnstypes = frozenset(dnstypes)
    if dnstypes_not:
        rule.dnstypes_not = frozenset(dnstypes_not)
    if ctags:
        rule.ctags = frozenset(ctags)
    if ctags_not:
        rule.ctags_not = frozenset(ctags_not)
    if clients:
        rule.clients = frozenset(clients)
    if clients_not:
        rule.clients_not = frozenset(clients_not)
    if denyallow:
        rule.denyallow = tuple(denyallow)
