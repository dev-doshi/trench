"""Parse every supported list dialect into Rule objects.

Dialects: hosts (`0.0.0.0 domain`), plain domain, dnsmasq (`address=/d/ip`),
wildcard (`*.d`), and Adblock DNS syntax (`||d^`, `@@`, `$important`,
`$badfilter`, `$dnstype=`, `$dnsrewrite=`, `$denyallow=`, `$ctag=`, `$client=`).
"""
from __future__ import annotations

import re

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
        _apply_modifiers(rule, modstr)
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


#: Nested quantifiers are the classic catastrophic-backtracking shape. A rule
#: list is remote input and `regex.search` runs against an attacker-chosen name
#: on the event loop, so one such pattern anywhere in a subscribed list is a
#: whole-resolver stall.
_REDOS = re.compile(r"\((?:[^()]*[+*?][^()]*)\)\s*[+*]|(?:\[[^\]]*\][+*]){2,}")


def _safe_regex(pat: str):
    """Compile a list-supplied pattern, refusing shapes that can blow up."""
    if _REDOS.search(pat):
        log.warning("refusing regex rule with nested quantifiers: %s", pat)
        return None
    if len(pat) > 512:
        log.warning("refusing over-long regex rule (%d chars)", len(pat))
        return None
    try:
        return re.compile(pat, re.IGNORECASE)
    except re.error:
        return None


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
        try:
            rule.regex = re.compile("^" + re.escape(p).replace(r"\*", ".*") + "$", re.IGNORECASE)
        except re.error:
            pass
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
            rule.rewrite = parse_dnsrewrite(value)
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
