"""Parse every supported list dialect into Rule objects.

Dialects: hosts (`0.0.0.0 domain`), plain domain, dnsmasq (`address=/d/ip`),
wildcard (`*.d`), and Adblock DNS syntax (`||d^`, `@@`, `$important`,
`$badfilter`, `$dnstype=`, `$dnsrewrite=`, `$denyallow=`, `$ctag=`, `$client=`).
"""
from __future__ import annotations

import re

from ..wire.rrtypes import type_from_text
from .rule import Rule, parse_dnsrewrite

_VALID_DOMAIN = re.compile(r"^[a-z0-9_*.-]+\.[a-z0-9_-]+\.?$")
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


def parse_list(text: str, source: str = "") -> list[Rule]:
    rules: list[Rule] = []
    for raw in text.splitlines():
        r = parse_line(raw, source)
        if r is not None:
            rules.append(r)
    return rules


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
    # split off modifiers ($ cannot appear in a domain)
    pattern, _, modstr = line.partition("$")
    rule = Rule(raw=line, block=block, source=source)
    _apply_pattern(rule, pattern.strip())
    if rule.suffix is None and rule.exact is None and rule.regex is None:
        return None
    if modstr:
        _apply_modifiers(rule, modstr)
    return rule


def _apply_pattern(rule: Rule, pat: str) -> None:
    if not pat:
        return
    if pat.startswith("/") and pat.endswith("/") and len(pat) > 2:
        try:
            rule.regex = re.compile(pat[1:-1], re.IGNORECASE)
        except re.error:
            pass
        return
    # |domain| exact
    if pat.startswith("|") and pat.endswith("|") and not pat.startswith("||"):
        rule.exact = pat.strip("|").rstrip("^").lower()
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
