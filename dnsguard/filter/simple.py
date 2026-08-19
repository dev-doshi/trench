"""P0 matcher: exact + suffix domain matching with allow/deny overrides.

Allow always beats block. Matching a domain blocks it and every subdomain.
Replaced by the compiled adblock/regex index in P2 (same Decision contract).
"""
from __future__ import annotations

import re

from . import Action, Decision

_COMMENT = re.compile(r"#.*$")
_LEADING_IP = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::)\s+")
_VALID = re.compile(r"^[a-z0-9_.-]+\.[a-z0-9_-]+$")
_IGNORE = {"localhost", "localhost.localdomain", "broadcasthost", "ip6-localhost"}


def parse_hosts(text: str) -> set[str]:
    out: set[str] = set()
    for raw in text.splitlines():
        line = _COMMENT.sub("", raw).strip().lower()
        if not line:
            continue
        line = _LEADING_IP.sub("", line).strip()
        parts = line.split()
        if not parts:
            continue
        dom = parts[0]
        if dom in _IGNORE or not _VALID.match(dom):
            continue
        out.add(dom)
    return out


class SimpleEngine:
    def __init__(self, blocked: set[str] | None = None,
                 allow: set[str] | None = None, deny: set[str] | None = None,
                 origin: dict[str, str] | None = None):
        self.blocked = blocked or set()
        self.allow = {d.lower() for d in (allow or set())}
        self.deny = {d.lower() for d in (deny or set())}
        self.origin = origin or {}   # domain -> source list name

    @property
    def size(self) -> int:
        return len(self.blocked)

    def _suffix_hit(self, labels: list[str], pool: set[str]) -> str | None:
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in pool:
                return cand
        return None

    def match(self, qname: str, qtype: int = 1, ctags: frozenset[str] = frozenset(),
              client: str = "", client_names: frozenset[str] = frozenset()) -> Decision:
        """Signature must stay identical to `FilterEngine.match`: the pipeline
        calls whichever engine it was given. This one keeps no per-rule
        modifiers, so the client and tag arguments are accepted and unused."""
        name = qname.rstrip(".").lower()
        if not name:
            return Decision()
        labels = name.split(".")
        # allow-list wins outright
        hit = self._suffix_hit(labels, self.allow)
        if hit:
            return Decision(Action.ALLOW, rule=f"@@{hit}", source="allowlist",
                            reason=f"allowed by {hit}")
        # explicit deny
        hit = self._suffix_hit(labels, self.deny)
        if hit:
            return Decision(Action.BLOCK, rule=hit, source="denylist",
                            reason=f"denied by {hit}")
        # gravity blocklist
        hit = self._suffix_hit(labels, self.blocked)
        if hit:
            return Decision(Action.BLOCK, rule=hit, source=self.origin.get(hit, "blocklist"),
                            reason=f"blocked by {hit}")
        return Decision()

    # runtime edits (used by API)
    def add_deny(self, d: str) -> None: self.deny.add(d.strip().lower())
    def add_allow(self, d: str) -> None: self.allow.add(d.strip().lower())
    def remove_rule(self, d: str) -> None:
        d = d.strip().lower(); self.deny.discard(d); self.allow.discard(d)
