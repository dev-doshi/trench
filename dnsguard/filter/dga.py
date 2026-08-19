"""DGA (domain-generation algorithm) detection.

Malware command-and-control cycles through random-looking names faster than any
blocklist can track, so the name's own structure is a tempting signal. It is
also, on its own, a trap: measured against real traffic, legitimate
infrastructure scores exactly as "random" as actual malware, because the
registrable domains of real services frequently are not English words —

    x7f2a9b1c3d4e5.biz          0.86   actual DGA
    epdg…pub.3gppnetwork.org    0.89   VoWiFi / WiFi calling
    d2k3j4h5.cloudfront.net     0.80   AWS CDN
    api.apple-cloudkit.com      0.75   iCloud
    ocsp.digicert.com           0.62   certificate revocation

Blocking on that score breaks WiFi calling and iCloud while barely
inconveniencing malware. So the lexical score is treated as what it is — a weak
prior — and blocking requires *behavioural* confirmation:

A DGA campaign generates **many distinct** random names, and because the vast
majority are unregistered, they come back **NXDOMAIN**. Real infrastructure
resolves, and the same name repeats. So a client is only considered to be
running a DGA when it has recently produced a burst of distinct random-looking
names that failed to resolve. Until then, random-looking names are flagged for
the operator and passed through — where, if they really are DGA, they fail
anyway.

Feed outcomes back with `note_outcome()` after resolution.
"""
from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass

# Common English letter bigrams. Broad enough that ordinary brand/infra words do
# not read as gibberish; the lexical score is only a prior, but a prior full of
# false positives is noise in the operator's face.
_COMMON_BIGRAMS = frozenset("""
th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as
ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la
ns di fo ho pe ec pr ad un ee em im wa ac il ld ge ol ut ai ay ph oo ck nc us na
ss ot pl ap po ap ci ap ig ab ul iv ei id ry sh ow tr ei so pa mo su ap gh ir ap
ap au ev ew ex ff ft gr gu ia ib ie if ik ip iz ke ki ky lu ly mp my nk nu ny od
og ok op os oy pi pu qu rd rg rk rm rn rs rt ru sc sk sl sm sn sp sq sw sy tc tw
ty ub ud ue ug um up uy va vi vo we wh wi wo ye yo ys yt za ze zo bl br cr cl dr
fl fr gl mi mu ni no nf nv ob oc om on op or ov ox oz
""".split())
_VOWELS = frozenset("aeiou")

# --- behavioural confirmation ---
BURST_WINDOW_S = 300.0     # how far back a client's failed random lookups count
BURST_MIN_NAMES = 5        # distinct failed random names before we call it a campaign
BURST_MAX_CLIENTS = 4096   # bound the state table


@dataclass
class DGAResult:
    suspicious: bool           # looks random (lexical prior)
    score: float
    label: str
    reason: str = ""
    block: bool = False        # only true once behaviour confirms a campaign
    confirmed: bool = False    # the client is in a DGA burst state


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _bigram_gibberish(s: str) -> float:
    """Fraction of adjacent letter pairs NOT seen in common English (0..1)."""
    letters = [c for c in s if c.isalpha()]
    if len(letters) < 3:
        return 0.0
    pairs = ["".join(letters[i:i + 2]) for i in range(len(letters) - 1)]
    uncommon = sum(1 for p in pairs if p not in _COMMON_BIGRAMS)
    return uncommon / len(pairs)


def _longest_consonant_run(s: str) -> int:
    run = best = 0
    for c in s:
        if c.isalpha() and c not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _registrable_label(qname: str) -> str:
    parts = qname.rstrip(".").lower().split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


class DGADetector:
    """Lexical prior + per-client behavioural confirmation.

    `block=True` no longer means "block anything that looks random"; it means
    "block random-looking names from a client already shown to be cycling
    through failed random names".
    """

    def __init__(self, *, threshold: float = 0.62, min_len: int = 10, block: bool = False,
                 burst_min_names: int = BURST_MIN_NAMES,
                 burst_window_s: float = BURST_WINDOW_S):
        self.threshold = threshold
        self.min_len = min_len
        self.block = block
        self.burst_min_names = burst_min_names
        self.burst_window_s = burst_window_s
        # client -> deque[(ts, label)] of random-looking names that did NOT resolve
        self._failed: dict[str, deque] = {}

    # --- lexical prior ---
    def score(self, label: str) -> float:
        n = len(label)
        if n < self.min_len:
            return 0.0
        gib = _bigram_gibberish(label)
        ent = min(1.0, _entropy(label) / 4.0)
        digits = sum(c.isdigit() for c in label) / n
        crun = min(1.0, _longest_consonant_run(label) / 6.0)
        length_boost = min(1.0, (n - self.min_len) / 12.0) * 0.15
        return min(1.0, 0.55 * gib + 0.20 * ent + 0.15 * digits + 0.10 * crun + length_boost)

    # --- behavioural state ---
    def _prune(self, dq: deque, now: float) -> None:
        cutoff = now - self.burst_window_s
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def campaign_size(self, client: str, *, now: float | None = None) -> int:
        """Distinct random-looking names from this client that failed recently."""
        dq = self._failed.get(client)
        if not dq:
            return 0
        self._prune(dq, now if now is not None else time.time())
        return len({label for _, label in dq})

    def note_outcome(self, qname: str, client: str, rcode: str, *,
                     now: float | None = None) -> None:
        """Record the resolution outcome. Only failures of random-looking names
        build toward a campaign — a name that resolves is, by definition, real
        infrastructure and must never push a client toward being blocked."""
        if not client or rcode not in ("NXDOMAIN", "SERVFAIL"):
            return
        label = _registrable_label(qname)
        if self.score(label) < self.threshold:
            return
        now = now if now is not None else time.time()
        dq = self._failed.get(client)
        if dq is None:
            if len(self._failed) >= BURST_MAX_CLIENTS:
                self._failed.clear()   # crude but bounded; state is advisory only
            dq = self._failed[client] = deque()
        dq.append((now, label))
        self._prune(dq, now)

    # --- decision ---
    def check(self, qname: str, client: str = "", *, now: float | None = None) -> DGAResult:
        label = _registrable_label(qname)
        sc = round(self.score(label), 3)
        if sc < self.threshold:
            return DGAResult(False, sc, label)
        n = self.campaign_size(client, now=now) if client else 0
        confirmed = n >= self.burst_min_names
        if confirmed:
            return DGAResult(True, sc, label, block=self.block, confirmed=True,
                             reason=(f"DGA campaign: {n} distinct random names from this "
                                     f"client failed to resolve within "
                                     f"{int(self.burst_window_s)}s (score {sc:.2f})"))
        return DGAResult(True, sc, label, block=False, confirmed=False,
                         reason=(f"random-looking name (score {sc:.2f}); no failed-lookup "
                                 f"burst from this client, so not blocked"))
