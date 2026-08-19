"""Safe-browsing / parental protection via local domain sets.

Categories: malware/phishing ("safe_browse") and adult ("parental"). Domains
load from data files maintained by the gravity scheduler; lookups are exact +
suffix on a hash-keyed set so large lists stay cheap. A tiny builtin sample
keeps the feature testable offline.
"""
from __future__ import annotations

from pathlib import Path

from ..log import get

log = get("safebrowse")

_BUILTIN_MALWARE = {"malware.testing.google.test", "phishing.example", "evil.test"}
_BUILTIN_ADULT = {"adult.example", "porn.test"}


class SafeBrowse:
    def __init__(self, malware: set[str] | None = None, adult: set[str] | None = None):
        self.malware = malware if malware is not None else set(_BUILTIN_MALWARE)
        self.adult = adult if adult is not None else set(_BUILTIN_ADULT)

    @classmethod
    def load(cls, data_dir: Path) -> SafeBrowse:
        return cls(_read(data_dir / "safebrowse_malware.txt", _BUILTIN_MALWARE),
                   _read(data_dir / "safebrowse_adult.txt", _BUILTIN_ADULT))

    def _hit(self, qname: str, pool: set[str]) -> bool:
        labels = qname.rstrip(".").lower().split(".")
        return any(".".join(labels[i:]) in pool for i in range(len(labels)))

    def check(self, qname: str, *, safe_browse: bool, parental: bool) -> str | None:
        if safe_browse and self._hit(qname, self.malware):
            return "malware"
        if parental and self._hit(qname, self.adult):
            return "adult"
        return None


def _read(path: Path, fallback: set[str]) -> set[str]:
    if not path.exists():
        return set(fallback)
    out: set[str] = set()
    for line in path.read_text(errors="replace").splitlines():
        s = line.strip().lower()
        if s and not s.startswith("#"):
            out.add(s.split()[0])
    return out or set(fallback)
