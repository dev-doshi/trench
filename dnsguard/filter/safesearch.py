"""Force Safe Search by rewriting search engines to their safe endpoints.

Returns the CNAME target a provider domain should be redirected to; the pipeline
resolves the target and returns the chain so stub clients get an address.
"""
from __future__ import annotations

# provider domain (exact or suffix) -> safe CNAME target
_MAP: dict[str, str] = {
    "google.com": "forcesafesearch.google.com",
    "www.google.com": "forcesafesearch.google.com",
    "bing.com": "strict.bing.com",
    "www.bing.com": "strict.bing.com",
    "duckduckgo.com": "safe.duckduckgo.com",
    "youtube.com": "restrict.youtube.com",
    "www.youtube.com": "restrict.youtube.com",
    "m.youtube.com": "restrict.youtube.com",
    "youtubei.googleapis.com": "restrict.youtube.com",
    "youtube.googleapis.com": "restrict.youtube.com",
    "www.youtube-nocookie.com": "restrict.youtube.com",
    "pixabay.com": "safesearch.pixabay.com",
    "yandex.com": "familysearch.yandex.ru",
    "www.yandex.com": "familysearch.yandex.ru",
}

# all national Google TLDs (google.de, google.co.uk, ...) map to the same target
_GOOGLE_SAFE = "forcesafesearch.google.com"


def safe_target(qname: str) -> str | None:
    name = qname.rstrip(".").lower()
    if name in _MAP:
        return _MAP[name]
    # national Google domains
    labels = name.split(".")
    if labels and labels[0] in ("google", "www"):
        rest = ".".join(labels[1:]) if labels[0] == "www" else name
        if rest.startswith("google.") or name.startswith("google."):
            return _GOOGLE_SAFE
    return None
