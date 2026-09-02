"""Labels implied by a filled-in issue form.

The forms already ask which part of Trench an issue is about; without this
that answer is prose in the body and a human retypes it as a label. The
mapping lives here rather than in the workflow so it can be tested, and so a
new dropdown option that nobody mapped fails a test instead of silently
labelling nothing.

    python3 scripts/triage_labels.py body.md        # prints one label per line

Reads the rendered issue body — the `### Heading` / value form GitHub produces
from an issue form — and prints the labels to add. It never removes labels: a
human's decision outranks a parser's.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

#: Dropdown answer -> area label. The keys are the option strings in
#: `.github/ISSUE_TEMPLATE/*.yml`; `scripts/check_templates.py` fails if a form
#: offers an option that is not a key here.
AREA_BY_ANSWER: dict[str, str] = {
    "Resolution — recursion, forwarding, DNSSEC, cache": "area/resolution",
    "Filtering — blocklists, rules, groups, safe search, services": "area/filtering",
    "Transports — Do53, DoT, DoH, DoQ, DoH3, discovery": "area/transport",
    "Authoritative zones — XFR, dynamic update, signing": "area/authoritative",
    "DHCP server": "area/dhcp",
    "Console or admin API": "area/console",
    "Query log, statistics, or export": "area/data",
    "CLI": "area/cli",
    "Packaging — Docker, systemd, pip, upgrade": "area/packaging",
    "Performance, memory, or stability": "area/performance",
    "Not sure": "",
}

#: Heading text of the dropdowns whose answer names an area.
_AREA_HEADINGS = ("Which part of Trench",)

#: Free-text signals. Deliberately few: a wrong label costs more than a
#: missing one, so only phrases that are unambiguous in this project appear.
_KEYWORDS: tuple[tuple[str, str], ...] = (
    (r"\bDNSSEC\b|\bRRSIG\b|\bNSEC3?\b|\btrust anchor", "area/resolution"),
    (r"\bDoH\b|\bDoT\b|\bDoQ\b|\bQUIC\b|\bDDR\b|\bDNR\b", "area/transport"),
    (r"\bTSIG\b|\bAXFR\b|\bIXFR\b|\bNOTIFY\b", "area/authoritative"),
    (r"\bDHCP\b", "area/dhcp"),
    (r"\bOOM\b|out of memory|memory leak", "area/performance"),
    (r"\bupdate (check|channel)\b|self-update|auto-?update", "area/packaging"),
)


def _sections(body: str) -> dict[str, str]:
    """`{heading: value}` for a rendered issue-form body."""
    out: dict[str, str] = {}
    heading: str | None = None
    buf: list[str] = []
    for line in body.splitlines():
        if line.startswith("### "):
            if heading is not None:
                out[heading] = "\n".join(buf).strip()
            heading, buf = line[4:].strip(), []
        elif heading is not None:
            buf.append(line)
    if heading is not None:
        out[heading] = "\n".join(buf).strip()
    return out


def labels_for(body: str) -> list[str]:
    """Every label the body implies, deduplicated, in a stable order."""
    found: list[str] = []

    def add(label: str) -> None:
        if label and label not in found:
            found.append(label)

    sections = _sections(body)
    for heading in _AREA_HEADINGS:
        answer = sections.get(heading, "").strip()
        if answer in AREA_BY_ANSWER:
            add(AREA_BY_ANSWER[answer])
    for pattern, label in _KEYWORDS:
        if re.search(pattern, body, re.IGNORECASE):
            add(label)
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("body", nargs="?", help="file holding the issue body (default: stdin)")
    args = ap.parse_args(argv)
    text = pathlib.Path(args.body).read_text() if args.body else sys.stdin.read()
    for label in labels_for(text):
        print(label)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
