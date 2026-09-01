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
    "Recursive resolver / upstream forwarding": "area/resolver",
    "DNSSEC validation": "area/dnssec",
    "Filtering / blocklists / rules": "area/filtering",
    "Answer cache": "area/cache",
    "Fast path (repeat-query replay)": "area/cache",
    "Transports (Do53, DoT, DoH, DoQ)": "area/transport",
    "Authoritative zones / XFR / dynamic update": "area/auth-zone",
    "DHCP server / lease-derived names": "area/dhcp",
    "Admin API": "area/api",
    "Admin console (web UI)": "area/console",
    "Query log / statistics / export": "area/store",
    "CLI": "area/cli",
    "Packaging, Docker, or systemd": "area/packaging",
    "Not sure": "",
}

#: Heading text of the dropdowns whose answer names an area.
_AREA_HEADINGS = ("Which part of Trench",)

#: Free-text signals. Deliberately few: a wrong label costs more than a
#: missing one, so only phrases that are unambiguous in this project appear.
_KEYWORDS: tuple[tuple[str, str], ...] = (
    (r"\bDNSSEC\b|\bRRSIG\b|\bNSEC3?\b|\btrust anchor", "area/dnssec"),
    (r"\bDoH\b|\bDoT\b|\bDoQ\b|\bQUIC\b", "area/transport"),
    (r"\bTSIG\b|\bAXFR\b|\bIXFR\b|\bNOTIFY\b", "area/auth-zone"),
    (r"\bDHCP\b", "area/dhcp"),
    (r"\bOOM\b|out of memory|memory leak", "area/performance"),
    (r"\bupdate (check|channel)\b|self-update|auto-?update", "area/updates"),
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
    # A report that says it used to work is a regression, which is triaged
    # differently from a defect that has always been there.
    worked = sections.get("Did this work before?", "")
    if worked and not re.fullmatch(r"(no|n/?a|never|-{1,3}|_No response_)\.?",
                                   worked.strip(), re.IGNORECASE):
        add("type/regression")
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
