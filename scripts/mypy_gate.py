#!/usr/bin/env python3
"""Fail CI on *new* type errors while the existing ones are worked off.

Trench carries a backlog of mypy findings, most of them one of two shapes:
an optional record (`SOA | None`, `Question | None`) used without narrowing,
concentrated in auth_zone/, and a generic `Rdata` read for a field only one
subclass has, in the zone-transfer and DNSSEC code. Fixing the second properly
means precise rdata types across the parser and the validator — worth doing,
and not worth doing in a hurry where a mistake is silent.

Ignoring mypy until then would mean new mistakes land unnoticed. So this
records the backlog in `mypy-baseline.txt` and fails only on findings that are
not in it. The count can go down and never up.

    python3 scripts/mypy_gate.py              # check against the baseline
    python3 scripts/mypy_gate.py --update     # re-record it after fixing some
    python3 scripts/mypy_gate.py --update --allow-growth   # after a mypy upgrade

Line numbers are deliberately not part of a finding's identity: editing the
top of a file would otherwise "introduce" every error below it.
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import re
import subprocess
import sys

BASELINE = pathlib.Path(__file__).resolve().parent.parent / "mypy-baseline.txt"
TARGET = "trench/"

# trench/app.py:488: error: message here  [code]
ERROR = re.compile(r"^(?P<file>[^:]+):\d+: error: (?P<msg>.*?)\s+\[(?P<code>[a-z-]+)\]$")


def signature(line: str) -> str | None:
    m = ERROR.match(line.strip())
    if not m:
        return None
    # Quoted names inside a message are stable; numbers in them are not
    # (mypy prints argument positions), so leave the text alone but drop the
    # line number, which the regex already did.
    return f"{m['file']}\t{m['code']}\t{m['msg']}"


def run_mypy() -> list[str]:
    proc = subprocess.run([sys.executable, "-m", "mypy", TARGET],
                          capture_output=True, text=True)
    if proc.returncode not in (0, 1):        # 2+ means mypy itself failed
        sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit(f"mypy exited {proc.returncode}")
    return [s for s in (signature(x) for x in proc.stdout.splitlines()) if s]


def load() -> collections.Counter:
    if not BASELINE.is_file():
        return collections.Counter()
    return collections.Counter(
        x for x in BASELINE.read_text().splitlines()
        if x.strip() and not x.startswith("#"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--update", action="store_true",
                    help="rewrite the baseline from the current state")
    ap.add_argument("--allow-growth", action="store_true",
                    help="with --update, also record findings that are not in "
                         "the baseline (for a mypy upgrade that rewords or adds "
                         "checks, not for new code)")
    args = ap.parse_args()

    found = collections.Counter(run_mypy())
    base = load()

    if args.update:
        # The ratchet is only a ratchet if re-recording cannot absorb a new
        # finding. A mypy upgrade legitimately changes the set, so that path
        # exists — but it has to be asked for by name, and shows up in review.
        grown = found - base
        if grown and not args.allow_growth:
            print(f"refusing to add {sum(grown.values())} finding(s) to the baseline:\n")
            for sig in sorted(grown):
                path, code, msg = sig.split("\t")
                print(f"  {path}: {msg}  [{code}]")
            print("\nFix them instead. If a mypy upgrade produced them, re-run with "
                  "--allow-growth\nand say so in the pull request.")
            return 1
        total = sum(found.values())
        BASELINE.write_text(
            "# Known mypy findings, recorded by scripts/mypy_gate.py.\n"
            "# New findings fail CI; this file may only ever shrink.\n"
            f"# {total} finding(s).\n"
            + "".join(f"{sig}\n" for sig in sorted(found.elements())))
        print(f"baseline updated: {total} finding(s)")
        return 0

    new = found - base
    fixed = base - found
    if fixed:
        print(f"{sum(fixed.values())} baselined finding(s) no longer occur — "
              f"run 'python3 scripts/mypy_gate.py --update' to lock that in.")
    if not new:
        print(f"no new type errors ({sum(found.values())} baselined)")
        return 0

    print(f"\n{sum(new.values())} new type error(s):\n")
    for sig, count in sorted(new.items()):
        path, code, msg = sig.split("\t")
        print(f"  {path}: {msg}  [{code}]" + (f"  (x{count})" if count > 1 else ""))
    print("\nFix them, or if a finding is genuinely unavoidable add a targeted\n"
          "`# type: ignore[code]` with a comment saying why.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
