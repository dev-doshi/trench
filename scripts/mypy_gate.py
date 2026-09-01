#!/usr/bin/env python3
"""Fail CI on *new* type errors while the existing ones are worked off.

Trench carries a backlog of mypy findings, most of them the same shape: the
DNSSEC and wire layers pass rdata around as `object` and duck-type it, so mypy
sees an attribute access on `object` and objects. Fixing that properly means
introducing precise rdata types across the parser and the validator — worth
doing, and not worth doing in a hurry in the two subsystems where a mistake
is silent.

Ignoring mypy until then would mean new mistakes land unnoticed. So this
records the backlog in `mypy-baseline.txt` and fails only on findings that are
not in it. The count can go down and never up.

    python3 scripts/mypy_gate.py              # check against the baseline
    python3 scripts/mypy_gate.py --update     # re-record it (only ever smaller)

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
    args = ap.parse_args()

    found = collections.Counter(run_mypy())
    base = load()

    if args.update:
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
