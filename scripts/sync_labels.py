"""Reconcile the repository's labels with `.github/labels.yml`.

Labels drift: someone renames one in the web UI, a colour is picked twice, a
form starts applying a label nobody created and the label silently does not
appear. This makes the file the source of truth and the UI the projection.

    python3 scripts/sync_labels.py --repo owner/name            # create/update
    python3 scripts/sync_labels.py --repo owner/name --prune    # also delete
    python3 scripts/sync_labels.py --check                      # parse only

`--prune` deletes labels the file does not list, which throws away their
history on any issue that used them, so it is opt-in and CI never passes it.

Auth comes from GITHUB_TOKEN (the workflow's own token is enough: it needs
`issues: write`). Uses urllib rather than requests so the workflow needs no
install step.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

import yaml

API = "https://api.github.com"
MANIFEST = pathlib.Path(__file__).resolve().parent.parent / ".github" / "labels.yml"


def load_manifest(path: pathlib.Path = MANIFEST) -> list[dict]:
    """The manifest, validated. Raises ValueError on anything malformed."""
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, list) or not data:
        raise ValueError(f"{path} must be a non-empty list of labels")
    seen: set[str] = set()
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: every entry must be a mapping, got {entry!r}")
        missing = {"name", "color", "description"} - set(entry)
        if missing:
            raise ValueError(f"{path}: {entry.get('name', entry)!r} is missing {sorted(missing)}")
        name = str(entry["name"])
        if name in seen:
            raise ValueError(f"{path}: duplicate label {name!r}")
        seen.add(name)
        color = str(entry["color"]).lstrip("#")
        if len(color) != 6 or any(c not in "0123456789abcdefABCDEF" for c in color):
            raise ValueError(f"{path}: {name!r} has a bad colour {entry['color']!r}")
        entry["color"] = color.lower()
    return data


def _request(method: str, url: str, token: str, body: dict | None = None) -> dict | list:
    payload = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=payload, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:   # noqa: S310 - fixed host
        raw = resp.read()
    return json.loads(raw) if raw else {}


def existing_labels(repo: str, token: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    page = 1
    while True:
        got = _request("GET", f"{API}/repos/{repo}/labels?per_page=100&page={page}", token)
        if not isinstance(got, list) or not got:
            break
        for label in got:
            out[label["name"]] = label
        if len(got) < 100:
            break
        page += 1
    return out


def sync(repo: str, token: str, manifest: list[dict], *, prune: bool = False,
         dry_run: bool = False) -> int:
    """Create, update and optionally delete. Returns the number of changes."""
    have = existing_labels(repo, token)
    changed = 0
    for want in manifest:
        name = want["name"]
        current = have.get(name)
        if current is None:
            print(f"+ create {name}")
            changed += 1
            if not dry_run:
                _request("POST", f"{API}/repos/{repo}/labels", token, want)
        elif (current.get("color", "").lower() != want["color"]
              or (current.get("description") or "") != want["description"]):
            print(f"~ update {name}")
            changed += 1
            if not dry_run:
                url = f"{API}/repos/{repo}/labels/{urllib.parse.quote(name)}"
                _request("PATCH", url, token, want)
    if prune:
        for name in sorted(set(have) - {label["name"] for label in manifest}):
            print(f"- delete {name}")
            changed += 1
            if not dry_run:
                url = f"{API}/repos/{repo}/labels/{urllib.parse.quote(name)}"
                _request("DELETE", url, token)
    return changed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""),
                    help="owner/name (defaults to $GITHUB_REPOSITORY)")
    ap.add_argument("--prune", action="store_true",
                    help="delete labels the manifest does not list (destructive)")
    ap.add_argument("--dry-run", action="store_true", help="say what would change")
    ap.add_argument("--check", action="store_true",
                    help="validate the manifest and exit, touching no network")
    args = ap.parse_args(argv)

    try:
        manifest = load_manifest()
    except (ValueError, OSError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.check:
        print(f"{MANIFEST.name}: {len(manifest)} labels, all well-formed")
        return 0

    token = os.environ.get("GITHUB_TOKEN", "")
    if not args.repo or not token:
        print("error: --repo and GITHUB_TOKEN are both required", file=sys.stderr)
        return 1
    try:
        changed = sync(args.repo, token, manifest, prune=args.prune, dry_run=args.dry_run)
    except urllib.error.HTTPError as e:
        print(f"error: GitHub said {e.code}: {e.read().decode(errors='replace')}",
              file=sys.stderr)
        return 1
    print(f"{changed} change(s)" + (" (dry run)" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
