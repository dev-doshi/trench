"""Gate the community metadata the way the code is gated.

Issue forms are YAML that GitHub parses at render time, so a mistake in one is
invisible until a user hits it and loses what they typed. This checks, before
merge, that:

  * every issue form parses and has the keys GitHub requires;
  * every label a form applies exists in `.github/labels.yml`;
  * every "which part of Trench" option is mapped to an area label in
    `scripts/triage_labels.py`, so triage cannot silently do nothing;
  * the label manifest itself is well-formed.

    python3 scripts/check_templates.py
"""
from __future__ import annotations

import pathlib
import sys

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from sync_labels import load_manifest  # noqa: E402
from triage_labels import AREA_BY_ANSWER  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
FORMS = ROOT / ".github" / "ISSUE_TEMPLATE"
#: Keys GitHub requires on an issue *form* (config.yml is not one).
_REQUIRED = ("name", "description", "body")
_ELEMENT_TYPES = {"markdown", "input", "textarea", "dropdown", "checkboxes"}


def _check_form(path: pathlib.Path, known: set[str], problems: list[str]) -> None:
    try:
        form = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        problems.append(f"{path.name}: does not parse: {e}")
        return
    if not isinstance(form, dict):
        problems.append(f"{path.name}: must be a mapping")
        return
    for key in _REQUIRED:
        if not form.get(key):
            problems.append(f"{path.name}: missing `{key}`")
    for label in form.get("labels", []):
        if label not in known:
            problems.append(f"{path.name}: applies unknown label {label!r} "
                            "(add it to .github/labels.yml)")
    ids: set[str] = set()
    for i, element in enumerate(form.get("body", []) or []):
        where = f"{path.name}: body[{i}]"
        if not isinstance(element, dict) or "type" not in element:
            problems.append(f"{where}: every element needs a `type`")
            continue
        kind = element["type"]
        if kind not in _ELEMENT_TYPES:
            problems.append(f"{where}: unknown element type {kind!r}")
            continue
        if kind != "markdown":
            ident = element.get("id")
            if not ident:
                problems.append(f"{where}: {kind} needs an `id`")
            elif ident in ids:
                problems.append(f"{where}: duplicate id {ident!r}")
            else:
                ids.add(ident)
        attrs = element.get("attributes") or {}
        if kind != "markdown" and not attrs.get("label"):
            problems.append(f"{where}: {kind} needs a `label`")
        if kind == "dropdown":
            options = attrs.get("options") or []
            if not options:
                problems.append(f"{where}: dropdown has no options")
            if attrs.get("label") in ("Which part of Trench",):
                for option in options:
                    if option not in AREA_BY_ANSWER:
                        problems.append(
                            f"{where}: option {option!r} is not mapped in "
                            "scripts/triage_labels.py, so triage would ignore it")
        if kind == "checkboxes" and not (attrs.get("options") or []):
            problems.append(f"{where}: checkboxes has no options")


def _check_config(path: pathlib.Path, problems: list[str]) -> None:
    try:
        cfg = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        problems.append(f"{path.name}: does not parse: {e}")
        return
    for i, link in enumerate(cfg.get("contact_links", []) or []):
        for key in ("name", "url", "about"):
            if not link.get(key):
                problems.append(f"{path.name}: contact_links[{i}] is missing `{key}`")


def main() -> int:
    problems: list[str] = []
    try:
        known = {label["name"] for label in load_manifest()}
    except (ValueError, OSError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    forms = sorted(p for p in FORMS.glob("*.yml") if p.name != "config.yml")
    if not forms:
        print(f"error: no issue forms found in {FORMS}", file=sys.stderr)
        return 1
    for path in forms:
        _check_form(path, known, problems)
    config = FORMS / "config.yml"
    if config.exists():
        _check_config(config, problems)

    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print(f"{len(forms)} issue form(s) and {len(known)} label(s): consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
