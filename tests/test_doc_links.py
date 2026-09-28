"""Every GitHub URL in the shipped docs points at this repository.

`pyproject.toml` names the project's own URLs, so it is the reference rather
than a string repeated in a test. One link had been left on a `trench/trench`
placeholder — the one from the configuration guide to `trench.example.yaml`,
which is the file that guide sends readers to for the full setting reference.
"""
from __future__ import annotations

import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
_GITHUB = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")


def _canonical() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    return _GITHUB.search(data["project"]["urls"]["Source"]).group(1)


def _documents():
    yield ROOT / "README.md"
    yield ROOT / "mkdocs.yml"
    yield from sorted((ROOT / "docs").glob("*.md"))


def test_no_document_links_at_another_repository():
    canonical = _canonical()
    wrong = []
    for path in _documents():
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            for match in _GITHUB.finditer(line):
                repo = match.group(1).removesuffix(".git")
                if repo != canonical:
                    wrong.append(f"{path.relative_to(ROOT)}:{lineno} -> {repo}")
    assert not wrong, f"links to a repository that is not {canonical}:\n  " + "\n  ".join(wrong)
