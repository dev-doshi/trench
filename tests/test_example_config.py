"""`trench.example.yaml` against the model it is supposed to describe.

The file says every key Trench reads is shown in it, which made it the one
place an operator can discover a setting without reading `config.py`. That
claim had quietly stopped being true: thirty settings had accreted without
being added, including every stream and UDP bound that keeps a flood from
costing a task and a parse, the fast path, DoH3, DNS cookies, TSIG keys and
secondary zones.

So the claim is a test rather than a sentence. Adding a setting now fails here
until it is documented — which is the only way a reference file stays one.
"""
from __future__ import annotations

import pathlib

import pytest
import yaml

from trench.config import Config

EXAMPLE = pathlib.Path(__file__).resolve().parent.parent / "trench.example.yaml"

#: Keys that are deliberately absent, with the reason. Anything else missing is
#: an omission, not a decision.
UNDOCUMENTED = {
    "allow_dhcp": "a runtime gate set by the --allow-dhcp CLI flag, not a file key",
}

#: Keys whose shown value is deliberately not the default, because the file
#: doubles as a starter config. The header says so; this says which.
NOT_THE_DEFAULT = {
    "data_dir", "server.do53.port", "upstream.servers", "filtering.sources",
    "server.dot.host", "server.doh.host", "server.doq.host", "server.doh3.host",
    "server.user", "server.group",
}


def _paths(model, prefix: str = "") -> set[str]:
    out = set()
    for name, field in model.model_fields.items():
        path = f"{prefix}{name}"
        out.add(path)
        if hasattr(field.annotation, "model_fields"):
            out |= _paths(field.annotation, path + ".")
    return out


@pytest.fixture(scope="module")
def example() -> dict:
    return yaml.safe_load(EXAMPLE.read_text()) or {}


def test_the_example_validates_against_the_model(example):
    Config.model_validate(example)


def test_the_example_has_no_keys_the_model_does_not_read(example):
    """The other direction: a key removed from the model but left in the file
    reads as a supported setting that silently does nothing."""
    known = _paths(Config)
    stale = []

    def walk(node, prefix=""):
        for key, value in (node or {}).items():
            path = f"{prefix}{key}"
            if path not in known:
                stale.append(path)
            elif isinstance(value, dict):
                walk(value, path + ".")

    walk(example)
    assert not stale, f"documented but not read by Trench: {stale}"


def test_every_setting_appears_in_the_example():
    text = EXAMPLE.read_text()
    missing = sorted(p for p in _paths(Config)
                     if p not in UNDOCUMENTED and p.rsplit(".", 1)[-1] not in text)
    assert not missing, (
        f"{len(missing)} setting(s) missing from trench.example.yaml: {missing}\n"
        "Document them, or add them to UNDOCUMENTED here with the reason.")


def test_the_values_shown_are_the_defaults(example):
    """The file's own claim, minus the starter-config values it flags."""
    defaults = Config.model_validate({})
    wrong = []

    def walk(shown, actual, prefix=""):
        for key, value in (shown or {}).items():
            if not hasattr(actual, key):
                continue
            real = getattr(actual, key)
            path = f"{prefix}{key}"
            if isinstance(value, dict) and hasattr(real, "model_fields"):
                walk(value, real, path + ".")
            elif (not isinstance(value, dict) and path not in NOT_THE_DEFAULT
                    and value != real):
                wrong.append(f"{path}: shown {value!r}, default {real!r}")

    walk(example, defaults)
    assert not wrong, (
        "trench.example.yaml says the shown values are the defaults:\n  "
        + "\n  ".join(wrong))
