"""A console entry for a device the config file declares changes only what it says.

The console writes a `client` row the first time anyone changes one thing about
a device — puts it in a group, exempts it — and that row overrides the file's
entry on the same ident. Every field the row left out used to fall back to the
global default, so putting the kids' tablet in a group silently dropped its
name and its tags.
"""
from __future__ import annotations

import json

from trench.clients.registry import ClientRegistry
from trench.config import Config


def _cfg():
    return Config.model_validate({
        "filtering": {"groups": {"kids": {"deny": ["a.example"]}, "work": {"deny": ["b.example"]}}},
        "clients": [
        {"ident": "10.0.0.7", "type": "ip", "name": "tablet", "block": False,
         "tags": ["kids"], "safe_search": True, "group": "kids"},
    ]})


def _row(policy, name="", ident="10.0.0.7"):
    return {"ident": ident, "ident_type": "ip", "name": name, "policy": json.dumps(policy)}


def test_a_group_change_keeps_the_files_name_and_exemption():
    c = ClientRegistry.client_from_row(_cfg(), _row({"group": "work"}))
    assert c.name == "tablet" and c.policy.name == "tablet"
    assert c.policy.group == "work"
    assert c.policy.block is False and c.policy.ctags == frozenset({"kids"})
    assert c.policy.safe_search is True


def test_what_the_row_says_still_wins():
    c = ClientRegistry.client_from_row(_cfg(), _row({"block": True, "group": ""}, name="Tab"))
    assert (c.name, c.policy.block, c.policy.group) == ("Tab", True, "")


def test_a_device_the_file_does_not_know_gets_the_defaults():
    c = ClientRegistry.client_from_row(_cfg(), _row({"group": "kids"}, ident="10.0.0.8"))
    assert (c.name, c.policy.block, c.policy.safe_search) == ("", True, False)
    assert c.policy.name == "10.0.0.8"
