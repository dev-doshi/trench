"""Config import from PiHole gravity.db and AdGuard YAML."""
from __future__ import annotations

import sqlite3

from dnsguard.ops.migrate_import import import_adguard, import_pihole


def test_import_pihole(tmp_path):
    db = tmp_path / "gravity.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE adlist(id INTEGER, address TEXT, enabled INT);
        CREATE TABLE domainlist(id INTEGER, type INT, domain TEXT, enabled INT);
        INSERT INTO adlist VALUES (1,'https://example.com/hosts.txt',1),(2,'https://off/list',0);
        INSERT INTO domainlist VALUES (1,1,'ads.bad.com',1),(2,0,'good.com',1),
            (3,3,'^track.*',1),(4,2,'^safe.*',1);
    """)
    con.commit(); con.close()
    res = import_pihole(str(db))
    assert res.sources == ["https://example.com/hosts.txt"]   # disabled excluded
    assert "ads.bad.com" in res.deny
    assert "good.com" in res.allow
    assert "/^track.*/" in res.rules           # deny regex
    assert "@@/^safe.*/" in res.rules          # allow regex


def test_import_adguard(tmp_path):
    yml = tmp_path / "AdGuardHome.yaml"
    yml.write_text("""
filters:
  - enabled: true
    url: https://list.one/hosts
  - enabled: false
    url: https://list.off/hosts
user_rules:
  - "||ads.example^"
  - "@@||safe.example^"
  - "! a comment"
""")
    res = import_adguard(str(yml))
    assert res.sources == ["https://list.one/hosts"]
    assert "||ads.example^" in res.rules
    assert "@@||safe.example^" in res.allow
