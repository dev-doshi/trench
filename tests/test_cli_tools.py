"""The CLI's offline tools: TSIG keygen, regex-test, backup/restore, Apple
configuration profiles, DNS stamps."""
from __future__ import annotations

import base64

from trench.cli.main import main


def test_keygen_tsig(capsys):
    assert main(["keygen-tsig", "mykey", "--bytes", "16"]) == 0
    out = capsys.readouterr().out
    assert "tsig_keys:" in out and "name: mykey." in out
    secret = [ln.split("secret:")[1].strip() for ln in out.splitlines() if "secret:" in ln][0]
    assert len(base64.b64decode(secret)) == 16


def test_regex_test_block(capsys):
    # adblock-style suffix rule should block the domain + subdomains
    assert main(["regex-test", "||ads.example.com^", "ads.example.com", "safe.com"]) == 0
    out = capsys.readouterr().out
    lines = {ln.split()[0]: ln for ln in out.strip().splitlines()}
    assert "BLOCK" in lines["ads.example.com"]
    assert "BLOCK" not in lines["safe.com"]


def test_backup_restore_roundtrip(tmp_path, capsys):
    data = tmp_path / "data"
    data.mkdir()
    (data / "config.yaml").write_text("hello: world")
    (data / "sub").mkdir()
    (data / "sub" / "x.txt").write_text("nested")
    archive = tmp_path / "backup.tar.gz"
    assert main(["backup", str(archive), "--data-dir", str(data)]) == 0
    assert archive.exists()

    dest = tmp_path / "restored"
    assert main(["restore", str(archive), "--data-dir", str(dest)]) == 0
    assert (dest / "config.yaml").read_text() == "hello: world"
    assert (dest / "sub" / "x.txt").read_text() == "nested"


def test_restore_refuses_nonempty(tmp_path):
    data = tmp_path / "d"; data.mkdir(); (data / "f").write_text("x")
    archive = tmp_path / "b.tar.gz"
    main(["backup", str(archive), "--data-dir", str(data)])
    dest = tmp_path / "dest"; dest.mkdir(); (dest / "keep").write_text("important")
    assert main(["restore", str(archive), "--data-dir", str(dest)]) == 1
    assert (dest / "keep").exists()


def test_profile_emits_plist(capsys):
    assert main(["profile", "--doh-url", "https://dns.home/dns-query"]) == 0
    out = capsys.readouterr().out
    import plistlib
    plist = plistlib.loads(out.encode())
    assert plist["PayloadContent"][0]["DNSSettings"]["ServerURL"] == "https://dns.home/dns-query"


def test_stamp_doh(capsys):
    assert main(["stamp", "doh", "dns.example.com"]) == 0
    assert capsys.readouterr().out.strip().startswith("sdns://")
