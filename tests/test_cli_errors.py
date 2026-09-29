"""What the CLI does when the operator's environment is wrong.

A missing path, an archive that is not one, a file that is not a Pi-hole
database: each gets one `error:` line on stderr and exit 1 — never a traceback,
and never output on stdout that a script could redirect into a config file.
Usage mistakes are argparse's: exit 2.
"""
from __future__ import annotations

import sqlite3

import pytest

from trench.cli.main import main


def _pihole_db(path):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE adlist(address, enabled)")
    con.execute("CREATE TABLE domainlist(type, domain, enabled)")
    con.execute("INSERT INTO adlist VALUES('https://lists.example/a.txt', 1)")
    con.execute("INSERT INTO domainlist VALUES(1, 'bad.example', 1)")
    con.commit()
    con.close()


def _one_error_line(capsys):
    cap = capsys.readouterr()
    assert cap.out == ""
    assert "Traceback" not in cap.err
    assert len(cap.err.strip().splitlines()) == 1
    return cap.err


def test_import_pihole_accepts_the_pihole_directory(tmp_path, capsys):
    _pihole_db(tmp_path / "gravity.db")
    assert main(["import", "pihole", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "https://lists.example/a.txt" in out and "bad.example" in out


@pytest.mark.parametrize("kind", ["pihole", "adguard"])
def test_import_of_a_missing_path_is_one_line(tmp_path, capsys, kind):
    assert main(["import", kind, str(tmp_path / "nope")]) == 1
    assert "not found" in _one_error_line(capsys)


def test_import_pihole_of_a_non_database_is_one_line(tmp_path, capsys):
    junk = tmp_path / "gravity.db"
    junk.write_bytes(b"\x00not sqlite" * 20)
    assert main(["import", "pihole", str(junk)]) == 1
    assert "not a readable Pi-hole gravity.db" in _one_error_line(capsys)


def test_import_pihole_of_a_foreign_database_is_one_line(tmp_path, capsys):
    other = tmp_path / "other.db"
    sqlite3.connect(other).execute("CREATE TABLE t(x)").connection.close()
    assert main(["import", "pihole", str(other)]) == 1
    assert "no such table" in _one_error_line(capsys)


def test_import_adguard_of_binary_is_one_line(tmp_path, capsys):
    junk = tmp_path / "AdGuardHome.yaml"
    junk.write_bytes(bytes(range(128, 256)))
    assert main(["import", "adguard", str(junk)]) == 1
    assert "not a usable adguard config" in _one_error_line(capsys)


def test_backup_refuses_a_data_dir_that_is_a_file(tmp_path, capsys):
    f = tmp_path / "file"
    f.write_text("x")
    assert main(["backup", str(tmp_path / "b.tgz"), "--data-dir", str(f)]) == 1
    assert "not a directory" in _one_error_line(capsys)
    assert not (tmp_path / "b.tgz").exists()


def test_backup_into_a_missing_directory_is_one_line(tmp_path, capsys):
    (tmp_path / "data").mkdir()
    out = tmp_path / "no" / "such" / "b.tgz"
    assert main(["backup", str(out), "--data-dir", str(tmp_path / "data")]) == 1
    assert "does not exist" in _one_error_line(capsys)


def test_a_failed_backup_leaves_nothing_behind(tmp_path, monkeypatch):
    """A truncated archive at the target name is worse than none: a restore
    would trust it."""
    import tarfile
    data = tmp_path / "data"
    data.mkdir()
    (data / "a").write_text("x")
    out = tmp_path / "b.tgz"

    def boom(self, *a, **kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(tarfile.TarFile, "add", boom)
    assert main(["backup", str(out), "--data-dir", str(data)]) == 1
    assert list(tmp_path.iterdir()) == [data]


def test_backup_inside_the_data_dir_does_not_archive_itself(tmp_path):
    import tarfile
    data = tmp_path / "data"
    data.mkdir()
    (data / "a").write_text("x")
    out = data / "b.tgz"
    assert main(["backup", str(out), "--data-dir", str(data)]) == 0
    with tarfile.open(out) as tar:
        assert sorted(tar.getnames()) == ["data", "data/a"]


def test_restore_of_a_missing_archive_is_one_line(tmp_path, capsys):
    assert main(["restore", str(tmp_path / "nope.tgz"),
                 "--data-dir", str(tmp_path / "d")]) == 1
    assert "trench restore: error:" in _one_error_line(capsys)


def test_restore_of_a_non_archive_is_one_line(tmp_path, capsys):
    junk = tmp_path / "junk.tgz"
    junk.write_text("not a tarball")
    assert main(["restore", str(junk), "--data-dir", str(tmp_path / "d")]) == 1
    assert "not a gzip file" in _one_error_line(capsys)


def test_regex_test_with_a_missing_rule_file_is_one_line(tmp_path, capsys):
    assert main(["regex-test", f"@{tmp_path / 'nope'}", "a.example"]) == 1
    _one_error_line(capsys)


@pytest.mark.parametrize("bad", ["abc", "nan", "5x"])
def test_pause_rejects_a_bad_duration_before_sending_anything(capsys, bad):
    with pytest.raises(SystemExit) as e:
        main(["pause", bad, "--url", "http://127.0.0.1:1"])
    assert e.value.code == 2
    assert "invalid duration" in capsys.readouterr().err


def test_restore_replaces_rather_than_merges(tmp_path):
    """A leftover `trench.db-wal` next to a restored `trench.db` is replayed
    into it by SQLite: files the archive does not carry must not survive."""
    data = tmp_path / "data"
    data.mkdir()
    (data / "keep.txt").write_text("new")
    archive = tmp_path / "b.tgz"
    assert main(["backup", str(archive), "--data-dir", str(data)]) == 0
    dest = tmp_path / "dest"
    (dest / "sub").mkdir(parents=True)
    (dest / "trench.db-wal").write_text("stale")
    (dest / "sub" / "old").write_text("stale")
    assert main(["restore", str(archive), "--data-dir", str(dest), "--force"]) == 0
    assert sorted(p.name for p in dest.iterdir()) == ["keep.txt"]


def test_a_truncated_archive_leaves_the_target_untouched(tmp_path, capsys):
    data = tmp_path / "data"
    data.mkdir()
    (data / "big").write_bytes(__import__("os").urandom(200_000))
    archive = tmp_path / "b.tgz"
    assert main(["backup", str(archive), "--data-dir", str(data)]) == 0
    archive.write_bytes(archive.read_bytes()[:50_000])
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "current").write_text("still here")
    capsys.readouterr()
    assert main(["restore", str(archive), "--data-dir", str(dest), "--force"]) == 1
    assert "trench restore: error:" in _one_error_line(capsys)
    assert sorted(p.name for p in dest.iterdir()) == ["current"]


def test_backup_snapshots_a_live_database(tmp_path):
    """Rows still in the WAL, with the writer's connection open, are in the
    archive's database — and the archive carries no -wal/-shm to pair wrongly."""
    import tarfile
    data = tmp_path / "data"
    data.mkdir()
    live = sqlite3.connect(data / "trench.db")
    live.execute("PRAGMA journal_mode=WAL")
    live.execute("PRAGMA wal_autocheckpoint=0")
    live.execute("CREATE TABLE t(x)")
    live.executemany("INSERT INTO t VALUES(?)", [(i,) for i in range(500)])
    live.commit()
    assert (data / "trench.db-wal").stat().st_size > 0
    try:
        archive = tmp_path / "b.tgz"
        assert main(["backup", str(archive), "--data-dir", str(data)]) == 0
    finally:
        live.close()
    with tarfile.open(archive) as tar:
        assert sorted(tar.getnames()) == ["data", "data/trench.db"]
    dest = tmp_path / "dest"
    assert main(["restore", str(archive), "--data-dir", str(dest)]) == 0
    con = sqlite3.connect(dest / "trench.db")
    try:
        assert con.execute("SELECT count(*) FROM t").fetchone() == (500,)
        assert con.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        con.close()
    assert not list(tmp_path.glob(".b.tgz*"))
