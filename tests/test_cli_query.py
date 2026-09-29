"""`trench query` — the built-in dig — and the CLI's remaining offline paths.

`query` is what an operator uses to check the server from the box itself, over
each transport in turn, and no test called it: neither the transport spelling,
the rendering of an answer, nor the failure message.
"""
from __future__ import annotations

import asyncio
import socket
import threading

import pytest

from trench.cli.main import main
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.rrtypes import Flags, Rcode


class UdpEcho:
    """A one-shot DNS server that answers whatever it is asked."""

    def __init__(self, answers=None, rcode=Rcode.NOERROR):
        self.answers = answers if answers is not None else [("1.2.3.4", 300)]
        self.rcode = rcode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.questions: list = []
        self._t = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *a):
        self.sock.close()

    def _serve(self):
        try:
            data, addr = self.sock.recvfrom(4096)
        except OSError:
            return
        q = Message.parse(data)
        self.questions.append(q.question)
        resp = q.reply(self.rcode)
        for ip, ttl in self.answers:
            resp.answers.append(RR(q.question.name, Type.A, Class.IN, ttl, R.A(ip)))
        try:
            self.sock.sendto(resp.to_wire(), addr)
        except OSError:
            pass


def test_query_prints_status_and_answers(capsys):
    with UdpEcho([("93.184.216.34", 120)]) as srv:
        rc = main(["query", "example.com", "A", "@udp",
                   "--server", f"127.0.0.1:{srv.port}"])
    assert rc == 0
    out = capsys.readouterr().out
    assert ";; status: NOERROR, answers: 1 (udp)" in out
    assert "example.com." in out and "120" in out and "93.184.216.34" in out
    assert srv.questions[0].rtype == Type.A


def test_query_defaults_to_an_a_record_over_udp(capsys):
    with UdpEcho() as srv:
        assert main(["query", "example.com", "--server", f"127.0.0.1:{srv.port}"]) == 0
    assert srv.questions[0].rtype == Type.A
    assert "(udp)" in capsys.readouterr().out


def test_query_honours_the_record_type(capsys):
    with UdpEcho([]) as srv:
        main(["query", "example.com", "AAAA", "--server", f"127.0.0.1:{srv.port}"])
    assert srv.questions[0].rtype == Type.AAAA


def test_query_renders_a_non_zero_rcode(capsys):
    with UdpEcho([], rcode=Rcode.NXDOMAIN) as srv:
        assert main(["query", "nope.example.com",
                     "--server", f"127.0.0.1:{srv.port}"]) == 0
    assert ";; status: NXDOMAIN, answers: 0" in capsys.readouterr().out


def test_query_reports_a_failure_on_stderr(capsys):
    # Nothing listening: the upstream retries and then gives up.
    rc = main(["query", "example.com", "--server", "127.0.0.1:1"])
    assert rc == 1
    assert ";; query failed:" in capsys.readouterr().err


def test_query_rejects_an_unknown_record_type(capsys):
    # A typo is a usage error with a suggestion, not a Python traceback.
    assert main(["query", "example.com", "NOTATYPE", "--server", "127.0.0.1:1"]) == 2
    err = capsys.readouterr().err
    assert "unknown record type 'NOTATYPE'" in err and "AAAA" in err


def test_query_rejects_an_unknown_transport(capsys):
    assert main(["query", "example.com", "A", "@carrier-pigeon"]) == 2
    assert "@udp, @tcp, @tls, @https or @quic" in capsys.readouterr().err


def test_query_reports_how_long_it_took(capsys):
    with UdpEcho() as srv:
        main(["query", "example.com", "--server", f"127.0.0.1:{srv.port}"])
    assert ";; query time:" in capsys.readouterr().out


@pytest.mark.parametrize("transport,scheme", [
    ("@udp", "udp"), ("@tcp", "tcp"), ("@tls", "tls"),
    ("@https", "https"), ("@quic", "quic"), ("udp", "udp"), ("", "udp"),
])
def test_query_accepts_every_transport_spelling(transport, scheme, monkeypatch):
    """The spelling has to survive into the upstream spec. Driven through a
    double rather than a dead port: a QUIC handshake to a black hole takes a
    full minute to give up, which is correct and useless in a test."""
    from trench.cli.main import _do_query

    seen = {}

    class FakeUp:
        def __init__(self, spec, verify=True):
            seen["spec"] = spec

        async def query(self, q):
            return q.reply(Rcode.NOERROR)

        async def close(self):
            pass

    import trench.transport.upstream as up_mod
    monkeypatch.setattr(up_mod, "Upstream", FakeUp)
    args = type("A", (), {"transport": transport, "server": "127.0.0.1:5354",
                          "insecure": True, "type": "A", "name": "example.com"})()
    assert asyncio.run(_do_query(args)) == 0
    assert seen["spec"].scheme == scheme


def test_query_over_a_dead_port_fails_rather_than_hanging(capsys):
    assert main(["query", "example.com", "A", "@tcp", "--server", "127.0.0.1:1"]) == 1
    assert ";; query failed:" in capsys.readouterr().err


def test_query_over_tcp_against_a_real_listener(capsys):
    """The TCP path frames with a two-byte length prefix; UDP does not."""
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]

    def serve():
        conn, _ = lsock.accept()
        with conn:
            head = conn.recv(2)
            n = int.from_bytes(head, "big")
            q = Message.parse(conn.recv(n))
            resp = q.reply(Rcode.NOERROR)
            resp.answers.append(RR(q.question.name, Type.A, Class.IN, 60,
                                   R.A("10.0.0.1")))
            wire = resp.to_wire()
            conn.sendall(len(wire).to_bytes(2, "big") + wire)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        assert main(["query", "example.com", "A", "@tcp",
                     "--server", f"127.0.0.1:{port}"]) == 0
    finally:
        t.join(5)
        lsock.close()
    out = capsys.readouterr().out
    assert "(tcp)" in out and "10.0.0.1" in out


def test_query_message_carries_rd():
    """Asserted directly, since the server double only records the question."""
    from trench.cli.main import _do_query

    captured = {}

    class FakeUp:
        def __init__(self, spec, verify=True):
            captured["verify"] = verify
            captured["spec"] = spec

        async def query(self, q):
            captured["q"] = q
            return q.reply(Rcode.NOERROR)

        async def close(self):
            captured["closed"] = True

    import trench.transport.upstream as up_mod
    real = up_mod.Upstream
    up_mod.Upstream = FakeUp
    try:
        args = type("A", (), {"transport": "@udp", "server": "127.0.0.1:53",
                              "insecure": True, "type": "A", "name": "example.com"})()
        assert asyncio.run(_do_query(args)) == 0
    finally:
        up_mod.Upstream = real
    assert captured["q"].flags & Flags.RD
    assert captured["verify"] is False           # --insecure
    assert captured["closed"] is True            # the session is always closed


# --- the offline tools not otherwise covered ---
def test_regex_test_reads_rules_from_a_file(tmp_path, capsys):
    rules = tmp_path / "rules.txt"
    rules.write_text("||ads.example.com^\n@@||ok.ads.example.com^$important\n")
    assert main(["regex-test", f"@{rules}", "ads.example.com",
                 "ok.ads.example.com", "safe.example.com"]) == 0
    lines = {ln.split()[0]: ln for ln in capsys.readouterr().out.strip().splitlines()}
    assert "BLOCK" in lines["ads.example.com"]
    assert "ALLOW" in lines["ok.ads.example.com"]
    assert "NONE" in lines["safe.example.com"]


def test_regex_test_reports_an_unparseable_rule(capsys):
    assert main(["regex-test", "#a comment", "example.com"]) == 1
    assert "no valid rule parsed" in capsys.readouterr().err


def test_regex_test_lowercases_the_names_under_test(capsys):
    main(["regex-test", "||ads.example.com^", "ADS.EXAMPLE.COM"])
    assert "BLOCK" in capsys.readouterr().out


def test_regex_test_names_the_matching_rule(capsys):
    main(["regex-test", "||ads.example.com^", "ads.example.com"])
    assert "[ads.example.com]" in capsys.readouterr().out


def test_backup_refuses_a_missing_data_dir(tmp_path, capsys):
    rc = main(["backup", str(tmp_path / "out.tar.gz"),
               "--data-dir", str(tmp_path / "nope")])
    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_restore_refuses_a_member_outside_the_data_dir(tmp_path, capsys):
    """An archive is untrusted input; a `../../etc/...` member used to pass
    through the name rewrite untouched."""
    import tarfile
    archive = tmp_path / "evil.tar.gz"
    payload = tmp_path / "payload"
    payload.write_text("pwned")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(payload, arcname="data/../../escape.txt")
    dest = tmp_path / "restored"
    rc = main(["restore", str(archive), "--data-dir", str(dest)])
    assert rc == 1
    assert "refusing member outside the data dir" in capsys.readouterr().err
    assert not (tmp_path.parent / "escape.txt").exists()


def test_restore_skips_link_members(tmp_path, capsys):
    import tarfile
    archive = tmp_path / "links.tar.gz"
    real = tmp_path / "real.txt"
    real.write_text("ok")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(real, arcname="data/real.txt")
        info = tarfile.TarInfo("data/link.txt")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    dest = tmp_path / "restored"
    assert main(["restore", str(archive), "--data-dir", str(dest)]) == 0
    assert "skipping link member" in capsys.readouterr().err
    assert (dest / "real.txt").read_text() == "ok"
    assert not (dest / "link.txt").exists()


def test_restore_skips_special_members(tmp_path, capsys):
    import tarfile
    archive = tmp_path / "special.tar.gz"
    real = tmp_path / "real.txt"
    real.write_text("ok")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(real, arcname="data/real.txt")
        info = tarfile.TarInfo("data/fifo")
        info.type = tarfile.FIFOTYPE
        tar.addfile(info)
    dest = tmp_path / "restored"
    assert main(["restore", str(archive), "--data-dir", str(dest)]) == 0
    assert "skipping special member" in capsys.readouterr().err


def test_restore_into_a_nonempty_dir_with_force(tmp_path, capsys):
    import tarfile
    data = tmp_path / "data"
    data.mkdir()
    (data / "a.txt").write_text("new")
    archive = tmp_path / "b.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(data, arcname="data")
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "old.txt").write_text("stale")
    assert main(["restore", str(archive), "--data-dir", str(dest), "--force"]) == 0
    assert (dest / "a.txt").read_text() == "new"


def test_profile_requires_a_transport(capsys):
    assert main(["profile"]) == 1
    assert "provide --doh-url or --dot-host" in capsys.readouterr().err


def test_profile_with_dot_and_pinned_addresses(capsys):
    rc = main(["profile", "--dot-host", "dns.example.org",
               "--address", "192.0.2.1", "--address", "2001:db8::1"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dns.example.org" in out and "192.0.2.1" in out and "2001:db8::1" in out


def test_stamp_dot(capsys):
    assert main(["stamp", "dot", "dns.example.org", "--port", "8853"]) == 0
    assert capsys.readouterr().out.startswith("sdns://")


def test_import_requires_a_known_kind():
    with pytest.raises(SystemExit):
        main(["import", "unbound", "/tmp/x"])


def test_no_subcommand_is_rejected():
    with pytest.raises(SystemExit):
        main([])


def test_restore_skips_the_archive_root_directory_entry(tmp_path):
    """A `data/` member strips to the empty name; extracting it would recreate
    the top-level directory inside itself."""
    import tarfile
    archive = tmp_path / "roots.tar.gz"
    real = tmp_path / "real.txt"
    real.write_text("ok")
    with tarfile.open(archive, "w:gz") as tar:
        tar.addfile(tarfile.TarInfo("data"))          # bare top-dir entry
        info = tarfile.TarInfo("data/")               # and its trailing-slash twin
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
        tar.add(real, arcname="data/real.txt")
    dest = tmp_path / "restored"
    assert main(["restore", str(archive), "--data-dir", str(dest)]) == 0
    assert (dest / "real.txt").read_text() == "ok"
    assert not (dest / "data").exists()
