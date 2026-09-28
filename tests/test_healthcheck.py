"""The container healthcheck probes where Trench actually listens.

Nothing covered this file before, and it is the only signal Docker has about
whether Trench is working. Its port used to be hardcoded to 53 while both
`Config`'s default and `trench.example.yaml` say 5354 — a container that
resolved perfectly reported unhealthy for as long as it ran.
"""
from __future__ import annotations

import importlib.util
import pathlib
import socket

import pytest
import yaml

from trench.config import Config

_PATH = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "healthcheck.py"
_spec = importlib.util.spec_from_file_location("trench_healthcheck", _PATH)
assert _spec and _spec.loader
hc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hc)


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for name in ("TRENCH_CONFIG", "TRENCH_HEALTH_HOST", "TRENCH_HEALTH_PORT"):
        monkeypatch.delenv(name, raising=False)


def _config(tmp_path, do53: dict) -> str:
    path = tmp_path / "trench.yaml"
    path.write_text(yaml.safe_dump({"server": {"do53": do53}}))
    return str(path)


def test_port_comes_from_the_config(tmp_path, monkeypatch):
    monkeypatch.setattr(hc, "CONFIG", _config(tmp_path, {"host": "127.0.0.1", "port": 5399}))
    assert hc.target() == ("127.0.0.1", 5399)


def test_shipped_example_is_probed_where_it_listens(monkeypatch):
    """The config the README's Docker quickstart tells you to copy."""
    example = pathlib.Path(__file__).resolve().parents[1] / "trench.example.yaml"
    monkeypatch.setattr(hc, "CONFIG", str(example))
    do53 = Config.model_validate(yaml.safe_load(example.read_text())).server.do53
    assert hc.target() == (do53.host, do53.port)
    assert do53.port != hc.FALLBACK[1], "example no longer differs from the old hardcoded port"


def test_wildcard_host_is_probed_over_loopback(tmp_path, monkeypatch):
    monkeypatch.setattr(hc, "CONFIG", _config(tmp_path, {"host": "0.0.0.0", "port": 53}))
    assert hc.target() == ("127.0.0.1", 53)


def test_missing_config_falls_back(monkeypatch, tmp_path):
    monkeypatch.setattr(hc, "CONFIG", str(tmp_path / "absent.yaml"))
    assert hc.target() == hc.FALLBACK


def test_env_overrides_the_config(tmp_path, monkeypatch):
    monkeypatch.setattr(hc, "CONFIG", _config(tmp_path, {"host": "127.0.0.1", "port": 5399}))
    monkeypatch.setenv("TRENCH_HEALTH_PORT", "5300")
    assert hc.target() == ("127.0.0.1", 5300)


def test_disabled_do53_says_so_instead_of_timing_out(tmp_path, monkeypatch):
    monkeypatch.setattr(hc, "CONFIG", _config(tmp_path, {"enabled": False}))
    with pytest.raises(hc.NoListener):
        hc.target()
    assert hc.main() == 1


def test_disabled_do53_yields_to_an_explicit_port(tmp_path, monkeypatch):
    monkeypatch.setattr(hc, "CONFIG", _config(tmp_path, {"enabled": False}))
    monkeypatch.setenv("TRENCH_HEALTH_PORT", "5300")
    assert hc.target() == (hc.FALLBACK[0], 5300)


def test_a_live_answer_passes_and_a_foreign_packet_does_not(monkeypatch):
    """End to end over a real socket: the reply must carry the id we sent."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    monkeypatch.setenv("TRENCH_HEALTH_HOST", "127.0.0.1")
    monkeypatch.setenv("TRENCH_HEALTH_PORT", str(port))
    monkeypatch.setattr(hc, "TIMEOUT", 2.0)

    def serve(reply_id: int) -> None:
        data, peer = srv.recvfrom(4096)
        srv.sendto(reply_id.to_bytes(2, "big") + b"\x81\x80" + data[4:], peer)

    import threading
    t = threading.Thread(target=serve, args=(hc.QID,), daemon=True)
    t.start()
    assert hc.main() == 0
    t.join(2)

    t = threading.Thread(target=serve, args=(hc.QID ^ 0xFFFF,), daemon=True)
    t.start()
    assert hc.main() == 1, "a reply carrying somebody else's id must not pass"
    t.join(3)
    srv.close()
