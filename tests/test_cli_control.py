"""The CLI's daemon-facing commands, against a real HTTP server.

`status`/`toggle`/`flush-cache`/`update`, `upgrade`, `why` and `pause` are the
commands an operator reaches for when something is wrong, and none of them was
covered: their error handling — the "is the daemon running?" hint, the HTTPError
body that carries the daemon's refusal, the long timeout that stops a two-minute
pip install being reported as a failure — existed only on paper.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from trench.cli.main import _seconds, main


class _Handler(BaseHTTPRequestHandler):
    routes: dict = {}
    seen: list = []

    def _respond(self):
        key = (self.command, self.path.split("?")[0])
        entry = self.routes.get(key) or self.routes.get(("*", self.path.split("?")[0]))
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.seen.append({"method": self.command, "path": self.path, "body": body,
                          "auth": self.headers.get("Authorization")})
        if entry is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error":"no such route"}')
            return
        status, payload = entry
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST = _respond

    def log_message(self, *a):
        pass


@pytest.fixture
def api():
    """A stub daemon. `api.routes[(method, path)] = (status, payload)`."""
    _Handler.routes = {}
    _Handler.seen = []
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01},
                         daemon=True)
    t.start()

    class Api:
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        routes = _Handler.routes
        seen = _Handler.seen

    yield Api
    srv.shutdown()
    srv.server_close()


DEAD = "http://127.0.0.1:1"          # nothing listens here


# --- status / toggle / flush-cache / update ---
@pytest.mark.parametrize("cmd,path,method", [
    ("status", "/api/v1/system", "GET"),
    ("toggle", "/api/v1/toggle", "POST"),
    ("flush-cache", "/api/v1/cache/flush", "POST"),
    ("update", "/api/v1/gravity/refresh", "POST"),
])
def test_control_commands_hit_the_right_route(api, capsys, cmd, path, method):
    api.routes[(method, path)] = (200, {"ok": True})
    assert main([cmd, "--url", api.url]) == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True}
    assert api.seen[-1]["method"] == method and api.seen[-1]["path"] == path


def test_control_sends_the_bearer_token(api):
    api.routes[("GET", "/api/v1/system")] = (200, {"ok": True})
    main(["status", "--url", api.url, "--token", "s3cret"])
    assert api.seen[-1]["auth"] == "Bearer s3cret"


def test_control_omits_the_header_when_there_is_no_token(api):
    api.routes[("GET", "/api/v1/system")] = (200, {"ok": True})
    main(["status", "--url", api.url])
    assert api.seen[-1]["auth"] is None


def test_control_failure_suggests_the_two_likely_causes(capsys):
    assert main(["status", "--url", DEAD]) == 1
    err = capsys.readouterr().err
    assert "is the daemon running?" in err and "--token" in err


def test_control_reports_an_http_error(api, capsys):
    api.routes[("GET", "/api/v1/system")] = (401, {"error": "unauthorized"})
    assert main(["status", "--url", api.url]) == 1
    assert "error:" in capsys.readouterr().err


# --- upgrade ---
BASE = {"current_version": "1.2.0", "latest_version": "1.2.0",
        "update_available": False, "can_apply": True}


def test_upgrade_status_is_the_default_action(api, capsys):
    api.routes[("GET", "/api/v1/update")] = (200, BASE)
    assert main(["upgrade", "--url", api.url]) == 0
    out = capsys.readouterr().out
    assert "running   1.2.0" in out and "latest    1.2.0" in out


def test_upgrade_reports_an_available_release(api, capsys):
    api.routes[("GET", "/api/v1/update")] = (
        200, {**BASE, "latest_version": "1.3.0", "update_available": True})
    main(["upgrade", "status", "--url", api.url])
    assert "available 1.3.0" in capsys.readouterr().out


def test_upgrade_says_when_nothing_has_been_checked_yet(api, capsys):
    api.routes[("GET", "/api/v1/update")] = (200, {**BASE, "latest_version": None})
    main(["upgrade", "--url", api.url])
    assert "not checked yet" in capsys.readouterr().out


def test_upgrade_reports_a_staged_release_and_the_last_error(api, capsys):
    api.routes[("GET", "/api/v1/update")] = (200, {
        **BASE, "restart_required": True, "applied_version": "1.3.0",
        "last_error": "wheel not found"})
    main(["upgrade", "--url", api.url])
    out = capsys.readouterr().out
    assert "staged    1.3.0" in out and "restart to run it" in out
    assert "last error: wheel not found" in out


def test_upgrade_explains_a_refusal_to_self_install(api, capsys):
    api.routes[("GET", "/api/v1/update")] = (
        200, {**BASE, "can_apply": False, "why_not": "installed from a distro package"})
    main(["upgrade", "--url", api.url])
    assert "cannot install here: installed from a distro package" in capsys.readouterr().out


def test_upgrade_json_passes_the_payload_straight_through(api, capsys):
    api.routes[("GET", "/api/v1/update")] = (200, BASE)
    assert main(["upgrade", "--url", api.url, "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == BASE


@pytest.mark.parametrize("action,path", [
    ("check", "/api/v1/update/check"),
    ("apply", "/api/v1/update/apply"),
    ("rollback", "/api/v1/update/rollback"),
])
def test_upgrade_actions_post_to_their_route(api, capsys, action, path):
    api.routes[("POST", path)] = (200, BASE)
    assert main(["upgrade", action, "--url", api.url]) == 0
    assert api.seen[-1]["path"] == path


def test_upgrade_apply_pins_a_version_in_the_body(api):
    api.routes[("POST", "/api/v1/update/apply")] = (200, BASE)
    main(["upgrade", "apply", "--version", "1.4.2", "--url", api.url])
    assert json.loads(api.seen[-1]["body"]) == {"version": "1.4.2"}


def test_upgrade_apply_without_a_pin_sends_no_body(api):
    api.routes[("POST", "/api/v1/update/apply")] = (200, BASE)
    main(["upgrade", "apply", "--url", api.url])
    assert api.seen[-1]["body"] == b""


def test_upgrade_surfaces_the_daemons_refusal_from_the_error_body(api, capsys):
    api.routes[("POST", "/api/v1/update/apply")] = (
        403, {"error": "this installation is managed by the package manager"})
    assert main(["upgrade", "apply", "--url", api.url]) == 1
    assert "managed by the package manager" in capsys.readouterr().err


def test_upgrade_http_error_with_an_unreadable_body_still_reports(api, capsys):
    api.routes[("POST", "/api/v1/update/check")] = (500, b"<html>oops</html>")
    assert main(["upgrade", "check", "--url", api.url]) == 1
    assert "error:" in capsys.readouterr().err


def test_upgrade_error_in_a_200_body_is_still_an_error(api, capsys):
    api.routes[("GET", "/api/v1/update")] = (200, {"error": "no network"})
    assert main(["upgrade", "--url", api.url]) == 1
    assert "no network" in capsys.readouterr().err


def test_upgrade_reports_an_unreachable_daemon(capsys):
    assert main(["upgrade", "--url", DEAD]) == 1
    assert "is the daemon running?" in capsys.readouterr().err


def test_upgrade_gives_installs_a_long_timeout(api, monkeypatch):
    """A pip install that takes two minutes was reported as a failure."""
    seen = {}
    import trench.cli.main as cli
    real = cli._api_call
    monkeypatch.setattr(cli, "_api_call",
                        lambda *a, **kw: seen.update(timeout=kw.get("timeout")) or dict(BASE))
    main(["upgrade", "apply", "--url", api.url])
    assert seen["timeout"] == 900
    seen.clear()
    main(["upgrade", "check", "--url", api.url])
    assert seen["timeout"] == 30
    assert real is not None


def test_upgrade_rejects_an_unknown_action():
    with pytest.raises(SystemExit):
        main(["upgrade", "downgrade"])


# --- why ---
WHY = {"verdict": "blocked by a subscribed list",
       "findings": [{"stage": "filter", "verdict": "BLOCK", "detail": "||ads.example.com^"}]}


def test_why_prints_the_verdict_and_findings(api, capsys):
    api.routes[("GET", "/api/v1/explain")] = (200, WHY)
    assert main(["why", "ads.example.com", "--url", api.url]) == 0
    out = capsys.readouterr().out
    assert "blocked by a subscribed list" in out
    assert "[filter] BLOCK: ||ads.example.com^" in out


def test_why_passes_name_type_client_and_resolve(api):
    api.routes[("GET", "/api/v1/explain")] = (200, WHY)
    main(["why", "ads.example.com", "AAAA", "--client", "10.0.0.5",
          "--resolve", "--url", api.url])
    q = api.seen[-1]["path"]
    assert "name=ads.example.com" in q and "type=AAAA" in q
    assert "client=10.0.0.5" in q and "resolve=1" in q


def test_why_omits_optional_parameters_when_unset(api):
    api.routes[("GET", "/api/v1/explain")] = (200, WHY)
    main(["why", "ads.example.com", "--url", api.url])
    q = api.seen[-1]["path"]
    assert "client=" not in q and "resolve=" not in q


def test_why_renders_the_live_resolution_and_extended_errors(api, capsys):
    api.routes[("GET", "/api/v1/explain")] = (200, {
        **WHY, "live": {"action": "block", "rcode": "NXDOMAIN", "answers": [],
                        "extended_errors": [{"code": 15, "text": "Blocked"}]}})
    main(["why", "ads.example.com", "--resolve", "--url", api.url])
    out = capsys.readouterr().out
    assert "[live] block: NXDOMAIN -> no addresses" in out
    assert "extended error 15: Blocked" in out


def test_why_lists_addresses_when_there_are_some(api, capsys):
    api.routes[("GET", "/api/v1/explain")] = (200, {
        **WHY, "live": {"action": "allow", "rcode": "NOERROR",
                        "answers": ["93.184.216.34"]}})
    main(["why", "example.com", "--resolve", "--url", api.url])
    assert "-> 93.184.216.34" in capsys.readouterr().out


def test_why_says_when_the_live_resolution_failed(api, capsys):
    # --resolve was asked for; a failure to resolve is an answer too, and used
    # to vanish silently, which read as "nothing to report".
    api.routes[("GET", "/api/v1/explain")] = (200, {**WHY, "live": {"error": "timed out"}})
    main(["why", "example.com", "--resolve", "--url", api.url])
    out = capsys.readouterr().out
    assert "[live] could not resolve it now: timed out" in out
    assert "->" not in out


def test_why_summarises_recent_log_entries(api, capsys):
    api.routes[("GET", "/api/v1/explain")] = (200, {
        **WHY, "recent": [{"action": "block"}, {"action": "block"}]})
    main(["why", "ads.example.com", "--url", api.url])
    assert "[log] 2 recent queries; last action block" in capsys.readouterr().out


def test_why_says_query_for_one_log_entry(api, capsys):
    api.routes[("GET", "/api/v1/explain")] = (200, {**WHY, "recent": [{"action": "allow"}]})
    main(["why", "ads.example.com", "--url", api.url])
    assert "[log] 1 recent query; last action allow" in capsys.readouterr().out


def test_why_tolerates_a_finding_with_missing_fields(api, capsys):
    api.routes[("GET", "/api/v1/explain")] = (200, {"verdict": "v", "findings": [{"stage": "x"}]})
    assert main(["why", "a.example", "--url", api.url]) == 0
    assert "[x] ?" in capsys.readouterr().out


def test_why_json_mode(api, capsys):
    api.routes[("GET", "/api/v1/explain")] = (200, WHY)
    assert main(["why", "x.example.com", "--json", "--url", api.url]) == 0
    assert json.loads(capsys.readouterr().out) == WHY


def test_why_reports_an_unreachable_daemon(capsys):
    assert main(["why", "x.example.com", "--url", DEAD]) == 1
    assert "is the daemon running?" in capsys.readouterr().err


def test_why_shows_the_api_error_rather_than_the_daemon_hint(api, capsys):
    """A 400 for a bad type came out as "HTTP Error 400: Bad Request (is the
    daemon running?)" — pointing at the one thing that was working."""
    api.routes[("GET", "/api/v1/explain")] = (400, {"error": "unknown type 'AAA'"})
    assert main(["why", "x.example.com", "AAA", "--url", api.url]) == 1
    err = capsys.readouterr().err
    assert "unknown type 'AAA'" in err and "daemon running" not in err


def test_why_hints_at_the_token_on_a_bare_401(api, capsys):
    api.routes[("GET", "/api/v1/explain")] = (401, b"")
    assert main(["why", "x.example.com", "--url", api.url]) == 1
    assert "--token" in capsys.readouterr().err


# --- pause ---
@pytest.mark.parametrize("text,seconds", [
    ("30s", 30), ("5m", 300), ("1h", 3600), ("90", 90), ("0", 0), ("", 0),
    ("  2H  ", 7200), ("1.5m", 90), ("s", 0),
])
def test_seconds_parsing(text, seconds):
    assert _seconds(text) == seconds


def test_pause_posts_the_duration_and_client(api, capsys):
    api.routes[("POST", "/api/v1/pause")] = (200, {"paused_until": 123})
    assert main(["pause", "5m", "--client", "10.0.0.5", "--url", api.url]) == 0
    assert json.loads(api.seen[-1]["body"]) == {"seconds": 300.0, "client": "10.0.0.5"}
    assert json.loads(capsys.readouterr().out) == {"paused_until": 123}


def test_pause_defaults_to_five_minutes(api):
    api.routes[("POST", "/api/v1/pause")] = (200, {})
    main(["pause", "--url", api.url])
    assert json.loads(api.seen[-1]["body"])["seconds"] == 300.0


def test_pause_zero_resumes(api):
    api.routes[("POST", "/api/v1/pause")] = (200, {})
    main(["pause", "0", "--url", api.url])
    assert json.loads(api.seen[-1]["body"])["seconds"] == 0.0


def test_pause_sends_the_token(api):
    api.routes[("POST", "/api/v1/pause")] = (200, {})
    main(["pause", "--url", api.url, "--token", "tok"])
    assert api.seen[-1]["auth"] == "Bearer tok"


def test_pause_reports_an_unreachable_daemon(capsys):
    assert main(["pause", "--url", DEAD]) == 1
    assert "is the daemon running?" in capsys.readouterr().err


def test_pause_rejects_a_duration_it_cannot_read(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["pause", "soon", "--url", DEAD])
    assert exc.value.code == 2
    assert "invalid duration" in capsys.readouterr().err


def test_pause_rejects_more_than_a_day(capsys):
    assert main(["pause", "25h", "--url", DEAD]) == 2
    assert "24h" in capsys.readouterr().err


# --- errors that say what to do ---
def test_a_missing_token_is_named_as_the_cause(api, capsys):
    api.routes[("GET", "/api/v1/system")] = (401, b"")
    assert main(["status", "--url", api.url]) == 1
    err = capsys.readouterr().err
    assert "wants a token" in err and "TRENCH_TOKEN" in err


def test_a_rejected_token_is_named_as_the_cause(api, capsys):
    api.routes[("GET", "/api/v1/system")] = (401, b"")
    assert main(["status", "--url", api.url, "--token", "old"]) == 1
    assert "did not accept that token" in capsys.readouterr().err


def test_a_token_without_the_scope_says_which_scope(api, capsys):
    api.routes[("POST", "/api/v1/toggle")] = (403, b"")
    assert main(["toggle", "--url", api.url, "--token", "viewer-only"]) == 1
    assert "need editor" in capsys.readouterr().err


def test_a_wrong_port_is_suggested_on_404(api, capsys):
    assert main(["status", "--url", api.url + "/nope"]) == 1
    assert "404" in capsys.readouterr().err


def test_a_non_json_reply_says_so(api, capsys):
    api.routes[("GET", "/api/v1/system")] = (200, b"<html>")
    assert main(["status", "--url", api.url]) == 1
    assert "not with JSON" in capsys.readouterr().err


def test_a_url_without_a_scheme_says_so(capsys):
    assert main(["status", "--url", "127.0.0.1:8089"]) == 1
    assert "must start with http://" in capsys.readouterr().err


def test_nothing_listening_is_said_plainly(capsys):
    assert main(["status", "--url", DEAD]) == 1
    assert "nothing is listening at" in capsys.readouterr().err


def test_url_and_token_come_from_the_environment(api, monkeypatch):
    api.routes[("GET", "/api/v1/system")] = (200, {"ok": True})
    monkeypatch.setenv("TRENCH_URL", api.url)
    monkeypatch.setenv("TRENCH_TOKEN", "from-env")
    assert main(["status"]) == 0
    assert api.seen[-1]["auth"] == "Bearer from-env"


# --- a person at a terminal gets sentences; a pipe keeps getting JSON ---
@pytest.fixture
def tty(monkeypatch):
    monkeypatch.setattr("trench.cli.main._isatty", lambda: True)


def test_status_on_a_terminal_reads_as_sentences(api, capsys, tty):
    api.routes[("GET", "/api/v1/system")] = (200, {
        "version": "2.0.0", "uptime": 7260, "upstream": ["1.1.1.1"], "mode": "parallel"})
    assert main(["status", "--url", api.url]) == 0
    out = capsys.readouterr().out
    assert "trench    2.0.0, up 2h 1m" in out and "upstream  1.1.1.1 (parallel)" in out


def test_json_flag_wins_on_a_terminal(api, capsys, tty):
    api.routes[("GET", "/api/v1/system")] = (200, {"version": "2.0.0"})
    main(["status", "--json", "--url", api.url])
    assert json.loads(capsys.readouterr().out) == {"version": "2.0.0"}


def test_toggle_off_on_a_terminal_is_loud(api, capsys, tty):
    api.routes[("POST", "/api/v1/toggle")] = (200, {"enabled": False})
    main(["toggle", "--url", api.url])
    assert "filtering is OFF" in capsys.readouterr().out


def test_pause_on_a_terminal_says_how_to_undo_it(api, capsys, tty):
    api.routes[("POST", "/api/v1/pause")] = (200, {"paused_until": 2_000_000_000, "clients": {}})
    main(["pause", "5m", "--url", api.url])
    out = capsys.readouterr().out
    assert "paused for everyone until" in out and "trench pause 0" in out
