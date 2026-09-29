"""trench CLI: built-in dig over every transport, control via the API,
and config import. Run `trench <command> -h` for details.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from ..version import __version__
from ..wire import Class, Message, Question
from ..wire.name import Name
from ..wire.rrtypes import type_from_text, type_to_text

DEFAULT_URL = "http://127.0.0.1:8089"


def _api_args(p: argparse.ArgumentParser, as_json: bool = True) -> None:
    """`--url`, `--token` and `--json`, the same on every command that talks to
    the daemon.

    Both connection flags fall back to the environment, so an operator exports
    `TRENCH_TOKEN` once instead of pasting a secret into every command line —
    where it also lands in shell history and in `ps` for every other user on
    the box to read.
    """
    p.add_argument("--url", default=os.environ.get("TRENCH_URL") or DEFAULT_URL,
                   help="daemon API address (env TRENCH_URL; default %(default)s)")
    p.add_argument("--token", default=os.environ.get("TRENCH_TOKEN", ""),
                   help="API token from Settings → Access (env TRENCH_TOKEN)")
    if as_json:
        p.add_argument("--json", action="store_true", dest="as_json",
                       help="print the daemon's raw JSON reply")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trench", description="Trench CLI",
        epilog="Commands that talk to the daemon read TRENCH_URL and TRENCH_TOKEN "
               "from the environment. `trench <command> -h` for details.")
    p.add_argument("--version", action="version", version=f"trench {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("query", help="resolve a name over any transport")
    q.add_argument("name")
    q.add_argument("type", nargs="?", default="A")
    q.add_argument("transport", nargs="?", default="@udp",
                   help="@udp|@tcp|@tls|@https|@quic")
    q.add_argument("--server", default="127.0.0.1:5354")
    q.add_argument("--insecure", action="store_true", help="skip TLS verify")

    for name, help_ in [("status", "show server status"), ("toggle", "toggle blocking"),
                        ("flush-cache", "flush the DNS cache"), ("update", "refresh blocklists")]:
        s = sub.add_parser(name, help=help_)
        _api_args(s)

    # `update` above refreshes blocklists and has meant that for two major
    # versions; upgrading Trench itself is a different verb on purpose.
    up = sub.add_parser("upgrade", help="check for, install, or roll back a Trench release")
    up.add_argument("action", nargs="?", default="status",
                    choices=["status", "check", "apply", "rollback"])
    up.add_argument("--version", dest="pin", default="",
                    help="install this exact version instead of the newest")
    _api_args(up)

    why = sub.add_parser("why", help="explain what this server did with a name")
    why.add_argument("name")
    why.add_argument("type", nargs="?", default="A")
    why.add_argument("--client", default="", help="the device that complained")
    why.add_argument("--resolve", action="store_true",
                     help="also resolve it now and report what came back")
    _api_args(why)

    pause = sub.add_parser("pause", help="suspend filtering for a while")
    pause.add_argument("duration", nargs="?", default="5m", type=_duration,
                       help="e.g. 30s, 5m, 1h; 0 resumes")
    pause.add_argument("--client", default="", help="one device only")
    _api_args(pause)

    imp = sub.add_parser("import", help="import PiHole/AdGuard config")
    imp.add_argument("kind", choices=["pihole", "adguard"])
    imp.add_argument("path", help="Pi-hole: gravity.db or the directory holding it "
                     "(e.g. /etc/pihole); AdGuard: AdGuardHome.yaml")

    kg = sub.add_parser("keygen-tsig", help="generate a TSIG key (for zone transfers)")
    kg.add_argument("name", nargs="?", default="xfr-key.")
    kg.add_argument("--algorithm", default="hmac-sha256.")
    kg.add_argument("--bytes", type=int, default=32, dest="nbytes")

    rt = sub.add_parser("regex-test", help="test filter rules against names")
    rt.add_argument("rule", help="a rule line, or @path to read rules from a file")
    rt.add_argument("names", nargs="+", help="domain names to test")

    bk = sub.add_parser("backup", help="archive the data directory to a .tar.gz "
                        "(safe while the daemon runs)")
    bk.add_argument("out", help="output archive path")
    bk.add_argument("--data-dir", default="./data")

    rs = sub.add_parser("restore", help="restore a data directory from a .tar.gz "
                        "(stop the daemon first)")
    rs.add_argument("archive")
    rs.add_argument("--data-dir", default="./data")
    rs.add_argument("--force", action="store_true",
                    help="replace the contents of a non-empty target")

    pr = sub.add_parser("profile", help="emit an Apple .mobileconfig for encrypted DNS")
    pr.add_argument("--name", default="Trench")
    pr.add_argument("--doh-url", help="https://host/dns-query")
    pr.add_argument("--dot-host", help="TLS server name")
    pr.add_argument("--address", action="append", help="pin resolver IP (repeatable)")

    pw = sub.add_parser("passwd", help="set a web-admin password (offline, on the box)")
    pw.add_argument("user", nargs="?", default="admin")
    pw.add_argument("--data-dir", default="./data")
    pw.add_argument("--db", default="trench.db", help="database file inside the data dir")
    pwsrc = pw.add_mutually_exclusive_group()
    pwsrc.add_argument("--password", help="new password (omit to generate one and print it)")
    pwsrc.add_argument("--password-stdin", action="store_true", dest="password_stdin",
                       help="read the new password from stdin, keeping it out of "
                            "`ps` and shell history")
    pw.add_argument("--role", default="admin", help="role if the user has to be created")
    pw.add_argument("--clear-totp", action="store_true", dest="clear_totp",
                    help="also remove the account's two-factor secret")

    st = sub.add_parser("stamp", help="emit a DNS stamp (sdns://)")
    st.add_argument("kind", choices=["doh", "dot"])
    st.add_argument("host")
    st.add_argument("--path", default="/dns-query")
    st.add_argument("--port", type=int, default=853)

    return p


async def _do_query(args) -> int:
    from ..transport.upstream import Upstream, parse_upstream
    scheme = args.transport.lstrip("@") or "udp"
    if scheme not in ("udp", "tcp", "tls", "https", "quic"):
        print(f";; unknown transport {args.transport!r}: use @udp, @tcp, @tls, @https "
              "or @quic", file=sys.stderr)
        return 2
    # A typo in the type or the name used to escape as a Python traceback.
    try:
        rtype = type_from_text(args.type)
    except (ValueError, KeyError):
        print(f";; unknown record type {args.type!r} (try A, AAAA, MX, TXT, HTTPS…)",
              file=sys.stderr)
        return 2
    try:
        qname = Name.from_text(args.name)
    except (ValueError, UnicodeError) as e:
        print(f";; {args.name!r} is not a valid name: {e}", file=sys.stderr)
        return 2
    try:
        spec = parse_upstream(f"{scheme}://{args.server}" if scheme != "udp" else args.server)
    except (ValueError, KeyError) as e:
        print(f";; cannot use --server {args.server!r}: {e}", file=sys.stderr)
        return 2
    up = Upstream(spec, verify=not args.insecure)
    q = Message(id=0x1234)
    q.set_flag(0x0100, True)  # RD
    q.questions.append(Question(qname, rtype, Class.IN))
    started = time.perf_counter()
    try:
        resp = await up.query(q)
    except Exception as e:
        why = str(e) or type(e).__name__
        print(f";; query failed: {why} (asking {args.server} over {scheme})", file=sys.stderr)
        return 1
    finally:
        await up.close()
    took = (time.perf_counter() - started) * 1000
    from ..wire.rrtypes import Rcode
    rc = Rcode(resp.rcode).name if resp.rcode in iter(Rcode) else str(resp.rcode)
    print(f";; status: {rc}, answers: {len(resp.answers)} ({scheme})")
    print(f";; query time: {took:.0f} ms, server: {args.server}")
    for rr in resp.answers:
        print(f"{rr.name.to_text():<32} {rr.ttl:<6} {type_to_text(rr.rtype):<7} {rr.rdata.to_text()}")
    return 0


def _api_call(url: str, path: str, token: str, method: str = "GET",
              body: dict | None = None, timeout: float = 5):
    """One call to the daemon's API.

    `timeout` is a parameter because the fixed five seconds is right for
    `status` and wrong for anything that runs pip: an install that takes two
    minutes was being reported as a failure while it was still succeeding.
    """
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url.rstrip("/") + path, method=method, headers=headers,
                                 data=data)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


_HINT = "is the daemon running? do you need --token?"


def _describe_failure(e: BaseException, url: str, token: str) -> str:
    """One line that says what went wrong *and* what to do about it.

    Every daemon-facing command used to print the exception verbatim with the
    same two guesses after it, so a wrong token, a stopped daemon, a typo in
    `--url` and a daemon refusing the request all read alike —
    `<urlopen error [Errno 111] Connection refused>` is accurate and useless.
    Each cause below has a different fix, so each says which.
    """
    if not url.startswith(("http://", "https://")):
        return f"--url must start with http:// or https:// (got {url!r})"
    if isinstance(e, urllib.error.HTTPError):
        try:
            detail = json.loads(e.read() or b"{}").get("error", "")
        except Exception:
            detail = ""
        if e.code == 401 and not token:
            return (f"the daemon at {url} wants a token (401); {_HINT} — pass "
                    "--token or set TRENCH_TOKEN (create one under Settings → Access)")
        # A refusal that explains itself ("managed by the package manager") is
        # the whole message; the guesses below are only for a bare status.
        if detail and e.code not in (401,):
            return f"the daemon refused: {detail} ({e.code})"
        if e.code in (401, 403):
            if not token:
                return (f"the daemon at {url} wants a token ({e.code}); {_HINT} — pass "
                        "--token or set TRENCH_TOKEN (create one under Settings → Access)")
            if e.code == 401:
                return (f"the daemon at {url} did not accept that token (401) — it may "
                        f"have been revoked or mistyped; {_HINT}")
            return (f"that token is not allowed to do this ({detail or '403 Forbidden'}) — "
                    "`status` and `why` need viewer; `toggle`, `pause`, `flush-cache` "
                    "and `update` need editor; `upgrade apply` needs admin")
        if e.code == 404:
            return (f"{url} answered 404 — is --url pointing at the Trench console "
                    f"port? ({detail or e.reason})")
        return f"the daemon refused: {detail or e.reason} ({e.code})"
    if isinstance(e, (TimeoutError, socket.timeout)):
        return f"no reply from {url} in time; the daemon may be busy or wedged ({_HINT})"
    if isinstance(e, urllib.error.URLError):
        reason = e.reason
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return f"no reply from {url} in time; the daemon may be busy or wedged ({_HINT})"
        if isinstance(reason, ConnectionRefusedError):
            return f"nothing is listening at {url} ({_HINT})"
        if isinstance(reason, socket.gaierror):
            return f"cannot resolve the host in --url {url} ({_HINT})"
        return f"cannot reach {url}: {reason} ({_HINT})"
    if isinstance(e, json.JSONDecodeError):
        return f"{url} answered, but not with JSON — is --url the Trench console? ({_HINT})"
    return f"{e} ({_HINT})"


def _call(args, path: str, method: str = "GET", body: dict | None = None,
          timeout: float = 5):
    """`_api_call` with the failure reported; `None` means already reported."""
    try:
        return _api_call(args.url, path, args.token, method, body=body, timeout=timeout)
    except Exception as e:
        print(f"error: {_describe_failure(e, args.url, args.token)}", file=sys.stderr)
        return None


def _human(args) -> bool:
    """Sentences for a person at a terminal; JSON for `--json` and for pipes.

    A pipe keeps getting JSON so scripts written against the old output (which
    was always JSON) keep working.
    """
    return not getattr(args, "as_json", False) and _isatty()


def _isatty() -> bool:
    return sys.stdout.isatty()


def _ago(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 90 * 60:
        return f"{seconds // 60}m"
    if seconds < 48 * 3600:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    return f"{seconds // 86400}d {seconds % 86400 // 3600}h"


def _say_control(cmd: str, out: dict) -> None:
    if cmd == "status":
        print(f"trench    {out.get('version', '?')}, up {_ago(out.get('uptime', 0))}")
        ups = out.get("upstream") or []
        print(f"upstream  {', '.join(map(str, ups)) or 'none'} ({out.get('mode', '?')})")
    elif cmd == "toggle":
        print("filtering is on" if out.get("enabled") else
              "filtering is OFF — every name resolves until you run `trench toggle` again")
    elif cmd == "flush-cache":
        n = out.get("flushed", 0)
        print(f"flushed {n} cached answer{'' if n == 1 else 's'}")
    elif cmd == "update":
        print("blocklist refresh started; it runs in the background "
              "(Breakage shows what the new lists changed)")


def _do_control(args) -> int:
    paths = {"status": ("/api/v1/system", "GET"), "toggle": ("/api/v1/toggle", "POST"),
             "flush-cache": ("/api/v1/cache/flush", "POST"), "update": ("/api/v1/gravity/refresh", "POST")}
    path, method = paths[args.cmd]
    out = _call(args, path, method)
    if out is None:
        return 1
    if _human(args) and isinstance(out, dict):
        _say_control(args.cmd, out)
    else:
        print(json.dumps(out, indent=2))
    return 0


def _do_upgrade(args) -> int:
    """Drive the daemon's update endpoints.

    Deliberately a thin client: the daemon owns the decision about whether this
    installation may update itself, so the CLI never does the work itself and
    cannot be used to sidestep that judgement.
    """
    routes = {"status": ("/api/v1/update", "GET"),
              "check": ("/api/v1/update/check", "POST"),
              "apply": ("/api/v1/update/apply", "POST"),
              "rollback": ("/api/v1/update/rollback", "POST")}
    path, method = routes[args.action]
    body = {"version": args.pin} if args.action == "apply" and args.pin else None
    try:
        # Installing runs pip twice and can take minutes on an SD card.
        timeout = 900 if args.action in ("apply", "rollback") else 30
        out = _api_call(args.url, path, args.token, method, body=body, timeout=timeout)
    except Exception as e:
        # The daemon's refusal ("managed by the package manager") arrives as a
        # JSON body on an HTTP error, and is the whole message; an auth failure
        # has no body and gets the token hint instead.
        print(f"error: {_describe_failure(e, args.url, args.token)}", file=sys.stderr)
        return 1
    if args.as_json:
        print(json.dumps(out, indent=2))
        return 0
    if "error" in out:
        print(f"error: {out['error']}", file=sys.stderr)
        return 1
    print(f"running   {out.get('current_version', '?')}")
    latest = out.get("latest_version") or "unknown"
    if out.get("update_available"):
        print(f"available {latest}")
    else:
        print(f"latest    {latest}" if latest != "unknown" else "latest    not checked yet")
    if out.get("restart_required"):
        print(f"staged    {out.get('applied_version', '')} — restart to run it")
    if out.get("last_error"):
        print(f"last error: {out['last_error']}")
    if not out.get("can_apply") and out.get("why_not"):
        print(f"cannot install here: {out['why_not']}")
    return 0


def _seconds(text: str) -> float:
    """`30s`, `5m`, `1h`, or a bare number of seconds. Raises ValueError."""
    text = text.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600}
    if text and text[-1] in units:
        return float(text[:-1] or 0) * units[text[-1]]
    return float(text or 0)


def _duration(text: str) -> float:
    """argparse `type=` for `pause`: a typo is a usage error (exit 2), caught
    before anything is sent, not a ValueError traceback."""
    try:
        seconds = _seconds(text)
    except ValueError:
        seconds = -1.0
    if not seconds >= 0:            # also rejects nan
        raise argparse.ArgumentTypeError(
            f"invalid duration {text!r} (use e.g. 30s, 5m, 1h, or 0 to resume)")
    return seconds


def _do_why(args) -> int:
    params = {"name": args.name, "type": args.type}
    if args.client:
        params["client"] = args.client
    if args.resolve:
        params["resolve"] = "1"
    path = "/api/v1/explain?" + urllib.parse.urlencode(params)
    # --resolve performs a live lookup, which can take a slow upstream's full
    # timeout on its own; five seconds reported those as a dead daemon.
    out = _call(args, path, timeout=20 if args.resolve else 5)
    if out is None:
        return 1
    if args.as_json:
        print(json.dumps(out, indent=2))
        return 0
    print(out.get("verdict", ""))
    for f in out.get("findings", []):
        # a finding from a newer daemon may lack a field; say less, not crash
        detail = f.get("detail", "")
        print(f"  · [{f.get('stage', '?')}] {f.get('verdict', '?')}"
              + (f": {detail}" if detail else ""))
    live = out.get("live") or {}
    if live and "error" not in live:
        answers = ", ".join(live.get("answers") or []) or "no addresses"
        print(f"  · [live] {live.get('action')}: {live.get('rcode')} -> {answers}")
        for ede in live.get("extended_errors", []):
            print(f"  · [live] extended error {ede.get('code')}: {ede.get('text', '')}")
    elif live.get("error"):
        print(f"  · [live] could not resolve it now: {live['error']}")
    recent = out.get("recent") or []
    if recent:
        n = len(recent)
        print(f"  · [log] {n} recent {'query' if n == 1 else 'queries'}; last action "
              f"{recent[0].get('action')}")
    return 0


def _do_pause(args) -> int:
    seconds = args.duration         # parsed by _duration; a typo already exited 2
    if not 0 <= seconds <= 86_400:
        print("error: a pause is 0 (resume) to 24h; for longer, `trench toggle`",
              file=sys.stderr)
        return 2
    out = _call(args, "/api/v1/pause", "POST", body={"seconds": seconds, "client": args.client})
    if out is None:
        return 1
    if not _human(args) or not isinstance(out, dict):
        print(json.dumps(out, indent=2))
        return 0
    who = args.client or "everyone"
    if seconds == 0:
        print(f"filtering resumed for {who}")
    else:
        until = out.get("clients", {}).get(args.client) if args.client else out.get("paused_until")
        at = time.strftime("%H:%M:%S", time.localtime(until)) if until else "?"
        print(f"filtering paused for {who} until {at}; `trench pause 0"
              + (f" --client {args.client}" if args.client else "") + "` resumes now")
    return 0


def _do_import(args) -> int:
    import sqlite3
    from pathlib import Path

    from ..ops.migrate_import import import_adguard, import_pihole
    path = Path(args.path)
    if args.kind == "pihole" and path.is_dir():
        path = path / "gravity.db"      # `trench import pihole /etc/pihole`
    if not path.is_file():
        print(f"error: {path} not found", file=sys.stderr)
        return 1
    try:
        res = import_pihole(str(path)) if args.kind == "pihole" else import_adguard(str(path))
    except sqlite3.Error as e:
        # Nothing has been written yet, so stdout stays empty and a script
        # redirecting it into a config file gets no half-document.
        print(f"error: {path} is not a readable Pi-hole gravity.db ({e})", file=sys.stderr)
        return 1
    except (ValueError, AttributeError, TypeError) as e:
        # yaml.YAMLError is a ValueError subclass; the others are a YAML file
        # that parsed but is not shaped like AdGuardHome.yaml.
        print(f"error: {path} is not a usable {args.kind} config ({e})", file=sys.stderr)
        return 1
    print(f"# imported from {args.kind}: {res.summary()}")
    out = {"filtering": {"sources": res.sources, "deny": res.deny, "allow": res.allow}}
    if res.rules:
        out["filtering"]["rules"] = res.rules
    import yaml
    print(yaml.safe_dump(out, sort_keys=False))
    return 0


def _do_keygen_tsig(args) -> int:
    import base64
    import secrets
    secret = base64.b64encode(secrets.token_bytes(args.nbytes)).decode()
    name = args.name if args.name.endswith(".") else args.name + "."
    print("# add to trench.yaml, and give the same key to the peer server:")
    print("tsig_keys:")
    print(f"  - name: {name}")
    print(f"    algorithm: {args.algorithm}")
    print(f"    secret: {secret}")
    return 0


def _do_regex_test(args) -> int:
    from ..filter import FilterEngine
    from ..filter.parser import parse_line, parse_list
    if args.rule.startswith("@"):
        from pathlib import Path
        try:
            rules = parse_list(Path(args.rule[1:]).read_text())
        except OSError as e:
            print(f"cannot read rules from {args.rule[1:]}: {e.strerror or e}", file=sys.stderr)
            return 1
    else:
        r = parse_line(args.rule)
        rules = [r] if r else []
    if not rules:
        print(f"no valid rule parsed from {args.rule!r} — expected adblock (||ads.example^), "
              "hosts (0.0.0.0 ads.example), a bare domain, or /regex/", file=sys.stderr)
        return 1
    engine = FilterEngine.compile(rules)
    rc = 0
    for name in args.names:
        d = engine.match(name.lower())
        verdict = getattr(d.action, "name", str(d.action))
        rule = f"  [{d.rule}]" if getattr(d, "rule", None) else ""
        print(f"{name:<40} {verdict}{rule}")
    return rc


_SQLITE_MAGIC = b"SQLite format 3\x00"
_SQLITE_SIDECARS = ("-wal", "-shm", "-journal")


def _sqlite_files(root):
    """The SQLite databases under `root`, by header rather than by name."""
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink() or p.name.endswith(_SQLITE_SIDECARS):
            continue
        try:
            with open(p, "rb") as f:
                if f.read(16) == _SQLITE_MAGIC:
                    yield p
        except OSError:
            continue


def _do_backup(args) -> int:
    import shutil
    import sqlite3
    import tarfile
    import tempfile
    from pathlib import Path
    data = Path(args.data_dir)
    if not data.is_dir():
        print(f"data dir {data} not found (or not a directory)", file=sys.stderr)
        return 1
    # Written beside the target and renamed into place, so a failure halfway
    # (full disk, Ctrl-C, a cron job killed by a timeout) cannot leave a
    # truncated archive at the name a restore will later trust.
    out = Path(args.out)
    if not out.parent.is_dir():
        print(f"output directory {out.parent} does not exist", file=sys.stderr)
        return 1
    tmp = out.with_name(f".{out.name}.partial")
    # A live database is not a set of files to copy. The daemon writes the
    # query log every 250 ms, and a byte copy of `trench.db` plus its `-wal`
    # taken at different moments is a database SQLite may refuse to open —
    # found out at restore time. Each one is snapshotted through SQLite's
    # online-backup API instead, and the snapshot is what goes in the archive,
    # without the sidecars. Beside the output, not in /tmp: the query log can
    # be larger than a Pi's RAM-backed /tmp.
    snapdir = Path(tempfile.mkdtemp(dir=out.parent, prefix=f".{out.name}.snap-"))
    try:
        snaps: dict[str, Path] = {}
        skip: set[str] = set()
        for i, db in enumerate(_sqlite_files(data)):
            arc = (Path(data.name) / db.relative_to(data)).as_posix()
            snap = snapdir / str(i)
            src = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            try:
                dst = sqlite3.connect(snap)
                try:
                    src.backup(dst)
                finally:
                    dst.close()
            finally:
                src.close()
            snaps[arc] = snap
            skip.update(arc + suffix for suffix in ("",) + _SQLITE_SIDECARS)

        def keep(m):
            if m.name in skip or Path(m.name).name in (tmp.name, snapdir.name):
                return None
            return m

        with tarfile.open(tmp, "w:gz") as tar:
            tar.add(data, arcname=data.name, filter=keep)
            for arc, snap in snaps.items():
                tar.add(snap, arcname=arc)
        tmp.replace(out)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(snapdir, ignore_errors=True)
    print(f"backed up {data} -> {out}")
    return 0


def _do_restore(args) -> int:
    import os
    import shutil
    import tarfile
    import tempfile
    from pathlib import Path
    dest = Path(args.data_dir)
    if dest.exists() and not dest.is_dir():
        print(f"{dest} is not a directory", file=sys.stderr)
        return 1
    if dest.exists() and any(dest.iterdir()) and not args.force:
        print(f"{dest} is not empty; pass --force to overwrite", file=sys.stderr)
        return 1
    with tarfile.open(args.archive, "r:gz") as tar:
        # Reading every header walks the whole archive, so a truncated or
        # corrupt one fails here — before anything in `dest` has been touched.
        members = tar.getmembers()
        # strip the leading archive top-dir so contents land directly in data-dir
        top = members[0].name.split("/")[0] + "/" if members else ""
        wanted = []
        for m in members:
            if m.name == top.rstrip("/"):
                continue
            m.name = m.name[len(top):] if m.name.startswith(top) else m.name
            if not m.name:
                continue
            # An archive is data, not a trusted input — "a local backup" is only
            # true until someone is talked into restoring one. The name rewrite
            # above deliberately *keeps* names that do not start with `top`, so
            # a `../../etc/trench/trench.yaml` member passed through
            # untouched, and Python 3.11 still extracts with no filter by
            # default. Links are refused outright; everything else must stay
            # inside the data dir.
            if m.islnk() or m.issym():
                print(f"skipping link member {m.name!r}", file=sys.stderr)
                continue
            if not m.isfile() and not m.isdir():
                print(f"skipping special member {m.name!r}", file=sys.stderr)
                continue
            norm = os.path.normpath(m.name)
            if os.path.isabs(norm) or norm == ".." or norm.startswith("../"):
                print(f"refusing member outside the data dir: {m.name!r}",
                      file=sys.stderr)
                return 1
            wanted.append(m)
        # Extracted into a staging directory first, then swapped in. Extracting
        # over the old contents left every file the archive does not carry in
        # place — among them a `trench.db-wal` that SQLite then replays into
        # the restored database, and a failure halfway left a mix of both.
        # Inside `dest`, so the swap is a rename even when `dest` is a mount
        # point (a Docker volume), where renaming `dest` itself is not possible.
        dest.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(dir=dest, prefix=".restore-"))
        try:
            for m in wanted:
                # `filter=` only exists from 3.11.4; the checks above are what
                # actually hold the line on older builds.
                try:
                    tar.extract(m, stage, filter="data")
                except TypeError:
                    tar.extract(m, stage)
            for child in dest.iterdir():
                if child == stage:
                    continue
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            for child in stage.iterdir():
                child.rename(dest / child.name)
        finally:
            shutil.rmtree(stage, ignore_errors=True)
    print(f"restored {args.archive} -> {dest}")
    return 0


def _do_profile(args) -> int:
    from ..onboarding import apple_mobileconfig
    if not args.doh_url and not args.dot_host:
        print("provide --doh-url or --dot-host", file=sys.stderr)
        return 1
    print(apple_mobileconfig(display_name=args.name, doh_url=args.doh_url,
                             dot_host=args.dot_host, server_addresses=args.address))
    return 0


async def _do_passwd(args) -> int:
    """Reset a web password without being able to log in.

    The autogenerated first-run password is shown once; once that has scrolled
    away, an operator with full physical access to the box can be locked out of
    their own resolver. Write access to the database is the proof of ownership
    here, so this deliberately works offline against the file rather than
    through the authenticated API.

    `--clear-totp` covers the other half of being locked out. A lost
    authenticator is not recoverable through the console — the console is what
    you cannot reach — and resetting the password alone leaves the second factor
    standing, so the reset appeared to work and the next login still failed.
    """
    import secrets
    from pathlib import Path

    from ..api.auth import AuthManager
    from ..store import Database

    path = Path(args.data_dir) / args.db
    if not path.exists():
        print(f"no database at {path} (wrong --data-dir?)", file=sys.stderr)
        return 1
    if args.password_stdin:
        args.password = sys.stdin.readline().rstrip("\r\n")
        if not args.password:
            print("no password on stdin", file=sys.stderr)
            return 1
    password = args.password or secrets.token_urlsafe(12)
    db = Database(path)
    await db.connect()
    try:
        auth = AuthManager(db)
        row = await db.fetchone("SELECT id FROM app_user WHERE name=?", (args.user,))
        if row:
            await auth.set_password(args.user, password)
            what = "password reset"
        else:
            await auth.create_user(args.user, password, args.role)
            what = f"user created ({args.role})"
        if args.clear_totp:
            await auth.set_totp(args.user, "")
            what += ", two-factor removed"
    finally:
        await db.close()
    # Sessions live in the daemon's memory, so a running daemon keeps serving
    # anyone already logged in until it is restarted. Say so rather than imply
    # the reset kicked them out.
    print(f"{args.user}: {what} (restart the daemon to drop existing sessions)")
    if not args.password:
        print(f"password: {password}")
    return 0


def _do_stamp(args) -> int:
    from ..onboarding import doh_stamp, dot_stamp
    if args.kind == "doh":
        print(doh_stamp(args.host, args.path))
    else:
        print(dot_stamp(args.host, port=args.port))
    return 0


def main(argv: list[str] | None = None) -> int:
    import sqlite3
    import tarfile
    args = _build_parser().parse_args(argv)
    # These are the operator's environment, not bugs: a path that is missing,
    # unwritable or not an archive. One line and exit 1, never a traceback,
    # so a script can tell "failed" from "crashed" and a person can act on it.
    try:
        return _dispatch(args)
    except KeyboardInterrupt:
        return 130
    except (OSError, EOFError, tarfile.TarError, sqlite3.Error) as e:
        print(f"trench {args.cmd}: error: {e}", file=sys.stderr)
        return 1


def _dispatch(args) -> int:
    handlers = {
        "keygen-tsig": _do_keygen_tsig, "regex-test": _do_regex_test,
        "backup": _do_backup, "restore": _do_restore,
        "profile": _do_profile, "stamp": _do_stamp,
    }
    if args.cmd == "query":
        return asyncio.run(_do_query(args))
    if args.cmd == "passwd":
        return asyncio.run(_do_passwd(args))
    if args.cmd in ("status", "toggle", "flush-cache", "update"):
        return _do_control(args)
    if args.cmd == "upgrade":
        return _do_upgrade(args)
    if args.cmd == "why":
        return _do_why(args)
    if args.cmd == "pause":
        return _do_pause(args)
    if args.cmd == "import":
        return _do_import(args)
    if args.cmd in handlers:
        return handlers[args.cmd](args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
