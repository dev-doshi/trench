"""trench CLI: built-in dig over every transport, control via the API,
and config import. Run `trench <command> -h` for details.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

from ..version import __version__
from ..wire import Class, Message, Question
from ..wire.name import Name
from ..wire.rrtypes import type_from_text, type_to_text


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="trench", description="Trench CLI")
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
        s.add_argument("--url", default="http://127.0.0.1:8089")
        s.add_argument("--token", default="")

    # `update` above refreshes blocklists and has meant that for two major
    # versions; upgrading Trench itself is a different verb on purpose.
    up = sub.add_parser("upgrade", help="check for, install, or roll back a Trench release")
    up.add_argument("action", nargs="?", default="status",
                    choices=["status", "check", "apply", "rollback"])
    up.add_argument("--version", dest="pin", default="",
                    help="install this exact version instead of the newest")
    up.add_argument("--json", action="store_true", dest="as_json")
    up.add_argument("--url", default="http://127.0.0.1:8089")
    up.add_argument("--token", default="")

    why = sub.add_parser("why", help="explain what this server did with a name")
    why.add_argument("name")
    why.add_argument("type", nargs="?", default="A")
    why.add_argument("--client", default="", help="the device that complained")
    why.add_argument("--resolve", action="store_true",
                     help="also resolve it now and report what came back")
    why.add_argument("--json", action="store_true", dest="as_json")
    why.add_argument("--url", default="http://127.0.0.1:8089")
    why.add_argument("--token", default="")

    pause = sub.add_parser("pause", help="suspend filtering for a while")
    pause.add_argument("duration", nargs="?", default="5m",
                       help="e.g. 30s, 5m, 1h; 0 resumes")
    pause.add_argument("--client", default="", help="one device only")
    pause.add_argument("--url", default="http://127.0.0.1:8089")
    pause.add_argument("--token", default="")

    imp = sub.add_parser("import", help="import PiHole/AdGuard config")
    imp.add_argument("kind", choices=["pihole", "adguard"])
    imp.add_argument("path")

    kg = sub.add_parser("keygen-tsig", help="generate a TSIG key (for zone transfers)")
    kg.add_argument("name", nargs="?", default="xfr-key.")
    kg.add_argument("--algorithm", default="hmac-sha256.")
    kg.add_argument("--bytes", type=int, default=32, dest="nbytes")

    rt = sub.add_parser("regex-test", help="test filter rules against names")
    rt.add_argument("rule", help="a rule line, or @path to read rules from a file")
    rt.add_argument("names", nargs="+", help="domain names to test")

    bk = sub.add_parser("backup", help="archive the data directory to a .tar.gz")
    bk.add_argument("out", help="output archive path")
    bk.add_argument("--data-dir", default="./data")

    rs = sub.add_parser("restore", help="restore a data directory from a .tar.gz")
    rs.add_argument("archive")
    rs.add_argument("--data-dir", default="./data")
    rs.add_argument("--force", action="store_true", help="overwrite a non-empty target")

    pr = sub.add_parser("profile", help="emit an Apple .mobileconfig for encrypted DNS")
    pr.add_argument("--name", default="Trench")
    pr.add_argument("--doh-url", help="https://host/dns-query")
    pr.add_argument("--dot-host", help="TLS server name")
    pr.add_argument("--address", action="append", help="pin resolver IP (repeatable)")

    pw = sub.add_parser("passwd", help="set a web-admin password (offline, on the box)")
    pw.add_argument("user", nargs="?", default="admin")
    pw.add_argument("--data-dir", default="./data")
    pw.add_argument("--db", default="trench.db", help="database file inside the data dir")
    pw.add_argument("--password", help="new password (omit to generate one and print it)")
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
    spec = parse_upstream(f"{scheme}://{args.server}" if scheme != "udp" else args.server)
    up = Upstream(spec, verify=not args.insecure)
    rtype = type_from_text(args.type)
    q = Message(id=0x1234)
    q.set_flag(0x0100, True)  # RD
    q.questions.append(Question(Name.from_text(args.name), rtype, Class.IN))
    try:
        resp = await up.query(q)
    except Exception as e:
        print(f";; query failed: {e}", file=sys.stderr)
        return 1
    finally:
        await up.close()
    from ..wire.rrtypes import Rcode
    rc = Rcode(resp.rcode).name if resp.rcode in iter(Rcode) else str(resp.rcode)
    print(f";; status: {rc}, answers: {len(resp.answers)} ({scheme})")
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
    req = urllib.request.Request(url + path, method=method, headers=headers, data=data)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _do_control(args) -> int:
    paths = {"status": ("/api/v1/system", "GET"), "toggle": ("/api/v1/toggle", "POST"),
             "flush-cache": ("/api/v1/cache/flush", "POST"), "update": ("/api/v1/gravity/refresh", "POST")}
    path, method = paths[args.cmd]
    try:
        out = _api_call(args.url, path, args.token, method)
        print(json.dumps(out, indent=2))
        return 0
    except Exception as e:
        print(f"error: {e} (is the daemon running? do you need --token?)", file=sys.stderr)
        return 1


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
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read()).get("error", "")
        except Exception:
            detail = ""
        print(f"error: {detail or e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error: {e} (is the daemon running? do you need --token?)", file=sys.stderr)
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
    """`30s`, `5m`, `1h`, or a bare number of seconds."""
    text = text.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600}
    if text and text[-1] in units:
        return float(text[:-1] or 0) * units[text[-1]]
    return float(text or 0)


def _do_why(args) -> int:
    params = {"name": args.name, "type": args.type}
    if args.client:
        params["client"] = args.client
    if args.resolve:
        params["resolve"] = "1"
    path = "/api/v1/explain?" + urllib.parse.urlencode(params)
    try:
        out = _api_call(args.url, path, args.token)
    except Exception as e:
        print(f"error: {e} (is the daemon running? do you need --token?)", file=sys.stderr)
        return 1
    if args.as_json:
        print(json.dumps(out, indent=2))
        return 0
    print(out.get("verdict", ""))
    for f in out.get("findings", []):
        print(f"  · [{f['stage']}] {f['verdict']}: {f['detail']}")
    live = out.get("live") or {}
    if live and "error" not in live:
        answers = ", ".join(live.get("answers") or []) or "no addresses"
        print(f"  · [live] {live.get('action')}: {live.get('rcode')} -> {answers}")
        for ede in live.get("extended_errors", []):
            print(f"  · [live] extended error {ede['code']}: {ede['text']}")
    recent = out.get("recent") or []
    if recent:
        print(f"  · [log] {len(recent)} recent quer(y|ies); last action "
              f"{recent[0].get('action')}")
    return 0


def _do_pause(args) -> int:
    seconds = _seconds(args.duration)
    body = json.dumps({"seconds": seconds, "client": args.client}).encode()
    req = urllib.request.Request(
        args.url + "/api/v1/pause", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {args.token}"} if args.token else {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            print(json.dumps(json.loads(r.read()), indent=2))
        return 0
    except Exception as e:
        print(f"error: {e} (is the daemon running? do you need --token?)", file=sys.stderr)
        return 1


def _do_import(args) -> int:
    from ..ops.migrate_import import import_adguard, import_pihole
    res = import_pihole(args.path) if args.kind == "pihole" else import_adguard(args.path)
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
        rules = parse_list(Path(args.rule[1:]).read_text())
    else:
        r = parse_line(args.rule)
        rules = [r] if r else []
    if not rules:
        print("no valid rule parsed", file=sys.stderr)
        return 1
    engine = FilterEngine.compile(rules)
    rc = 0
    for name in args.names:
        d = engine.match(name.lower())
        verdict = getattr(d.action, "name", str(d.action))
        rule = f"  [{d.rule}]" if getattr(d, "rule", None) else ""
        print(f"{name:<40} {verdict}{rule}")
    return rc


def _do_backup(args) -> int:
    import tarfile
    from pathlib import Path
    data = Path(args.data_dir)
    if not data.exists():
        print(f"data dir {data} not found", file=sys.stderr)
        return 1
    with tarfile.open(args.out, "w:gz") as tar:
        tar.add(data, arcname=data.name)
    print(f"backed up {data} -> {args.out}")
    return 0


def _do_restore(args) -> int:
    import tarfile
    from pathlib import Path
    dest = Path(args.data_dir)
    if dest.exists() and any(dest.iterdir()) and not args.force:
        print(f"{dest} is not empty; pass --force to overwrite", file=sys.stderr)
        return 1
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(args.archive, "r:gz") as tar:
        members = tar.getmembers()
        # strip the leading archive top-dir so contents land directly in data-dir
        top = members[0].name.split("/")[0] + "/" if members else ""
        root = dest.resolve()
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
            # default. Links are refused outright; everything else must resolve
            # inside dest.
            if m.islnk() or m.issym():
                print(f"skipping link member {m.name!r}", file=sys.stderr)
                continue
            if not m.isfile() and not m.isdir():
                print(f"skipping special member {m.name!r}", file=sys.stderr)
                continue
            target = (root / m.name).resolve()
            if target != root and root not in target.parents:
                print(f"refusing member outside the data dir: {m.name!r}",
                      file=sys.stderr)
                return 1
            # `filter=` only exists from 3.11.4; the resolve() check above is
            # what actually holds the line on older builds.
            try:
                tar.extract(m, dest, filter="data")
            except TypeError:
                tar.extract(m, dest)
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
    args = _build_parser().parse_args(argv)
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
