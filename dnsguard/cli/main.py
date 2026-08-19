"""dnsguard CLI: built-in dig over every transport, control via the API,
and config import. Run `dnsguard <command> -h` for details.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import urllib.request

from ..version import __version__
from ..wire import Class, Message, Question
from ..wire.name import Name
from ..wire.rrtypes import type_from_text, type_to_text


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dnsguard", description="DNSGuard CLI")
    p.add_argument("--version", action="version", version=f"dnsguard {__version__}")
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
    pr.add_argument("--name", default="DNSGuard")
    pr.add_argument("--doh-url", help="https://host/dns-query")
    pr.add_argument("--dot-host", help="TLS server name")
    pr.add_argument("--address", action="append", help="pin resolver IP (repeatable)")

    pw = sub.add_parser("passwd", help="set a web-admin password (offline, on the box)")
    pw.add_argument("user", nargs="?", default="admin")
    pw.add_argument("--data-dir", default="./data")
    pw.add_argument("--db", default="dnsguard.db", help="database file inside the data dir")
    pw.add_argument("--password", help="new password (omit to generate one and print it)")
    pw.add_argument("--role", default="admin", help="role if the user has to be created")

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


def _api_call(url: str, path: str, token: str, method: str = "GET"):
    req = urllib.request.Request(url + path, method=method,
                                 headers={"Authorization": f"Bearer {token}"} if token else {})
    with urllib.request.urlopen(req, timeout=5) as r:
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
    print("# add to dnsguard.yaml, and give the same key to the peer server:")
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
        for m in members:
            if m.name == top.rstrip("/"):
                continue
            m.name = m.name[len(top):] if m.name.startswith(top) else m.name
            if m.name:
                tar.extract(m, dest)  # noqa: S202 (trusted local backup)
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

    The autogenerated first-run password is only ever printed to the log; once
    that log rotates, an operator with full physical access to the box can be
    locked out of their own resolver. Write access to the database is the proof
    of ownership here, so this deliberately works offline against the file
    rather than through the authenticated API.
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
    if args.cmd == "import":
        return _do_import(args)
    if args.cmd in handlers:
        return handlers[args.cmd](args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
