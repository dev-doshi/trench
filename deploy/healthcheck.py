#!/usr/bin/env python3
"""Container healthcheck: does Trench still answer a query?

Resolution is the only thing worth probing. A process that is up but has
stopped answering is exactly the failure a healthcheck exists to catch, so
this sends a real query over the loopback and requires a well-formed reply
carrying the id it sent — an unrelated UDP packet must not pass.

Where to send it comes from the server's own config. A hardcoded port is a
copy of a fact that lives in `trench.yaml`, and the copy goes stale the moment
anyone edits it: this probe used to assume :53, while both `Config`'s default
and `trench.example.yaml` say 5354, so the general-purpose Compose quickstart
produced a container that resolved perfectly and reported unhealthy for as
long as it ran. `TRENCH_HEALTH_*` still overrides everything, for a deployment
whose config this process cannot see.
"""
from __future__ import annotations

import os
import socket
import sys

CONFIG = os.environ.get("TRENCH_CONFIG", "/data/trench.yaml")
NAME = os.environ.get("TRENCH_HEALTH_NAME", "health-check.trench.invalid")
TIMEOUT = float(os.environ.get("TRENCH_HEALTH_TIMEOUT", "4"))

# A name under .invalid can never resolve, which is the point: any rcode is a
# pass. We are testing that the server is processing queries, not that the
# internet is reachable — probing a real name would turn an upstream outage
# into a container restart loop.
QID = 0x4A17

# Only when the config cannot be read at all. Both Compose files mount it at
# /data/trench.yaml, so this is the hand-rolled `docker run` case.
FALLBACK = ("127.0.0.1", 53)


class NoListener(Exception):
    """The config has no Do53 UDP listener for this probe to reach."""


def _from_config() -> tuple[str, int]:
    try:
        import yaml
        with open(CONFIG) as fh:
            do53 = ((yaml.safe_load(fh) or {}).get("server") or {}).get("do53")
    except Exception:
        return FALLBACK
    if do53 is None:
        return FALLBACK
    if not do53.get("enabled", True) or not do53.get("udp", True):
        raise NoListener(
            f"{CONFIG} disables Do53 (or its UDP half), so there is nothing "
            f"for this probe to query. Point TRENCH_HEALTH_HOST/PORT at a "
            f"listener it can reach, or drop the healthcheck."
        )
    host = str(do53.get("host", FALLBACK[0]))
    if host in ("0.0.0.0", "::", ""):     # wildcard: loopback is part of it
        host = "127.0.0.1"
    return host, int(do53.get("port", FALLBACK[1]))


def target() -> tuple[str, int]:
    """Where to probe. An explicit override wins over the config."""
    env_host = os.environ.get("TRENCH_HEALTH_HOST")
    env_port = os.environ.get("TRENCH_HEALTH_PORT")
    try:
        host, port = _from_config()
    except NoListener:
        # An operator who names a port has named a listener, so the config's
        # Do53 settings no longer decide whether this probe can work.
        if not env_port:
            raise
        host, port = FALLBACK
    return env_host or host, int(env_port) if env_port else port


def query() -> bytes:
    header = QID.to_bytes(2, "big") + b"\x01\x00" + b"\x00\x01" + b"\x00" * 6
    labels = NAME.encode().split(b".")
    qname = b"".join(bytes([len(x)]) + x for x in labels) + b"\x00"
    return header + qname + b"\x00\x01\x00\x01"          # A, IN


def main() -> int:
    try:
        host, port = target()
    except (NoListener, ValueError) as e:
        print(f"trench healthcheck: {e}", file=sys.stderr)
        return 1
    # getaddrinfo rather than a hardcoded AF_INET: `host: '::'` in the config
    # is a supported listener, and an IPv6 literal is not an IPv4 socket.
    try:
        family, socktype, proto, _, addr = socket.getaddrinfo(
            host, port, type=socket.SOCK_DGRAM)[0]
    except OSError as e:
        print(f"trench healthcheck failed: {host}:{port}: {e}", file=sys.stderr)
        return 1
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(query(), addr)
        while True:
            data, _ = sock.recvfrom(4096)
            if len(data) < 12:
                continue
            if int.from_bytes(data[:2], "big") != QID:
                continue                                 # not our reply
            if not data[2] & 0x80:
                continue                                 # not a response
            return 0
    except OSError as e:
        print(f"trench healthcheck failed: {host}:{port}: {e}", file=sys.stderr)
        return 1
    finally:
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
