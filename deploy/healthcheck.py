#!/usr/bin/env python3
"""Container healthcheck: does Trench still answer a query?

Resolution is the only thing worth probing. A process that is up but has
stopped answering is exactly the failure a healthcheck exists to catch, so
this sends a real query over the loopback and requires a well-formed reply
carrying the id it sent — an unrelated UDP packet must not pass.
"""
from __future__ import annotations

import os
import socket
import sys

PORT = int(os.environ.get("TRENCH_HEALTH_PORT", "53"))
HOST = os.environ.get("TRENCH_HEALTH_HOST", "127.0.0.1")
NAME = os.environ.get("TRENCH_HEALTH_NAME", "health-check.trench.invalid")
TIMEOUT = float(os.environ.get("TRENCH_HEALTH_TIMEOUT", "4"))

# A name under .invalid can never resolve, which is the point: any rcode is a
# pass. We are testing that the server is processing queries, not that the
# internet is reachable — probing a real name would turn an upstream outage
# into a container restart loop.
QID = 0x4A17


def query() -> bytes:
    header = QID.to_bytes(2, "big") + b"\x01\x00" + b"\x00\x01" + b"\x00" * 6
    labels = NAME.encode().split(b".")
    qname = b"".join(bytes([len(x)]) + x for x in labels) + b"\x00"
    return header + qname + b"\x00\x01\x00\x01"          # A, IN


def main() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(query(), (HOST, PORT))
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
        print(f"trench healthcheck failed: {e}", file=sys.stderr)
        return 1
    finally:
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
