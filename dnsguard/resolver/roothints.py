"""IANA root server hints (priming). Bundled; refreshable from named.root."""
from __future__ import annotations

# a-m.root-servers.net (IPv4 + a couple IPv6), as of the current root zone
ROOT_HINTS: list[str] = [
    "198.41.0.4",       # a
    "170.247.170.2",    # b
    "192.33.4.12",      # c
    "199.7.91.13",      # d
    "192.203.230.10",   # e
    "192.5.5.241",      # f
    "192.112.36.4",     # g
    "198.97.190.53",    # h
    "192.36.148.17",    # i
    "192.58.128.30",    # j
    "193.0.14.129",     # k
    "199.7.83.42",      # l
    "202.12.27.33",     # m
    "2001:503:ba3e::2:30",  # a (v6)
    "2001:500:2f::f",       # f (v6)
]
