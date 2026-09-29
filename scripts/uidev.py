"""Dev harness: run the Trench API + console UI against a plausible network.

Not part of the shipped product. It exists so every view has something to
render, and so the screenshots in the README are of a resolver in front of a
real-looking house rather than of a loopback smoke test.

    python3 scripts/uidev.py              # 6 hours of history, then live
    python3 scripts/uidev.py --hours 24   # a longer window
    python3 scripts/uidev.py --hours 0    # live only

The traffic model is deliberately not uniform. Devices wake, burst, and go
quiet; hot names come back from cache while cold ones pay for an upstream
round trip; a handful of queries time out. Uniform random traffic renders as a
flat bar chart and a single latency spike, which is exactly what a synthetic
dataset looks like from the outside.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import random
import sys
import tempfile
import time

# make this runnable from any cwd (the preview harness runs from the repo root)
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from trench.api import APIServer
from trench.app import App
from trench.config import Config
from trench.store.querylog import _COLUMNS, _INSERT, QueryRecord

# ---------------------------------------------------------------- the network

class Device:
    """One thing on the LAN, with the name pattern that thing actually has."""

    def __init__(self, name, ip, mac, rate, names, block_rate, awake, ads):
        self.name, self.ip, self.mac = name, ip, mac
        self.rate = rate              # queries per minute while awake
        self.names = names            # (weight, name) it resolves
        self.block_rate = block_rate  # share of its traffic that is ad/telemetry
        self.awake = awake            # (start_hour, end_hour) in local time
        # What *this* device's blocked traffic is. A thermostat phones home to
        # a metrics endpoint; it does not load a display ad. Drawing every
        # device's blocked names from one pool is the tell that gives a
        # synthetic query log away.
        self.ads = ads

    def pick(self):
        total = sum(w for w, _ in self.names)
        n = random.uniform(0, total)
        for w, name in self.names:
            n -= w
            if n <= 0:
                return name
        return self.names[-1][1]


_BROWSING = [
    (9, "github.com"), (7, "api.github.com"), (6, "objects.githubusercontent.com"),
    (8, "news.ycombinator.com"), (5, "wikipedia.org"), (5, "upload.wikimedia.org"),
    (6, "reddit.com"), (4, "styles.redditmedia.com"), (5, "nytimes.com"),
    (4, "static01.nyt.com"), (6, "stripe.com"), (3, "js.stripe.com"),
    (5, "cloudflare.com"), (4, "cdnjs.cloudflare.com"), (4, "arxiv.org"),
    (5, "python.org"), (4, "pypi.org"), (5, "files.pythonhosted.org"),
    (4, "registry.npmjs.org"), (3, "archlinux.org"), (3, "kernel.org"),
    (3, "debian.org"), (3, "mozilla.org"), (2, "openstreetmap.org"),
    (2, "tile.openstreetmap.org"), (3, "signal.org"), (2, "bbc.co.uk"),
    (2, "static.bbci.co.uk"), (2, "theguardian.com"),
]
_APPLE = [
    (9, "gateway.icloud.com"), (7, "p50-content.icloud.com"), (6, "apple.com"),
    (5, "gs-loc.apple.com"), (5, "configuration.apple.com"), (4, "captive.apple.com"),
    (4, "time.apple.com"), (3, "push.apple.com"),
]
_STREAM = [
    (12, "netflix.com"), (10, "occ-0-2851-2848.1.nflxso.net"), (9, "ipv4-c001.lhr001.ix.nflxvideo.net"),
    (8, "youtube.com"), (9, "rr3---sn-4g5e6nsz.googlevideo.com"), (6, "i.ytimg.com"),
    (5, "spotify.com"), (4, "audio-fa.scdn.co"), (4, "disneyplus.com"),
]
# Blocked traffic, split by the kind of thing that actually emits it.
_ADS_WEB = [
    (10, "doubleclick.net"), (9, "ads.doubleclick.net"), (8, "google-analytics.com"),
    (8, "googlesyndication.com"), (7, "googleadservices.com"), (7, "scorecardresearch.com"),
    (6, "adservice.google.com"), (6, "graph.facebook.com"), (5, "connect.facebook.net"),
]
_ADS_APP = [
    (8, "app-measurement.com"), (7, "firebaselogging-pa.googleapis.com"),
    (6, "analytics.tiktok.com"), (5, "in.appcenter.ms"), (5, "graph.facebook.com"),
    (4, "doubleclick.net"),
]
_ADS_TELEMETRY = [
    (7, "device-metrics-us.amazon.com"), (6, "telemetry.dropbox.com"),
    (6, "settings-win.data.microsoft.com"), (5, "firebaselogging-pa.googleapis.com"),
]
_ADS = _ADS_WEB + _ADS_APP + _ADS_TELEMETRY
_IOT = [
    (14, "api.nest.com"), (10, "time.nist.gov"), (8, "pool.ntp.org"),
    (6, "firmware.tado.com"), (5, "mqtt.hivemq.com"),
]
_INFRA = [
    (12, "deb.debian.org"), (10, "security.debian.org"), (8, "ghcr.io"),
    (7, "auth.docker.io"), (7, "production.cloudflare.docker.com"),
    (6, "prometheus.io"), (5, "grafana.com"),
]

DEVICES = [
    Device("macbook-pro",  "10.0.4.21",  "3c:22:fb:8a:11:4d", 34, _BROWSING + _APPLE, 0.16, (7, 24), _ADS_WEB),
    Device("iphone-mahir", "10.0.4.37",  "a4:83:e7:2c:90:e1", 22, _APPLE,             0.31, (7, 24), _ADS_APP),
    Device("work-laptop",  "10.0.4.44",  "f0:18:98:5b:2a:77", 26, _BROWSING + _INFRA, 0.12, (9, 18), _ADS_WEB),
    Device("apple-tv",     "10.0.4.62",  "b8:e8:56:31:0c:9a", 18, _STREAM,            0.07, (18, 24), _ADS_APP),
    Device("pixel-tablet", "10.0.4.71",  "d0:2b:20:44:8f:12", 12, _STREAM,            0.28, (8, 23), _ADS_APP),
    Device("nas",          "10.0.4.10",  "00:11:32:9d:41:5c",  6, _INFRA,             0.02, (0, 24), _ADS_TELEMETRY),
    Device("thermostat",   "10.0.4.118", "18:b4:30:7f:e2:03",  2, _IOT,               0.09, (0, 24), _ADS_TELEMETRY),
]

BLOCKED = {n for _, n in _ADS}

QTYPES = [(44, "A"), (36, "AAAA"), (16, "HTTPS"), (2, "PTR"), (1, "TXT"), (1, "SRV")]
UPSTREAMS = ["1.1.1.1", "9.9.9.9"]


def _weighted(pairs):
    total = sum(w for w, _ in pairs)
    n = random.uniform(0, total)
    for w, v in pairs:
        n -= w
        if n <= 0:
            return v
    return pairs[-1][1]


def _latency(action):
    """Microseconds, shaped like the thing it is measuring.

    A cache hit is a dict lookup. A block is a lookup plus a synthesised
    answer. A forward is a round trip over DoT to a resolver one hop off the
    ISP, which is milliseconds and has a long tail. A failure is a timeout.
    """
    if action == "cached":
        return int(random.lognormvariate(math.log(45), 0.45))
    if action == "blocked":
        return int(random.lognormvariate(math.log(120), 0.5))
    if action == "failed":
        return random.randint(1_800_000, 5_000_000)
    us = int(random.lognormvariate(math.log(21_000), 0.75))
    return min(us, 900_000)


def _answers(action, qtype):
    if action == "blocked":
        # `zero_ip` answers the address types and NODATA for everything else;
        # a sinkholed HTTPS query does not come back holding an AAAA.
        return {"A": ["0.0.0.0"], "AAAA": ["::"]}.get(qtype, [])
    if action == "failed" or qtype not in ("A", "AAAA"):
        return []
    if qtype == "AAAA":
        return [f"2606:4700::{random.randint(0x1000, 0xffff):x}"]
    return [f"{random.choice((104, 151, 172, 185))}.{random.randint(1, 254)}."
            f"{random.randint(1, 254)}.{random.randint(1, 254)}"]


class Traffic:
    """Generates query records, keeping enough state to be self-consistent.

    The cache is the point: a name resolved a moment ago comes back from
    memory, so the outcome mix and the latency histogram both fall out of the
    traffic rather than being drawn from thin air.
    """

    def __init__(self):
        self.seen: dict[tuple[str, str], float] = {}

    def one(self, device: Device, ts: float) -> QueryRecord:
        blocked = random.random() < device.block_rate
        name = _weighted(device.ads) if blocked else device.pick()
        qtype = _weighted(QTYPES)
        if qtype == "PTR":
            name = f"{random.randint(1, 254)}.4.0.10.in-addr.arpa"

        key = (name, qtype)
        fresh = ts - self.seen.get(key, -1e9) < random.uniform(60, 900)
        self.seen[key] = ts

        if name in BLOCKED or blocked:
            # `zero_ip` is the shipped default: NOERROR carrying 0.0.0.0 / ::,
            # not NXDOMAIN. A blocked row that claims both is a giveaway.
            action, rcode, upstream = "blocked", "NOERROR", ""
            reason, rule, source = "blocklist", f"||{name}^", "hagezi-pro"
        elif fresh:
            action, rcode, upstream, reason, rule, source = "cached", "NOERROR", "", "", "", ""
        elif random.random() < 0.004:
            action, rcode = "failed", "SERVFAIL"
            upstream, reason, rule, source = random.choice(UPSTREAMS), "upstream timeout", "", ""
        else:
            action, rcode = "forwarded", "NOERROR"
            upstream, reason, rule, source = random.choice(UPSTREAMS), "", "", ""

        return QueryRecord(
            ts=int(ts * 1_000_000), client_ip=device.ip, client_id=device.name,
            qname=name, qtype=qtype, proto=random.choice(("udp", "udp", "udp", "tcp", "tls")),
            action=action, reason=reason, rule=rule, source=source, upstream=upstream,
            rcode=rcode, answers=_answers(action, qtype), elapsed_us=_latency(action),
            dnssec="secure" if action == "forwarded" and random.random() < 0.35 else "",
        )


def _activity(device: Device, ts: float) -> float:
    """How busy this device is at this instant, in [0, 1].

    Devices are asleep outside their hours, ramp at the edges, and get a slow
    sinusoidal wobble on top so the timeline has a shape instead of a level.
    """
    hour = time.localtime(ts).tm_hour + time.localtime(ts).tm_min / 60
    start, end = device.awake
    if not (start <= hour < end):
        return 0.04                                     # background chatter
    span = end - start
    phase = (hour - start) / span
    ramp = min(1.0, phase * 6, (1 - phase) * 6)
    return max(0.05, ramp * (0.65 + 0.35 * math.sin(ts / 900)))


# ---------------------------------------------------------------- the history

async def backfill(app: App, hours: float) -> int:
    """Write `hours` of history straight to the table.

    Straight, rather than through `enqueue()`: that path batches 500 rows every
    250 ms and sheds above 50,000 queued, which is correct for a live resolver
    and useless for loading a day of traffic at once.
    """
    if hours <= 0 or app.querylog is None or app.querylog.db is None:
        return 0
    traffic = Traffic()
    now = time.time()
    records: list[QueryRecord] = []

    for device in DEVICES:
        ts = now - hours * 3600
        while ts < now:
            level = _activity(device, ts)
            if level <= 0.05 and random.random() > 0.15:
                ts += 60
                continue
            # A device does not emit one query a minute; it emits a burst when
            # something on it opens a connection, then nothing.
            for _ in range(max(1, int(random.expovariate(1 / (device.rate * level / 4)) + 1))):
                records.append(traffic.one(device, ts + random.uniform(0, 8)))
            ts += random.expovariate(1 / (60 / max(0.2, level)))

    records.sort(key=lambda r: r.ts)
    rows = [[json.dumps(r.answers) if c == "answers" else getattr(r, c) for c in _COLUMNS]
            for r in records]
    for i in range(0, len(rows), 2000):
        await app.querylog.db.executemany(_INSERT, rows[i:i + 2000])

    # The last three hours also belong in the in-memory counters, which is what
    # the header totals and the sparkline read.
    for r in records:
        if r.ts / 1_000_000 > now - 3 * 3600:
            app.counters.record(client=r.client_ip, qname=r.qname, qtype=r.qtype,
                                action=r.action, rcode=r.rcode, upstream=r.upstream,
                                elapsed_us=r.elapsed_us, reason=r.reason)
    return len(rows)


# ------------------------------------------------------------------- the live

async def live(app: App) -> None:
    traffic = Traffic()
    while True:
        now = time.time()
        device = random.choice(DEVICES)
        if random.random() > _activity(device, now):
            await asyncio.sleep(0.1)
            continue
        rec = traffic.one(device, now)
        app.counters.record(client=rec.client_ip, qname=rec.qname, qtype=rec.qtype,
                            action=rec.action, rcode=rec.rcode, upstream=rec.upstream,
                            elapsed_us=rec.elapsed_us, reason=rec.reason)
        if app.querylog is not None:
            app.querylog.enqueue(rec)
        await asyncio.sleep(random.expovariate(1 / 2.5))


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hours", type=float, default=6, help="history to seed before starting")
    ap.add_argument("--port", type=int, default=8089)
    ap.add_argument("--seed", type=int, default=None, help="fix the RNG for reproducible screenshots")
    ap.add_argument("--no-live", dest="live", action="store_false",
                    help="serve the seeded window and generate nothing further")
    args = ap.parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    cfg = Config.model_validate({
        "data_dir": tempfile.mkdtemp(prefix="trench-uidev-"),
        "server": {"do53": {"enabled": False}},
        "querylog": {"enabled": True, "privacy_level": 0, "retention_days": 90},
        # two groups, so the device-to-group controls have somewhere to put things
        "filtering": {"deny": sorted(BLOCKED), "groups": {
            "kids": {"deny": ["tiktok.com", "roblox.com"]},
            "work": {"inherit": False, "allow": ["doubleclick.net"]},
        }},
        "clients": [{"ident": d.ip, "type": "ip", "name": d.name} for d in DEVICES],
        "web": {"enabled": True, "host": "127.0.0.1", "port": args.port, "admin_password": "admin"},
    })
    app = App(cfg)
    await app.setup_storage()
    n = await backfill(app, args.hours)
    if n:
        print(f"seeded {n:,} queries over {args.hours:g}h from {len(DEVICES)} devices")
    app.api = APIServer(app, "127.0.0.1", args.port)
    await app.api.start()
    print(f"UI dev server on http://127.0.0.1:{args.port}  (login: admin / admin)")
    if args.live:
        asyncio.ensure_future(live(app))
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
