"""Dev harness: run the Trench API + console UI and synthesize realistic live
traffic so every view has data to render. Not part of the shipped product."""
from __future__ import annotations

import asyncio
import os
import random
import sys
import time

# make this runnable from any cwd (the preview harness runs from the repo root)
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from trench.api import APIServer
from trench.app import App
from trench.config import Config
from trench.store.querylog import QueryRecord

DOMAINS_OK = ["github.com", "cloudflare.com", "apple.com", "wikipedia.org", "netflix.com",
              "signal.org", "arxiv.org", "news.ycombinator.com", "npmjs.com", "python.org",
              "grafana.net", "fastly.net", "akamai.net"]
DOMAINS_BLOCK = ["ads.doubleclick.net", "tracker.example.com", "telemetry.microsoft.com",
                 "analytics.tiktok.com", "pixel.facebook.com", "metrics.apple.com"]
DOMAINS_THREAT = ["kq3v9z7x1p2w.info", "x7f2a9b1c3d4e5.biz"]
CLIENTS = ["10.0.0.5", "10.0.0.12", "10.0.0.23", "192.168.1.40", "192.168.1.101", "10.0.0.8"]
UPSTREAMS = ["1.1.1.1", "9.9.9.9", "8.8.8.8"]
QTYPES = ["A", "AAAA", "HTTPS", "MX", "TXT", "PTR"]


async def synth(app: App):
    while True:
        r = random.random()
        if r < 0.62:
            dom, action, up = random.choice(DOMAINS_OK), random.choice(["forwarded", "cached"]), random.choice(UPSTREAMS)
            rcode, reason = "NOERROR", ""
        elif r < 0.9:
            dom, action, up, rcode, reason = random.choice(DOMAINS_BLOCK), "blocked", "", "NXDOMAIN", "gravity blocklist"
        elif r < 0.96:
            dom, action, up, rcode, reason = random.choice(DOMAINS_OK), "failed", random.choice(UPSTREAMS), "SERVFAIL", "upstream timeout"
        else:
            dom = random.choice(DOMAINS_THREAT)
            action, up, rcode, reason = "blocked", "", "NXDOMAIN", "DGA detection"
            app.counters.note_dga(dom)
        client = random.choice(CLIENTS)
        qtype = random.choice(QTYPES)
        elapsed = random.randint(80, 4200) if action != "cached" else random.randint(20, 90)
        app.counters.record(client=client, qname=dom, qtype=qtype, action=action,
                            rcode=rcode, upstream=up, elapsed_us=elapsed, reason=reason)
        if app.querylog is not None:
            app.querylog.enqueue(QueryRecord(
                ts=int(time.time() * 1_000_000), client_ip=client, client_id="",
                qname=dom, qtype=qtype, proto="udp", action=action, reason=reason,
                rule=dom if action == "blocked" else "", source="gravity" if action == "blocked" else "",
                upstream=up, rcode=rcode, answers=[], elapsed_us=elapsed))
        await asyncio.sleep(random.uniform(0.05, 0.35))


async def main():
    import tempfile
    cfg = Config.model_validate({
        "data_dir": tempfile.mkdtemp(prefix="trench-uidev-"),
        "server": {"do53": {"enabled": False}},
        "querylog": {"enabled": True, "privacy_level": 0},
        "filtering": {"deny": ["ads.doubleclick.net", "tracker.example.com"]},
        "web": {"enabled": True, "host": "127.0.0.1", "port": 8089, "admin_password": "admin"},
    })
    app = App(cfg)
    await app.setup_storage()
    app.api = APIServer(app, "127.0.0.1", 8089)
    await app.api.start()
    print("UI dev server on http://127.0.0.1:8089  (login: admin / admin)")
    asyncio.ensure_future(synth(app))
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
