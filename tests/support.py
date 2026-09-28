"""Test helpers shared across suites.

`blocked_engine` exists because the pipeline suites used to build their filter
from `SimpleEngine`, a second matcher that no deployment ever ran. Its semantics
differed from the real one — no `$ctag`, no `$client`, no regex, a different
precedence order — so a change to `FilterEngine` could break every deployment
while the transport, multicore and upstream suites stayed green. This builds the
engine that actually serves queries, from the rule text an operator would write.
"""
from __future__ import annotations

import socket

from trench.filter import FilterEngine, iter_rules


def blocked_engine(*domains: str, allow: tuple[str, ...] = ()) -> FilterEngine:
    """A FilterEngine blocking `domains` and their subdomains, allowing `allow`."""
    lines = [f"||{d}^" for d in domains] + [f"@@||{d}^$important" for d in allow]
    return FilterEngine.compile(iter_rules("\n".join(lines), "test"))


def free_port(retries: int = 20) -> int:
    """A localhost port that is free for *both* TCP and UDP.

    Probing with one protocol says nothing about the other. Several servers
    under test bind both halves — `Do53Server` does, and the API's aiohttp
    site is TCP — so a UDP-only probe hands out a port whose TCP half is
    already taken, and the bind fails as EADDRINUSE on whichever run happens
    to lose the race. That reads as an unrelated test failing at random,
    which is the worst kind of red.
    """
    for _ in range(retries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            tcp.bind(("127.0.0.1", 0))
            port: int = tcp.getsockname()[1]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind(("127.0.0.1", port))
        except OSError:
            continue
        return port
    raise RuntimeError(f"no port free on both TCP and UDP after {retries} tries")


async def api_app(tmp_path, **overrides):
    """An `App` with storage up and an `APIServer` listening, plus its base URL.

    The API suites each grew their own copy of this; sharing it means a change
    to App's start-up sequence is made once rather than in six places.
    """
    from trench.api import APIServer
    from trench.app import App
    from trench.config import Config
    data = {"data_dir": str(tmp_path),
            "server": {"do53": {"enabled": False}},
            "web": {"enabled": True, "admin_password": "pw"}}
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key] = {**data[key], **value}
        else:
            data[key] = value
    app = App(Config.model_validate(data))
    await app.setup_storage()
    port = free_port()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    return app, f"http://127.0.0.1:{port}"


async def shutdown_api(app):
    await app.api.stop()
    if app.db is not None:
        await app.db.close()
