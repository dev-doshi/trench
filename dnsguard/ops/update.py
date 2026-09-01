"""Knowing a newer DNSGuard exists, and — where it is safe — installing it.

Self-updating software is a liability wearing a convenience costume: it is code
that rewrites the code that is deciding, right now, what a household is allowed
to resolve. This was left out of an earlier milestone for exactly that reason.
It is here now because the alternative in practice is a resolver that quietly
runs a version with a known parser bug in it for a year.

So the design is arranged around what can go wrong rather than around the happy
path:

  * **Checking and applying are different actions.** The default mode only
    checks and tells you. Nothing on the check path writes to the filesystem,
    and `mode: notify` never installs anything no matter how old the running
    version is.
  * **The artifact is verified before it is trusted.** The index states a
    sha256 for the wheel; the download is hashed and compared before anything
    is unpacked. A mismatch is a hard failure, never a warning. The release
    path publishes to PyPI through trusted publishing (OIDC, no long-lived
    token), so the digest chains back to the CI run that built the artifact.
  * **It is installed twice.** First into a throwaway staging environment,
    where it must import and answer `--version`; only then into the live one.
    A wheel that cannot start is discovered while the running install is still
    untouched.
  * **It refuses where it cannot be safe.** A container image cannot rewrite
    itself, a distribution package belongs to the distribution's package
    manager, and an editable checkout belongs to whoever is working in it.
    Each of those is detected and refused with the reason, rather than half
    done.
  * **It does not restart itself by default.** Applying an update stages new
    code on disk; the running process keeps serving from the code already in
    memory. Restarting is the supervisor's job, and DNSGuard will only ask
    systemd to do it if explicitly configured to.

**On "no interruption".** The honest claim is narrower than "no downtime". An
update never interrupts resolution *while it is being applied*: the running
process is not touched, and applying is refused outright while a blocklist
build holds `App._building`, so an update cannot collide with the one job that
already peaks this box's memory. The restart afterwards is a real restart —
short, because the listening sockets are pre-bound before the workers fork and
the compiled block table is mapped from disk rather than recompiled, so the
resolver comes back filtered rather than coming back open. For a genuinely
gapless restart, put the listeners behind systemd socket activation: systemd
holds them across the restart and the kernel queues what arrives meanwhile.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..log import get
from ..version import USER_AGENT, __version__

log = get("updates")

#: The release index. PyPI's JSON API carries the sha256 of every artifact in
#: the same response that names the version, so one request yields both the
#: answer and the means to verify it.
DEFAULT_INDEX = "https://pypi.org/pypi/dnsguard/json"

#: Ceiling on a downloaded artifact. A DNSGuard wheel is a couple of MB; this
#: is loose enough never to bite and tight enough that a redirected or hostile
#: index cannot stream this box out of memory.
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

#: How long the staging install and the smoke test get before they are
#: abandoned. Creating a venv on an SD card is slow, so this is generous.
STAGING_TIMEOUT = 600.0
SMOKE_TIMEOUT = 120.0


class UpdateError(Exception):
    """An update could not be checked or applied. The message is for an operator."""


# ─────────────────────────────────────────────────────────────── versions ──
#: PEP 440, restricted to the shapes this project actually publishes: a release
#: segment, an optional pre-release, and optional post/dev segments.
_VERSION = re.compile(
    r"^\s*v?(?P<release>\d+(?:\.\d+)*)"
    r"(?:(?P<pre_l>a|b|rc|alpha|beta|c|pre|preview)\.?(?P<pre_n>\d*))?"
    r"(?:\.post\.?(?P<post>\d+))?"
    r"(?:\.dev\.?(?P<dev>\d+))?\s*$",
    re.IGNORECASE,
)

_PRE_ORDER = {"dev": -2, "a": -1, "b": 0, "rc": 1, None: 2, "post": 3}
_PRE_ALIAS = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}


def parse_version(text: str) -> tuple | None:
    """A sortable key for a version string, or None if it is not one.

    Ordering is the PEP 440 ordering for the subset above: dev < alpha < beta
    < rc < final < post. Comparing version *strings* is how "2.10.0" ends up
    older than "2.9.0", which is a bug that only appears once a project has
    shipped ten minor releases and is unpleasant to find then.
    """
    m = _VERSION.match(text or "")
    if m is None:
        return None
    release = tuple(int(part) for part in m.group("release").split("."))
    # Pad so 2.0 and 2.0.0 compare equal rather than by length.
    release = release + (0,) * (4 - len(release)) if len(release) < 4 else release
    pre_l = m.group("pre_l")
    if pre_l:
        pre_l = _PRE_ALIAS.get(pre_l.lower(), pre_l.lower())
    if m.group("dev") is not None:
        stage, number = "dev", int(m.group("dev"))
    elif m.group("post") is not None:
        stage, number = "post", int(m.group("post"))
    elif pre_l:
        stage, number = pre_l, int(m.group("pre_n") or 0)
    else:
        stage, number = None, 0
    return (release, _PRE_ORDER.get(stage, 2), number)


def is_prerelease(text: str) -> bool:
    key = parse_version(text)
    return key is not None and key[1] < 2


def is_newer(candidate: str, current: str) -> bool:
    """True when `candidate` is a strictly later version than `current`."""
    a, b = parse_version(candidate), parse_version(current)
    return a is not None and b is not None and a > b


# ─────────────────────────────────────────────────────── install methods ──
@dataclass(frozen=True)
class Install:
    """How this DNSGuard got onto the box, and whether it may rewrite itself."""

    method: str          # venv | system | container | source | unknown
    prefix: str          # sys.prefix, for the record
    python: str          # the interpreter that would run pip
    writable: bool       # can this process write to the install directory?
    reason: str = ""     # why it cannot self-update, when it cannot

    @property
    def can_apply(self) -> bool:
        return self.method == "venv" and self.writable and not self.reason


def _in_container() -> bool:
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        return True
    try:
        cgroup = Path("/proc/1/cgroup").read_text()
    except OSError:
        return False
    return any(marker in cgroup for marker in ("docker", "kubepods", "containerd", "lxc"))


def detect_install(package_dir: Path | None = None) -> Install:
    """Classify the running installation.

    Only one shape is self-updatable: a virtual environment this process can
    write to. Everything else has an owner that is not us — an image build, a
    distribution's package manager, or a developer's working tree — and
    installing over any of them produces a box whose state nobody can predict
    from the outside.
    """
    root = package_dir or Path(__file__).resolve().parent.parent
    prefix, python = sys.prefix, sys.executable
    if _in_container():
        return Install("container", prefix, python, False,
                       "running in a container: rebuild or pull the image instead")
    # An editable install or a source checkout: the code is someone's working
    # tree, and pip would fight whatever is managing it.
    if (root.parent / ".git").exists() or (root.parent / "pyproject.toml").exists():
        return Install("source", prefix, python, False,
                       "running from a source checkout: use git and pip yourself")
    if any(part in ("dist-packages",) for part in root.parts):
        return Install("system", prefix, python, False,
                       "installed by the system package manager: update through it")
    if sys.prefix == sys.base_prefix:
        return Install("unknown", prefix, python, False,
                       "not running inside a virtual environment DNSGuard owns")
    writable = os.access(root, os.W_OK) and os.access(Path(python).parent, os.W_OK)
    return Install("venv", prefix, python, writable,
                   "" if writable else "the virtual environment is not writable by this user")


# ─────────────────────────────────────────────────────────────── releases ──
@dataclass(frozen=True)
class Release:
    version: str
    url: str
    sha256: str
    size: int = 0
    requires_python: str = ""
    yanked: bool = False


def pick_release(index: dict, *, current: str, allow_prerelease: bool = False,
                 want: str | None = None) -> Release | None:
    """The release to move to, or None when there is nothing to do.

    `want` pins an exact version (that is what a rollback is). Otherwise the
    newest version that is newer than what is running wins. Yanked releases are
    skipped: a yank is the publisher saying "not this one", and honouring it is
    the entire point of the flag.
    """
    releases = index.get("releases") or {}
    candidates: list[tuple[tuple, str]] = []
    for version, files in releases.items():
        key = parse_version(version)
        if key is None or not files:
            continue
        if want is not None:
            if version != want:
                continue
        else:
            if not allow_prerelease and is_prerelease(version):
                continue
            if not is_newer(version, current):
                continue
        candidates.append((key, version))
    if not candidates:
        return None
    _, version = max(candidates)
    for artifact in releases[version]:
        if artifact.get("packagetype") != "bdist_wheel" or artifact.get("yanked"):
            continue
        digest = (artifact.get("digests") or {}).get("sha256", "")
        url = artifact.get("url", "")
        if not digest or not url:
            continue
        return Release(version=version, url=url, sha256=digest.lower(),
                       size=int(artifact.get("size") or 0),
                       requires_python=artifact.get("requires_python") or "",
                       yanked=bool(artifact.get("yanked")))
    return None


# ───────────────────────────────────────────────────── maintenance window ──
_WINDOW = re.compile(r"^\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*$")


def window_contains(window: str, when: datetime | None = None) -> bool:
    """Is `when` inside `HH:MM-HH:MM` local time? An empty window is always true.

    Windows that wrap midnight (``23:00-02:00``) are the normal case for a
    maintenance window and are handled as one interval, not two.
    """
    if not window.strip():
        return True
    m = _WINDOW.match(window)
    if m is None:
        raise ValueError(f"not a maintenance window: {window!r} (want HH:MM-HH:MM)")
    sh, sm, eh, em = (int(g) for g in m.groups())
    if not (0 <= sh < 24 and 0 <= eh < 24 and sm < 60 and em < 60):
        raise ValueError(f"not a time of day: {window!r}")
    now = when or datetime.now()
    minutes = now.hour * 60 + now.minute
    start, end = sh * 60 + sm, eh * 60 + em
    if start == end:
        return True
    return start <= minutes < end if start < end else (minutes >= start or minutes < end)


# ────────────────────────────────────────────────────────────────── state ──
@dataclass
class UpdateState:
    """What the last check and the last apply found. Persisted across restarts.

    Kept on disk so a restart does not lose the fact that an update is staged
    and waiting — which is exactly the moment a restart happens.
    """

    last_check: float = 0.0
    last_error: str = ""
    latest_version: str = ""
    latest_url: str = ""
    latest_sha256: str = ""
    applied_version: str = ""
    applied_at: float = 0.0
    previous_version: str = ""
    restart_required: bool = False
    history: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> UpdateState:
        try:
            raw = json.loads(path.read_text())
        except (OSError, ValueError):
            return cls()
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in raw.items() if k in known})

    def save(self, path: Path) -> None:
        """Atomically. A half-written state file reads as no state at all, and
        `load` would then quietly forget that a restart is pending."""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w") as fh:
            json.dump(asdict(self), fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def note(self, event: str, **detail: Any) -> None:
        self.history.append({"ts": int(time.time()), "event": event, **detail})
        del self.history[:-20]


#: A wheel filename, and nothing that is also a path. pip parses the *name* to
#: learn what it is installing — a wheel renamed to anything else is rejected
#: with "not a valid wheel filename" — so the name has to come from the index.
#: It is therefore attacker-influenced input used to build a path, which is why
#: it is matched against this rather than merely basename'd.
_WHEEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]*\.whl$")


def _artifact_name(url: str) -> str:
    """The filename to save an artifact under, taken from its URL and checked.

    Refuses anything that is not a plain wheel filename, so a hostile or broken
    index cannot steer the write out of the staging directory.
    """
    from urllib.parse import unquote, urlsplit

    candidate = os.path.basename(unquote(urlsplit(url).path))
    if not _WHEEL_NAME.match(candidate) or candidate in (".", "..") or os.sep in candidate:
        raise UpdateError(f"the index offered an artifact this cannot save: {candidate!r}")
    return candidate


# ──────────────────────────────────────────────────────────────── updater ──
class Updater:
    """Checks for a newer release, and applies one when told it may.

    Everything that touches the network or a subprocess is awaited with a
    timeout and never runs on the event loop's critical path: the check is a
    scheduler job like the blocklist refresh, and pip runs as a subprocess.
    """

    def __init__(self, cfg, *, data_dir: Path, current_version: str = __version__,
                 is_busy: Callable[[], bool] | None = None,
                 audit: Callable[..., Any] | None = None,
                 fetch_json: Callable[[str], Any] | None = None) -> None:
        self.cfg = cfg
        self.data_dir = Path(data_dir)
        self.current = current_version
        # `is_busy` is App._building: an update must not run while a blocklist
        # build is compiling, because that is already the memory high-water
        # mark of the whole process.
        self._is_busy = is_busy or (lambda: False)
        self._audit = audit
        self._fetch_json = fetch_json          # injected in tests
        self.state = UpdateState.load(self.state_path)
        self.install = detect_install()
        self._applying = asyncio.Lock()

    # ---------------------------------------------------------------- paths
    @property
    def state_path(self) -> Path:
        return self.data_dir / "updates.json"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "updates"

    # --------------------------------------------------------------- status
    def status(self) -> dict:
        """Everything the API, the CLI and the console render. No side effects."""
        available = bool(self.state.latest_version
                         and is_newer(self.state.latest_version, self.current))
        return {
            "mode": self.cfg.mode,
            "channel": self.cfg.channel,
            "current_version": self.current,
            "latest_version": self.state.latest_version,
            "update_available": available,
            "last_check": self.state.last_check,
            "last_error": self.state.last_error,
            "restart_required": self.state.restart_required,
            "applied_version": self.state.applied_version,
            "previous_version": self.state.previous_version,
            "install_method": self.install.method,
            "can_apply": self.install.can_apply and self.cfg.mode != "off",
            "why_not": self._why_not(),
            "window": self.cfg.window,
            "in_window": self._in_window(),
            "history": list(self.state.history),
        }

    def _why_not(self) -> str:
        if self.cfg.mode == "off":
            return "updates.mode is off"
        if not self.install.can_apply:
            return self.install.reason or f"cannot self-update a {self.install.method} install"
        return ""

    def _in_window(self) -> bool:
        try:
            return window_contains(self.cfg.window)
        except ValueError as e:
            log.warning("%s; treating the window as always-open", e)
            return True

    # ---------------------------------------------------------------- check
    async def check(self) -> Release | None:
        """Ask the index what the newest release is. Never raises into a caller
        that is a scheduler job; the error is recorded and surfaced instead."""
        if self.cfg.mode == "off":
            return None
        try:
            index = await self._get_index()
            release = pick_release(index, current=self.current,
                                   allow_prerelease=self.cfg.channel == "prerelease")
        except Exception as e:                       # noqa: BLE001 - recorded below
            self.state.last_check = time.time()
            self.state.last_error = str(e)
            self.state.save(self.state_path)
            log.warning("update check failed: %s", e)
            return None
        self.state.last_check = time.time()
        self.state.last_error = ""
        if release is None:
            self.state.latest_version = self.current
            self.state.latest_url = self.state.latest_sha256 = ""
        else:
            self.state.latest_version = release.version
            self.state.latest_url = release.url
            self.state.latest_sha256 = release.sha256
            log.info("DNSGuard %s is available (running %s)", release.version, self.current)
        self.state.save(self.state_path)
        return release

    async def _get_index(self) -> dict:
        if self._fetch_json is not None:
            got = self._fetch_json(self.cfg.index)
            return await got if asyncio.iscoroutine(got) else got
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=self.cfg.timeout)
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        async with (
            aiohttp.ClientSession(timeout=timeout, headers=headers) as session,
            session.get(self.cfg.index) as resp,
        ):
            resp.raise_for_status()
            body = await resp.content.read(MAX_ARTIFACT_BYTES + 1)
            if len(body) > MAX_ARTIFACT_BYTES:
                raise UpdateError("the release index is implausibly large; refusing")
            return json.loads(body)

    # ------------------------------------------------------------ scheduled
    async def tick(self) -> None:
        """The scheduler job: check, and in `auto` mode apply when allowed.

        Deliberately quiet about the ordinary outcomes — an operator should
        hear about an update once, not once per interval.
        """
        release = await self.check()
        if release is None or self.cfg.mode != "auto":
            return
        if not self.install.can_apply:
            log.info("update %s available but not applied: %s",
                     release.version, self._why_not())
            return
        if not self._in_window():
            log.info("update %s available; waiting for the maintenance window %s",
                     release.version, self.cfg.window)
            return
        if self._is_busy():
            log.info("update %s available; deferring, a blocklist build is running",
                     release.version)
            return
        try:
            await self.apply(release)
        except UpdateError as e:
            log.error("automatic update to %s failed: %s", release.version, e)

    # ---------------------------------------------------------------- apply
    async def apply(self, release: Release | None = None, *, version: str | None = None,
                    allow_downgrade: bool = False) -> dict:
        """Stage, verify, smoke-test and install. Returns the new status.

        Raises `UpdateError` with an operator-readable reason rather than
        leaving a half-applied install behind: every step before the live
        install happens in a temporary directory.
        """
        if self._applying.locked():
            raise UpdateError("an update is already being applied")
        async with self._applying:
            return await self._apply_locked(release, version, allow_downgrade)

    async def _apply_locked(self, release: Release | None, version: str | None,
                            allow_downgrade: bool) -> dict:
        if self.cfg.mode == "off":
            raise UpdateError("updates.mode is off")
        if not self.install.can_apply:
            raise UpdateError(self._why_not() or "this installation cannot update itself")
        if self._is_busy():
            raise UpdateError("a blocklist build is running; try again when it finishes")

        if release is None:
            index = await self._get_index()
            release = pick_release(index, current=self.current, want=version,
                                   allow_prerelease=self.cfg.channel == "prerelease"
                                   or version is not None)
            if release is None:
                raise UpdateError(f"no installable release found for {version or 'a newer version'}")
        if not allow_downgrade and not is_newer(release.version, self.current):
            raise UpdateError(f"{release.version} is not newer than {self.current}")

        self.work_dir.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix="stage-", dir=self.work_dir))
        try:
            wheel = await self._download(release, staging)
            await self._smoke_test(wheel, staging)
            await self._install(wheel)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

        self.state.previous_version = self.current
        self.state.applied_version = release.version
        self.state.applied_at = time.time()
        self.state.restart_required = True
        self.state.note("applied", version=release.version, previous=self.current)
        self.state.save(self.state_path)
        if self._audit is not None:
            # App._audit is a coroutine; a test's is not. Both are allowed.
            noted = self._audit("update.apply", release.version,
                                f"{self.current} -> {release.version}")
            if asyncio.iscoroutine(noted):
                await noted
        log.warning("DNSGuard %s installed; the running process is still %s — "
                    "restart to complete the update", release.version, self.current)
        await self._maybe_restart()
        return self.status()

    async def rollback(self) -> dict:
        """Reinstall the version that was running before the last apply."""
        previous = self.state.previous_version
        if not previous:
            raise UpdateError("nothing to roll back to: no update has been applied")
        return await self.apply(version=previous, allow_downgrade=True)

    # ------------------------------------------------------------- internals
    async def _download(self, release: Release, into: Path) -> Path:
        """Fetch the wheel and verify its digest. A mismatch is fatal."""
        target = into / _artifact_name(release.url)
        digest = hashlib.sha256()
        total = 0
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=max(self.cfg.timeout * 10, 60.0))
        headers = {"User-Agent": USER_AGENT}
        async with (
            aiohttp.ClientSession(timeout=timeout, headers=headers) as session,
            session.get(release.url) as resp,
        ):
            resp.raise_for_status()
            with open(target, "wb") as fh:
                async for chunk in resp.content.iter_chunked(65536):
                    total += len(chunk)
                    if total > MAX_ARTIFACT_BYTES:
                        raise UpdateError("the artifact exceeds the size ceiling; refusing")
                    digest.update(chunk)
                    fh.write(chunk)
        got = digest.hexdigest()
        if got != release.sha256:
            raise UpdateError(
                f"artifact digest mismatch for {release.version}: the index says "
                f"{release.sha256}, the download hashed to {got}")
        if release.size and total != release.size:
            raise UpdateError(f"artifact size mismatch: expected {release.size}, got {total}")
        log.info("verified %s (%d bytes, sha256 %s)", target.name, total, got[:16])
        return target

    async def _smoke_test(self, wheel: Path, staging: Path) -> None:
        """Install into a throwaway environment and make it prove it starts.

        `--system-site-packages` so the staging environment borrows the
        dependencies already installed rather than downloading the whole tree
        again; `--no-deps` for the same reason. This is testing the artifact,
        not resolving a dependency graph — the real install does that.
        """
        env = staging / "venv"
        await self._run([sys.executable, "-m", "venv", "--system-site-packages", str(env)],
                        timeout=STAGING_TIMEOUT, what="create the staging environment")
        python = env / ("Scripts" if os.name == "nt" else "bin") / "python"
        await self._run([str(python), "-m", "pip", "install", "--no-input",
                         "--disable-pip-version-check", "--no-deps", str(wheel)],
                        timeout=STAGING_TIMEOUT, what="install into the staging environment")
        out = await self._run([str(python), "-c",
                               "import dnsguard, dnsguard.app, dnsguard.engine.pipeline;"
                               " print(dnsguard.version.__version__)"],
                              timeout=SMOKE_TIMEOUT, what="import the staged build")
        log.info("staged build imports and reports version %s", out.strip())

    async def _install(self, wheel: Path) -> None:
        """Install into the live environment. Runs only after the smoke test."""
        await self._run([self.install.python, "-m", "pip", "install", "--no-input",
                         "--disable-pip-version-check", "--upgrade", str(wheel)],
                        timeout=STAGING_TIMEOUT, what="install into the live environment")

    async def _run(self, argv: list[str], *, timeout: float, what: str) -> str:
        """A subprocess, off the loop, with a timeout and its output captured.

        pip is chatty on success and essential on failure, so stdout and stderr
        are kept and folded into the exception rather than logged into the
        void.
        """
        log.debug("running: %s", " ".join(argv))
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise UpdateError(f"timed out trying to {what} after {timeout:.0f}s") from None
        text = (out or b"").decode("utf-8", "replace")
        if proc.returncode != 0:
            tail = "\n".join(text.strip().splitlines()[-15:])
            raise UpdateError(f"failed to {what} (exit {proc.returncode}):\n{tail}")
        return text

    async def _maybe_restart(self) -> None:
        """Ask the supervisor to restart us, if configured to.

        Never `os.execv` and never a kill: a resolver that restarts itself from
        inside is a resolver whose sockets, forked workers and in-flight
        queries all end up in states nobody modelled. systemd already knows how
        to stop and start this unit; the transient timer below means the
        restart is issued by systemd rather than by a process that is about to
        be killed by it.
        """
        if self.cfg.restart != "systemd":
            return
        unit = self.cfg.unit or "dnsguard"
        if shutil.which("systemd-run"):
            argv = ["systemd-run", "--collect", "--on-active=2",
                    f"--unit=dnsguard-update-restart-{int(time.time())}",
                    "systemctl", "restart", unit]
        elif shutil.which("systemctl"):
            argv = ["systemctl", "restart", unit]
        else:
            log.error("updates.restart is 'systemd' but neither systemd-run nor "
                      "systemctl is on PATH; restart %s yourself", unit)
            return
        try:
            await self._run(argv, timeout=30.0, what=f"schedule a restart of {unit}")
            log.warning("a restart of %s has been scheduled", unit)
        except UpdateError as e:
            # Privilege is the usual cause: DNSGuard sheds root after binding,
            # so it cannot talk to systemd unless the operator arranged it.
            log.error("%s — the update is installed and will take effect on the "
                      "next restart", e)
