"""Update checking and applying.

The dangerous half of this feature is not the download, it is every path that
decides *not* to install: the mode gate, the install-method gate, the busy
gate, the window, and the digest check. Those are what stop a resolver from
rewriting itself at a bad moment or from an artifact that is not the one the
index described, so they are what is tested hardest here.

Nothing in this file touches the network: the index is injected, and the one
test that installs anything builds its own wheel from a throwaway package.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import pathlib
import subprocess
import sys
import venv
from datetime import datetime

import pytest

from trench.config import Config, UpdatesConfig
from trench.ops.update import (
    Install,
    Release,
    UpdateError,
    Updater,
    UpdateState,
    detect_install,
    is_newer,
    is_prerelease,
    parse_version,
    pick_release,
    window_contains,
)

# ───────────────────────────────────────────────────────────────── versions ──


def test_versions_compare_numerically_not_as_strings():
    # The bug this exists to prevent: "2.10.0" < "2.9.0" as text.
    assert is_newer("2.10.0", "2.9.0")
    assert not is_newer("2.9.0", "2.10.0")
    assert is_newer("2.0.1", "2.0.0")
    assert not is_newer("2.0.0", "2.0.0")


def test_prereleases_order_below_the_release_they_precede():
    assert is_newer("2.1.0", "2.1.0rc1")
    assert is_newer("2.1.0rc1", "2.1.0b1")
    assert is_newer("2.1.0b1", "2.1.0a1")
    assert is_newer("2.1.0a1", "2.1.0.dev1")
    assert is_newer("2.1.0.post1", "2.1.0")
    assert not is_newer("2.1.0rc1", "2.1.0")


def test_a_short_version_equals_its_padded_form():
    assert parse_version("2.0") == parse_version("2.0.0") == parse_version("2.0.0.0")


def test_nonsense_is_not_a_version():
    for text in ("", "latest", "two point oh", "2.0.0-fork", None):
        assert parse_version(text) is None
    # And an unparseable version can never be "newer", rather than raising.
    assert not is_newer("latest", "2.0.0")
    assert not is_newer("2.0.0", "latest")


def test_prerelease_detection():
    assert is_prerelease("2.1.0rc1") and is_prerelease("2.1.0.dev3")
    assert not is_prerelease("2.1.0") and not is_prerelease("2.1.0.post1")


# ────────────────────────────────────────────────────────────────── indexes ──
def _index(*versions: str, digest: str = "ab" * 32, yanked: set[str] | None = None) -> dict:
    yanked = yanked or set()
    return {
        "info": {"name": "trench-dns", "version": versions[-1] if versions else ""},
        "releases": {
            v: [{"packagetype": "bdist_wheel",
                 "url": f"https://example.invalid/trench-{v}-py3-none-any.whl",
                 "digests": {"sha256": digest},
                 "size": 1234,
                 "yanked": v in yanked}]
            for v in versions
        },
    }


def test_the_newest_stable_release_wins():
    got = pick_release(_index("2.0.0", "2.1.0", "2.10.0"), current="2.0.0")
    assert got is not None and got.version == "2.10.0"


def test_prereleases_are_skipped_unless_asked_for():
    index = _index("2.0.0", "2.1.0rc1")
    assert pick_release(index, current="2.0.0") is None
    got = pick_release(index, current="2.0.0", allow_prerelease=True)
    assert got is not None and got.version == "2.1.0rc1"


def test_nothing_newer_means_nothing_to_do():
    assert pick_release(_index("2.0.0"), current="2.0.0") is None
    assert pick_release(_index("1.9.0"), current="2.0.0") is None


def test_a_yanked_artifact_is_not_offered():
    """A yank is the publisher saying 'not this one'."""
    index = _index("2.0.0", "2.1.0", yanked={"2.1.0"})
    assert pick_release(index, current="2.0.0") is None


def test_an_exact_version_can_be_pinned_which_is_how_rollback_works():
    got = pick_release(_index("1.9.0", "2.0.0"), current="2.0.0", want="1.9.0")
    assert got is not None and got.version == "1.9.0"


def test_a_release_with_no_wheel_is_not_installable():
    index = _index("2.1.0")
    index["releases"]["2.1.0"][0]["packagetype"] = "sdist"
    assert pick_release(index, current="2.0.0") is None


def test_a_release_with_no_digest_is_not_installable():
    """Without a digest there is nothing to verify the download against, and an
    unverifiable artifact is worse than no update."""
    index = _index("2.1.0")
    index["releases"]["2.1.0"][0]["digests"] = {}
    assert pick_release(index, current="2.0.0") is None


# ─────────────────────────────────────────────────────────────────── window ──
def test_a_window_bounds_when_automatic_updates_may_run():
    assert window_contains("03:00-05:00", datetime(2026, 1, 1, 4, 0))
    assert not window_contains("03:00-05:00", datetime(2026, 1, 1, 6, 0))
    assert not window_contains("03:00-05:00", datetime(2026, 1, 1, 2, 59))


def test_a_window_may_wrap_midnight():
    assert window_contains("23:00-02:00", datetime(2026, 1, 1, 23, 30))
    assert window_contains("23:00-02:00", datetime(2026, 1, 1, 1, 0))
    assert not window_contains("23:00-02:00", datetime(2026, 1, 1, 12, 0))


def test_an_empty_window_means_any_time():
    assert window_contains("", datetime(2026, 1, 1, 12, 0))


def test_a_malformed_window_is_refused_rather_than_guessed():
    for text in ("3-5", "03:00", "25:00-26:00", "03:00-05:61"):
        with pytest.raises(ValueError):
            window_contains(text)


# ──────────────────────────────────────────────────────────────── detection ──
def test_a_container_install_refuses_to_rewrite_itself(monkeypatch):
    monkeypatch.setattr("trench.ops.update._in_container", lambda: True)
    install = detect_install()
    assert install.method == "container" and not install.can_apply
    assert "image" in install.reason


def test_a_source_checkout_refuses(monkeypatch, tmp_path):
    monkeypatch.setattr("trench.ops.update._in_container", lambda: False)
    root = tmp_path / "src" / "trench"
    root.mkdir(parents=True)
    (root.parent / "pyproject.toml").write_text("[project]\n")
    install = detect_install(root)
    assert install.method == "source" and not install.can_apply


def test_a_distribution_package_refuses(monkeypatch, tmp_path):
    monkeypatch.setattr("trench.ops.update._in_container", lambda: False)
    root = tmp_path / "usr" / "lib" / "python3" / "dist-packages" / "trench"
    root.mkdir(parents=True)
    install = detect_install(root)
    assert install.method == "system" and not install.can_apply


# ────────────────────────────────────────────────────────────────── updater ──
def _updater(tmp_path, index: dict, *, mode="notify", current="2.0.0",
             busy=False, can_apply=True, **cfg) -> Updater:
    settings = UpdatesConfig(mode=mode, **cfg)
    up = Updater(settings, data_dir=tmp_path, current_version=current,
                 is_busy=lambda: busy, fetch_json=lambda url: index)
    if can_apply:
        up.install = Install("venv", str(tmp_path), sys.executable, True)
    else:
        up.install = Install("container", str(tmp_path), sys.executable, False,
                             "running in a container")
    return up


@pytest.mark.asyncio
async def test_a_check_records_what_it_found_and_persists_it(tmp_path):
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"))
    found = await up.check()
    assert found is not None and found.version == "2.1.0"
    assert up.status()["update_available"] is True

    # And it survives the restart it is most likely to be interrupted by.
    reloaded = UpdateState.load(up.state_path)
    assert reloaded.latest_version == "2.1.0"


@pytest.mark.asyncio
async def test_mode_off_checks_nothing(tmp_path):
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"), mode="off")
    assert await up.check() is None
    assert not up.state_path.exists()


@pytest.mark.asyncio
async def test_a_failing_index_is_recorded_not_raised(tmp_path):
    """The check runs on a timer; an exception out of it would kill the job."""
    def boom(url):
        raise OSError("name resolution failed")

    up = Updater(UpdatesConfig(), data_dir=tmp_path, current_version="2.0.0",
                 fetch_json=boom)
    assert await up.check() is None
    assert "name resolution" in up.status()["last_error"]


@pytest.mark.asyncio
async def test_notify_mode_never_installs(tmp_path, monkeypatch):
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"), mode="notify")
    monkeypatch.setattr(up, "_download", _must_not_run)
    await up.tick()                       # would raise if it tried to install
    assert up.status()["update_available"] is True
    assert up.status()["restart_required"] is False


@pytest.mark.asyncio
async def test_auto_mode_defers_while_a_blocklist_build_is_running(tmp_path, monkeypatch):
    """The one job that already peaks this box's memory must not be joined by
    an install."""
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"), mode="auto", busy=True)
    monkeypatch.setattr(up, "_download", _must_not_run)
    await up.tick()
    assert up.status()["restart_required"] is False


@pytest.mark.asyncio
async def test_auto_mode_waits_for_the_maintenance_window(tmp_path, monkeypatch):
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"), mode="auto",
                  window="03:00-03:01")
    monkeypatch.setattr(up, "_in_window", lambda: False)
    monkeypatch.setattr(up, "_download", _must_not_run)
    await up.tick()
    assert up.status()["restart_required"] is False


@pytest.mark.asyncio
async def test_an_install_it_does_not_own_is_refused(tmp_path):
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"), mode="auto", can_apply=False)
    with pytest.raises(UpdateError, match="container"):
        await up.apply()
    assert up.status()["can_apply"] is False


@pytest.mark.asyncio
async def test_applying_while_busy_is_refused_even_when_asked_directly(tmp_path):
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"), mode="auto", busy=True)
    with pytest.raises(UpdateError, match="blocklist build"):
        await up.apply()


@pytest.mark.asyncio
async def test_a_downgrade_is_refused_unless_it_is_a_rollback(tmp_path):
    up = _updater(tmp_path, _index("1.9.0", "2.0.0"), mode="auto")
    with pytest.raises(UpdateError, match="not newer"):
        await up.apply(version="1.9.0")


@pytest.mark.asyncio
async def test_rollback_needs_something_to_roll_back_to(tmp_path):
    up = _updater(tmp_path, _index("2.0.0"), mode="auto")
    with pytest.raises(UpdateError, match="nothing to roll back"):
        await up.rollback()


async def _must_not_run(*a, **k):
    raise AssertionError("this path must not download or install anything")


# ──────────────────────────────────────────────────────── artifact handling ──
@pytest.mark.asyncio
async def test_a_digest_mismatch_is_fatal(tmp_path, monkeypatch):
    """The whole trust model is 'the index said these bytes'. A download that
    hashes to something else is an attack or a corruption, never a warning."""
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"), mode="auto")
    payload = b"not the wheel the index described"
    _serve(monkeypatch, payload)
    release = Release(version="2.1.0", url="https://example.invalid/sample_pkg-2.1.0-py3-none-any.whl",
                      sha256="00" * 32, size=len(payload))
    with pytest.raises(UpdateError, match="digest mismatch"):
        await up._download(release, tmp_path)


@pytest.mark.asyncio
async def test_a_size_mismatch_is_fatal(tmp_path, monkeypatch):
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"), mode="auto")
    payload = b"short"
    _serve(monkeypatch, payload)
    release = Release(version="2.1.0", url="https://example.invalid/sample_pkg-2.1.0-py3-none-any.whl",
                      sha256=hashlib.sha256(payload).hexdigest(), size=999)
    with pytest.raises(UpdateError, match="size mismatch"):
        await up._download(release, tmp_path)


@pytest.mark.asyncio
async def test_a_matching_digest_is_accepted(tmp_path, monkeypatch):
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"), mode="auto")
    payload = b"the exact bytes the index described"
    _serve(monkeypatch, payload)
    release = Release(version="2.1.0", url="https://example.invalid/sample_pkg-2.1.0-py3-none-any.whl",
                      sha256=hashlib.sha256(payload).hexdigest(), size=len(payload))
    got = await up._download(release, tmp_path)
    assert got.read_bytes() == payload


def _serve(monkeypatch, payload: bytes) -> None:
    """Stand in for aiohttp with something that yields `payload` in chunks."""
    class _Content:
        async def iter_chunked(self, n):
            for i in range(0, len(payload), n or 1):
                yield payload[i:i + (n or 1)]

    class _Resp:
        content = _Content()

        def raise_for_status(self):
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class _Session:
        def __init__(self, *a, **k):
            pass

        def get(self, url):
            return _Resp()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    import aiohttp
    monkeypatch.setattr(aiohttp, "ClientSession", _Session)


def test_the_artifact_name_comes_from_the_index_and_is_checked():
    """pip parses a wheel's *filename* to learn what it is installing, so the
    name has to come from the index — which makes it attacker-influenced input
    used to build a path."""
    from trench.ops.update import _artifact_name

    assert _artifact_name(
        "https://files.pythonhosted.org/x/trench-2.1.0-py3-none-any.whl"
    ) == "trench-2.1.0-py3-none-any.whl"
    # Anything that is not a wheel, or has no name at all, is refused outright.
    for hostile in ("https://x/trench-2.1.0.tar.gz", "https://x/", "https://x/..%2f"):
        with pytest.raises(UpdateError):
            _artifact_name(hostile)
    # Traversal — plain or percent-encoded — collapses to a bare name inside the
    # staging directory rather than escaping it.
    assert _artifact_name("https://x/../../etc/cron.d/evil.whl") == "evil.whl"
    assert _artifact_name("https://x/%2e%2e%2fboot.whl") == "boot.whl"


@pytest.mark.asyncio
async def test_an_index_for_another_project_is_refused(tmp_path):
    """`trench` is a real, unrelated PyPI project (a deep-learning library), so
    one wrong character in `updates.index` points the updater at somebody
    else's code — and every other rail would pass it, because the digest comes
    from that same index and their wheel imports fine."""
    impostor = {"info": {"name": "trench", "summary": "Deep learning library"},
                "releases": {"9.9.9": [{"packagetype": "bdist_wheel",
                                        "url": "https://x/trench-9.9.9-py3-none-any.whl",
                                        "digests": {"sha256": "ab" * 32},
                                        "size": 1}]}}
    up = _updater(tmp_path, impostor, mode="auto")
    assert await up.check() is None                    # recorded, not raised
    assert "not 'trench-dns'" in up.status()["last_error"]
    with pytest.raises(UpdateError, match="refusing to treat it"):
        await up.apply()


@pytest.mark.asyncio
async def test_an_index_that_names_nothing_is_refused(tmp_path):
    up = _updater(tmp_path, {"releases": {}}, mode="auto")
    assert await up.check() is None
    assert "unnamed project" in up.status()["last_error"]


def test_the_distribution_name_is_compared_the_way_packaging_does():
    from trench.ops.update import _check_index

    for spelling in ("trench-dns", "Trench_DNS", "trench.dns", "TRENCH--DNS"):
        assert _check_index({"info": {"name": spelling}, "releases": {}})
    for wrong in ("trench", "trenchdns", "trench-dnssec"):
        with pytest.raises(UpdateError):
            _check_index({"info": {"name": wrong}, "releases": {}})


@pytest.mark.asyncio
async def test_a_staged_build_reporting_the_wrong_version_is_refused(tmp_path, monkeypatch):
    """Importing is the weak half of the smoke test: another project's wheel
    imports perfectly well. Reporting our version is the half it cannot fake."""
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"), mode="auto")
    payload = b"wheel"
    _serve(monkeypatch, payload)
    release = Release(version="2.1.0", sha256=hashlib.sha256(payload).hexdigest(),
                      url="https://x/trench_dns-2.1.0-py3-none-any.whl", size=len(payload))

    async def _run(argv, *, timeout, what):
        return "1.0.0\n" if "-c" in argv else ""

    monkeypatch.setattr(up, "_run", _run)
    with pytest.raises(UpdateError, match="reports version '1.0.0'"):
        await up.apply(release)
    assert up.status()["restart_required"] is False


# ───────────────────────────────────────────────────────────── the real thing ──
@pytest.mark.asyncio
async def test_apply_installs_a_real_wheel_and_records_the_move(tmp_path, monkeypatch):
    """End to end against a genuine wheel, a genuine venv and a real pip.

    Everything except the network is real: the artifact is built here, served
    to the updater from disk, verified by digest, installed into a throwaway
    staging environment, smoke-tested, and then installed into a second
    environment standing in for the live one.
    """
    wheel = _build_wheel(tmp_path / "build")
    payload = wheel.read_bytes()
    _serve(monkeypatch, payload)

    live = tmp_path / "live"
    venv.EnvBuilder(with_pip=True, symlinks=True).create(live)
    live_python = live / ("Scripts" if sys.platform == "win32" else "bin") / "python"

    up = _updater(tmp_path / "data", _index("2.0.0"), mode="auto")
    up.install = Install("venv", str(live), str(live_python), True)
    release = Release(version="2.1.0", url="https://example.invalid/sample_pkg-2.1.0-py3-none-any.whl",
                      sha256=hashlib.sha256(payload).hexdigest(), size=len(payload))
    # The smoke test imports trench, which this fake package is not; run it
    # against the module the wheel actually ships.
    monkeypatch.setattr(up, "_smoke_test", _smoke_the_sample.__get__(up, Updater))

    status = await up.apply(release)

    assert status["applied_version"] == "2.1.0"
    assert status["previous_version"] == "2.0.0"
    assert status["restart_required"] is True
    installed = subprocess.run(
        [str(live_python), "-c", "import sample_pkg; print(sample_pkg.__version__)"],
        capture_output=True, text=True, timeout=120)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    assert installed.stdout.strip() == "2.1.0"
    # And the fact that a restart is owed survives the restart itself.
    assert UpdateState.load(up.state_path).restart_required is True


async def _smoke_the_sample(self, wheel, staging, release) -> None:
    """The stock smoke test, pointed at the sample package's name."""
    env = staging / "venv"
    await self._run([sys.executable, "-m", "venv", "--system-site-packages", str(env)],
                    timeout=600, what="create the staging environment")
    python = env / ("Scripts" if sys.platform == "win32" else "bin") / "python"
    await self._run([str(python), "-m", "pip", "install", "--no-input",
                     "--disable-pip-version-check", "--no-deps", str(wheel)],
                    timeout=600, what="install into the staging environment")
    out = await self._run([str(python), "-c",
                           "import sample_pkg; print(sample_pkg.__version__)"],
                          timeout=120, what="import the staged build")
    assert out.strip().splitlines()[-1].strip() == release.version


def _build_wheel(where: pathlib.Path) -> pathlib.Path:
    """A minimal, real wheel — no network, no dependencies."""
    pytest.importorskip("build", reason="the `build` package is needed to make a wheel")
    src = where / "src"
    (src / "sample_pkg").mkdir(parents=True)
    (src / "sample_pkg" / "__init__.py").write_text('__version__ = "2.1.0"\n')
    (src / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools>=68"]\n'
        'build-backend = "setuptools.build_meta"\n\n'
        '[project]\nname = "sample-pkg"\nversion = "2.1.0"\n')
    out = subprocess.run([sys.executable, "-m", "build", "--wheel", "--no-isolation",
                          "--outdir", str(where / "dist"), str(src)],
                         capture_output=True, text=True, timeout=600)
    if out.returncode != 0:
        pytest.skip(f"could not build a test wheel: {out.stdout[-400:]}{out.stderr[-400:]}")
    wheels = sorted((where / "dist").glob("*.whl"))
    assert wheels, "the build produced no wheel"
    return wheels[0]


# ─────────────────────────────────────────────────────────────── integration ──
@pytest.mark.asyncio
async def test_the_app_arms_and_disarms_the_check_from_the_config(tmp_path):
    """`updates.mode: off` must take effect without a restart — that is exactly
    the moment an operator is turning it off."""
    from trench.app import App

    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "web": {"enabled": False},
                                 "updates": {"mode": "notify",
                                             "check_interval_hours": 24}})
    app = App(cfg)
    await app._adopt_updates()
    assert app.updater is not None
    assert "update-check" in app.scheduler._tasks

    app.config.updates.mode = "off"
    await app._adopt_updates()
    assert app.updater is None
    assert "update-check" not in app.scheduler._tasks
    app.scheduler.stop()


@pytest.mark.asyncio
async def test_the_updater_refuses_to_run_on_a_sibling_worker(tmp_path):
    """Four workers checking the same index on the same timer is waste; four of
    them installing into the same virtual environment is corruption."""
    from trench.app import App

    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "web": {"enabled": False},
                                 "updates": {"mode": "auto"}})
    app = App(cfg, primary=False, worker_idx=1, nworkers=4)
    await app._adopt_updates()
    assert app.updater is None


@pytest.mark.asyncio
async def test_the_scheduled_tick_survives_a_failing_updater(tmp_path):
    """A job that raises is a job that stops running."""
    from trench.app import App

    cfg = Config.model_validate({"data_dir": str(tmp_path),
                                 "server": {"do53": {"enabled": False}},
                                 "web": {"enabled": False}})
    app = App(cfg)

    class Boom:
        async def tick(self):
            raise RuntimeError("the index caught fire")

    app.updater = Boom()
    await app._update_tick()          # must not raise


def test_the_state_file_is_written_atomically(tmp_path):
    """A half-written state file reads as no state, which loses the fact that a
    restart is owed."""
    state = UpdateState(latest_version="2.1.0", restart_required=True)
    path = tmp_path / "updates.json"
    state.save(path)
    assert json.loads(path.read_text())["restart_required"] is True
    assert not (tmp_path / "updates.tmp").exists()
    assert UpdateState.load(path).latest_version == "2.1.0"


def test_unknown_keys_in_a_state_file_do_not_stop_the_daemon(tmp_path):
    """An older or newer Trench wrote it; it is a cache, not a contract."""
    path = tmp_path / "updates.json"
    path.write_text(json.dumps({"latest_version": "2.2.0", "from_the_future": 1}))
    assert UpdateState.load(path).latest_version == "2.2.0"


def test_a_corrupt_state_file_is_survivable(tmp_path):
    path = tmp_path / "updates.json"
    path.write_text("{not json")
    assert UpdateState.load(path).latest_version == ""


@pytest.mark.asyncio
async def test_two_applies_at_once_are_refused(tmp_path):
    """pip installing into the same environment twice concurrently is how a
    half-installed package happens."""
    up = _updater(tmp_path, _index("2.0.0", "2.1.0"), mode="auto")
    started = asyncio.Event()

    async def slow(*a, **k):
        started.set()
        await asyncio.sleep(0.2)
        raise UpdateError("stopping here; the lock is what is under test")

    up._download = slow
    first = asyncio.ensure_future(up.apply())
    await started.wait()
    with pytest.raises(UpdateError, match="already being applied"):
        await up.apply()
    with pytest.raises(UpdateError):
        await first


# ────────────────────────────────────────────────────────────────────── API ──
@pytest.mark.asyncio
async def test_the_api_exposes_status_and_refuses_an_unsafe_install(tmp_path):
    """The endpoints as a caller meets them: unauthenticated is refused,
    a viewer may read, and applying is refused with a reason rather than a
    stack trace when the installation cannot update itself."""
    import aiohttp

    from trench.api import APIServer
    from trench.app import App

    cfg = Config.model_validate({
        "data_dir": str(tmp_path),
        "server": {"do53": {"enabled": False}},
        "web": {"enabled": True, "admin_password": "secret123"},
        "updates": {"mode": "notify", "check_interval_hours": 0},
    })
    app = App(cfg)
    await app.setup_storage()
    await app._adopt_updates()
    assert app.updater is not None
    app.updater._fetch_json = lambda url: _index("2.0.0", "2.99.0")
    app.updater.install = Install("container", "/", sys.executable, False,
                                  "running in a container")

    import socket as _socket
    probe = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    app.api = APIServer(app, "127.0.0.1", port)
    await app.api.start()
    base = f"http://127.0.0.1:{port}"
    jar = aiohttp.CookieJar(unsafe=True)
    try:
        async with aiohttp.ClientSession(cookie_jar=jar) as s:
            async with s.get(f"{base}/api/v1/update") as r:
                assert r.status == 401, "update status must not be public"
            async with s.post(f"{base}/api/v1/auth/login",
                              json={"name": "admin", "password": "secret123"}) as r:
                assert r.status == 200

            async with s.get(f"{base}/api/v1/update") as r:
                assert r.status == 200
                body = await r.json()
            assert body["current_version"] and body["can_apply"] is False
            assert "container" in body["why_not"]

            async with s.post(f"{base}/api/v1/update/check") as r:
                assert r.status == 200
                body = await r.json()
            assert body["latest_version"] == "2.99.0"
            assert body["update_available"] is True

            # Admin, and still refused — the refusal is the feature.
            async with s.post(f"{base}/api/v1/update/apply", json={}) as r:
                assert r.status == 409
                body = await r.json()
            assert "container" in body["error"]
    finally:
        await app.api.stop()
        await app.stop()
