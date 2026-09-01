"""Shared blocklist table.

Two properties matter and neither is visible from a normal unit test of `get()`:
the table must be *exact* (a false positive is a website that will not load),
and it must be genuinely shared with fork children (that is the entire reason it
exists instead of a dict).
"""
from __future__ import annotations

import os
import pickle
import random
import string

import pytest

from trench.filter.shared import SharedBlockTable


def rand_domains(n: int, seed: int = 1) -> list[str]:
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        labels = ["".join(rng.choices(string.ascii_lowercase, k=rng.randint(3, 12)))
                  for _ in range(rng.randint(2, 4))]
        out.append(".".join(labels) + ".com")
    return out


def test_roundtrip_every_key():
    doms = rand_domains(20_000)
    t = SharedBlockTable.build([(d, "src") for d in doms])
    assert len(t) == len(set(doms))
    assert all(t.get(d) == "src" for d in doms)


def test_no_false_positives():
    """The reason this stores full domain text instead of fingerprints."""
    t = SharedBlockTable.build([(d, "src") for d in rand_domains(20_000, seed=1)])
    present = set(rand_domains(20_000, seed=1))
    absent = [d for d in rand_domains(20_000, seed=2) if d not in present]
    assert len(absent) > 19_000
    assert not any(t.get(d) is not None for d in absent)


def test_empty_table():
    t = SharedBlockTable.build([])
    assert len(t) == 0 and t.get("anything.example") is None
    assert t.nbytes < 64 * 1024, "an empty table should cost approximately nothing"
    assert SharedBlockTable().get("anything.example") is None  # never built at all


def test_first_source_wins():
    t = SharedBlockTable.build([("dup.example", "first"), ("dup.example", "second")])
    assert t.get("dup.example") == "first"
    assert len(t) == 1 and t.source_counts == {"first": 1}


def test_probe_chain_survives_removal():
    """Colliding keys share a probe chain; a removal must not strand the keys
    behind it, which is why discard() uses an overlay instead of clearing slots."""
    doms = rand_domains(5_000)
    t = SharedBlockTable.build([(d, "src") for d in doms])
    for d in doms[:100]:
        t.discard(d)
    assert all(t.get(d) is None for d in doms[:100])
    assert all(t.get(d) == "src" for d in doms[100:])
    assert len(t) == len(doms) - 100


def test_oversized_domain_is_skipped_not_corrupting():
    """A name longer than the packed length field must be dropped cleanly — the
    caller keeps it as a Rule — rather than silently truncated into a wrong key."""
    long_name = ("a" * 60 + ".") * 5 + "example"
    assert len(long_name) > 255
    t = SharedBlockTable.build([(long_name, "src"), ("ok.example", "src")])
    assert t.get(long_name) is None
    assert t.get("ok.example") == "src"


def test_memory_is_a_fraction_of_the_dict_it_replaces():
    doms = rand_domains(50_000)
    t = SharedBlockTable.build([(d, "src") for d in doms])
    per_domain = t.nbytes / len(t)
    # A dict[str, str] of the same content measures ~350 B/domain resident.
    assert per_domain < 60, f"{per_domain:.0f} B/domain is too close to the dict"


def test_source_counts_track_contribution():
    items = [(d, "a") for d in rand_domains(300, seed=3)]
    items += [(d, "b") for d in rand_domains(200, seed=4)]
    t = SharedBlockTable.build(items)
    assert t.source_counts == {"a": 300, "b": 200}


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
def test_fork_children_read_the_same_table():
    """The point of the exercise: a forked worker must resolve against the
    parent's table without rebuilding or copying it."""
    doms = rand_domains(5_000)
    t = SharedBlockTable.build([(d, "src") for d in doms])
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        try:
            os.close(r)
            hits = sum(1 for d in doms if t.get(d) == "src")
            misses = sum(1 for d in rand_domains(1000, seed=9) if t.get(d) is not None)
            with os.fdopen(w, "wb") as f:
                pickle.dump((hits, misses, len(t)), f)
        finally:
            os._exit(0)
    os.close(w)
    with os.fdopen(r, "rb") as f:
        hits, misses, n = pickle.load(f)
    os.waitpid(pid, 0)
    assert hits == len(doms), "child could not see the parent's table"
    assert misses == 0
    assert n == len(t)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
def test_child_removals_do_not_leak_into_the_parent():
    """Shared pages are read-only by construction; an operator edit applied in
    one worker must not silently unblock a domain in the others."""
    t = SharedBlockTable.build([("ads.example", "src")])
    pid = os.fork()
    if pid == 0:
        try:
            t.discard("ads.example")
        finally:
            os._exit(0)
    os.waitpid(pid, 0)
    assert t.get("ads.example") == "src"


@pytest.mark.asyncio
async def test_app_reuses_the_prefork_engine(tmp_path):
    """A worker handed a pre-built engine must not re-fetch the lists — that
    duplicated download-and-parse is most of a small board's startup time."""
    from trench.app import App
    from trench.config import Config
    from trench.filter import FilterEngine, compile_rules

    listfile = tmp_path / "list.txt"
    listfile.write_text("||ads.example^\n")
    cfg = Config.model_validate({
        "data_dir": str(tmp_path),
        "filtering": {"sources": [str(listfile)]},
        "server": {"do53": {"enabled": False}},
    })
    prebuilt = FilterEngine.compile(compile_rules("||sentinel.example^", "prefork"))
    app = App(cfg, prebuilt_filter=prebuilt)
    await app.load_blocklists()
    assert app.filter is prebuilt
    assert app.pipeline.filter is prebuilt
    assert "sentinel.example" in prebuilt.block_table   # the list file was not read
    assert app._gravity is not None, "a later refresh must still work"


# --- file-backed: persistence, handover, corruption ---
def test_table_survives_the_process_that_built_it(tmp_path):
    """The reason crc32 is used instead of the faster built-in hash(): a table
    written by one process must still be readable by an unrelated one."""
    path = tmp_path / "gravity.table"
    doms = rand_domains(5_000)
    SharedBlockTable.build([(d, "hagezi") for d in doms], path)

    import subprocess
    import sys
    import textwrap
    script = textwrap.dedent(f"""
        from trench.filter.shared import SharedBlockTable
        t = SharedBlockTable.open({str(path)!r})
        print(len(t), t.get({doms[0]!r}), t.get("definitely-absent.example"))
    """)
    out = subprocess.run([sys.executable, "-c", script], capture_output=True,
                         text=True, check=True).stdout.split()
    assert out == ["5000", "hagezi", "None"]


def test_rebuild_is_atomic_and_noticed(tmp_path):
    path = tmp_path / "gravity.table"
    old = SharedBlockTable.build([("a.example", "v1")], path)
    assert not old.stale()

    SharedBlockTable.build([("a.example", "v2"), ("b.example", "v2")], path)
    assert old.stale(), "a reader must be able to tell the file was replaced"
    # the old mapping keeps serving correctly until it is replaced
    assert old.get("a.example") == "v1" and old.get("b.example") is None

    new = SharedBlockTable.open(path)
    assert new.get("a.example") == "v2" and new.get("b.example") == "v2"
    assert not new.stale()


def test_no_partial_table_is_ever_visible(tmp_path):
    """Rebuild writes to a temp name and renames, so a reader opening the path
    at any moment gets a complete table — never a half-written one."""
    path = tmp_path / "gravity.table"
    SharedBlockTable.build([("a.example", "v1")], path)
    for _ in range(20):
        SharedBlockTable.build([(d, "v2") for d in rand_domains(2_000)], path)
        t = SharedBlockTable.open(path)
        assert len(t) == 2_000
    assert not list(tmp_path.glob("*.tmp.*")), "temp files must not be left behind"


def test_corrupt_table_is_rejected_not_misread(tmp_path):
    from trench.filter.shared import TableFormatError
    path = tmp_path / "gravity.table"
    SharedBlockTable.build([(d, "src") for d in rand_domains(1000)], path)

    truncated = tmp_path / "short.table"
    truncated.write_bytes(path.read_bytes()[:200])
    with pytest.raises(TableFormatError):
        SharedBlockTable.open(truncated)

    garbage = tmp_path / "garbage.table"
    garbage.write_bytes(b"not a table at all" * 100)
    with pytest.raises(TableFormatError):
        SharedBlockTable.open(garbage)

    tiny = tmp_path / "tiny.table"
    tiny.write_bytes(b"DGBT")
    with pytest.raises(TableFormatError):
        SharedBlockTable.open(tiny)


def test_source_counts_survive_a_round_trip(tmp_path):
    path = tmp_path / "gravity.table"
    items = [(d, "a") for d in rand_domains(300, seed=3)]
    items += [(d, "b") for d in rand_domains(200, seed=4)]
    SharedBlockTable.build(items, path)
    assert SharedBlockTable.open(path).source_counts == {"a": 300, "b": 200}


# --- App integration: instant start, refresh handover ---
def _cfg(tmp_path, listfile, **over):
    from trench.config import Config
    base = {"data_dir": str(tmp_path), "server": {"do53": {"enabled": False}},
            "filtering": {"sources": [str(listfile)]}}
    base.update(over)
    return Config.model_validate(base)


@pytest.mark.asyncio
async def test_startup_serves_from_the_cached_table_without_reparsing(tmp_path):
    """Restarting a resolver must not mean a minute of unanswered queries while
    600k domains are re-read."""
    from trench.app import App
    listfile = tmp_path / "list.txt"
    listfile.write_text("||ads.example^\n")

    app = App(_cfg(tmp_path, listfile))
    await app.load_blocklists()
    assert app.table_path.exists()
    assert app.filter.match("ads.example").action.name == "BLOCK"

    # Second start with the source removed: if it were re-read, nothing would
    # block. Serving from the cached table is the whole point.
    listfile.unlink()
    again = App(_cfg(tmp_path, listfile))
    await again.load_blocklists()
    assert again.filter.match("ads.example").action.name == "BLOCK"
    assert again.filter.match("unrelated.example").action.name == "NONE"


@pytest.mark.asyncio
async def test_worker_adopts_a_rebuild_from_another_worker(tmp_path):
    """One worker compiles, the rest map the result — one download and one
    compiled copy per machine instead of N of each."""
    from trench.app import App
    listfile = tmp_path / "list.txt"
    listfile.write_text("||first.example^\n")

    follower = App(_cfg(tmp_path, listfile), primary=False, worker_idx=1, nworkers=2)
    await follower.load_blocklists()
    assert follower.filter.match("first.example").action.name == "BLOCK"
    assert not follower.adopt_refreshed_table(), "nothing has changed yet"

    # the primary rebuilds from an updated list
    listfile.write_text("||second.example^\n")
    primary = App(_cfg(tmp_path, listfile), primary=True, worker_idx=0, nworkers=2)
    await primary.load_blocklists()
    await primary.refresh_blocklists()

    assert follower.adopt_refreshed_table()
    assert follower.filter.match("second.example").action.name == "BLOCK"
    assert follower.filter.match("first.example").action.name == "NONE"


@pytest.mark.asyncio
async def test_follower_never_compiles_its_own_copy(tmp_path):
    """A follower calling refresh must not fetch and compile — that is the
    duplicated work this design exists to remove."""
    from trench.app import App
    listfile = tmp_path / "list.txt"
    listfile.write_text("||ads.example^\n")
    follower = App(_cfg(tmp_path, listfile), primary=False, worker_idx=1, nworkers=2)
    await follower.load_blocklists()

    called = []
    async def fail():
        called.append(1)
        raise AssertionError("a follower must not compile blocklists")
    follower._gravity.build = fail
    await follower.refresh_blocklists()
    assert not called


@pytest.mark.asyncio
async def test_operator_rules_still_apply_after_adopting_a_table(tmp_path):
    """Adopting a table replaces the imported domains only; a locally allowed
    domain must not come back blocked."""
    from trench.app import App
    listfile = tmp_path / "list.txt"
    listfile.write_text("||ads.example^\n||keepme.example^\n")
    cfg = _cfg(tmp_path, listfile,
               filtering={"sources": [str(listfile)], "allow": ["keepme.example"]})
    app = App(cfg, primary=False, worker_idx=1, nworkers=2)
    await app.load_blocklists()
    assert app.filter.match("keepme.example").action.name == "ALLOW"

    listfile.write_text("||ads.example^\n||keepme.example^\n||more.example^\n")
    primary = App(cfg, primary=True, worker_idx=0, nworkers=2)
    await primary.load_blocklists()
    await primary.refresh_blocklists()
    assert app.adopt_refreshed_table()
    assert app.filter.match("keepme.example").action.name == "ALLOW"
    assert app.filter.match("more.example").action.name == "BLOCK"
