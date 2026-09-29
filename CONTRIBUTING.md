# Contributing to Trench

## Getting set up

```bash
git clone https://github.com/dev-doshi/trench
cd trench
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Python 3.11 or newer; CI tests 3.11 through 3.14. If you use
[uv](https://docs.astral.sh/uv/), `uv sync --extra dev` installs exactly the
versions in `uv.lock` — the same ones CI and the Docker image use — and
`uv run pytest -q` runs the suite in that environment. Either way works; when
a test passes for you and fails in CI, the lockfile is the first thing to
compare against.

A dependency change goes in `pyproject.toml` *and* `uv.lock`: run `uv lock`
and commit both. CI installs with `--locked` and fails if they disagree.

The admin console is prebuilt into `trench/web/dist`, so no Node toolchain is
needed unless you are changing the console itself. If you are, read
[`trench/web/frontend/CONTRIBUTING.md`](trench/web/frontend/CONTRIBUTING.md)
first:

```bash
cd trench/web/frontend
npm ci
npm run build          # writes ../dist, which is committed
```

The helper scripts under `scripts/` are indexed in
[`scripts/README.md`](scripts/README.md).

## Before you open a pull request

```bash
ruff check trench/ tests/ scripts/ deploy/
python3 scripts/mypy_gate.py
pytest -q
```

`pre-commit install` (after `pip install pre-commit`) runs the first two on
every commit, using `.pre-commit-config.yaml`.

All three gate CI, along with a benchmark that compares your branch against
its merge base on the same runner. A change that costs more than 30% on the
hot path fails; if the cost is deliberate, say so in the PR and the threshold
can be revisited.

## What a good change looks like

- **Tests come with it.** A bug fix needs a test that fails without it. The
  suite is the reason this project can be changed at all — over 2,500 tests
  over the wire parser, the resolver, DNSSEC, the filter engine, the
  transports, the DHCP server and the API.
- **Protocol claims cite the RFC.** If a change alters what goes on the wire,
  name the RFC and section in the code comment, not just the PR.
- **Comments explain why, not what.** The existing code does this; match it.
  A comment that restates the line above it is noise, and one that records the
  attack a check exists to stop is worth several tests.
- **New behaviour is off by default** if it can break resolution for someone
  who upgrades without reading the release notes.

## Security-sensitive areas

Changes to these get read closely, and should keep their existing tests
passing without modification unless the PR explains why the old expectation
was wrong:

- `trench/wire/` — parses hostile input; see `tests/test_wire_hostile.py`
  and `scripts/fuzz_wire.py`.
- `trench/resolver/dnssec/` — a permissive bug here silently voids
  validation for every name.
- `trench/auth_zone/tsig.py`, `update.py`, `xfr_service.py` — transaction
  authentication.
- `trench/api/auth.py` — roles, tokens, TOTP, lockout.
- `trench/engine/fastpath.py` — replays recorded response bytes; anything it
  skips must be something the recorded answer already accounted for.

Never send a vulnerability in as a pull request. See [SECURITY.md](SECURITY.md).

## Fuzzing and differential testing

```bash
BUDGET=60 SEED=1 python3 scripts/fuzz_wire.py   # seconds, not iterations
python3 scripts/diff_dnspython.py          # differential against dnspython
python3 scripts/bench.py --quick
```

## Commits and pull requests

Conventional Commits (`fix:`, `feat:`, `perf:`, `docs:`, `refactor:`,
`test:`, `chore:`). Keep a PR to one concern. Note anything that changes
configuration, defaults, or on-the-wire behaviour — that becomes a
`CHANGELOG.md` entry.

## Code of conduct

Participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Type checking

`mypy trench/` currently reports a backlog of findings, mostly of two shapes:
an optional record (`SOA | None`, `Question | None`) used without narrowing,
concentrated in `auth_zone/`, and a generic `Rdata` read for a field only one
subclass has, in the zone-transfer and DNSSEC code. Typing the second properly
means precise rdata types across the parser and the validator — worth doing,
and not worth rushing in subsystems where a mistake is silent.

Until then the backlog is recorded and ratcheted:

```bash
python3 scripts/mypy_gate.py            # fails on findings not in the baseline
python3 scripts/mypy_gate.py --update   # after you fix some, lock the gain in
```

`mypy-baseline.txt` may only ever shrink: `--update` refuses to add findings.
The one exception is a mypy upgrade, which can report old code differently —
that PR re-records with `--update --allow-growth` and says so. mypy and ruff
are pinned exactly in the dev extra for this reason. CI runs the gate, so a
new type error fails the build even though the old ones do not.
