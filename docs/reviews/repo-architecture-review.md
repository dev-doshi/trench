# Repository & Architecture Review

*Scope: repository layout, module boundaries, packaging, CI/CD, and contributor
documentation, as of `177320e` (version 2.0.0, nothing tagged yet).*

Overall the repository is in good shape. It has a strict, readable layering
with no import cycles between packages, a supply-chain-aware release pipeline,
a ratcheted type gate, and documentation that explains *why* as well as *what*.
Most of the findings below are drift: things that were true when written and
have since gone stale, or tooling that was added but never wired in.

Findings are tagged **[High]** (wrong behaviour or a trap for users or
maintainers), **[Medium]** (friction or a latent risk) or **[Low]** (polish).

---

## Architecture & Modularity

### What works

- **No import-time cycles between packages.** A static pass over every
  module-level `import` in `trench/` finds no strongly connected components at
  package level. The layering is:

  ```
  errors, log, version                       (leaves)
  wire                                       -> errors only
  filter, cache, clients, plugins, learn,
  discovery, security                        -> wire, log, errors
  transport                                  -> wire, security
  resolver                                   -> transport, wire
  store                                      -> security (hashutil)
  engine                                     -> cache, filter, resolver, stats, store, config
  auth_zone                                  -> resolver, wire
  api, ops, gravity, cli                     -> the above
  app                                        -> composition root, imports everything
  ```

  `wire` depending only on `errors` matters most here: the one package that
  parses hostile bytes can be fuzzed and reviewed on its own.
- **Back-edges are confined to type-checking imports.** `transport/*` refers to
  `engine.Pipeline` only under `TYPE_CHECKING`. `config` imports `filter` and
  `transport` lazily, inside validators.
- **`app.py` is a real composition root.** Optional subsystems (`api`,
  `auth_zone`, `dhcp`, `web`, `plugins`, `ops`, `learn`) are imported lazily,
  so a disabled feature costs nothing at startup and cannot break it.

### Findings

1. **[Medium] `app.py` (1,433 lines) and `api/server.py` (1,317 lines) are the
   two places where change concentrates.** `app.py` both builds and runs every
   subsystem, and `api/server.py` holds every route. Neither has a cycle
   problem, but they are the files most likely to cause merge conflicts and
   the hardest to review. Suggested seams:
   - `app.py`: move each subsystem's construction into a `build_<x>(cfg)`
     function next to the subsystem (for example `auth_zone/service.py` and
     `dhcp/service.py`), leaving `App` to handle lifecycle ordering only.
     `tests/test_app_builders.py` already tests builders this way.
   - `api/server.py`: split routes by resource into modules registered on the
     `aiohttp` app (`api/routes/querylog.py`, `rules.py`, `clients.py`, and so
     on), each exposing a `register(app, deps)` function.
2. **[Low] `engine` depends on `store`.** `engine/pipeline.py` and
   `engine/fastpath.py` import `QueryRecord`/`record_from_ctx` from
   `store.querylog` at module level, so the hot path imports the storage
   package, and its `security` dependency, even when the query log is off. The
   imports are the record type, not SQLite handles, so the coupling is mild.
   Moving `QueryRecord` into `engine/` (or a neutral `trench/records.py`)
   behind a small `QuerySink` protocol that `store.querylog` implements would
   give `engine` the same isolation `wire` has, and the worker/multicore path
   (`test_worker_querylog.py`) an obvious substitution point.
3. **[Low] `store` depends on `security`** only for
   `security.hashutil.hash_identifier`. It is a pure hashing helper, so a
   neutral module (`trench/hashing.py`, or keeping it in `security` but with
   no reverse dependency) would stop the storage layer from depending on the
   TLS/ACME/privilege-drop package.
4. **[Low] Top-level modules are uneven.** `config.py`, `discovery.py`,
   `errors.py`, `log.py` and `version.py` live at the package root next to
   24 subpackages. `discovery.py` (DDR/DNR) is a feature, not infrastructure,
   and belongs in `engine/` or its own subpackage.
5. **[Low] `trench/web/` and `trench/data/` have no `__init__.py`.** The wheel
   currently contains `trench/web/blockpage.py` (verified by building one), but
   only because of how setuptools collects it next to the `web/dist/**`
   package-data. Adding an empty `trench/web/__init__.py` makes the import
   `from .web.blockpage import BlockPageServer` (in `app.py`) independent of
   that. The CI `package` job checks for the console's `index.html` but not
   that `trench.web.blockpage` imports.
6. **[Low] `scripts/uidev.py` imports private names** (`_COLUMNS`, `_INSERT`)
   from `trench.store.querylog`. A rename there breaks the dev harness without
   failing any test. Expose a small public `bulk_insert()` helper, or add a
   smoke test that imports the script.

### Test layout vs. module layout

`tests/` is flat: 131 `test_*.py` files for 23 subpackages, named by topic
(`test_dnssec_attacks.py`, `test_zone_transactions_wire.py`) rather than by
module path. Topic names read well, but mapping a module to its tests means
grep, not navigation, and several subsystems are spread over 5–9 files
(`test_zone_*`, `test_dnssec*`, `test_upstream*`, `test_recursive*`).

**Recommendation [Low]:** mirror the package layout one level deep
(`tests/wire/`, `tests/resolver/dnssec/`, `tests/auth_zone/`, …) and keep the
topic file names inside each. `pytest` needs no configuration change, and
`CODEOWNERS` could then give `tests/wire/` the same owner as `trench/wire/`.
The move is mechanical and is best done in one PR, while no feature branches
are open.

---

## Packaging & Dependency Management

### What works

- The distribution name `trench-dns`, the import package, both entry points
  (`trench`, `trenchd`), and `ops/update.py`'s `DIST_NAME`/`DEFAULT_INDEX`
  all agree.
- The version is single-sourced from `trench/version.py`, and the release
  workflow checks the tag, `CHANGELOG.md`, `Dockerfile` and
  `docker-compose.yml` against it.
- Runtime dependencies are few (7), all maintained, and free of conflicts.
  `uvloop` is correctly platform-gated. The docs extra caps MkDocs `<2`, with
  the reason in a comment.
- The CI `package` job builds the wheel, installs it into a clean venv, and
  checks that package data survives.

### Findings

1. **[High] `uv.lock` is committed but nothing uses it.** No workflow,
   Dockerfile or document mentions `uv`. CI installs with
   `pip install -e ".[dev]"`, the image with `pip install .`, and Dependabot
   watches the `pip` ecosystem, which does not update `uv.lock`. The result:
   - the lockfile (564 KB) will drift from what CI actually tests;
   - release images resolve dependencies at build time, so rebuilding the same
     tag can give a different image;
   - contributors may assume the lock is authoritative when it is not.

   **Pick one:** adopt it (`uv sync --locked --extra dev` in CI; install the
   image from `uv export --frozen --no-dev` output as a constraints file;
   switch Dependabot to `package-ecosystem: uv`; document `uv` in
   CONTRIBUTING), **or** delete it and add `uv.lock` to `.gitignore`. Adopting
   it is recommended, because it also fixes finding 2.
2. **[High] Gate tools are unpinned** (`ruff>=0.5`, `mypy>=1.8`). A new mypy
   release that rewords a message changes the finding signatures in
   `mypy-baseline.txt`, so `mypy_gate.py` reports "new" errors and CI turns
   red without any code change. A ruff release that adds checks to a selected
   rule family does the same. Pin both exactly (`ruff==X.Y.Z`,
   `mypy==X.Y.Z`) and let Dependabot bump them in a PR that also refreshes the
   baseline, or get the pins from the lockfile per finding 1.
3. **[Medium] Supported Python versions trail the ecosystem.**
   `requires-python = ">=3.11"`, but the classifiers, CI matrix and README
   badge stop at 3.12. Python 3.13 has been stable for two years and 3.14 for
   one, and `uv.lock` already carries a `>= 3.15` resolution marker. Add 3.13
   and 3.14 to the matrix and classifiers. Consider moving the Docker base
   from `python:3.12-slim-bookworm` to a `trixie` image, since Debian 13 is now
   stable.
4. **[Medium] Classifiers claim more than CI verifies.**
   `Development Status :: 5 - Production/Stable` goes on a project with no
   published release, and `Operating System :: MacOS :: MacOS X` has no macOS
   job. Either add a `macos-latest` row to the test matrix (cheap, and it
   exercises the `uvloop` and `SO_REUSEPORT` paths) or drop the classifier.
5. **[Low] The Dockerfile uninstalls the wrong distribution name.** The stub
   layer runs `pip uninstall -y trench`, but the distribution is `trench-dns`.
   pip prints "Skipping trench as it is not installed" and continues, leaving
   the `trench-dns 0.0.0` stub installed until the next layer overwrites it.
   This is harmless today, but it is exactly the class of stub-leak the
   comment above it describes. Change it to `pip uninstall -y trench-dns`.
6. **[Low] `pytest-cov`/`coverage` are dev dependencies that nothing runs.**
   Either add `--cov=trench --cov-report=xml` to CI (and optionally
   `fail_under` in `[tool.coverage.report]`, ratcheted like mypy) or drop them.

---

## CI/CD & Automation Gaps

### What works

- **`ci.yml`** covers ruff, the mypy ratchet, pytest on 3.11/3.12, issue-form
  consistency, a rebuild-and-diff of the committed console (`trench/web/dist`),
  a same-runner benchmark against the PR base, a multi-arch Docker build, and
  a wheel install smoke test.
- **`release.yml`** is tag-driven, uses PyPI trusted publishing (no API
  token), pins the publish action by digest, publishes multi-arch images to
  GHCR with build-provenance attestations, and builds release notes from the
  changelog. Manual runs default to dry run.
- **`security.yml`** runs CodeQL (`security-extended`), `pip-audit --strict`
  on the resolved tree, and a seeded, time-budgeted wire fuzzer on every PR
  and weekly.
- Governance automation (labels as code, form-to-label triage with the issue
  body passed through the environment rather than interpolated, a narrowly
  scoped stale bot) is careful and well commented.

### Findings

1. **[High] A manual non-dry-run release builds the branch, not the tag.**
   Every job in `release.yml` uses `actions/checkout@v4` with no `ref:`. On
   `workflow_dispatch`, `GITHUB_REF` is the branch the run was started from,
   so `verify` compares `inputs.tag` against the branch's `version.py`, and
   `pypi`, `ghcr` and `github_release` build whatever is at the branch head.
   Also on dispatch:
   - `docker/metadata-action`'s `type=semver` rules produce no tags, because
     the ref is not a tag, so the image is pushed as `latest` only;
   - `softprops/action-gh-release` has no `tag_name`, so it tries to release
     `refs/heads/<branch>`.

   **Fix:** add `ref: ${{ inputs.tag || github.ref }}` to every checkout. Pass
   `tag_name: v${{ needs.verify.outputs.version }}` to the release action.
   Give the metadata action
   `type=semver,pattern=...,value=v${{ needs.verify.outputs.version }}` so the
   tags come from the verified version instead of the ref.
2. **[High] GitHub Release assets are not the files uploaded to PyPI.**
   `github_release` runs `python3 -m build` again instead of reusing the
   `pypi` job's output. Without `SOURCE_DATE_EPOCH` the sdist/wheel differ
   byte-for-byte (timestamps), so a user checking a release asset's hash
   against PyPI's will not get a match. Build once in a dedicated job, upload
   with `actions/upload-artifact`, and have `pypi` and `github_release` both
   download that artifact. `actions/attest-build-provenance` can then attest
   the Python artifacts too, not only the image.
3. **[Medium] `latest` moves on every tag.** `type=raw,value=latest` is
   unconditional, so a pre-release (`v2.1.0-rc1`) or a backport (`v2.0.3`
   after `v2.1.0`) would repoint `latest`. Use
   `type=raw,value=latest,enable=${{ !contains(needs.verify.outputs.version, '-') }}`
   (or the metadata action's `flavor: latest=auto`, which skips
   pre-releases), and keep backports on their own line.
4. **[Medium] Action pinning is inconsistent with the project's own policy.**
   `release.yml` explains that the PyPI action is pinned by digest because it
   runs with `id-token: write`. The `ghcr` job has the same permission plus
   `packages: write`, yet `docker/login-action`, `setup-buildx-action`,
   `metadata-action`, `build-push-action` and `attest-build-provenance` are
   pinned only by major tag. The same goes for `softprops/action-gh-release`
   (`contents: write`). Pin every action in a job that holds write or OIDC
   permissions by SHA. Dependabot already keeps SHA pins current, so the
   comment in `dependabot.yml` ("Workflows pin actions by major tag") should
   change with it.
5. **[Medium] The CI Docker build never runs the image.** The `docker` job
   builds amd64 and arm64 under QEMU on every PR, which is slow, but never
   starts a container. The Dockerfile's own comments describe a stub-leak bug
   that "dies on `from ..version import USER_AGENT`", which a build alone
   would not catch. Add `load: true` for the native platform, then run
   `docker run --rm trench:ci trenchd --version` and a short
   start + `trench-healthcheck` probe. Consider building arm64 only on `main`
   and in releases to shorten PR feedback.
6. **[Medium] The release `test` job is thinner than CI.** It runs Python 3.12
   only, with no frontend dist check and no wheel smoke test, so a tag cut
   from a commit whose CI never ran (or ran red) can still publish. Either
   call `ci.yml` as a reusable workflow (`workflow_call`) from `release.yml`,
   or require the `CI` check to have passed on the tagged SHA.
7. **[Low] `inputs.tag` is interpolated directly into shell** in `verify`
   (`TAG="${{ inputs.tag }}"`). Only people with write access can dispatch,
   so the risk is low, but the triage workflow already shows the right
   pattern: pass it through `env:`.
8. **[Low] Missing automation worth adding:**
   - a `pre-commit` config (ruff + ruff-format + the mypy gate) so the three
     PR-template checks run before push;
   - `ruff format --check` if the project wants a formatter (currently lint
     only);
   - a scheduled full-length fuzz run (for example 30 minutes weekly) in
     addition to the 120 s per-PR pass, with the corpus cached between runs;
   - a docs link check against the published site after deploy
     (`test_doc_links.py` covers repository links only).

---

## Documentation & Contributor Workflows

### What works

- README, CONTRIBUTING, SECURITY, SUPPORT and the issue forms route each kind
  of report to one place, and they agree with each other on that routing.
- The README's "Status" box and `docs/installation.md` say plainly that
  `pip install trench-dns` and `docker pull` do not work yet. That candour
  prevents a whole class of bug reports.
- `trench.example.yaml` is safe by default (loopback DNS on `:5354`,
  loopback console, encrypted transports off until a certificate is supplied,
  `admin_password: null` printing a one-time password) and explains each
  production value next to the timid one.
- The `data/default_blocklist.txt` quickstart path resolves against the
  installed package (`gravity/manager.py`), and `tests/test_gravity_fetch.py`
  locks that in.

### Findings

1. **[High] `docs/upgrading.md` tells users to
   `pip install --upgrade trench`.** On PyPI `trench` belongs to an unrelated
   project, which `docs/installation.md` warns "is worse than failing". It
   must be `pip install --upgrade trench-dns`. In the same file,
   `docker compose pull` does nothing for the repository's
   `docker-compose.yml`, which builds `trench:latest` locally. Until an image
   is published, the step is `git pull && docker compose up -d --build`.
2. **[Medium] CONTRIBUTING says "around 800 tests"; there are 2,565.**
   (`pytest --collect-only -q`). Either drop the number or state it without
   precision ("a few thousand").
3. **[Medium] The mypy backlog is described in the wrong place.** CONTRIBUTING
   and the `mypy_gate.py` docstring both say the backlog is mostly "the DNSSEC
   and wire layers pass rdata around as `object`". The baseline disagrees: 30
   of its 64 findings are in `auth_zone/` (mostly `SOA | None` and `Rdata`
   narrowing in `xfr.py`/`update.py`), 10 in `resolver/`, and only 1 in
   `wire/`. Updating the text points contributors at the work that is
   actually easy to pick off (`Optional` narrowing in `auth_zone`).
4. **[Medium] `mypy_gate.py --update` can grow the baseline.** Both the
   docstring and the baseline header say the file "may only ever shrink", but
   `--update` rewrites it with whatever mypy currently reports, new findings
   included. Make `--update` refuse when `found - base` is non-empty (with a
   `--force` escape hatch for mypy upgrades), so the ratchet is enforced by
   code rather than by review.
5. **[Medium] The changelog has an `[Unreleased]` section above `[2.0.0]`,
   but `version.py` still says `2.0.0` and no tag exists.** If `v2.0.0` is cut
   now, `release.yml` publishes the `[2.0.0]` notes, and everything under
   `[Unreleased]` ships without being mentioned. The footer link
   `v2.0.0...HEAD` also points at a tag that does not exist. Before the first
   tag, either fold `[Unreleased]` into `[2.0.0]` (and update its date) or
   bump to `2.1.0`.
6. **[Low] The README's "Development" tree is out of date.** It omits
   `analyze/`, `cli/`, `learn/`, `onboarding/` and `stats/`. It describes
   `ops/` as only "Prometheus metrics, Pi-hole/AdGuard import" (it also holds
   the updater, notary, explain and what-if) and `security/` as "TLS, scrypt
   hashing, TOTP" (it also holds ACME and privilege drop). It says `api/`
   serves the console, and lists the ruff command without `deploy/`, unlike
   CONTRIBUTING, CI and the PR template. A layout list that tests cannot check
   will drift again; consider generating it from each subpackage's
   `__init__.py` docstring, or checking in `test_doc_links.py` that every
   subpackage is mentioned.
7. **[Low] Dev scripts are undocumented as a set.** `scripts/` holds nine
   tools. CONTRIBUTING mentions `fuzz_wire`, `diff_dnspython`, `bench` and
   `mypy_gate`, and the README mentions `uidev`. `loadgen.py`,
   `check_templates.py`, `sync_labels.py` and `triage_labels.py` are
   discoverable only by reading CI. A short `scripts/README.md` (one line per
   script: purpose, and whether it is for contributors or CI only) would fix
   this.
8. **[Low] `trench/web/frontend/` has its own `CONTRIBUTING.md` and
   `DESIGN.md`** that the root CONTRIBUTING does not link to. Add a line under
   "Getting set up" pointing console contributors there.
9. **[Low] SECURITY.md says to email "the address listed in the repository
   profile"** as the fallback. Name the address, or drop the fallback, since
   private advisories are always available on public repositories.

---

## Suggested order of work

| # | Item | Effort |
|---|------|--------|
| 1 | Fix `docs/upgrading.md` distribution name and Compose step | minutes |
| 2 | Release workflow: checkout `ref`, `tag_name`, semver `value`, gated `latest` | small |
| 3 | Build once, reuse artifacts for PyPI and the GitHub Release | small |
| 4 | Resolve `[Unreleased]` vs `2.0.0` before the first tag | small |
| 5 | Pin ruff/mypy; decide adopt-or-delete for `uv.lock` | small–medium |
| 6 | SHA-pin actions in privileged jobs; smoke-run the CI image | small |
| 7 | Python 3.13/3.14 in the matrix; macOS row or drop the classifier | small |
| 8 | Enforce the mypy ratchet in `--update`; correct the backlog description | small |
| 9 | README tree, test count, `scripts/README.md`, Dockerfile uninstall name | small |
| 10 | Split `app.py` builders and `api/server.py` routes; decouple `engine` from `store` | medium |
| 11 | Mirror `trench/` layout in `tests/` | medium, mechanical |
