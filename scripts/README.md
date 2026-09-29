# scripts/

Developer and maintainer tooling. None of it ships in the wheel or the image.
Each script's docstring has the details; this is the index.

| Script | What it is for | Run by |
|---|---|---|
| `mypy_gate.py` | Fails on type errors that are not in `mypy-baseline.txt`. `--update` re-records the baseline after you fix some; it refuses to grow it unless you add `--allow-growth` (for a mypy upgrade). | CI, pre-commit |
| `check_templates.py` | Issue forms parse, their labels exist in `.github/labels.yml`, and every area option maps to a label. | CI |
| `bench.py` | Hot-path microbenchmarks. `--json` snapshots, `--compare` fails on a regression beyond `--threshold`. | CI (PRs, base vs head on one runner) |
| `fuzz_wire.py` | Mutation fuzzer for the wire codec. `BUDGET` is seconds, `SEED` makes a run reproducible. | Security workflow (PRs, main, weekly) |
| `diff_dnspython.py` | Re-encodes every rdata type and compares it byte for byte with dnspython. | By hand |
| `loadgen.py` | UDP load generator reporting latency percentiles; `--self-test` starts a server in-process. | By hand |
| `uidev.py` | Runs the API and console against a simulated household, so every view has data. See `trench/web/frontend/CONTRIBUTING.md`. | By hand |
| `sync_labels.py` | Makes the repository's labels match `.github/labels.yml`. | Labels workflow |
| `triage_labels.py` | Maps a filled-in issue form to area labels. | Triage workflow |

`fuzz_wire.py` and `diff_dnspython.py` need dnspython, which the dev extra
installs.
