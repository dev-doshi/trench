## What this changes

<!-- One paragraph. Link the issue it closes. -->

## Why

<!-- The behaviour that was wrong, or the capability that was missing. -->

## Checklist

- [ ] `ruff check trench/ tests/ scripts/ deploy/` passes
- [ ] `python3 scripts/mypy_gate.py` reports no new type errors
- [ ] `pytest -q` passes
- [ ] Tests cover the change (a fix has a test that fails without it)
- [ ] Protocol changes cite the RFC and section in a code comment
- [ ] `CHANGELOG.md` updated if this changes configuration, defaults, or
      on-the-wire behaviour

## Risk

<!--
Does this touch the wire parser, DNSSEC validation, TSIG, the API's auth, or
the fast path? If so, say what an incorrect version of this change would let
an attacker do.
-->
