# ADR-0004: Sovereign risk isolation + lock-file guardian from day 0

**Date**: 2026-07-05 · **Status**: Accepted

## Context
Principle 4: risk is sovereign; nothing overrides it. The spec's TIAMAT design
requires the risk limits to live in an immutable YAML whose SHA-256 is verified
before any order routes. If risk code depends on the modules it governs,
sovereignty is a fiction.

## Decision
- `leviathan_core.risk` may not import from `execution`, `decision`, or
  `ingress` — enforced by an AST-walking test, not convention.
- `infra/risk/risk_governance.lock.yaml` is copied verbatim from the spec repo
  and ships with the repo.
- `risk/lock.py` implements the guardian primitives now: `compute_lock_sha256`
  and `verify_risk_lock`, which refuses an empty expected hash ("trade blind")
  and any mismatch. The expected hash is supplied via
  `LEVIATHAN_RISK_LOCK_SHA256`, never read from the file being verified.
- OS-level immutability (`chattr +i` equivalent) is an ops concern documented
  for deployment; the hash check is the code-level backstop.

## Consequences
- Phase 4's veto engine builds on primitives that already exist and are tested.
- Any future PR that makes risk import execution fails CI immediately.
