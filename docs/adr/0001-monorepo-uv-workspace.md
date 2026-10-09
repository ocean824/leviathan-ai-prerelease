# ADR-0001: uv-workspace monorepo with core/apps split

**Date**: 2026-07-05 · **Status**: Accepted

## Context
The spec repo's module map proposes a single `src/oracle/` tree. The PRDs imply
a web app + API + desktop terminal + Python quant services. We need one repo
that keeps domain logic testable in isolation from delivery mechanisms.

## Decision
uv workspace monorepo: `packages/leviathan-core` (pure domain, pydantic only)
and `apps/api` (FastAPI) as workspace members; `apps/terminal` (Vite/React/TS)
managed by npm independently. Toolchain: Python 3.11, uv, ruff, mypy `strict`,
pytest; Node 22+, tsc strict.

## Consequences
- Core logic is importable by backtester, API, and future workers without
  dragging in FastAPI or DB drivers (enforced by `test_import_boundaries.py`).
- One `uv sync --all-packages` bootstraps the Python side; CI mirrors it.
- Future members slot in cleanly: `packages/leviathan-backtest`,
  `apps/worker`, `packages/leviathan-connectors`.
