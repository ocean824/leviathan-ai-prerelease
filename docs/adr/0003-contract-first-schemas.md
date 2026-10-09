# ADR-0003: Contract-first — hardened Layer-1 schemas before any feature

**Date**: 2026-07-05 · **Status**: Accepted

## Context
The spec's schema appendix defines 7 reference models but with `str`
timestamps, `float` prices, and bare string literals. That is not quant-grade:
float money drifts, naive timestamps lie, and stringly-typed labels rot.

## Decision
Implement the 7 canonical contracts in Phase 0 with upgrades:
- tz-aware `datetime` (UTC) — never string timestamps
- `Decimal` for all prices/sizes — never float money
- `StrEnum` for every label (states, permissions, outcomes, modes)
- `frozen=True` + `extra="forbid"` on every contract
- `ExecutionIntent.risk_session_id` — intents carry the frozen snapshot that
  authorized them, making "risk before execution" structural, not procedural
- `sentiment_modifier` bounded ±0.25 — sentiment tilts, never overrides
- Blocked trades journal without prices; executed trades require them
  (model validator)

Cross-layer rules live in `contracts.py` as pure guard functions raising
`ContractViolationError`, shared by every execution path.

## Consequences
- Wire format changed slightly from the spec examples (Decimal-as-string in
  JSON, `max_daily_drawdown_pct` rename, added `risk_session_id`). The replay
  fixture is the canonical example.
- Every later phase codes against a stable, tested vocabulary.
