# PRD Conflicts & Architect Rulings

**Date**: 2026-07-05 · **Status**: Binding until superseded by a new ADR

The PRD digests (prd-digest-1, prd-digest-2) surfaced duplicate and conflicting
specifications. These rulings resolve them so no implementation phase has to
re-litigate. Each ruling becomes an ADR if/when its phase begins.

## 1. Market data pipeline — genuine duplicate, must merge (Phase 2 blocker)

`market-data-ingestion-pipeline` vs `market-data-pipeline-ingestion` describe
the same system with conflicting specs (p99 ≤50ms vs ≤15ms; ns vs ms
timestamps; news feeds in one, WAL/backpressure in the other).

**Ruling**: One domain: `leviathan_core.ingress` + a future
`packages/leviathan-connectors`. Union of features (news feeds AND
WAL/backpressure). Timestamps: nanosecond capture precision at the connector
edge (stored as int64), millisecond precision at the contract layer. Latency
SLO: start at ≤50ms p99; ≤15ms is an optimization target once the paper spine
is proven, not a day-1 constraint.

## 2. Archived vs active PRDs — active always wins

| Archived (ignore for build) | Canonical successor |
|---|---|
| knowledge-ingestion | knowledge-ingestion-obsidian-sync (TRITON) |
| research-backtesting-lab | research-rbi-lab (NAUTILUS) |
| signal-session-state-detection | signal-detection (SIREN) |
| truth-validation-order-flow-options | truth-validation (SCYLLA) |

Archived PRDs are consulted only for migration crosswalks, never for scope.

## 3. Kill-switch 4-way conflict — single sovereign arbiter

Risk Safeguards, Risk Limits & Compliance, Security Compliance Hardening, and
MCP Co-Agent Control each independently define kill-switch mechanisms.

**Ruling**: There is exactly ONE kill-switch authority: the sovereign risk
domain (`leviathan_core.risk`, TIAMAT). All other systems are *requesters*
(may petition for a halt) and *subscribers* (must obey halt state). No other
module may own halt state. This is the same principle as ADR-0004 applied to
runtime control: risk is sovereign, everything else petitions.

## 4. risk-limits-compliance + risk-safeguards — unify

Both active, overlapping (exposure caps, staleness blocks, audit trails).

**Ruling**: One layered risk domain: `risk/lock.py` (immutable limits) →
`risk/veto_engine.py` (pre-trade veto matrix) → future `risk/safeguards.py`
(runtime monitors: staleness, quota, freshness). Single audit stream,
append-only.

## 5. mcp-co-agent-control vs mega-ai-integration — layered, shared schema

Both define agent sessions, tool scopes, dual-approval, audit chains.

**Ruling**: MCP co-agent control is the *internal* control plane; ØMEGA
integration is a *bilateral protocol* built on top of it. Shared entity types
(AgentSession, ToolScope, ApprovalChain) are defined ONCE in
`leviathan_core.integration` schemas; both features import them. Divergence is
a contract violation, not a style choice.

## 6. Cross-cutting patterns adopted as workspace conventions

From the digests' executive summaries, these are now conventions:
- **Idempotency-Key** header on every mutating API endpoint.
- **Append-only audit** — no UPDATE/DELETE on audit tables, enforced in
  migrations.
- **RBAC** everywhere; scopes defined alongside routes.
- **Event topics** are versioned contracts (`leviathan.<domain>.<event>.v1`).
- **Desktop-first UI** — the terminal is the product surface; web-admin is
  secondary.
