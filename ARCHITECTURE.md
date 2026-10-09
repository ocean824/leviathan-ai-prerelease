# LEVIATHAN AI — Architecture

Phase 0 architectural ground truth. ADRs in [docs/adr/](docs/adr/) record the
reasoning; this file records the shape.

## Sources of truth

1. **Spec repo**: [ocean824/LEVIATHAN-AI-BLACKWEALTHCAPITAL](https://github.com/ocean824/LEVIATHAN-AI-BLACKWEALTHCAPITAL)
   — vision, 12+ domains, Hermes Pantheon (14 agents), risk lock, module map.
   Cloned locally at `../_reference-github/`. Digest: [docs/notes/github-architecture-digest.md](docs/notes/github-architecture-digest.md)
2. **CodeSpring PRDs**: 40+ feature PRDs (backend/database/frontend each).
   Digests: [docs/notes/prd-digest-1-features-a-m.md](docs/notes/prd-digest-1-features-a-m.md),
   [docs/notes/prd-digest-2-features-m-z.md](docs/notes/prd-digest-2-features-m-z.md)

Where the two disagree, the spec repo's *architecture* wins and the PRDs' *feature
detail* wins.

## Layering

```
┌───────────────────────────────────────────────────────────┐
│ apps/terminal   Vite+React operator console (PROTEUS)     │
├───────────────────────────────────────────────────────────┤
│ apps/api        FastAPI gateway: ingress webhooks, REST,  │
│                 ØMEGA protocol transport                  │
├───────────────────────────────────────────────────────────┤
│ packages/leviathan-core   PURE DOMAIN. No I/O frameworks. │
│                                                           │
│   ingress → state → truth → decision → RISK → execution   │
│                                          │        │       │
│              knowledge → research        └─> journal      │
│                            (RBI gauntlet)                 │
├───────────────────────────────────────────────────────────┤
│ infra/          TimescaleDB (journals, time-series),      │
│                 Redis (live state), risk lock YAML        │
└───────────────────────────────────────────────────────────┘
```

## Hard boundaries (all enforced by tests)

| Boundary | Enforcement |
|---|---|
| Core imports no I/O frameworks | `test_import_boundaries.py` |
| `risk/` imports nothing it governs (execution, decision, ingress) | `test_import_boundaries.py` |
| Contracts are frozen (immutable value objects) | pydantic `frozen=True` + test |
| Unknown fields rejected | pydantic `extra="forbid"` |
| Risk lock integrity | SHA-256 guardian, `test_risk_lock.py` |
| Pipeline law (5 rules) | `contracts.py` + `test_schema_contracts.py` |

## Canonical Layer-1 contracts

`StrategyGenome → CandidateSetup → TruthValidationResult → DecisionPacket →
RiskSnapshot → ExecutionIntent → TradeJournalRecord`

Upgrades over the spec's reference models (see ADR-0003): tz-aware `datetime`
instead of strings, `Decimal` for prices/sizes, `StrEnum` for every label,
`risk_session_id` on ExecutionIntent so intents are cryptographically tied to
the frozen snapshot that authorized them, and blocked-trade journaling encoded
in the model validator.

## Handoff standard (module map, spec repo)

> A single replay fixture can enter through ingress, be classified by state,
> validated by truth, approved or blocked by decision and risk, simulated by
> paper execution, and recorded by the journal layer.

`tests/fixtures/replay_nq_breakout.json` is that fixture. Phase 0 proves the
contract layer end-to-end; Phases 2–5 make each hop real.

## Deferred decisions (revisit when the phase arrives)

- **Message bus**: in-process asyncio first; NATS/Redis Streams when multi-service.
- **Vector store**: provider-agnostic interface in `knowledge/`; pick Qdrant vs
  Pinecone at Phase 1.
- **Migrations**: Alembic lands with the first real table (Phase 1).
- **Desktop packaging**: Tauri preferred over Electron; decide at Phase 7.
- **Model router**: per-agent LLM policies (Claude/DeepSeek/Gemini/Ollama) at Phase 4.
