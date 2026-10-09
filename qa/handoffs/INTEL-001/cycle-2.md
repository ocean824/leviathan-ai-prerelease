# INTEL-001 cycle 2 — deterministic evidence reference ordering

Status: bounded cycle-2 delta frozen. This delta addresses the cycle-2 review finding that evidence references tied on `(source, record_digest)` could retain caller order and change the trace hash.

## Change

- `IntelExplanationTraceV1` canonicalizes both `evidence_refs` and `normalized_event_refs` using the full canonical JSON serialization used by `trace_sha256`.
- `build_trace` applies the same total ordering before construction.
- A repeated `(source, record_digest)` with conflicting serialized metadata is rejected with content-free `CONFLICTING_TRACE_REF`; exact duplicate references remain deterministic.
- The existing duplicate-factor rejection and factor outcome ordering remain unchanged.
- Added order-reversal regressions for both evidence-reference arrays. Each tied-key pair with differing metadata is rejected with the same error regardless of input order.

## Frozen files

| Path | Cycle-1 SHA-256 | Cycle-2 SHA-256 |
|---|---|---|
| `packages/leviathan-core/src/leviathan_core/intel/trace.py` | `508cddcae734ed4ab206360fb846e8fece78882648b6ee2bc68e9793fcd0067e` | `f470345add3412dc1cc81e5d788f7e7b66203419ddbf5d9648775c0121766047` |
| `packages/leviathan-core/tests/intel/test_factor_contract.py` | `6bd49a8d9516d2ad6e5e28d48e4b0122ec85b67be819354db567154271db3852` | `267592f92b98233ffc8ea36ee5d4f13cfcd388221a60ee7b4de02e8e2df37d07` |
| `qa/acceptance/intel_001/test_intel_001_acceptance.py` | independent acceptance update was pending | `8714f69fca1681e9b8a9f23cc2d61a6bc38d0446812f4c7679750d1c24427d40` |

The acceptance file was updated by its owner to assert the newly required order-independent hash, without implementation edits by this worker. Its final hash was verified before the passing gate run.

## Verification

- `uv run --locked pytest packages/leviathan-core/tests/intel/test_factor_contract.py qa/acceptance/intel_001/test_intel_001_acceptance.py -q`: **14 passed**.
- `uv run --locked mypy`: **clean**, 433 source files.
- `uv run --locked ruff check . --extend-exclude qa/integration-backups`: **clean**.
- Scoped Ruff on the two changed implementation/test files: **clean**.
- The entire `packages/leviathan-core/tests` suite was started, but stopped at approximately 10% after over a minute; no full-core-suite result is claimed. The focused worker and independent acceptance suites above completed successfully.

## Provenance

Cycle-1 ledger: `qa/handoffs/INTEL-001/cycle-1.md` (SHA-256 `39b6c87f652b3916850492384c7dadd3dd6806c3513dff6a9d501c02661f304b`). The canonical-start manifest remains `qa/handoffs/INTEL-001/canonical-start-manifest.json`; it was reconstructed in cycle 1 from the untouched copied baseline and explicitly was not a contemporaneous copy-time capture. No dependencies or lockfiles changed in this delta.
