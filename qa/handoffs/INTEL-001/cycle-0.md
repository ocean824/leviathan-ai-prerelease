# INTEL-001 Data Contract and Trace — Cycle 0

Status: implementation frozen for independent acceptance and review.

## Scope

Implemented the `FactorScoreV1`/typed abstention contract, a sealed point-in-time context, deterministic explanation trace, and two reference adapters over existing SIG-001 and FLOW-001 kernel outputs. No fusion, calibration, portfolio decision, doctrine parsing, provider access, or network calls were added. Factor scores are normalized evidence values, not calibrated trade probabilities.

## Canonical copy and generated delta

- Canonical source at copy: `C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\LEVIATHAN AI\repo`.
- Worktree: `C:\Users\XYRASYSTEMS\.traycer\worktrees\local__repo__72e9e418f8\feature-intel001-contract-trace`.
- Both inventories exclude `.git`, `.venv`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `__pycache__`, `node_modules`, `target`, and `.scratch`.
- Census: canonical 1,681 files; worktree 1,686 files; 1,681 shared files byte-identical; directory diff found exactly five additions, with zero changed or deleted files.
- The census/diff above was generated before writing this handoff. The handoff itself is a separate deliverable under `qa/handoffs/INTEL-001/` and is not one of the five implementation/test additions.
- Canonical shared-file snapshot fingerprint: `0a3c404e4bf1f023f8c6a10a0ff3268da6182bca84fe9c62657ea52c38d3e239` (SHA-256 over sorted `relative_path\nfile_sha256` pairs for the 1,681 identical files).
- No dependency or lockfile changes.

| Directory-diff path | Canonical start | Frozen SHA-256 |
|---|---|---|
| `packages/leviathan-core/src/leviathan_core/intel/__init__.py` | absent | `64c2870aae1192614802f3c441beed439fc9a4fb16bdba338c719e0a8156fd26` |
| `packages/leviathan-core/src/leviathan_core/intel/adapters.py` | absent | `29486d1b8b8ba49ea216c1d8d0e1ed5842633bee2a1fd8ea9c179303c95cc342` |
| `packages/leviathan-core/src/leviathan_core/intel/models.py` | absent | `234299e624d402adae82f56d5f1bbf4f7d10b62aa7f96d9307de67358ded2aff` |
| `packages/leviathan-core/src/leviathan_core/intel/trace.py` | absent | `9904cd44b08e3df8d78cead738880a152a6c8ac5b7bc47f0d913c26254377d58` |
| `packages/leviathan-core/tests/intel/test_factor_contract.py` | absent | `40ba140f0e6df2e1892631b9983a68a83cfd7b59d2e7a18a0a5aab7ba80ae1be` |

## Contract and provenance decisions

- `FactorScoreV1` uses the closed family and direction enums, exact bounded decimal strings for strength/reliability, instrument/venue, decision as-of and source event times, freshness, method/version, and immutable evidence refs. The abstention branch is the typed `FactorAbstentionV1` with a closed reason enum.
- Look-ahead evidence is a hard validation failure (`FUTURE_EVIDENCE` through the context issuer); stale and missing data abstain. Unknown freshness abstains unless `allow_unknown_freshness=True` is explicitly issued into the context; that policy bit is retained in the factor outcome.
- FEAT-001 results are checked by `require_feature_result`; their existing `observation_hash` and `feat001.feature_result.v1` seal tag are carried through. No FEAT result digest is re-derived.
- MD normalized events feed evidence from their existing `source_payload_sha256`, source/event time, receive time, native record key, sequence, and provider session. No second market-event issuer is introduced.
- SIG-001 `StructureSignalV1` and FLOW-001 `FlowEvaluation` have no existing seal registry. Their typed contexts are issued by this module and bind a canonical digest of the immutable snapshot. Adapter context builders reject substitution with different snapshot content.
- `to_layer_observation()` projects factor values into the existing `LayerObservationV1` fusion contract instead of defining a parallel fusion observation.
- SIG mapping uses existing direction/confidence and rejects tombstone, gap, or stale-quality inputs. FLOW mapping requires an accepted/integrity-valid evaluation, entitled source, and explicit aggression score; otherwise it abstains. Reliability `1` means the existing kernel's binary quality/entitlement gate passed; it is not calibration.
- `IntelExplanationTraceV1` links evidence and normalized-event refs to factor outcomes and explicit optional fusion, calibration, portfolio, and risk refs. It records exclusions and hashes canonical serialized content deterministically via `trace_sha256`.

## Verification

- `uv sync --locked --all-packages`: passed in the copied worktree.
- Worktree import origin: `uv run --locked python -c "import leviathan_core; print(leviathan_core.__file__)"` printed `C:\Users\XYRASYSTEMS\.traycer\worktrees\local__repo__72e9e418f8\feature-intel001-contract-trace\packages\leviathan-core\src\leviathan_core\__init__.py`.
- New tests: `uv run --locked pytest packages/leviathan-core/tests/intel/test_factor_contract.py -q` → 7 passed.
- Final source/test hashes were rechecked after the complete core package rerun; it remained 6,548 passed, 10 skipped, 1 xfailed.
- Full configured Python test trees, run as separate processes to preserve sibling support imports and avoid duplicate module names:
  - `uv run --locked pytest packages/leviathan-core/tests -q` → 6,548 passed, 10 skipped, 1 xfailed.
  - `uv run --locked pytest packages/leviathan-store/tests -q` → 548 passed, 2 skipped.
  - `uv run --locked pytest packages/leviathan-vault/tests -q` → 163 passed, 36 skipped.
  - `uv run --locked pytest packages/leviathan-market-data/tests -q` → 1,128 passed.
  - `uv run --locked pytest apps/api/tests -q` → 1,446 passed, 1 skipped.
  - Aggregate: 9,833 passed, 49 skipped, 1 xfailed.
- A single default root pytest invocation stops at collection because existing package/API tests both define `test_live_activation` and `test_live_activation_acceptance`. `--import-mode=importlib` also cannot collect existing tests that import sibling support modules as top-level names. Running the configured trees independently passed all tests.
- `uv run --locked mypy` → success, 433 source files.
- `uv run --locked ruff check . --extend-exclude qa/integration-backups` → all checks passed. Unfiltered `ruff check .` reports 10 existing findings confined to `qa/integration-backups`; the directory diff confirmed those files are unchanged from canonical.
- `uv run --locked ruff format --check packages/leviathan-core/src/leviathan_core/intel packages/leviathan-core/tests/intel` → 5 files already formatted.

## Remaining scope

Only SIG-001 and FLOW-001 reference adapters are included. All other family adapters, score fusion, probability calibration, explanation-to-portfolio/risk execution, and walk-forward calibration remain subsequent lanes. No trade intent or execution eligibility is implied by these factor values.
