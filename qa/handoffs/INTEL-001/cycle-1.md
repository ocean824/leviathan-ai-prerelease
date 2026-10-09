# INTEL-001 Data Contract and Trace ? Cycle 1

Status: cycle-1 delta frozen. Independent acceptance remains unmodified and passes.

## Rulings applied

- Unknown freshness is now controlled only by `FactorFreshnessPolicyV1`, a typed, versioned per-factor policy, with `allow_unknown_freshness=False` by default. The policy is not an ad-hoc context flag. When explicitly enabled, a score retains `freshness="unknown"` and carries the policy object, its version and `unknown_freshness_allowed=True` so downstream fusion can distinguish and discount it. Both reference adapters attach the enabled policy; default paths abstain.
- Trace construction rejects duplicate `factor_id` values with `DUPLICATE_FACTOR_ID`. It sorts factor outcomes by full canonical JSON serialization, and an order-reversal regression confirms hash stability.
- Added the requested per-file canonical-start manifest. Cycle 0 did not preserve copy-time file hashes; cycle 1 reconstructed the manifest from the untouched copied baseline, verified its tree fingerprint against the recorded cycle-0 fingerprint. The manifest explicitly records this provenance and is not represented as a contemporaneous capture.

## Baseline and generated diff

Baseline fingerprint: `0a3c404e4bf1f023f8c6a10a0ff3268da6182bca84fe9c62657ea52c38d3e239`.
Canonical-start manifest: `qa/handoffs/INTEL-001/canonical-start-manifest.json`, SHA-256 `67a6b0aa02e26e96b9328785b5766e66cce0dd8e1a2a8d89097dcc0721b23aa8`, 1,681 sorted entries.

The actual directory comparison against the manifest reported **9 added paths, 0 modified baseline paths and 0 deleted paths**. Standard cache/build exclusions were `.git`, `.venv`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `node_modules`, `target` and `.scratch`.

| Path | Baseline | Frozen SHA-256 | Owner |
|---|---|---|---|
| `packages/leviathan-core/src/leviathan_core/intel/__init__.py` | absent | `0e4766cd0c87c62f4ddf54f9fccd21dd58d5962104db5f63ae06e50437406a4e` | implementation |
| `packages/leviathan-core/src/leviathan_core/intel/adapters.py` | absent | `b30c8ae088968b37144bfc418b18a078b107e55cabbafce7f7af6be7b78643b5` | implementation |
| `packages/leviathan-core/src/leviathan_core/intel/models.py` | absent | `7606cf5c60733cf88d187eb0f4a9ab3c231472749caf48cb73d546ce0917743d` | implementation |
| `packages/leviathan-core/src/leviathan_core/intel/trace.py` | absent | `508cddcae734ed4ab206360fb846e8fece78882648b6ee2bc68e9793fcd0067e` | implementation |
| `packages/leviathan-core/tests/intel/test_factor_contract.py` | absent | `6bd49a8d9516d2ad6e5e28d48e4b0122ec85b67be819354db567154271db3852` | implementation tests |
| `qa/acceptance/intel_001/test_intel_001_acceptance.py` | absent | `19a20661f57d19de71614fea45816d54fe0235be4e8dd3f691b5db9cd9f30c64` | independent acceptance, e51a5665; unchanged |
| `qa/handoffs/INTEL-001/canonical-start-manifest.json` | absent | `67a6b0aa02e26e96b9328785b5766e66cce0dd8e1a2a8d89097dcc0721b23aa8` | baseline evidence |
| `qa/handoffs/INTEL-001/cycle-0.md` | absent | `c1435aea50e728abb00ef55c786234e84fc0b36baf0add79e9e5589251c653ba` | prior handoff |
| `qa/handoffs/INTEL-001/cycle-1.md` | absent | recorded by the final handoff SHA; excluded from its own hash inventory | this handoff |

No dependencies or lockfiles changed. The independent acceptance file was not edited.

## Gates

All configured Python suites were rerun in this worktree:

| Command | Result |
|---|---|
| `uv run --locked pytest packages/leviathan-core/tests -q` | 6,550 passed, 10 skipped (final code snapshot) |
| `uv run --locked pytest packages/leviathan-store/tests -q` | 548 passed, 2 skipped |
| `uv run --locked pytest packages/leviathan-vault/tests -q` | 163 passed, 36 skipped |
| `uv run --locked pytest packages/leviathan-market-data/tests -q` | 1,128 passed |
| `uv run --locked pytest apps/api/tests -q` | 1,446 passed, 1 skipped |
| `uv run --locked pytest packages/leviathan-core/tests/intel/test_factor_contract.py -q` | 8 passed |
| `uv run --locked pytest qa/acceptance/intel_001/test_intel_001_acceptance.py -q` | 4 passed, unchanged |
| `uv run --locked mypy` | 433 source files, no issues |
| `uv run --locked ruff check . --extend-exclude qa/integration-backups` | all checks passed |
| `uv run --locked ruff format --check packages/leviathan-core/src/leviathan_core/intel packages/leviathan-core/tests/intel` | 5 files already formatted |

Aggregate configured Python total including the independent acceptance: **9,839 passed, 49 skipped**. Suite runs were separate because the repository's combined pytest layout has duplicate top-level test module names and sibling support-module imports. The standard Ruff command excludes unchanged `qa/integration-backups`; the prior unfiltered check reports 10 existing issues only in that excluded backup tree.

The required `__file__` check resolved `leviathan_api`, `leviathan_market_data`, `leviathan_core`, `leviathan_store` and `leviathan_vault` exclusively under `feature-intel001-contract-trace`.

No fusion/calibration, doctrine parsing, portfolio/risk decision or execution eligibility was added.
