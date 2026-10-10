# INTEL-002 — cycle 1b handoff

## Scope

This delta completes the cycle-1 acceptance-coverage request. It retains the DEX effective-time fix from cycle 1, adds direct adapter coverage for DP-001, REG-001, COT and FEAT-backed macro, and explicitly defers tier-3 scheduled-event scoring to INTEL-003. No acceptance-owned file was edited and no provider calls were made.

## Adapter coverage and point-in-time rules

The added fake-snapshot tests assert concrete `FactorScoreV1` output, direction, bounded strength, stale/missing abstention where applicable, evidence digest/issuer lineage, source-event time, availability time and the evidence refs carried into the factor result. Tests also verify that an input availability later than the decision cutoff raises `FUTURE_EVIDENCE` for the multi-input dark-pool, regime and COT projections.

| Adapter | Time/provenance behavior | Cycle-1b test |
|---|---|---|
| DP-001 dark pool | Digest binds result digest/window plus source IDs, source event IDs, aggregate context IDs and adjustment versions. Source event time is the maximum contributing ranked-print event time (window end only when no ranked print exists); availability is the issued result as-of. | `test_dark_pool_adapter_projects_issued_result_with_source_lineage_and_latest_time` |
| REG-001 regime | Digest binds recomputed result digest, inputs hash, revision and all factor provenance fields. Event time is max contributing factor event time; availability is max contributing availability/baseline/feature-availability time. | `test_regime_adapter_uses_maximum_input_times_and_abstains_when_stale` |
| CFTC COT | Digest binds selected vintage source, constituent, revision and published/received/available times as well as the result projection. Effective event and availability times are maxima across selected vintages and result metadata. | `test_cot_adapter_preserves_vintage_provenance_max_times_and_abstains` |
| FEAT-backed macro | Reuses FEAT issuance and evidence conversion; event/availability remain the issued feature result's point-in-time fields. Missing or stale feature abstains. | `test_macro_feature_adapter_preserves_point_in_time_lineage_and_abstains` |

DEX's separate multi-input rule remains: effective source-event time is the maximum of the chain observation and every contributing delta observation; any event, availability, OI or delta input beyond the cutoff is a hard `FUTURE_EVIDENCE` failure. Cycle-1 tests cover NOW chain + NOW+1 delta at NOW+2 cutoff and a post-cutoff delta rejection. Market-book requires event time to equal the issued book receipt update time. FEAT and IND consume a single issued point-in-time result; GEX consumes one issued horizon. No local timestamps replace source time.

## Tier-3 scheduled-event adapter: deferred

There is **no implemented tier-3 scheduled-event latest-evidence adapter in INTEL-002**. The earlier cycle-0 scheduled-event paragraph describes future semantics only and is superseded by this explicit status. It is deferred to INTEL-003 until PUBLIC-DATA-001 and API-ANYTHING-001 evidence schemas and mapping contracts are frozen.

INTEL-003 semantics: preserve scheduled `event_at` as event metadata; use source-observation `as_of` as `EvidenceRefV1.source_event_ns` and `knowable_at` as `EvidenceRefV1.as_of_ns`. An already-announced future event may be used when its `knowable_at` is at or before the decision cutoff. Future source observation or knowable time hard-fails; missing knowable time, stale/unknown freshness without an explicit versioned policy, or a degraded operation abstains. Tier-3 inputs use lower reliability and every source record retains `redistribution=false`. Future scheduled-event scoring and probability factors are not claimed as implemented here.

The ZQ 30-day Fed Funds futures FOMC outcome-probability factor remains a versioned, point-in-time, backtestable backlog item. CME FedWatch is not used.

## Changed-file ledger

Cycle-1b start hashes are the cycle-1 frozen hashes for the four DEX files, and the cycle-0 hashes for the existing adapter module and adapter test. Cycle-0 and cycle-1 ledgers remain unchanged.

| Path | Cycle-1b start SHA-256 | Cycle-1b frozen SHA-256 |
|---|---|---|
| `packages/leviathan-core/src/leviathan_core/dealer_delta/models.py` | `24f88a267635e78da9800701d784382dacba712f701572e016e8c7d5324afd15` | `24f88a267635e78da9800701d784382dacba712f701572e016e8c7d5324afd15` |
| `packages/leviathan-core/src/leviathan_core/dealer_delta/kernel.py` | `2c3a16a0a6ef46476e4415d928262573cced248c65de8c6cf2ae813ac31b686a` | `2c3a16a0a6ef46476e4415d928262573cced248c65de8c6cf2ae813ac31b686a` |
| `packages/leviathan-core/src/leviathan_core/dealer_delta/adapter.py` | `fda1b2aaf138f58535c8ade603c86231279a774e4dbd5946cd9023f885de7085` | `fda1b2aaf138f58535c8ade603c86231279a774e4dbd5946cd9023f885de7085` |
| `packages/leviathan-core/tests/dealer_delta/test_dex_kernel.py` | `6bf05dd168522c7f6fd631ff1c32491f38ef56671a322d4d90af190da3ff2670` | `6bf05dd168522c7f6fd631ff1c32491f38ef56671a322d4d90af190da3ff2670` |
| `packages/leviathan-core/src/leviathan_core/intel/kernel_adapters.py` | `8e70d351d84256967a79e852d1a715828d318e659bf4c2e424c968c297a47174` | `30b67e64d636be0e804d32dff01e7f15952759547c598b2b87192258f9384807` |
| `packages/leviathan-core/tests/intel/test_kernel_adapters.py` | `d0f81fd25445a1a7feb63622b94caedf3222c8c87512881d4aa3d3715a8198b8` | `26132f88e9294fdf6dae9ec728c1bb5d912918b8dfe1d387a22f44c518fc6712` |

No dependencies or lockfiles changed. The independent acceptance file remains unchanged at SHA-256 `6ac341c8b430eef7e0f8a1365c952a0ccb54523590eb9b20068af74d8497ac0b`.

## Gates

- Targeted adapter/DEX/contract tests: **25 passed**.
- Independent acceptance: `uv run --locked pytest -q qa/acceptance/INTEL-002/test_intel002_cold_acceptance.py` — **7 passed**.
- Root mypy: `uv run --locked mypy` — **passed**, 441 source files.
- Root Ruff: `uv run --locked ruff check . --extend-exclude qa/integration-backups` — **passed**.
- Module-origin check: `leviathan_core`, `leviathan_market_data`, `leviathan_store`, `leviathan_vault` and `leviathan_api` all resolve under `feature-intel002-lane1-dex-cycle1`.
- Full configured Python roots were run package-by-package to avoid duplicate-basename collection collisions: core **6,593 passed, 10 skipped, 1 xfailed**; store **548 passed, 2 skipped**; vault **163 passed, 36 skipped**; market-data **1,129 passed**; API **1,475 passed, 1 skipped**. Combined: **9,908 passed, 49 skipped, 1 xfailed**. The independent acceptance test adds **7 passed**. Focused adapter/DEX/contract tests were rerun after the last test edits: **25 passed**.
- A single root `uv run --locked pytest -q` cannot collect because of two duplicate `test_live_activation` module basenames across API and store. `--import-mode=importlib` avoids the basename collision but breaks legacy test-local helper imports (18 collection errors). Package-by-package commands above exercise the full configured suite without editing tests.
