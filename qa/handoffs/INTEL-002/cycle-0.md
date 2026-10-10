# INTEL-002 — cycle 0 handoff

## Scope and baseline

Implemented offline INTEL adapters for MD-006 book snapshots, FEAT-001, GEX-001, DP-001, REG-001, IND-001 and CFTC COT/FEAT-backed macro, plus the clean-room DEX-001 scenario kernel and adapter. Existing SIG-001 and FLOW-001 reference adapters remain unchanged and are covered by their existing tests.

The copy-time manifest is [`canonical-start-manifest.json`](canonical-start-manifest.json), SHA-256 `8e6628c9bf409177d526e95f662eb8d9798a5c893d410a32c1f4606cc07860d8`, 1,823 files, tree fingerprint `43e69f911e48b02148be86faf702f78345cddca3196aa2bb4d3263abf0902b0e`. After canonical advanced, the worktree was synchronized from the current canonical root. A fresh path/hash comparison found no non-owned file differences; the generated `.wrangler/cache/wrangler-account.json` was excluded as runtime account cache.

No dependencies or lockfiles changed. No provider calls were made.

## DEX decision

DEX uses a separate `DexChainEvidenceV1` and per-series `DexOptionEvidenceV1`; it does not change GEX `OptionSeriesEvidenceV1` or market-data `ChainRowV1`, and it never derives delta. Each DEX input binds the same chain snapshot ID, as-of timestamps and provenance digest as GEX. `DexFactorAdapter` requires exactly one matching GEX horizon and rejects a snapshot/provenance mismatch. Missing delta returns a typed `MISSING_DELTA` abstention. The kernel computes exact `delta × open_interest × multiplier × declared call/put dealer sign`, grouped by expiry; the sign is a scenario assumption, not observed dealer inventory.

## Evidence and adapter mapping

| Adapter | Existing trust/provenance reused | Projection |
|---|---|---|
| MD-006 book | Issued `BookSnapshotReceiptV1`; MD-001 normalized event payload digest, source time, sequence/session | Bid/ask depth imbalance; incoherent, stale, or missing book abstains |
| FEAT-001 / macro features | `require_feature_result`; `evidence_from_feature_result` carries FEAT issuer tag, seal reference, observation hash | Explicit versioned mapping scale; missing feature abstains |
| GEX-001 | Existing `semantic_digest` issuance verification; snapshot/horizon digest and times | Confidence as neutral GEX factor |
| DP-001 | Result content hash verified against `_result_hash`; window digest and timestamps | Buy/sell imbalance; invalid/pending result abstains |
| REG-001 | Recomputed result content digest; evaluation time, inputs hash and revision | Composite regime / 2; non-current or ineligible result abstains |
| IND-001 | `require_indicator_result`; canonical finalized result bytes and availability | Explicit versioned scale; warmup/gap/late/invalid abstains |
| CFTC COT | Existing point-in-time COT result fields, report publication/availability, revision IDs | Contrarian percentile projection; degraded/insufficient result abstains |
| DEX-001 | Sealed DEX estimate plus GEX semantic digest and matching chain snapshot/time | Signed delta-equivalent contracts by expiry; missing delta abstains |
| SIG-001 / FLOW-001 | Existing INTEL-001 as-of context and content-bound signal/native print references | Existing reference adapters; their tests remain green |

Every adapter consumes an issued `AsOfContextV1`; future evidence is a hard validation error, while missing, stale, unknown (unless a versioned factor policy allows it), or kernel-ineligible input abstains. Numeric scaling is explicit and is not calibration.

## New source adapters deferred

| Source | Planned endpoint / auth seam | Factor mapping |
|---|---|---|
| SEC EDGAR | Submissions and filing archives; SEC-compliant User-Agent, no credential material in INTEL | `insider_activity` → `insider` |
| Quiver | Reviewed Quiver API endpoints; vault-resolved credential via its adapter | `insider_activity`, `political_trades` → `insider` |
| Trading Economics | Calendar/series endpoints; vault-resolved API key | `earnings`, `event_risk`, `rates_macro` → `macro` |
| Census | Census data API; optional key through its adapter | `rates_macro` → `macro` |
| USDA | Quick Stats API; vault-resolved key | `rates_macro` → `macro` |
| Copernicus | CDS catalogue/data API; vault-resolved token | Weather/crop supply inputs → `macro` |
| Kalshi / Polymarket / Coinbase public reads | Public market-data APIs/feeds; adapter-owned auth where required | `event_risk` → `prediction_market` or `macro` |
| PUBLIC-DATA-001 | Typed `PublicEvidenceV1`; SEC, FINRA, CFTC, Treasury/NY Fed/BLS/Fed calendar and public prediction-market outputs | Insider→`insider`; dark pool/off-exchange→`dark_pool`; short activity→`volume`; positioning/rates→`macro`; event risk→`macro`/`prediction_market` |
| API-ANYTHING-001 | Typed tier-3 `PublicOperationResultV1`; validated operation registry | Earnings/event risk/sentiment→`macro`; Senate PTR→`insider`; Cboe volatility→`indicator` |

Public and tier-3 records preserve source/native record key, canonical digest, source-observation and publication/knowable timestamps, provider/session/sequence when available, and `redistribution=false`. For `PublicEvidenceV1`, `as_of` maps to `EvidenceRefV1.source_event_ns` and `knowable_at` maps to `as_of_ns`. For scheduled API-ANYTHING events, `event_at` remains target-event metadata; a future scheduled event is usable when it was knowable by the decision cutoff. Future source-observation or knowable timestamps hard-fail. Tier-3 evidence receives lower reliability and abstains on missing knowable time or DEGRADED operation status. Inputs above the context's 128-reference limit raise an explicit selection/schema error; they are never silently truncated.

**Backlog:** derive FOMC meeting-outcome probabilities from Databento 30-day Fed Funds (ZQ) futures as an event-risk/rates factor. CME FedWatch is not used. Keep the probability method versioned, point-in-time and backtestable.

## Gates

- Targeted INTEL/DEX tests: 19 passed (adapter contract, fake FEAT/book/indicator inputs and DEX/GEX lineage).
- Root Ruff: `uv run --locked ruff check . --extend-exclude qa/integration-backups` — passed.
- Root mypy: `uv run --locked mypy` — passed, 441 source files.
- Module origin check: `leviathan_core`, `leviathan_market_data`, `leviathan_store`, `leviathan_vault` and `leviathan_api` all imported from this worktree.
- Full package runs are being recorded below after completion. Combined root collection is not supported by the current test layout: default mode collides on duplicate `test_live_activation` basenames, while `--import-mode=importlib` breaks test-local helper imports. Package-by-package CI commands are used instead.

## Changed-file ledger

Generated from a full canonical/worktree file-hash comparison, excluding generated caches and `.venv`. Canonical-start SHA and frozen SHA are shown; `NEW` means no canonical-start file existed.

| Path | Canonical-start SHA-256 | Frozen SHA-256 |
|---|---|---|
| `packages/leviathan-core/src/leviathan_core/dealer_delta/__init__.py` | NEW | `ffa75de75989e59fb7cc3ab17afc75f729e10c47541e7133f495fa348e9bd9ba` |
| `packages/leviathan-core/src/leviathan_core/dealer_delta/adapter.py` | NEW | `1f4d1aec47340c3a006b5e04230889d1789d12a3f68673601b14061e8ed55ba1` |
| `packages/leviathan-core/src/leviathan_core/dealer_delta/kernel.py` | NEW | `098da8a1da9fde3dab7468d28e32b967167a7d87e1eef8f685459d692c8343e3` |
| `packages/leviathan-core/src/leviathan_core/dealer_delta/models.py` | NEW | `42853e693fea9e8cf2eb01106dca3167477fbbaa912aa7de063bb498983e460e` |
| `packages/leviathan-core/src/leviathan_core/intel/__init__.py` | `0e4766cd0c87c62f4ddf54f9fccd21dd58d5962104db5f63ae06e50437406a4e` | `e54af0294395973e3f85724dbc33b1000d06e5af8943cc6af798ec32ca811643` |
| `packages/leviathan-core/src/leviathan_core/intel/kernel_adapters.py` | NEW | `8e70d351d84256967a79e852d1a715828d318e659bf4c2e424c968c297a47174` |
| `packages/leviathan-core/src/leviathan_core/intel/models.py` | `7606cf5c60733cf88d187eb0f4a9ab3c231472749caf48cb73d546ce0917743d` | `190adc5ddc6b70342a5db4727dc79f19144f22056fd6a7bfd3edd007f8bd56d7` |
| `packages/leviathan-core/src/leviathan_core/intel/trace.py` | `f470345add3412dc1cc81e5d788f7e7b66203419ddbf5d9648775c0121766047` | `5c85f6e3c4a09a3591a6b0f4b6551487bd5fd6ac562963445db30a8fc443ec62` |
| `packages/leviathan-core/tests/dealer_delta/test_dex_kernel.py` | NEW | `64eddfa8d44da4b8eb679fc01a1d87851913656c46bf427d39dde423300eb7ec` |
| `packages/leviathan-core/tests/intel/test_kernel_adapters.py` | NEW | `d0f81fd25445a1a7feb63622b94caedf3222c8c87512881d4aa3d3715a8198b8` |

