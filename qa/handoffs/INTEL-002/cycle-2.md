# INTEL-002 — cycle 2 handoff

## Scope and outcome

Cycle 2 applies the three P2 regressions and the inexpensive P3 corrections from the reviewer’s cycle-1b review. This handoff is cumulative across cycles 0, 1 and 1b, not a delta-only file list. The original copy-time baseline is `canonical-start-manifest.json` (SHA-256 `8e6628c9bf409177d526e95f662eb8d9798a5c893d410a32c1f4606cc07860d8`; 1,823 entries; tree fingerprint `43e69f911e48b02148be86faf702f78345cddca3196aa2bb4d3263abf0902b0e`).

The three P2 fixes are implemented:

- **Dark pool:** the sealed DP-001 result now binds `latest_contributing_event_ns`, computed from every adjusted dark print used in any output component, including prints below `min_notional`. The INTEL adapter uses this value. The regression fixture has a qualifying print at 150 and a sub-threshold contributing sell at 180; the score reports 180.
- **DEX determinism:** DEX series are serialized canonically by `series_id` and expiry before digesting. `series_id` is unique in the input contract, so strike is not an available tie-break field and duplicate IDs are rejected. The regression reverses the series input and asserts identical estimate digest, evidence refs and trace hash.
- **DEX signs:** CALL delta is constrained to [0, 1], PUT to [-1, 0], and `None` remains the missing-delta abstention. Invalid signs are rejected by the sanitized Pydantic validation boundary (`ValidationError`, public message `INVALID_FUSION_INPUT`); they are never inverted.

## P3 disposition

| Finding | Disposition |
|---|---|
| DEX exposure units | Kept the compatible `signed_delta_contracts` field name and documented that the multiplier is already applied and the value is delta-equivalent underlying units. The module docstring says the same. |
| DEX policy and GEX binding | Both DEX dealer-side signs are included in the semantic digest. The DEX evidence reference binds the DEX policy id/version and the matching GEX policy id/version plus the selected GEX horizon's assumption id/version. |
| Row-level DEX/GEX attestation | **Known limit:** chain snapshot, provider, times and provenance are checked at attestation level; each DEX series id/expiry/OI/source-record digest is not joined against an individual GEX chain row in this offline lane. A live feeder must issue and bind the per-row chain evidence before claiming row-level correspondence. |
| COT and regime time fallbacks | Removed `asof_ns` / evaluation-time substitution for missing publication or availability. Legitimate zero timestamps are retained via explicit `is not None` checks. If input times are absent, the adapter issues an empty evidence context and abstains `MISSING_EVIDENCE`. |
| Tautological test expectations | Replaced implementation-derived max assertions with literal fixture values. The DP regression is the explicit 150/180 reproduction. |
| Caller-declared freshness | **Deferred to INTEL-003:** this lane has no shared, versioned max-age policy by factor/source. Inventing thresholds here would create inconsistent freshness semantics; adapters continue to require the issued context and its explicit freshness state. |
| Macro adapter family/source boundary | Added a macro-family constructor check and restricts found FEAT data to `FRED`, `BEA` or `EIA` source-dataset prefixes. |
| Unrelated trace formatting | Restored `intel/trace.py` byte-for-byte to the canonical-start version, reducing merge churn. |

The tier-3 scheduled-event adapter remains deferred to INTEL-003 as recorded in cycle 1b. The ZQ/FOMC factor remains backlog-only.

## Cumulative source and test ledger

Hashes are generated from the canonical-start manifest and current worktree file bytes. `NEW` means the path did not exist in the canonical-start manifest. `UNCHANGED` means the frozen bytes equal that baseline.

| Path | Canonical-start SHA-256 | Cycle-2 frozen SHA-256 |
|---|---|---|
| `packages/leviathan-core/src/leviathan_core/dark_pool/kernel.py` | `285c164a555f91f1cbd776c018688a0a67b310346225b6e5930008a4eb46d139` | `ce49d2ca29cb6c5cc91c5d85329be7dc5b4a8c1600bdd182b435747794be3d2a` |
| `packages/leviathan-core/src/leviathan_core/dark_pool/models.py` | `5d382fa97d80ac1c7de33bdfc8b5083afb48f97f2ad4aaeef4f61fd4610bd9b0` | `1d3796d90adb48253a3202abd5c21a4c1f991b0fa5f75e8c7e3b1f3442b393ee` |
| `packages/leviathan-core/src/leviathan_core/dealer_delta/__init__.py` | `NEW` | `ffa75de75989e59fb7cc3ab17afc75f729e10c47541e7133f495fa348e9bd9ba` |
| `packages/leviathan-core/src/leviathan_core/dealer_delta/adapter.py` | `NEW` | `656e1667cfd4fc092f1502705e5e07b34ae4c7f236ecbb0e07955b22aaf58c9f` |
| `packages/leviathan-core/src/leviathan_core/dealer_delta/kernel.py` | `NEW` | `44e347c5ee89ea48cd1fa9ae6401378fed5478f9689e7cdda059e1ded65613f5` |
| `packages/leviathan-core/src/leviathan_core/dealer_delta/models.py` | `NEW` | `7799740367e188ebbc471f1b12ed5314dc9d6567754b5cd5516bacced4773abd` |
| `packages/leviathan-core/src/leviathan_core/intel/__init__.py` | `0e4766cd0c87c62f4ddf54f9fccd21dd58d5962104db5f63ae06e50437406a4e` | `e54af0294395973e3f85724dbc33b1000d06e5af8943cc6af798ec32ca811643` |
| `packages/leviathan-core/src/leviathan_core/intel/kernel_adapters.py` | `NEW` | `f04b058db274cd07f48b2d1ea2df277ee44c8ea8945bf97d747b14c6de213e5a` |
| `packages/leviathan-core/src/leviathan_core/intel/models.py` | `7606cf5c60733cf88d187eb0f4a9ab3c231472749caf48cb73d546ce0917743d` | `190adc5ddc6b70342a5db4727dc79f19144f22056fd6a7bfd3edd007f8bd56d7` |
| `packages/leviathan-core/src/leviathan_core/intel/trace.py` | `f470345add3412dc1cc81e5d788f7e7b66203419ddbf5d9648775c0121766047` | `UNCHANGED` |
| `packages/leviathan-core/tests/dealer_delta/test_dex_kernel.py` | `NEW` | `6d548c05ce23822340c67f77606b784bcc4acc2302777349b404cfe8fe004f81` |
| `packages/leviathan-core/tests/intel/test_kernel_adapters.py` | `NEW` | `482a3914eeea361a4120bf974af611f86931c7dc1f64abde19aaa1aed59e3842` |

The cycle-0, cycle-1 and cycle-1b handoffs and the canonical-start manifest remain byte-identical to their prior recorded hashes: cycle-0 `97e8c5c21d3b6476ce7ea6f8684b89601bc9bd6309124f986cfc3befdfb90a97`; cycle-1 `f58d5d8147256f4937e0c70b3a7ec0bd30590ae49415db467137c90af1760655`; cycle-1b `37323759f9b12b22c3f57ffd9be9131e22053b8fc7f2e13f6c42d75026a037ef`.

## Verification

- Focused changed-scope + unchanged cold acceptance: `uv run --locked pytest packages/leviathan-core/tests/dealer_delta packages/leviathan-core/tests/intel/test_kernel_adapters.py packages/leviathan-core/tests/intel/test_factor_contract.py packages/leviathan-core/tests/dark_pool qa/acceptance/INTEL-002/test_intel002_cold_acceptance.py -q` — **108 passed**.
- Root `uv run --locked mypy` — **passed**, 441 source files.
- Scoped Ruff on changed source/test paths — **passed**; the edited source/test files were formatted.
- Root `uv run --locked ruff check . --extend-exclude qa/integration-backups` — **blocked by 66 lint findings** in the external acceptance file `qa/acceptance/INTEL-002/test_intel002_cycle1b_acceptance.py`; no writer-owned source/test file was reported.
- Broader core + INTEL acceptance run — **6,613 passed, 10 skipped, 3 failed**. All three failures are in `test_intel002_cycle1b_acceptance.py`: one fixture uses `fixture-bars` for the newly enforced macro source allowlist, and two missing-provenance assertions still expect `KERNEL_REJECTED` instead of `MISSING_EVIDENCE`. The frozen external acceptance file was not edited. Acceptance update is pending with its owner.
- No dependencies changed; no provider calls were made.

The worktree has unrelated canonical drift from later integrated lanes. The cumulative ledger above lists the INTEL-002 source and test surface only; other copied/drift paths were excluded from ownership based on the copy-time manifest and directory comparison.
