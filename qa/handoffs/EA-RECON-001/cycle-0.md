---
title: "EA-RECON-001 lanes 0 and 1: evidence registry and preset pilot"
kind: spec
comments: none
---

# EA-RECON-001 cycle 0

## Scope and handling

Implemented the evidence registry (Lane 0) and Golden Goose/KLP preset-schema pilot (Lane 1). This is configuration/provenance work only. No `.ex4`, `.ex5` or `.exe` was opened, copied, decoded, executed or tested; no Strategy Tester run occurred. The seed library remains outside the repository. The 16 repository `.set` fixtures contain sanitized parameter rows only, with presentation `hint` rows removed. AppleDouble sidecars are not registered, and secret-looking fields/value patterns are quarantined with fixed errors.

## Copy-time baseline and generated diff

- Worktree: `C:\Users\XYRASYSTEMS\.traycer\worktrees\local__repo__72e9e418f8\feature-ea-recon001-20261009`.
- Canonical root copied: `C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\LEVIATHAN AI\repo`.
- Copy method: detached worktree at `d3208136d1872cf6e0bb33ec79aa06f01de98562`, then byte synchronization from the live canonical working tree. Excluded `.git`, `.venv`, caches, `node_modules`, build outputs and `.pyc`; kept the worktree `.git` pointer.
- Copy-time census: 1,684 files, 24,129,619 bytes; zero missing/extra/different paths and zero skipped symlinks.
- `qa/handoffs/EA-RECON-001/canonical-start-manifest.json` SHA-256: `cf9107b910b2d1b5d848cbe33996b2e74d4ec65202ea6a0110bcd669a83537e6` (captured 2026-10-09T20:43:37Z).
- A post-copy hash comparison against that manifest found 19 new files, zero changed baseline files and zero missing baseline files before this ledger was written. The 19 additions are exactly the module, its test, the 16 parameter-only fixtures and the canonical-start manifest listed below. No shared source/test file was changed.

### Added source and test files

| Path | SHA-256 |
| --- | --- |
| `packages/leviathan-core/src/leviathan_core/strategy_ingest/presets/golden_goose_klp_presets.py` | `db9629ff849cbd2b63024ffdc0f28a908a27adfc096e40bf0f4eb7d7ed039393` |
| `packages/leviathan-core/tests/strategy_ingest/test_golden_goose_klp_presets.py` | `097b9ced8c2e9700fca25ed463fa7dfe3cff9322ab92b930cfb3c4e132e3ae11` |
| `qa/handoffs/EA-RECON-001/canonical-start-manifest.json` | `cf9107b910b2d1b5d848cbe33996b2e74d4ec65202ea6a0110bcd669a83537e6` |

### Added sanitized parameter fixtures

| Fixture | SHA-256 |
| --- | --- |
| `gg-1k-harvest-goal-mt4.set` | `85f0229c281484f243443ce2ab563a0ffbba9b1d3faae66bcae44bb41f6dbbe8` |
| `gg-2-5k-harvest-goal-mt4.set` | `e5f7a2942710e4bbabe466aa78155fd6a0d714b41c9ea0929ae30590739cac39` |
| `gg-2k-harvest-goal-mt4.set` | `f22c4a98918df171bec7dbd170592e6a2b89cf937d5d170141511420a00e83f1` |
| `gg-dg-modified-v3-4.set` | `d2dcc6df4efa2b6a4e591ed581fd7fbb58bd385a654f1dc0324767d1e2fa879a` |
| `gg-dg.set` | `58f31315b287d978c2b0e5ead44b26412caac7dc3bcfec93f2c9ae0011c7d31f` |
| `gg-dt-mt4.set` | `6918d429b1a7ed74d07b9cc6f8188e3cd70cc9dd5d8f3480b410a09111d6e189` |
| `gg-dt-mt5.set` | `8c6eb369d6bd646aabe6a1371307c00f86458c5e8ca233dd79a5d15ca9f055db` |
| `gg-ma.set` | `fe7e9e4a97b99d65e748b68b84d69121beae17ccd8c8a1277e0909072de089a4` |
| `golden-goose-5k-harvest-goal-w-news-filter-mt4.set` | `94297658984b2e0dc247f39f020f5c8745024ffd5147c1fa9a0a72771a1a230d` |
| `golden-goose-ftmo-challenge-mt4.set` | `9568036beea27f7a6ed8aff4542fdca75cd4088e30fcf6228245833f90e014c5` |
| `golden-goose-ftmo-challenge-mt5.set` | `1bdec3963783fd3f87baeb94fbdd7b46ccd2e80f9209d38b363e363fa03a741f` |
| `golden-goose-ftmo-verification-mt4.set` | `61afe8f924791570ba6b96ed85b46275098db0a7051042533ba961466ae6454f` |
| `golden-goose-ftmo-verification-mt5.set` | `61043e603acfb3b7ba008c0b0962a19749fe51e856dd468371d64af41cdb1c27` |
| `klp-ftmo-m2-2-2-m2-100k-10-0-pct-mdlbal.set` | `173b7ec6d7bd05e0342700a424db5d5ac2161edca4abeb34041c7889056dd5e7` |
| `klp-ftmo-m2-2-2-m2-100k-2-0-pct-mdlbal.set` | `38ff0aa8d2a26275a042f7f88745d110ebb9c8238740bb9aedb777e989bbf231` |
| `klp-ftmo-m2-2-2-m2-100k-5-0-pct-mdlbal.set` | `b2bf047681d739db77632b65c0b694680b198b742b619b65811748a3b1fa5608` |

## Implementation and evidence

- The adapter exposes a closed 16-entry registry (13 Golden Goose, 3 KLP), a typed schema-v1 mapping for 176 source parameter names, source and sanitized-fixture SHA bindings, roles, platform, manifest locator, per-file `crack_labelled`, and owner-attestation reference.
- Import parses parameter settings only, refuses unregistered or modified inputs, rejects secret-like field names and secret-shaped values without echo, preserves Decimal fields, and leaves instrument and timezone mappings unresolved (`UNBOUND` / `None`). It does not assert or synthesize strategy logic.
- Shared start hashes and verified current hashes match:
  - `mt_set_import.py`: `648538d2cb50e84e2b5f9914d757ff7cd4e1d0c96a0061c92eaa42d2087c59a8`
  - `kinno_presets.py`: `c08e0f7fb22c6a6e9d4d432deb0d59886ece30c3d2222f74c5067b63c5d05af4`
  - `titan_x_presets.py`: `0aa9bd4d7592b942b0c35eddbcca57e6366e371b9612aa258f0c8a00e3e18f8e`
  - Existing shared importer tests were also untouched: `test_mt_set_import.py` `3a944d7c97e0d98c7d64d9d41a1c93a121cd69c85f6d7a171110206d60b319be`.
- `uv sync` completed. `importlib.import_module(...golden_goose_klp_presets).__file__` resolved to the assigned worktree's `packages/leviathan-core/src/.../golden_goose_klp_presets.py`.
- Lane-0 evidence artifact: `artifacts/leviathan-build/execution-and-intelligence-plan/ea-recon-plan/evidence-registry/index.md`, SHA-256 at verification: `d0627abb597eadee1b6cc35eb6778f4d71235860c0971754c52a3bf3a27891fc`.
- External seed manifest SHA-256 is `f67c0acd7b4cf3851994e6597daaba02d62dcc332c7e56620a2fd046c715a05d`; its 122 unique file records and per-file `crack_labelled` flags are in the evidence artifact. The manifest's owner licensing statement remains an owner attestation, not independent legal verification.

## Verification

| Gate | Result |
| --- | --- |
| Focused new preset + existing importer tests | `uv run --locked python -m pytest packages/leviathan-core/tests/strategy_ingest/test_golden_goose_klp_presets.py packages/leviathan-core/tests/strategy_ingest/test_mt_set_import.py -q --tb=short` — 30 passed |
| Full strategy-ingest suite | `uv run --locked python -m pytest packages/leviathan-core/tests/strategy_ingest -q --tb=short` — 490 passed, 1 skipped |
| Full core suite | `uv run --locked python -m pytest packages/leviathan-core/tests` — 6,550 passed, 10 skipped, 1 xfailed |
| Full store suite | `uv run --locked python -m pytest packages/leviathan-store/tests` — 548 passed, 2 skipped |
| Full vault suite | `uv run --locked python -m pytest packages/leviathan-vault/tests` — 163 passed, 36 skipped |
| Full market-data suite | `uv run --locked python -m pytest packages/leviathan-market-data/tests` — 1,128 passed |
| Full API suite | `uv run --locked python -m pytest apps/api/tests` — 1,446 passed, 1 skipped |
| Full configured suite aggregate | Separate package-root runs above — 9,835 passed, 49 skipped, 1 xfailed |
| Exact monolithic root pytest | `uv run --locked python -m pytest` reached collection of 9,824 items, then stopped on two pre-existing duplicate module basenames: API and store `test_live_activation.py` and `test_live_activation_acceptance.py`. No test-body failure was reported. `--import-mode=importlib` was unsuitable because unrelated tests import helper modules by bare name. Running each configured root separately covered all configured test files. |
| Mypy default | `uv run --locked mypy` — success, 430 source files |
| Mypy Linux full project | `uv run --locked mypy --platform linux` — 22 existing platform/stub errors in 6 unrelated source files (Windows-only `windll`, `WinDLL`, `msvcrt.locking`/`st_file_attributes`, and an unavailable `keyring` stub); no new adapter error. |
| Mypy Darwin full project | `uv run --locked mypy --platform darwin` — 21 existing platform/stub errors in 6 unrelated source files of the same Windows-only area; no new adapter error. |
| Mypy adapter Linux/Darwin | The new module alone passes both `mypy --platform linux` and `mypy --platform darwin`. |
| Ruff root | `uv run --locked ruff check .` reports 10 existing import-order/line-length errors under archived `qa/integration-backups/`; the new module is clean. `uv run --locked ruff check . --exclude qa/integration-backups` passes. |
| Ruff touched-file check/format | New adapter and test both pass `ruff check`; `ruff format --check` reports both already formatted. |

## Lane 2 setup request

No owner EA has been run. To begin the authorized black-box capture, the Windows workstation needs:

1. The owner's licensed MT5 terminal and tester agent, with Help/About terminal build and MetaEditor/tester build recorded. The owner should launch and operate it; licensed `.ex5` files remain outside the repo and are treated as opaque. No `.ex4/.ex5/.exe` transfer or inspection is needed.
2. A frozen broker-specific XAUUSD M2 history for 2023-02-06 through 2023-05-13, preferably tick data at the intended modeling fidelity, with source and dataset hash, timezone/DST, symbol digits/tick size/contract size, bid/ask/spread behavior, commission, swap, slippage assumptions, and tester modeling mode. Confirm what KLP INI `Model=4` means on that terminal build before selecting the capture model.
3. An owner-authorized Strategy Tester/demo profile with no live order access, starting balance USD 100,000 and leverage 1:100 to match the INI. If the vendor license is account-bound, activate it only on that authorized test profile via the owner's existing secure mechanism; do not share credentials in chat or repository.
4. An approved evidence location outside Git for tester reports and normalized trade observations, along with a frozen settings file and run metadata per preset.


## Final manifest recheck

After writing the cycle ledger, a fresh comparison against the copy-time manifest found 20 added worktree files (the 19 implementation/fixture/manifest files listed above plus this ledger), zero changed baseline files and zero missing baseline files. The PROJECT-side ledger copy is outside the worktree census.
