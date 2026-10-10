# INTEL-002 ? cycle 1 handoff

## Scope

Applied the single adjudicated P2 from the INTEL-002 cycle-0 review in a separate copy, `feature-intel002-lane1-dex-cycle1`; the cycle-0 tree remains unchanged for acceptance. The DEX estimate now distinguishes the raw chain observation (`chain_observed_ns`) from its effective input observation (`observed_ns`). The effective value is `max(chain observed_ns, every per-series delta_observed_ns)`. DEX input validation already rejects any chain, delta observation, availability or OI timestamp later than the evaluation cutoff; that hard-fail behavior is retained.

The adapter binds the GEX chain by `chain_observed_ns`, snapshot ID, availability, provider and provenance, while carrying the effective DEX observation through both the DEX evidence ref and `FactorScoreV1.source_event_ns`. Thus NOW chain + NOW+1 delta at cutoff NOW+2 emits NOW+1, and evidence beyond the cutoff raises `FUTURE_EVIDENCE`.

Reviewed the other INTEL-002 adapters for multi-input time handling. `MarketBookFactorAdapter` requires the normalized market event time to equal the book receipt update time; remaining adapters project one issued kernel result/context rather than combining independently timed inputs. DEX is the only new multi-input factor requiring the maximum-input observation rule in this lane.

## Cycle-1 changed-file ledger

Cycle-1 starting bytes are the cycle-0 freeze. Baseline hashes below match `qa/handoffs/INTEL-002/cycle-0.md`.

| Path | Cycle-1 start SHA-256 | Cycle-1 frozen SHA-256 |
|---|---|---|
| `packages/leviathan-core/src/leviathan_core/dealer_delta/models.py` | `42853e693fea9e8cf2eb01106dca3167477fbbaa912aa7de063bb498983e460e` | `24f88a267635e78da9800701d784382dacba712f701572e016e8c7d5324afd15` |
| `packages/leviathan-core/src/leviathan_core/dealer_delta/kernel.py` | `098da8a1da9fde3dab7468d28e32b967167a7d87e1eef8f685459d692c8343e3` | `2c3a16a0a6ef46476e4415d928262573cced248c65de8c6cf2ae813ac31b686a` |
| `packages/leviathan-core/src/leviathan_core/dealer_delta/adapter.py` | `1f4d1aec47340c3a006b5e04230889d1789d12a3f68673601b14061e8ed55ba1` | `fda1b2aaf138f58535c8ade603c86231279a774e4dbd5946cd9023f885de7085` |
| `packages/leviathan-core/tests/dealer_delta/test_dex_kernel.py` | `64eddfa8d44da4b8eb679fc01a1d87851913656c46bf427d39dde423300eb7ec` | `6bf05dd168522c7f6fd631ff1c32491f38ef56671a322d4d90af190da3ff2670` |

No dependencies changed. No acceptance-file edits were made.

## Verification

- `uv run --locked pytest -q packages/leviathan-core/tests/dealer_delta packages/leviathan-core/tests/intel/test_kernel_adapters.py packages/leviathan-core/tests/intel/test_factor_contract.py` ? **21 passed**.
- `uv run --locked mypy` ? **passed**, 441 source files.
- Scoped Ruff on `packages/leviathan-core/src/leviathan_core/dealer_delta` and `packages/leviathan-core/tests/dealer_delta` ? **passed**.
- Root `uv run --locked ruff check . --extend-exclude qa/integration-backups` currently reports **8 findings in the independent acceptance file** `qa/acceptance/INTEL-002/test_intel002_cold_acceptance.py` (one F401, one B008, six E501); the coordinator routed its cleanup to acceptance author f437439e. This is recorded as an external gate item. The file was not changed here.
- Cycle-0 full package suite results remain recorded in `cycle-0.md`; this bounded delta reran the changed DEX and adjacent INTEL tests, root mypy and scoped Ruff.
