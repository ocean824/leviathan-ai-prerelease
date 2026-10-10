# PUBLIC-DATA-001 cycle 2 freeze ledger

## Baseline and scope

Cycle 2 is compared with `public-data-001-c1-frozen`, as directed by the coordinator. The canonical-start manifest is [cycle-2-start.json](cycle-2-start.json), SHA-256 `dbb5ccb0c6107b082b7c18fe054e730fe0d36a69698881f7924bf3aba4649c94`, containing 1,557 baseline files. This ledger lists all 15 changed or added files. The ledger is deliberately excluded from its own file hash table.

Cycle 1 already included NY Fed Markets, TreasuryDirect auctions, FINRA short interest, SEC 13F and 13D/G, and House Clerk PTR sources. Cycle 2 removes Binance from runtime enablement and marks it `EXCLUDED` for U.S. persons. Coinbase U.S. derivatives public endpoints replace it, gated off by default and enabled explicitly in startup settings. Crypto registry entries record U.S. eligibility and the terms basis.

The cycle adds per-record scoring bindings in `apps/api/src/leviathan_api/public_source_factor_adapters.py`. Stable mappings are: SEC Form 4/13F/13D-G to `insider` / `insider_activity`; FINRA ATS/off-exchange to `dark_pool` / `dark_pool`; Reg SHO and short interest to `volume` / `short_activity`; CFTC COT to `macro` / `positioning`; Treasury, NY Fed, BLS and Fed calendar to `macro` / `rates_macro`. Scheduled-event risk and prediction-market probability remain separately typed; no cross-source aggregation is performed. Inputs without a defensible signed factor abstain. Each mapped record preserves explicit source values and time semantics, deterministic provenance, and `redistribution: false`.

API-ANYTHING stays a separate `PublicOperationRecordV1` contract. Its five registry entries are `api_anything.calendar.fed`, `api_anything.earnings.forward`, `api_anything.senate.efd.ptr`, `api_anything.cboe.daily.stats`, and `api_anything.cnn.fear_greed`. `public_sources/__init__.py` composes those with official sources through `register_many`; operation records and digests remain intact for INTEL binding. Live templates and site calls are not enabled.

## Changed and added files

For modified files, the first hash is the c1 frozen canonical-start SHA-256 and the second is the cycle-2 frozen SHA-256. `ABSENT` means the file did not exist in the c1 baseline.

| State | Path | Canonical-start SHA-256 | Frozen SHA-256 |
|---|---|---|---|
| Modified | `apps/api/config/local-paper-market-data.example.toml` | `99362276aa6ef0054fa43ed00d31be22248e553643aba1201db8245db544ecd4` | `9ae2f259f567907509e6764b4af3e7fd9985e179e32788dfb6840db880ce5853` |
| Modified | `apps/api/src/leviathan_api/market_data_runtime.py` | `05f72833b9aa9594d5b2dbbc7f19b8e1771edbb2e6e78fc39d1281283f1609a4` | `bbb2324da32cbe9d8a63dc3001bb84e3d541eaf36b5d948840c8c4fce62e5543` |
| Modified | `apps/api/src/leviathan_api/market_data_runtime_config.py` | `ceef28308638cb1a8581d872b1e7dbb5c695ecf82276dd75c444eda5441811d1` | `1cc0e4d9821124a5074e82445d7387292e044ff20047917f4fbf5ab06eef26a2` |
| Added | `apps/api/src/leviathan_api/public_source_factor_adapters.py` | `ABSENT` | `edbf72d0be10856f74e1aa993a2f769ec4b99ae570b250ef29a0e7eb19f8c33c` |
| Modified | `apps/api/src/leviathan_api/public_sources_intel.py` | `10b29746deeeb1b320d3304c0e28d1e976548f78ff70a366b6096d7f4e526e02` | `f7611b203fd05f4ba154ec9761c2ab1ffbe24a5a53007eff38693e3991384a3a` |
| Added | `apps/api/tests/test_public_source_factor_adapters.py` | `ABSENT` | `9d28b9292bd2739e98c8b67f2070f44c58fb0b4718b355c8b368176f64d34336` |
| Modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/__init__.py` | `bcedacb6064de7fe207553cf641ecc94b122b2db07e02eb60bd2ee34dcdf6255` | `169cd11f106b9500296334857602576ab4b60b17473e127ac5c0c8f1957469de` |
| Added | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/api_anything_client.py` | `ABSENT` | `cd4ce506bd5a1f02378c9888bd9f15682c7a5816e8a5e3ceb77ce9bc121b2aad` |
| Added | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/api_anything_registry.py` | `ABSENT` | `836398f56809a5da6f56aac70ec6f3dc35721ef1dbaa499a97a8d418e698a2f5` |
| Modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/registry.py` | `dc168e14544c18ffe8977d20f935e438f13c9bbd8fea8f186158dad1f015eae1` | `f7e4ae882f0a8d70539c5118fa73b7842d920c260eeec193aa10b55558d63847` |
| Modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/sources.py` | `d3108e368e6809e7c63008fba3a5c35b38561c2a482b3609d41eccd34b3a674a` | `b7aaba8c7df4e5220898669ef596939a973a826ce43404109a0f31aab636defb` |
| Added | `packages/leviathan-market-data/tests/fixtures/api_anything_fear_greed.json` | `ABSENT` | `5eebcc77b9e23440ff65dbf434edfbdc857e17c0de436661c164e90f583bf30c` |
| Added | `packages/leviathan-market-data/tests/test_api_anything_client.py` | `ABSENT` | `202a42dd3da47e9019f4c1b1a55cc2c4554fa38cca3e8699c51575eef8a59220` |
| Modified | `packages/leviathan-market-data/tests/test_public_sources.py` | `8bd04914c1cc839ee31ea846d9de603220b6339fcf4bcd129377b5a8c295b528` | `e9d1a82e713ac09c37cf9f6a4b9904db390322f9b9243f961edbaac84f5aa0be` |
| Added | `qa/handoffs/PUBLIC-DATA-001/cycle-2-start.json` | `ABSENT` | `dbb5ccb0c6107b082b7c18fe054e730fe0d36a69698881f7924bf3aba4649c94` |

## Gates

| Gate | Result |
|---|---|
| `uv sync --locked` | PASS (58 resolved, 48 checked) |
| `pytest packages/leviathan-core/tests -q` | PASS (6,579 passed, 10 skipped) |
| `pytest packages/leviathan-store/tests -q` | PASS (548 passed, 2 skipped) |
| `pytest packages/leviathan-vault/tests -q` | PASS (163 passed, 36 skipped) |
| `pytest packages/leviathan-market-data/tests -q` | PASS (1,166 passed) |
| `pytest apps/api/tests -q` | PASS (1,490 passed, 1 skipped) |
| `pytest qa/acceptance/PUBLIC-DATA-001 -q` | PASS (21 passed) |
| `pytest tests -q` | PASS (289 passed) |
| `mypy` | PASS (443 files) |
| `mypy --platform linux` | PASS (443 files) |
| `mypy --platform darwin` | PASS (443 files) |
| `ruff check --extend-exclude qa/integration-backups .` | PASS |

The first full core-suite attempt had a SQLite timing failure under shared-host load. The isolated test passed; the full core suite then passed on rerun. The results above are the final rerun results.

## Artifact hashes

| Artifact | SHA-256 |
|---|---|
| `public-data-001/discovery/index.md` | `4138603cca970f5734e0ac4647aee58c7281b0e050f2d6ab931968044dbfccf3` |
| `public-data-001/cycle-2/index.md` | `49c435a206456cf85259f19c48193ea0fa13df304ab13ebe7579c65f86888c57` |
| `public-data-001/api-anything-design/index.md` | `d1d1b576fb53c6110d6633aeecb048740b09c48d88a54c22a23e22c1c1560550` |
