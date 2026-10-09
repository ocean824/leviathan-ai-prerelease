# MD-RUNTIME-001 cycle 2 freeze

**State:** Frozen for the assigned targeted review; runtime integration and live-provider smoke remain outstanding. No provider API calls, real vault-key resolution, canonical repository writes, or commits were made.

## Cycle-2 changes

This cycle resolves the two assigned review findings:

- **Databento DBN open-ended mapping bounds:** accepts `UNDEF_TIMESTAMP` as an open bound in `SymbolMappingMsg.start_ts` and `end_ts`; later remaps close the prior interval. Malformed non-sentinel values and reversed/empty intervals remain rejected. Mapping and remap regression tests pass.
- **Credential resolution latency:** live-session and reconnect credential lookup runs through `asyncio.to_thread`, once per session start/reconnect and held only for that session. A slow fake resolver test proves concurrent event-loop progress; no per-message resolution or runtime key cache is introduced.

The production historical bridge, bounded live lifecycle, chart read model/WebSocket, and strict config loading remain as described in cycle 1. `main.py` remains untouched. Dependency metadata retains the rebased PKG-MAC `keyring` marker and pinned `databento-dbn==0.71.0`; no full Databento SDK was added. Existing `metadata.get_cost` remains the sole cost preflight. Massive uses the bounded host/path-pinned stdlib transport.

## Canonical sync and diff method

Canonical repository: `C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\LEVIATHAN AI\repo`.

The final full walk compared canonical and this worktree by relative path and SHA-256. Standard excluded generated/environment directories: `.git`, `.venv`, `node_modules`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `dist`, `build`, `target`, `__pycache__`, `.next`, `.vite`, `coverage`, `htmlcov`, `.tox`, `.nox`. `qa/integration-backups` was included and synced byte-identically. Census: canonical **1,631 files**; worktree **1,652 files** before writing this cycle-2 handoff; **31 differing/extra paths**, **0 canonical-only paths**. The handoff's own path is omitted from its generated table because including its hash would be self-referential; cycle-0 and cycle-1 ledgers are included. Every other differing path follows, generated from that directory diff; `MISSING` means no canonical file existed at the cycle-2 baseline.

| Path | Canonical-start SHA-256 | Frozen worktree SHA-256 |
| --- | --- | --- || `apps/api/config/local-paper-market-data.example.toml` | `MISSING` | `b4625fc74e639d7b54e414da048171c104c6f00f97de0354e972c340a3e086da` |
| `apps/api/src/leviathan_api/market_data_backfill.py` | `MISSING` | `e3e2fc93271df912834035e75b7b982ca2f2e2e4be53a8bf85e5aeb31e0b956c` |
| `apps/api/src/leviathan_api/market_data_runtime.py` | `MISSING` | `6f1b21b89c3e93b693874e22e845318cbffeb9835132f12c0bf21f09d850f6e4` |
| `apps/api/src/leviathan_api/market_data_runtime_config.py` | `MISSING` | `d1e975834654cf42286c9b108f9f9d325ca92f9cccb30fa234d858058d6c7313` |
| `apps/api/src/leviathan_api/paper_mounts_runtime.py` | `046f78088e4a13fc01428cc48d9b1f09417503f6eb918b9f2cf5c985ddb25812` | `d323bd3f8701577b1b796daf5b49f6952f15c0c5c6db4d936ea73cec7155076c` |
| `apps/api/src/leviathan_api/routers/market_data_paper_v1.py` | `362865c065e4eb0cde530c33c025d19075ecf1bbaaf340414828f1c80f5e73a7` | `3429894dec8fc233491665e27bc939872b345100501e1cf39019d45a329cdcf8` |
| `apps/api/src/leviathan_api/wave35_mounts.py` | `e02924cd109568e3e9de21d4c2ea4507e0af6c85e257589c1dccc47c94cbbc99` | `ab5c25ef5a3bcd74934ecd31976fc05b4b724c675959ab4ad77460b6beb4360b` |
| `apps/api/tests/test_market_data_runtime.py` | `MISSING` | `f67c1deba0aef703900dfeafc74d8fd2c23e62dbf0549118365c338c4900303f` |
| `apps/api/tests/test_market_data_runtime_config.py` | `MISSING` | `1509cc4c118d98a58f2c60a0c193ce24b478da5efbb4941c3aa0121b2bd9ed39` |
| `apps/terminal/src/App.tsx` | `a8f39dcee18dac5541e2c900e32a194d9c271ce82c5ecc4413c3e31894a52201` | `a248204b00c6575b943e1cbeac04351aa5c707d2d8d7e6bd562030b2e0395ae1` |
| `apps/terminal/src/wave33/marketData/api.ts` | `6a01105f7ed28052160224844cd1612ebd172f2f7528748ab204e6c7fe228fcb` | `d5febd8bd2ed3a1f3e05d3ce37cd714e3bf1cabe3d2d76282043a9f265ec0a9b` |
| `apps/terminal/src/wave34/charts/LiveMarketDataWorkspace.tsx` | `MISSING` | `a253f7f1a99cff00d5fb4b25f7dd3af6a635afc8bd0aeb66bd09601bdd4ec861` |
| `apps/terminal/src/wave34/charts/model.ts` | `f71cbf894ae448b01bc397553a9f86ffbedd8348d01ed37e9a81695fc555c803` | `be7f93a6c21d505a8c028e2f0a8089fed408b4c083d69dd81b58d6aa1d776cb8` |
| `apps/terminal/src/wave34/charts/PriceDepthFootprintView.tsx` | `f70781d1c07c742a09d9cdfc848f1c6568f1591467c29752f811b72a692e00d9` | `9b1b296b8ed2a5ee143e5df27fef0bd6834a866296dbd76dec66c1705354265f` |
| `apps/terminal/src/wave34/charts/test/liveMarketData.test.tsx` | `MISSING` | `1f5dbf404a90d453752a9018f286d02e7c32c0607b2f3c2081e9d1bd01584c17` |
| `packages/leviathan-market-data/pyproject.toml` | `ec45ba91f8d2776534765fc105e2df631b3699ea3205c0a91ce8ce3b09b991c6` | `9d68c4374b4ceee60ac19888eebaa80413a8851cb166cea62725f4ba5e7de1cf` |
| `packages/leviathan-market-data/src/leviathan_market_data/live/backfill_jobs.py` | `MISSING` | `efc2a013bf77434564589afed2a9616adffeebd0e5cdab381c44a5347ceb56cd` |
| `packages/leviathan-market-data/src/leviathan_market_data/live/latest_store.py` | `MISSING` | `92516fe8c5852db44145eb18fa9c74147aa408e4a536e09923dc34f30a58e4af` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/databento_live.py` | `MISSING` | `46e8bc89d5d3bdeb806e3784797d8c8fecec0819cede751f75e0bedb19e2190e` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/databento_mapping.py` | `MISSING` | `1cdc454da1043f5307308f9326ca770f5368983e10e2905b307166b1f70133de` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/massive_live.py` | `MISSING` | `c339a663b791353ef5ef18b1b7dbe9d197fc6b8b65ba63238b0d4d2edd3cee50` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/massive_transport.py` | `MISSING` | `bcfdcbea4f265bc8ecae0c136535d42f0895087f9769cf53127cc1314a4f1365` |
| `packages/leviathan-market-data/src/leviathan_market_data/py.typed` | `MISSING` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `packages/leviathan-market-data/tests/live/test_databento_mapping.py` | `MISSING` | `c17b4d50ad85308303daee5542c8cb6f3442097c9426076de8e73cb0b0ba7622` |
| `packages/leviathan-market-data/tests/live/test_runtime.py` | `MISSING` | `bf3168f0439ddf49f241bb9cefbfe407607239fb451ec960f04cf8c5b5ba7041` |
| `packages/leviathan-market-data/tests/test_massive_transport.py` | `MISSING` | `069a127ead9a71c936e58b9da10b9afb95e5d28b12bbe9ff4aa8cee817b127f9` |
| `qa/acceptance/md_runtime_001/test_md_runtime_001_acceptance.py` | `MISSING` | `59d7392ef0fb981e15b99d67327c9d7f2f6a8a895890a67af7f146c789477dc2` |
| `qa/acceptance/pkg_mac_001_phase_a/test_pkg_mac_001_phase_a_acceptance.py` | `b6cb4dc4dc70a71769a21d76770c40cdae0511d1d6104375fe217e24e3d86953` | `49faf537e0454566168450be9361185c617fb6afcb5d438e14c3981d1ed9325c` |
| `qa/handoffs/MD-RUNTIME-001/cycle-0.md` | `MISSING` | `729fcac1eacb1bbae3fdef8c54a5078341359e43646786affa949aa380188bf6` |
| `qa/handoffs/MD-RUNTIME-001/cycle-1.md` | `MISSING` | `8aaf83efe4c1c51fd3493314b8234e1395df72c608124c00f972679aabe1b3f9` |
| `uv.lock` | `8217f08bcdd0e017af9947517ad8a25bc0508ea55dfaf05f617cc989d7692c2a` | `815c94a6fadbe1c8c7bef19258b1ef99d259715cf4b5bfa8eab0f3daadfaf4e5` |

## Dependency and DBN verification

- `packages/leviathan-market-data/pyproject.toml` adds the native decoder pin while retaining the canonical package metadata; `uv.lock` carries Databento together with canonical PKG-MAC keyring changes.
- Package metadata reports `Apache-2.0`. Verified CPython 3.14 wheel hashes: Windows x86_64 `b5ebcb1ef3c9cabc4c598ef54668dd4e81a555790eed70c94d697af7d3557c4f`; macOS universal2 `48c0f13003e7012386d4998e1a60441d0f24d12ae2849b914070d5f381cf3874`; macOS x86_64 `b2cc4a6afcda102f0c9bd26e4b1f6662e77f893a2415d725025f0e5a5042236b`.
- Dependency delta: pinned `databento-dbn==0.71.0`; no full SDK and no other new runtime dependency in this task. `uv sync --locked --all-packages` completed successfully.

## Import-origin guard

With `PYTHONPATH` removed, the required `uv run --locked python -c` module-origin check resolved all five packages inside this worktree:

- `leviathan_api`: `apps/api/src/leviathan_api/__init__.py`
- `leviathan_market_data`: `packages/leviathan-market-data/src/leviathan_market_data/__init__.py`
- `leviathan_core`: `packages/leviathan-core/src/leviathan_core/__init__.py`
- `leviathan_store`: `packages/leviathan-store/src/leviathan_store/__init__.py`
- `leviathan_vault`: `packages/leviathan-vault/src/leviathan_vault/__init__.py`

## Gates

All commands ran in this worktree without `PYTHONPATH`; both `LEVIATHAN_LICENSE_STATE` and `LEVIATHAN_LICENSE_FEATURES` were unset for the license-default and full Python runs.

| Gate | Result |
| --- | --- |
| `uv sync --locked --all-packages` | PASS |
| Full requested Python suite via `uv run --locked python -m pytest apps/api/tests packages/leviathan-market-data/tests qa/acceptance/md_runtime_001 apps/desktop/sidecar/tests packages/leviathan-vault/tests infra/release/tests qa/acceptance/pkg_mac_001_phase_a -q` | 2,867 passed, 38 skipped, 2 failed, 15 warnings. The only failures were `qa/acceptance/pkg_mac_001_phase_a/test_pkg_mac_001_phase_a_acceptance.py::test_windows_feed_entry_matches_canonical` and `::test_tauri_platform_configs_keep_macos_packaging_and_windows_semantics`. Both are the known location-dependent defect: `_CANONICAL` points to nonexistent sibling `..\\repo`; coordinator routed its fix to the test owner and confirmed canonical passes. Not attributable to MD-RUNTIME. |
| License-gate acceptance with both license variables unset | 14 passed, 1 upstream Starlette/httpx deprecation warning |
| MD-RUNTIME independent acceptance (`qa/acceptance/md_runtime_001/test_md_runtime_001_acceptance.py`) | 14 passed, 1 upstream Starlette/httpx deprecation warning |
| `uv run --locked mypy` | PASS: no issues in 428 source files |
| `uv run --locked ruff check . --extend-exclude qa/integration-backups` | PASS |
| Terminal Vitest (`npm.cmd run test -- --pool=forks --maxWorkers=1 --no-file-parallelism`; single-worker equivalent for installed Vitest 5.0.3) | 66 files passed; 1,399 passed, 1 skipped |
| `npm.cmd run build` | PASS: 89 modules built |
| `npm.cmd run lint` | PASS with existing `PaperMarketDataHealthView.tsx:154` missing-`refreshVenues` hook-dependency warning |

The full Python result is recorded transparently with the coordinator's explicit non-blocking classification for the two location-dependent PKG-MAC nodes. All other requested gates pass. The pending live smoke must verify provider entitlements, credentials, latency and production session behavior after integration.

## Review scope

This cycle freezes the full actual worktree delta listed above. In particular it includes the previously omitted `paper_mounts_runtime.py`, terminal `wave33/marketData/api.ts`, and new `live/backfill_jobs.py`; all three hashes are in the generated table. Request targeted review of those three paths with the complete cycle-2 delta before re-integration.
