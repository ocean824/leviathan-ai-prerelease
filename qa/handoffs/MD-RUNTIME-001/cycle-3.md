# MD-RUNTIME-001 cycle 3 freeze

**State:** Frozen for targeted review of the two cycle-3 findings. Runtime integration and live-provider smoke remain outstanding. No provider API calls, real vault-key resolution, canonical repository writes, or commits were made.

## Cycle-3 fixes

- **Chart WebSocket principal resolution:** the route now wraps the existing WebSocket scope in Starlette `HTTPConnection`, not the HTTP-only `Request`, and calls the same trusted-principal resolver. The shared resolver's input type was widened to `HTTPConnection`; HTTP requests remain supported because `Request` is its subclass. Loopback enforcement and exact `TrustedPrincipalV1` checks remain unchanged. A positive test connects from loopback using a valid test principal, receives an initial snapshot and a subsequent live update. Existing independent refusal probes for non-loopback and wrong principal remain unchanged and pass.
- **Backfill queue lifetime capacity:** the active cap counts only queued/running jobs. Completed, failed and cancelled status records move to a separately bounded FIFO retaining the latest 16; old records are evicted and `read()` returns `None` for an evicted ID, which the route reports as not found. Tests submit 24 sequential jobs with active capacity 1 and verify eviction, then prove a seventeenth concurrent job is rejected at the default active cap 16.

## Canonical sync and actual directory diff

Canonical repository: `C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\LEVIATHAN AI\repo`.

The final full walk compared relative paths and SHA-256 values. Standard exclusions: `.git`, `.venv`, `node_modules`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `dist`, `build`, `target`, `__pycache__`, `.next`, `.vite`, `coverage`, `htmlcov`, `.tox`, `.nox`. Integration backups were included. Census before writing this cycle-3 handoff: canonical **1,631 files**, worktree **1,654 files**, **34 differing/extra paths**, **0 canonical-only paths**. The cycle-3 handoff itself is excluded from its own table to avoid a self-referential hash; cycle-0, cycle-1 and cycle-2 handoffs are included. Table generated from that directory diff; `MISSING` denotes no canonical file at the current baseline.

Canonical's corrected PKG-MAC acceptance file `qa/acceptance/pkg_mac_001_phase_a/test_pkg_mac_001_phase_a_acceptance.py` was synced into the worktree at SHA-256 `b6cb4dc4dc70a71769a21d76770c40cdae0511d1d6104375fe217e24e3d86953`, resolving the two cycle-2 location-dependent test failures. The file was not edited by this worker.

| Path | Canonical-start SHA-256 | Frozen worktree SHA-256 |
| --- | --- | --- || `apps/api/config/local-paper-market-data.example.toml` | `MISSING` | `b4625fc74e639d7b54e414da048171c104c6f00f97de0354e972c340a3e086da` |
| `apps/api/src/leviathan_api/market_data_backfill.py` | `MISSING` | `e3e2fc93271df912834035e75b7b982ca2f2e2e4be53a8bf85e5aeb31e0b956c` |
| `apps/api/src/leviathan_api/market_data_runtime.py` | `MISSING` | `6f1b21b89c3e93b693874e22e845318cbffeb9835132f12c0bf21f09d850f6e4` |
| `apps/api/src/leviathan_api/market_data_runtime_config.py` | `MISSING` | `d1e975834654cf42286c9b108f9f9d325ca92f9cccb30fa234d858058d6c7313` |
| `apps/api/src/leviathan_api/observation_runtime.py` | `99fa50712a26da6ab0bc6195231c6d39d09ed4885ffecb118939a3ff449683a8` | `86d1b01dcb8387e012fb6935ffbad9919df607bd5b491ef5d0814ea8da4ac051` |
| `apps/api/src/leviathan_api/paper_mounts_runtime.py` | `046f78088e4a13fc01428cc48d9b1f09417503f6eb918b9f2cf5c985ddb25812` | `d323bd3f8701577b1b796daf5b49f6952f15c0c5c6db4d936ea73cec7155076c` |
| `apps/api/src/leviathan_api/routers/market_data_paper_v1.py` | `362865c065e4eb0cde530c33c025d19075ecf1bbaaf340414828f1c80f5e73a7` | `45411c3e0e8228390be568c44d3879356f8f632ffa87b64bc8c8d280772b1afa` |
| `apps/api/src/leviathan_api/wave35_mounts.py` | `e02924cd109568e3e9de21d4c2ea4507e0af6c85e257589c1dccc47c94cbbc99` | `bbf0a4475ae15e62192b8d12c5d947fe2fe565ba7b2ab289889a41b35fe8693d` |
| `apps/api/tests/test_market_data_paper_v1.py` | `a8fffafb88ced585e84b0bdfc03c62c19ceb8a4da427d7bf11bcf1b30e270501` | `8b1d8939249002444d6cd1479ebe13cdd304789c1ea89e419ab2dea323abcc5a` |
| `apps/api/tests/test_market_data_runtime.py` | `MISSING` | `f67c1deba0aef703900dfeafc74d8fd2c23e62dbf0549118365c338c4900303f` |
| `apps/api/tests/test_market_data_runtime_config.py` | `MISSING` | `1509cc4c118d98a58f2c60a0c193ce24b478da5efbb4941c3aa0121b2bd9ed39` |
| `apps/terminal/src/App.tsx` | `a8f39dcee18dac5541e2c900e32a194d9c271ce82c5ecc4413c3e31894a52201` | `a248204b00c6575b943e1cbeac04351aa5c707d2d8d7e6bd562030b2e0395ae1` |
| `apps/terminal/src/wave33/marketData/api.ts` | `6a01105f7ed28052160224844cd1612ebd172f2f7528748ab204e6c7fe228fcb` | `d5febd8bd2ed3a1f3e05d3ce37cd714e3bf1cabe3d2d76282043a9f265ec0a9b` |
| `apps/terminal/src/wave34/charts/LiveMarketDataWorkspace.tsx` | `MISSING` | `a253f7f1a99cff00d5fb4b25f7dd3af6a635afc8bd0aeb66bd09601bdd4ec861` |
| `apps/terminal/src/wave34/charts/model.ts` | `f71cbf894ae448b01bc397553a9f86ffbedd8348d01ed37e9a81695fc555c803` | `be7f93a6c21d505a8c028e2f0a8089fed408b4c083d69dd81b58d6aa1d776cb8` |
| `apps/terminal/src/wave34/charts/PriceDepthFootprintView.tsx` | `f70781d1c07c742a09d9cdfc848f1c6568f1591467c29752f811b72a692e00d9` | `9b1b296b8ed2a5ee143e5df27fef0bd6834a866296dbd76dec66c1705354265f` |
| `apps/terminal/src/wave34/charts/test/liveMarketData.test.tsx` | `MISSING` | `1f5dbf404a90d453752a9018f286d02e7c32c0607b2f3c2081e9d1bd01584c17` |
| `packages/leviathan-market-data/pyproject.toml` | `ec45ba91f8d2776534765fc105e2df631b3699ea3205c0a91ce8ce3b09b991c6` | `9d68c4374b4ceee60ac19888eebaa80413a8851cb166cea62725f4ba5e7de1cf` |
| `packages/leviathan-market-data/src/leviathan_market_data/live/backfill_jobs.py` | `MISSING` | `009dee7cea0446b83b53f823e44daaa4226add5a3987b922c23f86d961669d7e` |
| `packages/leviathan-market-data/src/leviathan_market_data/live/latest_store.py` | `MISSING` | `92516fe8c5852db44145eb18fa9c74147aa408e4a536e09923dc34f30a58e4af` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/databento_live.py` | `MISSING` | `46e8bc89d5d3bdeb806e3784797d8c8fecec0819cede751f75e0bedb19e2190e` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/databento_mapping.py` | `MISSING` | `1cdc454da1043f5307308f9326ca770f5368983e10e2905b307166b1f70133de` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/massive_live.py` | `MISSING` | `c339a663b791353ef5ef18b1b7dbe9d197fc6b8b65ba63238b0d4d2edd3cee50` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/massive_transport.py` | `MISSING` | `bcfdcbea4f265bc8ecae0c136535d42f0895087f9769cf53127cc1314a4f1365` |
| `packages/leviathan-market-data/src/leviathan_market_data/py.typed` | `MISSING` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `packages/leviathan-market-data/tests/live/test_backfill_jobs.py` | `MISSING` | `af087b3074b1898ce7ce2505d82a895455a4b7ecb90c0d701eadf0332c24fd5f` |
| `packages/leviathan-market-data/tests/live/test_databento_mapping.py` | `MISSING` | `c17b4d50ad85308303daee5542c8cb6f3442097c9426076de8e73cb0b0ba7622` |
| `packages/leviathan-market-data/tests/live/test_runtime.py` | `MISSING` | `bf3168f0439ddf49f241bb9cefbfe407607239fb451ec960f04cf8c5b5ba7041` |
| `packages/leviathan-market-data/tests/test_massive_transport.py` | `MISSING` | `069a127ead9a71c936e58b9da10b9afb95e5d28b12bbe9ff4aa8cee817b127f9` |
| `qa/acceptance/md_runtime_001/test_md_runtime_001_acceptance.py` | `MISSING` | `59d7392ef0fb981e15b99d67327c9d7f2f6a8a895890a67af7f146c789477dc2` |
| `qa/handoffs/MD-RUNTIME-001/cycle-0.md` | `MISSING` | `729fcac1eacb1bbae3fdef8c54a5078341359e43646786affa949aa380188bf6` |
| `qa/handoffs/MD-RUNTIME-001/cycle-1.md` | `MISSING` | `8aaf83efe4c1c51fd3493314b8234e1395df72c608124c00f972679aabe1b3f9` |
| `qa/handoffs/MD-RUNTIME-001/cycle-2.md` | `MISSING` | `c4f761f8b3bbf1ae811d0d6ab7b862aadd1132fef7aa0f068c2eadf78d7726a7` |
| `uv.lock` | `8217f08bcdd0e017af9947517ad8a25bc0508ea55dfaf05f617cc989d7692c2a` | `815c94a6fadbe1c8c7bef19258b1ef99d259715cf4b5bfa8eab0f3daadfaf4e5` |

## Dependency, config and provider boundaries

The cycle-2 dependency delta remains unchanged: `databento-dbn==0.71.0` is pinned with Apache-2.0 metadata; the full Databento SDK was not added. CPython 3.14 wheel hashes are Windows x86_64 `b5ebcb1ef3c9cabc4c598ef54668dd4e81a555790eed70c94d697af7d3557c4f`, macOS universal2 `48c0f13003e7012386d4998e1a60441d0f24d12ae2849b914070d5f381cf3874`, and macOS x86_64 `b2cc4a6afcda102f0c9bd26e4b1f6662e77f893a2415d725025f0e5a5042236b`. The root lock retains the canonical PKG-MAC keyring marker. No dependency changes were made in cycle 3.

Runtime configuration remains strict, bounded and credential-free; credentials resolve through the vault seam only when a session starts/reconnects. DBN mapping messages populate the session registry; Massive remains L1-only. Historical Databento reads use the existing adapter's sole `metadata.get_cost` preflight and configured spend cap; Massive historical transport stays host/path pinned, bounded and redirect refusing. No `main.py` change or provider call was made.

## Import-origin guard

With `PYTHONPATH` removed, the required `uv run --locked python -c` check resolved all packages inside this feature worktree:

- `leviathan_api`: `C:\Users\XYRASYSTEMS\.traycer\worktrees\local__repo__72e9e418f8\feature-md-runtime-001-20261008\apps\api\src\leviathan_api\__init__.py`
- `leviathan_market_data`: `C:\Users\XYRASYSTEMS\.traycer\worktrees\local__repo__72e9e418f8\feature-md-runtime-001-20261008\packages\leviathan-market-data\src\leviathan_market_data\__init__.py`
- `leviathan_core`: `C:\Users\XYRASYSTEMS\.traycer\worktrees\local__repo__72e9e418f8\feature-md-runtime-001-20261008\packages\leviathan-core\src\leviathan_core\__init__.py`
- `leviathan_store`: `C:\Users\XYRASYSTEMS\.traycer\worktrees\local__repo__72e9e418f8\feature-md-runtime-001-20261008\packages\leviathan-store\src\leviathan_store\__init__.py`
- `leviathan_vault`: `C:\Users\XYRASYSTEMS\.traycer\worktrees\local__repo__72e9e418f8\feature-md-runtime-001-20261008\packages\leviathan-vault\src\leviathan_vault\__init__.py`

## Gates

All Python gates ran through the worktree interpreter without `PYTHONPATH`; `LEVIATHAN_LICENSE_STATE` and `LEVIATHAN_LICENSE_FEATURES` were unset during the full run.

| Gate | Result |
| --- | --- |
| `uv sync --locked --all-packages` | PASS |
| Full Python suite: `uv run --locked python -m pytest apps/api/tests packages/leviathan-market-data/tests qa/acceptance/md_runtime_001 apps/desktop/sidecar/tests packages/leviathan-vault/tests infra/release/tests qa/acceptance/pkg_mac_001_phase_a -q` | **2,872 passed, 38 skipped, 15 warnings** |
| Cycle-3 focused tests: market-data paper router, Wave35 mounts, runtime, and `test_backfill_jobs.py` | **35 passed**, 2 existing warnings |
| MD-RUNTIME + PKG-MAC acceptance modules | **23 passed**, 1 upstream Starlette/httpx deprecation warning |
| `uv run --locked mypy` | PASS: no issues in 428 source files |
| `uv run --locked ruff check . --extend-exclude qa/integration-backups` | PASS |
| Terminal Vitest (`npm.cmd run test -- --pool=forks --maxWorkers=1 --no-file-parallelism`) | 66 files passed; 1,399 passed, 1 skipped |
| `npm.cmd run build` | PASS: 89 modules built |
| `npm.cmd run lint` | PASS with existing `PaperMarketDataHealthView.tsx:154` missing-`refreshVenues` hook-dependency warning |

The independent MD-RUNTIME acceptance file was not modified. Its existing non-loopback and wrong-principal refusal checks pass; cycle-3's positive loopback snapshot/update case is covered by `apps/api/tests/test_market_data_paper_v1.py`. Live-provider entitlement, credentials and latency smoke remain for post-integration validation.
