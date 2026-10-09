# MD-RUNTIME-001 cycle 4 freeze

**State:** Frozen for the targeted WebSocket principal-middleware correction. Live-provider smoke and runtime integration remain outstanding. No provider calls, real vault-key resolution, canonical-repo writes, or commits were made.

## Change

`OperatorPrincipalMiddleware` now applies the same Host, Origin, and capability evidence predicate to WebSocket handshakes as HTTP requests. A denied WebSocket is closed before route dispatch/accept: 4401 for missing or invalid capability, 4403 for Host/Origin failure. A valid handshake receives a freshly issued trusted principal in the ASGI scope state, which the unchanged default W35 resolver reads via `HTTPConnection(websocket.scope)`. The existing HTTP behavior is unchanged: invalid evidence clears the principal and dispatches as before.

Added real `create_app()` + W35 composition tests with `principal_resolver=None`: valid loopback capability/Origin/Host receives `ChartSnapshotV1` followed by a delta; missing capability, invalid capability, and non-loopback Origin close before accept. Existing HTTP operator-principal and acceptance tests pass.

## Canonical sync and actual directory diff

Canonical repo: `C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\LEVIATHAN AI\repo`.

Full walk with exclusions `.git`, `.venv`, `node_modules`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `dist`, `build`, `target`, `__pycache__`, `.next`, `.vite`, `coverage`, `htmlcov`, `.tox`, `.nox`; integration backups included. Census excluding this ledger's own row: worktree **1,655 files**, canonical **1,631 files**, **37 differing/extra paths**, **0 canonical-only paths**. No newer non-owned canonical files were missing. The 37 paths are the prior MD-RUNTIME implementation delta and handoffs plus this cycle's shared middleware/test changes. The complete table below was generated from the sorted full-walk path and SHA-256 comparison; `MISSING` means the path does not exist in canonical.

| Path | Canonical-start SHA-256 | Frozen worktree SHA-256 |
| --- | --- | --- |
| `apps/api/config/local-paper-market-data.example.toml` | MISSING | `b4625fc74e639d7b54e414da048171c104c6f00f97de0354e972c340a3e086da` |
| `apps/api/src/leviathan_api/auth/operator_principal.py` | `1491e1d5d486c106ee2b18d10d86624e2066f8171a9c29b0968cdf58f8ebc39d` | `3dda567cb3b6eece8b38e418f03f840e1e311508f141c1859f16fcba8796cd46` |
| `apps/api/src/leviathan_api/market_data_backfill.py` | MISSING | `e3e2fc93271df912834035e75b7b982ca2f2e2e4be53a8bf85e5aeb31e0b956c` |
| `apps/api/src/leviathan_api/market_data_runtime.py` | MISSING | `6f1b21b89c3e93b693874e22e845318cbffeb9835132f12c0bf21f09d850f6e4` |
| `apps/api/src/leviathan_api/market_data_runtime_config.py` | MISSING | `d1e975834654cf42286c9b108f9f9d325ca92f9cccb30fa234d858058d6c7313` |
| `apps/api/src/leviathan_api/observation_runtime.py` | `99fa50712a26da6ab0bc6195231c6d39d09ed4885ffecb118939a3ff449683a8` | `86d1b01dcb8387e012fb6935ffbad9919df607bd5b491ef5d0814ea8da4ac051` |
| `apps/api/src/leviathan_api/paper_mounts_runtime.py` | `046f78088e4a13fc01428cc48d9b1f09417503f6eb918b9f2cf5c985ddb25812` | `d323bd3f8701577b1b796daf5b49f6952f15c0c5c6db4d936ea73cec7155076c` |
| `apps/api/src/leviathan_api/routers/market_data_paper_v1.py` | `362865c065e4eb0cde530c33c025d19075ecf1bbaaf340414828f1c80f5e73a7` | `45411c3e0e8228390be568c44d3879356f8f632ffa87b64bc8c8d280772b1afa` |
| `apps/api/src/leviathan_api/wave35_mounts.py` | `e02924cd109568e3e9de21d4c2ea4507e0af6c85e257589c1dccc47c94cbbc99` | `bbf0a4475ae15e62192b8d12c5d947fe2fe565ba7b2ab289889a41b35fe8693d` |
| `apps/api/tests/test_market_data_paper_v1.py` | `a8fffafb88ced585e84b0bdfc03c62c19ceb8a4da427d7bf11bcf1b30e270501` | `2da09dbfd6befcb31ace5f56cc8ccab03b3d2c7853204ee2d4551e1e74260c9d` |
| `apps/api/tests/test_market_data_runtime.py` | MISSING | `f67c1deba0aef703900dfeafc74d8fd2c23e62dbf0549118365c338c4900303f` |
| `apps/api/tests/test_market_data_runtime_config.py` | MISSING | `1509cc4c118d98a58f2c60a0c193ce24b478da5efbb4941c3aa0121b2bd9ed39` |
| `apps/api/tests/test_operator_principal.py` | `f2150b51a8fe1e0c93868c031f4c6b6f65b6546452693257e35d12cb9740b5ee` | `fb1a5d7f6cda01501994e4cc2527622789a86ba137dd62349c710cc579279f82` |
| `apps/terminal/src/App.tsx` | `a8f39dcee18dac5541e2c900e32a194d9c271ce82c5ecc4413c3e31894a52201` | `a248204b00c6575b943e1cbeac04351aa5c707d2d8d7e6bd562030b2e0395ae1` |
| `apps/terminal/src/wave33/marketData/api.ts` | `6a01105f7ed28052160224844cd1612ebd172f2f7528748ab204e6c7fe228fcb` | `d5febd8bd2ed3a1f3e05d3ce37cd714e3bf1cabe3d2d76282043a9f265ec0a9b` |
| `apps/terminal/src/wave34/charts/LiveMarketDataWorkspace.tsx` | MISSING | `a253f7f1a99cff00d5fb4b25f7dd3af6a635afc8bd0aeb66bd09601bdd4ec861` |
| `apps/terminal/src/wave34/charts/model.ts` | `f71cbf894ae448b01bc397553a9f86ffbedd8348d01ed37e9a81695fc555c803` | `be7f93a6c21d505a8c028e2f0a8089fed408b4c083d69dd81b58d6aa1d776cb8` |
| `apps/terminal/src/wave34/charts/PriceDepthFootprintView.tsx` | `f70781d1c07c742a09d9cdfc848f1c6568f1591467c29752f811b72a692e00d9` | `9b1b296b8ed2a5ee143e5df27fef0bd6834a866296dbd76dec66c1705354265f` |
| `apps/terminal/src/wave34/charts/test/liveMarketData.test.tsx` | MISSING | `1f5dbf404a90d453752a9018f286d02e7c32c0607b2f3c2081e9d1bd01584c17` |
| `packages/leviathan-market-data/pyproject.toml` | `ec45ba91f8d2776534765fc105e2df631b3699ea3205c0a91ce8ce3b09b991c6` | `9d68c4374b4ceee60ac19888eebaa80413a8851cb166cea62725f4ba5e7de1cf` |
| `packages/leviathan-market-data/src/leviathan_market_data/live/backfill_jobs.py` | MISSING | `009dee7cea0446b83b53f823e44daaa4226add5a3987b922c23f86d961669d7e` |
| `packages/leviathan-market-data/src/leviathan_market_data/live/latest_store.py` | MISSING | `92516fe8c5852db44145eb18fa9c74147aa408e4a536e09923dc34f30a58e4af` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/databento_live.py` | MISSING | `46e8bc89d5d3bdeb806e3784797d8c8fecec0819cede751f75e0bedb19e2190e` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/databento_mapping.py` | MISSING | `1cdc454da1043f5307308f9326ca770f5368983e10e2905b307166b1f70133de` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/massive_live.py` | MISSING | `c339a663b791353ef5ef18b1b7dbe9d197fc6b8b65ba63238b0d4d2edd3cee50` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/massive_transport.py` | MISSING | `bcfdcbea4f265bc8ecae0c136535d42f0895087f9769cf53127cc1314a4f1365` |
| `packages/leviathan-market-data/src/leviathan_market_data/py.typed` | MISSING | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `packages/leviathan-market-data/tests/live/test_backfill_jobs.py` | MISSING | `af087b3074b1898ce7ce2505d82a895455a4b7ecb90c0d701eadf0332c24fd5f` |
| `packages/leviathan-market-data/tests/live/test_databento_mapping.py` | MISSING | `c17b4d50ad85308303daee5542c8cb6f3442097c9426076de8e73cb0b0ba7622` |
| `packages/leviathan-market-data/tests/live/test_runtime.py` | MISSING | `bf3168f0439ddf49f241bb9cefbfe407607239fb451ec960f04cf8c5b5ba7041` |
| `packages/leviathan-market-data/tests/test_massive_transport.py` | MISSING | `069a127ead9a71c936e58b9da10b9afb95e5d28b12bbe9ff4aa8cee817b127f9` |
| `qa/acceptance/md_runtime_001/test_md_runtime_001_acceptance.py` | MISSING | `6311d702a84c55e6a4b5d1c8a9a7035f64fb122dfb4639bba0d75b21b6565c0b` |
| `qa/handoffs/MD-RUNTIME-001/cycle-0.md` | MISSING | `729fcac1eacb1bbae3fdef8c54a5078341359e43646786affa949aa380188bf6` |
| `qa/handoffs/MD-RUNTIME-001/cycle-1.md` | MISSING | `8aaf83efe4c1c51fd3493314b8234e1395df72c608124c00f972679aabe1b3f9` |
| `qa/handoffs/MD-RUNTIME-001/cycle-2.md` | MISSING | `c4f761f8b3bbf1ae811d0d6ab7b862aadd1132fef7aa0f068c2eadf78d7726a7` |
| `qa/handoffs/MD-RUNTIME-001/cycle-3.md` | MISSING | `aa1b9a0915de8ef04def389c31494b36fa853ccf63f50a8b149a55f0af85ef13` |
| `uv.lock` | `8217f08bcdd0e017af9947517ad8a25bc0508ea55dfaf05f617cc989d7692c2a` | `815c94a6fadbe1c8c7bef19258b1ef99d259715cf4b5bfa8eab0f3daadfaf4e5` |

The shared security middleware canonical-start SHA is `1491e1d5d486c106ee2b18d10d86624e2066f8171a9c29b0968cdf58f8ebc39d`; frozen SHA is `3dda567cb3b6eece8b38e418f03f840e1e311508f141c1859f16fcba8796cd46`.

## Gates

Import-origin check, with no `PYTHONPATH`: PASS. `leviathan_api`, `leviathan_market_data`, `leviathan_core`, `leviathan_store`, and `leviathan_vault` all resolved under `feature-md-runtime-001-20261008`.

- `uv sync --locked --all-packages`: PASS.
- Focused HTTP principal + W35 WebSocket tests: **59 passed**, 1 existing Starlette/httpx deprecation warning.
- `uv run --locked mypy`: PASS, 428 source files.
- `uv run --locked ruff check . --extend-exclude qa/integration-backups`: PASS; scoped `ruff format --check` for the three changed Python implementation/test files: PASS.
- Full Python command `uv run --locked python -m pytest apps/api/tests packages/leviathan-market-data/tests qa/acceptance/md_runtime_001 apps/desktop/sidecar/tests packages/leviathan-vault/tests infra/release/tests qa/acceptance/pkg_mac_001_phase_a -q`: **2,877 passed, 38 skipped, 1 failed**, 15 warnings. The only failure is `qa/acceptance/md_runtime_001/test_md_runtime_001_acceptance.py::test_real_app_chart_websocket_authorized_snapshot_then_fake_feed_delta`: the test omits the required exact loopback Host header, so middleware returns 4403 before accept. Acceptance update pending; owner `e51a5665`. The test-owned correction is not included in this freeze.
- Terminal `npm.cmd run test -- --pool=forks --maxWorkers=1 --no-file-parallelism`: **1,399 passed, 1 skipped**.
- `npm.cmd run build`: PASS, 89 modules.
- `npm.cmd run lint`: PASS with the existing `PaperMarketDataHealthView.tsx:154` `refreshVenues` dependency warning.

`main.py` remains unchanged. The WebSocket refusal rules preserve exact Host/Origin checks; tests use explicit loopback Host because Starlette's test handshake does not supply the production browser Host in this setup. No live-provider smoke or latency measurement was run.
