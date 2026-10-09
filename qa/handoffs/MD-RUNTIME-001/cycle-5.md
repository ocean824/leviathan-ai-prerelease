# MD-RUNTIME-001 cycle 5 freeze

**State:** Frozen for the browser chart-stream ticket correction. Live provider smoke remains outstanding. No provider calls, real vault-key resolution, canonical-repo writes, or commits were made.

## Change

Added an HTTP-minted, opaque, single-use chart stream ticket for browser WebSockets. Tickets are random `token_urlsafe(32)` values, bounded by a 1,024 default / 4,096 maximum in-memory store, TTL capped at 30 seconds, stored as SHA-256 digests, and compared in constant time. Ticket bindings cover the issued principal, verified local profile, exact request Origin and one venue/instrument/data-type scope. Store overflow evicts the oldest ticket. Invalid or wrong-scope ticket presentations do not authorize a socket; a valid ticket is consumed before accept. Wrong or missing Host/Origin is rejected before ticket consumption. The socket selects only `leviathan.chart.v1`; the ticket is never put in the URL or logged.

The `/api/md/chart/ticket` POST remains behind the existing operator-principal middleware and default W35 principal resolver. WebSocket middleware requires the exact configured loopback Host and Origin, and permits either the existing capability evidence for non-browser clients or the scoped browser ticket. Terminal obtains a fresh ticket through the existing API client before each socket and remints on reconnect. Failed ticket minting and socket closure remain visibly disconnected/stale.

## Canonical sync and actual directory diff

Canonical source root: `C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\LEVIATHAN AI\repo`. Full hash walk excluded only `.git, .mypy_cache, .next, .nox, .pytest_cache, .ruff_cache, .tox, .venv, .vite, __pycache__, build, coverage, dist, htmlcov, node_modules, target`. At freeze: canonical **1631 files**; worktree **1658 files** excluding this self-referential cycle-5 ledger; canonical-only/missing in worktree **0**; differing or worktree-extra paths **42**. The path/hash table below is generated from that full directory comparison (including prior cycle handoffs); no canonical-only files were found.

| Worktree path | Canonical-start SHA-256 | Frozen SHA-256 |
| --- | --- | --- |
| `apps/api/config/local-paper-market-data.example.toml` | MISSING | b4625fc74e639d7b54e414da048171c104c6f00f97de0354e972c340a3e086da |
| `apps/api/src/leviathan_api/auth/__init__.py` | 970b9b2ca745d33e517211a8793145624446ea5c15eec7932008bfc7e0f32830 | 8ff13de9aca5d0865f7e2d5441708876d2af27d59b16a6a8cc131e4bcf3672ba |
| `apps/api/src/leviathan_api/auth/chart_stream_tickets.py` | MISSING | 4f9abf8cb217283284320a60aeb30df597c2f0f4755e6fab2d1340c05ede751e |
| `apps/api/src/leviathan_api/auth/operator_principal.py` | 1491e1d5d486c106ee2b18d10d86624e2066f8171a9c29b0968cdf58f8ebc39d | 4a8cfea91ad22a61aafec1551e75316e81253ca1ecea516d55e0c8722f50b8ef |
| `apps/api/src/leviathan_api/market_data_backfill.py` | MISSING | e3e2fc93271df912834035e75b7b982ca2f2e2e4be53a8bf85e5aeb31e0b956c |
| `apps/api/src/leviathan_api/market_data_runtime.py` | MISSING | 6f1b21b89c3e93b693874e22e845318cbffeb9835132f12c0bf21f09d850f6e4 |
| `apps/api/src/leviathan_api/market_data_runtime_config.py` | MISSING | d1e975834654cf42286c9b108f9f9d325ca92f9cccb30fa234d858058d6c7313 |
| `apps/api/src/leviathan_api/observation_runtime.py` | 99fa50712a26da6ab0bc6195231c6d39d09ed4885ffecb118939a3ff449683a8 | 86d1b01dcb8387e012fb6935ffbad9919df607bd5b491ef5d0814ea8da4ac051 |
| `apps/api/src/leviathan_api/paper_mounts_runtime.py` | 046f78088e4a13fc01428cc48d9b1f09417503f6eb918b9f2cf5c985ddb25812 | d323bd3f8701577b1b796daf5b49f6952f15c0c5c6db4d936ea73cec7155076c |
| `apps/api/src/leviathan_api/routers/market_data_paper_v1.py` | 362865c065e4eb0cde530c33c025d19075ecf1bbaaf340414828f1c80f5e73a7 | e0c322057b829919cb7dc930209a86cc7661d98edfb93194c8fbabe244d0a84a |
| `apps/api/src/leviathan_api/wave35_mounts.py` | e02924cd109568e3e9de21d4c2ea4507e0af6c85e257589c1dccc47c94cbbc99 | d0c70304b112dcd3c39616cf67cf779a5c6017bd6f24a5c04c048508080a3b55 |
| `apps/api/tests/test_market_data_paper_v1.py` | a8fffafb88ced585e84b0bdfc03c62c19ceb8a4da427d7bf11bcf1b30e270501 | 2da09dbfd6befcb31ace5f56cc8ccab03b3d2c7853204ee2d4551e1e74260c9d |
| `apps/api/tests/test_market_data_runtime.py` | MISSING | f67c1deba0aef703900dfeafc74d8fd2c23e62dbf0549118365c338c4900303f |
| `apps/api/tests/test_market_data_runtime_config.py` | MISSING | 1509cc4c118d98a58f2c60a0c193ce24b478da5efbb4941c3aa0121b2bd9ed39 |
| `apps/api/tests/test_operator_principal.py` | f2150b51a8fe1e0c93868c031f4c6b6f65b6546452693257e35d12cb9740b5ee | fb1a5d7f6cda01501994e4cc2527622789a86ba137dd62349c710cc579279f82 |
| `apps/terminal/src/App.tsx` | a8f39dcee18dac5541e2c900e32a194d9c271ce82c5ecc4413c3e31894a52201 | a248204b00c6575b943e1cbeac04351aa5c707d2d8d7e6bd562030b2e0395ae1 |
| `apps/terminal/src/wave33/marketData/api.ts` | 6a01105f7ed28052160224844cd1612ebd172f2f7528748ab204e6c7fe228fcb | 9b2245b7cc728dfdc4635c6fef25fd9a3478a01a0d680abaa86d1172bf251b3f |
| `apps/terminal/src/wave33/marketData/test/paperMarketDataHealth.unit.test.tsx` | d1a622e8a1a2e1518bf82a08f395cdb58ced00be7e0ce144f9b66f57b64fc840 | 776a8e3196340a8a61ec86e63f13042a7b1b43c28ec59194900ed9f54d6bd21c |
| `apps/terminal/src/wave34/charts/LiveMarketDataWorkspace.tsx` | MISSING | 79953ed7eef48143624304532e712db5f2e868cee6cdab736837a10bf0a69e30 |
| `apps/terminal/src/wave34/charts/PriceDepthFootprintView.tsx` | f70781d1c07c742a09d9cdfc848f1c6568f1591467c29752f811b72a692e00d9 | 9b1b296b8ed2a5ee143e5df27fef0bd6834a866296dbd76dec66c1705354265f |
| `apps/terminal/src/wave34/charts/model.ts` | f71cbf894ae448b01bc397553a9f86ffbedd8348d01ed37e9a81695fc555c803 | be7f93a6c21d505a8c028e2f0a8089fed408b4c083d69dd81b58d6aa1d776cb8 |
| `apps/terminal/src/wave34/charts/test/liveMarketData.test.tsx` | MISSING | beafc7f2b15e2f8cf327e408cf253ccf02e7a8bc16b4ccaae643bffa83535221 |
| `artifacts/leviathan-build/market-data-buildout/md-runtime-acceptance/index.md` | MISSING | 7fcc54e6f23c604227741abd3efae0e23b40541804ca0e27ae2faa7bcd023b24 |
| `packages/leviathan-market-data/pyproject.toml` | ec45ba91f8d2776534765fc105e2df631b3699ea3205c0a91ce8ce3b09b991c6 | 9d68c4374b4ceee60ac19888eebaa80413a8851cb166cea62725f4ba5e7de1cf |
| `packages/leviathan-market-data/src/leviathan_market_data/live/backfill_jobs.py` | MISSING | 009dee7cea0446b83b53f823e44daaa4226add5a3987b922c23f86d961669d7e |
| `packages/leviathan-market-data/src/leviathan_market_data/live/latest_store.py` | MISSING | 92516fe8c5852db44145eb18fa9c74147aa408e4a536e09923dc34f30a58e4af |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/databento_live.py` | MISSING | 46e8bc89d5d3bdeb806e3784797d8c8fecec0819cede751f75e0bedb19e2190e |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/databento_mapping.py` | MISSING | 1cdc454da1043f5307308f9326ca770f5368983e10e2905b307166b1f70133de |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/massive_live.py` | MISSING | c339a663b791353ef5ef18b1b7dbe9d197fc6b8b65ba63238b0d4d2edd3cee50 |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/massive_transport.py` | MISSING | bcfdcbea4f265bc8ecae0c136535d42f0895087f9769cf53127cc1314a4f1365 |
| `packages/leviathan-market-data/src/leviathan_market_data/py.typed` | MISSING | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| `packages/leviathan-market-data/tests/live/test_backfill_jobs.py` | MISSING | af087b3074b1898ce7ce2505d82a895455a4b7ecb90c0d701eadf0332c24fd5f |
| `packages/leviathan-market-data/tests/live/test_databento_mapping.py` | MISSING | c17b4d50ad85308303daee5542c8cb6f3442097c9426076de8e73cb0b0ba7622 |
| `packages/leviathan-market-data/tests/live/test_runtime.py` | MISSING | bf3168f0439ddf49f241bb9cefbfe407607239fb451ec960f04cf8c5b5ba7041 |
| `packages/leviathan-market-data/tests/test_massive_transport.py` | MISSING | 069a127ead9a71c936e58b9da10b9afb95e5d28b12bbe9ff4aa8cee817b127f9 |
| `qa/acceptance/md_runtime_001/test_md_runtime_001_acceptance.py` | MISSING | 6b62df3d78bd4f3013f0fc05512687893b318e5c61086535a5896513662e7203 |
| `qa/handoffs/MD-RUNTIME-001/cycle-0.md` | MISSING | 729fcac1eacb1bbae3fdef8c54a5078341359e43646786affa949aa380188bf6 |
| `qa/handoffs/MD-RUNTIME-001/cycle-1.md` | MISSING | 8aaf83efe4c1c51fd3493314b8234e1395df72c608124c00f972679aabe1b3f9 |
| `qa/handoffs/MD-RUNTIME-001/cycle-2.md` | MISSING | c4f761f8b3bbf1ae811d0d6ab7b862aadd1132fef7aa0f068c2eadf78d7726a7 |
| `qa/handoffs/MD-RUNTIME-001/cycle-3.md` | MISSING | aa1b9a0915de8ef04def389c31494b36fa853ccf63f50a8b149a55f0af85ef13 |
| `qa/handoffs/MD-RUNTIME-001/cycle-4.md` | MISSING | eac0fe0f0526badebddf1286ee98e801a5e76787ec9ca6e95c00194d7f8da731 |
| `uv.lock` | 8217f08bcdd0e017af9947517ad8a25bc0508ea55dfaf05f617cc989d7692c2a | 815c94a6fadbe1c8c7bef19258b1ef99d259715cf4b5bfa8eab0f3daadfaf4e5 |

## Dependency delta

No cycle-5 dependency change. The retained MD-RUNTIME dependency delta from canonical is `databento-dbn==0.71.0; python_version < '3.15'` in `packages/leviathan-market-data/pyproject.toml` plus its lock entries; no full Databento SDK was added. Prior verification recorded Apache-2.0 metadata and cp314 Windows x86_64 wheel SHA `b5ebcb1ef3c9cabc4c598ef54668dd4e81a555790eed70c94d697af7d3557c4f`, macOS universal2 (arm64+x86_64) SHA `48c0f13003e7012386d4998e1a60441d0f24d12ae2849b914070d5f381cf3874`, and macOS x86_64 SHA `b2cc4a6afcda102f0c9bd26e4b1f6662e77f893a2415d725025f0e5a5042236b`. Current canonical `uv.lock` start hash is `8217f08bcdd0e017af9947517ad8a25bc0508ea55dfaf05f617cc989d7692c2a`; frozen worktree `uv.lock` is `815c94a6fadbe1c8c7bef19258b1ef99d259715cf4b5bfa8eab0f3daadfaf4e5`. The canonical Darwin keyring delta is preserved.

## Gates and evidence

- `uv sync --locked --all-packages`: passed (58 packages resolved; 48 checked).
- Worktree import-origin check for `leviathan_api`, `leviathan_market_data`, `leviathan_core`, `leviathan_store`, `leviathan_vault`: all five `__file__` paths were inside the worktree.
- `uv run --locked mypy`: **Success: no issues found in 429 source files**.
- `uv run --locked ruff check . --extend-exclude qa/integration-backups`: **All checks passed**.
- `uv run --locked python -m pytest apps/api/tests packages/leviathan-market-data/tests qa/acceptance/md_runtime_001 apps/desktop/sidecar/tests packages/leviathan-vault/tests infra/release/tests qa/acceptance/pkg_mac_001_phase_a -q`: **2,878 passed, 38 skipped, 15 warnings** (265.24s). This module invocation is used because the `uv run pytest` launcher initially selected the canonical launcher and failed collection; the worktree interpreter/module run passed.
- Independent cycle-5 acceptance `qa/acceptance/md_runtime_001/test_md_runtime_001_acceptance.py`, SHA `6b62df3d78bd4f3013f0fc05512687893b318e5c61086535a5896513662e7203`: **16 passed**. Acceptance handoff `artifacts/leviathan-build/market-data-buildout/md-runtime-acceptance/index.md`, SHA `7fcc54e6f23c604227741abd3efae0e23b40541804ca0e27ae2faa7bcd023b24`.
- Focused API route/middleware/W35 tests: **42 passed, 2 warnings**; scoped mypy and Ruff passed. Acceptance author's combined focused backend/operator/acceptance set: **90 passed**.
- `npm.cmd run test -- --pool=forks --maxWorkers=1 --no-file-parallelism`: **66 files passed; 1,400 passed, 1 skipped**. Focused chart workspace suite: **3 passed**.
- `npm.cmd run build`: passed (`tsc -b`, Vite production build).
- `npm.cmd run lint`: exit 0. Existing warning remains at `src/wave33/marketData/PaperMarketDataHealthView.tsx:154` (`refreshVenues` hook dependency); no cycle-5 warning remains.
- Scoped `ruff format --check`, Ruff, and `git diff --check`: passed. `git diff --check` emitted only pre-existing CRLF normalization notices in unrelated Journal, risk lock and import-boundary files.

No live provider connection or secret read was attempted. Deployment/live feed availability and latency remain for the coordinator's post-integration smoke.
