# API-ANYTHING-001 Cycle 2 freeze ledger

- Generated at: `2026-10-10T04:27:34+00:00`
- Baseline: `qa/handoffs/API-ANYTHING-001/cycle-2-start.json` (1737 files; SHA-256 `bb2e5731332790b3d6917a480e447dfdb1f16fe0d7fa6ded4758b50329dc8af8`)
- Source Cycle 1 ledger: SHA-256 `0c34208cf8b400c8e4e324640c3cc4207c1a40d794deca76e5683f8b1140158e`
- Diff totals: 9 added, 25 modified, 0 deleted.
- Excluded build/runtime directories: `.git`, `.venv`, `node_modules`, `target`, `dist`, Python caches, `.scratch`, and `.vendor-build`.
- The three `public_sources/{registry.py,sources.py,__init__.py}` files are omitted from this lane ledger because they belong to PUBLIC-DATA-001 and match its C2C-frozen copies.
- The stray Cycle 1 artifact copy is omitted; it was removed from this worktree.

## Cycle 2 changes

- Removed all `AA_CONTROL` production behavior. The test-only network seam stays outside `dist`; reviewer acceptance launches the production entrypoint.
- Patched vendored learn handling to classify structured bot-wall signals as typed challenges and hand off to a visible isolated Chrome window. The vendor patch includes package metadata and TypeScript configuration changes; its SHA-256 is `561f5f9159c10b4323db62f6917ddca931ab1274c9fa76480a6fd8068eff6d94`.
- Added per-operation `challenge_hosts` arrays to the committed pin registry and candidate metadata. Each is intentionally empty pending a reviewed third-party challenge origin; data-request host allowlists remain strict.
- Split pin approval (90 days) from canary freshness (48 hours). Successful calls count as semantic canaries; due failures abstain.
- Export/import now targets the sidecar's committed `templates/` tree. Added cross-tree replay-only E2E with fake network injection outside `dist`.
- Candidate learn and repair templates are credential-scanned and replayed against a sanitized recorded fixture before candidate metadata and its fixture digest are persisted.
- The Python client verifies `PINNED.json` against the build-generated registry hash. The current registry SHA-256 is `ac4cc2b5d18ec89b55f79580e09a8a63b885a803a0bb8ac264eca3ed1020f967`.
- All lockfile package entries now include `resolved` and `integrity`; `npm ci --ignore-scripts --offline` installed 23 packages successfully with no reported vulnerabilities.
- Removed the API-ANYTHING-specific exception from root `pyproject.toml`; scoped acceptance lint exceptions live in the acceptance directory.
- Official platform check: Node 22 has macOS x64 builds; current Playwright requirements specify macOS 14+, so Big Sur 11.7 uses replay-only mode without Chrome. This Intel Mac was not tested on-device.
- Live learning remains paused; no operation is pinned. No network learning was performed in Cycle 2.

## Verification

| Gate | Result |
|---|---:|
| Coordinator acceptance findings (`-k finding`) | 6 passed, 153 deselected, 3 xfailed, 1 xpassed |
| Cycle 1 production policy suite | 60 passed |
| Cycle 2 cross-tree export/import replay-only E2E | 1 passed |
| Market-data api-anything client tests | 20 passed |
| `npm test` | 9 passed |
| Ruff (`--extend-exclude qa/integration-backups`) | passed |
| mypy default / Linux / Darwin | all three passed for `api_anything_client.py` |
| `packages/leviathan-core/tests` | 6,578 passed, 10 skipped, 1 xfailed |
| `packages/leviathan-store/tests` | 548 passed, 2 skipped |
| `packages/leviathan-vault/tests` | 1,475 passed, 1 skipped |
| `packages/leviathan-market-data/tests` | 163 passed, 36 skipped |
| `apps/api/tests` | 1,149 passed |

The six unmodified reviewer acceptance finding tests pass. All project pytest roots were run in separate processes.

## Diff-generated file inventory

| Status | Path | Old SHA-256 | New SHA-256 | New bytes |
|---|---|---|---|---:|
| added | `artifacts/leviathan-build/market-data-buildout/api-anything-001/index.md` | `-` | `4c9ed749eee2f2617dd2764a1c03acb392e86cd21150eba998813deb60cda3b9` | 3068 |
| modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/api_anything_client.py` | `92d8c6ac5bcd59773e78ee5088de4d3160d8ce116339d63d4eb0bf3918560afc` | `ca669f94dbef82f6c7be681f333b1f2808761befa0ff6fbcf9f8a4a54edccd24` | 39189 |
| modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/api_anything_registry.py` | `daf47d82aefee2cbb12678d2bde13c8771397256510d1de3327892904dd87ebd` | `e97b35fd799aa8a4b2b79a081c7886b650b9565182dd1f18fb5b0681ab408161` | 5145 |
| modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/api_anything_templates.py` | `af03d8d6893474d6799cf51b38aa5d4a308f5b8cbf3dba2f1bcdc50e9635818a` | `14017dcdeb2311d34fae4f9d402f7f2fd9057732d1cbdc65aa408faf0e7c7f56` | 5202 |
| modified | `packages/leviathan-market-data/tests/fixtures/api_anything_fear_greed.json` | `c523606a01b59c7bbdbf509801af3cdaf9e68c9498d345f1ffc69bc35b8d32bc` | `ce157a730cdc503a4a0e5f155c5bd0a9bb0c291afc809ea5290fc6d4ac35596a` | 1135 |
| modified | `packages/leviathan-market-data/tests/test_api_anything_client.py` | `6b76aedd16b89812af1380d2b619650780320b56faa69b22b171732134121cc3` | `618037cf91294bbaed6fcac722502a51a08764418fe6dd4a28eca08f436c3a86` | 12879 |
| modified | `pyproject.toml` | `90fada55ceb5d5cc60678aca9df5e7e4da4361ff2ac135af3ef600c766b20ca1` | `26f2c0abc7a22a21e6214096e75be69c876d0b3ed8171c9370c5f2f3a1474251` | 1844 |
| modified | `qa/acceptance/API-ANYTHING-001/aa_harness.py` | `16646aa5edd7d23b8d2d3273b4e88be0c3fb9603191f3deca5ebde40a03159a8` | `e54d60887ffb55807900eece4efc6c682b5e2d5310ec38d6b186ad9c806350fb` | 18666 |
| modified | `qa/acceptance/API-ANYTHING-001/conftest.py` | `6abcea4ec999a2cec70343a5f607f66188d6e2f4af92573572afa7d678ab26c4` | `7795e050d59afcbbdd5ff21380602b3060add5da7df26a948d51830613a5f266` | 6446 |
| modified | `qa/acceptance/API-ANYTHING-001/cycle1/c1_harness.py` | `325a713b12f7538a31c7872128e33091b554d449ae7dc9cca28d0a28cfc0c6c1` | `ab07f909d77f16419e3037f5a24acf5f34a6c28495e64b4b2ccd69145239ff99` | 19140 |
| modified | `qa/acceptance/API-ANYTHING-001/cycle1/test_c1_pins_policy.py` | `6bece367bdfe36ccde99e1d2768e6f20322f9e5117fb0c1e5929342c961d6531` | `13a3b2f58841d22d6612682ae13afee479d0f9c2d286cc7f3e3a0fe89ede9f18` | 18248 |
| added | `qa/acceptance/API-ANYTHING-001/cycle1/test_c2_template_transfer_replay.py` | `-` | `6f3410c3ad44f8e5cc2efe39d2f5d003d047de01737f1a20d2b5faf9d5390aa7` | 2421 |
| added | `qa/acceptance/API-ANYTHING-001/loopback-injection.mjs` | `-` | `e4f192646299c67b076e9c55415d3ffbb12e2678be8c0b88bc58930ad38c799e` | 724 |
| added | `qa/acceptance/API-ANYTHING-001/offline-injection.mjs` | `-` | `1df82e24ef3113846b240818963aca9455bcf8ee2bad77f45f198bfebf0a631f` | 477 |
| added | `qa/acceptance/API-ANYTHING-001/pyproject.toml` | `-` | `a1aaa7feb5297d3a012ab36ed01abb3efb9cc50f0b0d7615a0d4b896aeb3e4ed` | 265 |
| modified | `qa/acceptance/API-ANYTHING-001/test_03_real_vendor_loopback.py` | `9a0806b968d77aa72d627004c819ad451bee5c9a8b0d84d0e780fe1940baacc6` | `7da315eb703b761f84174c05e3beb68a4e894dc8c1c1aa6c529b3bcdb8ddbd9a` | 8048 |
| added | `qa/handoffs/API-ANYTHING-001/cycle-2-start.json` | `-` | `bb2e5731332790b3d6917a480e447dfdb1f16fe0d7fa6ded4758b50329dc8af8` | 347090 |
| added | `qa/handoffs/API-ANYTHING-001/generate_cycle2_ledger.py` | `-` | `d2ac413b2a06e58a0e8dfb31518d443de13e8038ddd06c3d540de5572fe2a604` | 7279 |
| added | `services/public-collector/e2e/stdio.test.mjs` | `-` | `0a2df55c4b4e8b0a11f1bc13453c5640c7cdce74d9a4a3a480bdcd36d893247b` | 2448 |
| modified | `services/public-collector/package-lock.json` | `7463c4c3f2a909d2c28059c6341c188b2eec5b89a160342e4c8cd74b94f32290` | `46585fe26da38cc50400bbd201dde0cd1d592d11a06dc2fb2d521735f3a19c4c` | 36933 |
| modified | `services/public-collector/package.json` | `b123c421380fd0cb421154f0569e44ab4bcf251a18cad470b27526bfe36fdbb5` | `fd670ee3c95907aee259787ebfacfd1b4fbfa20196d618e29075e43c542ece9a` | 554 |
| modified | `services/public-collector/patches/api-anything-runtime.patch` | `2354cdb5660eb933ee82b6b52d385eaf2744a86c53e8da42e055150a421b665a` | `561f5f9159c10b4323db62f6917ddca931ab1274c9fa76480a6fd8068eff6d94` | 9730 |
| modified | `services/public-collector/runtime-manifest.json` | `0db2f97a57072019548736554d5691278cafb6b7f1d1e77fdd720d5ce8c9bfb4` | `1a7b1dea7db74c567daab14ecf399e9f87bb08a8f2f320204b973bb9f2649c87` | 459 |
| modified | `services/public-collector/scripts/build-vendor.mjs` | `b369ce8c5ff5732bdae2f6402ee4df9db1bd40d735315fcb17750d072bc9636b` | `a5135ef2da0b8f3029a40f80d74bfef01d42612f05f61a14588bdf3c9e690147` | 3985 |
| modified | `services/public-collector/src/challenge.ts` | `1a66b7621226b436f2c604adc700383217c85a37b799eab58e0761b4ea5dcaba` | `f1a8ac98503e63098f09a238f3ae0bc90585873dd8a88f45300c9b842c1af144` | 5174 |
| modified | `services/public-collector/src/contracts.ts` | `a29e4c3c7e52862ed8a618cf9bfaa44aad30a405fda14709a6e3d465864c1d18` | `49079e92f168092d29211ea6334a8d9b92501f8518b63718f28222e8e7f871ca` | 7892 |
| modified | `services/public-collector/src/main.ts` | `0259f2ac0994994ab78b7b4deabc7673d8fbc2a069339bf66c28a856af03fb98` | `0ccadc8e28ed4d2e566c0ba309180db063ddc58bfe3501eb09d3538cf6cfcb4d` | 44179 |
| added | `services/public-collector/src/pin-hash.ts` | `-` | `a1e1ecbc16764a2063f4bedd43603e33e7f576b19bef694b908272b5d6cf1f80` | 172 |
| modified | `services/public-collector/src/robots.ts` | `6ab00a83ee01a8ee309cf48a495f9b94a955bb71d575e029beac06e02af36c16` | `fc88d30ed36c10d31dbf6a8da8b89914e27f63ea15145231635b858878fb941a` | 5742 |
| modified | `services/public-collector/templates/PINNED.json` | `169c5956dc9da097d39b78824ca59831354fb42bfe76dd671fc2f0a1614352f5` | `ac4cc2b5d18ec89b55f79580e09a8a63b885a803a0bb8ac264eca3ed1020f967` | 3015 |
| modified | `services/public-collector/vendor/api-anything/package.json` | `5349af07d72cd721a15a99285a680bc7053db1fed12c6006aac43b97df37b339` | `ebeddc284e88eebad100e4c7c218105fd787b4d4a5b3ed914862d06c8f00aaed` | 926 |
| modified | `services/public-collector/vendor/api-anything/src/browser.ts` | `3fdb28de2435a9abeaed390ed04937cdbe1887e6476b9cebd0aca7517c9f3d0f` | `a99622a66ffc0faae89652cec18468f50e6299d5a96cead2a4d52a222152d1bc` | 52510 |
| modified | `services/public-collector/vendor/api-anything/src/heal.ts` | `97b73b9877a2d8becee26674975cdd3a43131166eb90b52b5685ac0fe6d82a22` | `16d421326624480a7597eac966e1c6f1cfd633520d4965fbea23626dc08a4157` | 52319 |
| modified | `services/public-collector/vendor/api-anything/tsconfig.build.json` | `82abaa23e09117edea58a3aa677ad5420920cd688fb9301a2b49a83f26922791` | `c0474231d1b524f86e897d2eae73acbeebab79cb69a72ca06a5819850e51bcc9` | 413 |
