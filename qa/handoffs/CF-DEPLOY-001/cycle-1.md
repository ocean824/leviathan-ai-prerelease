# CF-DEPLOY-001 cycle 1 freeze ledger

## Scope and source snapshot

Cycle 1 rebases the deploy-preparation work onto the current canonical working tree while retaining the PKG-MAC platform/Keychain changes. The canonical-start copy was made from working-tree bytes (not Git blobs), with `.git`, `.venv`, `node_modules`, `target`, `dist`, `.pytest_cache`, and `.mypy_cache` excluded. Canonical HEAD at copy: `d3208136d1872cf6e0bb33ec79aa06f01de98562`.

- Canonical-start manifest: `qa/handoffs/CF-DEPLOY-001/cycle-1-canonical-start.json`
- Manifest SHA-256: `b53292c44e04ea55deb28aef95cdcf6a2df5d1706825a46b944f78d4c91db94a`
- Manifest scope: 54 copied paths; all manifest paths were compared against the current canonical working tree before freeze.
- No files were written to `repo\`; no commit was created.

## Changes

- Bound Stripe webhook `livemode` to explicit `STRIPE_MODE`: Test accepts only `false`, Live only `true`. Mismatches return fixed 422 and emit only `STRIPE_MODE_MISMATCH`; no ledger state is written.
- Deploy script defaults to `-StripeMode Test`; Live is explicit and uses the existing live Stripe vault entries. It creates/reuses the exact webhook endpoint and stores the returned signing secret in the selected environment's vault name before supplying it to Wrangler through stdin.
- Signing-key initialization stores a validated keypair as one atomic encrypted vault value. Matching retries are idempotent; mismatched/invalid pair state fails with remediation guidance and never silently overwrites.
- Added complete registry entry schemas for generated live secrets, Stripe webhook secrets, Stripe test API key, and provider keys.
- Updated Workers.dev origins, desktop updater and licence origins, Admin origins, and the configurable data-gateway client. Local loopback development overrides remain supported.
- Updated the Windows Tauri updater endpoint only. `apps/desktop/src-tauri/tauri.conf.json` SHA-256 is `9a55edc96e874f195af3f1f58191d13d3a1d58db81ce4cd2c6ca9f983e6b73ff`; changed key: `plugins.updater.endpoints[0]`. `bundle.targets`, `createUpdaterArtifacts`, and other bundle semantics are unchanged. The existing PKG-MAC acceptance hash pin remains untouched and needs the coordinator-routed pin update.
- No deploy, Wrangler login, provider API call, or secret read was performed.

## Changed file hashes

Hashes are SHA-256 of working-tree file bytes. `NOT_PRESENT` means the path did not exist in the canonical-start manifest.

| Path | Canonical-start SHA-256 | Cycle-1 SHA-256 |
| --- | --- | --- |
| `apps/admin/qa/vitest.config.ts` | `17339765b53c96eb6ca62d927f83bf3d9c2042dbfc708071ee7cc55206826eba` | `2ebfe27c4252a888901e56b7ff8cb00d65d83655e00a9ea574c291cbb35e7354` |
| `apps/admin/scripts/build.ps1` | `e5733eee23311ad7a50758d53500a68742cd8728048522cfb2d540c3b075b36a` | `8f2f15a9896627c01ace29c6ccbad9e0d0e4ae92d00a2022b65f29b2acd5d867` |
| `apps/admin/src-tauri/tauri.conf.json` | `d45a6fdd3b269e5f919720442625b870c85d5b682bd21c99dc7866558f414350` | `b4a900c5d4f247d6d81d2b051e6850749c4ab3ccbe1a8f7511e10790d01ca1d7` |
| `apps/admin/ui/src/test/AdminApp.enrollment.acceptance.test.tsx` | `1fb71351b2592bc0e4df8e66919e5918feb8d73ce675d92bddc1e21fa4dfa68d` | `d4de164e4a43e347410c8dd83da21833e3791de51215a5f4d40284162c27ae58` |
| `apps/admin/ui/vite.config.ts` | `aa462bf9591e27695360b0ff2bbaa9a5c11afa66067bbd310d073affff861d40` | `744266d1b73ea0a30782a30f39c80618e50b183ba220e84be3f4856d7b81c04e` |
| `apps/admin/ui/vitest.config.ts` | `aa46c62d85def4952156e039dafd0907f108acc69fc50a0e484a8c3713b4af12` | `0c751bc2e65709be47912ed0fd0a805f64604a254dc732681f27bc395f0f64bf` |
| `apps/desktop/src-tauri/src/license.rs` | `a6fa16891dabf06571baac1e24a9aebc01e6bd5fb082cc98f4f8d974843213b8` | `41bc7fddd9494fe53570a53b09130f9469278af2bdc61af5b932c85fab771c9f` |
| `apps/desktop/src-tauri/tauri.conf.json` | `122b7c90800305cece8a18a9cb6e49d929e8e94b266bcb3f003324873ed765fa` | `9a55edc96e874f195af3f1f58191d13d3a1d58db81ce4cd2c6ca9f983e6b73ff` |
| `infra/release/cloudflare/Deploy-LeviathanWorkers.ps1` | `` | `398e538fc04786176e59964c63b1b9a33675f2a1fb1aa356b86b8a7e15de186b` |
| `infra/release/cloudflare/README.md` | `` | `f90f13e6cadf664c8ac67b8277970df7d1dd02fa732a772c802201a879668953` |
| `infra/release/cloudflare/SECRET_REGISTRY.entries.json` | `` | `7b71a846a03eafec358c9681c025743ddf5d7a59e37d85afb67a14db1989ce6a` |
| `infra/release/cloudflare/SigningKeyPair.psm1` | `NOT_PRESENT` | `643281d71cc799a131cf6916138e0ef7c203489b1d0f86f7c84bf55acf7504f6` |
| `infra/release/feed.json` | `a03ac2344aa01dcc700bb28f66069cafddf321f2bcea84fe206c501503d7f9c0` | `e1f226151ccc96716bb5f92c91760205c053713af60a1a7393ab9a3a96363e08` |
| `infra/release/license_worker.json` | `e9601b152afc668d9a3a4073738043ccffae5e9313c60369ee657028cbb19d9c` | `e9bf3c60609f4cbffecf2aece4df498fb366b885fd9c0987ff1e673bcd1facdd` |
| `infra/release/tests/SigningKeyPair.Tests.ps1` | `NOT_PRESENT` | `d026528a558d051ef889ff68614ea571a54f289755e0ef4c4cf9ac5f78b4e542` |
| `infra/release/tests/test_cf_deploy001_acceptance.py` | `` | `a51d3354d5f1bd08c99421c0268c0c5d9145254309aa1739f4ce63c15ec60b1d` |
| `infra/release/tests/test_update001_acceptance.py` | `6921638855ea22b5c5efbaca1d475d0b47c25cd0f9621e19e13a7a03df45c570` | `056c73a748475254172385221644e0de5aca6f600c4b34c85ce955594cfb722e` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/gateway_client.py` | `0bf4e7b59eb1ba4eca3e160b86e886dd7a12563cf58e1ea160dd01b0bc7942e9` | `d39833a3cd3d0158b5a331ffd9833fdff5c98493d2f7361fa7e6ada24166ba29` |
| `packages/leviathan-market-data/tests/wave34/test_gateway_client.py` | `ebc2bf9c1c75326d3fac326b741aa10a084d8f95e4ee5e92b18c48e6fe1a8b17` | `48f0b3e1ccb7c182c1f10dc6a94c4c7c13291ad6c63885639ad4677eb4bfde1d` |
| `workers/data-gateway/src/handler.ts` | `ed01b4126e08767f3f5f870c84555cfb46a68b278cb57f581cb292bb69be071d` | `bf6f2a0209c7cd9f4dd19253db80b44f4c7aa1251ac99f8ce1fcbf46105028c4` |
| `workers/data-gateway/tests/gateway.unit.test.ts` | `0b20b0926e1c9f7d761603e750a413d9e2f6ca868b2314e3aced4d36d45e1a42` | `38def8c79d335486b5469fb6256fb0ee1d2a08e8cbb6cb63ae3d9ab03052e9f6` |
| `workers/data-gateway/wrangler.toml` | `ecfd2e10e293978b763a33680ad214396ac66dc97fe3872a87d84c32d0ea092d` | `d3d876d7b6f44387a820c3733de159920f7d80df18da34db0bee40d7ad4379c3` |
| `workers/licensing/src/signup/handler.ts` | `7727785ed02bc0fcdc64afc7b3431c66deb5884464f06ef353e79edd9ce31787` | `3714660bc1342aededf8479d2a1e10a3fadf2773efa47ecf42464c2f0a0e9f36` |
| `workers/licensing/src/signup/models.ts` | `98138dfb658bbefdd58a25c4e36dd3e79b47cceeca9f8f04667fd78cfe1c1b2c` | `d28dbfbe014b497512a465442d78a4d1bf716075e9e7c17455b875d77438a9ed` |
| `workers/licensing/src/signup/routes.ts` | `d829a54ae16d3479814b261138784bce3617f13df1b842b0608075fa74f0fc46` | `44eefcb84db5752703adf94a71c6670898dc1e43670b1c1d07c629b165a9546e` |
| `workers/licensing/src/signup/webhook.ts` | `a58752c1c25fa0f7ae5b031f2481128d8583a7a0c62dc36da37009032ffad43c` | `748ed61236c8e76e840fb1cef1ea4a6096ac865c8c0b792891250ded95b5914e` |
| `workers/licensing/src/worker/compose.ts` | `e37a4fa09bf13c057286696fcba591d9b8d7eb844b34a4f0ce10bd5469285677` | `aa816eacebc404244c4076559573f42dd43d4cd157632a8784416fbeadad5637` |
| `workers/licensing/src/worker/handler.ts` | `6e14ba07e8ed5750d39b7a87950151c4fab5d330cc73f9a985a7d792c85bf555` | `5d08fff2bd88b7b58342de34db2ffaf919dd155cdc2508d4dac2dd84db9e163b` |
| `workers/licensing/tests/compose.test.ts` | `0db8c1931ff9d6d2dc84b20f57b2d3c64b3953601fbd80f35a9c9ce87f4e1557` | `c0e8cb74e0876686f29d6d6a3f4dbb17c275ba7deb6b69d11cd6a1836f58ae88` |
| `workers/licensing/tests/signup.test.ts` | `5fc729a925368f974ed4f80c8e26c8cf57d1738c67a3d25b74178314e9c1a2e5` | `2f051ad251ba1273d76d21f8a781646cff075164294014efdbf9d1256d8eedb3` |
| `workers/licensing/tests/test_signup_acceptance.py` | `c68bd747374a880e439d6e2008f0ef12944f72faa2eecb4ac8d58fe3e88f7e20` | `b72678ad19460aafd7b92da99ebbaea180487bea0f254f3575b0bab47ed53ff0` |
| `workers/licensing/wrangler.toml` | `f48ba7d9c319f845695deba26d66c3c63816ac341bdc2e6e6d7a50738011a07b` | `d6497774cdd68294cf8bc6e0fb7a374ee3f622b2844472c858a7a0a598b08875` |
| `workers/release-feed/src/handler.ts` | `cdee49f3fd2b674001d12a17be9f0cb37d4f19b28c1c2f90c7d3c2003714c812` | `1e4bad45b24f1b60b8e6fa976fa9b5e8d6ddd2b374dadd6a514f25033421f524` |
| `workers/release-feed/tests/feed.test.ts` | `7dd1d56669641fcfe43d2b846a4b743dc461a56b0554c8544a69b514456be87a` | `aa6d3b84b4dd0e8c8306b53af6e924018d8dbd9c817f656cd901c3afc9932185` |
| `workers/release-feed/wrangler.toml` | `63e458c1f8106c48e0882d6fe0ff0afde1fc3e4f02b4ca264c33c3ab78d4e0ac` | `eaf48e6a36e513f4f84d56a0621e65e5ecdb5554741908ca288c2aa6798b3cf9` |

## Verification

- Licensing Worker `npm test`: 189 passed, 2 failed. Both failures are the existing entitlement-catalog tests for unmapped `POST /md/chart/ticket`; focused signup tests: 10 passed.
- Release-feed Worker `npm test`: 22 passed; `npm run typecheck` passed.
- Data-gateway Worker `npm test`: 28 passed.
- Python config/URL/update/Admin/gateway focused suite: 74 passed; CF-specific acceptance: 7 passed; Admin UI: 14 passed; Admin Python acceptance: 6 passed; gateway-client tests: 14 passed.
- Admin UI build passed with default deployed origin and with `VITE_ADMIN_WORKER_ORIGIN=http://localhost:1420`.
- Desktop Rust origin test passed using the established override: `$env:TAURI_CONFIG='{"bundle":{"resources":[]}}'; $env:CARGO_BUILD_JOBS='1'; cargo test --lib --locked --offline worker_origin_config_is_one_exact_https_origin` (1 passed).
- Signing-key Pester tests: 5 passed. Deploy script parse and `-WhatIf` passed; output contained names only and did not import/read secrets.
- Default full mypy: 418 source files clean. Linux/Darwin platform mypy runs report existing Windows-only `ctypes`/`msvcrt`/`keyring` errors (22 Linux, 21 Darwin).
- Root Ruff reports 10 pre-existing findings under `qa/integration-backups`; scoped changed-Python Ruff and `git diff --check` pass.
- Both standard unsplit root pytest commands fail during collection due to canonical duplicate test basenames: `test_live_activation.py` and `test_live_activation_acceptance.py` in `apps/api/tests` and `packages/leviathan-store/tests`. No changes were made to those tests.

## Deployment safety

The coordinator-run script is dry-run capable and does not disclose secret values. Actual deploy and external Stripe/Cloudflare operations remain unexecuted pending review. The Stripe webhook URL is `https://leviathan-licensing-worker.ocean824.workers.dev/signup/stripe/webhook`; it uses `STRIPE_TEST_WEBHOOK_SECRET` or `STRIPE_LIVE_WEBHOOK_SECRET` in the Worker secret binding selected by `-StripeMode`.
