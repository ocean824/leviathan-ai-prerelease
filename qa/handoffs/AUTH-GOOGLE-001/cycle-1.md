---
kind: ticket
title: AUTH-GOOGLE-001 cycle 1 implementation ledger
status: 1
---

# AUTH-GOOGLE-001 cycle 1

## Snapshot and scope

- Worktree: `feature-auth-google-001`; canonical source: `projects/XYRASYSTEMS/LEVIATHAN AI/repo`.
- Canonical-start manifest: `b53292c44e04ea55deb28aef95cdcf6a2df5d1706825a46b944f78d4c91db94a`.
- Cycle-0 ledger SHA: `230A3B6235F7382758A601682EAB538D278658747DD2532FCA9744026356054B`. The original worktree `qa/handoffs/AUTH-GOOGLE-001/cycle-0.md` was lost during sync and could not be recovered; the cycle-0 implementation artifact records this prior frozen snapshot.
- Reconciliation excludes `.git`, `.venv`, `node_modules`, `target`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.wrangler`, `dist`, `build`, `.pyc`, and `.pyo`. SHA-256 is over file bytes; relative paths use `/` separators. The ledger itself is excluded from the diff.
- Census at freeze: CANONICAL_FILES=1875, WORKTREE_FILES=1890, DIFFERING_PATHS=$($diff.Count). Each residual row is classified as an AUTH-GOOGLE lane change or lane test asset; unrelated current canonical changes were byte-synced before this walk. `-` means a path is absent on that side.

## Cycle-1 changes

- Removed owner/admin role gating from LIVE activation while retaining account-owner principal binding, `live_trading` entitlement, confirmation, HALT, risk, and OMS gates; device-evidence handling is unchanged.
- HALT engage is a safety-off action and is not blocked by `live_trading` or expired/inactive license state. HALT lift requires `live_trading` and the trusted instance principal. Other kill/disengage safety-off routes remain open.
- Updated the entitlement catalog and API license gate consistently. Added coverage for non-admin self activation, cross-principal denial, missing entitlement, and HALT engage/lift under expiry/inactive states.
- Migrated inherited HALT-lift tests to explicitly provide a trusted entitled non-admin principal. No assertions were removed and no blanket auth bypass was added. Reason: stale tests assumed unauthenticated lift. Explicit 401 missing-principal, 403 missing-entitlement, and unentitled engage tests remain.
- dcd56d28 updated desktop sign-in and WIRE acceptance harness assertions for the Google/password TOTP enrollment paths and current signed JSON/proof flow. The QR acceptance harness was updated locally to stub the `google-signin` DOM element required by the current UI; assertions were unchanged.
- Google OIDC verification, PKCE/state/nonce flows, account linking, Worker routing, and Rust desktop loopback OAuth remain as cycle-0 implementation. No Google secret or live provider request was used.

## Verification

- API: `uv run --locked pytest tests -q --tb=short` from `apps/api` — 1502 passed, 1 skipped.
- Worker: `npm test` from `workers/licensing` — 204 passed; TypeScript check passed.
- Google Worker acceptance: `npx vitest run --config ../../qa/acceptance/AUTH-GOOGLE-001/vitest.config.ts` — 12 passed.
- Google Python import/policy acceptance: `uv run --locked pytest qa/acceptance/AUTH-GOOGLE-001/test_import_origin.py -q` — 2 passed; import resolved to this worktree.
- Desktop acceptance: `uv run --locked pytest apps/desktop/qa/test_desktop_signin_acceptance.py apps/desktop/qa/test_desktop_signin_wire_acceptance.py apps/desktop/qa/test_signin_qr_acceptance.py -q` — 26 passed.
- Rust: `cargo test --lib --locked --offline` with `CARGO_BUILD_JOBS=1` and `TAURI_CONFIG={"bundle":{"resources":[]}}` — 23 passed; `cargo check --locked --offline` with the same environment succeeded.
- Terminal focused: `npx vitest run src/wave36/liveActivation/test` — 16 passed. Full rerun: `npx vitest run --maxWorkers=1 --no-file-parallelism` — 1400 passed, 1 skipped.
- Admin UI: `npm test` — 14 passed; `npm run build` succeeded.
- Mypy default, `--platform linux`, and `--platform darwin` — passed, 436 source files each.
- Root Ruff: `uv run ruff check . --exclude qa/integration-backups` — all checks passed. Changed desktop acceptance files pass Ruff.

## Owner inputs and follow-ups

- Owner must create Google Desktop/Web OAuth clients and provide client IDs. The Web client secret must be stored in the vault and provisioned to Cloudflare Worker secrets per CF-DEPLOY runbook. No secret is committed.
- No live Google OAuth/Worker smoke test ran because owner OAuth credentials were not supplied.
- HALT lift is per signed-in desktop installation. Account-scoped HALT and CHAT delegation are follow-ups.
- SNAPTRADE `session_principal.ts` extraction is not in canonical at this snapshot. Google sessions use the existing USER-session resolver; merge onto the single verifier when SNAPTRADE integrates.
- Known unrelated gates: simulated Linux/Darwin mypy Windows-API diagnostics and default root Ruff findings in `qa/integration-backups` are pre-existing (Ruff run excluded that directory); a CF-DEPLOY acceptance mismatch belongs to CF-DEPLOY cycle 3.

## Complete residual-difference table

| Path | Canonical-current SHA-256 | Frozen worktree SHA-256 | Classification |
|---|---|---|---|
| `apps/api/src/leviathan_api/auth/operator_principal.py` | `4a8cfea91ad22a61aafec1551e75316e81253ca1ecea516d55e0c8722f50b8ef` | `227beb8dafe1f894d9704ed8939396da981838a3210f0a17c87d904d9b819f6f` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/src/leviathan_api/main.py` | `3d596400d1024b51489687cbb01611b3e031455e293c077666cdba1ba76e93c2` | `fe16221c1b1f0c789388e4dc50717976fe1cbee871785909d517917a277e7e6c` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/src/leviathan_api/middleware/license_gate.py` | `2d479c111df521e818259763b19548c27033c70b27db364d30cb9e4c910e1a8b` | `c097bdce697d9b62a43f92344061843eadcc8491552bef4c0995064d552c2bc0` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/src/leviathan_api/routers/live_activation.py` | `58d97f5247ee73abe5f6e35706b8e8da1264339b194713a5a0480986545ff896` | `0556c9b7e4a64f1e0ae3c31645d06836f7316255f934e10aaa126eb17a78e8e1` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/src/leviathan_api/routers/risk.py` | `4d049cc6cf458ede3b6f84bece378ab5d7743b1be9db104f5206f6726bfeb1da` | `4914de1d380da57959eac52b84d76a04e41d37bd771cf5e84c22199a9664915e` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/tests/conftest.py` | `81c5821ce4870138ee067d9b88635518e11318a987e7ade26ac5c4cfb8faed84` | `95ad967f632e2040ebe1d96b1a38530408f3fa3b770e9aa882ab9b790fb1c9f8` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/tests/test_engine_routes.py` | `650a4176d5c6a761e28901eb2f5789f1cc9ca3b5ae5649cd8bfd9fe737eeb96b` | `5413cb130ea2bc530faaccc6e9cba4d9218d0538238e2adb9ec556d7f9b3847c` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/tests/test_halt_durable.py` | `e11bcd62df7dd63de431926c15d10a9663996b274b9a3ee79a19f1183f262a03` | `be1fd7bbf1f5b2d0bb366865d7c579cbb9082712e08a2298f21a3fd945cbee00` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/tests/test_halt_reason_closed.py` | `29df854f72e6cb44f8c07eb15dd7ecf08e512bdbc3aa009da89503579f223edd` | `7b85bf2c4a71c543d8ce75e3969655457dd88e0721c318cc3998c2c9e00d3bca` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/tests/test_halt_reason_closed_acceptance.py` | `572bb0ba1df13f9f7d652e59223ffa7580bb5cbe11984469761c4dee986c4530` | `39692fd4bf5db2ed40468e2e1e780717fdc352518bf90f284db1ca3d7694a7ea` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/tests/test_instance_halt_principal.py` | `-` | `90208a820e74b39eabc24b4a38c78db2cc524f2cc6c8e9583995689c33cf0480` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/tests/test_license_gate.py` | `f39e1826b6f04112823d47a224308a8d94d62667ef7f48ed6337b8e2b5017b68` | `d7288b8fc47b597b538e574d8fdb39180c6196e0425828f9d452a852b89413e2` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/tests/test_live_activation.py` | `ca760c35438b3a680cf6e591fa8a35f1b717db06b080a8c9fd46b27d52368011` | `8455772a14b3a5fed8e7f0481414a2f253e38ea3f70c816ab0807ec5e4a9d33b` | AUTH-GOOGLE lane change / lane test asset |
| `apps/api/tests/test_live_activation_acceptance.py` | `dd468cd9b44c3b7310ed64e8951eeeab4d4c3947665c90517229926e071abfc5` | `dad9755a71e91650bba9c487d245a4e6e6783084d7ac59b233b19979c904ea98` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/qa/test_desktop_signin_acceptance.py` | `b35e4f67584761c03c3d3506d8fb794ac3ebe10c6ed9c203a06e89fc32aca66c` | `739fb0b8d88bd243ca5a52df1835c7db11dbf6e6a857b6dbf9ed4cec73aca39d` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/qa/test_desktop_signin_wire_acceptance.py` | `e3398ec657398610e285f32f59991bf84363b7d9e63838e5893640d3cd6722e2` | `91a7c4ed9a05b3b7f1921c678afe3498ff135195cc08b0a7c769dbf3dceb9e36` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/qa/test_signin_qr_acceptance.py` | `bd15c3db4a1dd4e8a2a5a480deced63eed08dbc0a628af51053db8d03c43fb10` | `58f55d260bf52781dabf089af4e8e2a06389f82325692573d1e585cba4630c92` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/shell/signin.html` | `617b79f949462b109702b74bd1930f2336159116a50a0d31f079496e62252198` | `a280d194c7bc3a20dd2d6e3ed6ffe6e81285cbaa3021e932eb1638aeed614600` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/shell/signin.js` | `511b0d388fae26e00e928503c62d063569f085f17fde9bbd1b2e31698b7336ad` | `e353f765ac5e30333cd81f50803cf746323600735c991f3135f57ce04dae5a1c` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/sidecar/leviathan_desktop.py` | `99cbcbc880ad570476bb6ac7674f732a24c17089473f140cd7be3972472a6a58` | `d0f95f926c9159da0d43501615444128be1b7c56bf9508db6c9f3e7d73381ca5` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/sidecar/session_identity.py` | `-` | `59b53f214861ed9b4280302001b3315fec0717339ab7d6e5fbada344fb45a30d` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/sidecar/tests/test_session_identity.py` | `-` | `ebfc5e893403e99f8d9ba2067b3099fa6558a3ffa716f7d19a95bd9d9c9b873b` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/src-tauri/build.rs` | `b9bdc095c5180f621157476c6b32259e0851691c49049f90a71ef80551885a80` | `cca7acb41588daa070a710e9e765571017f7ad8b8b3c45d0448eff952da7f2d4` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/src-tauri/src/google_login.rs` | `-` | `c5604edaff2f1ef023dd8bfcd99b7df85e4f465b23293a9d44322f33fee7dc6c` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/src-tauri/src/lib.rs` | `33a83619b73a01733b36e33cb8aca580e4a4ade74dbaa72fe3ab98571af90f33` | `ae73ac7c45ab313b81ea5c9196cc21d1c9ccda54f95efbb35b1787781e07747d` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/src-tauri/src/license.rs` | `41bc7fddd9494fe53570a53b09130f9469278af2bdc61af5b932c85fab771c9f` | `11dbbfae4602aadb71147163b548dadd43e7a19471b9b835935add46b8c7ee29` | AUTH-GOOGLE lane change / lane test asset |
| `apps/desktop/src-tauri/src/main.rs` | `16e2aa0d08efda3ffc4e0631d8295b6d5ec5419a238c4d3b38d4f42ec3a3289e` | `d4028aaafbb5a5c2a68b8bc7bc9ed9f7ff3618ecb69907fd3c64f5df2f2eb539` | AUTH-GOOGLE lane change / lane test asset |
| `apps/terminal/src/wave36/liveActivation/api.ts` | `c7561560291069f09c8c3e4541b3263b5c502549efedaaea2698c41ecef37e97` | `34e991f650e147aca88ed466ef3df80ad7782afcabba45557886df14e66b14f9` | AUTH-GOOGLE lane change / lane test asset |
| `apps/terminal/src/wave36/liveActivation/LiveActivationView.tsx` | `bbaaadd392c5daae3bacaf56b337040db5b9c999d19c10f7170c80f4b28e1321` | `0b709588c640f61cb7ced8fa3b9eee6831e30c07fbfe5712852c6e2625798c93` | AUTH-GOOGLE lane change / lane test asset |
| `infra/release/google_oauth.json` | `-` | `b2e192d589a1538c68ebe1c962bb47ff3b0dd23a2381b9a64aefba7e82da8c6e` | AUTH-GOOGLE lane change / lane test asset |
| `qa/acceptance/AUTH-GOOGLE-001/test_import_origin.py` | `-` | `4f0ca33774a0e401946ba814f2509ca089ba67fc48aaefc3bf7ef70809c1948c` | AUTH-GOOGLE lane change / lane test asset |
| `qa/acceptance/AUTH-GOOGLE-001/vitest.config.ts` | `-` | `0513917303ea5c8c3b6e7549086b653ebd122e59a3fc9908d6cfc2c781234236` | AUTH-GOOGLE lane change / lane test asset |
| `qa/acceptance/AUTH-GOOGLE-001/worker_acceptance.test.ts` | `-` | `1386a7e7f69c91314b77d13cf6e019d5c3d5c785cb60b30c4b0b953755fe884a` | AUTH-GOOGLE lane change / lane test asset |
| `workers/licensing/migrations/004_google_oidc.sql` | `-` | `b31f56802d9ae799fec4e9a0090b4fd156783912a3dd2fbe14bf6f4c001d619d` | AUTH-GOOGLE lane change / lane test asset |
| `workers/licensing/src/entitlement/feature_catalog.ts` | `6001a6837f885c30c4e6443aa95c796758c765f0f785df430fa3291f9a4a1c60` | `fb1f10109a0458aaea1e7af69b08b31f96d08acc0cbbfd86e481f04a45ea61d7` | AUTH-GOOGLE lane change / lane test asset |
| `workers/licensing/src/google_auth/oidc.ts` | `-` | `fd79e17aa4b95d807a1c50ae3b73dfe5fd5a2402b70b4261d3fa875e3b48c9bb` | AUTH-GOOGLE lane change / lane test asset |
| `workers/licensing/src/google_auth/pkce.ts` | `-` | `92381927147525c4640f089ba35e855869f87e98ff5aaa9160657c4488c228be` | AUTH-GOOGLE lane change / lane test asset |
| `workers/licensing/src/google_auth/routes.ts` | `-` | `87521010bc8b8a16df6f67de1b63a2962ca90190fb79ad3cd36e546df6f57a02` | AUTH-GOOGLE lane change / lane test asset |
| `workers/licensing/src/google_auth/store.ts` | `-` | `6daed30de59b9c0103e878c2899e82e003b1d2dab9d00cbd2d44b1ab77d2ce39` | AUTH-GOOGLE lane change / lane test asset |
| `workers/licensing/src/worker/compose.ts` | `aa816eacebc404244c4076559573f42dd43d4cd157632a8784416fbeadad5637` | `5f781aa52599de8076df29b247f6e4f989229ef89d142b475f59a21ffe3ef07b` | AUTH-GOOGLE lane change / lane test asset |
| `workers/licensing/src/worker/handler.ts` | `5d08fff2bd88b7b58342de34db2ffaf919dd155cdc2508d4dac2dd84db9e163b` | `0589c3ce4889c9eb0365fec261fd9d70d8029f4658422072db6775356c5b1733` | AUTH-GOOGLE lane change / lane test asset |
| `workers/licensing/tests/google_auth.test.ts` | `-` | `d840a0ed33facc1fa959826f098266c0f70ddaf7b594babf51233158e47bde5c` | AUTH-GOOGLE lane change / lane test asset |
| `workers/licensing/wrangler.toml` | `d6497774cdd68294cf8bc6e0fb7a374ee3f622b2844472c858a7a0a598b08875` | `778e980e7892c729dba1caf2a126b83940e1dc2e94168765c880a9e73ac621dd` | AUTH-GOOGLE lane change / lane test asset |
