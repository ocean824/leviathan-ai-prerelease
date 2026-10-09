# PKG-MAC-001 Phase B-CI freeze ledger

## Provenance and inventory

- Fresh copy: `repo-pkg-mac-001-phase-b-ci`.
- Canonical start: `repo`, HEAD `d3208136d1872cf6e0bb33ec79aa06f01de98562`, captured `2026-10-09T19:16:28Z`.
- Starting SHA-256 manifest: `qa/pkg-mac-001-phase-b-ci/canonical-start-hashes.json`.
- Epic artifact `index.md` SHA-256: `3151c8abb50600fd05867397d0d722f34cc23086d6e6c940063a7676a804fb04`.
- Inventory is source-only. Excludes `.git/`, `__pycache__/`, `*.pyc`, `.ruff_cache/`, `target/`, `node_modules/`, `.venv/`, `.mypy_cache/`, `.pytest_cache/`, `dist/`, `.scratch/`, `build/` and generated `*.tsbuildinfo`.
- Integration should copy only the paths listed below. Freeze-ledger SHA is reported out-of-band because a file cannot contain its own final hash.

## Changed deliverables

| Path | Start SHA-256 | Frozen SHA-256 |
|---|---|---|
| `.github/workflows/ci.yml` | `3bdceb4fe576eca5ec13613f4a867936f7aa9871da8c784f1c828f2bb9ec209a` | `d8c25d74c022cca6bdaf863e75d7e86f2c0596461b6830029c3b690d5a541c42` |
| `.github/workflows/macos-build.yml` | new | `a446c334a9eec799dafcea125e6825221757ae44d1a7616fa64cf7b15ab0f9c8` |
| `.github/workflows/windows-ci.yml` | new | `2f60001cd4910adbe1fee8ffb89cb4c22a22fdee6b26afb518b3c1b4e6646064` |
| `README.md` | `c2a82bf9b044ead4011c662638ae2ccf02ae92a67841b1119a4eb948190e3209` | `84a94dfb1b9de2baf9201ef72167c4464f9698af01afc38f5c54031665959ede` |
| `apps/desktop/MACOS_TEST_CHECKLIST.md` | new | `81756d82a37bb5e9f806d3784b8d1b2ec78848176b61dc905c708278bf4789cd` |
| `apps/desktop/scripts/build-macos.sh` | `47aa5daa1f98e7514741358f88488b3981c00f5d9b2d571f0e99e02a32d196ed` | `a014138fe4b1573b26ad4e2b79c8bdce0109dfce1e56fce382230127996b5f6a` |
| `apps/desktop/scripts/smoke-macos-sidecar.sh` | new | `4ca44ebdc9355b7dd8105d67198a0916d7c9786e002b9ebabbd3216a530f0811` |
| `apps/desktop/scripts/verify-macos-bundle.sh` | new | `f091d9024c894eaa9148038dd9d89dc13be15ada84075f72d4558f2ef2271e56` |
| `apps/desktop/src-tauri/tauri.macos.conf.json` | `084afadf4d4d3fd9ad21f3ebef189005f9bd16061a489badc6819a59bf1b15c8` | `f5bfc91ad367582edd925ae9a7056a2ad85c4b73f9110d57861f2c97216c3273` |
| `qa/pkg-mac-001-phase-b-ci/canonical-start-hashes.json` | new | `eb44ac0f2d22609511c77081dead9087cc8870b72dc8a2f1133afe9555be13a8` |
| `qa/pkg-mac-001-phase-b-ci/freeze-ledger.md` | new | SHA-256 provided out-of-band |
| Epic artifact `artifacts/leviathan-build/pkg-mac-001-phase-b-ci/index.md` | new | `3151c8abb50600fd05867397d0d722f34cc23086d6e6c940063a7676a804fb04` |

## Verification on Windows host

- PyYAML `BaseLoader` parsed `.github/workflows/ci.yml`, `macos-build.yml`, and `windows-ci.yml`; `actionlint` was unavailable. Workflows were manually reviewed.
- Git Bash `bash -n` passed for `build-macos.sh`, `verify-macos-bundle.sh`, and `smoke-macos-sidecar.sh`; embedded Python verifier compiled.
- `uv lock --check` passed.
- `uv run --locked ruff check . --extend-exclude qa/integration-backups` passed; `uv run mypy` passed (429 files).
- `packages/leviathan-core/tests`: 6,541 passed, 10 skipped, 1 xfailed.
- `packages/leviathan-store/tests`: 548 passed, 2 skipped.
- `packages/leviathan-vault/tests`: 163 passed, 36 skipped.
- `packages/leviathan-market-data/tests`: 1,128 passed.
- `apps/api/tests`: 1,446 passed, 1 skipped.
- `apps/desktop/sidecar/tests`: 51 passed, 1 skipped.
- `infra/release/tests`: 65 passed.
- Terminal: `npm test -- --maxWorkers=1` passed (66 files, 1,400 passed, 1 skipped); `npm run build` passed.
- CI contains no secrets. The macOS CI job disables updater artifact signing and does not receive provider keys.

## Mac-only verification outstanding

No macOS runner was available to this worker, so the DMG build and runtime checks are not claimed as executed here. The workflow selects `macos-15-intel`, sets macOS deployment target 11.0, builds x86_64 natively, then checks architecture/minimum OS for Mach-O contents, verifies bundled sidecar layout, runs a headless sidecar health smoke, and uploads the DMG. The owner's Big Sur 11.7.11 Gatekeeper, sign-in, Keychain, updater, relaunch and data-retention checks are documented in `apps/desktop/MACOS_TEST_CHECKLIST.md`.

## Cycle 1 review delta (changed paths only)

Previous freeze ledger SHA-256: `3dc3ec6a926a945e43069bc272d8eaa77f52cb4ee11effb009301e9c75a25b38`.

| Changed path | Cycle 0 SHA-256 | Cycle 1 SHA-256 |
|---|---|---|
| `.github/workflows/ci.yml` | `d8c25d74c022cca6bdaf863e75d7e86f2c0596461b6830029c3b690d5a541c42` | `43843ad6ea897619db09552e3b420704d716b67fe8448f75f1d7ad0c6739da41` |
| `.github/workflows/macos-build.yml` | `a446c334a9eec799dafcea125e6825221757ae44d1a7616fa64cf7b15ab0f9c8` | `92a56e29d573cee16de7166c0ad46df94a881d87f080ab1c6fccf1f148bf6c6e` |
| `.github/workflows/windows-ci.yml` | `2f60001cd4910adbe1fee8ffb89cb4c22a22fdee6b26afb518b3c1b4e6646064` | `e7b06086805305b83117594e10fff0f02487e85f62e0b18bb2818ea3bb325a2c` |
| `apps/desktop/scripts/verify-macos-bundle.sh` | `f091d9024c894eaa9148038dd9d89dc13be15ada84075f72d4558f2ef2271e56` | `247b22eb404d6e3d69396bff15640420b3b1a53a219025b66870f2186c2d2606` |
| `apps/desktop/scripts/smoke-macos-sidecar.sh` | `4ca44ebdc9355b7dd8105d67198a0916d7c9786e002b9ebabbd3216a530f0811` | `f710d8ca436cfe8c564791739155dd44ffd3fb4a4e8efa9b05dc5e252c33cd5c` |
| Epic artifact `artifacts/leviathan-build/pkg-mac-001-phase-b-ci/index.md` | `3151c8abb50600fd05867397d0d722f34cc23086d6e6c940063a7676a804fb04` | `a98aae8f41639c41846bc24cc4df750709aab25482dc80a89899e0d91b7c5369` |
| `qa/pkg-mac-001-phase-b-ci/freeze-ledger.md` | cycle 0 | SHA-256 reported out-of-band |

### Action pin provenance

Resolved read-only with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`; tag refs returned commit objects (no annotated-tag dereference was needed). Every action reference in the three workflows now uses the commit below and retains its release tag as a comment:

| Tag | Commit SHA |
|---|---|
| `actions/checkout@v7` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-python@v7` | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| `actions/setup-node@v7` | `949feb2413d6458794dcd2491c4babbbce0c15c1` |
| `actions/cache@v5` | `caa296126883cff596d87d8935842f9db880ef25` |
| `actions/upload-artifact@v7` | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `astral-sh/setup-uv@v10.2.0` | `c18668ad3cf93ea998bef934396af7bb5c839dc7` |

### Cycle 1 verification

- PyYAML `BaseLoader` parsed all three workflows; assertions confirmed top-level `contents: read`, a timeout on every job, and full 40-character SHA pins on every action. `actionlint` remains unavailable.
- Git Bash passed `bash -n` for `build-macos.sh`, `verify-macos-bundle.sh`, and `smoke-macos-sidecar.sh`.
- The verifier self-test passed. Fixtures prove rejection of an over-11.0 deployment target in the second architecture slice and rejection of a non-x86_64 slice. Embedded verifier Python passed `compile()`.
- Smoke health curl is bounded (`--connect-timeout 2`, `--max-time 5`, retry count 6, retry window 40 seconds). An EXIT trap sends TERM, escalates to KILL if needed, waits, and removes the temporary directory.
- All workflow jobs have explicit timeouts: Linux Python 60 minutes and terminal 30; Windows Python 60 and terminal 30; macOS build 60.
- Existing Windows suites and terminal tests were not rerun in cycle 1; cycle 1 changes are limited to workflow security/timeouts/action refs and macOS validation/smoke scripts. Their cycle 0 passing results remain recorded above.

## Cycle 2 CI fixes and Windows installer/release additions

- Canonical refresh: `d3208136d1872cf6e0bb33ec79aa06f01de98562`; starting hash inventory captured `2026-10-09T20:52:00Z` with `1683` files. Per-file canonical-start SHA-256 values are in `qa/pkg-mac-001-phase-b-ci/canonical-start-hashes.json`.
- macOS: terminal now builds before PyInstaller and `apps/terminal/dist/index.html` is checked explicitly. Windows: `build.ps1 -CI` uses CI MSVC discovery, disables updater signing without changing local defaults, and the workflow runs non-GUI acceptance then uploads the NSIS installer. The manual pre-release resolves successful Mac and Windows build runs for the same full commit SHA and publishes the artifacts with one write-scoped job. README links to Actions and Releases.
- Windows-only ctypes/locking references in HALT, vault, import transaction, and OMS now use typing-safe access without changing Windows calls. The `halt_store.py` change is structural only; HALT-focused tests pass.
- All workflows use top-level `contents: read`, explicit job timeouts, and full action commit pins with version comments. Only the pre-release publish job receives `contents: write`; only built-in `GITHUB_TOKEN` is used. Installer CI has no signing/provider secrets and disables updater artifact signing.
- Inventory excludes `.git/`, `.venv/`, `node_modules/`, `target/`, `dist/`, `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`, `__pycache__/`, `.scratch/`, `build/`, `*.pyc`, and generated build outputs. Integration copies only ledger-listed paths. The ledger hash is reported out of band.

### Cycle 2 changed-path hashes

| Path | Canonical-start SHA-256 | Frozen SHA-256 |
|---|---|---|
| `.gitattributes` | `b4079e8313eb59b524a2874a0432147531ef72330ea10870f3cf3f2a5c7e2204` | `9088dae4974477088566ef9e002098d7cf0ec58fca7192bf22e5ef66aa50df7e` |
| `.github/workflows/prerelease.yml` | `new at canonical start` | `01b13735d49d82a104636349dfad402be6b04b2be6f569836b708f4db417cc80` |
| `.github/workflows/windows-build.yml` | `new at canonical start` | `68d00c40c614150aa01a1c7145a5f7c85c7ea4d122f3dc8eb6bbaa61715f0d56` |
| `README.md` | `84a94dfb1b9de2baf9201ef72167c4464f9698af01afc38f5c54031665959ede` | `be09c4cbca34deed9ade10483b7230f4a37f1fac2f47d7b01fdd9e5c28177139` |
| `apps/admin/ui/package.json` | `faf6b754601ae9a50dd78c9482909240e8f348218f8c342d669a701384404056` | `a1c96157842a34b504a5c9791802f15d0b050a0a483b0600f2842959e9513a9c` |
| `apps/admin/ui/src/test/setup.ts` | `52aa176288fb9d5c1a504863f6e2ee9ab964b0c479527c4562283889b5593bd2` | `ea22e31c5794a6e643087ec9741208b7f6d2c8b8855b37bde7306a16101d943d` |
| `apps/admin/ui/src/vite-env.d.ts` | `aa7584620aeacda760765cd2a675bbc87d46ed7f83da955ccd3ed2fccb1c1ea4` | `15ae74e59dcfc50b8f91998849b8f6923db446b741017eb2f8c2a68bae816279` |
| `apps/api/src/leviathan_api/routers/mt_export_build_status.py` | `2c93f00339f2c401485df01f0efc22172ea66e87c5864d2c6b733469c5ed0de5` | `e57f02bab7f8143f7bf1b8c5bbfe706794851e7877e5c44372695d71a2ac0dc4` |
| `apps/api/tests/test_mt_export_build_status_api.py` | `2cb327c414b7a7b41048de97c73bdf8c4bcbf053aabd325183152cd45d8f59fc` | `08c0321992026de72fff8ca50a03a5c76e432ce513c892c58897af5e6e705aec` |
| `apps/api/tests/test_omega_runtime_factory_acceptance.py` | `8e4a6108c0fd8b56fde7e45b7d63826fc078878586c56d4c75d353596824f541` | `bcac6ef320f65bba7824988049bcc99c8363d882459c7ace8f820ba0ab87ce85` |
| `apps/desktop/qa/fixtures/license/active.json` | `c69d82478c8db4606da055574449036cf7aecd1b94f11a8a049a3726bf7dcb95` | `d7705e3e7cdcdcba4c7c25ad65bd9bfd99bca34ee09702def6b190865c1ba92b` |
| `apps/desktop/qa/fixtures/license/device-mismatch.json` | `7c3c4e5d17bb67d42c4126c997614fee27e49917ac843a49b783078f7fa6a4aa` | `f96e654c7d7833c1e29db9ad30348b714edd78dcb799cc0e16461217b003f23a` |
| `apps/desktop/qa/fixtures/license/expired.json` | `3209524d4c17ae72f79f22291f362132288b800c77b2bbd8b18bdfe5bf1f1a1a` | `0388a940aff8bd2746a153edab37595554adc6522b1259b9d4885bea2e7c0b8b` |
| `apps/desktop/qa/fixtures/license/inactive.json` | `2b8d497009719eeb92d7103b8728cc393aada005fd7dd7acd29e9745f7b97a83` | `f2b7af38dfc218567b2c286baf71d2177511f31019587d7d241a8c840fdd075d` |
| `apps/desktop/qa/fixtures/license/malformed.json` | `d4474afbfe749cb6ab69895fc0c3bcb20d5a23c0ee3f1557f335698373cecd63` | `6087c3e083f11ec4f58910232ca9893097264e87b0d72335afd58f580886ff14` |
| `apps/desktop/qa/fixtures/license/offline-cached.json` | `22afc27f3ff12de778b939bbdf2461eaa65762a0fdeed744d4526944f11bb953` | `df360c99e6433168a9ca3b79dd3489f1da91f387ad4e970850ddeed593b98101` |
| `apps/desktop/qa/test_desktop_signin_acceptance.py` | `792f22dae0f7aa2bda04cc5b262f45d43a39d0ed667eb8df2a957c54839ee7f7` | `b35e4f67584761c03c3d3506d8fb794ac3ebe10c6ed9c203a06e89fc32aca66c` |
| `apps/desktop/scripts/acceptance.ps1` | `dc5dfab67a58873fa4d89c14d6542a13643fc352b366444a2e372931a79ea871` | `1534b33b54c38d7773a48a2f50e1880b65beea30b5205938acca636cfe4e8b9e` |
| `apps/desktop/scripts/build-macos.sh` | `a014138fe4b1573b26ad4e2b79c8bdce0109dfce1e56fce382230127996b5f6a` | `2999a7f1619e2e3536d2b26d1e7f9b3bfd8a37c58a550659c4f19553473d6b9d` |
| `apps/desktop/scripts/build.ps1` | `9589d894dd8d085711743ea2a7ded7a85222209da79e6b08d64c8280ad3c646b` | `152a379941573be9175767350de5b6cf0b199510749f600af86f3294731bdba3` |
| `apps/desktop/src-tauri/Cargo.lock` | `906a8a290b47cb711fd1f06a740982140146d8787c6d832ce8bf893b732f318d` | `c10b022194522fe994c6a15fa4f1e2a720fac38ef1bd45bd5790c2c09d388274` |
| `apps/terminal/src/test/wave34Navigation.acceptance.test.tsx` | `6c01a9a63797463b465ef6915ef5b5fe107675b459135f2c71cd23ce98359c57` | `f3b3ad6b497a31dd6e4b368f64c633d3af52fcaa32b8525a8a2c90a2e749c8b4` |
| `apps/terminal/src/test/wave36Navigation.acceptance.test.tsx` | `733d4fd5b39e13d9b28b9ea46f5ff7a084beed70bb99e37d6a75562c54e59b08` | `3faaf0cc62c762b7a9a6bc15dbc87a4a10397693613f19ebcd6d30e359628996` |
| `apps/terminal/src/wave26/api/orderMonitor.ts` | `7eb4a8a7d978b79acd224bc504ec608ee05c2a9929ef42506fed2ded95ab87e3` | `141750ac20c07b85f1467e80adcd88e4fd33c28089d9c02fc0bcfb88df8b03d7` |
| `apps/terminal/src/wave26/test/orderMonitor.unit.test.tsx` | `57dceed248844825999be9a250eb7f9b25748772217819bb7f68d2b0ea9061bf` | `11a8881f8ed2ff870ca92729dac3869f72d637f1e8e89378fa36729f0f133123` |
| `apps/terminal/src/wave33/paperRiskReview/PaperRiskReviewView.tsx` | `295e1a997bb1dd56432f0d8558600e0ca2aebb52775260306759747fc3580347` | `9cb62e218e33a5b0c7ecfaafaf79e96e760ecfa8eb488596609ead2403f17b82` |
| `apps/terminal/src/wave33/paperRiskReview/api.ts` | `bb37d09b6767043acddd5ea77228a6f19f7e83eaee8b8530b929ef8caa2a9504` | `acbb115e6d03afcd4dad69f33cd0a19ef0700808e79b9f1375b8be6d4292d70e` |
| `apps/terminal/src/wave33/paperRiskReview/test/paperRiskReview.unit.test.tsx` | `dd5833007c3d45fd140ae848ff525faa752011e923fc097007d2986343a99968` | `5f0535d3ffe5738fc5baf4cb9b08ddc4c79b9f3890920a4ac9f7d335845554eb` |
| `data/risk_audit.jsonl` | `f92ec8a2802d1e21f79fb8c18df5b3cb288b6e09213039f19e1e6d2dffd3c8f0` | `ec636010542ace717697fa95afca9173a209b30ef2b61906b120349592525d99` |
| `packages/leviathan-core/src/leviathan_core/execution/routing/models.py` | `6b0b04d59aeaba983a6b1137d71084fac8f07b535515b493146a1dd00cb8b906` | `2a14a9b4151b0cde54d24e72cdb983227c44b39236e8a201ab2a090770c31e8e` |
| `packages/leviathan-core/src/leviathan_core/flash_loan_route_view.py` | `6126c48b6b3099753778879669b070994f09592b86090d279d4dd5dbb072b219` | `ced96f6732f7a76297b553c9e0cf2dc10bcea8a4a6ee332514c5a3b10dc43e64` |
| `packages/leviathan-core/src/leviathan_core/flow_radar/bursts.py` | `1bcc21b19e2f480940ad8e632f1f4f92ca9028065fb767fee8675e6d0aaab6d4` | `76e5f59c85b106ad7d493ec8cabd357e72e24e74ff0e88e16ac7bec8ac0cfb27` |
| `packages/leviathan-core/src/leviathan_core/flow_radar/tilt.py` | `6a06270c5c3e61bce880c2455bb73da7fdb75cb4995b4c196e1332cb7610fb57` | `c10016930fe4d7641e68687318ca90ea1749c391304e2f9cba72e4c5e97d92fa` |
| `packages/leviathan-core/src/leviathan_core/risk/halt_store.py` | `e771343971060cfbbc44f9d7126b79fa016a15f059828e2f04beb96dc54aa99c` | `a35f748ef8e610e9d55135e0dac0f00e3b7287841457249a2959db13d810a476` |
| `packages/leviathan-core/tests/defi_arb/test_route_view.py` | `7e06278eeef01d68aedc47607384833ab225e530484219d2e18c52b029b75bf2` | `da97364c9edd72ff56724485a4c0610b2d0e33feb8a6d46ff57f7ef837ba932f` |
| `packages/leviathan-core/tests/fixtures/ibkr_tws/mapping_orders.jsonl` | `e6827429ec7eb2dc900c7ef44cb65d9253c72a6dfac0b9a6f273406b6b407fc1` | `592c0301cc28f34f92a85c384ba2c15c32326aafa09b49c0cac3f2107598084d` |
| `packages/leviathan-core/tests/fixtures/replay_job/v1-nq-missing-hedge.json` | `969cba4a8a2e8fbf95563e6167877279f07b95dbdaf3be7dbf057bcbf25ad134` | `f3f0f8445e0fdb15952e29dc11afa716bc3eddf5f741c2543f7f8ee61b0b0a63` |
| `packages/leviathan-core/tests/flow_radar/test_flow_kernel.py` | `0a8674b13752e464c5bd13f587ad770322fe87a28acf92f7deafe4f891b4fa0d` | `3b294149d248ca94e14560c3eb61f348912c23767fe63338c9f6a3cf76922e94` |
| `packages/leviathan-core/tests/knowledge_sync/test_archive_policy_acceptance.py` | `23c252a424495c8882784991933b63ff7d5ce0abc51e5e46b81d11d35bb976f1` | `c9bb67998cce769dae31f437c95b026722597fbfca0e143d97994fb334ce8f9c` |
| `packages/leviathan-core/tests/legacy_session/test_legacy_session_acceptance.py` | `38d1269519242432f7b488b63c8052fcacc7c05d28a52112fb51e7e3282d8c70` | `e3840a5d658de3037467733799c7dec1f74fd9239a9e65e1287f43135e851cc8` |
| `packages/leviathan-core/tests/mt_export_bridge/test_telemetry_envelope_acceptance.py` | `ad29c8dfe94876ce0efa9402e9c8fcac5ce47bf18cc2c9bab60bd9cb45a58e61` | `76dff16b0e0125f3d6d8ece32e8f530b68094d2ebf22a2604d7bd5eba335d3fa` |
| `packages/leviathan-core/tests/test_import_boundaries.py` | `75cedaa74f5cc3f3f73f8d2c99d4a3c9ed8182a8a9ec515296a8b042873dd473` | `090b2f50876acb1f22d9e4d9f28ec4cb8eacf4f3cd26957f8ceaa3ad47f1ebc7` |
| `packages/leviathan-market-data/tests/fixtures/ingress/native-timestamp-provenance.jsonl` | `2f9eacf18f82782cf5a32811d9968df7906d2bbd402ad5e6ff9c8a0d785898d6` | `8e8814d200de305e65f6fdad93fe5b1e330d7aa8d1a2864712ecd5463d3a6fb9` |
| `packages/leviathan-store/src/leviathan_store/oms_ledger.py` | `1b40766b36e7e871a63681d6c04ddd16de6cc82b892bca5b20cc8f262cb67648` | `664ced980f0e424fcb50a18525575dfe62694d18338407337412f10e435accd0` |
| `packages/leviathan-store/tests/test_omega_due_store_acceptance.py` | `43626894a3fbdb5d0698ab9216dc14f2ca4706138f5126effe3652d970fb6608` | `f4f0c70977e0025a2cb42dfe0209e94745f69fcce18781b5e96ed86c9b2b1daf` |
| `packages/leviathan-vault/src/leviathan_vault/app_credentials.py` | `679d11eed6ea07a1c8ff64d1fc676744dbf1af625c9cd0f7bfde48d7048f8cf7` | `09f529d96c56075f9a8b239c2f44985b8e5cf0ec84f5faeb783dffc0a657a810` |
| `packages/leviathan-vault/src/leviathan_vault/client.py` | `c656923d9445a2dc4dcce76eca829e088ce0bd8ab8c1eea05a4bd667ed1cdb53` | `18d7779a358f51b03d0a94c5c6aecf7b8aa93b6619339e792e8133f1ca0ebbf8` |
| `packages/leviathan-vault/src/leviathan_vault/import_keys.py` | `6b8d5e839e953961b28010b777338c3562976379e12b623dd2839a2d1da50f0f` | `3e9f5e1091fec9f735d41faa62389166a0db499be0a17d22acf3ab03a28bdc4e` |
| `packages/leviathan-vault/src/leviathan_vault/transaction.py` | `b75ef0fa16a0d6b3b72b78ded7b0d63709cb73d3b385cb5e4aed311ad4ab7dea` | `284c927f09662f0c9b89f8b6f0d53f49bf1dd1362a30d9a0c2e3faf7a66b23bb` |
| `qa/gauntlet/performance/run.py` | `93bb444c515e1f02566c3d177d48fa1670b33ab02dfaeb7453fdb15197f895c9` | `c3a592a13c5c0a9389764a00a9782e01014d776f0d746e888bed847e7572d7f1` |
| `qa/gauntlet/test_uncategorized_inventory.py` | `add9f3254324e0fb02bc8882e0e6f14ed71d0f85992a77861f08fd402aa4c5ac` | `7e90f39bf73e7065e64ddb40f6fd681ee41e56bd488f6baf4b9730740f2ee3c5` |
| `qa/integration-backups/2026-10-08-pkg-mac-001-phase-a-c1c/qa/pkg-mac-001/phase-a-freeze.md` | `f46d952ca3cd2e5910ba8e3d338f85825b27e7fc06cc314f6e0f6b1ea0196f13` | `c9eac0b386dd5ce22fbe48432194c9aaad730e198e0d9ff737a110b2cb8e7af6` |
| `qa/pkg-mac-001-phase-b-ci/canonical-start-hashes.json` | `new at canonical start` | `4e7bdafd6b0ee1a7df965ed3089de0ffdb8be693cce4916f66f8db76981a91fc` |
| `workers/release-feed/tests/fixtures/admin-latest.json` | `7bef78cdb4abb7cc4d75445f3cbdc4d6e00a2ccb59459d284291bec7ce2a4ac9` | `9382ccf2b2c8a132c2103490bb173775774ea7c0f54de26eab1365b13771012d` |
| `workers/release-feed/tests/fixtures/desktop-latest.json` | `068a86b4a8eb49ce54da11c6032aec09cb763085cf2dd1725fa081c95336902a` | `789db2c56fbbc4a0f40f744b8a0171e20f1f1c9c308d5e56da62be47dfd94a68` |
| `qa/pkg-mac-001-phase-b-ci/freeze-ledger.md` | `587210c9293c69e69b4fdb870fefcc6116226c8ca076050fba8c90b70002dd57` | `reported out of band` |

### CRLF audit: 42 tracked source files

The 42 pure-CRLF tracked source files are listed below. The sovereign risk lock retains its exact bytes and is protected with `-text`; the other 41 files were converted to LF. The generated `qa/pkg-mac-001/canonical-start-hashes.json` inventory is excluded. `.gitattributes` also protects the pinned LF `apps/desktop/src-tauri/tauri.conf.json` acceptance input with `-text`; its SHA-256 remains `122b7c90800305cece8a18a9cb6e49d929e8e94b266bcb3f003324873ed765fa`.

| Path | Canonical-start SHA-256 | Frozen SHA-256 | Action |
|---|---|---|---|
| `apps/admin/ui/package.json` | `faf6b754601ae9a50dd78c9482909240e8f348218f8c342d669a701384404056` | `a1c96157842a34b504a5c9791802f15d0b050a0a483b0600f2842959e9513a9c` | Converted CRLF to LF per repository policy. |
| `apps/admin/ui/src/test/setup.ts` | `52aa176288fb9d5c1a504863f6e2ee9ab964b0c479527c4562283889b5593bd2` | `ea22e31c5794a6e643087ec9741208b7f6d2c8b8855b37bde7306a16101d943d` | Converted CRLF to LF per repository policy. |
| `apps/admin/ui/src/vite-env.d.ts` | `aa7584620aeacda760765cd2a675bbc87d46ed7f83da955ccd3ed2fccb1c1ea4` | `15ae74e59dcfc50b8f91998849b8f6923db446b741017eb2f8c2a68bae816279` | Converted CRLF to LF per repository policy. |
| `apps/api/src/leviathan_api/routers/mt_export_build_status.py` | `2c93f00339f2c401485df01f0efc22172ea66e87c5864d2c6b733469c5ed0de5` | `e57f02bab7f8143f7bf1b8c5bbfe706794851e7877e5c44372695d71a2ac0dc4` | Converted CRLF to LF per repository policy. |
| `apps/api/tests/test_mt_export_build_status_api.py` | `2cb327c414b7a7b41048de97c73bdf8c4bcbf053aabd325183152cd45d8f59fc` | `08c0321992026de72fff8ca50a03a5c76e432ce513c892c58897af5e6e705aec` | Converted CRLF to LF per repository policy. |
| `apps/api/tests/test_omega_runtime_factory_acceptance.py` | `8e4a6108c0fd8b56fde7e45b7d63826fc078878586c56d4c75d353596824f541` | `bcac6ef320f65bba7824988049bcc99c8363d882459c7ace8f820ba0ab87ce85` | Converted CRLF to LF per repository policy. |
| `apps/desktop/qa/fixtures/license/active.json` | `c69d82478c8db4606da055574449036cf7aecd1b94f11a8a049a3726bf7dcb95` | `d7705e3e7cdcdcba4c7c25ad65bd9bfd99bca34ee09702def6b190865c1ba92b` | Converted CRLF to LF per repository policy. |
| `apps/desktop/qa/fixtures/license/device-mismatch.json` | `7c3c4e5d17bb67d42c4126c997614fee27e49917ac843a49b783078f7fa6a4aa` | `f96e654c7d7833c1e29db9ad30348b714edd78dcb799cc0e16461217b003f23a` | Converted CRLF to LF per repository policy. |
| `apps/desktop/qa/fixtures/license/expired.json` | `3209524d4c17ae72f79f22291f362132288b800c77b2bbd8b18bdfe5bf1f1a1a` | `0388a940aff8bd2746a153edab37595554adc6522b1259b9d4885bea2e7c0b8b` | Converted CRLF to LF per repository policy. |
| `apps/desktop/qa/fixtures/license/inactive.json` | `2b8d497009719eeb92d7103b8728cc393aada005fd7dd7acd29e9745f7b97a83` | `f2b7af38dfc218567b2c286baf71d2177511f31019587d7d241a8c840fdd075d` | Converted CRLF to LF per repository policy. |
| `apps/desktop/qa/fixtures/license/malformed.json` | `d4474afbfe749cb6ab69895fc0c3bcb20d5a23c0ee3f1557f335698373cecd63` | `6087c3e083f11ec4f58910232ca9893097264e87b0d72335afd58f580886ff14` | Converted CRLF to LF per repository policy. |
| `apps/desktop/qa/fixtures/license/offline-cached.json` | `22afc27f3ff12de778b939bbdf2461eaa65762a0fdeed744d4526944f11bb953` | `df360c99e6433168a9ca3b79dd3489f1da91f387ad4e970850ddeed593b98101` | Converted CRLF to LF per repository policy. |
| `apps/desktop/qa/test_desktop_signin_acceptance.py` | `792f22dae0f7aa2bda04cc5b262f45d43a39d0ed667eb8df2a957c54839ee7f7` | `b35e4f67584761c03c3d3506d8fb794ac3ebe10c6ed9c203a06e89fc32aca66c` | Converted CRLF to LF per repository policy. |
| `apps/desktop/src-tauri/Cargo.lock` | `906a8a290b47cb711fd1f06a740982140146d8787c6d832ce8bf893b732f318d` | `c10b022194522fe994c6a15fa4f1e2a720fac38ef1bd45bd5790c2c09d388274` | Converted CRLF to LF per repository policy. |
| `apps/terminal/src/test/wave34Navigation.acceptance.test.tsx` | `6c01a9a63797463b465ef6915ef5b5fe107675b459135f2c71cd23ce98359c57` | `f3b3ad6b497a31dd6e4b368f64c633d3af52fcaa32b8525a8a2c90a2e749c8b4` | Converted CRLF to LF per repository policy. |
| `apps/terminal/src/test/wave36Navigation.acceptance.test.tsx` | `733d4fd5b39e13d9b28b9ea46f5ff7a084beed70bb99e37d6a75562c54e59b08` | `3faaf0cc62c762b7a9a6bc15dbc87a4a10397693613f19ebcd6d30e359628996` | Converted CRLF to LF per repository policy. |
| `apps/terminal/src/wave26/api/orderMonitor.ts` | `7eb4a8a7d978b79acd224bc504ec608ee05c2a9929ef42506fed2ded95ab87e3` | `141750ac20c07b85f1467e80adcd88e4fd33c28089d9c02fc0bcfb88df8b03d7` | Converted CRLF to LF per repository policy. |
| `apps/terminal/src/wave26/test/orderMonitor.unit.test.tsx` | `57dceed248844825999be9a250eb7f9b25748772217819bb7f68d2b0ea9061bf` | `11a8881f8ed2ff870ca92729dac3869f72d637f1e8e89378fa36729f0f133123` | Converted CRLF to LF per repository policy. |
| `apps/terminal/src/wave33/paperRiskReview/PaperRiskReviewView.tsx` | `295e1a997bb1dd56432f0d8558600e0ca2aebb52775260306759747fc3580347` | `9cb62e218e33a5b0c7ecfaafaf79e96e760ecfa8eb488596609ead2403f17b82` | Converted CRLF to LF per repository policy. |
| `apps/terminal/src/wave33/paperRiskReview/api.ts` | `bb37d09b6767043acddd5ea77228a6f19f7e83eaee8b8530b929ef8caa2a9504` | `acbb115e6d03afcd4dad69f33cd0a19ef0700808e79b9f1375b8be6d4292d70e` | Converted CRLF to LF per repository policy. |
| `apps/terminal/src/wave33/paperRiskReview/test/paperRiskReview.unit.test.tsx` | `dd5833007c3d45fd140ae848ff525faa752011e923fc097007d2986343a99968` | `5f0535d3ffe5738fc5baf4cb9b08ddc4c79b9f3890920a4ac9f7d335845554eb` | Converted CRLF to LF per repository policy. |
| `data/risk_audit.jsonl` | `f92ec8a2802d1e21f79fb8c18df5b3cb288b6e09213039f19e1e6d2dffd3c8f0` | `ec636010542ace717697fa95afca9173a209b30ef2b61906b120349592525d99` | Converted CRLF to LF per repository policy. |
| `infra/risk/risk_governance.lock.yaml` | `cfe9cf34554145327145de881ae0ac38642176a91a481c06fe830da10aa9fb87` | `cfe9cf34554145327145de881ae0ac38642176a91a481c06fe830da10aa9fb87` | Preserved exact CRLF bytes; protected by -text. |
| `packages/leviathan-core/src/leviathan_core/execution/routing/models.py` | `6b0b04d59aeaba983a6b1137d71084fac8f07b535515b493146a1dd00cb8b906` | `2a14a9b4151b0cde54d24e72cdb983227c44b39236e8a201ab2a090770c31e8e` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-core/src/leviathan_core/flash_loan_route_view.py` | `6126c48b6b3099753778879669b070994f09592b86090d279d4dd5dbb072b219` | `ced96f6732f7a76297b553c9e0cf2dc10bcea8a4a6ee332514c5a3b10dc43e64` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-core/src/leviathan_core/flow_radar/bursts.py` | `1bcc21b19e2f480940ad8e632f1f4f92ca9028065fb767fee8675e6d0aaab6d4` | `76e5f59c85b106ad7d493ec8cabd357e72e24e74ff0e88e16ac7bec8ac0cfb27` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-core/src/leviathan_core/flow_radar/tilt.py` | `6a06270c5c3e61bce880c2455bb73da7fdb75cb4995b4c196e1332cb7610fb57` | `c10016930fe4d7641e68687318ca90ea1749c391304e2f9cba72e4c5e97d92fa` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-core/tests/defi_arb/test_route_view.py` | `7e06278eeef01d68aedc47607384833ab225e530484219d2e18c52b029b75bf2` | `da97364c9edd72ff56724485a4c0610b2d0e33feb8a6d46ff57f7ef837ba932f` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-core/tests/fixtures/ibkr_tws/mapping_orders.jsonl` | `e6827429ec7eb2dc900c7ef44cb65d9253c72a6dfac0b9a6f273406b6b407fc1` | `592c0301cc28f34f92a85c384ba2c15c32326aafa09b49c0cac3f2107598084d` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-core/tests/fixtures/replay_job/v1-nq-missing-hedge.json` | `969cba4a8a2e8fbf95563e6167877279f07b95dbdaf3be7dbf057bcbf25ad134` | `f3f0f8445e0fdb15952e29dc11afa716bc3eddf5f741c2543f7f8ee61b0b0a63` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-core/tests/flow_radar/test_flow_kernel.py` | `0a8674b13752e464c5bd13f587ad770322fe87a28acf92f7deafe4f891b4fa0d` | `3b294149d248ca94e14560c3eb61f348912c23767fe63338c9f6a3cf76922e94` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-core/tests/knowledge_sync/test_archive_policy_acceptance.py` | `23c252a424495c8882784991933b63ff7d5ce0abc51e5e46b81d11d35bb976f1` | `c9bb67998cce769dae31f437c95b026722597fbfca0e143d97994fb334ce8f9c` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-core/tests/legacy_session/test_legacy_session_acceptance.py` | `38d1269519242432f7b488b63c8052fcacc7c05d28a52112fb51e7e3282d8c70` | `e3840a5d658de3037467733799c7dec1f74fd9239a9e65e1287f43135e851cc8` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-core/tests/mt_export_bridge/test_telemetry_envelope_acceptance.py` | `ad29c8dfe94876ce0efa9402e9c8fcac5ce47bf18cc2c9bab60bd9cb45a58e61` | `76dff16b0e0125f3d6d8ece32e8f530b68094d2ebf22a2604d7bd5eba335d3fa` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-core/tests/test_import_boundaries.py` | `75cedaa74f5cc3f3f73f8d2c99d4a3c9ed8182a8a9ec515296a8b042873dd473` | `090b2f50876acb1f22d9e4d9f28ec4cb8eacf4f3cd26957f8ceaa3ad47f1ebc7` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-market-data/tests/fixtures/ingress/native-timestamp-provenance.jsonl` | `2f9eacf18f82782cf5a32811d9968df7906d2bbd402ad5e6ff9c8a0d785898d6` | `8e8814d200de305e65f6fdad93fe5b1e330d7aa8d1a2864712ecd5463d3a6fb9` | Converted CRLF to LF per repository policy. |
| `packages/leviathan-store/tests/test_omega_due_store_acceptance.py` | `43626894a3fbdb5d0698ab9216dc14f2ca4706138f5126effe3652d970fb6608` | `f4f0c70977e0025a2cb42dfe0209e94745f69fcce18781b5e96ed86c9b2b1daf` | Converted CRLF to LF per repository policy. |
| `qa/gauntlet/performance/run.py` | `93bb444c515e1f02566c3d177d48fa1670b33ab02dfaeb7453fdb15197f895c9` | `c3a592a13c5c0a9389764a00a9782e01014d776f0d746e888bed847e7572d7f1` | Converted CRLF to LF per repository policy. |
| `qa/gauntlet/test_uncategorized_inventory.py` | `add9f3254324e0fb02bc8882e0e6f14ed71d0f85992a77861f08fd402aa4c5ac` | `7e90f39bf73e7065e64ddb40f6fd681ee41e56bd488f6baf4b9730740f2ee3c5` | Converted CRLF to LF per repository policy. |
| `qa/integration-backups/2026-10-08-pkg-mac-001-phase-a-c1c/qa/pkg-mac-001/phase-a-freeze.md` | `f46d952ca3cd2e5910ba8e3d338f85825b27e7fc06cc314f6e0f6b1ea0196f13` | `c9eac0b386dd5ce22fbe48432194c9aaad730e198e0d9ff737a110b2cb8e7af6` | Converted CRLF to LF per repository policy. |
| `workers/release-feed/tests/fixtures/admin-latest.json` | `7bef78cdb4abb7cc4d75445f3cbdc4d6e00a2ccb59459d284291bec7ce2a4ac9` | `9382ccf2b2c8a132c2103490bb173775774ea7c0f54de26eab1365b13771012d` | Converted CRLF to LF per repository policy. |
| `workers/release-feed/tests/fixtures/desktop-latest.json` | `068a86b4a8eb49ce54da11c6032aec09cb763085cf2dd1725fa081c95336902a` | `789db2c56fbbc4a0f40f744b8a0171e20f1f1c9c308d5e56da62be47dfd94a68` | Converted CRLF to LF per repository policy. |

### Cycle 2 verification on Windows

- `uv run --locked ruff check . --extend-exclude qa/integration-backups` and `ruff format --check` on the six typing-shim files passed.
- `uv run --locked mypy`, `mypy --platform linux`, and `mypy --platform darwin` each passed for 429 source files.
- Sidecar, release, and packaging suites: 212 passed, 1 skipped. Vault: 163 passed, 36 skipped. Store: 548 passed, 2 skipped. API: 1,446 passed, 1 skipped. HALT-focused tests: 5 passed.
- Terminal serial tests: 66 files, 1,400 passed, 1 skipped. `npm run build` passed and produced `apps/terminal/dist/index.html`.
- PyYAML BaseLoader parsed all five workflow files and policy assertions passed. `actionlint` was unavailable. PowerShell parsed `build.ps1` and `acceptance.ps1`. Git Bash passed `bash -n` for all three macOS scripts; verifier self-test rejected a bad second-slice minos and a non-x86_64 slice.
- Monolithic root pytest collection fails on duplicate test module basenames in default mode; importlib mode cannot resolve test-local helper modules. CI-style isolated suite invocations listed above passed. No hosted Actions build, macOS build, or Big Sur runtime test was executed by this Windows worker; those require coordinator push/hosted macOS runner and the owner Mac.

### Pinned action SHAs

| Action/tag | Commit SHA |
|---|---|
| `actions/checkout@v7` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-python@v7` | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| `actions/setup-node@v7` | `949feb2413d6458794dcd2491c4babbbce0c15c1` |
| `actions/cache@v5` | `caa296126883cff596d87d8935842f9db880ef25` |
| `actions/upload-artifact@v7` | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `astral-sh/setup-uv@v10.2.0` | `c18668ad3cf93ea998bef934396af7bb5c839dc7` |

New workflows reuse these pinned actions; `prerelease.yml` introduces no action dependency. No new action pin was introduced in cycle 2.


## Cycle 3 permission fix

Only `.github/workflows/prerelease.yml` changed in cycle 3. The publish job needs `actions: read` for `gh run list` and `gh run download`; its job-level permissions are now exactly `actions: read` and `contents: write`. Top-level permissions remain exactly `contents: read`.

| Changed path | Cycle 2 SHA-256 | Cycle 3 SHA-256 |
|---|---|---|
| `.github/workflows/prerelease.yml` | `01b13735d49d82a104636349dfad402be6b04b2be6f569836b708f4db417cc80` | `724c3ab1805b62158546610e7479e045d434b95c489a45b261d2c050f358021a` |

- PyYAML BaseLoader parsed the workflow; assertions confirmed manual dispatch only, top-level `contents: read`, a 20-minute job timeout, and publish-only `actions: read` plus `contents: write`.
- Cycle 3 ledger SHA-256 is reported out of band.
