# API-ANYTHING-001 Cycle 5 freeze ledger

- Generated at: `2026-10-10T06:34:42+00:00`
- Baseline: C5 start manifest (1768 files; SHA-256 `98a4854e604ade1107cc5898bf357566922571602a9db4088682c95f841c3b5f`)
- Source Cycle 4 ledger SHA-256: `6292791dae22035f04bb9bba83bb59f33c109d15c59e9ec0204f62009160bc8a`
- Diff totals: 5 added, 12 modified, 1 deleted.
- Excluded generated/cache directories: `.git`, `.venv`, `node_modules`, `target`, `dist`, Python caches, `.scratch`, and `.vendor-build`.
- Excluded the three shared `public_sources` files owned by PUBLIC-DATA-001, integration backups, and independent `qa/acceptance/API-ANYTHING-001/cycle2/` files.

## Cycle 5 changes

- Fixture sanitation now accepts each operation's native mapping recipe. It preserves the values selected by `extract`/`pick`, and redacts only unconsumed fields. Per-operation tests feed realistic JSON bodies with multi-word capitalized values through the built vendor extractor and assert `extract(sanitized) == extract(raw)` for all five operations.
- Fed and Senate mapping recipes remain JSON and now have registry-level `recorded-native-body-required` pin gates. The runtime rejects a pin for either operation unless its mapping provenance is a recorded native body from a live response.
- `templateMatchesMapping` runs against each committed template at call time before fixture replay or request serving.
- Added a production stdio learn test that feeds a recorded 403 challenge page to the real vendored `addOperation`; the production learn branch emits `USER_ACTION_REQUIRED`, performs the test-only handoff seam, resumes with a recorded success capture, and returns a candidate-only result.
- Regenerated `api-anything-runtime.patch` as one eight-file unified diff. The generator verifies reverse application against the vendored patched state and clean application to the reconstructed pristine tree. SHA-256 is pinned in the build script and runtime manifest.
- Created the C5 tree's own `.venv` with `uv sync --locked`; generated environments and build outputs are excluded from the ledger.

## Verification

| Gate | Result | Scope |
|---|---:|---|
| `npm test` | 24 passed | Collector sidecar build, unit tests, and production stdio process tests |
| Core pytest | 6,578 passed; 10 skipped; 1 xfailed | Separate `uv run pytest -q packages/leviathan-core/tests` process |
| Store pytest | 548 passed; 2 skipped | Separate process |
| Vault pytest | 163 passed; 36 skipped | Separate process |
| Market-data pytest | 1,150 passed | Separate process |
| API pytest | 1,475 passed; 1 skipped | Separate process; 15 existing warnings |
| Mypy | passed, 442 files | Default, `--platform linux`, and `--platform darwin` |
| Ruff requested command | 67 pre-existing F811 findings | `uv run ruff check . --extend-exclude qa/integration-backups`; findings are duplicate fixture imports in untouched acceptance cycle1 files |
| Ruff owned handoff script | passed | `generate_cycle5_ledger.py` |
| Finding acceptance | 7 passed, 2 failed, 210 deselected, 3 xfailed, 1 xpassed | Exact failures: `test_03_real_vendor_loopback.py::test_finding_second_call_in_same_process_must_not_block_for_the_cadence` and `test_03_real_vendor_loopback.py::test_finding_bot_wall_reaches_the_user_action_handoff_with_real_vendor`; both use the stale generic `extract: data` template. Acceptance-owned files were not modified. |
| Full cycle1 acceptance | 31 passed, 29 failed | Existing pinned-template fixtures use a generic `data` extractor and Fed/Senate pins lack recorded-body metadata required by C5. Acceptance-owned files were not modified. |

### Full cycle1 acceptance failure IDs

The full cycle1 acceptance failure IDs are:
- `test_c1_pins_policy.py::test_pinned_operation_serves_typed_provenanced_records_through_the_real_runtime[calendar.fed]`
- `test_c1_pins_policy.py::test_pinned_operation_serves_typed_provenanced_records_through_the_real_runtime[earnings.forward]`
- `test_c1_pins_policy.py::test_pinned_operation_serves_typed_provenanced_records_through_the_real_runtime[senate.efd.ptr]`
- `test_c1_pins_policy.py::test_pinned_operation_serves_typed_provenanced_records_through_the_real_runtime[cboe.daily.stats]`
- `test_c1_pins_policy.py::test_pinned_operation_serves_typed_provenanced_records_through_the_real_runtime[cnn.fear_greed]`
- `test_c1_pins_policy.py::test_stale_canary_runs_a_new_canary_before_serving`
- `test_c1_pins_policy.py::test_template_pointing_at_a_foreign_host_is_blocked_before_any_request`
- `test_c1_pins_policy.py::test_redirect_to_another_host_is_blocked_and_never_followed`
- `test_c1_pins_policy.py::test_redirect_within_the_allowed_host_is_followed`
- `test_c1_pins_policy.py::test_http_downgrade_redirect_is_blocked`
- `test_c1_pins_policy.py::test_robots_disallow_blocks_the_data_request`
- `test_c1_pins_policy.py::test_robots_specific_allow_beats_broader_disallow_and_our_agent_group_wins`
- `test_c1_pins_policy.py::test_robots_server_error_fails_closed_but_404_means_allowed`
- `test_c1_pins_policy.py::test_robots_policy_is_cached_on_disk_between_restarts`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cnn.fear_greed-stale observation-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cnn.fear_greed-future observation-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cnn.fear_greed-empty result-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cnn.fear_greed-duplicate ids-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[calendar.fed-empty event name-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[calendar.fed-scheduled absurdly far away-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[earnings.forward-ticker lowercase-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[earnings.forward-scheduled two years back-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[senate.efd.ptr-report on a foreign host-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[senate.efd.ptr-no transactions-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cboe.daily.stats-value out of range-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cboe.daily.stats-stale-<lambda>]`
- `test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cboe.daily.stats-term structure without maturity-<lambda>]`
- `test_c1_pins_policy.py::test_schema_invalid_rows_are_rejected`
- `test_c2_template_transfer_replay.py::test_cross_tree_export_import_then_replay_only_call_succeeds`

These old fixtures are rejected at call-time mapping validation before their intended assertions run.

The independent cycle2 acceptance directory is not present in this tree and was not touched. No live site learning was performed. The committed activation registry still pins no operations; candidates remain quarantined pending the normal writer, acceptance, review, and coordinator integration flow.

## Diff-generated file inventory

| Status | Path | Old SHA-256 | New SHA-256 | New bytes |
|---|---|---|---|---:|
| added | `qa/handoffs/API-ANYTHING-001/generate_cycle5_ledger.py` | `-` | `e366b76595fd4b8254ec8e8063f193bef60d6bae77e9bc1a6c87a6b46303fb40` | 11175 |
| deleted | `qa/handoffs/API-ANYTHING-001/make_cycle5_start.py` | `8a19586a586f65b4c695f84111cfea6482497d41cbd5981c29c363ca08698366` | `-` | - |
| modified | `services/public-collector/README.md` | `06ad5308a89dcdf7d9b9e5bba768e7a8cada29f1bf04461ca606b9c4167a86aa` | `e44f4b73fd1ed9a7b124bb867edf64d0e9a0715b394ee097e44e0b4662004857` | 6456 |
| added | `services/public-collector/e2e/learn-wall-fetch.mjs` | `-` | `466d3c1e42f807c1077b9d3415f0d355d622844b8fa0531278aa09ffceb1ca86` | 618 |
| added | `services/public-collector/e2e/learn-wall-loader.mjs` | `-` | `50146c387ef19d02c0189cab0b6b5e3708cf82af50a0a1229bd1ca4c60b9c1d9` | 1635 |
| added | `services/public-collector/e2e/learn-wall.test.mjs` | `-` | `27ab05b396afc8a5dd8af1f94c6718d75b16a7e6b524449efcea87cf899896c6` | 4027 |
| modified | `services/public-collector/patches/api-anything-runtime.patch` | `36135f286cb13b7c4e65de049ccc0beaa56f47aad6042a84d60ecf4edfbdad67` | `5409be5220c92fc6c6b2d5d6acc2ca819983a61f3204403ab5a58c175f0431cc` | 104354 |
| modified | `services/public-collector/runtime-manifest.json` | `27e714928715ad10a790299855175682a9b3897619603eff3917c82f67f3115f` | `ad54146e13ecd10f3382e96b557f50d75ede81ea38b8307383ea8f04b0f33310` | 459 |
| modified | `services/public-collector/scripts/build-vendor.mjs` | `504b0c2bd7a754722fc5d82adf9aa83b54ec6fea6df88260bbee003f6f3ac836` | `7e41ca5bbc2ea37a3e2d21a0e48a47eb079dabe386b82f01e1e9e91012630cae` | 4072 |
| added | `services/public-collector/scripts/regenerate-vendor-patch.mjs` | `-` | `3b60a842dd89ab549d7942c9c11d7540fe045fa384713a6181e69b4bee1ebf03` | 2996 |
| modified | `services/public-collector/src/contracts.test.ts` | `4f76751ad731b18849621067b4965fb9829397ff8dc1045e30f51395d003dc45` | `530614ae78aa20be7a6b473cdefb92f44a3130ef59bc8eda37585fece4ac1bc2` | 1975 |
| modified | `services/public-collector/src/contracts.ts` | `a64e49a60b56a5529d62ecb890458496923ffad616d175de38289bc7d2059d3b` | `5a075ee917c2d089666aff8cdf8ac9a5bc43f4d71e5ecd5fa25a1955fe34c74a` | 9358 |
| modified | `services/public-collector/src/fixture-sanitize.test.ts` | `675f140781cd2a1fce4a01936025e71260a99bf5ad0db92d0dbcb4a902e6fa3b` | `ce274736a5d5556ee7521f863b707d06ae386b97bdb2636bd8c52676f62d8e2c` | 3691 |
| modified | `services/public-collector/src/fixture-sanitize.ts` | `9393ba3900501a0b746a8d4344b774f123f7c932aca6e53468bdeb0490e9e8bc` | `4b95d624469a41f980eee99fb56d9747aa55daf3c8285e23d823d51d842242d9` | 4152 |
| modified | `services/public-collector/src/main.ts` | `5fb3ccc9cf1dd017f1ea9d63ff6d276c648df844c0a1b3dbe6719c5cc7386893` | `d8d5db18fea4dec920114dab20419b6120c2886036a37ae95f54609f425000d2` | 46315 |
| modified | `services/public-collector/src/mapping.test.ts` | `7f83737c587faaf2954cfc7f7ddc2b99d04887bf68820397d05463d6411a2e38` | `1dec2683c9fc896da20b626a33343a21be13e9277e4665aa99ee389fadc854b6` | 2117 |
| modified | `services/public-collector/src/pin-hash.ts` | `a1e1ecbc16764a2063f4bedd43603e33e7f576b19bef694b908272b5d6cf1f80` | `c92561e15537136e54890c1f29d34d7391074115bbad004cc4a33c43d9056ac6` | 172 |
| modified | `services/public-collector/templates/PINNED.json` | `ac4cc2b5d18ec89b55f79580e09a8a63b885a803a0bb8ac264eca3ed1020f967` | `97018c92db2f207bde57dac7da01bc3aae6d8aa82176b1fe3ea51312b6bf91ee` | 3305 |
