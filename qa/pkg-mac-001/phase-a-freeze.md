# PKG-MAC-001 Phase A freeze ledger

**Freeze status:** Cycle 1b resolver finding addressed; frozen for targeted re-check. macOS-host Phase B remains open.

**Fresh copied tree:** `C:/Users/XYRASYSTEMS/TRAYCER MASTER TEMPLATE/XYRA-MASTER/projects/XYRASYSTEMS/LEVIATHAN AI/repo-pkg-mac-001-phase-a`

**Canonical source:** `C:/Users/XYRASYSTEMS/TRAYCER MASTER TEMPLATE/XYRA-MASTER/projects/XYRASYSTEMS/LEVIATHAN AI/repo`

**Canonical-start hash record:** [canonical-start-hashes.json](canonical-start-hashes.json), SHA-256 `FEE967B46071CF252C06685CE85B5F881FA570AFB4516F6B3A1CCA1306D7B9B4`.

The tree was copied on 2026-10-08 at `2026-10-08T22:17:33.9294218Z`, before implementation edits. The hash record lists the initial hashes for the desktop build/config/process/license/vault/feed and protected API entrypoint files, supplemental canonical hashes for additional edited files, and paths absent from the canonical tree at copy time. It records excluded generated directories (`.git`, `target`, `node_modules`, `.venv`, `dist`, `__pycache__`, `*.pyc`, `.ruff_cache`, `.pytest_cache`). No canonical repo files were edited. Rechecking every initially hashed canonical file at freeze found no drift.

## Cycle 1 prior checkpoint hashes (superseded by cycle 1b final inventory below)

| File | Canonical start SHA-256 | Phase A freeze SHA-256 |
|---|---|---|
| `apps/desktop/src-tauri/src/main.rs` | `6e1336337337a117772b9cc7a4d43584bd9ae8d6de7d64f4537fc5c635d03a0b` | `16e2aa0d08efda3ffc4e0631d8295b6d5ec5419a238c4d3b38d4f42ec3a3289e` |
| `apps/desktop/src-tauri/src/license.rs` | `e5baea09c7d0a6202b21578661c418d89a28d65de9e69cfdd0b4444d5e3bd6f1` | `24e434571b7cd831429e1ae3b5c09a739f83486eb8f01bb366bc066b831fd3ec` |
| `apps/desktop/src-tauri/src/opener.rs` | `6b7da2d4ccf53d208a4bc7f5ba56ea9941468153321e873c73473506186773bb` | `9d6abb1c30c0feab2b107e83eb5c5b80af574205abeaf16b3ba1abf29d0bda5b` |
| `apps/api/src/leviathan_api/main.py` (protected; unchanged) | `424f4502497ed264bf491dbf10264b00b3499a3d55498af4d530222265d47db8` | `424f4502497ed264bf491dbf10264b00b3499a3d55498af4d530222265d47db8` |

## Phase A changes

- Moved `windows-sys` to a Windows target dependency and added a macOS-only `security-framework` dependency. Added `src/platform/{mod,windows,macos}.rs` to isolate data root, dialog, process flags/tree cleanup, profile path checks and single-instance file locking. Windows API behavior is retained behind the Windows module. The desktop shell uses the existing Tauri single-instance plugin.
- Added the macOS data root `~/Library/Application Support/LeviathanAI` in Rust and Python. Windows data and credential paths remain the existing `%LOCALAPPDATA%` paths. Sidecar readiness and risk-lock migration now call the shared Python resolver.
- Added a Keychain-backed runtime credential store behind the existing credential store interface. On macOS `keyring` is accepted only when the selected backend is Apple's Keychain; the saved on-disk profile contains an opaque marker, while the envelope is stored in Keychain. DPAPI remains the Windows backend. The Rust licensing cache stores its payload in Keychain and writes only `keychain:v1` to the data directory; sign-out deletes the Keychain item before removing the reference file, treats `errSecItemNotFound` as success, and returns a fixed cache error without claiming success if deletion fails.
- Added macOS device identity lookup from `IOPlatformUUID` via `/usr/sbin/ioreg`, then reused the existing device ID derivation and licensing payload contract.
- Added `tauri.macos.conf.json` with app/DMG targets, updater artifacts and an `.icns` icon. The shell resolves the sidecar by Apple target triple. `build-macos.sh` builds only the native host architecture and requires protected Tauri updater signing material. It stages only that target's sidecar. Admin packaging is unchanged and out of scope.
- Generalized updater manifest creation to accept per-platform artifact names and signatures and added Darwin arm64/x86_64 entries in fixtures. The existing release publisher uploads every manifest artifact and writes latest last; synthetic publisher tests now cover both Darwin keys. Existing worker target/architecture routing supports Darwin and has synthetic routing coverage.
- Added an unsigned internal DMG first-open/Gatekeeper guide, `MACOS_INTERNAL_TESTING.md`, and a macOS acceptance script. It prompts manual sign-in, confirms loopback health and duplicate-launch behavior, and names remaining host-only assertions.
- Corrected the Tauri opener acceptance test layout: Cargo previously auto-discovered a test file that was also included as a nested unit module, making `cargo test` fail on the original `super::super` import. The public denial assertion now lives in `src/opener/acceptance.rs` and remains part of the unit suite.

## Dependency provenance and license

| Dependency | Locked version | License | Use |
|---|---|---|---|
| Python `keyring` | 25.7.0; `>=25.6,<26`, Darwin marker | MIT | macOS Keychain-backed credentials; fallback backends fail closed |
| Rust `security-framework` | 3.5.1; macOS-only target | MIT OR Apache-2.0 | macOS Keychain-backed licensing cache |

No secret values, command-line secret arguments, commits, pushes, provider calls or release publication were used.

## Windows-host verification

| Gate | Result |
|---|---|
| `cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml --all -- --check` | PASS |
| `cargo check -j 1 --manifest-path apps/desktop/src-tauri/Cargo.toml` | PASS, no warnings |
| `cargo test -j 1 --manifest-path apps/desktop/src-tauri/Cargo.toml -- --test-threads=1` | PASS, 19 tests (16 library, 3 binary), 0 failures at resolver checkpoint |
| `uv run --locked pytest apps/desktop/sidecar/tests packages/leviathan-vault/tests infra/release/tests -q` | PASS, 262 passed, 37 skipped; one existing Starlette deprecation warning |
| `npm test` in `workers/release-feed` | PASS, 19 tests |
| `npm run typecheck` in `workers/release-feed` | PASS |
| `bash -n` on both macOS scripts using Git Bash | PASS |
| Python compile check on the PyInstaller spec; JSON parse checks on base and macOS Tauri configs | PASS |

API and terminal source files were not changed, so their full suites were not run. The Windows installer/acceptance scripts were not run in this phase; the verified Rust, sidecar and vault suites cover the affected Windows behavior. A Mac DMG build or macOS runtime test was not attempted from Windows.

## Phase B blockers and open verification

- The ownerâ€™s Mac must be connected as a host. Build one native architecture first, then the other. Real universal packaging remains deferred because the PyInstaller sidecar is architecture-specific.
- Verify the `security-framework` API compiles and run actual Keychain access/update/delete/relaunch/denial checks; verify Python keyring selects the Apple Keychain backend in the frozen application.
- Verify IOPlatformUUID stability and device binding, sign-in-first startup, loopback-only binding, process-tree shutdown/crash restart, single-instance behavior, application-support durability after removing the `.app`, signed updater install, strict version behavior and deferral/resumption with open orders.
- Exercise Gatekeeper first-open on the target macOS version. The DMG is unsigned and unnotarized; this is internal testing only.
- `infra/release/feed.json` and updater endpoint configuration still use placeholder release hosts. A live update test requires approved real feed configuration, trusted public key and the matching signing key supplied through the protected release environment. No actual release was signed or published in Phase A.
- `acceptance-macos.sh` includes manual steps for sign-in, restart confirmation, updater order deferral and data retention; those remain macOS-host acceptance checks.

Independent test author and reviewer are not claimed complete; coordinator assignment/integration remains next. No release-readiness or production claim follows from these Phase A Windows checks.

## Cycle 1 acceptance hardening

The cycle-1 independent acceptance finding required lexical validation of the environment-provided base path before appending the product data directory. Python and Rust now reject empty, relative, NUL-containing and parent-traversal bases with the existing fail-closed errors. Valid absolute paths are returned without canonicalization or normalization; existing final-directory symlink/reparse checks are unchanged. Unit tests cover invalid inputs and preservation of an absolute base.

The coordinator acceptance files were not modified. Their freeze hashes remain Python `263d7987c980926e5cc9f73a952608eeb66106e41fa9ab5fde4c030b3d31e79e` and Rust `4a521c48d785d83419338a877a6804e1ea16ae7ce411afa1240d924257a1d961`.

| Changed resolver file | Cycle 1 SHA-256 |
|---|---|
| `apps/desktop/sidecar/platform_paths.py` | `79e71bb232012ce38d6860512e8c1dad3799b85f67a7cb09f1d6f92f428e8a2e` |
| `apps/desktop/sidecar/tests/test_platform_paths.py` | `46cb37703c5097e44aee6d448c2172b534e87c9ac447d4492d480a71ca9e4e2e` |
| `apps/desktop/src-tauri/src/platform/mod.rs` | `57ef2d4172ebe668d6b17c3a9bcdfe30f5a02c6e5dea514d7e837605f44e6522` |

| Cycle 1 verification gate | Result |
|---|---|
| Unmodified Python acceptance file | PASS, 9 passed |
| Unmodified Rust acceptance file via Cargo integration test | PASS, 3 passed |
| Sidecar, vault and release infra Python suites | PASS, 271 passed, 37 skipped; one existing Starlette deprecation warning |
| Desktop `cargo test --locked --offline -j 1` with `TAURI_CONFIG={"bundle":{"resources":[]}}` | PASS, 26 total tests across library, binary and acceptance targets after review fix |
| `cargo fmt -- --check` | PASS |
| Ruff check and format check for touched Python and Python acceptance files | PASS |
| Release-feed worker `npm test` and `npm run typecheck` | PASS, 19 tests and typecheck |

The acceptance-file hashes were rechecked after testing and match the coordinator-provided values. Cycle 1 remains Windows-provable only; all Phase B macOS-host verification items above remain open.

## Cycle 1 review delta and final inventory

The independent review (`dde9d7f4`, CHANGES REQUESTED; review artifact SHA prefix `b21d7788`) identified a Keychain sign-out failure path, unrelated lock churn, incomplete changed-path accounting and generated cache files. Keychain cleanup now gates local marker deletion and the command success response. A non-not-found Security error maps to `CacheUnavailable`; a unit test verifies that this error leaves the marker-removal callback uncalled. Another test verifies item-not-found is idempotent success and a different status fails closed.

The `cssparser-macros` lock dependency is restored to canonical `syn 2.0.119`. The only remaining `Cargo.lock` difference from canonical is the new macOS-targeted `security-framework` dependency and its pin from canonical 3.7.0 to 3.5.1, matching the exact pin in `Cargo.toml`:

```diff
@@ package leviathan-desktop-shell dependencies
  "rustls",
+ "security-framework",
  "semver",
@@ package security-framework
-version = "3.7.0"
+version = "3.5.1"
-checksum = "b7f4bc775c73d9a02cde8bf7b2ec4c9d12743edf609006c7facc23998404cd1d"
+checksum = "b3297343eaf830f66ede390ea39da1d462b6b0c1b000f420d0a83f898bbbe6ef"
```

Generated cache files may exist or reappear during test runs. They are excluded from the changed-path inventory and are not deliverables; no repeated cleanup is required. The independent acceptance inputs below are non-author files authored by `e51a5665`; neither was edited.

### Complete changed-path inventory

All deliverable changed paths are listed below. The inventory excludes `.git/`, `target/`, `node_modules/`, `.venv/`, `dist/`, `__pycache__/`, `*.pyc`, `.ruff_cache/`, and `.pytest_cache/`; generated caches are not delivered. Integration should copy only ledger-listed source files. The ledger is a freeze record; its final SHA is bound by the sibling artifact `index.md`.

| Path | Final SHA-256 / status |
|---|---|
| `apps/desktop/MACOS_INTERNAL_TESTING.md` | `bdfd9af98146f13c8dca6fec4e2ce08519f119e38029073b3799007ebd39c5cf` |
| `apps/desktop/scripts/acceptance-macos.sh` | `be674a7d3c5a25077faab98b535362bb75572593fc310890cc0d18ccc9383fbf` |
| `apps/desktop/scripts/build-macos.sh` | `47aa5daa1f98e7514741358f88488b3981c00f5d9b2d571f0e99e02a32d196ed` |
| `apps/desktop/sidecar/leviathan_desktop.py` | `99cbcbc880ad570476bb6ac7674f732a24c17089473f140cd7be3972472a6a58` |
| `apps/desktop/sidecar/leviathan_desktop.spec` | `e891f62b71bfe5fcc8ec16a0587d39bdfc4db13e75f6e4a949187faff1bf63ce` |
| `apps/desktop/sidecar/platform_paths.py` | `79e71bb232012ce38d6860512e8c1dad3799b85f67a7cb09f1d6f92f428e8a2e` |
| `apps/desktop/sidecar/risk_lock_migration.py` | `0034150e616cfcefec47460d9b0e8717d0a97f929a547e5794282ae8ae419cea` |
| `apps/desktop/sidecar/tests/test_platform_paths.py` | `46cb37703c5097e44aee6d448c2172b534e87c9ac447d4492d480a71ca9e4e2e` |
| `apps/desktop/src-tauri/Cargo.lock` | `906a8a290b47cb711fd1f06a740982140146d8787c6d832ce8bf893b732f318d` |
| `apps/desktop/src-tauri/Cargo.toml` | `723adf2883df62250bfd17396bfa5885216f5cfd446a9ab1e1f2e78f5e39bb04` |
| `apps/desktop/src-tauri/src/lib.rs` | `33a83619b73a01733b36e33cb8aca580e4a4ade74dbaa72fe3ab98571af90f33` |
| `apps/desktop/src-tauri/src/license.rs` | `a6fa16891dabf06571baac1e24a9aebc01e6bd5fb082cc98f4f8d974843213b8` |
| `apps/desktop/src-tauri/src/main.rs` | `16e2aa0d08efda3ffc4e0631d8295b6d5ec5419a238c4d3b38d4f42ec3a3289e` |
| `apps/desktop/src-tauri/src/opener.rs` | `9d6abb1c30c0feab2b107e83eb5c5b80af574205abeaf16b3ba1abf29d0bda5b` |
| `apps/desktop/src-tauri/src/opener/acceptance.rs` | `200d437f72fb6ea14334d0f02455bf3ab76353ac461222a31e32084b84346840` |
| `apps/desktop/src-tauri/src/platform/macos.rs` | `543de789ca2a41fe3806ac7234c27bc838e40be1d0a29be429008923612529b1` |
| `apps/desktop/src-tauri/src/platform/mod.rs` | `57ef2d4172ebe668d6b17c3a9bcdfe30f5a02c6e5dea514d7e837605f44e6522` |
| `apps/desktop/src-tauri/src/platform/windows.rs` | `0c320220cba55586e7b5690266823f0244478a9b5d93affbd7c263bb8c1d5fcd` |
| `apps/desktop/src-tauri/tauri.macos.conf.json` | `084afadf4d4d3fd9ad21f3ebef189005f9bd16061a489badc6819a59bf1b15c8` |
| `apps/desktop/src-tauri/tests/opener_acceptance.rs` | deleted; assertion moved to `src/opener/acceptance.rs` |
| `infra/release/feed_manifest.py` | `0b91425f7d006af96b03f9e909a4c426b3761cad58c29854e08ccbb81c13dcf0` |
| `infra/release/tests/test_feed_manifest.py` | `16bd94a40c6971cabd8a4a5ece6830d2491c6de2d43e65e8cdf737a7cc0f9c2d` |
| `infra/release/tests/test_publish_feed.py` | `a3a76a7caf1dde90fccafa1eeab6dbfefa047a5fdeeb0102f4ffb6e76f860147` |
| `packages/leviathan-vault/pyproject.toml` | `f4159b7174d197afe7d3f446013f178e9962bb4f2cece262247de55aa40cd561` |
| `packages/leviathan-vault/src/leviathan_vault/app_credentials.py` | `679d11eed6ea07a1c8ff64d1fc676744dbf1af625c9cd0f7bfde48d7048f8cf7` |
| `packages/leviathan-vault/tests/test_macos_keychain_contract.py` | `c44f151655884e3974484117f2a5984a7a510057ee10728ab04662acc1c2af8d` |
| `uv.lock` | `8217f08bcdd0e017af9947517ad8a25bc0508ea55dfaf05f617cc989d7692c2a` |
| `workers/release-feed/tests/feed.test.ts` | `7dd1d56669641fcfe43d2b846a4b743dc461a56b0554c8544a69b514456be87a` |
| `apps/desktop/src-tauri/tests/pkg_mac_001_phase_a_acceptance.rs` | `4a521c48d785d83419338a877a6804e1ea16ae7ce411afa1240d924257a1d961` — acceptance author `e51a5665`, not PKG-MAC-001 |
| `qa/acceptance/pkg_mac_001_phase_a/test_pkg_mac_001_phase_a_acceptance.py` | `263d7987c980926e5cc9f73a952608eeb66106e41fa9ab5fde4c030b3d31e79e` — acceptance author `e51a5665`, not PKG-MAC-001 |
| `qa/pkg-mac-001/canonical-start-hashes.json` | `fee967b46071cf252c06685ce85b5f881fa570afb4516f6b3a1cca1306d7b9b4` — freeze record |
| `qa/pkg-mac-001/phase-a-freeze.md` | this ledger; final SHA is in sibling artifact `index.md` |

### Cycle 1a review-delta verification (before the credential-root finding)

| Gate | Result |
|---|---|
| Desktop Cargo tests with `TAURI_CONFIG={"bundle":{"resources":[]}}`, `--locked --offline -j 1` | PASS, 20 library + 3 binary + 3 acceptance tests; includes Keychain sign-out failure and item-not-found tests |
| `cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml -- --check` | PASS |

Cycle 1b acceptance and regression gates passed; ready for targeted re-review. No macOS-target build was attempted on Windows.
## Cycle 1b credential-path resolver fix

The cycle 1b acceptance finding identified `credential_root()` as a Windows bypass: it appended the credentials suffix directly to `LOCALAPPDATA`. Windows now resolves that base through `_validated_base`; macOS already routes credentials through `data_root()`, which uses the same validator. An audit of Rust found no parallel bypass: Rust callers use `platform::data_root()`, and the licence cache derives its path from that resolver.

Added tests cover empty, relative, NUL-containing and parent-traversal base values for `credential_root()` on both simulated OS branches. NUL values are supplied through a test-only environment proxy because the host OS rejects NULs in process environment variables.

| Cycle 1b gate | Result |
|---|---|
| Python acceptance file, unmodified | PASS, 9 passed |
| Sidecar, vault and release infra suites | PASS, 279 passed, 37 skipped; one existing Starlette deprecation warning |
| Desktop Cargo tests with `TAURI_CONFIG={"bundle":{"resources":[]}}`, `--locked --offline -j 1` | PASS, 20 library + 3 binary + 3 acceptance tests |
| `cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml -- --check` | PASS |
| Ruff check and format check for touched Python and acceptance files | PASS |

The final path hashes for `apps/desktop/sidecar/platform_paths.py` and `apps/desktop/sidecar/tests/test_platform_paths.py` in the inventory above bind the cycle 1b resolver and tests. Both acceptance file hashes still match the values supplied by the coordinator.

## Cycle 1c root Ruff formatting

Applied formatting-only import ordering and line wrapping to the four files identified by the integrated root Ruff gate. No behavior changes were made. The exact root command `uv run --locked ruff check . --extend-exclude qa/integration-backups` now passes with zero errors.

| File changed in cycle 1c | Final SHA-256 |
|---|---|
| `apps/desktop/sidecar/leviathan_desktop.py` | `99cbcbc880ad570476bb6ac7674f732a24c17089473f140cd7be3972472a6a58` |
| `apps/desktop/sidecar/risk_lock_migration.py` | `0034150e616cfcefec47460d9b0e8717d0a97f929a547e5794282ae8ae419cea` |
| `infra/release/feed_manifest.py` | `0b91425f7d006af96b03f9e909a4c426b3761cad58c29854e08ccbb81c13dcf0` |
| `packages/leviathan-vault/src/leviathan_vault/app_credentials.py` | `679d11eed6ea07a1c8ff64d1fc676744dbf1af625c9cd0f7bfde48d7048f8cf7` |

| Cycle 1c verification | Result |
|---|---|
| Root Ruff check, with integration-backups exclusion | PASS, zero errors |
| Ruff format check on the four changed files and `apps/desktop/sidecar/tests/test_platform_paths.py` | PASS, 5 files already formatted |
| Sidecar, vault and release infra Python suites | PASS, 279 passed, 37 skipped; one existing Starlette deprecation warning |

A broader Ruff format check over all three test directories reports six existing vault test files that are not formatted; none was changed in cycle 1c. The targeted changed-file format check above passes. The unmodified acceptance input hashes remain unchanged: Python `263d7987c980926e5cc9f73a952608eeb66106e41fa9ab5fde4c030b3d31e79e`, Rust `4a521c48d785d83419338a877a6804e1ea16ae7ce411afa1240d924257a1d961`.