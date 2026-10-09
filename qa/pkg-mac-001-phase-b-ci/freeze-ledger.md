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
