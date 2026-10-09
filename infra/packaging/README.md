# Windows package evidence

`build.log` is the append-only transcript of `apps/desktop/scripts/build.ps1`
runs; `build-native.log` captures native-tool stdout and stderr. The NSIS installer,
`SHA256SUMS.txt`, staged-file CycloneDX sidecar BOM, and `release-manifest.json`
are emitted under `apps/desktop/src-tauri/target/release/bundle/`. The manifest
binds installer, BOM, source inventory, Rust/UI lockfile components, and cached
offline WebView2 installer hashes. The BOM describes staged sidecar files, not
the build environment or the entire NSIS installer.

The installer is unsigned while code signing remains an open product
requirement. `acceptance.json` and `acceptance-window.png` record silent install,
loopback health, terminal HTML, the native window, a forced sidecar crash and
successful restart prompt, unauthorized-request rejection, duplicate launch,
normal and rapid close without an orphan sidecar, silent
uninstall, and retained user data. User data under
`%LOCALAPPDATA%\LeviathanAI\` remains after uninstall by design.

HALT-001 is integrated. Desktop provisions its single durable authority before
the API imports and records profile lifecycle in `data\profile.json`; this
marker never substitutes for the halt database. `halt-acceptance.json` records
the installed sidecar's ØMEGA engage, crash/restart restore, exact lift,
lift persistence and corrupt-store refusal. PKG-001 also covers overview
child LEV-REQ-X005 for the desktop shell.

Cycle-2 retained-profile upgrade uses an explicit sidecar CLI confirmation of
the reviewed old/new lock digests. It leaves normal startup fail-closed on an
old pin or a pending migration journal. The CLI backs up the old lock and SQLite
database as timestamped read-only files, writes an append-only hash/event audit,
then provisions the durable legacy_state_unknown halt before readiness. The
synthetic v1-profile test covers an interrupted pin swap, verified rollback,
post-commit resume, unlisted pin refusal, backup tampering, and a named lift.
See apps/desktop/README.md for the operator command and recovery procedure.
