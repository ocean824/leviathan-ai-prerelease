# Leviathan AI Windows desktop package

The desktop app is a Tauri 2 window around a loopback-only Python server. The
PyInstaller one-folder sidecar serves the existing FastAPI app at `/api` and the
built terminal at `/`. The shell waits for `LEVIATHAN_READY port=<n>` before it
opens the window. It stops the sidecar process tree when the window closes and
offers a restart if the sidecar exits unexpectedly.

## Build

On Windows 11 with Rust/MSVC and the Windows SDK, Node/npm, and `uv` installed:

```powershell
./apps/desktop/scripts/build.ps1
```

The script runs `npm ci` and `npm run build`, builds the PyInstaller sidecar with
`uv run --locked --no-dev --package leviathan-api --with pyinstaller==6.22.3`,
then builds the Tauri NSIS installer with CLI 2.12.0. It keeps generated Python, Rust, and staged files under
`apps/desktop`. It uses one Cargo job and the MSVC environment from
`vcvars64.bat`. The installer, `SHA256SUMS.txt`, and the CycloneDX sidecar SBOM
are in `apps/desktop/src-tauri/target/release/bundle/`. The SBOM inventories
every staged sidecar file and its SHA-256. `release-manifest.json` binds the
installer, sidecar BOM, source inventory, Rust/UI lockfile components, and the
cached offline WebView2 installer hash. Build output is recorded in
`infra/packaging/build.log` and `infra/packaging/build-native.log`. The build
prints the risk lock SHA-256.

The installer includes an offline WebView2 runtime. With
`TAURI_SIGNING_PRIVATE_KEY` set in the build environment, Tauri also creates and
signs the Windows updater archive; the private key is read only from the
environment and is never placed in build arguments or printed. Without the
key, the script prints `UNSIGNED UPDATE ARTIFACT`, skips updater signing, and
still writes a development `latest.json` with a null signature. The committed
`infra/release/updater.pub` is a DEV-ONLY public key and must be replaced by the
coordinator's release public key. The corresponding private key is never stored
in the repository. `infra/release/feed.json` supplies the feed base and endpoint
template; `latest.json` is written into the bundle directory.

At startup and every six hours the shell checks the signed update feed. A native
dialog offers “Download and install” or “Later”; Tauri verifies the archive
signature and the shell additionally accepts only a strictly newer SemVer
version. Before download and again before installation, the shell asks the
sidecar's capability-guarded `/desktop/update-readiness` route. LIVE mode, open
paper orders, a pending halt, or unreadable readiness state defer installation.
The app records a nonsecret deferred-update marker and reports that the update
will install on next launch. On that launch, the sidecar's bounded
`update-readiness` CLI checks the same local state before the normal API server
starts. The sidecar stops gracefully before installation, with a bounded
process-tree termination fallback. Protocol 01/02 secret scanning of build
inputs and outputs, binary artifact scanning, code signing, and installed
update acceptance remain separate release gates.

## Runtime data and security

The server binds only `127.0.0.1` on an available port. Native WebView bootstrap
adds a fresh per-launch capability header to same-origin `/api/` requests;
the server rejects missing or wrong capabilities and nonexact Host/Origin values.
The capability is never placed in a URL, log, or served asset. The browser content
policy permits only same-origin network requests. It never loads remote pages.
One shell owns the per-user data directory; a second launch focuses the existing
window in the same session. A separate exclusive data-file lock prevents another
session from starting a sidecar over that directory.
SQLite, risk audit, desktop logs, and a read-only copy of the risk governance
lock live in `%LOCALAPPDATA%\LeviathanAI\`. The sidecar checks the bundled and
local lock against the SHA-256 embedded during the build; a modified local lock
stops startup. No keys or `.env` files are bundled. Credentials must be resolved
at runtime through SEC-001.

## Silent installation

NSIS accepts `/S` and an optional `/D=<absolute install directory>` argument.
The installed app is `leviathan-desktop-shell.exe`; the uninstaller is `uninstall.exe`.
Silent uninstall uses `uninstall.exe /S`. Uninstall removes program files and
intentionally keeps `%LOCALAPPDATA%\LeviathanAI\` user data.

Run `./apps/desktop/scripts/acceptance.ps1` after building to verify silent
installation, loopback health and terminal HTML, native window capture, crash
restart prompt, rejected unauthorized requests, duplicate launch, close-during-startup
without orphan sidecar processes, silent uninstall, and retained user data. The
script uses an isolated temporary `LOCALAPPDATA` directory and writes `infra/packaging/acceptance.json` and
`infra/packaging/acceptance-window.png`.

The desktop shell sets `LEVIATHAN_HALT_STORE_PATH` to the absolute
`%LOCALAPPDATA%\LeviathanAI\data\halt-state.sqlite3` path before API import.
It classifies first use, existing v1 profiles, and previously provisioned
profiles from prelaunch evidence. It provisions the single core `HaltStore`
before readiness and writes `data\profile.json` only after a successful
provision or validation. Existing v1 profiles start with a durable
`legacy_state_unknown` halt until its exact reason is lifted. Missing or
corrupt previously provisioned stores stop startup. The marker records
lifecycle evidence; the halt database remains authoritative.

## Explicit retained v1 profile upgrade

A retained pre-HALT v1 profile can carry the old read-only risk lock SHA-256
46a03497679f8a59c82229ba28cef4bf56b7c1d7c30ae936016f876c9eaf3c51.
The current bundled lock is pinned to
cfe9cf34554145327145de881ae0ac38642176a91a481c06fe830da10aa9fb87.
Normal startup refuses the mismatch. With the desktop shell closed, an operator
may explicitly run the installed sidecar CLI:

    & "$InstallRoot\resources\sidecar\leviathan-desktop.exe" migrate-risk-lock --confirm 'MIGRATE:46a03497679f8a59c82229ba28cef4bf56b7c1d7c30ae936016f876c9eaf3c51:cfe9cf34554145327145de881ae0ac38642176a91a481c06fe830da10aa9fb87'

$InstallRoot is the actual install directory. The command uses the current
user's LOCALAPPDATA; verify it points to the intended profile before running.
Only that exact predecessor/current hash pair is allowed. The CLI acquires the
same per-user instance lock, requires a quiescent database with no WAL sidecars,
and backs up the old lock and database to timestamped read-only files under
%LOCALAPPDATA%\LeviathanAI\migrations\. An append-only audit records hashes,
backup name, and begin/commit/rollback events; it contains no database rows or
credential values. If interrupted, normal startup refuses the pending journal;
rerun the same confirmed CLI command to verify backups and complete or roll
back. Never delete the journal or marker to bypass this recovery.
If the durable legacy halt committed before its profile marker was written,
the retry verifies the lock, database and halt, writes the PRE_HALT_INSTALL
marker, and commits without discarding halt state. A malformed or incomplete
halt store stays quarantined by the pending journal: startup and automated
retry refuse it. Preserve the journal, backup, store and audit for an operator
review of the halt state before any manual recovery; do not delete them or
assume the profile can be re-provisioned safely.

Successful upgrade seeds the authoritative durable legacy_state_unknown halt
before API readiness. Clear that exact reason only through the normal named
HALT authority lift after reviewing the profile. The CLI does not lift it.

This package satisfies PKG-001 and overview child **LEV-REQ-X005** for the
Windows desktop shell. The installed acceptance checks durable ØMEGA halt
engage/restart/lift, corrupt-store refusal, native lifecycle, local API
capability rejection, and silent install/uninstall in an isolated profile.
