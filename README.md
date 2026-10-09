# LEVIATHAN AI

> **Black Wealth Capital** — local, research-first trading software built around risk permission and operator control.

This repository is a **pre-release**. It is for internal development and paper testing; it is not a production trading service. The long-form product blueprint remains in the [LEVIATHAN-AI-BLACKWEALTHCAPITAL specification repository](https://github.com/ocean824/LEVIATHAN-AI-BLACKWEALTHCAPITAL), with condensed project and PRD notes in [docs/notes/](docs/notes/).

## Contents

- [Current status](#current-status)
- [Architecture](#architecture)
- [Build and run](#build-and-run)
- [Credentials and security](#credentials-and-security)
- [Checks](#checks)
- [Repository layout](#repository-layout)

## Current status

The Python domain core, API, local desktop shell, terminal, and paper-trading path are under active development. The paper path covers the signal-to-decision and risk checks through paper routes and persistent journal/state. Direct broker execution is not available.

The API includes a local market-data runtime for supported providers. With no provider credentials or valid runtime configuration, its status is `NOT_CONFIGURED`; no key is bundled or required for that state. The desktop enforces sign-in-first, license, and feature gates before exposing the operator surface.

The Connections workflow is write-only: replace a credential, test a connection, or remove it. Stored values are never displayed. For now, credentials are imported separately on each machine through the vault importer or Connections. Account-bound key sync (**KEY-SYNC-001**) is pending the Cloudflare data-gateway deployment; after verified owner/admin sign-in, it is planned to fetch the same provider keys at session start and cache them in Windows DPAPI or macOS Keychain. Live data feeds will continue to connect directly from the app.

Planned venues are Forex.com MT5, Interactive Brokers (IBKR), Coinbase, Kalshi, and Polymarket. These are venue plans; direct broker execution is still pending.

The Windows Tauri 2 desktop path uses the local NSIS build script and has an acceptance script. A macOS x86_64 workflow is configured to build an unsigned, unnotarized DMG for internal testing; the owner still needs to run the Big Sur checklist in [apps/desktop/MACOS_TEST_CHECKLIST.md](apps/desktop/MACOS_TEST_CHECKLIST.md). The separate admin Tauri app and UI are present for Windows-side administration.

Licensing and release-feed Cloudflare Worker source, tests, and local publishing tools are in the repository. **Cloudflare deployment, direct broker execution, and signed public releases are pending.** macOS CI does not receive updater signing or provider secrets; its build has updater archive generation disabled.

## Architecture

The Tauri 2 desktop shell starts and supervises a one-folder PyInstaller Python sidecar. The sidecar serves the existing FastAPI app and built terminal over a loopback-only HTTP listener. The shell opens its trading surface only after the sign-in and license/feature checks pass. The app uses an OS-backed credential store (Windows DPAPI or macOS Keychain) and keeps durable profile data outside the application bundle.

The API composes the Python domain packages, SQLite-backed local state, the paper routes, and the configurable market-data runtime. Provider credentials are resolved through the vault interface. Licensing and release-feed Workers provide the corresponding server-side code; they are separate from the local desktop process.

The core pipeline law remains enforced in code: only approved decisions reach execution intents, risk is evaluated before an intent, blocked actions are journaled, and the risk lock is verified before routes proceed. See [the pipeline contracts](packages/leviathan-core/src/leviathan_core/contracts.py) and their tests.

## Build and run

### Windows desktop

Install Python 3.14, `uv`, Node/npm, Rust/MSVC, and the Windows SDK. Build the local NSIS installer from the repository root:

```powershell
./apps/desktop/scripts/build.ps1 -LicenseWorkerConfig C:/path/to/license-worker-config.json
./apps/desktop/scripts/acceptance.ps1
```

The worker configuration supplies a service origin; it is not a place for provider credentials. The installer and acceptance evidence are written under `apps/desktop/src-tauri/target/` and `infra/packaging/`. A release-signed Windows installer requires the authorized signing keys, injected into the local build environment; keep those keys outside the repository and never pass them as command-line arguments. Release publication remains coordinator-controlled.

### macOS x86_64

The macOS build script requires a native macOS host matching `TARGET_TRIPLE`; Windows cannot cross-compile this Tauri package. The supported internal target is Intel `x86_64-apple-darwin`, with a macOS 11.0 deployment target. For a local build, install Python 3.11 (`python3` on PATH), `uv`, Node 24/npm, and Rust with Xcode command-line tools. The configured hosted workflow uses GitHub's `macos-15-intel` runner and uploads the unsigned DMG as `leviathan-macos-x86_64-dmg`.

To build locally on an Intel Mac without updater signing keys:

```sh
TARGET_TRIPLE=x86_64-apple-darwin \
MACOSX_DEPLOYMENT_TARGET=11.0 \
SKIP_UPDATER_SIGNING=1 \
bash ./apps/desktop/scripts/build-macos.sh
```

The DMG is under `apps/desktop/src-tauri/target/x86_64-apple-darwin/release/bundle/macos/`. It is unsigned and unnotarized. On first open, Control-click or right-click the app and choose **Open** to pass Gatekeeper for this internal build. The build requires x86_64-compatible native Python wheels; CI sets `UV_NO_BUILD=1` so a dependency without a wheel cannot silently compile from an sdist.

### Development API and terminal

From the repository root, sync the Python workspace. Start the API and terminal in separate shells for local development:

```sh
uv sync --all-packages
uv run uvicorn leviathan_api.main:app --reload
```

```sh
cd apps/terminal
npm ci
npm run dev
```

The desktop build compiles the terminal and packages it with the local API sidecar. Development routes, licensing configuration, and provider availability still apply.

## Credentials and security

- Add market-data credentials only through the vault's supported credential-import workflow. The app stores credentials in the platform-protected backend and resolves references at runtime.
- Never put provider keys, license tokens, or private signing keys in source files, `.env` files, command-line arguments, logs, screenshots, workflow YAML, or the repository.
- Windows uses the existing DPAPI-backed store; macOS uses Keychain. macOS may ask for permission to access the app's Keychain item.
- Desktop API traffic binds to loopback and uses a per-launch capability; it is not intended to be exposed on a LAN or public interface.
- User data is stored outside the app at `%LOCALAPPDATA%\\LeviathanAI` on Windows and `~/Library/Application Support/LeviathanAI` on macOS. Removing the app does not remove that data.
- macOS CI is configured to create an unsigned, unnotarized DMG with updater archive signing disabled; CI has no provider secrets.
- Do not use this pre-release to route live orders. Direct broker execution and signed releases are pending.

## Checks

Python workspace:

```sh
uv sync --locked --all-packages
uv run ruff check . --extend-exclude qa/integration-backups
uv run mypy
uv run pytest -q packages/leviathan-core/tests
uv run pytest -q packages/leviathan-store/tests
uv run pytest -q apps/desktop/sidecar/tests
uv run pytest -q packages/leviathan-vault/tests
uv run pytest -q packages/leviathan-market-data/tests
uv run pytest -q infra/release/tests
uv run pytest -q apps/api/tests
```

Terminal:

```sh
cd apps/terminal
npm ci
npm test -- --maxWorkers=1
npm run build
```

The release-feed Worker, licensing Worker, admin UI, and desktop sidecar have focused tests in their respective project directories. The Windows desktop acceptance run is `apps/desktop/scripts/acceptance.ps1`. The macOS workflow is configured to check x86_64 architecture, bundled Mach-O deployment targets at or below 11.0, sidecar layout, and a headless loopback health request; the owner checklist covers manual Big Sur behavior.

## Repository layout

```text
packages/leviathan-core/       Domain contracts, risk, decision, paper execution, journal
packages/leviathan-market-data/Market-data schemas, normalization, and providers
packages/leviathan-vault/      Credential-store interfaces and import support
apps/api/                      FastAPI application and paper/runtime routes
apps/terminal/                 React/Vite operator terminal
apps/desktop/                  Tauri shell, PyInstaller sidecar, build and acceptance scripts
apps/admin/                     Separate Tauri admin client and UI
workers/licensing/             Licensing Cloudflare Worker
workers/release-feed/          Release-feed Cloudflare Worker
infra/release/                  Feed manifest and publisher tooling
docs/adr/                       Architecture decisions
docs/notes/                     Specification and PRD digests
```

See [the current pipeline contract](packages/leviathan-core/src/leviathan_core/contracts.py), [docs/notes/](docs/notes/), and the [product specification](https://github.com/ocean824/LEVIATHAN-AI-BLACKWEALTHCAPITAL).
