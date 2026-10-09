# macOS internal desktop testing

Phase A adds per-architecture packaging. The builder must run on a Mac with the matching native architecture; Windows cannot build the Tauri macOS application. Set `TARGET_TRIPLE` explicitly when needed (`aarch64-apple-darwin` or `x86_64-apple-darwin`). The resulting app and DMG are unsigned and unnotarized because an Apple Developer ID certificate is unavailable. Signed Tauri updater archives use the separately protected Tauri updater signing key.

For the first launch of the unsigned app, mount the DMG and copy **Leviathan AI.app** to an Applications folder. Control-click the app, choose **Open**, then choose **Open** again in the Gatekeeper confirmation. The ordinary double-click path may report that Apple cannot verify the developer. This exception is for the internal test build only.

User data remains outside the app at `~/Library/Application Support/LeviathanAI`; removing the app bundle or ejecting the DMG does not remove this folder. Runtime credential envelopes are references only; their secret payloads and the cached licensing session are stored in macOS Keychain. A Keychain access failure is fail-closed.

Build one architecture at a time. To publish one `latest.json` containing both Darwin entries, provide the other already-built signed archive through `OTHER_DARWIN_ARTIFACT` and its detached signature through `OTHER_DARWIN_SIGNATURE`. The feed publisher uploads immutable archives first and updates `latest.json` last; clients receive only strictly newer manifests. The updater signature key is distinct from Apple application signing.

## Phase B acceptance on the owner's Mac

Record the macOS version and architecture, inspect the bundle architecture, and test first-open Gatekeeper handling. Verify sign-in-first behavior, loopback-only sidecar binding, Keychain store/update/delete/relaunch and denial behavior, device binding, duplicate launch, graceful close, sidecar crash/restart, persistence after removing the app, signed update installation, strict older/equal-version rejection, and deferral/resumption while orders are open. The Phase A Windows host cannot validate these macOS-only behaviors.

## Added dependency rationale and license

| Dependency | Version constraint | Purpose | License |
|---|---|---|---|
| Python `keyring` | `>=25.6,<26`, macOS marker | Uses the macOS Keychain API for runtime credential envelopes; the code checks the selected backend and refuses other/fallback backends. | MIT |
| Rust `security-framework` | `=3.5.1`, macOS-only Cargo target | Uses Apple's Security framework for the cached sign-in session. | MIT OR Apache-2.0 |

Neither dependency places secret material on a command line or in source. The Python backend stores a base64 envelope as a Keychain item; the on-disk profile contains only an opaque version marker. The Rust session reference file contains only `keychain:v1`.
