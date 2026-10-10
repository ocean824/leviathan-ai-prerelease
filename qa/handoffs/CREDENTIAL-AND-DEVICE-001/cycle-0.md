# CREDENTIAL-AND-DEVICE-001 — cycle 0

Status: implementation and local gates complete; awaiting coordinator integration/review.

## Scope and safety decisions

Credentials remain write-only. Secret values are accepted only at mutation/use boundaries, passed directly to the selected OS-backed store, and are not carried by `CredentialReferenceV1`, status responses, audit metadata, exception text, logs, terminal DOM, or chat tool results. Provider status/test chat tools are READ-only. Replace returns a secret-free `OPEN_REPLACE_FORM` UI intent. Remove is a user-confirmed mutation: the client obtains a short-lived token after explicit confirmation and submits it with DELETE. No credential secret is a chat argument; chat EFFECT registration remains for the later CHAT-CAPABILITY integration.

The removal confirmation port issues a `secrets.token_urlsafe(32)` token, stores only its digest, binds it to principal/provider/environment/profile/action, expires it within 60 seconds, bounds in-memory state, and atomically consumes it. Reuse, expiry, missing token, or binding mismatch fails closed. Token is returned only from the issue endpoint and is excluded from logs/audit.

Broker profiles continue using the desktop credential store. Market-data provider credentials share the project-secret vault references and uppercase names already consumed by MD-RUNTIME/MD-KEYS; reads and writes go through the platform-neutral project-secret port (Windows XyraVault/DPAPI and macOS Keychain backend). No parallel market-data secret store was introduced.

For broker profile replacement/removal, the mutation resolves affected LIVE accounts first, calls the checked deactivation path for all affected accounts, mutates the credential, bumps its revision, then audits. Unknown mapping, store failure, or checked-deactivation failure fails closed before mutation. Credential revision invalidates prior LIVE evidence independently. Existing `deactivate_account` behavior is unchanged. Credential mutations remain subject to the `GRACE_READ_ONLY` license gate.

Kalshi private-key upload is bounded and format-checked, written directly to the store without a temporary file, and the request buffer is cleared after write. Provider testers are injected fakes; this lane performs no external provider calls.

## Environment and import provenance

A fresh environment was built in this plain-copy worktree; canonical `.venv` was not copied. `uv sync --locked --all-packages` completed. `npm ci` in `apps/terminal` added 108 packages and reported 0 vulnerabilities.

Import-origin command:

`uv run --locked python -c "import leviathan_api,leviathan_market_data,leviathan_core,leviathan_store,leviathan_vault;[print(m.__file__) for m in (leviathan_api,leviathan_market_data,leviathan_core,leviathan_store,leviathan_vault)]"`

All five imported module origins were under this worktree.

## Gates

Each configured Python root ran in a separate default-mode process, without `--import-mode=importlib`:

| Root | Result |
|---|---:|
| `apps/api/tests` | 1,464 passed, 1 skipped |
| `packages/leviathan-core/tests` | 6,541 passed, 10 skipped, 1 xfailed |
| `packages/leviathan-store/tests` | 548 passed, 2 skipped |
| `packages/leviathan-vault/tests` | 166 passed, 36 skipped |
| `packages/leviathan-market-data/tests` | 1,128 passed |
| `apps/desktop/sidecar/tests` | 51 passed, 1 skipped |
| `infra/release/tests` | 65 passed |
| `qa/acceptance` | 25 passed |
| **Aggregate** | **9,988 passed, 50 skipped, 1 xfailed** |

Root `uv run --locked mypy` passed (431 source files). Root `uv run --locked ruff check . --extend-exclude qa/integration-backups` passed.

Terminal `npm run build` and `npm run lint` passed. Lint retains the existing `PaperMarketDataHealthView.tsx:154` `refreshVenues` effect-dependency warning. The unrestricted default `npm test` run was resource-sensitive: 1,381 passed, 1 skipped, 21 failed (timeouts under parallel load plus the pre-existing chart loading assertion). The full suite passed with bounded workers and timeout: `npm test -- --maxWorkers=2 --testTimeout=15000` — 1,402 passed, 1 skipped across 67 files. Focused credential/Connections/legacy LiveTrading tests passed; latest credential API test file: 16 passed (one upstream Starlette/httpx deprecation warning).

## Canonical sync and directory-diff provenance

The worktree is a plain copy of canonical, with `.git` preserved and no copied `.venv`. Final recursive filesystem comparison used canonical `repo` against this worktree, excluding `.git`, `.venv`, `node_modules`, `target`, `dist`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.mypy_cache`, `.vite`, `coverage`, `integration-backups`, and `*.pyc`. Untouched canonical drift was byte-synced before freeze. The final content delta is the 13 modified canonical files and 7 worktree-only files listed below; no other non-owned canonical drift remained. Initial copy exclusions also omitted `*.env*` (including `.env.example`) by instruction.

Canonical-start hashes below are the captured hashes from initial sync/comparison; `ABSENT` means the path was not present in canonical at start. Frozen hashes are the final worktree bytes.

| Path | Canonical-start SHA-256 | Frozen SHA-256 |
|---|---|---|
| `apps/api/src/leviathan_api/chat_tools_runtime.py` | `91334aecb28bb4805ae958d61005d3adc3b72c086d2aa8880b2cf16013d1309e` | `175344843cd1f3ad2ed9e0575c34a568fea153d0a2fdfec0d77d7b5d568307cd` |
| `apps/api/src/leviathan_api/live_activation_runtime.py` | `ce053e97c5c6b7cd137e7e1e98a90c4fa148d84cf9e23a2c193e5e022526217b` | `35f9b8e4b5786ae7fc7cf357f6feb336a641265de5cee61e03d7de651bb89d34` |
| `apps/api/src/leviathan_api/main.py` | `3d596400d1024b51489687cbb01611b3e031455e293c077666cdbba1ba76e93c2` | `17d424dd387ca3c2f289016d2cf68cab3d3a6212653f13ae78e58874cf2a1657` |
| `apps/api/src/leviathan_api/state.py` | `66e6056db8dce5374317368680f6075276a8f195af2d7deffb438f3430a67c41` | `5d84be0538547ba9c157e7f56d108aae6a5734eb4135447bf43444d40b5e0f8d` |
| `apps/api/src/leviathan_api/wave35_mounts.py` | `d0c70304b112dcd3c39616cf67cf779a5c6017bd6f24a5c04c048508080a3b55` | `ad92537001cb8721ce4b84ee2916915ef4a17433cb7e3a3a7b8effe714c3bbcf` |
| `apps/api/src/leviathan_api/chat/tool_bridge.py` | `6d392b2bcac0bb02a85cfb651b54afbaa6530a48101bdbfa9c47269d77c702f3` | `26b987958a6226dd463fc94030a7b8104e56befff6601901e56c7db5e340dff5` |
| `apps/api/tests/test_chat_tools_registry.py` | `efdc5d19d9c2c1d4d05e4ec61b3befab4824209065c2f8076ea3dfea69ad9896` | `ef3608eb402b527a6dd8d146a2589c28da7ac481cd3c47cbe4779d3991441585` |
| `apps/api/tests/test_chat_tools_registry_acceptance.py` | `48d75cb3a9b82127e5ca25d784c31adae4e6e104b8d41d7b01fd90e9aef1d151` | `1a1cc488fb4a625aa04bee2e39d232b14dbf1e1f46107a92e1abd8d0d47520c7` |
| `apps/api/tests/test_live_activation.py` | `ca760c35438b3a680cf6e591fa8a35f1b717db06b080a8c9fd46b27d52368011` | `11f05f25f4e211bc36f1dd8c0a9031db44d92a19197450f478424df55f4b7049` |
| `apps/api/tests/chat/test_chat_tool_bridge_acceptance.py` | `d535804d2b26ab1434a6c5d2c691d5e56d3ebf03bcf886b0015fae1529c5f241` | `b766224d6da8c66f384a777a901676d19fb3245f6fe84321e60f351eec926938` |
| `apps/terminal/src/wave34/connections/ConnectionsView.tsx` | `a8c922ce11dc26a009331508235af08c36ab54117ed700750e63ff84537f18a4` | `6693c84122caa88d716ce0d6681331f481ba205a0872b419811d264cd2b762d8` |
| `packages/leviathan-vault/src/leviathan_vault/app_credentials.py` | `679d11eed6ea07a1c8ff64d1fc676744dbf1af625c9cd0f7bfde48d7048f8cf7` | `86ece36d03cccf66bf72fdc82ccd6cec5b015d35cc389813dbfda9e638d0ea8e` |
| `packages/leviathan-vault/src/leviathan_vault/import_keys.py` | `6b8d5e839e953961b28010b777338c3562976379e12b623dd2839a2d1da50f0f` | `99df0f8191dfbe96c5431ea77c838b8dd06b600d1fa1a661ac0b10ed80e2f525` |
| `apps/api/src/leviathan_api/credential_connections.py` | `ABSENT` | `7d205a01968d1ebab309d7360f41e3472ce94e26552a9d39453e73e54a64be71` |
| `apps/api/tests/test_credential_connections.py` | `ABSENT` | `c761902aaff8dea789546b4810ba38f03bf051fff192e249284306bcc451b069` |
| `apps/terminal/src/wave34/connections/credentialApi.ts` | `ABSENT` | `0fe283b24d17f6093818dd2371dda20a3104cff185992b86a8302068ee4d4d85` |
| `apps/terminal/src/wave34/connections/CredentialConnectionsPanel.tsx` | `ABSENT` | `cbe5e1c3a6d959c154ab2418bda5c3e62c46768324fb855ca0dc5ffd832fd96d` |
| `apps/terminal/src/wave34/connections/test/credentialConnections.test.tsx` | `ABSENT` | `e3ec0e85218fa0f9fbece9e299b7650eb2b93bbd2618eecef1aa1badb5ca0701` |
| `packages/leviathan-vault/src/leviathan_vault/project_secrets.py` | `ABSENT` | `e8a73dc49494ce6f0b988d868f96661420e62fd14f117a1ede9703ea2cea97e9` |
| `packages/leviathan-vault/tests/test_project_secrets.py` | `ABSENT` | `bca277c59233a4e91a01154d537450f7e8d14c0481e9395669cc2381cd6dc697` |

## Integration gates / limits

- Production Connections store, project-secret platform wiring, per-provider tester implementations, LIVE profile-to-account projection, durable audit sink, and licence-middleware registration/configuration remain integration responsibilities. This slice exercised injected fakes only and made no provider/network calls.
- Windows DPAPI paths were exercised in this environment; macOS Keychain selection is covered through the backend seam but needs macOS host verification.
- Chat status/test are registered as READ-only. Replace/remove EFFECT registration is intentionally deferred to CHAT-CAPABILITY integration; Remove remains explicit user confirmation and is not delegated.
- Credential mutation routes are ordinary mutating routes and are denied under `GRACE_READ_ONLY` by the existing licence gate.
- Credential revision bump plus LIVE deactivation require production binding/revision adapters to be wired before LIVE use with these profiles.