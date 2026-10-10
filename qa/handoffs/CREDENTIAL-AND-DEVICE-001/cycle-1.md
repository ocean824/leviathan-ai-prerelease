# CREDENTIAL-AND-DEVICE-001 — cycle 1

Status: cycle-1 implementation and required gates frozen; awaiting coordinator/reviewer integration.

## Cycle-1 adjudications

Cycle 1 closes reviewer findings P1 (legacy `/live-trading/credentials` mutation routes bypassed the Connections safety path) and P2 (the macOS project-secret factory accepted a generic keyring backend).

- Legacy PUT/DELETE retain their routes but delegate mutations to the shared credential service. Both paths derive the authenticated principal and credential binding, identify all affected LIVE accounts, run checked deactivation before mutation, mutate, bump revision, and audit. Resolution/deactivation/store failures fail closed. No router-owned credential-store write remains outside the shared service.
- The Keychain project-secret backend now reuses the PKG-MAC Apple Keychain validator. A non-Apple backend fails closed as `SECRET_UNAVAILABLE`.
- Independent acceptance covers the legacy path checks and fake non-Apple backend. Five scratch mutants were killed: secret logging, skipped LIVE deactivation, confirmation-token reuse, dropped revision bump, and malformed PEM acceptance.

## Frozen acceptance and source hashes

Independent acceptance (bc8d0f66): Python acceptance `9be97a0d27e689bbb0cb3bd7f61c6d14ca0bd5dcef1fcb00412b7729d9f70645`; terminal acceptance `9183a85173b3bc57007aa1847d03edd479fad089b1251129dc74b57bba6a379f`. Acceptance artifact SHA-256 `55d829780b9ef8f38e7aa411272794a6a2266a295dfa41367dbe55b8ce10f281` at `artifacts/leviathan-build/execution-and-intelligence-plan/credential-device-001/acceptance/index.md`.

| Path | Frozen SHA-256 |
|---|---|
| `apps/api/src/leviathan_api/credential_connections.py` | `63e494b734262ada925adbc369cb816bd4367ecc3604ab7191494cc23a857b6c` |
| `apps/api/src/leviathan_api/routers/credentials.py` | `541ce0f630ba1929fa00bab3fd1aacd5623bbd4f564efb50d0d1dcec96f88700` |
| `apps/api/src/leviathan_api/main.py` | `05c81e85e7724b8d7d9ad2c506f7822aa440e63482cce2afc2bcc4a31f7259d9` |
| `packages/leviathan-vault/src/leviathan_vault/project_secrets.py` | `662779c96d3b83df87c5af0d99b22a2a4dac273ec87f675b3c7d6dc8bca58e78` |
| `qa/acceptance/credential_device_001/test_credential_device_acceptance.py` | `9be97a0d27e689bbb0cb3bd7f61c6d14ca0bd5dcef1fcb00412b7729d9f70645` |
| `apps/terminal/src/wave34/connections/test/credentialConnections.acceptance.test.tsx` | `9183a85173b3bc57007aa1847d03edd479fad089b1251129dc74b57bba6a379f` |
| `apps/terminal/src/wave34/connections/credentialApi.ts` | `0fe283b24d17f6093818dd2371dda20a3104cff185992b86a8302068ee4d4d85` |
| `apps/terminal/src/wave34/connections/CredentialConnectionsPanel.tsx` | `cbe5e1c3a6d959c154ab2418bda5c3e62c46768324fb855ca0dc5ffd832fd96d` |
| `apps/terminal/src/test/liveTrading.acceptance.test.tsx` | `489576c99adaa3b91be4d4f3cecbac40f829a342cfc80566e20922e4b8fa7a97` |

The broader canonical-start and cycle-0 frozen hashes for all lane files are in `cycle-0.md`; cycle-1 changes are additive over that frozen snapshot. Current filesystem-diff hashes for every changed/new path are listed below.

## Rebase cutoff and filesystem census

Coordinator-set cutoff: canonical snapshot after syncing the 12 EXEC-CONTRACT-001 paths listed below. Canonical manifest SHA-256: `1f8b9a4e9e027cac189ed28c99c089383d92931824e1c25e92926f7bb97621d0`. Manifest rule: recursively enumerate regular files under canonical `repo`, excluding `.git`, `.venv`, `node_modules`, `target`, `dist`, `__pycache__`, `.pytest_cache`, `.ruff_cache`, `.mypy_cache`, `.vite`, `.wrangler`, `coverage`, `integration-backups`, `*.pyc`, and `.env*`; normalize relative paths to `/`; sort rows `path<TAB>lowercase SHA-256`; UTF-8 encode newline-joined rows; SHA-256 the bytes. Census: 1,531 files.

Copied from canonical after the cutoff was set and verified byte-identical:

- `packages/leviathan-core/src/leviathan_core/execution/broker_port_v1.py`
- `packages/leviathan-core/src/leviathan_core/execution/instrument_binding_v1.py`
- `packages/leviathan-core/src/leviathan_core/execution/oms.py`
- `packages/leviathan-core/src/leviathan_core/execution/order_models.py`
- `packages/leviathan-core/src/leviathan_core/execution/brokers/alpaca_mapping.py`
- `packages/leviathan-core/src/leviathan_core/execution/brokers/ibkr_mapping.py`
- `packages/leviathan-core/src/leviathan_core/execution/brokers/mt5_mapping.py`
- `packages/leviathan-core/tests/execution/test_broker_port_v1_acceptance.py`
- `packages/leviathan-core/tests/execution/test_instrument_binding_v1.py`
- `packages/leviathan-core/tests/execution/test_venue_order_admission_oms.py`
- `packages/leviathan-store/src/leviathan_store/oms_ledger.py`
- `qa/acceptance/exec_contract_001/test_exec_contract_001_acceptance.py`

Final directory comparison against canonical used the same exclusions: 1,531 canonical files, 1,541 worktree files, 31 path deltas. The deltas are the credential lane's modified/new source and tests plus its handoff ledger; the 12 EXEC-CONTRACT sync paths are equal to canonical. No unowned canonical drift was found at the frozen cutoff. Changes after the cutoff are integration drift for the coordinator's three-way merge; no further canonical resync was performed.

| Path | Canonical at cutoff SHA-256 (`ABSENT` if new) | Worktree frozen SHA-256 |
|---|---|---|
| `apps/api/src/leviathan_api/chat/capabilities_v1.py` | `e7c2e69bc662df6a375ac8ce03758c800920b38e9407fbb3614fceba7a498192` | `8a503d2f41403925fa9bc2f3f2a26eeebd5b13d41726dce7a6647d55a7911eb6` |
| `apps/api/src/leviathan_api/chat/tool_bridge.py` | `6d392b2bcac0bb02a85cfb651b54afbaa6530a48101bdbfa9c47269d77c702f3` | `26b987958a6226dd463fc94030a7b8104e56befff6601901e56c7db5e340dff5` |
| `apps/api/src/leviathan_api/chat_tools_runtime.py` | `91334aecb28bb4805ae958d61005d3adc3b72c086d2aa8880b2cf16013d1309e` | `175344843cd1f3ad2ed9e0575c34a568fea153d0a2fdfec0d77d7b5d568307cd` |
| `apps/api/src/leviathan_api/credential_connections.py` | `ABSENT` | `63e494b734262ada925adbc369cb816bd4367ecc3604ab7191494cc23a857b6c` |
| `apps/api/src/leviathan_api/live_activation_runtime.py` | `ce053e97c5c6b7cd137e7e1e98a90c4fa148d84cf9e23a2c193e5e022526217b` | `35f9b8e4b5786ae7fc7cf357f6feb336a641265de5cee61e03d7de651bb89d34` |
| `apps/api/src/leviathan_api/main.py` | `3d596400d1024b51489687cbb01611b3e031455e293c077666cdbba1ba76e93c2` | `05c81e85e7724b8d7d9ad2c506f7822aa440e63482cce2afc2bcc4a31f7259d9` |
| `apps/api/src/leviathan_api/routers/credentials.py` | `a5d2b88ca20084a21afaf427d9c213ad4a6202a133847d2658bf7a51f1ec3488` | `541ce0f630ba1929fa00bab3fd1aacd5623bbd4f564efb50d0d1dcec96f88700` |
| `apps/api/src/leviathan_api/state.py` | `66e6056db8dce5374317368680f6075276a8f195af2d7deffb438f3430a67c41` | `5d84be0538547ba9c157e7f56d108aae6a5734eb4135447bf43444d40b5e0f8d` |
| `apps/api/src/leviathan_api/wave35_mounts.py` | `d0c70304b112dcd3c39616cf67cf779a5c6017bd6f24a5c04c048508080a3b55` | `ad92537001cb8721ce4b84ee2916915ef4a17433cb7e3a3a7b8effe714c3bbcf` |
| `apps/api/tests/chat/test_chat_tool_bridge_acceptance.py` | `d535804d2b26ab1434a6c5d2c691d5e56d3ebf03bcf886b0015fae1529c5f241` | `b766224d6da8c66f384a777a901676d19fb3245f6fe84321e60f351eec926938` |
| `apps/api/tests/test_chat_capabilities.py` | `90571f4fb10100776556985f7c05fa519ad3a728abb7851d0cfe645ed5ea0b04` | `218ab1fdba8429edba30d3168e28c33427653e034593f26075508b0feee0f93b` |
| `apps/api/tests/test_chat_tools_registry.py` | `efdc5d19d9c2c1d4d05e4ec61b3befab4824209065c2f8076ea3dfea69ad9896` | `ef3608eb402b527a6dd8d146a2589c28da7ac481cd3c47cbe4779d3991441585` |
| `apps/api/tests/test_chat_tools_registry_acceptance.py` | `48d75cb3a9b82127e5ca25d784c31adae4e6e104b8d41d7b01fd90e9aef1d151` | `1a1cc488fb4a625aa04bee2e39d232b14dbf1e1f46107a92e1abd8d0d47520c7` |
| `apps/api/tests/test_credential_connections.py` | `ABSENT` | `c761902aaff8dea789546b4810ba38f03bf051fff192e249284306bcc451b069` |
| `apps/api/tests/test_credentials_api.py` | `92e2ad1b868b0affdbfeeae75b50f03443072c5de017b449159d291f30ac98ce` | `37a62212487fd19b1eb019cc67f15562c882a3d7938c27b52c72040c8615809f` |
| `apps/api/tests/test_credentials_api_acceptance.py` | `9453c193f3769fd30718192c411980125f380a6a201243487be7855af96dffed` | `e2b425205df252e8af612334c3e7beff5f27a7270cb19fbace9b6b4a049b3746` |
| `apps/api/tests/test_live_activation.py` | `ca760c35438b3a680cf6e591fa8a35f1b717db06b080a8c9fd46b27d52368011` | `11f05f25f4e211bc36f1dd8c0a9031db44d92a19197450f478424df55f4b7049` |
| `apps/terminal/src/tabs/live-trading/LiveTrading.tsx` | `e0ed902729b7d6f051e475a49c75a23a83c7cf42c554d5f8ff4a7273647b4f27` | `437579488efb63655468ee38857ed0019eef0437d7518442baa469982afe1f2f` |
| `apps/terminal/src/test/liveTrading.acceptance.test.tsx` | `e716a558d5466d48c1fa7b54b38d8e062968b7819f9f1a60d6c28e3ffe433885` | `489576c99adaa3b91be4d4f3cecbac40f829a342cfc80566e20922e4b8fa7a97` |
| `apps/terminal/src/test/liveTrading.test.tsx` | `cb3d370b87d86ddbbcf281ba2f7b2415c62409eafc5d2b50f5da05dabd022844` | `11714253cdd86b6c39b28f4b3f60d07b93f1f46313aebd3c07db53aaa99dc9ac` |
| `apps/terminal/src/wave34/connections/ConnectionsView.tsx` | `a8c922ce11dc26a009331508235af08c36ab54117ed700750e63ff84537f18a4` | `6693c84122caa88d716ce0d6681331f481ba205a0872b419811d264cd2b762d8` |
| `apps/terminal/src/wave34/connections/credentialApi.ts` | `ABSENT` | `0fe283b24d17f6093818dd2371dda20a3104cff185992b86a8302068ee4d4d85` |
| `apps/terminal/src/wave34/connections/CredentialConnectionsPanel.tsx` | `ABSENT` | `cbe5e1c3a6d959c154ab2418bda5c3e62c46768324fb855ca0dc5ffd832fd96d` |
| `apps/terminal/src/wave34/connections/test/credentialConnections.acceptance.test.tsx` | `ABSENT` | `9183a85173b3bc57007aa1847d03edd479fad089b1251129dc74b57bba6a379f` |
| `apps/terminal/src/wave34/connections/test/credentialConnections.test.tsx` | `ABSENT` | `e3ec0e85218fa0f9fbece9e299b7650eb2b93bbd2618eecef1aa1badb5ca0701` |
| `packages/leviathan-vault/src/leviathan_vault/app_credentials.py` | `09f529d96c56075f9a8b239c2f44985b8e5cf0ec84f5faeb783dffc0a657a810` | `aa904931199d4b3db3b9d1db3158577124bb7116e0e2a9d40e9f873f93bfee71` |
| `packages/leviathan-vault/src/leviathan_vault/import_keys.py` | `3e9f5e1091fec9f735d41faa62389166a0db499be0a17d22acf3ab03a28bdc4e` | `99df0f8191dfbe96c5431ea77c838b8dd06b600d1fa1a661ac0b10ed80e2f525` |
| `packages/leviathan-vault/src/leviathan_vault/project_secrets.py` | `ABSENT` | `662779c96d3b83df87c5af0d99b22a2a4dac273ec87f675b3c7d6dc8bca58e78` |
| `packages/leviathan-vault/tests/test_project_secrets.py` | `ABSENT` | `cdb9223ed6392fa3ead4c0db563e66a57ee792e7a4428da35e2bf05144f357b4` |
| `qa/acceptance/credential_device_001/test_credential_device_acceptance.py` | `ABSENT` | `9be97a0d27e689bbb0cb3bd7f61c6d14ca0bd5dcef1fcb00412b7729d9f70645` |
| `qa/handoffs/CREDENTIAL-AND-DEVICE-001/cycle-0.md` | `ABSENT` | `9b9bc3c854b73b7fd90795848d29e120928e059a88c1b1d559053f42d6d65758` |

## Gates

| Gate | Result |
|---|---:|
| Independent Python acceptance | 17 passed |
| Independent terminal acceptance | 3 passed |
| API + vault author suites with Python acceptance | 96 passed, 1 deprecation warning |
| Connections author suite + terminal acceptance | 5 passed |
| Full API root (post-cycle-0 canonical sync) | 1,494 passed, 1 skipped |
| Core root (post-cycle-1 cutoff sync) | 6,579 passed, 10 skipped, 5 warnings |
| Store root (post-cycle-1 cutoff sync) | 548 passed, 2 skipped |
| Vault root | 167 passed, 36 skipped |
| Market-data root | 1,129 passed |
| Sidecar root | 51 passed, 1 skipped |
| Release root | 71 passed, 1 failed (known mismatch below) |
| QA acceptance root | 67 passed |
| Combined per-root evidence | 10,106 passed, 50 skipped, 1 xfailed, 1 failed |
| `uv run --locked mypy` | Passed, 438 source files |
| `uv run --locked ruff check . --extend-exclude qa/integration-backups` | Passed |
| Terminal `npm test -- --maxWorkers=2 --testTimeout=15000` | 1,406 passed, 1 skipped, 68 files |
| Terminal `npm run build` | Passed |
| Terminal `npm run lint` | Passed; existing `PaperMarketDataHealthView.tsx:154` dependency warning remains |
| Import-origin check | All five package origins are inside this worktree |

The release-root failure is a coordinator-confirmed pre-existing canonical mismatch, not a blocker for this lane. `Deploy-LeviathanWorkers.ps1` now writes secret input as BOM-less raw bytes to prevent Wrangler storing a U+FEFF prefix, while `test_cf_deploy001_acceptance.py` still asserts the old text `StandardInput.Write($secretChars`. CF-DEPLOY cycle 3 (9f80bb72) owns the assertion update and regression tests. Neither release file was edited here.

## Integration gates

- Production Connections persistence, platform project-secret resolver wiring (Windows XyraVault/DPAPI and macOS PKG-MAC Apple Keychain), durable audit sink, real per-provider test adapters, and production credential-profile→LIVE-account resolution/deactivation/revision adapters must be wired before production use. This lane used fakes and made no provider calls.
- The licence gate is registered; credential mutations are blocked in `GRACE_READ_ONLY`.
- Chat tools expose status/test as READ only. Replace returns a secret-free `OPEN_REPLACE_FORM` intent; Remove uses the locally injected, single-use, digest-stored confirmation-token port with TTL ≤60 seconds. No chat EFFECT registrations were added; future chat wiring must use these APIs and preserve owner-only UI confirmation for credential removal.
- Credential values never enter reference/config/UI/chat status or audit data; secret values are consumed only at write/test boundaries and UI write fields clear after submit.