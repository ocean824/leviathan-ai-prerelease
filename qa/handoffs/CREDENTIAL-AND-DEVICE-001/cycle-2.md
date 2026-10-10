# CREDENTIAL-AND-DEVICE-001 — cycle 2

Status: device-binding correction implemented and locally verified; awaiting coordinator merge and reviewer closeout.

## Finding and correction

Cycle 2 addresses the P2 in `execution-and-intelligence-plan/credential-device-001/review/index.md`: a LIVE account record's `device_id` was not compared with a verified device identity.

- `PrincipalV1` and the sealed `TrustedPrincipalV1` now carry an optional validated `device_id`. The trusted adapter copies it as part of the sealed principal.
- `VerifiedPrincipalV1.device_id` is optional for compatibility with non-LIVE identities. `PrincipalVerifier.verify()` accepts it only from the signed token claim, rejects a malformed non-null claim, and carries it through `to_sec002_claims()` into the sealed trusted principal. A missing claim remains `None`.
- `_owner_account()` now requires a non-null principal device and an exact match with the server-side account evidence device. A missing or mismatched identity returns the existing fixed `ACCOUNT_NOT_FOUND` denial before LIVE precondition reads or event writes.
- The request body has no device field; a caller-supplied `device_id` is rejected by the strict request schema. No value from `LiveAccountEvidenceV1` is copied into the trusted principal.
- Existing owner/role logic was not changed in this cycle. The concurrent AUTH-GOOGLE-001 removal of the role gate remains an integration merge responsibility; this patch does not add or restore a role gate.

## Canonical cutoff and rebase

Cycle-2 base for `live_activation.py` was canonical SHA-256 `58d97f5247ee73abe5f6e35706b8e8da1264339b194713a5a0480986545ff896`; its only functional delta is the two device checks in `_owner_account()`.

The coordinator identified formatting-only canonical drift in the two core principal modules and authorized a local rebase. They were recopied from canonical at `authz_models.py` SHA-256 `002b770e615a0d270bc4f10a342b648804596c294611c280d9536e9e81419ed9` and `principal_verifier.py` SHA-256 `6b38b2fb49b48e428b2d7e45a9a0cb7cbe92e90cfe842491f1b218ca85d9d6d0`, then the device-id additions were reapplied and Ruff formatting run. The functional changes are limited to the optional field, its validation/sealed propagation, and token claim extraction.

## Frozen file hashes

| Path | Canonical-start SHA-256 | Cycle-2 SHA-256 |
|---|---|---|
| `apps/api/src/leviathan_api/routers/live_activation.py` | `58d97f5247ee73abe5f6e35706b8e8da1264339b194713a5a0480986545ff896` | `8d1cd58348adbcffb6fdff11f069e6dffeff7acb8162207667f0d8afeab6181c` |
| `packages/leviathan-core/src/leviathan_core/security/authz_models.py` | `002b770e615a0d270bc4f10a342b648804596c294611c280d9536e9e81419ed9` | `3da00327e835f4c2e5c6a059e18c22b0f4c064bbc6cb9fbda0a628edcf14e4b1` |
| `packages/leviathan-core/src/leviathan_core/security/principal_verifier.py` | `6b38b2fb49b48e428b2d7e45a9a0cb7cbe92e90cfe842491f1b218ca85d9d6d0` | `bed45deb8bc5bb7839713c063bf72f6ab12964e7ec6c0dccadd2778a8e7afae2` |
| `apps/api/tests/test_live_activation.py` | `11f05f25f4e211bc36f1dd8c0a9031db44d92a19197450f478424df55f4b7049` | `e85a8c6fb62681c41e811aa1f23e7c7dd86f4d9afe60d136bf7ca224138f63a3` |
| `apps/api/tests/test_live_activation_acceptance.py` | `dd468cd9b44c3b7310ed64e8951eeeab4d4c3947665c90517229926e071abfc5` | `af68612047471aeec7573e357938b5d45d7aae355dab90e3b9d3bb8e5586a2ad` |
| `apps/api/tests/test_live_wire.py` | `bf0021fccadcf4ed1e00fc445c267b7d1f9b66a50301f14a6d72213e55b29b0b` | `735ba1698dc4c1b38690b4ae86738201e456a890f75bf6a150c8c79b0c7ddec9` |
| `packages/leviathan-core/tests/security/test_principal_verifier.py` | `3c700df652d3be64fce8e91b67a79dfc1157cb2cc797482e94d37b10e61002ab` | `f535ea6ccef78e719e34c98979f9496b255b8376fb7420a6e68f8d3828dea2c6` |
| `packages/leviathan-core/tests/security/test_sec002_seal_migrate.py` | `76b8ad8f38fb747dcba394671964c430cc4c331e46819366b36d77c733f20929` | `2d302197c49a049007374170128ebe7333b9f7faf5ef5b5ee7f28a8bc2203e2f` |
| `packages/leviathan-core/tests/security/test_sec002_seal_migrate_acceptance.py` | `f720223e05d3f26956038994ff4f241d073d9df847d856f97de09ea58e9d8641` | `9978bdc4e4e458ecc032d1221d522a1b2aa0e5ad4a7171d4d2b3ae23cae4b9ef` |

The unmodified cold acceptance input `qa/acceptance/CREDENTIAL-AND-DEVICE-001/test_credential_device_cold_acceptance.py` has SHA-256 `6ff02ae8e93c4b794206d1e963e712e7f012a21997ed2e2909581540dba34e46`.

## Verification

| Gate | Result |
|---|---:|
| Cold acceptance + LIVE/auth focused tests | 132 passed, 1 upstream Starlette/httpx deprecation warning |
| Full API root, `uv run --locked python -m pytest apps/api/tests -q` | 1,497 passed, 1 skipped |
| Full core root, `uv run --locked python -m pytest packages/leviathan-core/tests -q` | 6,579 passed, 10 skipped, 1 xfailed |
| Isolated core OMS timing regression | 1 passed in 102.87s |
| Root mypy | Success, no issues in 438 source files |
| Ruff check and format on all nine changed files | Passed |
| Import-origin check | `leviathan_api`, `leviathan_market_data`, `leviathan_core`, `leviathan_store`, `leviathan_vault` all imported from this worktree |

The first full API attempt exposed that directly constructed non-LIVE verified principals omitted the optional claim; setting the sealed model default to `None` resolved it, and the full API root then passed. The first core-root attempt ran concurrently with the API root and hit the timing-sensitive OMS test plus a test-fixture field list; the standalone timing test and subsequent full core root passed after correcting the fixture.

Root Ruff reports pre-existing violations in the unmodified, independently authored cold acceptance file (`qa/acceptance/CREDENTIAL-AND-DEVICE-001/test_credential_device_cold_acceptance.py`, 18 findings). It was not edited. Ruff check and format pass for every cycle-2 changed file.

## Integration notes

- The device identity must be populated only by the verified session/licence adapter from its verified `device_id` claim, sourced from the licensing Worker's active server-side device record. Request evidence, headers, and body are not trusted sources.
- Missing `device_id` remains allowed for general non-LIVE principals; LIVE account access fails closed until a verified device identity is present and equal to the account's server-side evidence.
- AUTH-GOOGLE-001 is editing `live_activation.py` concurrently. Merge this localized check with its owner-role change while preserving exact owner-principal binding and without restoring a role gate.
- No venue transports, release files, external services, or provider calls were changed or used.
