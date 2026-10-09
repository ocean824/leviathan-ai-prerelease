# CF-DEPLOY-001 cycle 2 delta ledger

Cycle 2 addresses the remaining P2 from the cycle-1 review. Cycle-1 baseline ledger SHA-256: `55f4a9fcfafedacae59a639419f2dd9591a0808643578c48a5416be0740e34d6`. Review source: `artifacts/leviathan-build/cf-deploy-001-review/index.md` (reported SHA prefix `c69d29d0`).

## Live runtime keyset transaction

`-InitializeLiveKeys` now generates four values entirely in process: signing private key PKCS#8, matching public JWK, TOTP encryption key and internal service token. It writes each through `Set-XyraSecret -Replace`, in that order, then writes `LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT` last. The marker is a full-schema secret-registry entry containing a random keyset ID and SHA-256 digest over a canonical length-prefixed encoding of the ID and four values. It contains no key value.

A keyset is valid only when all four values pass validation and the marker digest matches. The deploy path checks this before Wrangler or Cloudflare operations and uses only the validated values. No marker or a mismatched marker causes regeneration and replacement of all four staged values before rewriting the marker. A valid committed set is idempotent; replacing one requires both `-RotateLiveKeys -InitializeLiveKeys`. `-RotateLiveKeys` without initialization is rejected. Marker-write acknowledgement loss is safe: a valid persisted marker is recognized as idempotent on retry.

The public and private signing values are checked as a matching P-256 pair. Generation/import uses `ECDsaCng`/`CngKeyBlobFormat.Pkcs8PrivateBlob`, compatible with Windows PowerShell 5.1.

## Cycle-2 file hashes

| Path | Cycle-1 SHA-256 | Cycle-2 SHA-256 |
| --- | --- | --- |
| `infra/release/cloudflare/Deploy-LeviathanWorkers.ps1` | `398e538fc04786176e59964c63b1b9a33675f2a1fb1aa356b86b8a7e15de186b` | `7e18f4e2511a661f58322980a13d25cc6fd61738b87f38a3370e1f6d8aa91e4d` |
| `infra/release/cloudflare/SigningKeyPair.psm1` | `643281d71cc799a131cf6916138e0ef7c203489b1d0f86f7c84bf55acf7504f6` | `473fc9215703c3a78573c5c77ec0eca92f5a409cb1ec9f508684ee08036a2ef9` |
| `infra/release/cloudflare/SECRET_REGISTRY.entries.json` | `7b71a846a03eafec358c9681c025743ddf5d7a59e37d85afb67a14db1989ce6a` | `528f944c8b87d4eff81778c90de1db871581ec45460c331d8f82e31982d12088` |
| `infra/release/cloudflare/README.md` | `f90f13e6cadf664c8ac67b8277970df7d1dd02fa732a772c802201a879668953` | `28b2ca48f0c09989ba44932ddba80d6af3965eef7e1f3fc5a8215fda6d991d0a` |
| `infra/release/tests/SigningKeyPair.Tests.ps1` | `d026528a558d051ef889ff68614ea571a54f289755e0ef4c4cf9ac5f78b4e542` | `c6d1507154e943071fd8b6885672f3ca291ccbd05aa21353fd370fce330430a9` |
| `infra/release/tests/test_cf_deploy001_acceptance.py` | `a51d3354d5f1bd08c99421c0268c0c5d9145254309aa1739f4ce63c15ec60b1d` | `3543e8681de4b53cda4d551ca78c49980356f15bd249fc3ebc7d005dd68585dc` |

## Verification

- `Invoke-Pester -Script infra/release/tests/SigningKeyPair.Tests.ps1`: 6 passed. Cases include each of the four value-write failures and marker-write failure followed by successful retry, mismatched/partial marker repair, no overwrite without explicit rotation, marker acknowledgement loss and idempotent retry, and matching/mismatching signing key/JWK.
- `uv run --locked python -m pytest infra/release/tests/test_cf_deploy001_acceptance.py -q`: 7 passed.
- `uv run --locked ruff check infra/release/tests/test_cf_deploy001_acceptance.py`: passed.
- `uv run --locked ruff format --check infra/release/tests/test_cf_deploy001_acceptance.py`: passed.
- PowerShell parser validation of `Deploy-LeviathanWorkers.ps1`: passed.
- Coordinator runbook `-WhatIf`: passed; displayed names only and did not import/read secrets.
- Scoped `git diff --check`: passed.

No real secret reads, Wrangler operations, deploys, or external provider/API calls were made.
