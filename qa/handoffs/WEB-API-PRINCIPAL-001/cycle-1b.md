# WEB-API-PRINCIPAL-001 — cycle 1b freeze ledger

Status: frozen for coordinator review.

## Baseline and rebase

Cycle 1b starts from a clean copy of the reconciled canonical repository at `C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\LEVIATHAN AI\repo`. This rebase incorporates the CREDENTIAL-AND-DEVICE reconciliation, including the canonical `credential_connections_runtime` wiring in `main.py`.

Canonical pre-reapply hashes:

- `apps/api/src/leviathan_api/main.py`: `94CF3AA6FB54803ED5741B58954519AA01A9B733DDA0AB06F90AF7BE239232CD`
- `apps/api/src/leviathan_api/settings.py`: `1D165594F058926E7B60A6E71443740F9A856B6E39E3C449067A05E775025525`
- Clean-copy start manifest: `qa/handoffs/WEB-API-PRINCIPAL-001/start-manifest.sha256`, SHA-256 `F21D451B470E6F7D460BD3F5BB3A7E3215C850A6B53EB3197AFC67E6DC874D3B` (1,662 entries).

Only the assertion verifier wiring was reapplied to the reconciled `main.py` and `settings.py`. The existing credential runtime wiring remains intact. The verifier and its focused tests were carried over unchanged from cycle 1 and hash-match the prior freeze.

## Diff-generated ledger

The start-manifest comparison normalized its UTF-8 BOM and excluded generated caches, virtual environments, integration backups, and the handoff directory. Result: 2 modified, 2 added, 0 removed.

Modified:

- `apps/api/src/leviathan_api/main.py` — `37C4A2920E098CB2C5A78E44EC27C2D18CBF2162CF5E43A54894F2BB97FEA61D`
- `apps/api/src/leviathan_api/settings.py` — `492EE4FA3CFDDBC7B6EDE0BF10496B0888BC6D5F51B6A872572ABFA855C93D1B`

Added:

- `apps/api/src/leviathan_api/auth/worker_assertion.py` — `FA440954D8EEF66C91B07823AB89EC256D4219E025BCE750C53F8CBD3857AFBF` (unchanged from cycle 1)
- `apps/api/tests/test_worker_assertion.py` — `0F71C64CE8DDD68CC47E6DA873226187562EEC61DCA4DEA0A379F9896C1CA5B0` (unchanged from cycle 1)

Removed: none.

## Verification

- API root: `uv run --locked python -m pytest apps/api/tests -q --tb=short` — **1,552 passed, 1 skipped**, exit 0 (264.63s; 49 warnings).
- Default mypy: `uv run --locked mypy` — **success**, no issues in 451 source files.
- Linux mypy: `uv run --locked mypy --platform linux` — **success**, no issues in 451 source files.
- Darwin mypy: `uv run --locked mypy --platform darwin` — **success**, no issues in 451 source files.

The mypy gates ran in separate processes after the API test root. Cycle 1b requested these gates; the other pytest roots and full-tree Ruff gate were not rerun. Cycle 1's changed-file Ruff result and broader gate evidence remain in `cycle-1.md`.

## Scope and boundaries

No route exposure or Worker implementation changed. The desktop auth path, current route inventory, and OMS → risk → LIVE gate → HALT safety path remain untouched. The cycle-1b delta restores the assertion verifier settings/app wiring on top of the reconciled canonical API while retaining `credential_connections_runtime`.

The verifier and request-scoped principal contract remain opt-in pending the upstream Worker assertion signer and shared production replay-store integration. Missing verifier configuration continues to fail closed on any future protected route integration.
