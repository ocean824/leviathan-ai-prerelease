# MD-RUNTIME-001b cycle 0 ? licensing route catalog delta

## Scope and result

Added the mounted chart-ticket endpoint to the closed entitlement catalog as a `charts` `READ` action. The HTTP license gate now binds the same route to `charts`; `POST /md/chart/ticket` is allowed through `GRACE_READ_ONLY` as a view-opening read, while entitlement enforcement remains active. No catalog action was replaced. The chart-stream WebSocket route is not discovered by the catalog's HTTP route scanner and is not an API route handled by the Python HTTP middleware, so no WebSocket catalog action was added.

The invariant is exact route coverage, not a permanent numeric count: the Python test compares catalog `(path, feature)` pairs to the route table and family expansion; the licensing Vitest verifies action IDs are unique and every discovered or pre-registered route has an exact binding. Current catalog contains **61 actions**.

## Canonical sync and changed-file ledger

Worktree: `C:/Users/XYRASYSTEMS/.traycer/worktrees/local__repo__72e9e418f8/feature-md-runtime-001b-license-catalog-20261009`
Canonical repo: `C:/Users/XYRASYSTEMS/TRAYCER MASTER TEMPLATE/XYRA-MASTER/projects/XYRASYSTEMS/LEVIATHAN AI/repo`
A full file comparison excluding `.git` and generated/cache directories found 1,692 files in each tree and exactly these five changed files; no other additions, removals or byte differences were found.

| Repo-relative path | Canonical SHA-256 | Frozen SHA-256 |
|---|---|---|
| `workers/licensing/src/entitlement/feature_catalog.ts` | `d4102a8368179edb7d7f01169d0c460e67c2526909bde17854231d0e91e78159` | `6001a6837f885c30c4e6443aa95c796758c765f0f785df430fa3291f9a4a1c60` |
| `apps/api/src/leviathan_api/middleware/license_gate.py` | `a4278ba9384e441ad0fefa9162cbc4469db12ca7a0b0dea9da60c5dba06ebb9a` | `2d479c111df521e818259763b19548c27033c70b27db364d30cb9e4c910e1a8b` |
| `apps/api/tests/test_license_gate.py` | `8744fdb89c40a0eccc7a2db3daf02e5f7d1b4057abd19532a5ecbd5ed45d1f1c` | `f39e1826b6f04112823d47a224308a8d94d62667ef7f48ed6337b8e2b5017b68` |
| `apps/api/tests/test_license_gate_acceptance.py` | `12b709fb48a41d97dc95b0cc63db6022e2b5269099df0fdf8559ab0e478b2ad5` | `f891120528e00d262293d0133fdccaf7a279e1814e260db95fca79e6b07acdd4` |
| `workers/licensing/tests/entitlement_features.test.ts` | `d5091abdbeebff749a9a6222a484398bbdd167277f1d87acd21ed1c170cd1bba` | `d280a96fafbf77c560f72b207e5e28f520643b365b584d34a5a76c89bc884ce3` |

## Verification

- `uv sync --locked --all-packages` ? passed; installed editable packages point into this worktree.
- `npm.cmd ci` in `workers/licensing` ? passed; lockfile unchanged.
- `npm.cmd test --prefix workers/licensing` ? **15 files, 191 tests passed**.
- `uv run --locked pytest apps/api/tests -q` ? **1,447 passed, 1 skipped**, 15 existing framework/OpenAPI warnings.
- `uv run --locked mypy` ? **429 source files, no issues**.
- `uv run --locked ruff check . --extend-exclude qa/integration-backups` ? passed.

The chart-ticket grace test confirms that an entitled `charts` principal passes the POST through in grace mode and a principal without the feature receives the fixed `FEATURE_NOT_ENTITLED` denial. Catalog and route-family tests enforce exact set equality and `charts == ("/md/chart/ticket",)`.
