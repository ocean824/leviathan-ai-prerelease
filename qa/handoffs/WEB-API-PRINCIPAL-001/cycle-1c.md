# WEB-API-PRINCIPAL-001 — cycle 1c freeze ledger

Status: frozen for coordinator delta review.

## Review finding and change

Cycle 1b review finding P3 (review SHA reported as `aa04979c…f694`, reviewer `dde9d7f4`): the Worker assertion contract requires JOSE `typ=JWT`, but the path accepted a missing `typ` through the shared verifier. Cycle 1c enforces exact `typ == "JWT"` in `WorkerAssertionVerifier.verify()` before principal verification. It does not change `principal_verifier.py` or desktop verification semantics.

The signed-token test helper now accepts a test JOSE header. Two regression tests create correctly signed synthetic-RSA assertions with (1) missing `typ` and (2) `typ="JOSE"`; both are rejected with the existing typed content-free `INVALID_ASSERTION` code.

## Baseline and diff-generated ledger

Cycle 1c is a separate copy of the frozen cycle-1b tree. The cycle-1b tree was left unchanged. The pre-edit manifest is `qa/handoffs/WEB-API-PRINCIPAL-001/cycle-1c-start-manifest.sha256`, SHA-256 `C30E797B794640EDEE904918F67FC53ACD33F70D46B720D0FF7B7788E800DE42` (1,665 entries). Manifest comparison excludes generated caches, virtual environments, integration backups, and the handoff directory.

Result: 2 modified, 0 added, 0 removed.

Modified:

- `apps/api/src/leviathan_api/auth/worker_assertion.py` — `D35F4A3B5041CAE543810873B2CA316D4E567EB85B710DB2E8A52EF98719592E`
- `apps/api/tests/test_worker_assertion.py` — `74A7485941F071DE87E26C2CA643201B84D57109A00F8155A49D66EC770DFEAE`

No other code file changed.

## Verification

- Focused signed `typ` cases: `uv run --locked python -m pytest apps/api/tests/test_worker_assertion.py -q --tb=short -k 'signed_assertion_missing_typ or signed_assertion_wrong_typ'` — **2 passed, 13 deselected**.
- API root: `uv run --locked python -m pytest apps/api/tests -q --tb=short` — **1,554 passed, 1 skipped**, exit 0 (313.54s; 49 warnings).
- Default mypy: `uv run --locked mypy` — success, no issues in 451 source files.
- Linux mypy: `uv run --locked mypy --platform linux` — success, no issues in 451 source files.
- Darwin mypy: `uv run --locked mypy --platform darwin` — success, no issues in 451 source files.
- Ruff lint for both changed files with `--extend-exclude qa/integration-backups` — all checks passed.
- Ruff format check passes for the changed test file. The verifier source also reports “would reformat” on the frozen cycle-1b baseline; no broad formatting change was made as part of this narrow review fix.

## Scope and production prerequisite

No route exposure, Worker implementation, desktop auth path, shared core principal verifier, or OMS → risk → LIVE gate → HALT path changed.

`InMemoryAssertionReplayStore` remains limited to development, test, paper, and demo. Staging/production require a persistent, atomic, fleet-wide replay store shared by API replicas and durable across restarts. The adapter belongs to WEB-TENANT-CONTEXT-001 or WEB-CONTAINER-DEPLOY-001 and must be integrated and verified before production use. The ticket artifact now records this prerequisite. No production readiness claim is made.
