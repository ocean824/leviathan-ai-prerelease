# CHAT-CAPABILITY-001 cycle 0 freeze

**State:** Implementation contract frozen for registry/runtime adoption in a later lane. No tool bridge or runtime wiring, provider calls, secret access, external network, order dispatch, canonical `repo` writes, or commits were made.

## Contract delivered

Added `apps/api/src/leviathan_api/chat/capabilities_v1.py` and its contract test. The module defines strict/frozen Pydantic schemas for capability input fields, capability policy, action policy, scope, freshness requirement, audit-event shape, account/venue mode assignment and mode admission. Schema references are stable IDs so future/planned rows can be represented before their executable schemas exist. Secret-kind inputs are rejected.

The immutable tables contain **75** action/capability rows: **17 current** rows exactly mirror the closed `tool_bridge.py` registry; **58 planned** rows map the terminal/API action inventory from chat-modes-discovery §2. Each row records confirmation class, lifecycle, current chat surface, allowed modes, request/response model IDs, scope, freshness metadata, and audit fields. The four protected action families are O2-or-higher; the table includes `live.enable`, `halt.lift`, `risk.limits.relax`, and credential change/put/delete as O2.

Freshness supports either an explicit bounded nanosecond age or a named policy reference. This contract does not invent production SLAs where the discovery did not establish a numeric value. Mode assignments are account-and-venue scoped and default to Analysis. Full-auto first enrollment is PAPER-only; a LIVE Full-auto admission requires `LiveActivationGatePortV1.live_account_enabled(account_id)` and fails closed on missing, false, or raising gates. Per-mode effect allowlists are stricter subsets of their confirmation classes.

The registry remains the current authority. A later wiring lane should import this module from the registry/runtime, compare the closed tool schema/confirmation metadata against these typed policies, then replace duplicated mappings only after CREDENTIAL-AND-DEVICE-001 integrates. This lane intentionally leaves `chat/tool_bridge.py` and `chat_tools_runtime.py` untouched.

## Fresh copy and full-tree comparison

Canonical root: `C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\LEVIATHAN AI\repo`.
Fresh worktree: `C:\Users\XYRASYSTEMS\.traycer\worktrees\local__repo__72e9e418f8\feature-chat-capability-001-3c86b0c`.

The tree was copied from canonical with `robocopy /E /COPY:DAT /DCOPY:DAT /R:0 /W:0`; `.venv` was excluded and then created locally by `uv sync`. A later full SHA-256 walk caught 11 newer canonical macOS-packaging paths and 4 changed packaging files outside this contract. Those canonical files were synced into the fresh tree, without replacing `.venv` or the owned files. Final sorted path/SHA comparison excluded `.git`, `.venv`, `node_modules`, Python/tool caches, build, coverage, dist and target directories: canonical **1,684 files**, worktree **1,686 files**, **0 canonical-only**, **0 changed**, and exactly **2 worktree-only** files (the owned module and test below). Both worktree and canonical Git HEAD were `d3208136d1872cf6e0bb33ec79aa06f01de98562`.

| Owned path | Canonical-start SHA-256 | Frozen SHA-256 | `git diff --no-index --stat /dev/null <path>` |
| --- | --- | --- | --- |
| `apps/api/src/leviathan_api/chat/capabilities_v1.py` | MISSING | `b34fc1f334e01cac0c297bd2f488c07187a8727c8f5e63c40c266b55635bc76b` | 879 insertions |
| `apps/api/tests/test_chat_capabilities.py` | MISSING | `cf81d1bd9625d667cbe7083299c4e257f16dbd6c4fdf18e07e6eade14ca9caee` | 270 insertions |

## Gates

| Gate | Result |
| --- | --- |
| `uv sync` | Passed in the fresh tree; `.venv` was created locally, not copied. |
| `uv run --locked python -c "import leviathan_api.chat.capabilities_v1 as m; print(m.__file__)"` | Imported from this worktree's `apps/api/src/leviathan_api/chat/capabilities_v1.py`. |
| `uv run --locked python -m pytest apps/api/tests/test_chat_capabilities.py -q` | **17 passed**, 1 upstream Starlette/httpx deprecation warning. |
| `uv run --locked python -m pytest apps/api/tests -q` | **1,463 passed, 1 skipped, 15 warnings**. |
| `uv run --locked mypy` | **Success: no issues found in 430 source files.** |
| `uv run --locked ruff check apps packages tests` | Passed. `ruff format --check` on both owned files: passed. |
| `uv run --locked ruff check .` | **10 findings**, all under copied historical `qa/integration-backups/...` files; no finding in an owned file. |

The one-shot root `uv run --locked python -m pytest -q` cannot collect this repository because `apps/api/tests/test_live_activation.py` and `packages/leviathan-store/tests/test_live_activation.py` (and the corresponding `*_acceptance.py` pair) collide by basename. The per-package suites were therefore run separately. Recorded results: core **6,541 passed, 10 skipped, 1 failure** in `test_oms_activity_reads.py::test_ten_thousand_row_read_adds_at_most_250ms_to_submit_median`; rerunning that benchmark alone produced its expected **1 xfailed** result because the measured latency gate remains open. Store **548 passed, 2 skipped**; vault **163 passed, 36 skipped**; market-data **1,128 passed**; API **1,463 passed, 1 skipped**. The benchmark and collection issues are outside the two owned paths; no unrelated test or backup was modified.

## Not in this lane

No registry/runtime adoption, persistence of mode assignments, mode-switch UI, owner-seed import, new tool dispatch, semi-auto trade cards, full-auto worker, or approvals were added. The discovery artifact's owner EA seed-folder location remains unresolved. The follow-up wiring lane must resolve that owner input separately and integrate the typed contract after CREDENTIAL-AND-DEVICE-001.