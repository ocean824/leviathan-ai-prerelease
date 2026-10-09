# CHAT-CAPABILITY-001 cycle 1 freeze

**Status:** cycle-1 implementation delta frozen for independent acceptance rerun and review recheck. No changes to `chat/tool_bridge.py`, `chat_tools_runtime.py`, the acceptance tests, provider integrations, canonical `repo\`, or external systems. No commits.

## Binding findings and resolutions

Cycle-0 review `chat-capability-001/review/index.md` (SHA `c7063467…`) requested changes; acceptance `chat-capability-001/acceptance/index.md` (SHA `972f954f…`) reported 8/9 acceptance cases and 25/26 combined, with HALT engagement as the only failure. The owner decision in `inputs/USER_DECISIONS_2026-10-09.md` additionally requires account-holder O2 delegation semantics.

| Finding / direction | Cycle-1 resolution |
| --- | --- |
| HALT engage unavailable in every mode | `halt.engage` is a current, chat-available E1 protective action permitted in Analysis, Semi-auto, and Full-auto without an O2 prompt or delegation. HALT lift remains O2. |
| Policy schemas bypassable via direct construction / `model_copy` | Strict frozen policy models validate assignment; `model_copy` revalidates; table loading revalidates policy entries and cross-table invariants. Protected O2 action classifications and secret-input prohibition are enforced in models and table validation. |
| Inventory lacked exact-set coverage / `paper.account.read` | The contract inventory test now asserts exact action-ID set equality with the discovery inventory, including `paper.account.read` and the omitted listed actions. |
| O2 role and delegation policy | O2 is per-user/per-account: in-app confirmation or an unexpired, non-revoked typed grant for LIVE toggle, HALT lift, or risk-limit change. Credential changes are never delegable or chat-accessible. No admin/owner role gate. Grant/revocation actions have typed audit events. |

The table has 75 rows: 18 current and 57 planned. This remains a contract-only lane; later registry/runtime wiring is required. No chat tool runtime or registry files changed.

## Frozen files

| Owned path | Cycle-0 SHA-256 | Cycle-1 SHA-256 |
| --- | --- | --- |
| `apps/api/src/leviathan_api/chat/capabilities_v1.py` | `b34fc1f334e01cac0c297bd2f488c07187a8727c8f5e63c40c266b55635bc76b` | `ed787bb79e56fdde8a716bc414f2e64e8f14c70ef3173decc5b55a37b6664769` |
| `apps/api/tests/test_chat_capabilities.py` | `cf81d1bd9625d667cbe7083299c4e257f16dbd6c4fdf18e07e6eade14ca9caee` | `a1eccdff5b4dd4e8e514763b0525bfbfe7df346d2c972f0ded6f8627ea3b09f4` |

## Gates

| Gate | Result |
| --- | --- |
| `uv run --locked python -m pytest apps/api/tests/test_chat_capabilities.py -q` | 27 passed (one upstream Starlette/httpx deprecation warning). |
| `uv run --locked python -m pytest apps/api/tests -q` | 1,473 passed, 1 skipped, 15 warnings in 314.23 seconds. |
| `uv run --locked mypy` | Success: no issues found in 430 source files. |
| `uv run --locked ruff check apps packages tests` | Passed. |
| `uv run --locked ruff format --check apps/api/src/leviathan_api/chat/capabilities_v1.py apps/api/tests/test_chat_capabilities.py` | Passed; both files already formatted. |

The one-shot root test collection still has the duplicate-basename limitation recorded in cycle 0. Cycle-0 package-level core/store/vault/market-data runs and known benchmark outcome remain in `cycle-0.md`; cycle 1 changed only the two API-owned files above. Independent acceptance rerun and review recheck are pending against these hashes.

## Independent acceptance rerun

Acceptance was rerun by e51a5665 against the frozen module, worker-test and ledger hashes above. Acceptance file SHA-256: `e9c63c192247d6be23bf511d20943e8facb5bf1d74681d325f4131084ee152a8`; acceptance-only: **15 passed**; combined with the worker test: **42 passed**. Ruff and format checks passed. Acceptance handoff `qa/handoffs/CHAT-CAPABILITY-001/acceptance-cycle-1.md` SHA-256: `a35239c6b4bf3e51e7233da4e7f177ccf82be4f2725e1970064fd84abda23c83`.

The independent review recheck remains pending.

# Cycle 2 delta — confirmation-class mode eligibility

Cycle-1 review identified that the exported policy models accepted `allowed_modes` outside the confirmation class's eligible modes, including an A3 row copied or directly constructed with every mode. The model could therefore represent an invalid policy even though `mode_allows_effect` later denied it.

A single immutable class-to-mode eligibility table now defines the class boundary and is used by `CapabilityPolicyV1`, `ActionPolicyV1`, and `mode_allows_effect`. R0 has no effect modes; E1 and O2 are eligible in all modes; A3 is eligible in Semi-auto and Full-auto (never Analysis); F4 is eligible only in Full-auto. `halt.engage` remains an explicit all-mode protective effect. Both policy models reject out-of-class modes on direct construction and on `model_copy(update=...)`, which revalidates. Tests cover A3 all-mode bypasses for both models, F4 mode bypass, and the HALT exception.

| Owned path | Cycle-1 SHA-256 | Cycle-2 SHA-256 |
| --- | --- | --- |
| `apps/api/src/leviathan_api/chat/capabilities_v1.py` | `ed787bb79e56fdde8a716bc414f2e64e8f14c70ef3173decc5b55a37b6664769` | `e7c2e69bc662df6a375ac8ce03758c800920b38e9407fbb3614fceba7a498192` |
| `apps/api/tests/test_chat_capabilities.py` | `a1eccdff5b4dd4e8e514763b0525bfbfe7df346d2c972f0ded6f8627ea3b09f4` | `90571f4fb10100776556985f7c05fa519ad3a728abb7851d0cfe645ed5ea0b04` |

| Gate | Result |
| --- | --- |
| `uv run --locked python -m pytest apps/api/tests/test_chat_capabilities.py -q` | **28 passed**, 1 upstream Starlette/httpx deprecation warning. |
| `uv run --locked python -m pytest apps/api/tests -q` | **1,474 passed, 1 skipped, 15 warnings** in 319.12 seconds. |
| `uv run --locked mypy` | Success: no issues found in 430 source files. |
| `uv run --locked ruff check apps packages tests` | Passed. |
| `uv run --locked ruff format --check apps/api/src/leviathan_api/chat/capabilities_v1.py apps/api/tests/test_chat_capabilities.py` | Passed; both files formatted. |

Cycle-2 independent acceptance mutation and review recheck are pending against these frozen hashes.

## Cycle-2 independent acceptance

Acceptance was rerun by e51a5665 against the cycle-2 source, worker-test and ledger hashes. Acceptance file SHA-256: `127677451369281c463985400d9fa2f676d8e89a4149ff8f87ae29d6dc94b54a`; acceptance-only: **17 passed**; combined with the author test: **45 passed**. Ruff and format passed. A scratch mutant that widened A3 modes to include Analysis was killed by the direct-construction and `model_copy` probes; acceptance also checks F4 excludes Semi-auto for both model types. Handoff `qa/handoffs/CHAT-CAPABILITY-001/acceptance-cycle-2.md` SHA-256: `d72ff818861c1f13b54a40cb28ced0cc2e75d09f9e21a73e4961439391aa28b`. Epic artifact SHA-256: `cce96d8c2254ed7dee8d5c07128b4b2a773f67eed1547d083b93d7e09d86c51e`.

Cycle-2 independent review recheck remains pending.
