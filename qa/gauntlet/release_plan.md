# GAUNTLET-001 release plan

## Decision and scope

**Candidate execution: NOT_TESTED. Release state: BLOCKED. Certification: NOT_CERTIFIED.** This plan and `verify_matrix.py` validate matrix completeness and qualifying evidence. They cannot certify the product or issue a release PASS.

The canonical Requirements Map v12 contains 72 requirement IDs. The validator resolves each map `source` reference relative to the map file's parent and discovers the canonical `.codespring/PRDs` tree from those references. The full PRD tree is inventoried, including files that the map does not cite; referenced Markdown outside the PRD tree is also included. Duplicate files are deduplicated by resolved path. At this snapshot the canonical tree has 123 Markdown files and 965 acceptance items; the full source inventory also includes the referenced `.codespring/project-overview.md`. There are no unavailable-source gates.

## Matrix and evidence contract

`plan.schema.json` defines `GauntletCandidateManifestV1`. The root contains `schema_version`, candidate metadata, one row per Requirements Map ID, `source_criteria`, and all required release gates. Map criteria use stable IDs `<requirement-id>.AC.<three-digit-index>` and exact canonical text. Each source criterion has a deterministic `SRC-<20-hex>` ID derived from the map-relative file path, source line, and exact item text; it records the exact behavior and mapped requirement IDs.

The validator requires the candidate's Requirements Map SHA-256 and a source inventory SHA-256 over every Markdown file in the full canonical `.codespring/PRDs` tree plus referenced Markdown outside that tree. Source files are read-only. Each parsed source acceptance item must be represented by a source-addressed matrix row or covered by an explicit candidate `source_exclusions` record with exact path, current SHA-256, and a nonempty reason. Excluded files remain in the inventory hash; unknown paths, duplicate exclusions, and stale hashes fail closed. An item with no source-addressed map row is retained as a blocked criterion with `{kind: PRD_UNMAPPED, gate_id: FULL_PRD_CRITERION_AUDIT}`.

Evidence counts only when it references `qa/handoffs/<ID>/evidence.json` under the canonical project root, with the handoff file's raw-byte SHA-256. The handoff binds the candidate commit, distinct worker and reviewer IDs, reviewer disposition `PASS`, current canonical repo file hashes under `repo/`, and an exactly matching subject/status/result. Stale bytes, arbitrary hash-valid files, missing independent review, or a mismatched result do not count as evidence.

Every non-PASS criterion or gate carries `{kind, gate_id}` using a closed `BlockerKindV1` value: `USER_INPUT_REQUIRED`, `CREDENTIAL_REQUIRED`, `LICENSE_REQUIRED`, `CERTIFICATE_REQUIRED`, `CLOUD_APPLY_REQUIRED`, `EXTERNAL_TERMINAL_REQUIRED`, `SOURCE_UNAVAILABLE`, `INTEGRATION_PENDING`, or `PRD_UNMAPPED`. `PRD_UNMAPPED` is limited to source criteria without a mapped requirement and must reference `FULL_PRD_CRITERION_AUDIT`. Other blocker kinds must match their exact required gate. Free text is rejected.

Successful validation always reports `certification_status: NOT_CERTIFIED`. `USER_RELEASE_APPROVAL` cannot PASS, and all-gate PASS is forbidden by construction.

## Validator use

API: `validate_matrix(requirements_path, source_root, candidate_path, evidence_root=None) -> dict[str, Any]`. `source_root` is the canonical project root containing `repo/` and `qa/handoffs/`; the Requirements Map must be directly under that root. If supplied, `evidence_root` must resolve to the same root.

```powershell
uv run python qa/gauntlet/verify_matrix.py `
  --requirements "<canonical REQUIREMENTS_MAP.yaml>" `
  --source-root "<canonical LEVIATHAN AI project root>" `
  --candidate "<candidate manifest.json>"
```

Exit 0 means matrix validation completed, not that the release passed. Output includes `validation_status: VALID` and `certification_status: NOT_CERTIFIED`. Invalid manifests return exit 2 with a content-free `error_code` and the same non-certification status. Unmapped requirements, omitted source items, missing source gates, arbitrary evidence, unsupported source formats, and incomplete release-gate coverage fail closed.

## Current requirement and source status

Every candidate-level map criterion and all 965 enumerated PRD source criteria remain blocked or `NOT_TESTED` until qualifying project handoffs bind them to a frozen candidate. The uncategorized PRD files contribute 41 `PRD_UNMAPPED` items; mapping the MT4/MT5 export-bridge, deployment-devops, and flash-loan-arbitrage PRDs is deferred to later contracts. The map and PRD sources are available; no source-unavailability claim is made.

| Area | Current evidence state | Gate |
|---|---|---|
| Frozen candidate and baseline evidence | No frozen candidate or qualifying handoff | `FROZEN_CANDIDATE_EVIDENCE` |
| Full PRD criterion audit | 123 PRD Markdown files and 965 acceptance items inventoried; 41 are `PRD_UNMAPPED`; no candidate-bound verification | `FULL_PRD_CRITERION_AUDIT` |
| Independent review | No reviewer PASS for a frozen candidate | `INDEPENDENT_REVIEW` |
| Performance and market-data reliability | No candidate-bound external execution evidence | `PERF-001`, `MD-008` |
| Risk limits | User numeric limits and approval are absent | `RISK-003_USER_LIMITS` |
| Broker credentials | No real broker credentials or authorized test | `LIVE_BROKER_CREDENTIALS` |
| Provider licensing | No candidate-bound license evidence | `PROVIDER_LICENSES` |
| Signing certificate | No signing certificate or signed package evidence | `SIGNING_CERTIFICATE` |
| Cloud apply | No approved apply/rollback evidence | `CLOUD_APPLY` |
| Installed Windows binary | No clean install/upgrade/uninstall run | `INSTALLED_WINDOWS_BINARY` |
| User release approval | No approval for a frozen candidate and evidence bundle | `USER_RELEASE_APPROVAL` |

## Release sequence

1. Freeze the candidate commit, exact Requirements Map bytes, and full canonical `.codespring/PRDs` inventory. The validator discovers the PRD tree from the map's references, hashes every Markdown file, and rejects unresolved references unless an exact `SOURCE_UNAVAILABLE` gate is present.
2. Generate every canonical map criterion and all 965 current PRD acceptance items, preserving stable IDs and exact text. Leave unmapped items blocked as `PRD_UNMAPPED`; use an explicit path/hash/reason exclusion only for a documented excluded file.
3. Run candidate-bound verification. Record `PASS`, `FAIL`, or `PARTIAL` only with qualifying project QA handoff evidence and independent review; use a closed blocker and exact gate ID for unrun work.
4. Complete the external gates for user risk limits, performance, market-data reliability, licenses, signing, installed Windows package, cloud apply/rollback, and independent review. Plans, mocks, and baseline tests do not clear these gates.
5. Run the validator and resolve schema, source-coverage, hash, and gate errors. Validation itself is not certification or deployment approval.
6. Present the evidence and unresolved gates for explicit user release approval. Keep live trading disabled until its separate authorization requirements are met.

## Snapshot fingerprints

- Requirements Map v12 SHA-256: `cdd971cb1e5e1f85a810e1c3627e40a14e27da3058f71433e64c69b4e0005f69`
- Full source inventory: 124 deduplicated Markdown files (123 PRD files plus the referenced overview); 965 acceptance items; SHA-256 `c6c08e110de1dbe405a1f94f9fa0589c1be9f40dcca8aa1d3d28e830a762a408`.
- CodeSpring source root: `C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\CODESPRING FILES\blackwealthcapital---leviathan-ai-codespring\.codespring`
- Candidate commit: not frozen; no candidate evidence bundle exists.
