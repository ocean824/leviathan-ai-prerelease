from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from uncategorized_inventory import InventoryError, build_inventory


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    source_root = tmp_path / "codespring"
    prd_dir = source_root / ".codespring" / "PRDs" / "uncategorized"
    prd_dir.mkdir(parents=True)
    map_path = tmp_path / "REQUIREMENTS_MAP.yaml"
    map_path.write_text(
        "schema_version: 1.0.0\nversion: 1\nrequirements: []\n",
        encoding="utf-8",
    )
    integration_log = tmp_path / "integrations.md"
    integration_log.write_text("# Integrations\n", encoding="utf-8")
    return source_root, map_path, integration_log, prd_dir


def _build(
    source_root: Path,
    map_path: Path,
    integration_log: Path,
    handoffs: tuple[Path, ...] = (),
) -> dict[str, object]:
    return build_inventory(
        source_root=source_root,
        map_path=map_path,
        integrations_log_path=integration_log,
        handoff_paths=handoffs,
    )


def test_discovers_all_files_and_acceptance_sections_deterministically(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    first = directory / "one.md"
    first.write_text(
        "# Product\n\n## Acceptance criteria\n"
        "- [ARCHIVED] AC-1 repeated wording\n"
        "- AC-1 repeated wording\n\n"
        "## Acceptance signals (Data-Level)\n"
        "1. A separate criterion.\n"
        "## Out of scope\n- not a criterion\n",
        encoding="utf-8",
    )
    second = directory / "two.md"
    second.write_text(
        "Acceptance criteria\n- [ARCHIVED] AC-1 repeated wording\n\n"
        "Acceptance criteria\n- A second section item\n",
        encoding="utf-8",
    )

    result = _build(source_root, map_path, integration_log)
    criteria = result["criteria"]
    assert isinstance(criteria, list)
    assert len(criteria) == 5
    summary = result["summary"]
    assert summary["source_criterion_count"] == 5
    assert summary["source_criterion_scope"] == "acceptance_sections_only"
    assert summary["no_contract_count"] == 5
    assert summary["coverage_class_counts"] == {
        "COVERED_CRITERION": 0,
        "CANDIDATE_UMBRELLA_ONLY": 0,
        "NO_CONTRACT": 5,
    }
    assert summary["per_file_criterion_counts"] == [
        {
            "path": ".codespring/PRDs/uncategorized/one.md",
            "count": 3,
            "coverage_class_counts": {
                "COVERED_CRITERION": 0,
                "CANDIDATE_UMBRELLA_ONLY": 0,
                "NO_CONTRACT": 3,
            },
        },
        {
            "path": ".codespring/PRDs/uncategorized/two.md",
            "count": 2,
            "coverage_class_counts": {
                "COVERED_CRITERION": 0,
                "CANDIDATE_UMBRELLA_ONLY": 0,
                "NO_CONTRACT": 2,
            },
        },
    ]
    assert len({item["criterion_id"] for item in criteria}) == 5
    archived_text = "[ARCHIVED] AC-1 repeated wording"
    assert (
        sum(
            item["source_text_sha256"] == hashlib.sha256(archived_text.encode()).hexdigest()
            for item in criteria
        )
        == 2
    )
    assert all(item["owners"] == [] for item in criteria)
    assert summary["unresolved_owners"] == []
    assert all(item["coverage_class"] == "NO_CONTRACT" for item in criteria)
    serialized = json.dumps(result, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert _build(source_root, map_path, integration_log) == result


def test_exact_map_link_preserves_owner_and_reports_unresolved_owner(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    (directory / "p.md").write_text(
        "# P\n## Acceptance criteria\n- A contract-backed behavior.\n",
        encoding="utf-8",
    )
    repo_root = map_path.parent / "repo"
    repo_root.mkdir()
    (repo_root / "target.py").write_text("target\n", encoding="utf-8")
    map_path.write_text(
        "schema_version: 1.0.0\nversion: 7\nrequirements:\n"
        "- id: REQ-X001\n"
        "  acceptance_criteria:\n"
        "  - A contract-backed behavior.\n"
        "  owner: TBD owner\n"
        "  implementation_target: target.py\n",
        encoding="utf-8",
    )
    result = _build(source_root, map_path, integration_log)
    item = result["criteria"][0]
    assert item["map_ids"] == ["REQ-X001"]
    assert item["owners"] == ["TBD owner"]
    assert item["contract_ids"] == ["NO_CONTRACT"]
    assert item["target_paths"] == ["target.py"]
    assert result["summary"]["map_version"] == "7"
    assert result["summary"]["unresolved_owners"] == [
        {"criterion_id": item["criterion_id"], "map_ids": ["REQ-X001"], "owners": ["TBD owner"]}
    ]


def test_malformed_unclosed_fence_fails_without_partial_snapshot(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    (directory / "broken.md").write_text(
        "# Broken\n## Acceptance criteria\n"
        "- visible criterion\n"
        "\x60\x60\x60text\n- hidden criterion\n",
        encoding="utf-8",
    )
    with pytest.raises(InventoryError) as error:
        _build(source_root, map_path, integration_log)
    assert error.value.code == "MALFORMED_MARKDOWN"
    assert "hidden criterion" not in str(error.value)


def test_input_hashes_cover_map_prds_log_and_handoffs(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    source_file = directory / "x.md"
    source_file.write_text("# X\n## Acceptance criteria\n- Behavior\n", encoding="utf-8")
    handoff = tmp_path / "handoff.md"
    handoff.write_text("# Handoff\n", encoding="utf-8")
    result = _build(source_root, map_path, integration_log, (handoff,))
    inputs = result["snapshot"]["inputs"]
    paths = [item["path"] for item in inputs]
    assert paths == sorted(paths)
    assert "REQUIREMENTS_MAP.yaml" in paths
    assert "integrations.md" in paths
    assert ".codespring/PRDs/uncategorized/x.md" in paths
    assert "handoff.md" in paths
    assert all(len(item["sha256"]) == 64 for item in inputs)


def test_per_file_counts_include_discovered_files_without_criteria(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    (directory / "with.md").write_text("# A\n## Acceptance criteria\n- one\n", encoding="utf-8")
    (directory / "without.md").write_text("# No acceptance section\n", encoding="utf-8")
    result = _build(source_root, map_path, integration_log)
    assert result["summary"]["per_file_criterion_counts"] == [
        {
            "path": ".codespring/PRDs/uncategorized/with.md",
            "count": 1,
            "coverage_class_counts": {
                "COVERED_CRITERION": 0,
                "CANDIDATE_UMBRELLA_ONLY": 0,
                "NO_CONTRACT": 1,
            },
        },
        {
            "path": ".codespring/PRDs/uncategorized/without.md",
            "count": 0,
            "coverage_class_counts": {
                "COVERED_CRITERION": 0,
                "CANDIDATE_UMBRELLA_ONLY": 0,
                "NO_CONTRACT": 0,
            },
        },
    ]


def test_area_umbrella_is_candidate_with_provenance_not_coverage(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    text = "Each PRD criterion remains individually unverified."
    (directory / "frontend-prd-crypto-flash-loan-arbitrage-engine.md").write_text(
        f"# Crypto PRD\n## Acceptance Criteria\n- {text}\n", encoding="utf-8"
    )
    map_path.write_text(
        "schema_version: 1.0.0\nversion: 12\nrequirements:\n"
        "- id: LEV-REQ-004\n"
        "  requirement: Crypto flash loan area umbrella\n"
        "  source: ../CODESPRING FILES/project/.codespring/PRDs/"
        "crypto-flash-loan-arbitrage-engine/\n"
        "  implementation_target: target.py\n"
        "  owner: ARB-001 staged first slice\n"
        "  acceptance_criteria:\n"
        "  - Every current PRD acceptance item remains separately linked.\n"
        "  disposition_reason: AREA UMBRELLA; remaining criteria are open.\n",
        encoding="utf-8",
    )
    proposal = map_path.parent / "architecture" / "proposals" / "ARB-001-slice.md"
    proposal.parent.mkdir(parents=True)
    proposal.write_text("# ARB-001 bounded slice\nFirst slice only.\n", encoding="utf-8")
    repo_target = map_path.parent / "repo" / "target.py"
    repo_target.parent.mkdir()
    repo_target.write_text("target\n", encoding="utf-8")
    integration_log.write_text("# Integrated\nARB-001 first slice status: PASS\n", encoding="utf-8")

    result = _build(source_root, map_path, integration_log)
    item = result["criteria"][0]
    assert item["coverage_class"] == "CANDIDATE_UMBRELLA_ONLY"
    assert item["map_ids"] == ["LEV-REQ-004"]
    assert item["contract_ids"] == ["ARB-001"]
    assert item["evidence_state"] == "INTEGRATION_RECORDED"
    assert any(ref["kind"] == "INTEGRATION_LOG" for ref in item["evidence_refs"])
    assert result["summary"]["coverage_class_counts"] == {
        "COVERED_CRITERION": 0,
        "CANDIDATE_UMBRELLA_ONLY": 1,
        "NO_CONTRACT": 0,
    }
    assert result["summary"]["no_contract_count"] == 0
    assert any(finding["code"] == "GENERIC_UMBRELLA_ONLY" for finding in result["findings"])


def test_exact_integration_mention_is_candidate_not_covered(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    exact = "The integrated health endpoint returns only the allowlisted fields."
    (directory / "prd.md").write_text(
        f"# API PRD\n## Acceptance Criteria\n- {exact}\n", encoding="utf-8"
    )
    integration_log.write_text(f"# Integration record\n- {exact}\n", encoding="utf-8")
    result = _build(source_root, map_path, integration_log)
    item = result["criteria"][0]
    assert item["coverage_class"] == "CANDIDATE_UMBRELLA_ONLY"
    assert item["evidence_refs"][0]["kind"] == "INTEGRATION_LOG"
    assert item["contract_ids"] == ["NO_CONTRACT"]
    assert result["summary"]["coverage_class_counts"]["COVERED_CRITERION"] == 0
    assert result["summary"]["coverage_class_counts"]["CANDIDATE_UMBRELLA_ONLY"] == 1


def test_exact_contract_clause_requires_related_evidence_ref(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    exact = "The status contract is evaluated with a trusted clock."
    (directory / "prd.md").write_text(
        f"# API PRD\n## Acceptance Criteria\n- {exact}\n", encoding="utf-8"
    )
    map_path.write_text(
        "schema_version: 1.0.0\nversion: 1\nrequirements:\n"
        "- id: REQ-X001\n"
        "  owner: C-001\n"
        "  acceptance_criteria:\n"
        f"  - {exact}\n",
        encoding="utf-8",
    )
    proposals = map_path.parent / "architecture" / "proposals"
    proposals.mkdir(parents=True)
    contract = proposals / "C-001-contract.md"
    contract.write_text(
        "# C-001\n-   THE  STATUS CONTRACT IS EVALUATED WITH A TRUSTED CLOCK!!!\n",
        encoding="utf-8",
    )
    integration_log.write_text("C-001 status: PASS\n", encoding="utf-8")

    result = _build(source_root, map_path, integration_log)
    item = result["criteria"][0]
    assert item["coverage_class"] == "COVERED_CRITERION"
    assert item["contract_ids"] == ["C-001"]
    contract_ref = next(ref for ref in item["evidence_refs"] if ref["kind"] == "CONTRACT_CLAUSE")
    assert contract_ref["line_start"] == contract_ref["line_end"] == 2
    assert contract_ref["sha256"] == hashlib.sha256(contract.read_bytes()).hexdigest()
    assert contract_ref["observed_status"] == "STATUS_NOT_STATED"
    integration_ref = next(ref for ref in item["evidence_refs"] if ref["kind"] == "INTEGRATION_LOG")
    assert integration_ref["observed_status"] == "PASS"
    assert any(
        input_item["path"].endswith("C-001-contract.md")
        for input_item in result["snapshot"]["inputs"]
    )
    assert result["schema_version"] == "gauntlet.coverage-snapshot.v2"


def test_contract_substring_plus_map_evidence_is_not_covered(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    criterion = "Gamma criterion."
    (directory / "gamma.md").write_text(
        f"# Gamma PRD\n## Acceptance Criteria\n- {criterion}\n", encoding="utf-8"
    )
    map_path.write_text(
        "schema_version: 1.0.0\nversion: 1\nrequirements:\n"
        "- id: MAP-GAMMA\n"
        "  contract_ids: [GAMMA-001]\n"
        "  acceptance_criteria:\n"
        f"  - {criterion}\n",
        encoding="utf-8",
    )
    proposals = map_path.parent / "architecture" / "proposals"
    proposals.mkdir(parents=True)
    contract = proposals / "GAMMA-001-contract.md"
    contract.write_text(
        "# Gamma contract\n"
        "- This unrelated sentence merely mentions Gamma criterion. as an example.\n",
        encoding="utf-8",
    )
    integration_log.write_text("MAP-GAMMA was recorded.\n", encoding="utf-8")

    result = _build(source_root, map_path, integration_log)
    item = result["criteria"][0]
    assert item["coverage_class"] == "CANDIDATE_UMBRELLA_ONLY"
    assert item["map_ids"] == ["MAP-GAMMA"]
    assert not any(ref["kind"] == "CONTRACT_CLAUSE" for ref in item["evidence_refs"])


def test_explicit_criterion_id_in_contract_clause_is_covered(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    exact = "The control response includes the declared status field."
    (directory / "prd.md").write_text(
        f"# API PRD\n## Acceptance Criteria\n- {exact}\n", encoding="utf-8"
    )
    map_path.write_text(
        "schema_version: 1.0.0\nversion: 1\nrequirements:\n"
        "- id: REQ-X001\n"
        "  contract_ids: [C-001]\n"
        "  acceptance_criteria:\n"
        f"  - {exact}\n",
        encoding="utf-8",
    )
    proposals = map_path.parent / "architecture" / "proposals"
    proposals.mkdir(parents=True)
    contract = proposals / "C-001-contract.md"
    contract.write_text("# C-001\n- placeholder clause\n", encoding="utf-8")
    initial = _build(source_root, map_path, integration_log)
    criterion_id = initial["criteria"][0]["criterion_id"]
    contract.write_text(
        f"# C-001\n- Implement the behavior identified by {criterion_id}.\n",
        encoding="utf-8",
    )

    result = _build(source_root, map_path, integration_log)
    item = result["criteria"][0]
    assert item["coverage_class"] == "COVERED_CRITERION"
    contract_ref = next(ref for ref in item["evidence_refs"] if ref["kind"] == "CONTRACT_CLAUSE")
    assert contract_ref["line_start"] == contract_ref["line_end"] == 2


def test_out_of_scope_constraints_are_counted_separately_as_leaf_statements(
    tmp_path: Path,
) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    (directory / "database-prd-mt4mt5-export-bridge.md").write_text(
        "# Database PRD\n## Key Behaviors & Constraints\n"
        "- Platforms: platform is MT4 or MT5.\n"
        "- Uniqueness:\n"
        "  - Template name/version is unique per platform.\n"
        "  - Parameter key is unique per template.\n"
        "## Acceptance Criteria\n- This criterion is counted separately.\n",
        encoding="utf-8",
    )
    result = _build(source_root, map_path, integration_log)
    summary = result["summary"]
    assert summary["source_criterion_count"] == 1
    assert summary["out_of_scope_constraint_count"] == 3
    assert summary["per_file_out_of_scope_constraint_counts"] == [
        {"path": ".codespring/PRDs/uncategorized/database-prd-mt4mt5-export-bridge.md", "count": 3}
    ]
    assert all(
        item["classification"] == "OUT_OF_SCOPE_CONSTRAINT"
        for item in result["out_of_scope_constraints"]
    )


def test_input_byte_ceiling_is_content_free(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    (directory / "oversized.md").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(InventoryError) as error:
        _build(source_root, map_path, integration_log)
    assert error.value.code == "INPUT_TOO_LARGE"
    assert str(error.value) == "INPUT_TOO_LARGE"


def test_markdown_discovery_has_a_file_count_ceiling(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    for index in range(513):
        (directory / f"{index:04d}.md").write_text("# Empty\n", encoding="utf-8")
    with pytest.raises(InventoryError) as error:
        _build(source_root, map_path, integration_log)
    assert error.value.code == "INPUT_TOO_LARGE"


def test_aggregate_input_byte_ceiling_is_content_free(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    for index in range(8):
        (directory / f"{index:04d}.md").write_bytes(b"x" * (2 * 1024 * 1024))
    with pytest.raises(InventoryError) as error:
        _build(source_root, map_path, integration_log)
    assert error.value.code == "INPUT_TOO_LARGE"
    assert str(error.value) == "INPUT_TOO_LARGE"


def test_requirements_map_nesting_has_a_depth_ceiling(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    (directory / "one.md").write_text("# One\n", encoding="utf-8")
    lines = ["schema_version: 1.0.0", "version: 1", "requirements:"]
    indent = "  "
    for index in range(66):
        lines.append(f"{indent}- id: REQ-{index:03d}")
        if index < 65:
            lines.append(f"{indent}  children:")
            indent += "  "
    map_path.write_text("\n".join(lines), encoding="utf-8")
    with pytest.raises(InventoryError) as error:
        _build(source_root, map_path, integration_log)
    assert error.value.code == "INPUT_TOO_LARGE"


def test_invalid_utf8_is_a_content_free_source_error(tmp_path: Path) -> None:
    source_root, map_path, integration_log, directory = _inputs(tmp_path)
    (directory / "bad.md").write_bytes(b"\xff")
    with pytest.raises(InventoryError) as error:
        _build(source_root, map_path, integration_log)
    assert error.value.code == "SOURCE_UNREADABLE"
    assert "\ufffd" not in str(error.value)
