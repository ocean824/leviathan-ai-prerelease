from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from verify_matrix import (
    REQUIRED_RELEASE_GATES,
    MatrixValidationError,
    _discover_prd_roots,
    _source_criteria_inventory,
    _source_items_for_file,
    main,
    required_release_gate_ids,
    source_inventory_sha256,
    validate_matrix,
)

COMMIT = "a" * 40
CANONICAL_MAP = Path(
    r"C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects"
    r"\XYRASYSTEMS\LEVIATHAN AI\REQUIREMENTS_MAP.yaml"
)


def _write_project(root: Path) -> None:
    (root / "repo" / "packages").mkdir(parents=True)
    source_root = (
        root.parent
        / "CODESPRING FILES"
        / "blackwealthcapital---leviathan-ai-codespring"
        / ".codespring"
        / "PRDs"
        / "demo"
    )
    source_root.mkdir(parents=True)
    (source_root / "backend.md").write_text(
        "# Demo\n\n## Acceptance Criteria\n\n- Identity works.\n- Identity is auditable.\n",
        encoding="utf-8",
    )
    (source_root / "replay.md").write_text(
        "# Replay\n\n## Acceptance Criteria\n\n- Replay is deterministic.\n",
        encoding="utf-8",
    )
    (root / "repo" / "packages" / "demo.py").write_text("identity = True\n", encoding="utf-8")


def _write_map(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema_version": "1.0.0",
        "version": 12,
        "requirements": [
            {
                "id": "LEV-REQ-001",
                "requirement": "identity",
                "source": (
                    "../CODESPRING FILES/blackwealthcapital---leviathan-ai-codespring/"
                    ".codespring/PRDs/demo/backend.md"
                ),
                "implementation_target": "packages/demo.py",
                "verification_method": "uv run pytest tests/test_demo.py -q",
                "acceptance_criteria": ["identity works", "identity is auditable"],
            },
            {
                "id": "LEV-REQ-002",
                "requirement": "replay",
                "source": (
                    "../CODESPRING FILES/blackwealthcapital---leviathan-ai-codespring/"
                    ".codespring/PRDs/demo/replay.md"
                ),
                "implementation_target": "packages/replay.py",
                "verification_method": "uv run pytest tests/test_replay.py -q",
                "acceptance_criteria": ["replay is deterministic"],
            },
        ],
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return data


def _blocker(gate_id: str) -> dict[str, str]:
    kind = (
        "SOURCE_UNAVAILABLE"
        if gate_id.startswith("SOURCE_UNAVAILABLE:")
        else {
            "FROZEN_CANDIDATE_EVIDENCE": "INTEGRATION_PENDING",
            "FULL_PRD_CRITERION_AUDIT": "INTEGRATION_PENDING",
            "INDEPENDENT_REVIEW": "INTEGRATION_PENDING",
            "PERF-001": "EXTERNAL_TERMINAL_REQUIRED",
            "MD-008": "EXTERNAL_TERMINAL_REQUIRED",
            "RISK-003_USER_LIMITS": "USER_INPUT_REQUIRED",
            "LIVE_BROKER_CREDENTIALS": "CREDENTIAL_REQUIRED",
            "PROVIDER_LICENSES": "LICENSE_REQUIRED",
            "SIGNING_CERTIFICATE": "CERTIFICATE_REQUIRED",
            "CLOUD_APPLY": "CLOUD_APPLY_REQUIRED",
            "INSTALLED_WINDOWS_BINARY": "EXTERNAL_TERMINAL_REQUIRED",
            "USER_RELEASE_APPROVAL": "USER_INPUT_REQUIRED",
        }[gate_id]
    )
    return {"kind": kind, "gate_id": gate_id}


def _criterion(criterion_id: str, expected: str, gate_id: str) -> dict[str, Any]:
    return {
        "criterion_id": criterion_id,
        "expected_behavior": expected,
        "actual_result": "Not executed against this candidate.",
        "test_types": ["integration"],
        "evidence": [],
        "environment": "test",
        "severity": "P1",
        "status": "NOT_TESTED",
        "blocker": _blocker(gate_id),
    }


def _manifest(
    project_root: Path,
    map_path: Path,
    map_data: dict[str, Any],
    source_exclusions: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    missing_sources = {
        gate_id: row["source"]
        for gate_id in required_release_gate_ids(map_path, project_root)
        if gate_id.startswith("SOURCE_UNAVAILABLE:")
        for row in map_data["requirements"]
        if gate_id
        == f"SOURCE_UNAVAILABLE:{hashlib.sha256(row['source'].encode()).hexdigest()[:16]}"
    }
    requirements = []
    for row in map_data["requirements"]:
        rid = row["id"]
        source_gate = next(
            (gate for gate, source in missing_sources.items() if source == row["source"]),
            "FROZEN_CANDIDATE_EVIDENCE",
        )
        requirements.append(
            {
                "requirement_id": rid,
                "source_reference": row["source"],
                "requirement_text": row["requirement"],
                "implementation_location": row["implementation_target"],
                "verification_method": row["verification_method"],
                "criteria": [
                    _criterion(f"{rid}.AC.{index:03d}", text, source_gate)
                    for index, text in enumerate(row["acceptance_criteria"], 1)
                ],
            }
        )
    source_criteria = []
    excluded_paths = {
        (project_root / entry["path"]).resolve() for entry in (source_exclusions or [])
    }
    for expected in _source_criteria_inventory(
        project_root, map_data["requirements"], excluded_paths
    ):
        blocker = (
            {"kind": "PRD_UNMAPPED", "gate_id": "FULL_PRD_CRITERION_AUDIT"}
            if not expected["mapped_requirement_ids"]
            else _blocker("FULL_PRD_CRITERION_AUDIT")
        )
        criterion = _criterion(
            expected["source_criterion_id"],
            expected["expected_behavior"],
            "FULL_PRD_CRITERION_AUDIT",
        )
        criterion["blocker"] = blocker
        if not expected["mapped_requirement_ids"]:
            criterion["status"] = "BLOCKED"
        source_criteria.append({**expected, **criterion})
    return {
        "schema_version": "1.0.0",
        "candidate": {
            "candidate_id": "candidate-test",
            "version": "0.0.0-test",
            "source_commit": COMMIT,
            "environment": "test",
            "requirements_map_sha256": hashlib.sha256(map_path.read_bytes()).hexdigest(),
            "source_inventory_sha256": source_inventory_sha256(
                project_root, map_data["requirements"]
            ),
            "release_artifacts": [],
            "source_exclusions": source_exclusions or [],
        },
        "requirements": requirements,
        "source_criteria": source_criteria,
        "release_gates": [
            {
                "gate_id": gate_id,
                "status": "NOT_TESTED",
                "description": f"{gate_id} has not been executed.",
                "actual_result": "No qualifying project handoff exists.",
                "evidence": [],
                "blocker": _blocker(gate_id),
                **(
                    {"source_reference": missing_sources[gate_id]}
                    if gate_id in missing_sources
                    else {}
                ),
            }
            for gate_id in sorted({*REQUIRED_RELEASE_GATES, *missing_sources})
        ],
    }


def _save(tmp_path: Path, manifest: dict[str, Any]) -> Path:
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    return path


@pytest.fixture
def setup_case(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, Any]]:
    project_root = tmp_path / "project"
    _write_project(project_root)
    map_path = project_root / "REQUIREMENTS_MAP.yaml"
    map_data = _write_map(map_path)
    manifest = _manifest(project_root, map_path, map_data)
    return map_path, project_root, _save(tmp_path, manifest), manifest


def _handoff_evidence(
    project_root: Path, subject_id: str, status: str, actual_result: str
) -> dict[str, str]:
    canonical_path = project_root / "repo" / "packages" / "demo.py"
    canonical_hash = hashlib.sha256(canonical_path.read_bytes()).hexdigest()
    record = {
        "schema_version": "1.0.0",
        "handoff_id": "independent-review-001",
        "candidate_commit": COMMIT,
        "worker_agent_id": "worker-001",
        "reviewer_agent_id": "reviewer-001",
        "review_disposition": "PASS",
        "canonical_files": [{"path": "packages/demo.py", "sha256": canonical_hash}],
        "results": [
            {
                "subject_id": subject_id,
                "status": status,
                "actual_result": actual_result,
                "canonical_file_paths": ["packages/demo.py"],
            }
        ],
    }
    evidence_path = project_root / "qa" / "handoffs" / "independent-review-001" / "evidence.json"
    evidence_path.parent.mkdir(parents=True)
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    evidence_path.write_bytes(raw)
    return {
        "kind": "PROJECT_QA_HANDOFF",
        "path": "qa/handoffs/independent-review-001/evidence.json",
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def test_complete_manifest_validates_without_certifying(
    setup_case: tuple[Path, Path, Path, dict[str, Any]],
) -> None:
    map_path, project_root, candidate_path, _ = setup_case
    result = validate_matrix(map_path, project_root, candidate_path)
    assert result["validation_status"] == "VALID"
    assert result["requirements_count"] == 2
    assert result["criteria_count"] == 3
    assert result["source_criteria_count"] == 3
    assert result["certification_status"] == "NOT_CERTIFIED"
    assert "certification" not in result or result["certification_status"] != "PASS"


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda m: m["requirements"].pop(), "MATRIX_REQUIREMENT_COVERAGE"),
        (
            lambda m: m["requirements"].append(
                dict(m["requirements"][0], requirement_id="UNKNOWN")
            ),
            "MATRIX_UNKNOWN_REQUIREMENT",
        ),
        (
            lambda m: m["requirements"].append(dict(m["requirements"][0])),
            "MATRIX_DUPLICATE_REQUIREMENT",
        ),
        (
            lambda m: m["requirements"][0]["criteria"].pop(),
            "MATRIX_CRITERIA_INCOMPLETE",
        ),
        (
            lambda m: m["requirements"][0]["criteria"][0].update(expected_behavior="changed"),
            "MATRIX_CRITERIA_MISMATCH",
        ),
        (lambda m: m["source_criteria"].pop(), "MATRIX_SOURCE_CRITERIA_INCOMPLETE"),
        (lambda m: m["release_gates"].pop(), "MATRIX_GATE_COVERAGE"),
    ],
)
def test_omitted_or_unmapped_manifest_item_fails_closed(
    setup_case: tuple[Path, Path, Path, dict[str, Any]], mutate: Any, code: str
) -> None:
    map_path, project_root, candidate_path, manifest = setup_case
    mutate(manifest)
    with pytest.raises(MatrixValidationError) as error:
        validate_matrix(map_path, project_root, _save(candidate_path.parent, manifest))
    assert error.value.code == code
    assert str(error.value) == code


def test_map_and_source_inventory_are_pinned(
    setup_case: tuple[Path, Path, Path, dict[str, Any]],
) -> None:
    map_path, project_root, candidate_path, manifest = setup_case
    source_file = project_root / (
        "../CODESPRING FILES/blackwealthcapital---leviathan-ai-codespring/"
        ".codespring/PRDs/demo/backend.md"
    )
    source_file.write_text(source_file.read_text() + "changed\n", encoding="utf-8")
    with pytest.raises(MatrixValidationError, match="MATRIX_SOURCE_INVENTORY_HASH_MISMATCH"):
        validate_matrix(map_path, project_root, candidate_path)
    source_file.write_text(
        "# Demo\n\n## Acceptance Criteria\n\n- Identity works.\n- Identity is auditable.\n",
        encoding="utf-8",
    )
    manifest["candidate"]["requirements_map_sha256"] = "0" * 64
    with pytest.raises(MatrixValidationError, match="MATRIX_REQUIREMENTS_MAP_HASH_MISMATCH"):
        validate_matrix(map_path, project_root, _save(candidate_path.parent, manifest))


def _write_unmapped_prd(project_root: Path) -> tuple[Path, str]:
    source_file = (
        project_root.parent
        / "CODESPRING FILES"
        / "blackwealthcapital---leviathan-ai-codespring"
        / ".codespring"
        / "PRDs"
        / "uncategorized"
        / "unmapped-demo.md"
    )
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_text(
        "# Unmapped demo\n\n## Acceptance Criteria\n\n- This local criterion has no map row.\n",
        encoding="utf-8",
    )
    return source_file, os.path.relpath(source_file, project_root).replace("\\", "/")


def test_unreferenced_prd_acceptance_item_is_blocked_as_unmapped(
    setup_case: tuple[Path, Path, Path, dict[str, Any]],
) -> None:
    map_path, project_root, candidate_path, _ = setup_case
    _write_unmapped_prd(project_root)
    map_data = yaml.safe_load(map_path.read_text(encoding="utf-8"))
    manifest = _manifest(project_root, map_path, map_data)

    unmapped = next(
        item
        for item in manifest["source_criteria"]
        if item["expected_behavior"] == "This local criterion has no map row."
    )
    assert unmapped["mapped_requirement_ids"] == []
    assert unmapped["status"] == "BLOCKED"
    assert unmapped["blocker"] == {
        "kind": "PRD_UNMAPPED",
        "gate_id": "FULL_PRD_CRITERION_AUDIT",
    }

    result = validate_matrix(map_path, project_root, _save(candidate_path.parent, manifest))
    assert result["source_criteria_count"] == 4


def test_source_exclusions_require_known_path_and_current_hash(
    setup_case: tuple[Path, Path, Path, dict[str, Any]],
) -> None:
    map_path, project_root, candidate_path, _ = setup_case
    source_file, source_reference = _write_unmapped_prd(project_root)
    map_data = yaml.safe_load(map_path.read_text(encoding="utf-8"))
    exclusion = {
        "path": source_reference,
        "sha256": hashlib.sha256(source_file.read_bytes()).hexdigest(),
        "reason": "Owned by a later PRD mapping contract.",
    }
    manifest = _manifest(project_root, map_path, map_data, [exclusion])
    assert all(item["source_reference"] != source_reference for item in manifest["source_criteria"])
    result = validate_matrix(map_path, project_root, _save(candidate_path.parent, manifest))
    assert result["source_exclusions_count"] == 1

    stale = json.loads(json.dumps(manifest))
    stale["candidate"]["source_exclusions"][0]["sha256"] = "0" * 64
    with pytest.raises(MatrixValidationError, match="MATRIX_SOURCE_EXCLUSION_HASH_MISMATCH"):
        validate_matrix(map_path, project_root, _save(candidate_path.parent, stale))

    unknown = json.loads(json.dumps(manifest))
    unknown["candidate"]["source_exclusions"][0]["path"] = "../PRDs/not-in-inventory.md"
    with pytest.raises(MatrixValidationError, match="MATRIX_SOURCE_EXCLUSION_UNKNOWN"):
        validate_matrix(map_path, project_root, _save(candidate_path.parent, unknown))


@pytest.mark.skipif(not CANONICAL_MAP.is_file(), reason="canonical project source tree is absent")
def test_canonical_prd_tree_includes_unreferenced_uncategorized_criteria() -> None:
    map_data = yaml.safe_load(CANONICAL_MAP.read_text(encoding="utf-8"))
    rows = map_data["requirements"]
    prd_roots = _discover_prd_roots(CANONICAL_MAP.parent, rows)
    if not prd_roots:
        pytest.skip("canonical .codespring/PRDs tree is absent")
    criteria = _source_criteria_inventory(CANONICAL_MAP.parent, rows)
    assert len(prd_roots) == 1
    assert len(list(next(iter(prd_roots)).rglob("*.md"))) == 123
    assert len(criteria) == 965


def test_missing_cited_source_gets_exact_fail_closed_gate(
    setup_case: tuple[Path, Path, Path, dict[str, Any]],
) -> None:
    map_path, project_root, candidate_path, _ = setup_case
    source = project_root / (
        "../CODESPRING FILES/blackwealthcapital---leviathan-ai-codespring/"
        ".codespring/PRDs/demo/backend.md"
    )
    source.unlink()
    map_data = yaml.safe_load(map_path.read_text(encoding="utf-8"))
    manifest = _manifest(project_root, map_path, map_data)
    source_reference = map_data["requirements"][0]["source"]
    gate_id = f"SOURCE_UNAVAILABLE:{hashlib.sha256(source_reference.encode()).hexdigest()[:16]}"
    criterion = manifest["requirements"][0]["criteria"][0]
    assert criterion["status"] == "NOT_TESTED"
    assert criterion["blocker"] == {"kind": "SOURCE_UNAVAILABLE", "gate_id": gate_id}
    assert any(
        gate["gate_id"] == gate_id and gate["source_reference"] == source_reference
        for gate in manifest["release_gates"]
    )
    result = validate_matrix(map_path, project_root, _save(candidate_path.parent, manifest))
    assert result["release_gate_statuses"][gate_id] == "NOT_TESTED"


def test_source_scanner_keeps_prose_criteria_and_rejects_tables(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    source = project_root / "inputs" / "prd" / "standalone.md"
    source.parent.mkdir(parents=True)
    source.write_text(
        "~~~markdown\n## Acceptance Criteria\n- Example is not a criterion.\n~~~\n"
        "## Acceptance Criteria\n\n```markdown\n"
        "- This example is not a criterion.\n## Fake heading\n```\n\n"
        "The service returns a typed error.\n\n- The response is deterministic.\n",
        encoding="utf-8",
    )
    items = _source_items_for_file(source, "../CODESPRING FILES/demo/standalone.md")
    assert [item["source_line"] for item in items] == [12, 14]
    assert [item["expected_behavior"] for item in items] == [
        "The service returns a typed error.",
        "The response is deterministic.",
    ]

    source.write_text(
        "## Acceptance Criteria\n\n| Case | Result |\n| --- | --- |\n",
        encoding="utf-8",
    )
    with pytest.raises(MatrixValidationError, match="SOURCE_ACCEPTANCE_FORMAT_UNSUPPORTED"):
        _source_items_for_file(source, project_root)


def test_criterion_pass_needs_independent_handoff_hashes(
    setup_case: tuple[Path, Path, Path, dict[str, Any]],
) -> None:
    map_path, project_root, candidate_path, manifest = setup_case
    criterion = manifest["requirements"][0]["criteria"][0]
    actual = "Observed expected behavior."
    criterion.update(status="PASS", actual_result=actual, evidence=[])
    criterion.pop("blocker")
    with pytest.raises(MatrixValidationError, match="MATRIX_EVIDENCE_MISSING"):
        validate_matrix(map_path, project_root, _save(candidate_path.parent, manifest))

    criterion["evidence"] = [
        _handoff_evidence(project_root, criterion["criterion_id"], "PASS", actual)
    ]
    result = validate_matrix(map_path, project_root, _save(candidate_path.parent, manifest))
    assert result["criterion_status_counts"] == {"NOT_TESTED": 5, "PASS": 1}
    assert result["certification_status"] == "NOT_CERTIFIED"


def test_arbitrary_hash_valid_text_does_not_count_as_handoff(
    setup_case: tuple[Path, Path, Path, dict[str, Any]],
) -> None:
    map_path, project_root, candidate_path, manifest = setup_case
    item_path = project_root / "arbitrary.txt"
    item_path.write_text("PASS: independently audited", encoding="utf-8")
    item = {
        "kind": "PROJECT_QA_HANDOFF",
        "path": "arbitrary.txt",
        "sha256": hashlib.sha256(item_path.read_bytes()).hexdigest(),
    }
    criterion = manifest["requirements"][0]["criteria"][0]
    criterion.update(status="PASS", actual_result="Observed expected behavior.", evidence=[item])
    criterion.pop("blocker")
    with pytest.raises(MatrixValidationError, match="EVIDENCE_NOT_PROJECT_HANDOFF"):
        validate_matrix(map_path, project_root, _save(candidate_path.parent, manifest))


def test_closed_blocker_vocabulary_and_exact_gate_binding(
    setup_case: tuple[Path, Path, Path, dict[str, Any]],
) -> None:
    map_path, project_root, candidate_path, manifest = setup_case
    criterion = manifest["requirements"][0]["criteria"][0]
    criterion["blocker"] = "pending"
    with pytest.raises(MatrixValidationError, match="MATRIX_BLOCKER_INVALID"):
        validate_matrix(map_path, project_root, _save(candidate_path.parent, manifest))


def test_all_gates_cannot_pass_and_user_approval_is_never_pass(
    setup_case: tuple[Path, Path, Path, dict[str, Any]],
) -> None:
    map_path, project_root, candidate_path, manifest = setup_case
    original = json.loads(json.dumps(manifest))
    for gate in manifest["release_gates"]:
        gate.update(status="PASS", evidence=[])
        gate.pop("blocker")
    with pytest.raises(MatrixValidationError, match="MATRIX_EVIDENCE_MISSING"):
        validate_matrix(map_path, project_root, _save(candidate_path.parent, manifest))
    manifest = original
    gate = next(g for g in manifest["release_gates"] if g["gate_id"] == "USER_RELEASE_APPROVAL")
    gate.update(status="PASS", evidence=[])
    gate.pop("blocker")
    with pytest.raises(MatrixValidationError, match="MATRIX_USER_APPROVAL_GATE_CANNOT_PASS"):
        validate_matrix(map_path, project_root, _save(candidate_path.parent, manifest))


def test_cli_returns_content_free_error_and_no_certification_claim(
    setup_case: tuple[Path, Path, Path, dict[str, Any]], capsys: pytest.CaptureFixture[str]
) -> None:
    map_path, project_root, candidate_path, manifest = setup_case
    manifest["requirements"].pop()
    _save(candidate_path.parent, manifest)
    exit_code = main(
        [
            "--requirements",
            str(map_path),
            "--source-root",
            str(project_root),
            "--candidate",
            str(candidate_path),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload == {
        "validation_status": "INVALID",
        "certification_status": "NOT_CERTIFIED",
        "error_code": "MATRIX_REQUIREMENT_COVERAGE",
    }
