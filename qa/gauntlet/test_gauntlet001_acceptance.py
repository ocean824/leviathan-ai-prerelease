from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from verify_matrix import (
    REQUIRED_RELEASE_GATES,
    MatrixValidationError,
    main,
    source_inventory_sha256,
    validate_matrix,
)

CANONICAL_MAP = Path(
    r"C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects"
    r"\XYRASYSTEMS\LEVIATHAN AI\REQUIREMENTS_MAP.yaml"
)
CANONICAL_MAP_SHA256 = "cdd971cb1e5e1f85a810e1c3627e40a14e27da3058f71433e64c69b4e0005f69"
SOURCE_RELATIVE = "inputs/prd/demo/spec.md"
SOURCE_TEXT = (
    "# Synthetic Product\n"
    "\n"
    "## Acceptance criteria\n"
    "- The launch flow requires explicit operator action.\n"
    "- Every decision has a traceable audit event.\n"
)
SOURCE_ITEMS = (
    (4, "The launch flow requires explicit operator action."),
    (5, "Every decision has a traceable audit event."),
)
_FIXED_GATE_BLOCKERS = {
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
}


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _source_gate_id(source_reference: str) -> str:
    return f"SOURCE_UNAVAILABLE:{_sha256(source_reference.encode('utf-8'))[:16]}"


def _write_project_root(
    root: Path,
    *,
    source_available: bool,
    source_text: str = SOURCE_TEXT,
) -> Path:
    (root / "inputs" / "prd").mkdir(parents=True)
    (root / "inputs" / "codespring").mkdir(parents=True)
    (root / "qa" / "handoffs").mkdir(parents=True)
    repo_file = root / "repo" / "packages" / "demo.py"
    repo_file.parent.mkdir(parents=True)
    repo_file.write_bytes(b"synthetic canonical implementation\n")
    if source_available:
        source_file = root / SOURCE_RELATIVE
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text(source_text, encoding="utf-8")
    return root


def _write_small_map(path: Path, source_reference: str) -> dict[str, Any]:
    map_data = {
        "schema_version": "1.0.0",
        "version": 12,
        "requirements": [
            {
                "id": "REQ-DEMO",
                "requirement": "The synthetic feature is bounded and auditable.",
                "source": source_reference,
                "implementation_target": "packages/demo.py",
                "verification_method": "uv run pytest tests/test_demo.py -q",
                "acceptance_criteria": ["The synthetic requirement is traceable."],
            }
        ],
    }
    path.write_text(yaml.safe_dump(map_data, sort_keys=False), encoding="utf-8")
    return map_data


def _criterion(
    requirement_id: str,
    index: int,
    expected: str,
    blocker: dict[str, str],
) -> dict[str, Any]:
    return {
        "criterion_id": f"{requirement_id}.AC.{index:03d}",
        "expected_behavior": expected,
        "actual_result": "No candidate execution evidence was supplied.",
        "test_types": ["release"],
        "evidence": [],
        "environment": "test",
        "severity": "P1",
        "status": "BLOCKED",
        "blocker": blocker.copy(),
    }


def _source_criterion(
    text: str,
    line: int,
    mapped_requirement_ids: list[str],
) -> dict[str, Any]:
    relative = SOURCE_RELATIVE
    stable = f"{relative}\0{line}\0{text}".encode()
    source_id = f"SRC-{_sha256(stable)[:20]}"
    return {
        "criterion_id": source_id,
        "source_criterion_id": source_id,
        "source_reference": relative,
        "source_line": line,
        "mapped_requirement_ids": mapped_requirement_ids,
        "expected_behavior": text,
        "actual_result": "This source criterion has not received integrated review.",
        "test_types": ["release"],
        "evidence": [],
        "environment": "test",
        "severity": "P1",
        "status": "BLOCKED",
        "blocker": {
            "kind": "INTEGRATION_PENDING",
            "gate_id": "FULL_PRD_CRITERION_AUDIT",
        },
    }


def _source_criteria(
    map_data: dict[str, Any],
    *,
    source_available: bool,
    source_items: tuple[tuple[int, str], ...],
) -> list[dict[str, Any]]:
    if not source_available:
        return []
    mapped_ids = sorted(
        row["id"] for row in map_data["requirements"] if row["source"] == SOURCE_RELATIVE
    )
    return [_source_criterion(text, line, mapped_ids) for line, text in source_items]


def _build_manifest(
    map_path: Path,
    project_root: Path,
    map_data: dict[str, Any],
    *,
    unavailable_sources: set[str],
    source_available: bool,
    source_items: tuple[tuple[int, str], ...] = SOURCE_ITEMS,
) -> dict[str, Any]:
    requirements = []
    for row in map_data["requirements"]:
        source_reference = row["source"]
        blocker_id = (
            _source_gate_id(source_reference)
            if source_reference in unavailable_sources
            else "FULL_PRD_CRITERION_AUDIT"
        )
        blocker_kind = (
            "SOURCE_UNAVAILABLE"
            if source_reference in unavailable_sources
            else "INTEGRATION_PENDING"
        )
        requirements.append(
            {
                "requirement_id": row["id"],
                "source_reference": source_reference,
                "requirement_text": row["requirement"],
                "implementation_location": row["implementation_target"],
                "verification_method": row["verification_method"],
                "criteria": [
                    _criterion(
                        row["id"],
                        index,
                        text,
                        {"kind": blocker_kind, "gate_id": blocker_id},
                    )
                    for index, text in enumerate(row["acceptance_criteria"], 1)
                ],
            }
        )

    gates = []
    for gate_id in sorted(REQUIRED_RELEASE_GATES):
        gates.append(
            {
                "gate_id": gate_id,
                "status": "NOT_TESTED",
                "description": f"{gate_id} has not been verified for this synthetic candidate.",
                "actual_result": "No integrated gate evidence was supplied.",
                "blocker": {"kind": _FIXED_GATE_BLOCKERS[gate_id], "gate_id": gate_id},
            }
        )
    for source_reference in sorted(unavailable_sources):
        gate_id = _source_gate_id(source_reference)
        gates.append(
            {
                "gate_id": gate_id,
                "status": "NOT_TESTED",
                "description": f"The local source for {source_reference} is unavailable.",
                "actual_result": "The cited source could not be audited in this project root.",
                "source_reference": source_reference,
                "blocker": {"kind": "SOURCE_UNAVAILABLE", "gate_id": gate_id},
            }
        )

    return {
        "schema_version": "1.0.0",
        "candidate": {
            "candidate_id": "gauntlet-acceptance-synthetic",
            "version": "0.0.0-test",
            "source_commit": "a" * 40,
            "environment": "test",
            "requirements_map_sha256": _sha256(map_path.read_bytes()),
            "source_inventory_sha256": source_inventory_sha256(project_root),
            "release_artifacts": [],
        },
        "requirements": requirements,
        "source_criteria": _source_criteria(
            map_data,
            source_available=source_available,
            source_items=source_items,
        ),
        "release_gates": gates,
    }


def _save_manifest(path: Path, manifest: dict[str, Any]) -> Path:
    path.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    return path


def _synthetic_case(
    tmp_path: Path,
    *,
    source_available: bool = True,
    source_text: str = SOURCE_TEXT,
    source_items: tuple[tuple[int, str], ...] = SOURCE_ITEMS,
) -> tuple[Path, Path, Path, dict[str, Any]]:
    project_root = _write_project_root(
        tmp_path / "project",
        source_available=source_available,
        source_text=source_text,
    )
    map_path = project_root / "REQUIREMENTS_MAP.yaml"
    source_reference = SOURCE_RELATIVE if source_available else "inputs/prd/demo/missing-spec.md"
    map_data = _write_small_map(map_path, source_reference)
    unavailable_sources = set() if source_available else {source_reference}
    manifest = _build_manifest(
        map_path,
        project_root,
        map_data,
        unavailable_sources=unavailable_sources,
        source_available=source_available,
        source_items=source_items,
    )
    candidate_path = _save_manifest(tmp_path / "candidate.json", manifest)
    return map_path, project_root, candidate_path, manifest


def _canonical_case(
    tmp_path: Path,
) -> tuple[Path, Path, Path, dict[str, Any], dict[str, Any]]:
    assert CANONICAL_MAP.is_file(), "canonical Requirements Map v12 is required"
    map_bytes = CANONICAL_MAP.read_bytes()
    assert _sha256(map_bytes) == CANONICAL_MAP_SHA256
    map_data = yaml.safe_load(map_bytes)
    assert map_data["version"] == 12
    assert len(map_data["requirements"]) == 72
    assert len({row["id"] for row in map_data["requirements"]}) == 72

    project_root = _write_project_root(tmp_path / "project", source_available=False)
    map_path = project_root / "REQUIREMENTS_MAP.yaml"
    map_path.write_bytes(map_bytes)
    unavailable_sources = {row["source"] for row in map_data["requirements"]}
    manifest = _build_manifest(
        map_path,
        project_root,
        map_data,
        unavailable_sources=unavailable_sources,
        source_available=False,
    )
    candidate_path = _save_manifest(tmp_path / "candidate.json", manifest)
    return map_path, project_root, candidate_path, manifest, map_data


def _write_handoff(
    project_root: Path,
    *,
    candidate_commit: str,
    results: list[dict[str, Any]],
    worker_agent_id: str = "worker-agent",
    reviewer_agent_id: str = "independent-reviewer",
    review_disposition: str = "PASS",
) -> dict[str, str]:
    relative_repo_path = "packages/demo.py"
    repo_file = project_root / "repo" / relative_repo_path
    repo_file.parent.mkdir(parents=True, exist_ok=True)
    if not repo_file.exists():
        repo_file.write_bytes(b"synthetic canonical implementation\n")
    canonical_hash = _sha256(repo_file.read_bytes())
    handoff = {
        "schema_version": "1.0.0",
        "handoff_id": "GAUNTLET-ACCEPTANCE",
        "candidate_commit": candidate_commit,
        "worker_agent_id": worker_agent_id,
        "reviewer_agent_id": reviewer_agent_id,
        "review_disposition": review_disposition,
        "canonical_files": [{"path": relative_repo_path, "sha256": canonical_hash}],
        "results": results,
    }
    content = json.dumps(handoff, sort_keys=True, separators=(",", ":")).encode("utf-8")
    handoff_path = project_root / "qa" / "handoffs" / "GAUNTLET-ACCEPTANCE" / "evidence.json"
    handoff_path.parent.mkdir(parents=True, exist_ok=True)
    handoff_path.write_bytes(content)
    return {
        "kind": "PROJECT_QA_HANDOFF",
        "path": "qa/handoffs/GAUNTLET-ACCEPTANCE/evidence.json",
        "sha256": _sha256(content),
    }


def _criterion_result(
    subject_id: str,
    *,
    status: str = "PASS",
    actual_result: str = "Synthetic acceptance evidence passed.",
) -> dict[str, Any]:
    return {
        "subject_id": subject_id,
        "status": status,
        "actual_result": actual_result,
        "canonical_file_paths": ["packages/demo.py"],
    }


def _mark_criterion_pass(
    project_root: Path,
    candidate: dict[str, Any],
    candidate_path: Path,
) -> dict[str, str]:
    criterion = candidate["requirements"][0]["criteria"][0]
    criterion.update(
        status="PASS",
        actual_result="Synthetic acceptance evidence passed.",
        evidence=[],
    )
    criterion.pop("blocker")
    evidence = _write_handoff(
        project_root,
        candidate_commit=candidate["candidate"]["source_commit"],
        results=[_criterion_result(criterion["criterion_id"])],
    )
    criterion["evidence"] = [evidence]
    candidate["candidate"]["release_artifacts"] = [evidence]
    _save_manifest(candidate_path, candidate)
    return evidence


def _assert_error(
    map_path: Path,
    project_root: Path,
    candidate_path: Path,
    expected_code: str,
) -> None:
    with pytest.raises(MatrixValidationError) as error:
        validate_matrix(map_path, project_root, candidate_path, project_root)
    assert error.value.code == expected_code
    assert str(error.value) == expected_code


def test_all_canonical_map_ids_and_criteria_are_mapped_without_certifying(
    tmp_path: Path,
) -> None:
    map_path, project_root, candidate_path, manifest, map_data = _canonical_case(tmp_path)
    expected_ids = {row["id"] for row in map_data["requirements"]}
    actual_ids = {row["requirement_id"] for row in manifest["requirements"]}

    assert len(expected_ids) == 72
    assert actual_ids == expected_ids
    result = validate_matrix(map_path, project_root, candidate_path, project_root)

    assert result["validation_status"] == "VALID"
    assert result["requirements_count"] == 72
    assert result["criteria_count"] == sum(
        len(row["acceptance_criteria"]) for row in map_data["requirements"]
    )
    assert set(result["criterion_status_counts"]) <= {"BLOCKED"}
    assert result["certification_status"] == "NOT_CERTIFIED"
    assert result["source_criteria_count"] == 0


def test_resolvable_codespring_prd_reference_maps_source_criteria(
    tmp_path: Path,
) -> None:
    project_parent = tmp_path / "projects" / "XYRASYSTEMS"
    project_root = project_parent / "LEVIATHAN AI"
    project_root.mkdir(parents=True)
    source_reference = (
        "../CODESPRING FILES/blackwealthcapital---leviathan-ai-codespring/"
        ".codespring/PRDs/monitoring-telemetry-logging/"
        "backend-prd-monitoring-telemetry-logging.md"
    )
    source_text = (
        "# Synthetic Monitoring PRD\n\n"
        "## Acceptance criteria\n"
        "- Every alert includes its source and event time.\n"
    )
    source_file = (project_root / source_reference).resolve()
    source_file.parent.mkdir(parents=True)
    source_file.write_text(source_text, encoding="utf-8")

    map_path = project_root / "REQUIREMENTS_MAP.yaml"
    map_data = _write_small_map(map_path, source_reference)
    source_item = "Every alert includes its source and event time."
    map_data["requirements"][0]["source"] = source_reference
    map_path.write_text(yaml.safe_dump(map_data, sort_keys=False), encoding="utf-8")

    project_root.mkdir(exist_ok=True)
    (project_root / "inputs" / "prd").mkdir(parents=True)
    (project_root / "inputs" / "codespring").mkdir(parents=True)
    repo_file = project_root / "repo" / "packages" / "demo.py"
    repo_file.parent.mkdir(parents=True)
    repo_file.write_bytes(b"synthetic canonical implementation\n")
    (project_root / "qa" / "handoffs").mkdir(parents=True)

    manifest = _build_manifest(
        map_path,
        project_root,
        map_data,
        unavailable_sources=set(),
        source_available=False,
    )
    stable = f"{source_reference}\0{4}\0{source_item}".encode()
    source_id = f"SRC-{_sha256(stable)[:20]}"
    manifest["source_criteria"] = [
        {
            "criterion_id": source_id,
            "source_criterion_id": source_id,
            "source_reference": source_reference,
            "source_line": 4,
            "mapped_requirement_ids": ["REQ-DEMO"],
            "expected_behavior": source_item,
            "actual_result": "This source criterion has not received integrated review.",
            "test_types": ["release"],
            "evidence": [],
            "environment": "test",
            "severity": "P1",
            "status": "BLOCKED",
            "blocker": {
                "kind": "INTEGRATION_PENDING",
                "gate_id": "FULL_PRD_CRITERION_AUDIT",
            },
        }
    ]
    candidate_path = _save_manifest(tmp_path / "candidate.json", manifest)

    result = validate_matrix(map_path, project_root, candidate_path, project_root)

    assert result["validation_status"] == "VALID"
    assert result["source_criteria_count"] == 1
    assert not any(
        gate_id.startswith("SOURCE_UNAVAILABLE:") for gate_id in result["release_gate_statuses"]
    )
    mapped = manifest["source_criteria"][0]
    assert mapped["source_reference"] == source_reference
    assert mapped["expected_behavior"] == source_item
    assert mapped["mapped_requirement_ids"] == ["REQ-DEMO"]


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing", "MATRIX_REQUIREMENT_COVERAGE"),
        ("unknown", "MATRIX_UNKNOWN_REQUIREMENT"),
    ],
)
def test_missing_or_unmapped_requirement_fails_closed(
    tmp_path: Path,
    mutation: str,
    expected_code: str,
) -> None:
    map_path, project_root, candidate_path, manifest, _map_data = _canonical_case(tmp_path)
    if mutation == "missing":
        manifest["requirements"].pop()
    else:
        extra = dict(manifest["requirements"][0])
        extra["requirement_id"] = "LEV-REQ-UNKNOWN-999"
        manifest["requirements"].append(extra)
    _save_manifest(candidate_path, manifest)

    _assert_error(map_path, project_root, candidate_path, expected_code)


def test_evidence_less_criteria_are_gated_and_cannot_claim_pass_without_evidence(
    tmp_path: Path,
) -> None:
    map_path, project_root, candidate_path, manifest, _map_data = _canonical_case(tmp_path)
    criteria = [criterion for row in manifest["requirements"] for criterion in row["criteria"]]
    assert criteria
    assert all(criterion["status"] in {"BLOCKED", "NOT_TESTED"} for criterion in criteria)
    assert all(not criterion["evidence"] and criterion["blocker"] for criterion in criteria)

    result = validate_matrix(map_path, project_root, candidate_path, project_root)
    assert result["validation_status"] == "VALID"
    assert result["certification_status"] == "NOT_CERTIFIED"

    criterion = manifest["requirements"][0]["criteria"][0]
    criterion.update(status="PASS", actual_result="Claimed pass without evidence.", evidence=[])
    criterion.pop("blocker")
    _save_manifest(candidate_path, manifest)
    _assert_error(map_path, project_root, candidate_path, "MATRIX_SOURCE_UNAVAILABLE_PASS")


def test_cli_never_emits_certification_pass_with_a_verified_criterion_pass(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    map_path, project_root, candidate_path, manifest = _synthetic_case(tmp_path)
    evidence = _mark_criterion_pass(project_root, manifest, candidate_path)
    criterion = manifest["requirements"][0]["criteria"][0]
    assert criterion["evidence"] == [evidence]

    exit_code = main(
        [
            "--requirements",
            str(map_path),
            "--source-root",
            str(project_root),
            "--candidate",
            str(candidate_path),
            "--evidence-root",
            str(project_root),
        ]
    )
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert report["validation_status"] == "VALID"
    assert report["certification_status"] == "NOT_CERTIFIED"
    assert report.get("certification") != "PASS"


def test_missing_source_has_an_exact_required_gate(tmp_path: Path) -> None:
    map_path, project_root, candidate_path, manifest = _synthetic_case(
        tmp_path,
        source_available=False,
    )
    source_reference = manifest["requirements"][0]["source_reference"]
    expected_gate = _source_gate_id(source_reference)
    gate = next(gate for gate in manifest["release_gates"] if gate["gate_id"] == expected_gate)
    assert gate["status"] in {"BLOCKED", "NOT_TESTED"}
    assert gate["source_reference"] == source_reference
    assert gate["blocker"] == {"kind": "SOURCE_UNAVAILABLE", "gate_id": expected_gate}

    result = validate_matrix(map_path, project_root, candidate_path, project_root)
    assert result["validation_status"] == "VALID"
    assert result["release_gate_statuses"][expected_gate] == "NOT_TESTED"

    manifest["release_gates"].remove(gate)
    _save_manifest(candidate_path, manifest)
    _assert_error(map_path, project_root, candidate_path, "MATRIX_GATE_COVERAGE")


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("omit", "MATRIX_SOURCE_CRITERIA_INCOMPLETE"),
        ("modify", "MATRIX_SOURCE_CRITERIA_MISMATCH"),
    ],
)
def test_auto_enumerated_source_criteria_cannot_be_omitted_or_changed(
    tmp_path: Path,
    mutation: str,
    expected_code: str,
) -> None:
    map_path, project_root, candidate_path, manifest = _synthetic_case(tmp_path)
    assert len(manifest["source_criteria"]) == 2
    assert (
        validate_matrix(map_path, project_root, candidate_path, project_root)[
            "source_criteria_count"
        ]
        == 2
    )

    if mutation == "omit":
        manifest["source_criteria"].pop()
    else:
        manifest["source_criteria"][0]["expected_behavior"] = "Changed source criterion."
    _save_manifest(candidate_path, manifest)
    _assert_error(map_path, project_root, candidate_path, expected_code)


def test_standalone_acceptance_prose_is_preserved_as_a_source_criterion(
    tmp_path: Path,
) -> None:
    prose = "The startup flow requires a human confirmation."
    source_text = f"# Synthetic Product\n\n## Acceptance criteria\n{prose}\n"
    map_path, project_root, candidate_path, manifest = _synthetic_case(
        tmp_path,
        source_text=source_text,
        source_items=((4, prose),),
    )

    result = validate_matrix(map_path, project_root, candidate_path, project_root)

    assert result["source_criteria_count"] == 1
    assert manifest["source_criteria"][0]["expected_behavior"] == prose
    assert manifest["source_criteria"][0]["source_line"] == 4


def test_table_form_acceptance_section_fails_closed(tmp_path: Path) -> None:
    table = (
        "# Synthetic Product\n\n"
        "## Acceptance criteria\n"
        "| Criterion | Result |\n"
        "| --- | --- |\n"
        "| Preserve evidence | Required |\n"
    )
    map_path, project_root, candidate_path, _manifest = _synthetic_case(
        tmp_path,
        source_text=table,
        source_items=(),
    )

    _assert_error(
        map_path,
        project_root,
        candidate_path,
        "SOURCE_ACCEPTANCE_FORMAT_UNSUPPORTED",
    )


def test_hash_valid_arbitrary_file_is_not_project_handoff_evidence(tmp_path: Path) -> None:
    map_path, project_root, candidate_path, manifest = _synthetic_case(tmp_path)
    arbitrary_path = project_root / "qa" / "handoffs" / "GAUNTLET-ACCEPTANCE" / "evidence.json"
    arbitrary_path.parent.mkdir(parents=True, exist_ok=True)
    arbitrary_bytes = b'{"result":"PASS"}'
    arbitrary_path.write_bytes(arbitrary_bytes)
    evidence = {
        "kind": "PROJECT_QA_HANDOFF",
        "path": "qa/handoffs/GAUNTLET-ACCEPTANCE/evidence.json",
        "sha256": _sha256(arbitrary_bytes),
    }
    criterion = manifest["requirements"][0]["criteria"][0]
    criterion.update(status="PASS", actual_result="Synthetic pass.", evidence=[evidence])
    criterion.pop("blocker")
    _save_manifest(candidate_path, manifest)

    _assert_error(map_path, project_root, candidate_path, "HANDOFF_RECORD_INVALID")


def test_stale_canonical_repo_hash_invalidates_handoff(tmp_path: Path) -> None:
    map_path, project_root, candidate_path, manifest = _synthetic_case(tmp_path)
    _mark_criterion_pass(project_root, manifest, candidate_path)
    repo_file = project_root / "repo" / "packages" / "demo.py"
    repo_file.write_bytes(b"canonical implementation changed after handoff\n")

    _assert_error(map_path, project_root, candidate_path, "HANDOFF_CANONICAL_HASH_MISMATCH")


@pytest.mark.parametrize(
    ("worker", "reviewer"),
    [
        ("worker-agent", ""),
        ("same-agent", "same-agent"),
    ],
)
def test_handoff_requires_a_distinct_reviewer_for_pass_evidence(
    tmp_path: Path,
    worker: str,
    reviewer: str,
) -> None:
    map_path, project_root, candidate_path, manifest = _synthetic_case(tmp_path)
    criterion = manifest["requirements"][0]["criteria"][0]
    criterion.update(status="PASS", actual_result="Synthetic acceptance evidence passed.")
    criterion.pop("blocker")
    evidence = _write_handoff(
        project_root,
        candidate_commit=manifest["candidate"]["source_commit"],
        results=[_criterion_result(criterion["criterion_id"])],
        worker_agent_id=worker,
        reviewer_agent_id=reviewer,
    )
    criterion["evidence"] = [evidence]
    manifest["candidate"]["release_artifacts"] = [evidence]
    _save_manifest(candidate_path, manifest)

    _assert_error(map_path, project_root, candidate_path, "HANDOFF_REVIEW_NOT_INDEPENDENT_PASS")


@pytest.mark.parametrize(
    ("mismatch", "expected_code"),
    [
        ("result", "HANDOFF_RESULT_MISSING"),
        ("candidate", "HANDOFF_CANDIDATE_MISMATCH"),
    ],
)
def test_handoff_must_bind_candidate_and_exact_result(
    tmp_path: Path,
    mismatch: str,
    expected_code: str,
) -> None:
    map_path, project_root, candidate_path, manifest = _synthetic_case(tmp_path)
    criterion = manifest["requirements"][0]["criteria"][0]
    criterion.update(status="PASS", actual_result="Synthetic acceptance evidence passed.")
    criterion.pop("blocker")
    result = _criterion_result(criterion["criterion_id"])
    candidate_commit = manifest["candidate"]["source_commit"]
    if mismatch == "result":
        result["actual_result"] = "A different result was reported."
    else:
        candidate_commit = "b" * 40
    evidence = _write_handoff(
        project_root,
        candidate_commit=candidate_commit,
        results=[result],
    )
    criterion["evidence"] = [evidence]
    manifest["candidate"]["release_artifacts"] = [evidence]
    _save_manifest(candidate_path, manifest)

    _assert_error(map_path, project_root, candidate_path, expected_code)


@pytest.mark.parametrize(
    ("blocker", "expected_code"),
    [
        ("Awaiting evidence", "MATRIX_BLOCKER_INVALID"),
        (
            {"kind": "SOURCE_UNAVAILABLE", "gate_id": "FULL_PRD_CRITERION_AUDIT"},
            "MATRIX_BLOCKER_GATE_MISMATCH",
        ),
    ],
)
def test_blockers_must_be_structured_and_match_their_gate(
    tmp_path: Path,
    blocker: Any,
    expected_code: str,
) -> None:
    map_path, project_root, candidate_path, manifest = _synthetic_case(tmp_path)
    manifest["requirements"][0]["criteria"][0]["blocker"] = blocker
    _save_manifest(candidate_path, manifest)

    _assert_error(map_path, project_root, candidate_path, expected_code)


def test_source_unavailable_criterion_must_use_its_own_gate(tmp_path: Path) -> None:
    map_path, project_root, candidate_path, manifest = _synthetic_case(
        tmp_path,
        source_available=False,
    )
    criterion = manifest["requirements"][0]["criteria"][0]
    criterion["blocker"] = {
        "kind": "EXTERNAL_TERMINAL_REQUIRED",
        "gate_id": "PERF-001",
    }
    _save_manifest(candidate_path, manifest)

    _assert_error(
        map_path,
        project_root,
        candidate_path,
        "MATRIX_SOURCE_UNAVAILABLE_BLOCKER_MISMATCH",
    )


def test_all_gate_pass_claim_is_rejected_even_with_hash_bound_records(tmp_path: Path) -> None:
    map_path, project_root, candidate_path, manifest = _synthetic_case(tmp_path)
    criterion = manifest["requirements"][0]["criteria"][0]
    criterion.update(status="PASS", actual_result="Synthetic acceptance evidence passed.")
    criterion.pop("blocker")
    results = [_criterion_result(criterion["criterion_id"])]
    for gate in manifest["release_gates"]:
        gate_result = f"Synthetic claim for gate {gate['gate_id']}."
        gate["status"] = "PASS"
        gate["actual_result"] = gate_result
        gate.pop("blocker")
        results.append(
            _criterion_result(
                f"GATE:{gate['gate_id']}",
                actual_result=gate_result,
            )
        )
    evidence = _write_handoff(
        project_root,
        candidate_commit=manifest["candidate"]["source_commit"],
        results=results,
    )
    criterion["evidence"] = [evidence]
    manifest["candidate"]["release_artifacts"] = [evidence]
    for gate in manifest["release_gates"]:
        gate["evidence"] = [evidence]
    _save_manifest(candidate_path, manifest)

    _assert_error(
        map_path,
        project_root,
        candidate_path,
        "MATRIX_USER_APPROVAL_GATE_CANNOT_PASS",
    )
