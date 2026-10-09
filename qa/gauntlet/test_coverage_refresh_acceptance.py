from __future__ import annotations

import hashlib
import importlib
import io
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

coverage_refresh = importlib.import_module("qa.gauntlet.coverage_refresh")
build_coverage_snapshot = coverage_refresh.build_coverage_snapshot
render_coverage_snapshot = coverage_refresh.render_coverage_snapshot
main = coverage_refresh.main
CoverageRefreshError = coverage_refresh.CoverageRefreshError


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _row(
    row_id: str,
    criterion: str,
    target: str,
    *,
    owner: str = "synthetic-acceptance-owner",
) -> dict[str, object]:
    return {
        "id": row_id,
        "requirement": criterion,
        "source": "PRDs/example.md",
        "implementation_target": target,
        "owner": owner,
        "acceptance_criteria": [criterion],
        "verification_method": "synthetic acceptance fixture",
        "status": "BLOCKED",
        "evidence": [],
    }


def _inputs(
    root: Path,
) -> tuple[Path, Path, Path, Path]:
    prd_root = root / "prd"
    source = prd_root / "PRDs" / "example.md"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "# Example PRD\n"
        "\n"
        "## Acceptance Criteria\n"
        "\n"
        "- Omitted source criterion remains visible.\n"
        "- Duplicate criterion is claimed twice.\n"
        "- Renamed criterion is present in the source.\n"
        "- Covered criterion has explicit acceptance and integration evidence.\n"
        "- Contract-only criterion has no acceptance verdict.\n"
        "\n"
        "## Out of Scope\n"
        "- Out-of-scope item must not be counted as acceptance coverage.\n",
        encoding="utf-8",
    )

    requirements_map = root / "requirements-map.yaml"
    _write_yaml(
        requirements_map,
        {
            "schema_version": "1.0.0",
            "version": 12,
            "requirements": [
                _row(
                    "MAP-DUP-A",
                    "Duplicate criterion is claimed twice.",
                    "src/duplicate.py",
                ),
                _row(
                    "MAP-DUP-B",
                    "Duplicate criterion is claimed twice.",
                    "src/duplicate.py",
                ),
                _row(
                    "LEV-REQ-0199",
                    "Old criterion text before source rename.",
                    "src/renamed.py",
                ),
                _row(
                    "MAP-COVERED",
                    "Covered criterion has explicit acceptance and integration evidence.",
                    "src/covered.py",
                    owner="synthetic-acceptance-owner CONTRACT-101",
                ),
                _row(
                    "MAP-CONTRACT-ONLY",
                    "Contract-only criterion has no acceptance verdict.",
                    "src/contract-only.py",
                    owner="synthetic-acceptance-owner CONTRACT-102",
                ),
            ],
        },
    )

    integrations = root / "integrations.md"
    integrations.write_text(
        "# Synthetic integration evidence\n"
        "\n"
        "Contract ID: CONTRACT-101\n"
        "Target path: src/covered.py\n"
        "Status: INTEGRATED\n"
        "Verdict: PASS\n"
        "Covered criterion has explicit acceptance and integration evidence.\n"
        "\n"
        "Contract ID: CONTRACT-102\n"
        "Target path: src/contract-only.py\n"
        "Status: CONTRACT_ONLY\n"
        "\n"
        "Unresolved reference: REQ-9999\n",
        encoding="utf-8",
    )

    handoffs = root / "handoffs"
    handoffs.mkdir()
    (handoffs / "covered.md").write_text(
        "# Synthetic acceptance handoff\n"
        "\n"
        "Contract ID: CONTRACT-101\n"
        "Target path: src/covered.py\n"
        "Status: ACCEPTANCE_RECORDED\n"
        "Verdict: PASS\n"
        "Covered criterion has explicit acceptance and integration evidence.\n",
        encoding="utf-8",
    )
    return requirements_map, prd_root, integrations, handoffs


def _report(root: Path) -> dict[str, Any]:
    requirements_map, prd_root, integrations, handoffs = _inputs(root)
    return build_coverage_snapshot(
        requirements_map_path=requirements_map,
        prd_root=prd_root,
        integrations_log_path=integrations,
        handoffs_root=handoffs,
    )


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _criterion_at_line(report: dict[str, Any], line_number: int) -> dict[str, Any]:
    return next(item for item in report["criteria"] if item["source"]["line_start"] == line_number)


def _assert_input_too_large(action: Callable[[], object]) -> None:
    try:
        action()
    except CoverageRefreshError as exc:
        assert exc.code == "INPUT_TOO_LARGE"
        assert str(exc) == "INPUT_TOO_LARGE"
        assert exc.args == ("INPUT_TOO_LARGE",)
    else:
        raise AssertionError("expected content-free INPUT_TOO_LARGE")


def test_refresh_preserves_omitted_criteria_and_flags_duplicate_and_renamed_claims(
    tmp_path: Path,
) -> None:
    report = _report(tmp_path)

    assert report["schema_version"] == "gauntlet.coverage-snapshot.v1"
    criteria = report["criteria"]
    assert len(criteria) == 5
    assert report["summary"]["source_criterion_count"] == 5

    omitted = _criterion_at_line(report, 5)
    assert omitted["source_text"] == "Omitted source criterion remains visible."
    assert (
        omitted["source_text_sha256"]
        == hashlib.sha256(b"Omitted source criterion remains visible.").hexdigest()
    )
    assert omitted["contract_ids"] == ["NO_CONTRACT"]
    assert omitted["evidence_state"] == "NO_CONTRACT"
    assert omitted["evidence_refs"] == []
    renamed = _criterion_at_line(report, 7)
    assert renamed["source_text"] == "Renamed criterion is present in the source."
    assert (
        renamed["source_text_sha256"]
        == hashlib.sha256(b"Renamed criterion is present in the source.").hexdigest()
    )
    assert renamed["map_ids"] == []

    findings = {finding["code"] for finding in report["findings"]}
    assert "SOURCE_WITHOUT_MAP" in findings
    assert "DUPLICATE_CLAIM" in findings
    assert "STALE_MAP_ID" in findings
    stale = next(finding for finding in report["findings"] if finding["code"] == "STALE_MAP_ID")
    assert stale["map_ids"] == ["REQ-9999"]
    assert report["summary"]["stale_map_id_count"] == 1

    duplicate = _criterion_at_line(report, 6)
    assert duplicate["source_text"] == "Duplicate criterion is claimed twice."
    assert duplicate["map_ids"] == ["MAP-DUP-A", "MAP-DUP-B"]
    assert duplicate["owners"] == ["synthetic-acceptance-owner"]
    assert duplicate["contract_ids"] == ["NO_CONTRACT"]
    assert duplicate["evidence_state"] == "NO_CONTRACT"
    assert duplicate["evidence_refs"] == []


def test_evidence_states_are_provenance_only_and_do_not_infer_pass_from_contract(
    tmp_path: Path,
) -> None:
    report = _report(tmp_path)
    covered = _criterion_at_line(report, 8)
    assert covered["source_text"] == (
        "Covered criterion has explicit acceptance and integration evidence."
    )
    assert covered["contract_ids"] == ["CONTRACT-101"]
    assert covered["target_paths"] == ["src/covered.py"]
    assert covered["owners"] == ["synthetic-acceptance-owner CONTRACT-101"]
    assert covered["coverage_class"] == "CANDIDATE_UMBRELLA_ONLY"
    assert covered["evidence_state"] == "ACCEPTANCE_AND_INTEGRATION_RECORDED"
    evidence_by_kind = {
        entry["kind"]: entry["observed_status"] for entry in covered["evidence_refs"]
    }
    assert set(evidence_by_kind) == {"INTEGRATION_LOG", "HANDOFF"}
    assert evidence_by_kind["INTEGRATION_LOG"] in {"INTEGRATED", "PASS"}
    assert evidence_by_kind["HANDOFF"] in {"ACCEPTANCE_RECORDED", "PASS"}
    assert all(
        set(entry) == {"path", "sha256", "kind", "observed_status"}
        for entry in covered["evidence_refs"]
    )

    contract_only = _criterion_at_line(report, 9)
    assert contract_only["source_text"] == ("Contract-only criterion has no acceptance verdict.")
    assert contract_only["contract_ids"] == ["CONTRACT-102"]
    assert contract_only["evidence_state"] == "CONTRACT_ONLY"
    assert contract_only["evidence_refs"]
    assert contract_only["evidence_refs"] == [
        {
            "path": "integrations.md",
            "sha256": hashlib.sha256((tmp_path / "integrations.md").read_bytes()).hexdigest(),
            "kind": "INTEGRATION_LOG",
            "observed_status": "CONTRACT_ONLY",
        }
    ]
    assert report["summary"]["no_contract_count"] == 3
    assert report["summary"]["unresolved_owners"] == []


def test_exact_contract_clause_reference_is_the_coverage_evidence(
    tmp_path: Path,
) -> None:
    requirements_map, prd_root, integrations, handoffs = _inputs(tmp_path)
    contract_path = tmp_path / "architecture" / "proposals" / "CONTRACT-101-terms.md"
    contract_path.parent.mkdir(parents=True)
    contract_path.write_text(
        "  COVERED   CRITERION HAS EXPLICIT ACCEPTANCE AND INTEGRATION EVIDENCE.  \n",
        encoding="utf-8",
    )

    report = build_coverage_snapshot(
        requirements_map_path=requirements_map,
        prd_root=prd_root,
        integrations_log_path=integrations,
        handoffs_root=handoffs,
    )
    covered = _criterion_at_line(report, 8)
    contract_refs = [ref for ref in covered["evidence_refs"] if ref["kind"] == "CONTRACT_CLAUSE"]

    assert covered["coverage_class"] == "COVERED_CRITERION"
    assert len(contract_refs) == 1
    contract_ref = contract_refs[0]
    assert contract_ref == {
        "path": "architecture/proposals/CONTRACT-101-terms.md",
        "sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        "kind": "CONTRACT_CLAUSE",
        "line_start": 1,
        "line_end": 1,
        "observed_status": "STATUS_NOT_STATED",
    }
    contract_lines = contract_path.read_text(encoding="utf-8").splitlines()
    assert contract_lines[contract_ref["line_start"] - 1 : contract_ref["line_end"]] == [
        "  COVERED   CRITERION HAS EXPLICIT ACCEPTANCE AND INTEGRATION EVIDENCE.  "
    ]


@pytest.mark.parametrize("embedded_source", ("integration", "handoff"))
def test_embedded_provenance_text_is_not_contract_clause_coverage(
    tmp_path: Path,
    embedded_source: str,
) -> None:
    requirements_map, prd_root, integrations, handoffs = _inputs(tmp_path)
    embedded = (
        "A broader, unrelated process mentions Covered criterion has explicit acceptance and "
        "integration evidence. while describing a separate workflow."
    )
    exact_criterion = "Covered criterion has explicit acceptance and integration evidence.\n"
    if embedded_source == "integration":
        integration_text = integrations.read_text(encoding="utf-8")
        integrations.write_text(
            integration_text.replace(exact_criterion, embedded + "\n"),
            encoding="utf-8",
        )
        handoff = handoffs / "covered.md"
        handoff_text = handoff.read_text(encoding="utf-8")
        handoff.write_text(handoff_text.replace(exact_criterion, ""), encoding="utf-8")
    else:
        integrations.write_text(
            integrations.read_text(encoding="utf-8").replace(exact_criterion, ""),
            encoding="utf-8",
        )
        handoff = handoffs / "covered.md"
        handoff_text = handoff.read_text(encoding="utf-8")
        handoff.write_text(
            handoff_text.replace(exact_criterion, embedded + "\n"),
            encoding="utf-8",
        )

    report = build_coverage_snapshot(
        requirements_map_path=requirements_map,
        prd_root=prd_root,
        integrations_log_path=integrations,
        handoffs_root=handoffs,
    )
    criterion = _criterion_at_line(report, 8)

    assert criterion["coverage_class"] == "CANDIDATE_UMBRELLA_ONLY"
    assert criterion["coverage_class"] != "COVERED_CRITERION"
    assert not any(ref["kind"] == "CONTRACT_CLAUSE" for ref in criterion["evidence_refs"])
    expected_provenance_kind = "INTEGRATION_LOG" if embedded_source == "integration" else "HANDOFF"
    assert expected_provenance_kind in {ref["kind"] for ref in criterion["evidence_refs"]}


def test_out_of_scope_section_is_excluded_from_source_criterion_totals(
    tmp_path: Path,
) -> None:
    report = _report(tmp_path)

    assert report["summary"]["source_criterion_count"] == 5
    assert not any(
        criterion["source_text"] == "Out-of-scope item must not be counted as acceptance coverage."
        for criterion in report["criteria"]
    )


def test_coverage_classes_and_umbrella_only_ids_are_counted_separately(
    tmp_path: Path,
) -> None:
    requirements_map, prd_root, integrations, handoffs = _inputs(tmp_path)
    project_map = yaml.safe_load(requirements_map.read_text(encoding="utf-8"))
    umbrella = _row(
        "LEV-REQ-0900",
        "Every current PRD acceptance item in this area.",
        "src/umbrella.py",
        owner="synthetic-acceptance-owner CONTRACT-103",
    )
    umbrella["source"] = "PRDs/example.md"
    umbrella["disposition_reason"] = "AREA UMBRELLA"
    project_map["requirements"].append(umbrella)
    _write_yaml(requirements_map, project_map)
    (integrations).write_text(
        integrations.read_text(encoding="utf-8")
        + "\nContract ID: CONTRACT-103\n"
        + "Target path: src/umbrella.py\n"
        + "Status: CONTRACT_ONLY\n",
        encoding="utf-8",
    )
    unmatched_source = prd_root / "PRDs" / "unmapped.md"
    unmatched_source.write_text(
        "# Unmapped PRD\n## Acceptance Criteria\n- Truly unmapped criterion.\n",
        encoding="utf-8",
    )

    report = build_coverage_snapshot(
        requirements_map_path=requirements_map,
        prd_root=prd_root,
        integrations_log_path=integrations,
        handoffs_root=handoffs,
    )

    assert report["summary"]["coverage_class_counts"] == {
        "COVERED_CRITERION": 0,
        "CANDIDATE_UMBRELLA_ONLY": 5,
        "NO_CONTRACT": 1,
    }
    assert report["summary"]["source_criterion_count"] == 6
    assert report["summary"]["no_contract_count"] == 1
    assert report["summary"]["umbrella_only_map_id_count"] == 1
    covered = _criterion_at_line(report, 8)
    assert covered["coverage_class"] == "CANDIDATE_UMBRELLA_ONLY"
    umbrella_only = [
        criterion
        for criterion in report["criteria"]
        if criterion["source"]["path"] == "PRDs/example.md"
        and criterion["coverage_class"] == "CANDIDATE_UMBRELLA_ONLY"
    ]
    assert len(umbrella_only) == 5
    assert all("LEV-REQ-0900" in item["map_ids"] for item in umbrella_only)
    assert all("CONTRACT-103" in item["contract_ids"] for item in umbrella_only)
    unmapped = next(
        criterion
        for criterion in report["criteria"]
        if criterion["source"]["path"] == "PRDs/unmapped.md"
    )
    assert unmapped["coverage_class"] == "NO_CONTRACT"
    assert unmapped["contract_ids"] == ["NO_CONTRACT"]


def test_criterion_identity_uses_full_stable_source_anchor_digest(tmp_path: Path) -> None:
    report = _report(tmp_path)
    criterion = _criterion_at_line(report, 8)
    source = criterion["source"]
    assert criterion["source_text"] == (
        "Covered criterion has explicit acceptance and integration evidence."
    )
    assert source["path"] == "PRDs/example.md"
    assert source["line_start"] == 8
    assert source["line_end"] == 8
    assert source["section_path"] == ["Example PRD", "Acceptance Criteria"]
    assert source["occurrence"] == 1

    canonical = (
        f"{source['path']}\n"
        f"{'/'.join(source['section_path'])}\n"
        f"{source['occurrence']}\n"
        f"{_normalize(criterion['source_text'])}"
    )
    expected = "CRIT-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert criterion["criterion_id"] == expected
    assert (
        criterion["source_text_sha256"]
        == hashlib.sha256(
            b"Covered criterion has explicit acceptance and integration evidence."
        ).hexdigest()
    )
    assert re.fullmatch(r"CRIT-[0-9a-f]{64}", criterion["criterion_id"])


def test_render_and_cli_are_deterministic_and_write_only_to_explicit_output(
    tmp_path: Path,
    capsys: Any,
) -> None:
    requirements_map, prd_root, integrations, handoffs = _inputs(tmp_path)
    args = [
        "--requirements-map",
        str(requirements_map),
        "--prd-root",
        str(prd_root),
        "--integrations-log",
        str(integrations),
        "--handoffs-root",
        str(handoffs),
    ]

    report = build_coverage_snapshot(
        requirements_map_path=requirements_map,
        prd_root=prd_root,
        integrations_log_path=integrations,
        handoffs_root=handoffs,
    )
    first = render_coverage_snapshot(report)
    second = render_coverage_snapshot(report)
    assert first == second
    assert first.endswith("\n")
    assert json.loads(first) == report
    assert "generated_at" not in report
    assert "timestamp" not in report

    assert main(args) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == report
    assert captured.err == ""

    output = tmp_path / "explicit-report.json"
    assert main([*args, "--output", str(output)]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert output.read_text(encoding="utf-8") == first


def test_bounded_recursive_prd_walk_rejects_directory_limit_plus_one(
    tmp_path: Path,
) -> None:
    requirements_map, prd_root, integrations, handoffs = _inputs(tmp_path)
    nested = prd_root / "PRDs" / "nested"
    nested.mkdir()
    for index in range(4094):
        (nested / f"directory-{index:04d}").mkdir()

    _assert_input_too_large(
        lambda: build_coverage_snapshot(
            requirements_map_path=requirements_map,
            prd_root=prd_root,
            integrations_log_path=integrations,
            handoffs_root=handoffs,
        )
    )


def test_bounded_recursive_handoff_walk_rejects_file_limit_plus_one(
    tmp_path: Path,
) -> None:
    requirements_map, prd_root, integrations, handoffs = _inputs(tmp_path)
    for index in range(8192):
        (handoffs / f"entry-{index:04d}.bin").write_bytes(b"")

    _assert_input_too_large(
        lambda: build_coverage_snapshot(
            requirements_map_path=requirements_map,
            prd_root=prd_root,
            integrations_log_path=integrations,
            handoffs_root=handoffs,
        )
    )


def test_input_byte_limit_rejects_file_limit_plus_one(tmp_path: Path) -> None:
    requirements_map, prd_root, integrations, handoffs = _inputs(tmp_path)
    (prd_root / "oversized.md").write_bytes(b"x" * (4 * 1024 * 1024 + 1))

    _assert_input_too_large(
        lambda: build_coverage_snapshot(
            requirements_map_path=requirements_map,
            prd_root=prd_root,
            integrations_log_path=integrations,
            handoffs_root=handoffs,
        )
    )


def test_read_growth_after_stat_is_rejected_with_content_free_limit_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requirements_map, prd_root, integrations, handoffs = _inputs(tmp_path)
    growing_handoff = handoffs / "growing.md"
    growing_handoff.write_text("small before open\n", encoding="utf-8")
    original_open = Path.open

    def grow_on_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == growing_handoff.resolve():
            return io.BytesIO(b"x" * (4 * 1024 * 1024 + 1))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", grow_on_open)
    _assert_input_too_large(
        lambda: build_coverage_snapshot(
            requirements_map_path=requirements_map,
            prd_root=prd_root,
            integrations_log_path=integrations,
            handoffs_root=handoffs,
        )
    )


def test_map_row_limit_rejects_one_row_above_bound(tmp_path: Path) -> None:
    requirements_map, prd_root, integrations, handoffs = _inputs(tmp_path)
    rows = ", ".join("{}" for _ in range(50_001))
    requirements_map.write_text(
        "version: 12\nrequirements: [" + rows + "]\n",
        encoding="utf-8",
    )

    _assert_input_too_large(
        lambda: build_coverage_snapshot(
            requirements_map_path=requirements_map,
            prd_root=prd_root,
            integrations_log_path=integrations,
            handoffs_root=handoffs,
        )
    )
