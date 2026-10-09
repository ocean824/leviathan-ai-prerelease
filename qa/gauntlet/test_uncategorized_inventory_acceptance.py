from __future__ import annotations

import hashlib
import io
from pathlib import Path
from typing import Any

import pytest
import yaml
from uncategorized_inventory import InventoryError, build_inventory


def _write_prd(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def _input_tree(root: Path, *, malformed: bool = False) -> tuple[Path, Path, Path]:
    checkout = root / "checkout"
    source_dir = checkout / ".codespring" / "PRDs" / "uncategorized"
    shared = "[CRIT-REPEAT] The shared criterion remains distinct by source."
    _write_prd(
        source_dir / "alpha.md",
        "# Alpha PRD\n"
        "\n"
        "## Acceptance criteria\n"
        f"- {shared}\n"
        f"- {shared}\n"
        "- Alpha section criterion.\n"
        "\n"
        "## Acceptance Signals (secondary)\n"
        "- The second acceptance section is inventoried.\n"
        "\n"
        "```markdown\n"
        "- This fenced example is ignored.\n"
        "```\n",
    )
    _write_prd(
        source_dir / "beta.md",
        "# Beta PRD\n"
        "\n"
        "Acceptance criteria\n"
        f"- {shared}\n"
        "- [ARCHIVED] Archived criteria remain inventoried.\n",
    )
    _write_prd(
        source_dir / "gamma.md",
        "# Gamma PRD\n\n## Acceptance Criteria\n- Gamma criterion.\n",
    )
    _write_prd(
        source_dir / "delta.md",
        "# Delta PRD\n\n## Acceptance criteria\n- Delta criterion.\n",
    )
    _write_prd(
        source_dir / "epsilon.md",
        "# Epsilon PRD\n\n## Acceptance Signals\n- Epsilon criterion.\n",
    )

    if malformed:
        _write_prd(
            source_dir / "malformed.md",
            "# Malformed PRD\n"
            "\n"
            "## Acceptance criteria\n"
            "- A criterion before an unclosed fence.\n"
            "```markdown\n"
            "- A fenced example is never accepted as a criterion.\n",
        )

    map_path = root / "requirements-map.yaml"
    map_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0.0",
                "version": 1,
                "requirements": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    integrations_log = root / "integrations.md"
    integrations_log.write_text("# Empty synthetic integrations log\n", encoding="utf-8")
    return checkout, map_path, integrations_log


def _build(root: Path, *, malformed: bool = False) -> dict[str, Any]:
    source_root, map_path, integrations_log = _input_tree(
        root,
        malformed=malformed,
    )
    return build_inventory(
        source_root=source_root,
        map_path=map_path,
        integrations_log_path=integrations_log,
        handoff_paths=[],
    )


def _build_inputs(
    source_root: Path,
    map_path: Path,
    integrations_log: Path,
    handoffs: tuple[Path, ...] = (),
) -> dict[str, Any]:
    return build_inventory(
        source_root=source_root,
        map_path=map_path,
        integrations_log_path=integrations_log,
        handoff_paths=handoffs,
    )


def _assert_input_too_large(action: Any) -> None:
    with pytest.raises(InventoryError) as caught:
        action()

    assert caught.value.code == "INPUT_TOO_LARGE"
    assert str(caught.value) == "INPUT_TOO_LARGE"
    assert caught.value.args == ("INPUT_TOO_LARGE",)


def test_inventory_discovers_current_files_and_exact_per_file_counts(
    tmp_path: Path,
) -> None:
    report = _build(tmp_path)

    assert report["summary"]["source_criterion_count"] == 9
    assert report["summary"]["no_contract_count"] == 9
    assert report["summary"]["per_file_criterion_counts"] == [
        {
            "path": f".codespring/PRDs/uncategorized/{name}.md",
            "count": count,
            "coverage_class_counts": {
                "COVERED_CRITERION": 0,
                "CANDIDATE_UMBRELLA_ONLY": 0,
                "NO_CONTRACT": count,
            },
        }
        for name, count in (
            ("alpha", 4),
            ("beta", 2),
            ("delta", 1),
            ("epsilon", 1),
            ("gamma", 1),
        )
    ]
    assert len(report["criteria"]) == 9
    assert all(item["contract_ids"] == ["NO_CONTRACT"] for item in report["criteria"])
    assert all(item["evidence_state"] == "NO_CONTRACT" for item in report["criteria"])
    assert all(item["owners"] == [] for item in report["criteria"])
    assert report["summary"]["unresolved_owners"] == []


def test_repeated_ids_and_duplicate_wording_keep_distinct_source_occurrences(
    tmp_path: Path,
) -> None:
    report = _build(tmp_path)
    shared = [
        item
        for item in report["criteria"]
        if (
            item["source"]["path"] == ".codespring/PRDs/uncategorized/alpha.md"
            and item["source"]["line_start"] in {4, 5}
        )
        or (
            item["source"]["path"] == ".codespring/PRDs/uncategorized/beta.md"
            and item["source"]["line_start"] == 4
        )
    ]

    assert len(shared) == 3
    assert len({item["criterion_id"] for item in shared}) == 3
    assert len({item["source_text_sha256"] for item in shared}) == 1
    assert {(item["source"]["path"], item["source"]["occurrence"]) for item in shared} == {
        (".codespring/PRDs/uncategorized/alpha.md", 1),
        (".codespring/PRDs/uncategorized/alpha.md", 2),
        (".codespring/PRDs/uncategorized/beta.md", 1),
    }


def test_archived_criterion_is_retained_and_fenced_example_is_ignored(
    tmp_path: Path,
) -> None:
    report = _build(tmp_path)
    archived = [
        item
        for item in report["criteria"]
        if item["source"]["path"] == ".codespring/PRDs/uncategorized/beta.md"
        and item["source"]["line_start"] == 5
    ]
    assert len(archived) == 1
    assert archived[0]["source"]["path"] == (".codespring/PRDs/uncategorized/beta.md")
    assert not any(
        item["source"]["path"] == ".codespring/PRDs/uncategorized/alpha.md"
        and item["source"]["line_start"] >= 10
        for item in report["criteria"]
    )


def test_unclosed_fence_fails_closed_without_returning_partial_inventory(
    tmp_path: Path,
) -> None:
    with pytest.raises(InventoryError) as caught:
        _build(tmp_path, malformed=True)

    assert caught.value.code == "MALFORMED_MARKDOWN"
    assert "Malformed PRD" not in str(caught.value)
    assert "fenced example" not in str(caught.value)


def test_unresolved_owner_is_criterion_scoped_and_preserves_literal_owner(
    tmp_path: Path,
) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    map_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0.0",
                "version": 1,
                "requirements": [
                    {
                        "id": "MAP-GAMMA",
                        "requirement": "Gamma criterion.",
                        "source": ".codespring/PRDs/uncategorized/gamma.md",
                        "implementation_target": "src/gamma.py",
                        "owner": "TBD - waiting on explicit assignment",
                        "acceptance_criteria": ["Gamma criterion."],
                        "verification_method": "synthetic fixture",
                        "status": "BLOCKED",
                        "evidence": [],
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    report = build_inventory(
        source_root=source_root,
        map_path=map_path,
        integrations_log_path=integrations_log,
        handoff_paths=[],
    )
    gamma = next(
        item
        for item in report["criteria"]
        if item["source"]["path"] == ".codespring/PRDs/uncategorized/gamma.md"
    )
    assert gamma["owners"] == ["TBD - waiting on explicit assignment"]
    assert report["summary"]["unresolved_owners"] == [
        {
            "criterion_id": gamma["criterion_id"],
            "map_ids": ["MAP-GAMMA"],
            "owners": ["TBD - waiting on explicit assignment"],
        }
    ]


def test_coverage_classes_require_exact_evidence_and_keep_umbrella_as_candidate(
    tmp_path: Path,
) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    project_root = map_path.parent
    (project_root / "repo" / "src").mkdir(parents=True)
    (project_root / "repo" / "src" / "alpha.py").write_text("alpha\n", encoding="utf-8")
    (project_root / "repo" / "src" / "gamma.py").write_text("gamma\n", encoding="utf-8")
    proposal_root = project_root / "architecture" / "proposals"
    _write_prd(proposal_root / "ALPHA-001-contract.md", "Alpha contract has no exact criterion.\n")
    gamma_contract = proposal_root / "GAMMA-001-contract.md"
    gamma_contract.write_text("  GAMMA   criterion.  \n", encoding="utf-8")
    map_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0.0",
                "version": 1,
                "requirements": [
                    {
                        "id": "MAP-ALPHA-AREA",
                        "requirement": "Every current PRD acceptance item in alpha.",
                        "source": "alpha",
                        "implementation_target": "src/alpha.py",
                        "disposition_reason": "AREA UMBRELLA",
                        "acceptance_criteria": ["Every current PRD acceptance item"],
                        "contract_ids": ["ALPHA-001"],
                        "owner": "Alpha team",
                    },
                    {
                        "id": "MAP-GAMMA",
                        "requirement": "Gamma criterion.",
                        "source": ".codespring/PRDs/uncategorized/gamma.md",
                        "implementation_target": "src/gamma.py",
                        "acceptance_criteria": ["Gamma criterion."],
                        "contract_ids": ["GAMMA-001"],
                        "owner": "Gamma team",
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    integrations_log.write_text(
        "# Explicit provenance\n\n## MAP-GAMMA\nStatus: CONTRACT_ONLY\n",
        encoding="utf-8",
    )

    report = _build_inputs(source_root, map_path, integrations_log)
    assert report["schema_version"] == "gauntlet.coverage-snapshot.v2"
    by_path = {
        path: [item for item in report["criteria"] if item["source"]["path"] == path]
        for path in (
            ".codespring/PRDs/uncategorized/alpha.md",
            ".codespring/PRDs/uncategorized/gamma.md",
        )
    }

    assert report["summary"]["coverage_class_counts"] == {
        "COVERED_CRITERION": 1,
        "CANDIDATE_UMBRELLA_ONLY": 4,
        "NO_CONTRACT": 4,
    }
    assert report["summary"]["no_contract_count"] == 4
    assert all(
        item["coverage_class"] == "CANDIDATE_UMBRELLA_ONLY"
        for item in by_path[".codespring/PRDs/uncategorized/alpha.md"]
    )
    assert all(
        item["map_ids"] == ["MAP-ALPHA-AREA"]
        for item in by_path[".codespring/PRDs/uncategorized/alpha.md"]
    )
    assert all(
        item["contract_ids"] == ["ALPHA-001"]
        for item in by_path[".codespring/PRDs/uncategorized/alpha.md"]
    )
    gamma = by_path[".codespring/PRDs/uncategorized/gamma.md"][0]
    assert gamma["coverage_class"] == "COVERED_CRITERION"
    assert gamma["map_ids"] == ["MAP-GAMMA"]
    assert gamma["contract_ids"] == ["GAMMA-001"]
    clause_refs = [
        ref
        for ref in gamma["evidence_refs"]
        if ref["kind"] == "CONTRACT_CLAUSE"
        and ref["path"] == "architecture/proposals/GAMMA-001-contract.md"
    ]
    assert len(clause_refs) == 1
    clause_ref = clause_refs[0]
    assert clause_ref == {
        "path": "architecture/proposals/GAMMA-001-contract.md",
        "sha256": hashlib.sha256(gamma_contract.read_bytes()).hexdigest(),
        "kind": "CONTRACT_CLAUSE",
        "line_start": 1,
        "line_end": 1,
        "observed_status": "STATUS_NOT_STATED",
    }
    contract_lines = gamma_contract.read_text(encoding="utf-8").splitlines()
    assert contract_lines[clause_ref["line_start"] - 1 : clause_ref["line_end"]] == [
        "  GAMMA   criterion.  "
    ]
    per_file = {item["path"]: item for item in report["summary"]["per_file_criterion_counts"]}
    assert per_file[".codespring/PRDs/uncategorized/alpha.md"]["coverage_class_counts"] == {
        "COVERED_CRITERION": 0,
        "CANDIDATE_UMBRELLA_ONLY": 4,
        "NO_CONTRACT": 0,
    }
    assert per_file[".codespring/PRDs/uncategorized/gamma.md"]["coverage_class_counts"] == {
        "COVERED_CRITERION": 1,
        "CANDIDATE_UMBRELLA_ONLY": 0,
        "NO_CONTRACT": 0,
    }


def test_contract_substring_and_integration_id_do_not_establish_coverage(
    tmp_path: Path,
) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    project_root = map_path.parent
    (project_root / "repo" / "src").mkdir(parents=True)
    (project_root / "repo" / "src" / "gamma.py").write_text("gamma\n", encoding="utf-8")
    proposal_root = project_root / "architecture" / "proposals"
    _write_prd(
        proposal_root / "GAMMA-001-contract.md",
        "An unrelated workflow mentions Gamma criterion. as an example, not a requirement.\n",
    )
    map_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0.0",
                "version": 1,
                "requirements": [
                    {
                        "id": "MAP-GAMMA",
                        "requirement": "Gamma criterion.",
                        "source": ".codespring/PRDs/uncategorized/gamma.md",
                        "implementation_target": "src/gamma.py",
                        "acceptance_criteria": ["Gamma criterion."],
                        "contract_ids": ["GAMMA-001"],
                        "owner": "Gamma team",
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    integrations_log.write_text(
        "# Integration evidence\n\n## MAP-GAMMA\nStatus: INTEGRATION_RECORDED\n",
        encoding="utf-8",
    )

    report = _build_inputs(source_root, map_path, integrations_log)
    gamma = next(
        item
        for item in report["criteria"]
        if item["source"]["path"] == ".codespring/PRDs/uncategorized/gamma.md"
    )

    assert gamma["coverage_class"] in {
        "CANDIDATE_UMBRELLA_ONLY",
        "NO_CONTRACT",
    }
    assert gamma["coverage_class"] != "COVERED_CRITERION"
    assert gamma["map_ids"] == ["MAP-GAMMA"]
    assert gamma["contract_ids"] == ["GAMMA-001"]


def test_out_of_scope_constraints_count_only_leaf_items(tmp_path: Path) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    alpha = source_root / ".codespring" / "PRDs" / "uncategorized" / "alpha.md"
    alpha.write_text(
        alpha.read_text(encoding="utf-8")
        + "\n## Key Behaviors & Constraints\n"
        + "- Parent category\n"
        + "  - Nested constraint one.\n"
        + "  - Nested constraint two.\n"
        + "- Standalone constraint.\n"
        + "## Constraints\n"
        + "- Another constraint.\n",
        encoding="utf-8",
    )

    report = _build_inputs(source_root, map_path, integrations_log)

    constraints = report["out_of_scope_constraints"]
    assert [item["source_text_sha256"] for item in constraints]
    assert len(constraints) == 4
    assert all(item["classification"] == "OUT_OF_SCOPE_CONSTRAINT" for item in constraints)
    assert report["summary"]["out_of_scope_constraint_count"] == 4
    assert [
        item["count"]
        for item in report["summary"]["per_file_out_of_scope_constraint_counts"]
        if item["path"] == ".codespring/PRDs/uncategorized/alpha.md"
    ] == [4]
    assert not any("Parent category" in item.get("source_text", "") for item in constraints)


@pytest.mark.parametrize("file_count", [512, 513])
def test_markdown_discovery_limit_accepts_max_and_rejects_max_plus_one(
    tmp_path: Path,
    file_count: int,
) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    source_dir = source_root / ".codespring" / "PRDs" / "uncategorized"
    for index in range(file_count - 5):
        _write_prd(
            source_dir / f"extra-{index:04d}.md",
            "# Extra\n## Acceptance criteria\n- Extra criterion.\n",
        )

    if file_count > 512:
        _assert_input_too_large(lambda: _build_inputs(source_root, map_path, integrations_log))
    else:
        report = _build_inputs(source_root, map_path, integrations_log)
        assert len(report["summary"]["per_file_criterion_counts"]) == 512


def test_walk_directory_limit_is_enforced(tmp_path: Path) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    source_dir = source_root / ".codespring" / "PRDs" / "uncategorized"
    for index in range(4096):
        (source_dir / f"directory-{index:04d}").mkdir()

    _assert_input_too_large(lambda: _build_inputs(source_root, map_path, integrations_log))


def test_walk_file_entry_limit_is_enforced(tmp_path: Path) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    source_dir = source_root / ".codespring" / "PRDs" / "uncategorized"
    for index in range(8188):
        (source_dir / f"entry-{index:04d}.bin").write_bytes(b"x")

    _assert_input_too_large(lambda: _build_inputs(source_root, map_path, integrations_log))


def test_per_input_byte_limit_is_enforced(tmp_path: Path) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    oversized_handoff = tmp_path / "oversized-handoff.md"
    oversized_handoff.write_bytes(b"x" * (2 * 1024 * 1024 + 1))

    _assert_input_too_large(
        lambda: _build_inputs(source_root, map_path, integrations_log, (oversized_handoff,))
    )


def test_aggregate_byte_limit_is_enforced(tmp_path: Path) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    handoffs = tuple(tmp_path / f"handoff-{index}.md" for index in range(8))
    for handoff in handoffs:
        handoff.write_bytes(b"x" * (2 * 1024 * 1024))

    _assert_input_too_large(
        lambda: _build_inputs(source_root, map_path, integrations_log, handoffs)
    )


def test_map_row_limit_accepts_max_and_rejects_max_plus_one(tmp_path: Path) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    source_dir = source_root / ".codespring" / "PRDs" / "uncategorized"
    for name in ("beta.md", "gamma.md", "delta.md", "epsilon.md"):
        (source_dir / name).unlink()

    def write_rows(row_count: int) -> None:
        rows = ", ".join("{id: ROW}" for _ in range(row_count))
        map_path.write_text(
            "schema_version: '1.0.0'\nversion: 1\nrequirements: [" + rows + "]\n",
            encoding="utf-8",
        )

    write_rows(50_000)
    report = _build_inputs(source_root, map_path, integrations_log)
    assert report["summary"]["source_criterion_count"] == 4

    write_rows(50_001)
    _assert_input_too_large(lambda: _build_inputs(source_root, map_path, integrations_log))


def test_map_nesting_limit_is_enforced(tmp_path: Path) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    root_row: dict[str, Any] = {"id": "DEPTH-0"}
    current = root_row
    for depth in range(65):
        child: dict[str, Any] = {"id": f"DEPTH-{depth + 1}"}
        current["children"] = [child]
        current = child
    map_path.write_text(
        yaml.safe_dump(
            {"schema_version": "1.0.0", "version": 1, "requirements": [root_row]},
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    _assert_input_too_large(lambda: _build_inputs(source_root, map_path, integrations_log))


def test_read_growth_after_stat_is_still_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root, map_path, integrations_log = _input_tree(tmp_path)
    growing_handoff = tmp_path / "growing-handoff.md"
    growing_handoff.write_text("small before open", encoding="utf-8")
    original_open = Path.open

    def grow_on_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == growing_handoff:
            return io.BytesIO(b"x" * (2 * 1024 * 1024 + 1))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", grow_on_open)
    _assert_input_too_large(
        lambda: _build_inputs(source_root, map_path, integrations_log, (growing_handoff,))
    )
