from __future__ import annotations

import hashlib
import importlib
import io
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

build_coverage_snapshot = importlib.import_module(
    "qa.gauntlet.coverage_refresh"
).build_coverage_snapshot
_coverage_module = importlib.import_module("qa.gauntlet.coverage_refresh")
CoverageRefreshError = _coverage_module.CoverageRefreshError
_InputBudget = _coverage_module._InputBudget  # noqa: SLF001


def _write_map(path: Path, source: str, claims: list[str], owner: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0.0",
                "version": 12,
                "requirements": [
                    {
                        "id": "MAP-1",
                        "source": source,
                        "implementation_target": "src/module.py",
                        "owner": owner,
                        "acceptance_criteria": claims,
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _inputs(tmp_path: Path, source: str, claims: list[str], owner: str) -> dict[str, Any]:
    prd_root = tmp_path / "prd"
    handoffs = tmp_path / "handoffs"
    handoffs.mkdir(exist_ok=True)
    map_path = tmp_path / "REQUIREMENTS_MAP.yaml"
    _write_map(map_path, source, claims, owner)
    integration = tmp_path / "integrations.md"
    integration.write_text("# Empty log\n", encoding="utf-8")
    return cast(
        dict[str, Any],
        build_coverage_snapshot(
            requirements_map_path=map_path,
            prd_root=prd_root,
            integrations_log_path=integration,
            handoffs_root=handoffs,
        ),
    )


def test_explicit_source_anchor_range_controls_mapping_and_contract_provenance(
    tmp_path: Path,
) -> None:
    prd = tmp_path / "prd"
    prd.mkdir()
    overview = prd / "project-overview.md"
    overview.write_text(
        "# Overview\n\n"
        "- First anchored criterion.\n"
        "- Second anchored criterion.\n"
        "- Outside anchor.\n",
        encoding="utf-8",
    )
    report = _inputs(
        tmp_path,
        "prd/project-overview.md#L3-L4",
        ["First anchored criterion."],
        "C-123 owned slice",
    )

    assert [item["source"]["line_start"] for item in report["criteria"]] == [3, 4]
    assert [item["source_text"] for item in report["criteria"]] == [
        "First anchored criterion.",
        "Second anchored criterion.",
    ]
    assert all(item["map_ids"] == ["MAP-1"] for item in report["criteria"])
    assert all(item["contract_ids"] == ["C-123"] for item in report["criteria"])
    assert all(item["evidence_state"] == "CONTRACT_ONLY" for item in report["criteria"])


def test_unanchored_specific_claim_does_not_attach_to_an_unrelated_source_criterion(
    tmp_path: Path,
) -> None:
    prd = tmp_path / "prd"
    source = prd / "PRDs" / "sample.md"
    source.parent.mkdir(parents=True)
    source.write_text(
        "# Sample\n\n## Acceptance Criteria\n\n- A source criterion.\n",
        encoding="utf-8",
    )
    report = _inputs(
        tmp_path,
        "prd/PRDs/sample.md",
        ["A different map assertion."],
        "C-123 owned slice",
    )

    criterion = report["criteria"][0]
    assert criterion["map_ids"] == []
    assert criterion["contract_ids"] == ["NO_CONTRACT"]
    assert criterion["evidence_state"] == "NO_CONTRACT"
    assert report["summary"]["no_contract_count"] == 1


def test_plain_out_of_scope_heading_ends_acceptance_criteria(tmp_path: Path) -> None:
    prd = tmp_path / "prd"
    source = prd / "PRDs" / "sample.md"
    source.parent.mkdir(parents=True)
    source.write_text(
        "# Sample\n\n## Acceptance Criteria\n\n- Included criterion.\n\n"
        "Out of scope\n\n- Excluded statement.\n",
        encoding="utf-8",
    )
    report = _inputs(tmp_path, "prd/PRDs/sample.md", [], "")
    assert [item["source_text"] for item in report["criteria"]] == ["Included criterion."]
    assert report["criteria"][0]["coverage_class"] == "NO_CONTRACT"
    assert report["summary"]["coverage_class_counts"] == {
        "COVERED_CRITERION": 0,
        "CANDIDATE_UMBRELLA_ONLY": 0,
        "NO_CONTRACT": 1,
    }


def test_recursive_input_file_size_limit_fails_with_fixed_code(tmp_path: Path) -> None:
    prd = tmp_path / "prd"
    source = prd / "PRDs" / "sample.md"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    map_path = tmp_path / "REQUIREMENTS_MAP.yaml"
    _write_map(map_path, "prd/PRDs/sample.md", [], "")
    integration = tmp_path / "integrations.md"
    integration.write_text("# Empty\n", encoding="utf-8")
    handoffs = tmp_path / "handoffs"
    handoffs.mkdir()

    try:
        build_coverage_snapshot(
            requirements_map_path=map_path,
            prd_root=prd,
            integrations_log_path=integration,
            handoffs_root=handoffs,
        )
    except CoverageRefreshError as exc:
        assert exc.code == "INPUT_TOO_LARGE"
        assert str(exc) == "INPUT_TOO_LARGE"
    else:
        raise AssertionError("oversized input was accepted")


def test_only_whole_contract_clause_or_explicit_id_can_cover(tmp_path: Path) -> None:
    criterion = "The export preserves its source timestamp."
    prd = tmp_path / "prd"
    source = prd / "PRDs" / "sample.md"
    source.parent.mkdir(parents=True)
    source.write_text(
        "# Sample\n\n## Acceptance Criteria\n\n- " + criterion + "\n",
        encoding="utf-8",
    )
    report = _inputs(
        tmp_path,
        "prd/PRDs/sample.md",
        [criterion],
        "C-123 owned slice",
    )
    assert report["criteria"][0]["coverage_class"] == "CANDIDATE_UMBRELLA_ONLY"

    contract = tmp_path / "architecture" / "proposals" / "C-123-contract.md"
    contract.parent.mkdir(parents=True)
    contract.write_text(
        "# Contract\n\n## Requirement\n\n- " + criterion + "\n",
        encoding="utf-8",
    )
    exact_report = _inputs(
        tmp_path,
        "prd/PRDs/sample.md",
        [criterion],
        "C-123 owned slice",
    )
    exact = exact_report["criteria"][0]
    assert exact["coverage_class"] == "COVERED_CRITERION"
    ref = next(item for item in exact["evidence_refs"] if item["kind"] == "CONTRACT_CLAUSE")
    assert ref["path"] == "architecture/proposals/C-123-contract.md"
    assert ref["line_start"] == 5
    assert ref["line_end"] == 5
    assert ref["sha256"] == hashlib.sha256(contract.read_bytes()).hexdigest()

    contract.write_text(
        "# Contract\n\n## Criterion link\n\n- Criterion ID: " + exact["criterion_id"] + "\n",
        encoding="utf-8",
    )
    id_report = _inputs(
        tmp_path,
        "prd/PRDs/sample.md",
        [criterion],
        "C-123 owned slice",
    )
    id_exact = id_report["criteria"][0]
    assert id_exact["coverage_class"] == "COVERED_CRITERION"
    id_ref = next(item for item in id_exact["evidence_refs"] if item["kind"] == "CONTRACT_CLAUSE")
    assert id_ref["line_start"] == id_ref["line_end"] == 5


def test_growth_after_stat_is_rejected_after_bounded_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "growing-input.txt"
    path.write_bytes(b"0123456789")
    real_stat = Path.stat
    real_open = Path.open
    read_requests: list[int] = []

    def stale_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        stat = real_stat(self, *args, **kwargs)
        if self == path:
            return SimpleNamespace(st_size=2)
        return stat

    class TrackedReader:
        def __init__(self, raw: bytes) -> None:
            self._stream = io.BytesIO(raw)

        def __enter__(self) -> TrackedReader:
            return self

        def __exit__(self, *_args: object) -> None:
            self._stream.close()

        def read(self, size: int = -1) -> bytes:
            read_requests.append(size)
            return self._stream.read(size)

    def growing_open(self, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if self == path and mode == "rb":
            return TrackedReader(b"0123456789")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(_coverage_module, "_MAX_INPUT_FILE_BYTES", 4)
    monkeypatch.setattr(_coverage_module, "_MAX_TOTAL_INPUT_BYTES", 8)
    monkeypatch.setattr(Path, "stat", stale_stat)
    monkeypatch.setattr(Path, "open", growing_open)

    with pytest.raises(CoverageRefreshError) as exc_info:
        _InputBudget().read(path)

    assert exc_info.value.code == "INPUT_TOO_LARGE"
    assert read_requests == [5]
