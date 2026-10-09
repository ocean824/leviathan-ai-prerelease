"""Fail-closed validator for the GAUNTLET-001 candidate evidence matrix.

Validation proves only that a manifest is complete and its referenced evidence
matches its hashes. It never certifies a release candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - dependency is part of the workspace
    raise RuntimeError("PyYAML is required to read the canonical Requirements Map") from exc


class MatrixValidationError(Exception):
    """Content-free typed validation failure suitable for CLI and API callers."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


REQUIRED_RELEASE_GATES = frozenset(
    {
        "FROZEN_CANDIDATE_EVIDENCE",
        "FULL_PRD_CRITERION_AUDIT",
        "INDEPENDENT_REVIEW",
        "PERF-001",
        "MD-008",
        "RISK-003_USER_LIMITS",
        "LIVE_BROKER_CREDENTIALS",
        "PROVIDER_LICENSES",
        "SIGNING_CERTIFICATE",
        "CLOUD_APPLY",
        "INSTALLED_WINDOWS_BINARY",
        "USER_RELEASE_APPROVAL",
    }
)
BLOCKER_KINDS = frozenset(
    {
        "USER_INPUT_REQUIRED",
        "CREDENTIAL_REQUIRED",
        "LICENSE_REQUIRED",
        "CERTIFICATE_REQUIRED",
        "CLOUD_APPLY_REQUIRED",
        "EXTERNAL_TERMINAL_REQUIRED",
        "SOURCE_UNAVAILABLE",
        "INTEGRATION_PENDING",
        "PRD_UNMAPPED",
    }
)
_GATE_BLOCKER_KIND = {
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

_STATUSES = frozenset(
    {"PASS", "FAIL", "PARTIAL", "BLOCKED", "NOT_TESTED", "NOT_APPLICABLE", "REMOVED_BY_USER"}
)
_EVIDENCE_STATUSES = frozenset({"PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE", "REMOVED_BY_USER"})
_GATED_STATUSES = frozenset(
    {"BLOCKED", "NOT_TESTED", "PARTIAL", "NOT_APPLICABLE", "REMOVED_BY_USER"}
)
_TEST_TYPES = frozenset(
    {
        "static",
        "unit",
        "component",
        "integration",
        "contract",
        "end_to_end",
        "system",
        "ux",
        "accessibility",
        "security",
        "compliance",
        "data",
        "performance",
        "load",
        "soak",
        "failure",
        "recovery",
        "compatibility",
        "regression",
        "release",
    }
)
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_HEX_160 = re.compile(r"^[0-9a-f]{40}$")
_SOURCE_HEADING = re.compile(r"^\s*(#{1,6})\s+(.+?)\s*#*\s*$")
_SOURCE_PLAIN_HEADING = re.compile(
    r"^\s*(?:acceptance(?: criteria| signals| & edge cases)?|"
    r"edge cases & acceptance(?: criteria)?|success criteria|definition of done)"
    r"(?:\s*\([^)]*\))?\s*:?\s*$",
    re.IGNORECASE,
)
_SOURCE_LIST_ITEM = re.compile(r"^(\s*)(?:[-*+]\s+|\d+[.)]\s+)(.*\S)?\s*$")
_SOURCE_MAP_ANCHOR = re.compile(r"#L(\d+)(?:-L?(\d+))?$", re.IGNORECASE)
_SOURCE_FENCE = re.compile(r"^\s*(?:`{3,}|~{3,})")
_GATE_ID_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _fail(code: str) -> None:
    raise MatrixValidationError(code)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resolve_source_reference(source_base: Path, source: str) -> tuple[Path, bool] | None:
    normalized = source.replace("\\", "/")
    anchor = _SOURCE_MAP_ANCHOR.search(normalized)
    clean = normalized.split("#", 1)[0]
    is_directory = clean.endswith("/")
    if not clean or clean.startswith("/") or re.match(r"^[A-Za-z]:", clean) or "\x00" in clean:
        _fail("SOURCE_REFERENCE_INVALID")
    try:
        base = source_base.resolve(strict=True)
        boundary = base.parent.resolve(strict=True)
        candidate = Path(os.path.abspath(base / clean.rstrip("/")))
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(boundary)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        _fail("SOURCE_REFERENCE_INVALID")
    cursor = candidate
    while cursor != boundary:
        if cursor.is_symlink():
            _fail("SOURCE_REFERENCE_INVALID")
        parent = cursor.parent
        if parent == cursor:
            _fail("SOURCE_REFERENCE_INVALID")
        cursor = parent
    if is_directory or resolved.is_dir():
        if not resolved.is_dir():
            return None
        try:
            markdown_files = [path for path in resolved.rglob("*.md") if path.is_file()]
        except OSError:
            _fail("SOURCE_REFERENCE_INVALID")
        if any(path.is_symlink() for path in resolved.rglob("*")):
            _fail("SOURCE_REFERENCE_INVALID")
        return (resolved, True) if markdown_files else None
    if not resolved.is_file():
        return None
    if anchor is not None:
        try:
            line_count = len(resolved.read_text(encoding="utf-8").splitlines())
        except (OSError, UnicodeError):
            return None
        if int(anchor.group(2) or anchor.group(1)) > line_count:
            return None
    return resolved, False


def _source_reference_available(source_base: Path, source: str) -> bool:
    return _resolve_source_reference(source_base, source) is not None


def _unavailable_source_gate_id(source: str) -> str:
    return f"SOURCE_UNAVAILABLE:{_sha256(source.encode('utf-8'))[:16]}"


def _expected_unavailable_sources(
    source_base: Path, canonical_rows: list[dict[str, Any]]
) -> dict[str, str]:
    unique_sources = sorted(
        {row["source"] for row in canonical_rows if isinstance(row.get("source"), str)}
    )
    return {
        _unavailable_source_gate_id(source): source
        for source in unique_sources
        if not _source_reference_available(source_base, source)
    }


def _referenced_markdown_files(
    source_base: Path, canonical_rows: list[dict[str, Any]]
) -> dict[Path, set[str]]:
    mapped: dict[Path, set[str]] = {}
    for prd_root in _discover_prd_roots(source_base, canonical_rows):
        try:
            paths = list(prd_root.rglob("*.md"))
        except OSError:
            _fail("SOURCE_INVENTORY_INVALID")
        if any(path.is_symlink() for path in prd_root.rglob("*")):
            _fail("SOURCE_INVENTORY_INVALID")
        for path in paths:
            if path.is_file():
                mapped.setdefault(path.resolve(strict=True), set())
    for row in canonical_rows:
        requirement_id = row.get("id")
        source = row.get("source")
        if not isinstance(requirement_id, str) or not isinstance(source, str):
            _fail("REQUIREMENTS_MAP_INVALID")
        resolved_source = _resolve_source_reference(source_base, source)
        if resolved_source is None:
            continue
        path, is_directory = resolved_source
        if is_directory:
            files = [item for item in path.rglob("*.md") if item.is_file()]
            if any(item.is_symlink() for item in path.rglob("*")):
                _fail("SOURCE_INVENTORY_INVALID")
        elif path.suffix.lower() == ".md":
            files = [path]
        else:
            files = []
        for markdown_path in files:
            mapped.setdefault(markdown_path, set()).add(requirement_id)
    return mapped


def _discover_prd_roots(source_base: Path, canonical_rows: list[dict[str, Any]]) -> set[Path]:
    roots: set[Path] = set()
    for row in canonical_rows:
        source = row.get("source")
        if not isinstance(source, str):
            _fail("REQUIREMENTS_MAP_INVALID")
        resolved_source = _resolve_source_reference(source_base, source)
        if resolved_source is None:
            continue
        path, _is_directory = resolved_source
        for candidate in (path, *path.parents):
            if (
                candidate.name.casefold() == "prds"
                and candidate.parent.name.casefold() == ".codespring"
            ):
                roots.add(candidate.resolve(strict=True))
                break
    return roots


def source_inventory_sha256(
    source_root: Path, canonical_rows: list[dict[str, Any]] | None = None
) -> str:
    """Hash the full discovered CodeSpring PRD tree and all referenced Markdown files."""
    if canonical_rows is None:
        _map_bytes, canonical_rows = _load_requirements(source_root / "REQUIREMENTS_MAP.yaml")
    try:
        base = source_root.resolve(strict=True)
    except OSError:
        _fail("SOURCE_INVENTORY_INVALID")
    files = _referenced_markdown_files(base, canonical_rows)
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: os.path.relpath(item, base).replace("\\", "/")):
        relative = os.path.relpath(path, base).replace("\\", "/")
        encoded = relative.encode("utf-8")
        try:
            raw = path.read_bytes()
        except OSError:
            _fail("SOURCE_INVENTORY_INVALID")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _is_acceptance_heading(line: str) -> tuple[int, bool] | None:
    heading = _SOURCE_HEADING.match(line)
    if heading is not None and re.search(
        r"acceptance|success criteria|definition of done", heading.group(2), re.IGNORECASE
    ):
        return len(heading.group(1)), True
    if _SOURCE_PLAIN_HEADING.match(line):
        return 6, False
    return None


def _make_source_item(
    relative: str, line_number: int | None, parts: list[str]
) -> dict[str, Any] | None:
    if line_number is None:
        return None
    text_value = " ".join(part.strip() for part in parts if part.strip())
    if not text_value:
        _fail("SOURCE_ACCEPTANCE_ITEM_EMPTY")
    stable_bytes = f"{relative}\0{line_number}\0{text_value}".encode()
    source_id = f"SRC-{_sha256(stable_bytes)[:20]}"
    return {
        "source_criterion_id": source_id,
        "criterion_id": source_id,
        "source_reference": relative,
        "source_line": line_number,
        "expected_behavior": text_value,
    }


def _source_items_for_file(path: Path, source_reference: str) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        _fail("SOURCE_FILE_UNREADABLE")
    sections: list[tuple[int, int]] = []
    in_fence = False
    for index, line in enumerate(lines):
        if _SOURCE_FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        heading = _is_acceptance_heading(line)
        if heading is None:
            continue
        level, markdown_heading = heading
        end = len(lines)
        if markdown_heading:
            fence = False
            for cursor in range(index + 1, len(lines)):
                if _SOURCE_FENCE.match(lines[cursor]):
                    fence = not fence
                    continue
                if fence:
                    continue
                next_heading = _SOURCE_HEADING.match(lines[cursor])
                if next_heading and len(next_heading.group(1)) <= level:
                    end = cursor
                    break
        else:
            fence = False
            for cursor in range(index + 1, len(lines)):
                if _SOURCE_FENCE.match(lines[cursor]):
                    fence = not fence
                    continue
                if fence:
                    continue
                next_heading = _SOURCE_HEADING.match(lines[cursor])
                if next_heading:
                    end = cursor
                    break
        sections.append((index + 1, end))

    relative = source_reference
    result: list[dict[str, Any]] = []
    for start, end in sections:
        current_line: int | None = None
        current_parts: list[str] = []
        in_section_fence = False

        for line_index in range(start, end):
            line = lines[line_index]
            if _SOURCE_FENCE.match(line):
                in_section_fence = not in_section_fence
                continue
            if in_section_fence:
                continue
            item = _SOURCE_LIST_ITEM.match(line)
            if item is not None:
                previous = _make_source_item(relative, current_line, current_parts)
                if previous is not None:
                    result.append(previous)
                current_line = line_index + 1
                current_parts = [item.group(2) or ""]
            elif not line.strip():
                previous = _make_source_item(relative, current_line, current_parts)
                if previous is not None:
                    result.append(previous)
                current_line = None
                current_parts = []
            elif line.lstrip().startswith("|"):
                _fail("SOURCE_ACCEPTANCE_FORMAT_UNSUPPORTED")
            elif _SOURCE_HEADING.match(line):
                previous = _make_source_item(relative, current_line, current_parts)
                if previous is not None:
                    result.append(previous)
                current_line = None
                current_parts = []
                continue
            elif current_line is not None:
                current_parts.append(line.strip())
            else:
                current_line = line_index + 1
                current_parts = [line.strip()]
        previous = _make_source_item(relative, current_line, current_parts)
        if previous is not None:
            result.append(previous)
    return result


def _source_criteria_inventory(
    source_base: Path,
    canonical_rows: list[dict[str, Any]],
    excluded_paths: set[Path] | None = None,
) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    mapped_files = _referenced_markdown_files(source_base, canonical_rows)
    excluded = excluded_paths or set()
    for path in sorted(
        mapped_files,
        key=lambda item: os.path.relpath(item, source_base).replace("\\", "/"),
    ):
        if path in excluded:
            continue
        relative = os.path.relpath(path, source_base).replace("\\", "/")
        mapped_ids = sorted(mapped_files[path])
        for item in _source_items_for_file(path, relative):
            item["mapped_requirement_ids"] = mapped_ids
            inventory.append(item)
    return inventory


def _validate_source_exclusions(
    exclusions: Any, source_base: Path, canonical_rows: list[dict[str, Any]]
) -> set[Path]:
    if not isinstance(exclusions, list):
        _fail("MATRIX_SOURCE_EXCLUSIONS_INVALID")
    source_files = _referenced_markdown_files(source_base, canonical_rows)
    by_reference = {
        os.path.relpath(path, source_base).replace("\\", "/"): path for path in source_files
    }
    excluded: set[Path] = set()
    seen: set[str] = set()
    for item in exclusions:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "reason"}:
            _fail("MATRIX_SOURCE_EXCLUSIONS_INVALID")
        reference = item.get("path")
        expected_hash = item.get("sha256")
        reason = item.get("reason")
        if (
            not isinstance(reference, str)
            or not reference
            or len(reference) > 4096
            or "\\" in reference
            or "\x00" in reference
            or not isinstance(expected_hash, str)
            or not _HEX_256.fullmatch(expected_hash)
            or not isinstance(reason, str)
            or not reason.strip()
            or len(reason) > 4096
        ):
            _fail("MATRIX_SOURCE_EXCLUSIONS_INVALID")
        if reference in seen:
            _fail("MATRIX_SOURCE_EXCLUSIONS_DUPLICATE")
        seen.add(reference)
        path = by_reference.get(reference)
        if path is None:
            _fail("MATRIX_SOURCE_EXCLUSION_UNKNOWN")
        try:
            actual_hash = _sha256(path.read_bytes())
        except OSError:
            _fail("SOURCE_INVENTORY_INVALID")
        if actual_hash != expected_hash:
            _fail("MATRIX_SOURCE_EXCLUSION_HASH_MISMATCH")
        excluded.add(path.resolve(strict=True))
    return excluded


def required_release_gate_ids(
    requirements_path: str | Path, source_root: str | Path
) -> tuple[str, ...]:
    """Return fixed gates plus one stable gate for each cited local-unavailable source."""
    _map_bytes, rows = _load_requirements(Path(requirements_path))
    root = Path(source_root).resolve(strict=True)
    return tuple(sorted({*REQUIRED_RELEASE_GATES, *_expected_unavailable_sources(root, rows)}))


def _strict_json(path: Path) -> Any:
    def pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail("MATRIX_DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def reject_constant(_constant: str) -> None:
        _fail("MATRIX_INVALID_JSON_NUMBER")

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs_no_duplicates,
            parse_constant=reject_constant,
        )
    except MatrixValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        _fail("MATRIX_UNREADABLE")


def _load_requirements(path: Path) -> tuple[bytes, list[dict[str, Any]]]:
    try:
        raw = path.read_bytes()
        data = yaml.safe_load(raw)
    except (OSError, UnicodeError, yaml.YAMLError):
        _fail("REQUIREMENTS_MAP_UNREADABLE")
    if not isinstance(data, dict) or not isinstance(data.get("requirements"), list):
        _fail("REQUIREMENTS_MAP_INVALID")
    requirements = data["requirements"]
    ids: list[str] = []
    for row in requirements:
        if not isinstance(row, dict):
            _fail("REQUIREMENTS_MAP_INVALID")
        rid = row.get("id")
        criteria = row.get("acceptance_criteria")
        if not isinstance(rid, str) or not rid or not isinstance(criteria, list) or not criteria:
            _fail("REQUIREMENTS_MAP_INVALID")
        if any(not isinstance(item, str) or not item.strip() for item in criteria):
            _fail("REQUIREMENTS_MAP_INVALID")
        ids.append(rid)
    if len(ids) != len(set(ids)):
        _fail("REQUIREMENTS_MAP_DUPLICATE_ID")
    return raw, requirements


def _safe_evidence_file(root: Path, item: Any) -> Path:
    if not isinstance(item, dict) or set(item) != {"kind", "path", "sha256"}:
        _fail("EVIDENCE_RECORD_INVALID")
    relative = item["path"]
    expected = item["sha256"]
    if (
        item.get("kind") != "PROJECT_QA_HANDOFF"
        or not isinstance(relative, str)
        or not relative
        or len(relative) > 4096
        or "\\" in relative
        or relative.startswith("/")
        or re.match(r"^[A-Za-z]:", relative)
        or any(part in {"", ".", ".."} for part in relative.split("/"))
        or not isinstance(expected, str)
        or not _HEX_256.fullmatch(expected)
    ):
        _fail("EVIDENCE_PATH_INVALID")
    try:
        base = root.resolve(strict=True)
    except OSError:
        _fail("EVIDENCE_PATH_INVALID")
    candidate = base.joinpath(*relative.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(base)
    except (OSError, ValueError):
        _fail("EVIDENCE_PATH_INVALID")
    cursor = candidate
    while cursor != base:
        if cursor.is_symlink():
            _fail("EVIDENCE_PATH_INVALID")
        cursor = cursor.parent
    if not resolved.is_file():
        _fail("EVIDENCE_PATH_INVALID")
    try:
        actual = _sha256(resolved.read_bytes())
    except OSError:
        _fail("EVIDENCE_UNREADABLE")
    if actual != expected:
        _fail("EVIDENCE_HASH_MISMATCH")
    parts = relative.split("/")
    if (
        len(parts) != 4
        or parts[0:2] != ["qa", "handoffs"]
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", parts[2])
        or parts[3] != "evidence.json"
    ):
        _fail("EVIDENCE_NOT_PROJECT_HANDOFF")
    return resolved


def _safe_repo_file(repo_root: Path, entry: Any) -> str:
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
        _fail("HANDOFF_CANONICAL_FILE_INVALID")
    relative = entry.get("path")
    expected = entry.get("sha256")
    if (
        not isinstance(relative, str)
        or not relative
        or "\\" in relative
        or relative.startswith("/")
        or re.match(r"^[A-Za-z]:", relative)
        or any(part in {"", ".", ".."} for part in relative.split("/"))
        or relative.split("/", 1)[0] == ".git"
        or not isinstance(expected, str)
        or not _HEX_256.fullmatch(expected)
    ):
        _fail("HANDOFF_CANONICAL_FILE_INVALID")
    try:
        root = repo_root.resolve(strict=True)
        path = root.joinpath(*relative.split("/"))
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        _fail("HANDOFF_CANONICAL_FILE_INVALID")
    cursor = path
    while cursor != root:
        if cursor.is_symlink():
            _fail("HANDOFF_CANONICAL_FILE_INVALID")
        cursor = cursor.parent
    if not resolved.is_file():
        _fail("HANDOFF_CANONICAL_FILE_INVALID")
    try:
        actual = _sha256(resolved.read_bytes())
    except OSError:
        _fail("HANDOFF_CANONICAL_FILE_INVALID")
    if actual != expected:
        _fail("HANDOFF_CANONICAL_HASH_MISMATCH")
    return relative


def _validate_handoff_evidence(
    project_root: Path,
    repo_root: Path,
    evidence: Any,
    candidate_commit: str,
    subject_id: str,
    expected_status: str,
    expected_actual_result: str,
) -> None:
    path = _safe_evidence_file(project_root, evidence)
    relative_path = evidence["path"]
    handoff_id = relative_path.split("/")[2]
    record = _strict_json(path)
    if not isinstance(record, dict) or set(record) != {
        "schema_version",
        "handoff_id",
        "candidate_commit",
        "worker_agent_id",
        "reviewer_agent_id",
        "review_disposition",
        "canonical_files",
        "results",
    }:
        _fail("HANDOFF_RECORD_INVALID")
    if record.get("schema_version") != "1.0.0" or record.get("handoff_id") != handoff_id:
        _fail("HANDOFF_RECORD_INVALID")
    if record.get("candidate_commit") != candidate_commit:
        _fail("HANDOFF_CANDIDATE_MISMATCH")
    worker = record.get("worker_agent_id")
    reviewer = record.get("reviewer_agent_id")
    if (
        not isinstance(worker, str)
        or not worker.strip()
        or not isinstance(reviewer, str)
        or not reviewer.strip()
        or worker == reviewer
        or record.get("review_disposition") != "PASS"
    ):
        _fail("HANDOFF_REVIEW_NOT_INDEPENDENT_PASS")
    canonical_files = record.get("canonical_files")
    if not isinstance(canonical_files, list) or not canonical_files:
        _fail("HANDOFF_CANONICAL_FILE_INVALID")
    verified_paths = [_safe_repo_file(repo_root, item) for item in canonical_files]
    if len(verified_paths) != len(set(verified_paths)):
        _fail("HANDOFF_CANONICAL_FILE_INVALID")
    results = record.get("results")
    if not isinstance(results, list):
        _fail("HANDOFF_RESULT_MISSING")
    matches = 0
    for result in results:
        if not isinstance(result, dict) or set(result) != {
            "subject_id",
            "status",
            "actual_result",
            "canonical_file_paths",
        }:
            _fail("HANDOFF_RESULT_INVALID")
        if result.get("subject_id") != subject_id:
            continue
        file_paths = result.get("canonical_file_paths")
        if (
            result.get("status") != expected_status
            or result.get("actual_result") != expected_actual_result
            or not isinstance(file_paths, list)
            or not file_paths
            or any(
                not isinstance(path_value, str) or path_value not in verified_paths
                for path_value in file_paths
            )
            or len(file_paths) != len(set(file_paths))
        ):
            continue
        matches += 1
    if matches != 1:
        _fail("HANDOFF_RESULT_MISSING")


def _require_text(value: Any, code: str = "MATRIX_SCHEMA_INVALID") -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(code)
    return value


def _expected_blocker_kind(gate_id: str, unavailable_gate_ids: set[str]) -> str | None:
    if gate_id in unavailable_gate_ids:
        return "SOURCE_UNAVAILABLE"
    return _GATE_BLOCKER_KIND.get(gate_id)


def _validate_blocker(
    blocker: Any,
    gate_statuses: dict[str, str],
    unavailable_gate_ids: set[str],
) -> str:
    if not isinstance(blocker, dict) or set(blocker) != {"kind", "gate_id"}:
        _fail("MATRIX_BLOCKER_INVALID")
    kind = blocker.get("kind")
    gate_id = blocker.get("gate_id")
    if not isinstance(kind, str) or kind not in BLOCKER_KINDS:
        _fail("MATRIX_BLOCKER_INVALID")
    if not isinstance(gate_id, str) or not _GATE_ID_SAFE.fullmatch(gate_id):
        _fail("MATRIX_BLOCKER_INVALID")
    if kind == "PRD_UNMAPPED":
        if gate_id != "FULL_PRD_CRITERION_AUDIT":
            _fail("MATRIX_BLOCKER_GATE_MISMATCH")
    elif _expected_blocker_kind(gate_id, unavailable_gate_ids) != kind:
        _fail("MATRIX_BLOCKER_GATE_MISMATCH")
    if gate_id not in gate_statuses:
        _fail("MATRIX_BLOCKER_GATE_UNKNOWN")
    if gate_statuses[gate_id] == "PASS":
        _fail("MATRIX_BLOCKER_GATE_ALREADY_PASS")
    return gate_id


def _validate_criterion(
    criterion: Any,
    expected_id: str,
    expected_text: str,
    project_root: Path,
    repo_root: Path,
    candidate_commit: str,
    gate_statuses: dict[str, str],
    unavailable_gate_ids: set[str],
    unavailable_source_gate_id: str | None = None,
) -> Counter[str]:
    if not isinstance(criterion, dict):
        _fail("MATRIX_CRITERIA_INCOMPLETE")
    allowed = {
        "criterion_id",
        "expected_behavior",
        "actual_result",
        "test_types",
        "evidence",
        "environment",
        "severity",
        "status",
        "blocker",
        "source_criterion_id",
        "source_reference",
        "source_line",
        "mapped_requirement_ids",
    }
    required = allowed - {
        "blocker",
        "source_criterion_id",
        "source_reference",
        "source_line",
        "mapped_requirement_ids",
    }
    if not required.issubset(criterion) or not set(criterion).issubset(allowed):
        _fail("MATRIX_SCHEMA_INVALID")
    if (
        criterion.get("criterion_id") != expected_id
        or criterion.get("expected_behavior") != expected_text
    ):
        _fail("MATRIX_CRITERIA_MISMATCH")
    actual_result = _require_text(criterion.get("actual_result"))
    tests = criterion.get("test_types")
    if not isinstance(tests, list) or not tests or any(not isinstance(v, str) for v in tests):
        _fail("MATRIX_SCHEMA_INVALID")
    if len(tests) != len(set(tests)) or any(value not in _TEST_TYPES for value in tests):
        _fail("MATRIX_SCHEMA_INVALID")
    environment = criterion.get("environment")
    if not isinstance(environment, str) or environment not in {
        "development",
        "test",
        "staging",
        "production",
    }:
        _fail("MATRIX_SCHEMA_INVALID")
    severity = criterion.get("severity")
    if not isinstance(severity, str) or severity not in {"P0", "P1", "P2", "P3"}:
        _fail("MATRIX_SCHEMA_INVALID")
    status = criterion.get("status")
    if not isinstance(status, str) or status not in _STATUSES:
        _fail("MATRIX_SCHEMA_INVALID")
    if status == "PASS":
        if "blocker" in criterion:
            _fail("MATRIX_BLOCKER_INVALID")
        if unavailable_source_gate_id is not None:
            _fail("MATRIX_SOURCE_UNAVAILABLE_PASS")
    else:
        if "blocker" not in criterion:
            _fail("MATRIX_BLOCKER_MISSING")
        blocker_id = _validate_blocker(criterion["blocker"], gate_statuses, unavailable_gate_ids)
        if unavailable_source_gate_id is not None and blocker_id != unavailable_source_gate_id:
            _fail("MATRIX_SOURCE_UNAVAILABLE_BLOCKER_MISMATCH")
    evidence = criterion.get("evidence")
    if not isinstance(evidence, list):
        _fail("MATRIX_SCHEMA_INVALID")
    if status in _EVIDENCE_STATUSES and not evidence:
        _fail("MATRIX_EVIDENCE_MISSING")
    for item in evidence:
        _validate_handoff_evidence(
            project_root,
            repo_root,
            item,
            candidate_commit,
            expected_id,
            status,
            actual_result,
        )
    return Counter({status: 1})


def _validate_source_criterion(
    criterion: Any,
    expected: dict[str, Any],
    project_root: Path,
    repo_root: Path,
    candidate_commit: str,
    gate_statuses: dict[str, str],
    unavailable_gate_ids: set[str],
) -> Counter[str]:
    if not isinstance(criterion, dict):
        _fail("MATRIX_SOURCE_CRITERIA_INCOMPLETE")
    for key in (
        "criterion_id",
        "source_criterion_id",
        "source_reference",
        "source_line",
        "mapped_requirement_ids",
        "expected_behavior",
    ):
        if criterion.get(key) != expected[key]:
            _fail("MATRIX_SOURCE_CRITERIA_MISMATCH")
    if not isinstance(criterion.get("source_line"), int) or isinstance(
        criterion["source_line"], bool
    ):
        _fail("MATRIX_SOURCE_CRITERIA_MISMATCH")
    mapped_ids = expected["mapped_requirement_ids"]
    blocker = criterion.get("blocker")
    if not mapped_ids:
        if criterion.get("status") != "BLOCKED" or blocker != {
            "kind": "PRD_UNMAPPED",
            "gate_id": "FULL_PRD_CRITERION_AUDIT",
        }:
            _fail("MATRIX_PRD_UNMAPPED_CRITERION")
    elif isinstance(blocker, dict) and blocker.get("kind") == "PRD_UNMAPPED":
        _fail("MATRIX_PRD_UNMAPPED_CRITERION")
    synthetic = dict(criterion)
    return _validate_criterion(
        synthetic,
        expected["source_criterion_id"],
        expected["expected_behavior"],
        project_root,
        repo_root,
        candidate_commit,
        gate_statuses,
        unavailable_gate_ids,
    )


def _validate_release_gates(
    gates: Any,
    project_root: Path,
    repo_root: Path,
    candidate_commit: str,
    unavailable_sources: dict[str, str],
) -> dict[str, str]:
    if not isinstance(gates, list):
        _fail("MATRIX_SCHEMA_INVALID")
    found: dict[str, str] = {}
    unavailable_gate_ids = set(unavailable_sources)
    expected_gate_ids = {*REQUIRED_RELEASE_GATES, *unavailable_gate_ids}
    for gate in gates:
        if not isinstance(gate, dict):
            _fail("MATRIX_SCHEMA_INVALID")
        gate_id = _require_text(gate.get("gate_id"))
        if gate_id not in expected_gate_ids:
            _fail("MATRIX_UNKNOWN_GATE")
        if gate_id in found:
            _fail("MATRIX_DUPLICATE_GATE")
        status = gate.get("status")
        if not isinstance(status, str) or status not in {
            "PASS",
            "FAIL",
            "BLOCKED",
            "NOT_TESTED",
        }:
            _fail("MATRIX_SCHEMA_INVALID")
        _require_text(gate.get("description"))
        actual_result = _require_text(gate.get("actual_result"))
        allowed = {
            "gate_id",
            "status",
            "description",
            "actual_result",
            "evidence",
            "blocker",
            "source_reference",
        }
        if not set(gate).issubset(allowed):
            _fail("MATRIX_SCHEMA_INVALID")
        if gate_id in unavailable_sources:
            if gate.get("source_reference") != unavailable_sources[gate_id]:
                _fail("MATRIX_SOURCE_GATE_MISMATCH")
            if status == "PASS":
                _fail("MATRIX_SOURCE_UNAVAILABLE_PASS")
        elif "source_reference" in gate:
            _fail("MATRIX_SCHEMA_INVALID")
        if gate_id == "USER_RELEASE_APPROVAL" and status == "PASS":
            _fail("MATRIX_USER_APPROVAL_GATE_CANNOT_PASS")
        if gate_id == "FULL_PRD_CRITERION_AUDIT" and status == "PASS" and unavailable_sources:
            _fail("MATRIX_FULL_PRD_AUDIT_SOURCE_GAP")
        evidence = gate.get("evidence", [])
        if not isinstance(evidence, list):
            _fail("MATRIX_SCHEMA_INVALID")
        if status == "PASS" and not evidence:
            _fail("MATRIX_EVIDENCE_MISSING")
        blocker = gate.get("blocker")
        if status == "PASS":
            if blocker is not None:
                _fail("MATRIX_BLOCKER_INVALID")
        else:
            if not isinstance(blocker, dict):
                _fail("MATRIX_BLOCKER_MISSING")
            blocker_id = _validate_blocker(blocker, found | {gate_id: status}, unavailable_gate_ids)
            if blocker_id != gate_id:
                _fail("MATRIX_BLOCKER_GATE_MISMATCH")
        for item in evidence:
            _validate_handoff_evidence(
                project_root,
                repo_root,
                item,
                candidate_commit,
                f"GATE:{gate_id}",
                status,
                actual_result,
            )
        found[gate_id] = status
    if set(found) != expected_gate_ids:
        _fail("MATRIX_GATE_COVERAGE")
    if found and all(status == "PASS" for status in found.values()):
        _fail("MATRIX_ALL_GATES_PASS_FORBIDDEN")
    return found


def validate_matrix(
    requirements_path: str | Path,
    source_root: str | Path,
    candidate_path: str | Path,
    evidence_root: str | Path | None = None,
) -> dict[str, Any]:
    """Validate canonical traceability and project handoff evidence.

    ``source_root`` is the project root containing inputs/, qa/handoffs/ and
    repo/. ``evidence_root`` remains a compatibility option but must resolve to
    that same project root. Validation never certifies a release.
    """
    map_path = Path(requirements_path)
    try:
        project_root = Path(source_root).resolve(strict=True)
        repo_root = (project_root / "repo").resolve(strict=True)
    except OSError:
        _fail("PROJECT_ROOT_INVALID")
    candidate_file = Path(candidate_path)
    if evidence_root is not None:
        try:
            if Path(evidence_root).resolve(strict=True) != project_root:
                _fail("PROJECT_ROOT_INVALID")
        except OSError:
            _fail("PROJECT_ROOT_INVALID")
    map_bytes, canonical_rows = _load_requirements(map_path)
    try:
        if map_path.resolve(strict=True).parent != project_root:
            _fail("PROJECT_ROOT_INVALID")
    except OSError:
        _fail("REQUIREMENTS_MAP_UNREADABLE")
    candidate = _strict_json(candidate_file)
    if not isinstance(candidate, dict) or set(candidate) != {
        "schema_version",
        "candidate",
        "requirements",
        "source_criteria",
        "release_gates",
    }:
        _fail("MATRIX_SCHEMA_INVALID")
    if candidate.get("schema_version") != "1.0.0":
        _fail("MATRIX_SCHEMA_INVALID")
    meta = candidate.get("candidate")
    required_meta = {
        "candidate_id",
        "version",
        "source_commit",
        "environment",
        "requirements_map_sha256",
        "source_inventory_sha256",
        "release_artifacts",
    }
    if (
        not isinstance(meta, dict)
        or not required_meta.issubset(meta)
        or not set(meta).issubset(required_meta | {"source_exclusions"})
    ):
        _fail("MATRIX_SCHEMA_INVALID")
    _require_text(meta.get("candidate_id"))
    _require_text(meta.get("version"))
    if not isinstance(meta.get("source_commit"), str) or not _HEX_160.fullmatch(
        meta["source_commit"]
    ):
        _fail("MATRIX_SCHEMA_INVALID")
    if not isinstance(meta.get("environment"), str) or meta["environment"] not in {
        "development",
        "test",
        "staging",
        "production",
    }:
        _fail("MATRIX_SCHEMA_INVALID")
    map_hash = _sha256(map_bytes)
    if meta.get("requirements_map_sha256") != map_hash:
        _fail("MATRIX_REQUIREMENTS_MAP_HASH_MISMATCH")
    source_hash = source_inventory_sha256(map_path.parent, canonical_rows)
    if meta.get("source_inventory_sha256") != source_hash:
        _fail("MATRIX_SOURCE_INVENTORY_HASH_MISMATCH")
    excluded_source_files = _validate_source_exclusions(
        meta.get("source_exclusions", []), map_path.parent, canonical_rows
    )
    release_artifacts = meta.get("release_artifacts")
    if not isinstance(release_artifacts, list):
        _fail("MATRIX_SCHEMA_INVALID")
    for item in release_artifacts:
        _safe_evidence_file(project_root, item)

    unavailable_sources = _expected_unavailable_sources(map_path.parent, canonical_rows)
    unavailable_gate_ids = set(unavailable_sources)
    gate_statuses = _validate_release_gates(
        candidate.get("release_gates"),
        project_root,
        repo_root,
        meta["source_commit"],
        unavailable_sources,
    )

    rows = candidate.get("requirements")
    if not isinstance(rows, list):
        _fail("MATRIX_SCHEMA_INVALID")
    expected_by_id = {row["id"]: row for row in canonical_rows}
    actual_ids: list[str] = []
    counts: Counter[str] = Counter()
    criterion_count = 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "requirement_id",
            "source_reference",
            "requirement_text",
            "implementation_location",
            "verification_method",
            "criteria",
        }:
            _fail("MATRIX_SCHEMA_INVALID")
        requirement_id = _require_text(row.get("requirement_id"))
        actual_ids.append(requirement_id)
        canonical = expected_by_id.get(requirement_id)
        if canonical is None:
            _fail("MATRIX_UNKNOWN_REQUIREMENT")
        if row.get("source_reference") != canonical.get("source"):
            _fail("MATRIX_SOURCE_MISMATCH")
        if row.get("requirement_text") != canonical.get("requirement"):
            _fail("MATRIX_REQUIREMENT_MISMATCH")
        if row.get("implementation_location") != canonical.get("implementation_target"):
            _fail("MATRIX_IMPLEMENTATION_MISMATCH")
        if row.get("verification_method") != canonical.get("verification_method"):
            _fail("MATRIX_VERIFICATION_MISMATCH")
        criteria = row.get("criteria")
        source_criteria = canonical["acceptance_criteria"]
        if not isinstance(criteria, list) or len(criteria) != len(source_criteria):
            _fail("MATRIX_CRITERIA_INCOMPLETE")
        for index, (criterion, expected_text) in enumerate(
            zip(criteria, source_criteria, strict=True), 1
        ):
            criterion_id = f"{requirement_id}.AC.{index:03d}"
            source_gate_id = _unavailable_source_gate_id(canonical["source"])
            counts.update(
                _validate_criterion(
                    criterion,
                    criterion_id,
                    expected_text,
                    project_root,
                    repo_root,
                    meta["source_commit"],
                    gate_statuses,
                    unavailable_gate_ids,
                    source_gate_id if source_gate_id in unavailable_gate_ids else None,
                )
            )
            criterion_count += 1
    if len(actual_ids) != len(set(actual_ids)):
        _fail("MATRIX_DUPLICATE_REQUIREMENT")
    if set(actual_ids) != set(expected_by_id):
        _fail("MATRIX_REQUIREMENT_COVERAGE")
    expected_source_criteria = _source_criteria_inventory(
        map_path.parent, canonical_rows, excluded_source_files
    )
    actual_source_criteria = candidate.get("source_criteria")
    if not isinstance(actual_source_criteria, list) or len(actual_source_criteria) != len(
        expected_source_criteria
    ):
        _fail("MATRIX_SOURCE_CRITERIA_INCOMPLETE")
    source_ids: list[str] = []
    for criterion, expected in zip(actual_source_criteria, expected_source_criteria, strict=True):
        source_ids.append(
            criterion.get("source_criterion_id") if isinstance(criterion, dict) else ""
        )
        counts.update(
            _validate_source_criterion(
                criterion,
                expected,
                project_root,
                repo_root,
                meta["source_commit"],
                gate_statuses,
                unavailable_gate_ids,
            )
        )
    if len(source_ids) != len(set(source_ids)):
        _fail("MATRIX_SOURCE_CRITERIA_DUPLICATE")
    return {
        "validation_status": "VALID",
        "certification_status": "NOT_CERTIFIED",
        "candidate_id": meta["candidate_id"],
        "requirements_count": len(actual_ids),
        "criteria_count": criterion_count,
        "source_criteria_count": len(expected_source_criteria),
        "criterion_status_counts": dict(sorted(counts.items())),
        "release_gate_statuses": dict(sorted(gate_statuses.items())),
        "requirements_map_sha256": map_hash,
        "source_inventory_sha256": source_hash,
        "source_exclusions_count": len(excluded_source_files),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--evidence-root", type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate_matrix(
            args.requirements, args.source_root, args.candidate, args.evidence_root
        )
    except MatrixValidationError as exc:
        print(
            json.dumps(
                {
                    "validation_status": "INVALID",
                    "certification_status": "NOT_CERTIFIED",
                    "error_code": exc.code,
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by CLI smoke test
    sys.exit(main())
