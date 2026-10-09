"""Build a deterministic, hash-bound inventory of PRD acceptance coverage.

The snapshot is diagnostic evidence only. A mapped requirement or contract does
not imply that its implementation or acceptance has passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, NotRequired, TypedDict

import yaml


class CoverageRefreshError(ValueError):
    """Content-free failure raised for invalid inputs or unreadable sources."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SnapshotInputV1(TypedDict):
    path: str
    sha256: str


class SourceAnchorV1(TypedDict):
    path: str
    section_path: list[str]
    line_start: int
    line_end: int
    occurrence: int


class EvidenceRefV1(TypedDict):
    path: str
    sha256: str
    kind: str
    observed_status: str
    line_start: NotRequired[int]
    line_end: NotRequired[int]


class CriterionV1(TypedDict):
    criterion_id: str
    source: SourceAnchorV1
    source_text: str
    source_text_sha256: str
    map_ids: list[str]
    owners: list[str]
    target_paths: list[str]
    contract_ids: list[str]
    coverage_class: str
    evidence_state: str
    evidence_refs: list[EvidenceRefV1]


class FindingV1(TypedDict):
    code: str
    criterion_ids: list[str]
    map_ids: list[str]
    contract_ids: list[str]
    source_paths: list[str]


class PerFileCountV1(TypedDict):
    path: str
    source_criterion_count: int
    sha256: str


class UnresolvedOwnerV1(TypedDict):
    criterion_id: str
    map_ids: list[str]
    owners: list[str]


class SummaryV1(TypedDict):
    source_criterion_count: int
    no_contract_count: int
    coverage_class_counts: dict[str, int]
    stale_map_id_count: int
    umbrella_only_map_id_count: int
    per_file_source_criteria: list[PerFileCountV1]
    unresolved_owners: list[UnresolvedOwnerV1]


class SnapshotV1(TypedDict):
    inputs: list[SnapshotInputV1]
    input_fingerprint_sha256: str


class CoverageSnapshotV1(TypedDict):
    schema_version: str
    snapshot: SnapshotV1
    summary: SummaryV1
    criteria: list[CriterionV1]
    findings: list[FindingV1]


class _MapRow(TypedDict):
    id: str
    source: str
    acceptance_criteria: list[str]
    requirement: str
    disposition_reason: str
    target_path: str
    owner: str
    contract_ids: list[str]


class _SourceCriterion(TypedDict):
    path: str
    section_path: list[str]
    line_start: int
    line_end: int
    occurrence: int
    text: str
    sha256: str
    criterion_id: str


class _EvidenceDoc(TypedDict):
    path: str
    sha256: str
    kind: str
    text: str
    contract_ids: list[str]
    target_paths: list[str]
    observed_status: str


_HEADING = re.compile(r"^\s*(#{1,6})\s+(.+?)\s*#*\s*$")
_PLAIN_ACCEPTANCE_HEADING = re.compile(
    r"^\s*(?:acceptance(?: criteria| signals| & edge cases)?|"
    r"edge cases & acceptance(?: criteria)?|success criteria|definition of done)"
    r"(?:\s*\([^)]*\))?\s*:?\s*$",
    re.IGNORECASE,
)
_OUT_OF_SCOPE_HEADING = re.compile(
    r"^\s*(?:#{1,6}\s*)?out\s+of\s+scope\s*#*\s*:?\s*$", re.IGNORECASE
)
_LIST_ITEM = re.compile(r"^(\s*)(?:[-*+]\s+|\d+[.)]\s+)(.*\S)?\s*$")
_CHECKBOX = re.compile(r"^\[[ xX]\]\s*")
_FENCE = re.compile(r"^\s*(?:`{3,}|~{3,})")
_CONTRACT_LINE = re.compile(
    r"(?im)^\s*(?:contract\s*id|kernel)\s*:\s*`?([A-Za-z0-9][A-Za-z0-9._-]{1,95})`?"
)
_CONTRACT_ID = re.compile(r"(?<![A-Za-z0-9])([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3})(?![A-Z0-9])")
_TARGET_LINE = re.compile(r"(?im)^\s*(?:target\s*path|implementation\s*target)\s*:\s*`?([^\s`]+)")
_REPO_PATH = re.compile(
    r"(?<![A-Za-z0-9])((?:apps|packages|qa|tests|workers|infra|docs|data|benchmarks)/"
    r"[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*(?:\.[A-Za-z0-9._+-]+)?)"
)
_STATUS_LINE = re.compile(r"(?im)^\s*(?:status|verdict)\s*:\s*`?([A-Za-z0-9_-]+)")
_UNRESOLVED_OWNER = re.compile(
    r"\b(?:unassigned|unknown|tbd|owner\s+remains\s+open)\b", re.IGNORECASE
)
_GENERIC_UMBRELLA = re.compile(
    r"\b(?:area\s+umbrella|area completion gate|every current .*criterion|all current .*criterion|"
    r"every current .*acceptance item|full area completion|broader .*remain open)\b",
    re.IGNORECASE,
)

_MAP_ID = re.compile(r"\b(?:LEV-REQ|REQ)-\d{4}\b")
_CANDIDATE_FAMILY = re.compile(
    r"\b(?:IND-00[12]|LSS-001|TRUTH-\d{3}|LTF-\d{3}|MTBR-[A-Z0-9-]+|"
    r"DEP-\d{3}|FLA-[A-Z0-9-]+)\b"
)
_COVERAGE_CLASSES = (
    "COVERED_CRITERION",
    "CANDIDATE_UMBRELLA_ONLY",
    "NO_CONTRACT",
)
_MAX_WALK_FILES = 8192
_MAX_WALK_DIRECTORIES = 4096
_MAX_INPUT_FILE_BYTES = 4 * 1024 * 1024
_MAX_TOTAL_INPUT_BYTES = 256 * 1024 * 1024
_MAX_MAP_ROWS = 50_000


class _InputBudget:
    def __init__(self) -> None:
        self.total = 0
        self.cache: dict[Path, bytes] = {}

    def read(self, path: Path) -> bytes:
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            _fail("INPUT_UNREADABLE")
        if resolved in self.cache:
            return self.cache[resolved]
        remaining = _MAX_TOTAL_INPUT_BYTES - self.total
        if remaining < 0:
            _fail("INPUT_TOO_LARGE")
        limit = min(_MAX_INPUT_FILE_BYTES, remaining)
        try:
            size = resolved.stat().st_size
        except OSError:
            _fail("INPUT_UNREADABLE")
        if size > limit:
            _fail("INPUT_TOO_LARGE")
        try:
            with resolved.open("rb") as handle:
                raw = handle.read(limit + 1)
        except OSError:
            _fail("INPUT_UNREADABLE")
        if len(raw) > limit:
            _fail("INPUT_TOO_LARGE")
        self.total += len(raw)
        self.cache[resolved] = raw
        return raw


def _bounded_walk(root: Path, *, suffixes: set[str] | None = None) -> list[Path]:
    """Enumerate a tree with fixed file and directory ceilings."""
    paths: list[Path] = []
    directory_count = 0
    file_count = 0
    try:
        for current, dirs, files in os.walk(root, followlinks=False):
            directory_count += 1
            if directory_count > _MAX_WALK_DIRECTORIES:
                _fail("INPUT_TOO_LARGE")
            current_path = Path(current)
            dirs[:] = sorted(name for name in dirs if not (current_path / name).is_symlink())
            for name in sorted(files):
                candidate = current_path / name
                if candidate.is_symlink():
                    _fail("SOURCE_INVENTORY_INVALID")
                file_count += 1
                if file_count > _MAX_WALK_FILES:
                    _fail("INPUT_TOO_LARGE")
                if suffixes is None or candidate.suffix.lower() in suffixes:
                    paths.append(candidate)
    except OSError:
        _fail("SOURCE_INVENTORY_INVALID")
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix().encode("utf-8"))


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fail(code: str) -> NoReturn:
    raise CoverageRefreshError(code)


def _read_bytes(path: Path, budget: _InputBudget | None = None) -> bytes:
    if budget is not None:
        return budget.read(path)
    try:
        if path.stat().st_size > _MAX_INPUT_FILE_BYTES:
            _fail("INPUT_TOO_LARGE")
        with path.open("rb") as handle:
            raw = handle.read(_MAX_INPUT_FILE_BYTES + 1)
        if len(raw) > _MAX_INPUT_FILE_BYTES:
            _fail("INPUT_TOO_LARGE")
        return raw
    except OSError:
        _fail("INPUT_UNREADABLE")


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _coverage_normalize(text: str) -> str:
    """Normalize a whole contract clause for exact criterion matching."""
    value = unicodedata.normalize("NFC", _normalize(text)).casefold()
    while value and unicodedata.category(value[-1]).startswith("P"):
        value = value[:-1].rstrip()
    return value


def _contract_clauses(text: str) -> list[tuple[str, int, int]]:
    """Extract whole bullets, sentences, and table cells with inclusive lines."""
    lines = text.splitlines()
    clauses: list[tuple[str, int, int]] = []
    paragraph: list[tuple[int, str]] = []

    def flush_paragraph() -> None:
        if not paragraph:
            return
        joined = " ".join(line for _, line in paragraph)
        spans: list[tuple[int, int, int]] = []
        offset = 0
        for line_number, line in paragraph:
            if spans:
                offset += 1
            start = offset
            offset += len(line)
            spans.append((start, offset, line_number))
        for match in re.finditer(r"[^.!?]+(?:[.!?]+|$)", joined):
            normalized = _coverage_normalize(match.group(0).strip())
            touched = [
                number
                for start, end, number in spans
                if end > match.start() and start < match.end()
            ]
            if normalized and touched:
                clauses.append((normalized, min(touched), max(touched)))
        paragraph.clear()

    index = 0
    fence: tuple[str, int] | None = None
    while index < len(lines):
        line = lines[index]
        fence_match = _FENCE.match(line)
        if fence_match:
            flush_paragraph()
            marker = fence_match.group(0).strip()
            marker_run = re.match(r"(?:`{3,}|~{3,})", marker)
            if marker_run is None:
                index += 1
                continue
            marker = marker_run.group(0)
            if fence is None:
                fence = (marker[0], len(marker))
            elif marker[0] == fence[0] and len(marker) >= fence[1]:
                fence = None
            index += 1
            continue
        if fence is not None:
            index += 1
            continue
        if not line.strip() or _HEADING.match(line):
            flush_paragraph()
            index += 1
            continue
        list_match = _LIST_ITEM.match(line)
        if list_match:
            flush_paragraph()
            start = index + 1
            end = start
            indent = len(list_match.group(1))
            parts = [list_match.group(2) or ""]
            cursor = index + 1
            while cursor < len(lines):
                continuation = lines[cursor]
                if not continuation.strip() or _LIST_ITEM.match(continuation):
                    break
                if _HEADING.match(continuation):
                    break
                continuation_indent = len(continuation) - len(continuation.lstrip())
                if continuation_indent <= indent:
                    break
                parts.append(continuation.strip())
                end = cursor + 1
                cursor += 1
            normalized = _coverage_normalize(" ".join(parts))
            if normalized:
                clauses.append((normalized, start, end))
            index = max(index + 1, cursor)
            continue
        if "|" in line:
            flush_paragraph()
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            for cell in cells:
                normalized = _coverage_normalize(cell)
                if normalized and not re.fullmatch(r":?-{3,}:?", cell):
                    clauses.append((normalized, index + 1, index + 1))
            index += 1
            continue
        paragraph.append((index + 1, line.strip()))
        index += 1
    flush_paragraph()
    return clauses


def _clause_matches_criterion(clause: str, criterion_text: str, criterion_id: str) -> bool:
    if _coverage_normalize(clause) == _coverage_normalize(criterion_text):
        return True
    return bool(
        criterion_id
        and re.search(
            rf"(?<![A-Za-z0-9_-]){re.escape(criterion_id)}(?![A-Za-z0-9_-])",
            clause,
            re.IGNORECASE,
        )
    )


def _rootless(path: Path, *, relative_to: Path | None = None) -> str:
    if relative_to is not None:
        try:
            return path.resolve().relative_to(relative_to.resolve()).as_posix()
        except (OSError, ValueError):
            pass
    absolute = str(path.resolve()).replace("\\", "/")
    marker = "/epics/"
    if marker in absolute:
        return "epics/" + absolute.split(marker, 1)[1]
    return path.name


def _load_map(path: Path, budget: _InputBudget | None = None) -> tuple[bytes, list[_MapRow]]:
    raw = _read_bytes(path, budget)
    try:
        payload = yaml.safe_load(raw)
    except yaml.YAMLError:
        _fail("REQUIREMENTS_MAP_INVALID")
    if (
        not isinstance(payload, dict)
        or payload.get("version") != 12
        or not isinstance(payload.get("requirements"), list)
    ):
        _fail("REQUIREMENTS_MAP_INVALID")
    result: list[_MapRow] = []
    if len(payload["requirements"]) > _MAX_MAP_ROWS:
        _fail("INPUT_TOO_LARGE")
    if len(payload["requirements"]) > _MAX_MAP_ROWS:
        _fail("INPUT_TOO_LARGE")
    seen_ids: set[str] = set()
    for raw_row in payload["requirements"]:
        if not isinstance(raw_row, dict):
            _fail("REQUIREMENTS_MAP_INVALID")
        row_id = raw_row.get("id")
        source = raw_row.get("source")
        acceptance = raw_row.get("acceptance_criteria")
        target = raw_row.get("implementation_target", "")
        owner = raw_row.get("owner", "")
        requirement = raw_row.get("requirement", "")
        disposition = raw_row.get("disposition_reason", "")
        requirement = "" if requirement is None else requirement
        disposition = "" if disposition is None else disposition
        if (
            not isinstance(row_id, str)
            or not row_id.strip()
            or row_id in seen_ids
            or not isinstance(source, str)
            or not source.strip()
            or not isinstance(acceptance, list)
            or not all(isinstance(item, str) for item in acceptance)
            or not isinstance(target, str)
            or not isinstance(owner, str)
            or not isinstance(requirement, str)
            or not isinstance(disposition, str)
        ):
            _fail("REQUIREMENTS_MAP_INVALID")
        seen_ids.add(row_id)
        result.append(
            {
                "id": row_id,
                "source": source,
                "acceptance_criteria": acceptance,
                "requirement": requirement,
                "disposition_reason": disposition,
                "target_path": target.strip().replace("\\", "/"),
                "owner": owner.strip(),
                "contract_ids": sorted(set(_CONTRACT_ID.findall(owner))),
            }
        )
    return raw, result


def _heading_title(line: str) -> tuple[int, str] | None:
    match = _HEADING.match(line)
    if match is not None:
        return len(match.group(1)), match.group(2).strip().rstrip("# ")
    if _PLAIN_ACCEPTANCE_HEADING.match(line):
        return 6, line.strip().rstrip(":")
    if _OUT_OF_SCOPE_HEADING.match(line):
        match = _HEADING.match(line)
        return (len(match.group(1)) if match else 6, "Out of scope")
    return None


def _criterion_id(path: str, section_path: list[str], occurrence: int, text: str) -> str:
    canonical = f"{path}\n{'/'.join(section_path)}\n{occurrence}\n{text}"
    return "CRIT-" + _sha256(canonical.encode("utf-8"))


def _parse_markdown(path: Path, relative: str, raw: bytes) -> list[_SourceCriterion]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        _fail("SOURCE_FILE_INVALID")
    in_fence = False
    stack: list[tuple[int, str]] = []
    sections: list[tuple[int, int, int, list[str]]] = []
    active: tuple[int, int, list[str]] | None = None
    for index, line in enumerate(lines):
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        heading = _heading_title(line)
        if heading is None:
            continue
        level, title = heading
        if title.casefold() == "out of scope":
            if active is not None:
                sections.append((active[1], index, active[0], active[2]))
                active = None
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, title))
            continue
        if active is not None and level <= active[0]:
            sections.append((active[1], index, active[0], active[2]))
            active = None
        while stack and stack[-1][0] >= level:
            stack.pop()
        stack.append((level, title))
        if re.search(r"acceptance|success criteria|definition of done", title, re.IGNORECASE):
            if active is not None:
                sections.append((active[1], index, active[0], active[2]))
            active = (level, index + 1, [entry[1] for entry in stack])
    if active is not None:
        sections.append((active[1], len(lines), active[0], active[2]))

    extracted: list[tuple[list[str], int, int, str]] = []
    for section_start, section_end, level, base_path in sections:
        nested_headings: list[tuple[int, str]] = []
        item_start: int | None = None
        item_end: int | None = None
        item_parts: list[str] = []

        def flush(
            *,
            section_base: list[str] = base_path,
            child_headings: list[tuple[int, str]] = nested_headings,
        ) -> None:
            nonlocal item_start, item_end, item_parts
            if item_start is None:
                return
            text = _normalize(" ".join(item_parts))
            text = _CHECKBOX.sub("", text, count=1)
            text = _normalize(text)
            if text:
                section_path = [*section_base, *(title for _, title in child_headings)]
                extracted.append((section_path, item_start, item_end or item_start, text))
            item_start = None
            item_end = None
            item_parts = []

        in_section_fence = False
        for line_index in range(section_start, section_end):
            line = lines[line_index]
            if _FENCE.match(line):
                in_section_fence = not in_section_fence
                continue
            if in_section_fence:
                continue
            heading = _heading_title(line)
            if heading is not None:
                h_level, title = heading
                if h_level <= level:
                    flush()
                    continue
                flush()
                while nested_headings and nested_headings[-1][0] >= h_level:
                    nested_headings.pop()
                nested_headings.append((h_level, title))
                continue
            list_item = _LIST_ITEM.match(line)
            if list_item is not None:
                flush()
                item_start = line_index + 1
                item_end = item_start
                item_parts = [list_item.group(2) or ""]
                continue
            if not line.strip():
                flush()
                continue
            if line.lstrip().startswith("|"):
                cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
                if cells and not all(re.fullmatch(r"[-: ]+", cell or "-") for cell in cells):
                    flush()
                    item_start = line_index + 1
                    item_end = item_start
                    item_parts = ["; ".join(cell for cell in cells if cell)]
                continue
            if item_start is None:
                item_start = line_index + 1
                item_parts = [line.strip()]
            else:
                item_parts.append(line.strip())
            item_end = line_index + 1
        flush()

    occurrences: Counter[tuple[str, tuple[str, ...], str]] = Counter()
    results: list[_SourceCriterion] = []
    for section_path, line_start, line_end, text in extracted:
        key = (relative, tuple(section_path), text)
        occurrences[key] += 1
        occurrence = occurrences[key]
        results.append(
            {
                "path": relative,
                "section_path": section_path,
                "line_start": line_start,
                "line_end": line_end,
                "occurrence": occurrence,
                "text": text,
                "sha256": _sha256(text.encode("utf-8")),
                "criterion_id": _criterion_id(relative, section_path, occurrence, text),
            }
        )
    return results


def _parse_intake(
    path: Path, budget: _InputBudget | None = None
) -> tuple[bytes, list[_SourceCriterion]]:
    raw = _read_bytes(path, budget)
    try:
        node = yaml.compose(raw)
        raw.decode("utf-8")
    except (yaml.YAMLError, UnicodeError):
        _fail("SOURCE_FILE_INVALID")
    if not isinstance(node, yaml.MappingNode):
        _fail("SOURCE_FILE_INVALID")
    requirements_node: yaml.SequenceNode | None = None
    for key, value in node.value:
        if isinstance(key, yaml.ScalarNode) and key.value == "requirements":
            if isinstance(value, yaml.SequenceNode):
                requirements_node = value
            break
    if requirements_node is None:
        _fail("SOURCE_FILE_INVALID")
    result: list[_SourceCriterion] = []
    occurrence_by_text: Counter[str] = Counter()
    for item in requirements_node.value:
        if not isinstance(item, yaml.ScalarNode):
            continue
        criterion = _normalize(item.value)
        if not criterion:
            continue
        occurrence_by_text[criterion] += 1
        line_start = item.start_mark.line + 1
        line_end = max(line_start, item.end_mark.line + 1)
        section = ["requirements"]
        result.append(
            {
                "path": "inputs/INTAKE.yaml",
                "section_path": section,
                "line_start": line_start,
                "line_end": line_end,
                "occurrence": occurrence_by_text[criterion],
                "text": criterion,
                "sha256": _sha256(criterion.encode("utf-8")),
                "criterion_id": _criterion_id(
                    "inputs/INTAKE.yaml", section, occurrence_by_text[criterion], criterion
                ),
            }
        )
    return raw, result


def _normalize_source_reference(source: str) -> str:
    value = source.replace("\\", "/").split("#", 1)[0]
    return value.rstrip("/")


def _source_line_range(source: str) -> tuple[int, int] | None:
    match = re.search(r"#L(\d+)(?:-L?(\d+))?$", source)
    if match is None:
        return None
    start = int(match.group(1))
    end = int(match.group(2) or start)
    if start < 1 or end < start:
        _fail("REQUIREMENTS_MAP_INVALID")
    return start, end


def _parse_anchored_source_criteria(
    rows: list[_MapRow], map_path: Path, prd_root: Path, budget: _InputBudget | None = None
) -> tuple[list[_SourceCriterion], list[tuple[str, Path, bytes]]]:
    criteria: dict[tuple[str, int, str], _SourceCriterion] = {}
    source_files: dict[str, tuple[str, Path, bytes]] = {}
    parsed_files: dict[str, tuple[Path, list[str], list[str]]] = {}
    for row in rows:
        source = row["source"]
        line_range = _source_line_range(source)
        if line_range is None:
            continue
        source_ref = _normalize_source_reference(source)
        source_obj = Path(source_ref)
        candidates = (
            [source_obj]
            if source_obj.is_absolute()
            else [map_path.parent / source_obj, prd_root / source_obj]
        )
        resolved: Path | None = None
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if resolved.is_file():
                break
            resolved = None
        if resolved is None:
            continue
        try:
            relative = resolved.relative_to(prd_root).as_posix()
        except ValueError:
            relative = _rootless(resolved)
        if relative not in parsed_files:
            raw = _read_bytes(resolved, budget)
            try:
                lines = raw.decode("utf-8").splitlines()
            except UnicodeError:
                _fail("SOURCE_FILE_INVALID")
            heading_stack: list[tuple[int, str]] = []
            sections: list[str] = []
            in_fence = False
            for line in lines:
                if _FENCE.match(line):
                    in_fence = not in_fence
                    sections.append("\x00")
                    continue
                if in_fence:
                    sections.append("\x00")
                    continue
                heading = _heading_title(line)
                if heading is not None:
                    level, title = heading
                    while heading_stack and heading_stack[-1][0] >= level:
                        heading_stack.pop()
                    heading_stack.append((level, title))
                sections.append("/".join(title for _, title in heading_stack))
            parsed_files[relative] = (resolved, lines, sections)
            source_files[relative] = (relative, resolved, raw)
        _file, lines, sections = parsed_files[relative]
        start, end = line_range
        for line_number in range(start, min(end, len(lines)) + 1):
            line = lines[line_number - 1]
            list_item = _LIST_ITEM.match(line)
            if list_item is None or sections[line_number - 1] == "\x00":
                continue
            text = _normalize(list_item.group(2) or "")
            if not text:
                continue
            section = [part for part in sections[line_number - 1].split("/") if part]
            key = (relative, line_number, text)
            if key in criteria:
                continue
            occurrence = 1 + sum(
                1
                for prior in criteria.values()
                if prior["path"] == relative
                and prior["section_path"] == section
                and prior["text"] == text
            )
            criteria[key] = {
                "path": relative,
                "section_path": section,
                "line_start": line_number,
                "line_end": line_number,
                "occurrence": occurrence,
                "text": text,
                "sha256": _sha256(text.encode("utf-8")),
                "criterion_id": _criterion_id(relative, section, occurrence, text),
            }
    return list(criteria.values()), list(source_files.values())


def _row_applies_to_source(
    row: _MapRow,
    source_path: str,
    line_start: int,
    map_path: Path,
    prd_root: Path,
) -> bool:
    line_range = _source_line_range(row["source"])
    if line_range is not None and not line_range[0] <= line_start <= line_range[1]:
        return False
    raw = _normalize_source_reference(row["source"])
    if row["id"] == "REQ-0001" and raw.replace("\\", "/").endswith("inputs/INTAKE.yaml"):
        return source_path == "inputs/INTAKE.yaml"
    candidates: list[Path] = []
    source_path_obj = Path(raw)
    if source_path_obj.is_absolute():
        candidates.append(source_path_obj)
    else:
        candidates.append(map_path.parent / source_path_obj)
        candidates.append(prd_root / source_path_obj)
    actual = (prd_root / source_path).resolve()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.is_file() and resolved == actual:
            return True
        if resolved.is_dir():
            try:
                actual.relative_to(resolved)
                return True
            except ValueError:
                continue
    return False


def _is_candidate_row(row: _MapRow) -> bool:
    searchable = " ".join(
        [row["requirement"], row["owner"], row["disposition_reason"], *row["acceptance_criteria"]]
    )
    return bool(_GENERIC_UMBRELLA.search(searchable) or _CANDIDATE_FAMILY.search(searchable))


def _evidence_docs(
    path: Path,
    kind: str,
    root: Path | None = None,
    budget: _InputBudget | None = None,
) -> list[_EvidenceDoc]:
    raw = _read_bytes(path, budget)
    # Evidence is provenance only. Preserve its exact raw digest, while replacing
    # undecodable bytes so ASCII IDs and statuses remain searchable.
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    id_lines: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        ids = set(_CONTRACT_ID.findall(line))
        ids.update(_CONTRACT_LINE.findall(line))
        id_lines.extend((index, contract_id) for contract_id in sorted(ids))
    if kind == "HANDOFF" and root is not None:
        try:
            relative = path.resolve().relative_to(root.resolve())
        except (OSError, ValueError):
            relative = Path(path.name)
        if len(relative.parts) > 1:
            folder_id = relative.parts[0]
            if re.fullmatch(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+", folder_id):
                id_lines.append((0, folder_id))
    if not id_lines:
        return []

    # A single-contract document remains one evidence record. In a multi-contract
    # document, each contract owns the lines up to the next contract marker so
    # targets and statuses cannot bleed between unrelated rows.
    unique_ids = list(dict.fromkeys(contract_id for _, contract_id in id_lines))
    if len(unique_ids) == 1:
        spans = [(0, len(lines), unique_ids[0])]
    else:
        markers = sorted(id_lines)
        spans = []
        for marker_index, (start, contract_id) in enumerate(markers):
            end = markers[marker_index + 1][0] if marker_index + 1 < len(markers) else len(lines)
            if end <= start:
                continue
            spans.append((start, end, contract_id))

    result: list[_EvidenceDoc] = []
    for start, end, contract_id in spans:
        block = "\n".join(lines[start:end])
        targets = {value.rstrip(".,;:").replace("\\", "/") for value in _TARGET_LINE.findall(block)}
        targets.update(value.replace("\\", "/") for value in _REPO_PATH.findall(block))
        status = _STATUS_LINE.search(block)
        result.append(
            {
                "path": _rootless(path, relative_to=root),
                "sha256": _sha256(raw),
                "kind": kind,
                "text": block,
                "contract_ids": [contract_id],
                "target_paths": sorted(targets),
                "observed_status": status.group(1).upper() if status else "STATUS_NOT_STATED",
            }
        )
    return result


def _evidence_state(linked_docs: list[_EvidenceDoc]) -> str:
    statuses = {doc["observed_status"] for doc in linked_docs}
    kinds = {doc["kind"] for doc in linked_docs}
    if statuses and statuses <= {"CONTRACT_ONLY"}:
        return "CONTRACT_ONLY"
    has_acceptance = "HANDOFF" in kinds
    has_integration = "INTEGRATION_LOG" in kinds
    if has_acceptance and has_integration:
        return "ACCEPTANCE_AND_INTEGRATION_RECORDED"
    if has_acceptance:
        return "ACCEPTANCE_RECORDED"
    if has_integration:
        return "INTEGRATION_RECORDED"
    return "CONTRACT_ONLY"


def _input_fingerprint(inputs: list[SnapshotInputV1]) -> str:
    rows = [f"{item['path']}\t{item['sha256']}\n" for item in inputs]
    return _sha256("".join(rows).encode("utf-8"))


def _add_finding(
    grouped: dict[str, dict[str, set[str]]],
    code: str,
    *,
    criterion_ids: Sequence[str] = (),
    map_ids: Sequence[str] = (),
    contract_ids: Sequence[str] = (),
    source_paths: Sequence[str] = (),
) -> None:
    entry = grouped.setdefault(
        code,
        {"criterion_ids": set(), "map_ids": set(), "contract_ids": set(), "source_paths": set()},
    )
    entry["criterion_ids"].update(criterion_ids)
    entry["map_ids"].update(map_ids)
    entry["contract_ids"].update(contract_ids)
    entry["source_paths"].update(source_paths)


def build_coverage_snapshot(
    *,
    requirements_map_path: Path,
    prd_root: Path,
    integrations_log_path: Path,
    handoffs_root: Path,
) -> CoverageSnapshotV1:
    """Read explicit inputs and return a deterministic v1 coverage snapshot."""
    map_path = Path(requirements_map_path)
    prd_base = Path(prd_root)
    integration_path = Path(integrations_log_path)
    handoff_base = Path(handoffs_root)
    proposal_root = map_path.parent / "architecture" / "proposals"
    if not map_path.is_file() or not integration_path.is_file():
        _fail("INPUT_NOT_FOUND")
    if not prd_base.is_dir() or not handoff_base.is_dir():
        _fail("INPUT_NOT_FOUND")
    try:
        map_path = map_path.resolve(strict=True)
        prd_base = prd_base.resolve(strict=True)
        integration_path = integration_path.resolve(strict=True)
        handoff_base = handoff_base.resolve(strict=True)
    except OSError:
        _fail("INPUT_NOT_FOUND")

    budget = _InputBudget()
    map_raw, rows = _load_map(map_path, budget)
    all_criteria: list[_SourceCriterion] = []
    source_files: list[tuple[str, Path, bytes]] = []
    try:
        markdown_paths = _bounded_walk(prd_base, suffixes={".md"})
    except OSError:
        _fail("SOURCE_INVENTORY_INVALID")
    for path in markdown_paths:
        if path.is_symlink():
            _fail("SOURCE_INVENTORY_INVALID")
        raw = _read_bytes(path, budget)
        relative = path.relative_to(prd_base).as_posix()
        source_files.append((relative, path, raw))
        all_criteria.extend(_parse_markdown(path, relative, raw))

    anchored_criteria, anchored_files = _parse_anchored_source_criteria(
        rows, map_path, prd_base, budget
    )
    seen_source_lines = {(item["path"], item["line_start"], item["text"]) for item in all_criteria}
    all_criteria.extend(
        item
        for item in anchored_criteria
        if (item["path"], item["line_start"], item["text"]) not in seen_source_lines
    )
    source_files.extend(anchored_files)

    intake_criteria: list[_SourceCriterion] = []
    intake_path = map_path.parent / "inputs" / "INTAKE.yaml"
    if any(row["id"] == "REQ-0001" for row in rows) and intake_path.is_file():
        intake_raw, intake_criteria = _parse_intake(intake_path, budget)
        source_files.append(("inputs/INTAKE.yaml", intake_path, intake_raw))
        all_criteria.extend(intake_criteria)

    integration_docs = _evidence_docs(integration_path, "INTEGRATION_LOG", budget=budget)
    handoff_paths = [
        path
        for path in _bounded_walk(handoff_base, suffixes={".md", ".markdown"})
        if path.relative_to(handoff_base).parts[0] != "GAUNTLET-MAP-REFRESH-001"
    ]
    handoff_docs = [
        doc
        for path in handoff_paths
        for doc in _evidence_docs(path, "HANDOFF", handoff_base, budget)
    ]
    evidence_docs = [*integration_docs, *handoff_docs]
    evidence_files: dict[tuple[str, str, str], _EvidenceDoc] = {}
    for doc in evidence_docs:
        key = (doc["path"], doc["sha256"], doc["kind"])
        aggregate = evidence_files.get(key)
        if aggregate is None:
            evidence_files[key] = {
                "path": doc["path"],
                "sha256": doc["sha256"],
                "kind": doc["kind"],
                "text": doc["text"],
                "contract_ids": list(doc["contract_ids"]),
                "target_paths": list(doc["target_paths"]),
                "observed_status": doc["observed_status"],
            }
        else:
            aggregate["text"] += "\n" + doc["text"]
            aggregate["contract_ids"] = sorted(
                set(aggregate["contract_ids"]) | set(doc["contract_ids"])
            )
            aggregate["target_paths"] = sorted(
                set(aggregate["target_paths"]) | set(doc["target_paths"])
            )
            if aggregate["observed_status"] != doc["observed_status"]:
                aggregate["observed_status"] = "STATUS_NOT_STATED"
    aggregate_evidence_docs = list(evidence_files.values())
    proposal_paths = (
        _bounded_walk(
            proposal_root, suffixes={".md", ".markdown", ".txt", ".yaml", ".yml", ".json"}
        )
        if proposal_root.is_dir()
        else []
    )
    contract_clause_cache: dict[Path, tuple[str, str, list[tuple[str, int, int]]]] = {}
    contract_input_entries: dict[str, str] = {}

    map_claims_by_text: dict[str, list[_MapRow]] = defaultdict(list)
    for row in rows:
        for text in row["acceptance_criteria"]:
            normalized = _normalize(text)
            if normalized:
                map_claims_by_text[normalized].append(row)

    candidate_rows_by_id = {row["id"] for row in rows if _is_candidate_row(row)}
    applies_cache: dict[tuple[str, str, int | None], bool] = {}

    def applies_to(row: _MapRow, criterion: _SourceCriterion) -> bool:
        line_range = _source_line_range(row["source"])
        line_key = criterion["line_start"] if line_range is not None else None
        key = (row["id"], criterion["path"], line_key)
        if key not in applies_cache:
            applies_cache[key] = _row_applies_to_source(
                row,
                criterion["path"],
                criterion["line_start"],
                map_path,
                prd_base,
            )
        return applies_cache[key]

    records: list[CriterionV1] = []
    unresolved_owners: list[UnresolvedOwnerV1] = []
    map_rows_with_source_criteria: set[str] = set()
    umbrella_map_ids: set[str] = set()
    exact_map_ids_by_criterion: dict[str, list[str]] = {}
    for criterion in all_criteria:
        exact_rows = [
            row
            for row in map_claims_by_text.get(criterion["text"], [])
            if applies_to(row, criterion)
        ]
        anchored_rows = [
            row
            for row in rows
            if _source_line_range(row["source"]) is not None and applies_to(row, criterion)
        ]
        umbrella_rows = [
            row for row in rows if row["id"] in candidate_rows_by_id and applies_to(row, criterion)
        ]
        matched_rows = sorted(
            {row["id"]: row for row in [*exact_rows, *anchored_rows, *umbrella_rows]}.values(),
            key=lambda row: row["id"],
        )
        exact_row_ids = {row["id"] for row in exact_rows}
        matched_rows.sort(key=lambda row: row["id"])
        map_ids = sorted({row["id"] for row in matched_rows})
        owners = sorted({row["owner"] for row in matched_rows if row["owner"]})
        targets = sorted({row["target_path"] for row in matched_rows if row["target_path"]})
        for row in matched_rows:
            map_rows_with_source_criteria.add(row["id"])
            if (
                row["id"] in {item["id"] for item in umbrella_rows}
                and row["id"] not in exact_row_ids
            ):
                umbrella_map_ids.add(row["id"])
        declared_contract_ids = sorted(
            {contract_id for row in matched_rows for contract_id in row["contract_ids"]}
        )
        target_linked_docs = [
            doc
            for doc in evidence_docs
            if doc["contract_ids"]
            and (
                not declared_contract_ids
                or bool(set(declared_contract_ids) & set(doc["contract_ids"]))
            )
            and any(
                target in doc["text"].replace("\\", "/") or target in doc["target_paths"]
                for target in targets
            )
        ]
        source_path_key = criterion["path"].replace("\\", "/").casefold()
        family_linked_docs = [
            doc
            for doc in aggregate_evidence_docs
            if _CANDIDATE_FAMILY.search(" ".join(doc["contract_ids"]))
            and source_path_key in doc["text"].replace("\\", "/").casefold()
        ]
        linked_docs = list(
            {
                (doc["path"], doc["sha256"], tuple(doc["contract_ids"])): doc
                for doc in [*target_linked_docs, *family_linked_docs]
            }.values()
        )
        contract_ids = sorted(
            set(declared_contract_ids) | {cid for doc in linked_docs for cid in doc["contract_ids"]}
        )
        if not contract_ids:
            contract_ids = ["NO_CONTRACT"]
            evidence_state = "NO_CONTRACT"
            evidence_refs: list[EvidenceRefV1] = []
        elif not linked_docs:
            evidence_state = "CONTRACT_ONLY"
            evidence_refs = []
        else:
            evidence_state = _evidence_state(linked_docs)
            evidence_refs = [
                {
                    "path": doc["path"],
                    "sha256": doc["sha256"],
                    "kind": doc["kind"],
                    "observed_status": doc["observed_status"],
                }
                for doc in linked_docs
            ]
            evidence_refs.sort(key=lambda item: (item["kind"], item["path"], item["sha256"]))

        contract_clause_refs: list[EvidenceRefV1] = []
        for contract_id in contract_ids:
            if contract_id == "NO_CONTRACT":
                continue
            for contract_path in proposal_paths:
                if contract_id.casefold() not in contract_path.stem.casefold():
                    continue
                cached = contract_clause_cache.get(contract_path)
                if cached is None:
                    contract_raw = budget.read(contract_path)
                    try:
                        contract_text = contract_raw.decode("utf-8")
                    except UnicodeError:
                        _fail("INPUT_UNREADABLE")
                    contract_hash = _sha256(contract_raw)
                    cached = (
                        contract_path.relative_to(map_path.parent).as_posix(),
                        contract_hash,
                        _contract_clauses(contract_text),
                    )
                    contract_clause_cache[contract_path] = cached
                    contract_input_entries[cached[0]] = contract_hash
                contract_display_path, contract_hash, clauses = cached
                for clause, line_start, line_end in clauses:
                    if not _clause_matches_criterion(
                        clause, criterion["text"], criterion["criterion_id"]
                    ):
                        continue
                    contract_clause_refs.append(
                        {
                            "path": contract_display_path,
                            "sha256": contract_hash,
                            "kind": "CONTRACT_CLAUSE",
                            "line_start": line_start,
                            "line_end": line_end,
                            "observed_status": "STATUS_NOT_STATED",
                        }
                    )
        evidence_refs.extend(contract_clause_refs)
        evidence_refs.sort(
            key=lambda item: (item["path"], item["kind"], item.get("line_start", 0), item["sha256"])
        )
        if contract_clause_refs:
            coverage_class = "COVERED_CRITERION"
        elif umbrella_rows or linked_docs or contract_ids != ["NO_CONTRACT"]:
            coverage_class = "CANDIDATE_UMBRELLA_ONLY"
        else:
            coverage_class = "NO_CONTRACT"
        record: CriterionV1 = {
            "criterion_id": criterion["criterion_id"],
            "source": {
                "path": criterion["path"],
                "section_path": criterion["section_path"],
                "line_start": criterion["line_start"],
                "line_end": criterion["line_end"],
                "occurrence": criterion["occurrence"],
            },
            "source_text": criterion["text"],
            "source_text_sha256": criterion["sha256"],
            "map_ids": map_ids,
            "owners": owners,
            "target_paths": targets,
            "contract_ids": contract_ids,
            "coverage_class": coverage_class,
            "evidence_state": evidence_state,
            "evidence_refs": evidence_refs,
        }
        records.append(record)
        exact_map_ids_by_criterion[record["criterion_id"]] = sorted(exact_row_ids)
        if matched_rows and any(
            not row["owner"] or _UNRESOLVED_OWNER.search(row["owner"]) for row in matched_rows
        ):
            unresolved_owners.append(
                {"criterion_id": record["criterion_id"], "map_ids": map_ids, "owners": owners}
            )

    map_id_set = {row["id"] for row in rows}
    referenced_map_ids: set[str] = set()
    for _relative, _path, raw in source_files:
        referenced_map_ids.update(_MAP_ID.findall(raw.decode("utf-8", errors="ignore")))
    for doc in evidence_docs:
        referenced_map_ids.update(_MAP_ID.findall(doc["text"]))
    stale_map_ids = referenced_map_ids - map_id_set

    findings_grouped: dict[str, dict[str, set[str]]] = {}
    for record in records:
        if record["coverage_class"] in {"NO_CONTRACT", "CANDIDATE_UMBRELLA_ONLY"}:
            _add_finding(
                findings_grouped,
                record["coverage_class"],
                criterion_ids=[record["criterion_id"]],
                map_ids=record["map_ids"],
                contract_ids=[
                    contract_id
                    for contract_id in record["contract_ids"]
                    if contract_id != "NO_CONTRACT"
                ]
                or (["NO_CONTRACT"] if record["coverage_class"] == "NO_CONTRACT" else []),
                source_paths=[record["source"]["path"]],
            )
        if not record["map_ids"]:
            _add_finding(
                findings_grouped,
                "SOURCE_WITHOUT_MAP",
                criterion_ids=[record["criterion_id"]],
                source_paths=[record["source"]["path"]],
            )
        exact_map_ids = exact_map_ids_by_criterion.get(record["criterion_id"], [])
        if len(exact_map_ids) > 1:
            _add_finding(
                findings_grouped,
                "DUPLICATE_CLAIM",
                criterion_ids=[record["criterion_id"]],
                map_ids=exact_map_ids,
                source_paths=[record["source"]["path"]],
            )
    for row_id in stale_map_ids:
        _add_finding(
            findings_grouped,
            "STALE_MAP_ID",
            map_ids=[row_id],
        )
    for row_id in umbrella_map_ids:
        row = next(item for item in rows if item["id"] == row_id)
        _add_finding(
            findings_grouped,
            "UMBRELLA_ONLY_MAP_ID",
            map_ids=[row_id],
            source_paths=[_normalize_source_reference(row["source"])],
        )

    matched_targets = {
        row["target_path"]
        for row in rows
        if row["id"] in map_rows_with_source_criteria and row["target_path"]
    }
    for doc in evidence_docs:
        orphan_targets = [target for target in doc["target_paths"] if target not in matched_targets]
        if orphan_targets and doc["contract_ids"]:
            _add_finding(
                findings_grouped,
                "CONTRACT_WITHOUT_SOURCE_CRITERION",
                contract_ids=doc["contract_ids"],
                source_paths=orphan_targets,
            )

    findings: list[FindingV1] = []
    for code, values in findings_grouped.items():
        findings.append(
            {
                "code": code,
                "criterion_ids": sorted(values["criterion_ids"]),
                "map_ids": sorted(values["map_ids"]),
                "contract_ids": sorted(values["contract_ids"]),
                "source_paths": sorted(values["source_paths"]),
            }
        )
    findings.sort(key=lambda item: item["code"])
    records.sort(
        key=lambda item: (
            item["source"]["path"],
            item["source"]["line_start"],
            item["criterion_id"],
        )
    )
    unresolved_owners.sort(key=lambda item: item["criterion_id"])

    input_entries: dict[str, str] = {}
    input_entries[_rootless(map_path)] = _sha256(map_raw)
    input_entries[_rootless(integration_path)] = _sha256(budget.read(integration_path))
    for relative, _path, raw in source_files:
        input_entries[relative] = _sha256(raw)
    for doc in handoff_docs:
        input_entries[doc["path"]] = doc["sha256"]
    input_entries.update(contract_input_entries)
    inputs: list[SnapshotInputV1] = [
        {"path": path, "sha256": digest} for path, digest in sorted(input_entries.items())
    ]
    per_file_counts: list[PerFileCountV1] = []
    counts_by_path = Counter(record["source"]["path"] for record in records)
    input_hashes = {item["path"]: item["sha256"] for item in inputs}
    for source_path in sorted(counts_by_path):
        per_file_counts.append(
            {
                "path": source_path,
                "source_criterion_count": counts_by_path[source_path],
                "sha256": input_hashes.get(source_path, _sha256(b"")),
            }
        )
    report: CoverageSnapshotV1 = {
        "schema_version": "gauntlet.coverage-snapshot.v1",
        "snapshot": {"inputs": inputs, "input_fingerprint_sha256": _input_fingerprint(inputs)},
        "summary": {
            "source_criterion_count": len(records),
            "no_contract_count": sum(
                1 for record in records if record["coverage_class"] == "NO_CONTRACT"
            ),
            "coverage_class_counts": {
                coverage_class: sum(
                    1 for record in records if record["coverage_class"] == coverage_class
                )
                for coverage_class in _COVERAGE_CLASSES
            },
            "stale_map_id_count": len(stale_map_ids),
            "umbrella_only_map_id_count": len(umbrella_map_ids),
            "per_file_source_criteria": per_file_counts,
            "unresolved_owners": unresolved_owners,
        },
        "criteria": records,
        "findings": findings,
    }
    return report


def render_coverage_snapshot(report: CoverageSnapshotV1) -> str:
    """Serialize a snapshot deterministically without timestamps or host paths."""
    try:
        return json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    except (TypeError, ValueError):
        _fail("SNAPSHOT_INVALID")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements-map", required=True, type=Path)
    parser.add_argument("--prd-root", required=True, type=Path)
    parser.add_argument("--integrations-log", required=True, type=Path)
    parser.add_argument("--handoffs-root", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_coverage_snapshot(
            requirements_map_path=args.requirements_map,
            prd_root=args.prd_root,
            integrations_log_path=args.integrations_log,
            handoffs_root=args.handoffs_root,
        )
        rendered = render_coverage_snapshot(report)
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            try:
                args.output.write_text(rendered, encoding="utf-8", newline="\n")
            except OSError:
                _fail("OUTPUT_UNWRITABLE")
        return 0
    except CoverageRefreshError as exc:
        sys.stderr.write(f"error_code: {exc.code}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
