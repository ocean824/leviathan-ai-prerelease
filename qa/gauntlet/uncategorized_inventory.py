"""Offline inventory of explicit acceptance criteria in uncategorized PRDs.

The inventory is evidence, not a release verdict. It never changes source PRDs,
the requirements map, integration records, or Gauntlet release evidence.

Resource ceilings: 4,096 visited directories and 8,192 entries per recursive
walk; at most 512 discovered PRD Markdown files; 2 MiB per input and 16 MiB
aggregate input bytes; 50,000 map rows and 64 levels of map nesting.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - workspace dependency
    raise RuntimeError("PyYAML is required for the requirements map") from exc


class InventoryError(Exception):
    """Content-free input or output failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_HEADING = re.compile(r"^\s{0,3}(#{1,6})[ \t]+(.+?)\s*#*\s*$")
_PLAIN_HEADING = re.compile(
    r"^\s{0,3}(Acceptance(?: criteria| signals(?:\s*\([^)]*\))?)?|"
    r"Out of scope|Edge cases|User-facing flows|Scope(?: & behavior)?)\s*:?\s*$",
    re.IGNORECASE,
)
_LIST_ITEM = re.compile(r"^(?P<indent>\s{0,8})(?:[-*+]\s+|\d+[.)]\s+)(?P<text>\S.*)?$")
_FENCE = re.compile(r"^\s{0,3}(?P<fence>\`{3,}|~{3,})")
_OWNER_UNKNOWN = re.compile(r"\b(?:unassigned|unknown|tbd)\b|owner\s+remains\s+open", re.IGNORECASE)
_ID_TOKEN = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3}\b")
_ACCEPTANCE_HEADING = re.compile(
    r"^acceptance(?:\s+criteria|\s+signals(?:\s*\([^)]*\))?)?$", re.IGNORECASE
)
_EVIDENCE_STATUS = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?(?:verdict|status)(?:\*\*)?\s*:\s*([^#\r\n|]+)"
)
_STATUS_LITERAL = re.compile(
    r"\b(PASS-WITH-FIXES|CHANGES REQUESTED|APPROVED|PASS|BLOCKED|PARTIAL|"
    r"INTEGRATED|IN PROGRESS|NOT STARTED|UNKNOWN)\b",
    re.IGNORECASE,
)
_CONSTRAINT_HEADING = re.compile(
    r"^(?:key behaviors?\s*&\s*constraints|constraints)$", re.IGNORECASE
)
_MAX_WALK_DIRECTORIES = 4096
_MAX_WALK_FILES = 8192
_MAX_SOURCE_MARKDOWN_FILES = 512
_MAX_INPUT_FILE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_INPUT_BYTES = 16 * 1024 * 1024
_MAX_MAP_ROWS = 50_000
_MAX_MAP_DEPTH = 64


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalized(text: str) -> str:
    return " ".join(text.split())


def _coverage_normalized(text: str) -> str:
    """Normalize text for exact criterion-to-contract-clause comparisons."""
    value = unicodedata.normalize("NFC", _normalized(text)).casefold()
    while value and unicodedata.category(value[-1]).startswith("P"):
        value = value[:-1].rstrip()
    return value


def _contract_clauses(text: str) -> list[tuple[str, int, int]]:
    """Return normalized whole bullets, sentences, and table cells with line anchors."""
    lines = text.splitlines()
    clauses: list[tuple[str, int, int]] = []
    paragraph: list[tuple[int, str]] = []

    def flush_paragraph() -> None:
        if not paragraph:
            return
        joined_parts: list[str] = []
        line_spans: list[tuple[int, int, int]] = []
        offset = 0
        for line_number, line_text in paragraph:
            if joined_parts:
                offset += 1
            start = offset
            joined_parts.append(line_text)
            offset += len(line_text)
            line_spans.append((start, offset, line_number))
        joined = " ".join(joined_parts)
        for match in re.finditer(r"[^.!?]+(?:[.!?]+|$)", joined):
            raw_clause = match.group(0).strip()
            normalized = _coverage_normalized(raw_clause)
            if not normalized:
                continue
            touched = [
                line_number
                for start, end, line_number in line_spans
                if end > match.start() and start < match.end()
            ]
            if touched:
                clauses.append((normalized, min(touched), max(touched)))
        paragraph.clear()

    index = 0
    fence: tuple[str, int] | None = None
    while index < len(lines):
        line = lines[index]
        fence_match = _FENCE.match(line)
        if fence_match:
            flush_paragraph()
            marker = fence_match.group("fence")
            if fence is None:
                fence = (marker[0], len(marker))
            elif marker[0] == fence[0] and len(marker) >= fence[1]:
                fence = None
            index += 1
            continue
        if fence is not None:
            index += 1
            continue
        if not line.strip():
            flush_paragraph()
            index += 1
            continue
        if _HEADING.match(line) or _PLAIN_HEADING.match(line):
            flush_paragraph()
            index += 1
            continue
        list_match = _LIST_ITEM.match(line)
        if list_match:
            flush_paragraph()
            start = index + 1
            end = start
            indent = len(list_match.group("indent"))
            parts = [list_match.group("text") or ""]
            cursor = index + 1
            while cursor < len(lines):
                continuation = lines[cursor]
                if not continuation.strip() or _LIST_ITEM.match(continuation):
                    break
                if _HEADING.match(continuation) or _PLAIN_HEADING.match(continuation):
                    break
                continuation_indent = len(continuation) - len(continuation.lstrip())
                if continuation_indent <= indent:
                    break
                parts.append(continuation.strip())
                end = cursor + 1
                cursor += 1
            normalized = _coverage_normalized(" ".join(parts))
            if normalized:
                clauses.append((normalized, start, end))
            index = max(index + 1, cursor)
            continue
        if "|" in line:
            flush_paragraph()
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if not cells or all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells if cell):
                index += 1
                continue
            for cell in cells:
                normalized = _coverage_normalized(cell)
                if normalized and not re.fullmatch(r":?-{3,}:?", cell):
                    clauses.append((normalized, index + 1, index + 1))
            index += 1
            continue
        paragraph.append((index + 1, line.strip()))
        index += 1
    flush_paragraph()
    return clauses


def _clause_matches_criterion(clause: str, criterion_text: str, criterion_id: str) -> bool:
    normalized_clause = _coverage_normalized(clause)
    if normalized_clause == _coverage_normalized(criterion_text):
        return True
    return bool(
        criterion_id
        and re.search(
            rf"(?<![A-Za-z0-9_-]){re.escape(criterion_id)}(?![A-Za-z0-9_-])",
            clause,
            re.IGNORECASE,
        )
    )


def _safe_read(path: Path, code: str) -> bytes:
    try:
        if path.stat().st_size > _MAX_INPUT_FILE_BYTES:
            raise InventoryError("INPUT_TOO_LARGE")
        with path.open("rb") as stream:
            raw = stream.read(_MAX_INPUT_FILE_BYTES + 1)
        if len(raw) > _MAX_INPUT_FILE_BYTES:
            raise InventoryError("INPUT_TOO_LARGE")
        return raw
    except InventoryError:
        raise
    except (OSError, ValueError):
        raise InventoryError(code) from None


def _bounded_walk(directory: Path, *, file_limit: int, suffix: str | None = None) -> list[Path]:
    """Walk without following directory symlinks and stop at documented ceilings."""
    found: list[Path] = []
    directory_count = 0
    file_count = 0

    def failed(_error: OSError) -> None:
        raise InventoryError("SOURCE_ROOT_INVALID") from None

    try:
        for current, children, names in os.walk(directory, topdown=True, onerror=failed):
            directory_count += 1
            if directory_count > _MAX_WALK_DIRECTORIES:
                raise InventoryError("INPUT_TOO_LARGE")
            children[:] = sorted(
                name for name in children if not (Path(current) / name).is_symlink()
            )
            for name in sorted(names):
                file_count += 1
                if file_count > _MAX_WALK_FILES:
                    raise InventoryError("INPUT_TOO_LARGE")
                if (Path(current) / name).is_symlink():
                    raise InventoryError("SOURCE_ROOT_INVALID")
                if suffix is None or name.lower().endswith(suffix.lower()):
                    found.append(Path(current) / name)
                    if len(found) > file_limit:
                        raise InventoryError("INPUT_TOO_LARGE")
    except InventoryError:
        raise
    except OSError:
        raise InventoryError("SOURCE_ROOT_INVALID") from None
    return found


def _source_directory(source_root: Path) -> Path:
    try:
        root = source_root.resolve(strict=True)
    except OSError:
        raise InventoryError("SOURCE_ROOT_INVALID") from None
    if not root.is_dir():
        raise InventoryError("SOURCE_ROOT_INVALID")
    candidates = (root / ".codespring" / "PRDs" / "uncategorized", root / "PRDs" / "uncategorized")
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise InventoryError("SOURCE_ROOT_INVALID")


def _markdown_files(source_root: Path) -> list[Path]:
    directory = _source_directory(source_root)
    files = sorted(
        (
            path
            for path in _bounded_walk(
                directory, file_limit=_MAX_SOURCE_MARKDOWN_FILES, suffix=".md"
            )
            if path.is_file()
        ),
        key=lambda path: path.relative_to(source_root).as_posix(),
    )
    if not files:
        raise InventoryError("SOURCE_ROOT_INVALID")
    return files


def _heading_title(line: str) -> tuple[int, str] | None:
    match = _HEADING.match(line)
    if match:
        return len(match.group(1)), _normalized(match.group(2)).rstrip("# ").strip()
    plain = _PLAIN_HEADING.match(line)
    if plain:
        return 0, _normalized(plain.group(1)).rstrip(":")
    return None


def _parse_criteria(
    path: Path, source_root: Path, raw_bytes: bytes | None = None
) -> list[dict[str, Any]]:
    raw = raw_bytes if raw_bytes is not None else _safe_read(path, "SOURCE_UNREADABLE")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise InventoryError("SOURCE_UNREADABLE") from None
    lines = text.splitlines()

    headings: list[tuple[int, int, list[str]]] = []
    stack: list[tuple[int, str]] = []
    fence: tuple[str, int] | None = None
    for index, line in enumerate(lines):
        fence_match = _FENCE.match(line)
        if fence_match:
            marker = fence_match.group("fence")
            if fence is None:
                fence = (marker[0], len(marker))
            elif marker[0] == fence[0] and len(marker) >= fence[1]:
                fence = None
            continue
        if fence is not None:
            continue
        found = _heading_title(line)
        if found is None:
            continue
        level, title = found
        if level == 0:
            level = max(2, stack[-1][0]) if stack else 1
        while stack and stack[-1][0] >= level:
            stack.pop()
        stack.append((level, title))
        if _ACCEPTANCE_HEADING.fullmatch(title):
            headings.append((index, level, [part for _, part in stack]))
    if fence is not None:
        raise InventoryError("MALFORMED_MARKDOWN")

    result: list[dict[str, Any]] = []
    occurrence_counts: Counter[tuple[tuple[str, ...], str]] = Counter()
    relative = path.relative_to(source_root).as_posix()
    for heading_index, level, section_path in headings:
        end = len(lines)
        for cursor in range(heading_index + 1, len(lines)):
            if _FENCE.match(lines[cursor]):
                continue
            next_heading = _heading_title(lines[cursor])
            if next_heading is None:
                continue
            next_level, _ = next_heading
            if next_level == 0:
                next_level = 1
            if next_level <= level:
                end = cursor
                break

        current_start: int | None = None
        current_indent = 0
        parts: list[str] = []
        last_line = 0

        def finish(line_end: int, section_path: list[str] = section_path) -> None:
            nonlocal current_start, current_indent, parts, last_line
            if current_start is not None:
                criterion_text = _normalized(" ".join(parts))
                if not criterion_text:
                    raise InventoryError("MALFORMED_MARKDOWN")
                key = (tuple(section_path), criterion_text)
                occurrence_counts[key] += 1
                occurrence = occurrence_counts[key]
                canonical = f"{relative}\n{'/'.join(section_path)}\n{occurrence}\n{criterion_text}"
                result.append(
                    {
                        "criterion_id": f"CRIT-{_sha256(canonical.encode('utf-8'))}",
                        "source": {
                            "path": relative,
                            "section_path": list(section_path),
                            "line_start": current_start,
                            "line_end": line_end,
                            "occurrence": occurrence,
                        },
                        "source_text_sha256": _sha256(criterion_text.encode("utf-8")),
                        "_normalized_text": criterion_text,
                    }
                )
            current_start = None
            current_indent = 0
            parts = []

        in_section_fence: tuple[str, int] | None = None
        for line_index in range(heading_index + 1, end):
            line = lines[line_index]
            fence_match = _FENCE.match(line)
            if fence_match:
                marker = fence_match.group("fence")
                if in_section_fence is None:
                    in_section_fence = (marker[0], len(marker))
                elif marker[0] == in_section_fence[0] and len(marker) >= in_section_fence[1]:
                    in_section_fence = None
                continue
            if in_section_fence is not None:
                continue
            if _heading_title(line) is not None:
                finish(last_line)
                continue
            item = _LIST_ITEM.match(line)
            if item:
                finish(last_line)
                item_text = item.group("text") or ""
                if not _normalized(item_text):
                    raise InventoryError("MALFORMED_MARKDOWN")
                current_start = line_index + 1
                current_indent = len(item.group("indent"))
                parts = [item_text]
                last_line = line_index + 1
                continue
            if current_start is not None:
                if not line.strip():
                    finish(last_line)
                elif line[:1].isspace() and len(line) - len(line.lstrip()) > current_indent:
                    parts.append(line.strip())
                    last_line = line_index + 1
                elif line.strip().startswith(("<!--", "|")):
                    finish(last_line)
                else:
                    parts.append(line.strip())
                    last_line = line_index + 1
        if in_section_fence is not None:
            raise InventoryError("MALFORMED_MARKDOWN")
        finish(last_line)
    return result


def _parse_out_of_scope_constraints(
    path: Path, source_root: Path, raw_bytes: bytes
) -> list[dict[str, Any]]:
    """Record leaf constraint bullets outside acceptance sections, without source text."""
    try:
        lines = raw_bytes.decode("utf-8").splitlines()
    except UnicodeError:
        raise InventoryError("SOURCE_UNREADABLE") from None

    sections: list[tuple[int, int, list[str]]] = []
    heading_stack: list[tuple[int, str]] = []
    fence: tuple[str, int] | None = None
    for index, line in enumerate(lines):
        fence_match = _FENCE.match(line)
        if fence_match:
            marker = fence_match.group("fence")
            if fence is None:
                fence = (marker[0], len(marker))
            elif marker[0] == fence[0] and len(marker) >= fence[1]:
                fence = None
            continue
        if fence is not None:
            continue
        found = _heading_title(line)
        if found is None:
            continue
        level, title = found
        if level == 0:
            level = max(2, heading_stack[-1][0]) if heading_stack else 1
        while heading_stack and heading_stack[-1][0] >= level:
            heading_stack.pop()
        heading_stack.append((level, title))
        path_titles = [part for _, part in heading_stack]
        if _CONSTRAINT_HEADING.fullmatch(title) and not any(
            _ACCEPTANCE_HEADING.fullmatch(part) for part in path_titles[:-1]
        ):
            sections.append((index, level, path_titles))
    if fence is not None:
        raise InventoryError("MALFORMED_MARKDOWN")

    relative = path.relative_to(source_root).as_posix()
    output: list[dict[str, Any]] = []
    occurrences: Counter[tuple[tuple[str, ...], str]] = Counter()
    for heading_index, level, section_path in sections:
        end = len(lines)
        for cursor in range(heading_index + 1, len(lines)):
            if _FENCE.match(lines[cursor]):
                continue
            next_heading = _heading_title(lines[cursor])
            if next_heading is None:
                continue
            next_level, _ = next_heading
            if next_level == 0:
                next_level = 1
            if next_level <= level:
                end = cursor
                break

        entries: list[dict[str, Any]] = []
        stack: list[dict[str, Any]] = []
        in_fence: tuple[str, int] | None = None
        for line_index in range(heading_index + 1, end):
            line = lines[line_index]
            fence_match = _FENCE.match(line)
            if fence_match:
                marker = fence_match.group("fence")
                if in_fence is None:
                    in_fence = (marker[0], len(marker))
                elif marker[0] == in_fence[0] and len(marker) >= in_fence[1]:
                    in_fence = None
                continue
            if in_fence is not None:
                continue
            if _heading_title(line) is not None:
                continue
            list_item = _LIST_ITEM.match(line)
            if list_item:
                indent = len(list_item.group("indent"))
                while stack and stack[-1]["indent"] >= indent:
                    stack.pop()
                text = _normalized(list_item.group("text") or "")
                if not text:
                    raise InventoryError("MALFORMED_MARKDOWN")
                entry = {
                    "indent": indent,
                    "text": text,
                    "line_start": line_index + 1,
                    "line_end": line_index + 1,
                    "has_children": False,
                }
                if stack:
                    stack[-1]["has_children"] = True
                entries.append(entry)
                stack.append(entry)
            elif stack and line.strip():
                stack[-1]["text"] = _normalized(f"{stack[-1]['text']} {line.strip()}")
                stack[-1]["line_end"] = line_index + 1
        if in_fence is not None:
            raise InventoryError("MALFORMED_MARKDOWN")
        for entry in entries:
            if entry["has_children"]:
                continue
            statement = entry["text"]
            key = (tuple(section_path), statement)
            occurrences[key] += 1
            output.append(
                {
                    "classification": "OUT_OF_SCOPE_CONSTRAINT",
                    "source": {
                        "path": relative,
                        "section_path": list(section_path),
                        "line_start": entry["line_start"],
                        "line_end": entry["line_end"],
                        "occurrence": occurrences[key],
                    },
                    "source_text_sha256": _sha256(statement.encode("utf-8")),
                }
            )
    output.sort(
        key=lambda item: (
            item["source"]["path"],
            tuple(item["source"]["section_path"]),
            item["source"]["line_start"],
            item["source"]["occurrence"],
        )
    )
    return output


def _load_map(
    path: Path, raw: bytes | None = None
) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
    raw = raw if raw is not None else _safe_read(path, "MAP_INVALID")
    try:
        document = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError, RecursionError):
        raise InventoryError("MAP_INVALID") from None
    if not isinstance(document, dict) or not isinstance(document.get("requirements", []), list):
        raise InventoryError("MAP_INVALID")
    rows: list[dict[str, Any]] = []

    def visit(items: list[Any], depth: int = 0) -> None:
        if depth > _MAX_MAP_DEPTH:
            raise InventoryError("INPUT_TOO_LARGE")
        for item in items:
            if not isinstance(item, dict):
                raise InventoryError("MAP_INVALID")
            rows.append(item)
            if len(rows) > _MAX_MAP_ROWS:
                raise InventoryError("INPUT_TOO_LARGE")
            children = item.get("children", [])
            if children is not None:
                if not isinstance(children, list):
                    raise InventoryError("MAP_INVALID")
                visit(children, depth + 1)

    visit(document.get("requirements", []))
    return raw, document, rows


def _as_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _contract_ids_for_row(row: Mapping[str, Any], proposal_files: Sequence[Path]) -> list[str]:
    explicit = _as_strings(row.get("contract_ids"))
    owner_text = " ".join(_as_strings(row.get("owner")))
    candidate_ids = set(explicit) | set(_ID_TOKEN.findall(owner_text))
    if not proposal_files or not candidate_ids:
        return []
    existing: set[str] = set()
    for path in proposal_files:
        stem = path.stem.upper()
        for contract_id in candidate_ids:
            if contract_id.upper() in stem:
                existing.add(contract_id)
    return sorted(existing)


def _is_area_umbrella(row: Mapping[str, Any]) -> bool:
    disposition = " ".join(_as_strings(row.get("disposition_reason")))
    acceptance = " ".join(_as_strings(row.get("acceptance_criteria")))
    return bool(
        re.search(r"area\s+umbrella", disposition, re.IGNORECASE)
        or re.search(r"every current PRD acceptance item", acceptance, re.IGNORECASE)
    )


def _slug_tokens(value: str) -> set[str]:
    normalized = value.lower().replace("mt4mt5", "mt4 mt5")
    return set(re.findall(r"[a-z0-9]+", normalized))


def _area_rows_for_source(
    source_path: Path, map_rows: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    stem = re.sub(r"^(?:backend|database|frontend)-prd-", "", source_path.stem, flags=re.I)
    source_key = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")
    source_tokens = _slug_tokens(stem)
    matches: list[dict[str, Any]] = []
    for row in map_rows:
        if not _is_area_umbrella(row):
            continue
        source_field = row.get("source")
        if not isinstance(source_field, str):
            continue
        area_slug = source_field.replace("\\", "/").rstrip("/").split("/")[-1]
        area_key = re.sub(r"[^a-z0-9]+", "-", area_slug.lower()).strip("-")
        if area_key and (area_key in source_key or source_key in area_key):
            matches.append(row)
            continue
        area_tokens = _slug_tokens(area_slug)
        requirement_tokens = _slug_tokens(str(row.get("requirement", "")))
        # MT export bridge PRDs are the current source family for the EA-builder
        # umbrella; both platform markers plus the export term are required.
        if (
            {"mt4", "mt5"}.issubset(source_tokens)
            and {"mt4", "mt5"}.issubset(area_tokens)
            and "export" in source_tokens
            and "export" in requirement_tokens
        ):
            matches.append(row)
    return matches


def _status_from_text(text: str, identifiers: set[str]) -> str:
    lines = text.splitlines()
    matching = [
        index
        for index, line in enumerate(lines)
        if any(_has_identifier(line, token) for token in identifiers)
    ]
    for index in matching:
        direct_status = _STATUS_LITERAL.search(lines[index])
        if direct_status:
            return direct_status.group(1).upper()
        heading = _HEADING.match(lines[index])
        if heading and any(_has_identifier(lines[index], token) for token in identifiers):
            level = len(heading.group(1))
            for candidate in lines[index + 1 :]:
                next_heading = _HEADING.match(candidate)
                if next_heading and len(next_heading.group(1)) <= level:
                    break
                match = _EVIDENCE_STATUS.search(candidate)
                if match:
                    literal = _STATUS_LITERAL.search(match.group(1))
                    if literal:
                        return literal.group(1).upper()
            continue
        for cursor in range(max(0, index - 4), min(len(lines), index + 5)):
            line = lines[cursor]
            if cursor != index and (
                _HEADING.match(line)
                or (
                    _ID_TOKEN.search(line)
                    and not any(_has_identifier(line, token) for token in identifiers)
                )
            ):
                continue
            match = _EVIDENCE_STATUS.search(line)
            if match:
                literal = _STATUS_LITERAL.search(match.group(1))
                if literal:
                    return literal.group(1).upper()
    return "STATUS_NOT_STATED"


def _has_identifier(text: str, identifier: str) -> bool:
    return (
        re.search(rf"(?<![A-Z0-9]){re.escape(identifier)}(?![A-Z0-9])", text, re.IGNORECASE)
        is not None
    )


def _display_path(path: Path, source_root: Path, project_root: Path) -> str:
    resolved = path.resolve()
    for root in (source_root.resolve(), project_root.resolve()):
        try:
            return resolved.relative_to(root).as_posix()
        except ValueError:
            pass
    parts = resolved.parts
    if "epics" in parts:
        index = parts.index("epics")
        return Path(*parts[index:]).as_posix()
    return f"external/{resolved.name}"


def _evidence_ref(
    path: Path,
    source_root: Path,
    project_root: Path,
    kind: str,
    raw: bytes,
    text: str,
    identifiers: set[str],
) -> dict[str, str]:
    return {
        "path": _display_path(path, source_root, project_root),
        "sha256": _sha256(raw),
        "kind": kind,
        "observed_status": _status_from_text(text, identifiers),
    }


def build_inventory(
    *,
    source_root: Path,
    map_path: Path,
    integrations_log_path: Path,
    handoff_paths: Sequence[Path] = (),
) -> dict[str, Any]:
    """Build a deterministic, hash-bound snapshot from current inputs."""
    try:
        source_root = Path(source_root).resolve(strict=True)
    except OSError:
        raise InventoryError("SOURCE_ROOT_INVALID") from None
    map_path = Path(map_path)
    integrations_log_path = Path(integrations_log_path)
    handoffs = tuple(Path(path) for path in handoff_paths)
    total_input_bytes = 0

    def read_input(path: Path, code: str) -> bytes:
        nonlocal total_input_bytes
        raw = _safe_read(path, code)
        total_input_bytes += len(raw)
        if total_input_bytes > _MAX_TOTAL_INPUT_BYTES:
            raise InventoryError("INPUT_TOO_LARGE")
        return raw

    files = _markdown_files(source_root)
    source_raw: dict[Path, bytes] = {}
    for path in files:
        source_raw[path] = read_input(path, "SOURCE_UNREADABLE")
    map_raw = read_input(map_path, "MAP_INVALID")
    _, map_document, map_rows = _load_map(map_path, map_raw)
    project_root = map_path.parent
    proposal_root = project_root / "architecture" / "proposals"
    proposal_files = (
        _bounded_walk(proposal_root, file_limit=_MAX_WALK_FILES) if proposal_root.is_dir() else []
    )
    area_candidates_by_file = {path: _area_rows_for_source(path, map_rows) for path in files}
    contract_id_cache: dict[int, list[str]] = {}

    def row_contract_ids(row: dict[str, Any]) -> list[str]:
        key = id(row)
        if key not in contract_id_cache:
            contract_id_cache[key] = _contract_ids_for_row(row, proposal_files)
        return contract_id_cache[key]

    try:
        integrations_raw = read_input(integrations_log_path, "INTEGRATION_LOG_INVALID")
        integrations_text = integrations_raw.decode("utf-8")
    except (OSError, UnicodeError):
        raise InventoryError("INTEGRATION_LOG_INVALID") from None
    handoff_text: dict[Path, str] = {}
    handoff_raw: dict[Path, bytes] = {}
    for path in handoffs:
        try:
            handoff_raw[path] = read_input(path, "HANDOFF_INVALID")
            handoff_text[path] = handoff_raw[path].decode("utf-8")
        except (OSError, UnicodeError):
            raise InventoryError("HANDOFF_INVALID") from None

    repo_root = project_root / "repo"
    criteria: list[dict[str, Any]] = []
    out_of_scope_constraints: list[dict[str, Any]] = []
    contract_raw: dict[Path, bytes] = {}
    for file_path in files:
        out_of_scope_constraints.extend(
            _parse_out_of_scope_constraints(file_path, source_root, source_raw[file_path])
        )
        for item in _parse_criteria(file_path, source_root, source_raw[file_path]):
            normalized_text = item.pop("_normalized_text")
            exact_rows: list[dict[str, Any]] = []
            for row in map_rows:
                values = row.get("acceptance_criteria", [])
                if isinstance(values, str):
                    values = [values]
                if not isinstance(values, list):
                    continue
                if any(
                    isinstance(value, str) and _normalized(value) == normalized_text
                    for value in values
                ):
                    exact_rows.append(row)

            candidate_rows = area_candidates_by_file[file_path]
            rows_by_object_id = {id(row): row for row in (*exact_rows, *candidate_rows)}
            linked_rows = list(rows_by_object_id.values())

            map_ids = sorted(
                {str(row["id"]) for row in linked_rows if isinstance(row.get("id"), str)}
            )
            owners = sorted(
                {owner for row in linked_rows for owner in _as_strings(row.get("owner"))}
            )
            contract_ids = sorted(
                {contract for row in linked_rows for contract in row_contract_ids(row)}
            )
            target_paths: set[str] = set()
            for row in linked_rows:
                target = row.get("implementation_target")
                if isinstance(target, str) and target.strip():
                    target_path = target.replace("\\", "/")
                    if (repo_root / target_path).is_file():
                        target_paths.add(target_path)

            criterion_contracts: list[tuple[Path, bytes, str]] = []
            if contract_ids:
                for path in proposal_files:
                    stem = path.stem.upper()
                    if not any(contract.upper() in stem for contract in contract_ids):
                        continue
                    if path.suffix.lower() not in {".md", ".txt", ".yaml", ".yml", ".json"}:
                        continue
                    if path not in contract_raw:
                        contract_raw[path] = read_input(path, "CONTRACTS_INVALID")
                    try:
                        contract_text = contract_raw[path].decode("utf-8")
                    except UnicodeError:
                        raise InventoryError("CONTRACTS_INVALID") from None
                    criterion_contracts.append((path, contract_raw[path], contract_text))

            refs: list[dict[str, Any]] = []
            identifiers = set(contract_ids) | set(map_ids)
            normalized_evidence = [
                (integrations_log_path, integrations_text, integrations_raw, "INTEGRATION_LOG"),
                *[
                    (path, text, handoff_raw[path], "HANDOFF")
                    for path, text in handoff_text.items()
                ],
            ]
            for evidence_path, evidence_text, evidence_bytes, evidence_kind in normalized_evidence:
                if any(
                    _has_identifier(evidence_text, identifier) for identifier in identifiers
                ) or (normalized_text in _normalized(evidence_text)):
                    refs.append(
                        _evidence_ref(
                            evidence_path,
                            source_root,
                            project_root,
                            evidence_kind,
                            evidence_bytes,
                            evidence_text,
                            identifiers,
                        )
                    )
            contract_clause_refs: list[dict[str, Any]] = []
            criterion_id = item["criterion_id"]
            for contract_path, contract_bytes, contract_text in criterion_contracts:
                for clause_text, line_start, line_end in _contract_clauses(contract_text):
                    if not _clause_matches_criterion(clause_text, normalized_text, criterion_id):
                        continue
                    contract_clause_refs.append(
                        {
                            "path": _display_path(contract_path, source_root, project_root),
                            "sha256": _sha256(contract_bytes),
                            "kind": "CONTRACT_CLAUSE",
                            "line_start": line_start,
                            "line_end": line_end,
                            "observed_status": "STATUS_NOT_STATED",
                        }
                    )
            refs.extend(contract_clause_refs)
            refs.sort(key=lambda ref: (ref["path"], ref["kind"], ref["sha256"]))

            if contract_clause_refs:
                coverage_class = "COVERED_CRITERION"
            elif candidate_rows or exact_rows or contract_ids or refs:
                coverage_class = "CANDIDATE_UMBRELLA_ONLY"
            else:
                coverage_class = "NO_CONTRACT"

            contract_list = contract_ids if contract_ids else ["NO_CONTRACT"]
            has_integration = any(ref["kind"] == "INTEGRATION_LOG" for ref in refs)
            has_acceptance = any(
                ref["kind"] == "HANDOFF"
                and ref["observed_status"] != "STATUS_NOT_STATED"
                and re.search(r"acceptance", handoff_text[path], re.IGNORECASE)
                for path in handoffs
                for ref in refs
                if ref["path"] == _display_path(path, source_root, project_root)
            )
            if has_integration and has_acceptance:
                state = "ACCEPTANCE_AND_INTEGRATION_RECORDED"
            elif has_acceptance:
                state = "ACCEPTANCE_RECORDED"
            elif has_integration:
                state = "INTEGRATION_RECORDED"
            elif contract_ids:
                state = "CONTRACT_ONLY"
            else:
                state = "NO_CONTRACT"

            criteria.append(
                {
                    **item,
                    "coverage_class": coverage_class,
                    "map_ids": map_ids,
                    "contract_ids": contract_list,
                    "owners": owners,
                    "target_paths": sorted(target_paths),
                    "evidence_state": state,
                    "evidence_refs": refs,
                }
            )

    criteria.sort(key=lambda item: item["criterion_id"])
    unresolved_owners = [
        {
            "criterion_id": item["criterion_id"],
            "map_ids": item["map_ids"],
            "owners": item["owners"],
        }
        for item in criteria
        if item["map_ids"]
        and (not item["owners"] or any(_OWNER_UNKNOWN.search(owner) for owner in item["owners"]))
    ]
    unresolved_owners.sort(key=lambda item: item["criterion_id"])

    grouped: dict[str, dict[str, set[str]]] = {}

    def group(code: str) -> dict[str, set[str]]:
        return grouped.setdefault(
            code,
            {
                "criterion_ids": set(),
                "map_ids": set(),
                "contract_ids": set(),
                "source_paths": set(),
            },
        )

    by_map: dict[str, list[dict[str, Any]]] = {}
    for item in criteria:
        if not item["map_ids"]:
            group("SOURCE_WITHOUT_MAP")["criterion_ids"].add(item["criterion_id"])
            group("SOURCE_WITHOUT_MAP")["source_paths"].add(item["source"]["path"])
        for map_id in item["map_ids"]:
            by_map.setdefault(map_id, []).append(item)
        if item["coverage_class"] == "CANDIDATE_UMBRELLA_ONLY" and item["map_ids"]:
            for row in map_rows:
                if row.get("id") not in item["map_ids"]:
                    continue
                if _is_area_umbrella(row):
                    group("GENERIC_UMBRELLA_ONLY")["criterion_ids"].add(item["criterion_id"])
                    group("GENERIC_UMBRELLA_ONLY")["map_ids"].update(item["map_ids"])
                    group("GENERIC_UMBRELLA_ONLY")["contract_ids"].update(
                        contract for contract in item["contract_ids"] if contract != "NO_CONTRACT"
                    )
                    group("GENERIC_UMBRELLA_ONLY")["source_paths"].add(item["source"]["path"])
    rows_by_id = {row.get("id"): row for row in map_rows if isinstance(row.get("id"), str)}
    for item in criteria:
        for map_id in item["map_ids"]:
            row = rows_by_id.get(map_id, {})
            target = row.get("implementation_target")
            if (
                isinstance(target, str)
                and target.strip()
                and target.replace("\\", "/") not in item["target_paths"]
            ):
                group("STALE_MAP_ID")["criterion_ids"].add(item["criterion_id"])
                group("STALE_MAP_ID")["map_ids"].add(map_id)
                group("STALE_MAP_ID")["source_paths"].add(item["source"]["path"])
    for map_id, mapped in by_map.items():
        if _is_area_umbrella(rows_by_id.get(map_id, {})):
            continue
        if len(mapped) > 1:
            group("DUPLICATE_CLAIM")["criterion_ids"].update(
                item["criterion_id"] for item in mapped
            )
            group("DUPLICATE_CLAIM")["map_ids"].add(map_id)
            group("DUPLICATE_CLAIM")["contract_ids"].update(
                contract
                for item in mapped
                for contract in item["contract_ids"]
                if contract != "NO_CONTRACT"
            )
            group("DUPLICATE_CLAIM")["source_paths"].update(
                item["source"]["path"] for item in mapped
            )

    findings = [
        {
            "code": code,
            "criterion_ids": sorted(value["criterion_ids"]),
            "map_ids": sorted(value["map_ids"]),
            "contract_ids": sorted(value["contract_ids"]),
            "source_paths": sorted(value["source_paths"]),
        }
        for code, value in sorted(grouped.items())
    ]

    input_hashes: dict[str, str] = {
        _display_path(map_path, source_root, project_root): _sha256(map_raw),
        _display_path(integrations_log_path, source_root, project_root): _sha256(integrations_raw),
    }
    for path in files:
        input_hashes[_display_path(path, source_root, project_root)] = _sha256(source_raw[path])
    for path in handoffs:
        input_hashes[_display_path(path, source_root, project_root)] = _sha256(handoff_raw[path])
    for path, raw in contract_raw.items():
        input_hashes[_display_path(path, source_root, project_root)] = _sha256(raw)
    snapshot_inputs = [
        {"path": path, "sha256": digest} for path, digest in sorted(input_hashes.items())
    ]

    counts = Counter(item["source"]["path"] for item in criteria)
    class_names = (
        "COVERED_CRITERION",
        "CANDIDATE_UMBRELLA_ONLY",
        "NO_CONTRACT",
    )
    coverage_class_counts = Counter(item["coverage_class"] for item in criteria)
    per_file_class_counts: dict[str, Counter[str]] = {}
    for item in criteria:
        per_file_class_counts.setdefault(item["source"]["path"], Counter())[
            item["coverage_class"]
        ] += 1
    out_of_scope_counts = Counter(item["source"]["path"] for item in out_of_scope_constraints)
    summary = {
        "map_version": str(map_document.get("version", "VERSION_NOT_STATED")),
        "source_criterion_scope": "acceptance_sections_only",
        "source_criterion_count": len(criteria),
        "coverage_class_counts": {name: coverage_class_counts[name] for name in class_names},
        "no_contract_count": coverage_class_counts["NO_CONTRACT"],
        "per_file_criterion_counts": [
            {
                "path": path.relative_to(source_root).as_posix(),
                "count": counts[path.relative_to(source_root).as_posix()],
                "coverage_class_counts": {
                    name: per_file_class_counts.get(
                        path.relative_to(source_root).as_posix(), Counter()
                    )[name]
                    for name in class_names
                },
            }
            for path in files
        ],
        "out_of_scope_constraint_count": len(out_of_scope_constraints),
        "per_file_out_of_scope_constraint_counts": [
            {
                "path": path.relative_to(source_root).as_posix(),
                "count": out_of_scope_counts[path.relative_to(source_root).as_posix()],
            }
            for path in files
        ],
        "unresolved_owners": unresolved_owners,
        "finding_count": len(findings),
    }
    return {
        "schema_version": "gauntlet.coverage-snapshot.v2",
        "snapshot": {"inputs": snapshot_inputs},
        "summary": summary,
        "criteria": criteria,
        "out_of_scope_constraints": out_of_scope_constraints,
        "findings": findings,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inventory current uncategorized PRD acceptance criteria."
    )
    parser.add_argument(
        "--source-root", type=Path, required=True, help="Current CodeSpring checkout root."
    )
    parser.add_argument(
        "--map", dest="map_path", type=Path, required=True, help="Current Requirements Map YAML."
    )
    parser.add_argument(
        "--integrations-log", type=Path, required=True, help="Authoritative integrations log."
    )
    parser.add_argument("--handoff", dest="handoffs", type=Path, action="append", default=[])
    parser.add_argument(
        "--output", type=Path, help="Optional caller-selected disposable JSON output path."
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = build_inventory(
            source_root=args.source_root,
            map_path=args.map_path,
            integrations_log_path=args.integrations_log,
            handoff_paths=args.handoffs,
        )
        payload = (
            json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        )
        if args.output is None:
            sys.stdout.write(payload)
            return 0
        try:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
        except OSError:
            raise InventoryError("OUTPUT_INVALID") from None
        return 0
    except InventoryError as exc:
        sys.stderr.write(f"{exc.code}\n")
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised by CLI users
    raise SystemExit(main())
