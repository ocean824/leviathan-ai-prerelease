"""Offline, fail-closed structural and provenance checks for the Leviathan vault.

This is a local data validator. It neither executes note content nor contacts services.
All public failures contain a fixed reason code and, when available, a file index.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Never, SupportsIndex, cast
from urllib.parse import unquote, urlsplit

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node

MAX_MARKDOWN_BYTES: Final = 5 * 1024 * 1024
MAX_FRONTMATTER_BYTES: Final = 64 * 1024
MAX_CORPUS_BYTES: Final = 32 * 1024 * 1024
MAX_VAULT_BYTES: Final = 8 * 1024 * 1024
MAX_FILES: Final = 10_000
MAX_VAULT_ENTRIES: Final = 64
MAX_UTC_NS: Final = 253_402_300_799_999_999_999
ARCHIVE_SHA256: Final = "6f5237ff0dcbefd8ef0f120d81af2a702ef90ec29b78dac062bc285b894ea1e0"
SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z", re.ASCII)
SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
BAD_LINE_SEPARATOR = re.compile(r"[\v\f\x1c-\x1e\x85\u2028\u2029]")
SOURCE_PART = re.compile(r"[A-Za-z0-9_.-]+\Z", re.ASCII)
INLINE_LINK = re.compile(r"!?\[[^\[\]\r\n]*\]\(([^()\r\n]+)\)")
WIKILINK = re.compile(r"!?\[\[([^\[\]\r\n]+)\]\]")
ANGLE_LINK = re.compile(r"<([^<>\r\n]+)>")
HTML_TAG = re.compile(
    r"<(?:!--|![^<>]*>|\?[^<>]*\?>|/?[A-Za-z][A-Za-z0-9-]*(?=[\s/>])[^<>]*>)"
)
HTML_LINE_START = re.compile(
    r"(?m)^[ \t]*(?:(?:>[ \t]*)|(?:(?:[-*+]|[0-9]{1,9}[.)])[ \t]+))*"
    r"</?[A-Za-z][A-Za-z0-9-]*(?=[ \t/\r>]|$)"
)
HTML_ATTRIBUTE = re.compile(r"\b(?:href|src)\s*=", re.IGNORECASE)
HTML_FRAGMENT = re.compile(r"<[A-Za-z/!?]")
CONTAINER_PREFIX = r"(?:[ \t]{0,3}(?:>[ \t]*|(?:[-*+]|[0-9]{1,9}[.)])[ \t]+))*"
NONROOT_FENCE = re.compile(
    r"^[ \t]*(?:(?:>[ \t]*|[-*+][ \t]+|[0-9]{1,9}[.)][ \t]+))*(`{3,}|~{3,})"
)
REFERENCE_DEF = re.compile(
    r"(?m)^" + CONTAINER_PREFIX
    + r"[ \t]{0,3}\[([^\]\r\n]+)\]:[ \t]*(?:<([^<>\r\n]+)>|([^\s\r\n]+))[ \t]*$"
)
REFERENCE_CANDIDATE = re.compile(
    r"(?m)^[ \t]*(?:(?:>[ \t]*)|(?:(?:[-*+]|[0-9]{1,9}[.)])[ \t]+))*"
    r"\[[^\r\n]+\]:"
)
FULL_REFERENCE = re.compile(r"!?\[([^\[\]\r\n]+)\]\[([^\[\]\r\n]*)\]")
SHORT_REFERENCE = re.compile(r"!?\[([^\[\]\r\n]+)\]")
BARE_EXTERNAL = re.compile(r"(?i)(?<![A-Za-z0-9_])(?:https?://|ftp://|file://|mailto:|www\.)")
EXTERNAL_HTTPS_HOSTS: Final = frozenset[str]()
SECTIONS: Final = {
    "research": "research",
    "strategies": "strategy",
    "market-structure": "market-structure",
    "trade-journal": "trade-journal",
    "post-mortems": "post-mortem",
    "source-lineage": "source-lineage",
}
SEED_PATHS: Final = frozenset(
    (
        "research/research--source-quality-gates.md",
        "strategies/strategy--risk-gated-hypothesis.md",
        "market-structure/market-structure--source-freshness.md",
        "source-lineage/source-lineage--revision-chain.md",
    )
)
ALLOWED_DIRECTORIES: Final = frozenset((*SECTIONS, "schema", "tools", "templates"))
ALLOWED_FILES: Final = {
    "README.md": "markdown",
    "vault-map.md": "markdown",
    "schema/note.schema.json": "json",
    "schema/vault-rules.json": "json",
    "tools/validate_vault.py": "python",
    **{f"{section}/index.md": "markdown" for section in SECTIONS},
    **{name: "markdown" for name in SEED_PATHS},
    **{f"templates/{kind}.md": "markdown" for kind in SECTIONS.values()},
}
NOTE_TYPES: Final = frozenset((*SECTIONS.values(), "moc", "index"))
TRUST_LABELS: Final = frozenset(
    ("project-source", "operator-authored", "external-untrusted", "agent-generated-unreviewed")
)
NOTE_KEYS: Final = frozenset(
    (
        "schema_version", "note_id", "note_type", "title", "status", "trust_label",
        "created_at_utc_ns", "updated_at_utc_ns", "ingest", "methodology", "asset",
        "regime", "tags", "source_refs", "related_note_ids",
    )
)
REQUIRED_KEYS: Final = NOTE_KEYS - {"tags", "related_note_ids"}


class VaultValidationError(Exception):
    """Typed, non-echoing validation failure."""

    def __init__(
        self, code: str, file_index: int | None = None, report: ValidationReport | None = None
    ) -> None:
        self.code = code
        self.file_index = file_index
        self.report = report
        super().__init__(code if file_index is None else f"{code}:{file_index}")


@dataclass(frozen=True)
class ValidationReport:
    markdown_files: int
    notes_checked: int
    source_refs_checked: int
    links_checked: int
    corpus_files: int
    match_count: int
    archive_sha256: str | None
    candidate_tree_sha256: str | None

    def __post_init__(self) -> None:
        for count in (
            self.markdown_files, self.notes_checked, self.source_refs_checked,
            self.links_checked, self.corpus_files, self.match_count,
        ):
            if type(count) is not int or count < 0:
                _fail("INVALID_SCHEMA")
        if self.archive_sha256 is not None and self.archive_sha256 != ARCHIVE_SHA256:
            _fail("INVALID_SCHEMA")
        if self.candidate_tree_sha256 is not None and (
            type(self.candidate_tree_sha256) is not str
            or SHA256.fullmatch(self.candidate_tree_sha256) is None
        ):
            _fail("INVALID_SCHEMA")

    def __copy__(self) -> Never:
        _fail("INVALID_SCHEMA")

    def __deepcopy__(self, memo: object) -> Never:
        _fail("INVALID_SCHEMA")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        _fail("INVALID_SCHEMA")


class _StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        if self.check_event(AliasEvent):  # type: ignore[no-untyped-call]
            raise VaultValidationError("YAML_INVALID")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise VaultValidationError("YAML_INVALID")
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if type(key) is not str or key in result:
                raise VaultValidationError("YAML_INVALID")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _fail(code: str, index: int | None = None) -> Never:
    raise VaultValidationError(code, index) from None


def _text(value: object, index: int, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value):
        _fail("INVALID_SCHEMA", index)
    result = value
    try:
        result.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail("INVALID_SCHEMA", index)
    return result


def _slug(value: object, index: int) -> str:
    if type(value) is not str or SLUG.fullmatch(value) is None:
        _fail("INVALID_ASCII_SLUG", index)
    return value


def _uuid(value: object, index: int) -> str:
    if type(value) is not str:
        _fail("INVALID_NOTE_ID", index)
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        _fail("INVALID_NOTE_ID", index)
    if str(parsed) != value:
        _fail("INVALID_NOTE_ID", index)
    return value


def _is_alias(path: Path) -> bool:
    entry = os.lstat(path)
    attributes = getattr(entry, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    junction = getattr(os.path, "isjunction", lambda _: False)
    return stat.S_ISLNK(entry.st_mode) or bool(attributes & reparse) or junction(path)


def _no_alias_ancestors(path: Path) -> None:
    for component in (*reversed(path.parents), path):
        if os.path.lexists(component) and _is_alias(component):
            _fail("INVALID_PATH")


def _safe_root(value: Path | str) -> Path:
    try:
        path = Path(value).absolute()
        _no_alias_ancestors(path)
        if not path.is_dir():
            _fail("INVALID_PATH")
        return path.resolve(strict=True)
    except (OSError, ValueError, TypeError):
        _fail("INVALID_PATH")


def _safe_child(root: Path, parts: tuple[str, ...], index: int, code: str) -> Path:
    if not parts or any(p in ("", ".", "..") or SOURCE_PART.fullmatch(p) is None for p in parts):
        _fail(code, index)
    candidate = root
    for part in parts:
        candidate = candidate / part
        if os.path.lexists(candidate) and _is_alias(candidate):
            _fail(code, index)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        _fail(code, index)
    if not resolved.is_file():
        _fail(code, index)
    return resolved


def _safe_corpus_file(root: Path, relative: str) -> Path:
    if not relative or relative.startswith("/") or "\\" in relative or "%" in relative:
        _fail("CORPUS_INCOMPLETE")
    parts = tuple(relative.split("/"))
    if any(part in ("", ".", "..") or ":" in part for part in parts):
        _fail("CORPUS_INCOMPLETE")
    try:
        relative.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail("CORPUS_INCOMPLETE")
    candidate = root
    for part in parts:
        candidate = candidate / part
        if candidate.exists() and _is_alias(candidate):
            _fail("CORPUS_INCOMPLETE")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        _fail("CORPUS_INCOMPLETE")
    if not resolved.is_file():
        _fail("CORPUS_INCOMPLETE")
    return resolved


def _read_bytes(path: Path, index: int, *, limit: int, code: str) -> bytes:
    try:
        if _is_alias(path) or os.lstat(path).st_size > limit:
            _fail(code, index)
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError:
        _fail(code, index)
    if len(data) > limit:
        _fail(code, index)
    return data


def _strict_json(data: bytes, code: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail(code)
            result[key] = value
        return result

    def constant(_: str) -> Never:
        _fail(code)

    try:
        loaded = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except (UnicodeError, ValueError):
        _fail(code)
    if type(loaded) is not dict:
        _fail(code)
    return cast(dict[str, Any], loaded)


def _frontmatter(data: bytes, index: int) -> tuple[dict[str, Any], str]:
    if not data.startswith((b"---\n", b"---\r\n")):
        _fail("YAML_INVALID", index)
    parts = re.split(rb"(\r\n|\r|\n)", data)
    lines = [parts[i] + parts[i + 1] for i in range(0, len(parts) - 1, 2)]
    if parts[-1]:
        lines.append(parts[-1])
    position = len(lines[0])
    closing = -1
    for line in lines[1:]:
        if line.rstrip(b"\r\n") == b"---":
            closing = position
            position += len(line)
            break
        position += len(line)
        if position > MAX_FRONTMATTER_BYTES:
            _fail("SIZE_LIMIT", index)
    if closing < 0:
        _fail("YAML_INVALID", index)
    try:
        raw = data[len(lines[0]):closing].decode("utf-8", errors="strict")
        body = data[position:].decode("utf-8", errors="strict")
        loaded = yaml.load(raw, Loader=_StrictLoader)
    except (UnicodeError, yaml.YAMLError, RecursionError):
        _fail("YAML_INVALID", index)
    if type(loaded) is not dict:
        _fail("YAML_INVALID", index)
    return cast(dict[str, Any], loaded), body


def _timestamp(value: object, index: int) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UTC_NS:
        _fail("INVALID_TIMESTAMP", index)
    return value


def _taxons(value: object, index: int) -> list[str]:
    if type(value) is not list:
        _fail("INVALID_SCHEMA", index)
    checked = [_slug(item, index) for item in cast(list[object], value)]
    if len(set(checked)) != len(checked):
        _fail("INVALID_SCHEMA", index)
    return checked


def _markdown_lines(text: str, *, keepends: bool = False) -> list[str]:
    parts = re.split(r"(\r\n|\r|\n)", text)
    if not keepends:
        return parts[::2]
    lines = [parts[i] + parts[i + 1] for i in range(0, len(parts) - 1, 2)]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def _visible_markdown(text: str) -> str:
    """Mask fenced code while retaining offsets for link consumption."""
    fence_char = ""
    fence_length = 0
    visible: list[str] = []
    prefix = ""
    for full_line in _markdown_lines(text, keepends=True):
        line = full_line.removesuffix("\r\n").removesuffix("\r").removesuffix("\n")
        fence = re.match(prefix + r"(`{3,}|~{3,})", line)
        if fence is not None:
            marker = fence.group(1)
            if fence_char and (
                marker[0] == fence_char and len(marker) >= fence_length
                and re.fullmatch(prefix + re.escape(marker) + r"[ \t]*", line)
            ):
                fence_char, fence_length = "", 0
            elif not fence_char and (marker[0] != "`" or "`" not in line[fence.end():]):
                fence_char, fence_length = marker[0], len(marker)
            if fence_char or marker[0] != "`" or "`" not in line[fence.end():]:
                visible.append(" " * len(line) + full_line[len(line):])
            else:
                visible.append(full_line)
        elif fence_char:
            visible.append(" " * len(line) + full_line[len(line):])
        else:
            visible.append(full_line)
    return "".join(visible)


def _reject_invalid_fences(text: str, index: int, code: str = "INVALID_FENCE") -> None:
    fence_char = ""
    fence_length = 0
    for line in _markdown_lines(text):
        if fence_char:
            closer = re.fullmatch(r"( {0,3})(`{3,}|~{3,})[ \t]*", line)
            if closer is not None:
                marker = closer.group(2)
                if marker[0] == fence_char and len(marker) >= fence_length:
                    if closer.group(1):
                        _fail(code, index)
                    fence_char, fence_length = "", 0
            continue
        fence = NONROOT_FENCE.match(line)
        if fence is not None:
            marker = fence.group(1)
            if marker[0] == "`" and "`" in line[fence.end():]:
                continue
            if fence.start(1) > 0:
                _fail(code, index)
            fence_char, fence_length = marker[0], len(marker)


def _source_anchors(lines: list[str]) -> set[str]:
    anchors: set[str] = set()
    for line in _markdown_lines(_visible_markdown("\n".join(lines))):
        atx = re.fullmatch(r" {0,3}#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*", line)
        if atx is not None:
            anchors.add(line.strip())
            anchors.add(atx.group(1).strip())
        if not line.startswith(("    ", "\t")):
            block = re.search(r"(?:^|\s)\^([A-Za-z0-9_-]+)[ \t]*$", line)
            if block is not None:
                anchors.add("^" + block.group(1))
    return anchors


def _source_ref(
    value: object, project_root: Path, codespring_root: Path, index: int,
) -> None:
    if type(value) is not dict or set(value) != {"authority_class", "locator", "section", "sha256"}:
        _fail("INVALID_SOURCE_REF", index)
    ref = cast(dict[str, object], value)
    authority = ref["authority_class"]
    locator = ref["locator"]
    section = ref["section"]
    digest = ref["sha256"]
    if type(authority) is not str or type(locator) is not str or type(digest) is not str:
        _fail("INVALID_SOURCE_REF", index)
    if type(section) is not str or not section or len(section) > 200:
        _fail("INVALID_SOURCE_REF", index)
    _text(section, index)
    if SHA256.fullmatch(digest) is None:
        _fail("INVALID_SOURCE_REF", index)
    if authority == "project-prd" and locator.startswith("codespring-prd://"):
        root, suffix = codespring_root, locator.removeprefix("codespring-prd://")
    elif authority in {"project-adr", "project-spec"} and locator.startswith("project://"):
        root, suffix = project_root, locator.removeprefix("project://")
    else:
        _fail("INVALID_SOURCE_REF", index)
    if "%" in suffix or "\\" in suffix or ":" in suffix:
        _fail("INVALID_SOURCE_REF", index)
    path = _safe_child(root, tuple(suffix.split("/")), index, "INVALID_SOURCE_REF")
    data = _read_bytes(path, index, limit=MAX_MARKDOWN_BYTES, code="INVALID_SOURCE_REF")
    if hashlib.sha256(data).hexdigest() != digest:
        _fail("SOURCE_HASH_MISMATCH", index)
    try:
        source_text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail("INVALID_SOURCE_REF", index)
    if BAD_LINE_SEPARATOR.search(source_text):
        _fail("INVALID_CHAR", index)
    lines = _markdown_lines(source_text)
    _reject_invalid_fences("\n".join(lines), index, "INVALID_SOURCE_REF")
    if section not in _source_anchors(lines):
        _fail("INVALID_SOURCE_REF", index)


def _walk_files(
    root: Path, *, max_entries: int = MAX_FILES,
    allowed_directories: frozenset[str] | None = None,
) -> list[Path]:
    files: list[Path] = []
    seen_case: set[str] = set()
    def walk_error(_: OSError) -> Never:
        _fail("INVALID_PATH")

    for current, dirs, names in os.walk(
        root, topdown=True, followlinks=False, onerror=walk_error
    ):
        for name in (*dirs, *names):
            child = Path(current) / name
            if _is_alias(child):
                _fail("INVALID_PATH")
            relative = child.relative_to(root).as_posix()
            try:
                relative.encode("utf-8", errors="strict")
            except UnicodeError:
                _fail("INVALID_ASCII_SLUG")
            folded = relative.casefold()
            if folded in seen_case:
                _fail("CASE_COLLISION")
            seen_case.add(folded)
            if len(seen_case) > max_entries:
                _fail("SIZE_LIMIT")
        if allowed_directories is not None:
            for name in dirs:
                if (Path(current) / name).relative_to(root).as_posix() not in allowed_directories:
                    _fail("INVALID_SCHEMA")
        for name in names:
            files.append(Path(current) / name)
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def _preflight_files(root: Path, files: list[Path]) -> None:
    """Bound the complete, closed candidate tree before any file is read."""
    if len(files) != len(ALLOWED_FILES):
        _fail("INVALID_SCHEMA")
    total = 0
    observed: set[str] = set()
    for path in files:
        name = path.relative_to(root).as_posix()
        kind = ALLOWED_FILES.get(name)
        if kind is None:
            _fail("INVALID_SCHEMA")
        observed.add(name)
        try:
            entry = os.lstat(path)
            if _is_alias(path) or not stat.S_ISREG(entry.st_mode):
                _fail("INVALID_PATH")
        except OSError:
            _fail("INVALID_PATH")
        limit = MAX_MARKDOWN_BYTES if kind == "markdown" else (
            MAX_FRONTMATTER_BYTES if kind == "json" else 256 * 1024
        )
        if entry.st_size > limit or entry.st_size < 0:
            _fail("SIZE_LIMIT")
        total += entry.st_size
        if total > MAX_VAULT_BYTES:
            _fail("SIZE_LIMIT")
    if observed != set(ALLOWED_FILES):
        _fail("INVALID_SCHEMA")


def _link_target(
    raw: str, note_path: Path, root: Path, known: set[str], index: int,
    *, wiki: bool = False,
) -> str | None:
    """Resolve one link without following aliases or leaving the closed vault."""
    target = raw.split("|", 1)[0] if wiki else raw
    if not target or target != target.strip():
        _fail("INVALID_LINK", index)
    if target.startswith("https://"):
        try:
            parsed = urlsplit(target)
            allowed = (
                parsed.hostname in EXTERNAL_HTTPS_HOSTS and parsed.username is None
                and parsed.password is None and parsed.port is None
            )
        except ValueError:
            allowed = False
        if not allowed:
            _fail("INVALID_LINK", index)
        return None
    if ":" in target or target.startswith("//"):
        _fail("INVALID_LINK", index)
    target = target.split("#", 1)[0]
    if wiki and target and not target.endswith(".md"):
        target += ".md"
    if not target:
        return note_path.relative_to(root).as_posix()
    target = unquote(target)
    if target.startswith("/") or any(char in target for char in ("\\", "\x00", "?", "%", ":")):
        _fail("LINK_ESCAPE", index)
    candidate = note_path.parent
    for part in target.split("/"):
        if part == "..":
            candidate = candidate.parent
        elif part and part != ".":
            candidate = candidate / part
            if os.path.lexists(candidate) and _is_alias(candidate):
                _fail("LINK_ESCAPE", index)
        try:
            candidate.relative_to(root)
        except ValueError:
            _fail("LINK_ESCAPE", index)
    lexical = candidate.relative_to(root).as_posix()
    folded = {item.casefold() for item in known}
    if lexical not in known and lexical.casefold() in folded:
        _fail("CASE_COLLISION", index)
    try:
        relative = candidate.resolve(strict=True).relative_to(root).as_posix()
    except ValueError:
        _fail("LINK_ESCAPE", index)
    except OSError:
        _fail("LINK_MISSING", index)
    if relative not in known:
        if relative.casefold() in folded:
            _fail("CASE_COLLISION", index)
        _fail("LINK_MISSING", index)
    return relative


def _links(
    body: str, note_path: Path, root: Path, known: set[str], index: int
) -> tuple[int, set[str]]:
    scan = _visible_markdown(body.replace("\r\n", "\n").replace("\r", "\n"))
    if HTML_TAG.search(scan) or HTML_LINE_START.search(scan) or HTML_ATTRIBUTE.search(scan):
        _fail("INVALID_LINK", index)
    remaining = list(scan)
    targets: set[str] = set()
    references: dict[str, str] = {}
    count = 0

    def consume(start: int, end: int) -> None:
        remaining[start:end] = " " * (end - start)

    def add(target: str, *, wiki: bool = False) -> None:
        nonlocal count
        resolved = _link_target(target, note_path, root, known, index, wiki=wiki)
        if resolved is not None:
            targets.add(resolved)
        count += 1

    for match in REFERENCE_DEF.finditer(scan):
        label = " ".join(match.group(1).casefold().split())
        if not label or label in references:
            _fail("INVALID_LINK", index)
        target = match.group(2) or match.group(3)
        references[label] = target
        _link_target(target, note_path, root, known, index)
        consume(*match.span())
    for match in WIKILINK.finditer("".join(remaining)):
        add(match.group(1), wiki=True)
        consume(*match.span())
    for match in INLINE_LINK.finditer("".join(remaining)):
        add(match.group(1))
        consume(*match.span())
    for match in FULL_REFERENCE.finditer("".join(remaining)):
        label = " ".join((match.group(2) or match.group(1)).casefold().split())
        if label not in references:
            _fail("INVALID_LINK", index)
        add(references[label])
        consume(*match.span())
    for match in ANGLE_LINK.finditer("".join(remaining)):
        add(match.group(1))
        consume(*match.span())
    for match in SHORT_REFERENCE.finditer("".join(remaining)):
        label = " ".join(match.group(1).casefold().split())
        if label not in references:
            _fail("INVALID_LINK", index)
        add(references[label])
        consume(*match.span())
    rest = "".join(remaining)
    if (
        "[" in rest or "]" in rest or HTML_FRAGMENT.search(rest)
        or REFERENCE_CANDIDATE.search(rest)
        or FULL_REFERENCE.search(rest)
        or ANGLE_LINK.search(rest)
        or BARE_EXTERNAL.search(rest)
    ):
        _fail("INVALID_LINK", index)
    return count, targets


def _note(
    metadata: dict[str, Any], relative: str, index: int, project_root: Path,
    codespring_root: Path,
) -> tuple[str, list[str], int]:
    if not metadata.keys() >= REQUIRED_KEYS or not metadata.keys() <= NOTE_KEYS:
        _fail("INVALID_SCHEMA", index)
    if type(metadata["schema_version"]) is not int or metadata["schema_version"] != 1:
        _fail("INVALID_SCHEMA", index)
    note_id = _uuid(metadata["note_id"], index)
    note_type = metadata["note_type"]
    if type(note_type) is not str or note_type not in NOTE_TYPES:
        _fail("INVALID_SCHEMA", index)
    if relative == "vault-map.md":
        expected = "moc"
    else:
        section, sep, name = relative.partition("/")
        if not sep or section not in SECTIONS:
            _fail("INVALID_ASCII_SLUG", index)
        _slug(section, index)
        if name == "index.md":
            expected = "index"
        else:
            expected = SECTIONS[section]
            if "/" in name or not name.startswith(expected + "--") or not name.endswith(".md"):
                _fail("INVALID_ASCII_SLUG", index)
            _slug(name[len(expected) + 2:-3], index)
    if note_type != expected:
        _fail("INVALID_SCHEMA", index)
    _text(metadata["title"], index)
    if type(metadata["status"]) is not str or metadata["status"] not in (
        "draft", "reviewed", "archived"
    ):
        _fail("INVALID_SCHEMA", index)
    if type(metadata["trust_label"]) is not str or metadata["trust_label"] not in TRUST_LABELS:
        _fail("INVALID_SCHEMA", index)
    created = _timestamp(metadata["created_at_utc_ns"], index)
    updated = _timestamp(metadata["updated_at_utc_ns"], index)
    if updated < created:
        _fail("INVALID_TIMESTAMP", index)
    if type(metadata["ingest"]) is not bool:
        _fail("INVALID_SCHEMA", index)
    if metadata["ingest"]:
        # Tenant approval is an external trusted policy; this template has no such port.
        _fail("INGEST_NOT_ALLOWED", index)
    for key in ("methodology", "asset", "regime"):
        _taxons(metadata[key], index)
    if "tags" in metadata:
        _taxons(metadata["tags"], index)
    refs = metadata["source_refs"]
    if type(refs) is not list:
        _fail("INVALID_SCHEMA", index)
    if (relative in SEED_PATHS or metadata["trust_label"] == "project-source") and (
        expected not in {"moc", "index"} and not refs
    ):
        _fail("INVALID_SOURCE_REF", index)
    if relative in SEED_PATHS and metadata["trust_label"] != "project-source":
        _fail("INVALID_SCHEMA", index)
    for ref in refs:
        _source_ref(ref, project_root, codespring_root, index)
    related = metadata.get("related_note_ids", [])
    if type(related) is not list:
        _fail("INVALID_SCHEMA", index)
    related_ids = [_uuid(item, index) for item in related]
    if len(set(related_ids)) != len(related_ids):
        _fail("INVALID_NOTE_ID", index)
    return note_id, related_ids, len(refs)


def _normalized(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _matching_span(candidate: str, source: str) -> bool:
    # A span is contiguous in the normalized text, with >=12 tokens and >=80 chars.
    tokens = candidate.split()
    if len(tokens) < 12:
        return False
    for start in range(len(tokens) - 11):
        end = start + 12
        length = sum(len(token) for token in tokens[start:end]) + 11
        while end < len(tokens) and length < 80:
            length += 1 + len(tokens[end])
            end += 1
        if length >= 80:
            span = " ".join(tokens[start:end])
            offset = source.find(span)
            while offset >= 0:
                before = offset == 0 or source[offset - 1] == " "
                after_at = offset + len(span)
                after = after_at == len(source) or source[after_at] == " "
                if before and after:
                    return True
                offset = source.find(span, offset + 1)
    return False


def _corpus_scan(
    candidates: list[bytes], corpus: Path, manifest_path: Path,
) -> tuple[int, int, str]:
    try:
        if _is_alias(manifest_path) or not manifest_path.is_file():
            _fail("CORPUS_INCOMPLETE")
    except OSError:
        _fail("CORPUS_INCOMPLETE")
    raw = _read_bytes(manifest_path, 0, limit=MAX_FRONTMATTER_BYTES, code="CORPUS_INCOMPLETE")
    manifest = _strict_json(raw, "CORPUS_INCOMPLETE")
    if (
        type(manifest.get("schema_version")) is not int
        or manifest["schema_version"] != 1
        or manifest.get("archive_sha256") != ARCHIVE_SHA256
        or manifest.get("coverage_complete") is not True
        or type(manifest.get("expected_text_entries")) is not int
        or type(manifest.get("entries")) is not list
        or type(manifest.get("extraction_failures")) is not list
        or manifest["extraction_failures"]
        or type(manifest.get("restricted_terms")) is not list
        or not manifest["restricted_terms"]
    ):
        _fail("CORPUS_INCOMPLETE")
    entries = manifest["entries"]
    if not entries or len(entries) != manifest["expected_text_entries"] or len(entries) > MAX_FILES:
        _fail("CORPUS_INCOMPLETE")
    terms = manifest["restricted_terms"]
    if any(type(term) is not str or not term.strip() for term in terms):
        _fail("CORPUS_INCOMPLETE")
    try:
        for term in terms:
            term.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail("CORPUS_INCOMPLETE")
    corpus_files = _walk_files(corpus)
    if len(corpus_files) != len(entries):
        _fail("CORPUS_INCOMPLETE")
    total_size = 0
    for path in corpus_files:
        try:
            entry = os.lstat(path)
            if _is_alias(path) or not stat.S_ISREG(entry.st_mode):
                _fail("CORPUS_INCOMPLETE")
        except OSError:
            _fail("CORPUS_INCOMPLETE")
        if entry.st_size > MAX_MARKDOWN_BYTES or entry.st_size < 0:
            _fail("CORPUS_INCOMPLETE")
        total_size += entry.st_size
        if total_size > MAX_CORPUS_BYTES:
            _fail("CORPUS_INCOMPLETE")
    observed: set[str] = set()
    source_texts: list[str] = []
    source_hashes: set[str] = set()
    total = 0
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"corpus_file", "sha256"}:
            _fail("CORPUS_INCOMPLETE")
        name, digest = entry["corpus_file"], entry["sha256"]
        if type(name) is not str or type(digest) is not str or SHA256.fullmatch(digest) is None:
            _fail("CORPUS_INCOMPLETE")
        if name in observed or "\\" in name or "%" in name:
            _fail("CORPUS_INCOMPLETE")
        observed.add(name)
        path = _safe_corpus_file(corpus, name)
        data = _read_bytes(path, 0, limit=MAX_MARKDOWN_BYTES, code="CORPUS_INCOMPLETE")
        total += len(data)
        if total > MAX_CORPUS_BYTES or hashlib.sha256(data).hexdigest() != digest:
            _fail("CORPUS_INCOMPLETE")
        source_hashes.add(digest)
        try:
            source_texts.append(_normalized(data.decode("utf-8", errors="strict")))
        except UnicodeError:
            _fail("CORPUS_INCOMPLETE")
    if observed != {p.relative_to(corpus).as_posix() for p in corpus_files}:
        _fail("CORPUS_INCOMPLETE")
    normalized_terms = [_normalized(cast(str, term)) for term in terms]
    matches = 0
    for candidate in candidates:
        try:
            candidate_text = candidate.decode("utf-8", errors="strict")
        except UnicodeError:
            _fail("INVALID_SCHEMA")
        normalized = _normalized(candidate_text)
        if hashlib.sha256(candidate).hexdigest() in source_hashes:
            matches += 1
        if any(term and term in normalized for term in normalized_terms):
            matches += 1
        for source_text in source_texts:
            if _matching_span(normalized, source_text):
                matches += 1
    return len(corpus_files), matches, ARCHIVE_SHA256


def validate_vault(
    root: Path | str,
    project_root: Path | str,
    codespring_root: Path | str,
    *,
    restricted_corpus: Path | str | None = None,
    coverage_manifest: Path | str | None = None,
) -> ValidationReport:
    """Validate the local vault; raise only typed, non-echoing failures."""
    try:
        vault = _safe_root(root)
        project = _safe_root(project_root)
        codespring = _safe_root(codespring_root)
        if (restricted_corpus is None) != (coverage_manifest is None):
            _fail("CORPUS_INCOMPLETE")
        files = _walk_files(
            vault, max_entries=MAX_VAULT_ENTRIES,
            allowed_directories=ALLOWED_DIRECTORIES,
        )
        _preflight_files(vault, files)
        contents: dict[str, bytes] = {}
        tree = hashlib.sha256()
        for path in files:
            relative = path.relative_to(vault).as_posix()
            kind = ALLOWED_FILES[relative]
            limit = MAX_MARKDOWN_BYTES if kind == "markdown" else (
                MAX_FRONTMATTER_BYTES if kind == "json" else 256 * 1024
            )
            data = _read_bytes(path, 0, limit=limit, code="SIZE_LIMIT")
            if kind == "python":
                try:
                    source_text = data.decode("utf-8", errors="strict")
                except UnicodeError:
                    _fail("INVALID_SCHEMA")
                if "\x00" in source_text:
                    _fail("INVALID_SCHEMA")
            contents[relative] = data
            tree.update(relative.encode("utf-8") + b"\0" + hashlib.sha256(data).digest())
        for config in ("schema/note.schema.json", "schema/vault-rules.json"):
            loaded = _strict_json(contents[config], "INVALID_SCHEMA")
            if (
                type(loaded) is not dict
                or type(loaded.get("schema_version")) is not int
                or loaded["schema_version"] != 1
            ):
                _fail("INVALID_SCHEMA")
        known_markdown = {name for name, kind in ALLOWED_FILES.items() if kind == "markdown"}
        markdown_paths = [vault / name for name in sorted(known_markdown)]
        ids: dict[str, int] = {}
        pending_related: list[tuple[int, list[str]]] = []
        link_targets: dict[str, set[str]] = {}
        index_bodies: dict[str, str] = {}
        notes = refs_checked = links_checked = 0
        for index, path in enumerate(markdown_paths, start=1):
            relative = path.relative_to(vault).as_posix()
            data = contents[relative]
            title_targets: set[str] = set()
            try:
                full_text = data.decode("utf-8", errors="strict")
            except UnicodeError:
                _fail("INVALID_SCHEMA", index)
            if BAD_LINE_SEPARATOR.search(full_text):
                _fail("INVALID_CHAR", index)
            _reject_invalid_fences(full_text, index)
            visible_text = _visible_markdown(full_text)
            if (
                HTML_TAG.search(visible_text) or HTML_LINE_START.search(visible_text)
                or HTML_ATTRIBUTE.search(visible_text)
            ):
                _fail("INVALID_LINK", index)
            if relative == "README.md":
                body = full_text
            elif relative.startswith("templates/") and not data.startswith(
                (b"---\n", b"---\r\n")
            ):
                # A template without properties is still excluded by its path.
                body = full_text
            else:
                metadata, body = _frontmatter(data, index)
                title = metadata.get("title")
                if type(title) is str:
                    title_count, title_targets = _links(title, path, vault, known_markdown, index)
                    links_checked += title_count
                if relative.startswith("templates/"):
                    if metadata.get("ingest") is not False:
                        _fail("INGEST_NOT_ALLOWED", index)
                else:
                    note_id, related, count = _note(metadata, relative, index, project, codespring)
                    if note_id in ids:
                        _fail("DUPLICATE_NOTE_ID", index)
                    ids[note_id] = index
                    pending_related.append((index, related))
                    refs_checked += count
                    notes += 1
                    if (
                        relative != "vault-map.md"
                        and not relative.endswith("/index.md")
                        and ("{{" in body or "}}" in body or "<TODO>" in body)
                    ):
                        _fail("TEMPLATE_MARKER", index)
            count, targets = _links(body, path, vault, known_markdown, index)
            links_checked += count
            targets.update(title_targets)
            link_targets[relative] = targets
            if relative.endswith("/index.md"):
                index_bodies[relative] = body
        for index, related in pending_related:
            if any(item not in ids for item in related):
                _fail("INVALID_NOTE_ID", index)
        if not {f"{section}/index.md" for section in SECTIONS} <= link_targets["vault-map.md"]:
            _fail("INVALID_LINK")
        for section in SECTIONS:
            local_notes = {
                name for name in known_markdown
                if name.startswith(section + "/") and name != f"{section}/index.md"
            }
            if not local_notes <= link_targets[f"{section}/index.md"]:
                _fail("INVALID_LINK")
            if not local_notes and "empty" not in index_bodies[f"{section}/index.md"].casefold():
                _fail("INVALID_SCHEMA")
        corpus_files = matches = 0
        archive_hash: str | None = None
        if restricted_corpus is not None and coverage_manifest is not None:
            corpus_files, matches, archive_hash = _corpus_scan(
                list(contents.values()), _safe_root(restricted_corpus), Path(coverage_manifest)
            )
            if matches:
                report = ValidationReport(
                    len(markdown_paths), notes, refs_checked, links_checked,
                    corpus_files, matches, archive_hash, tree.hexdigest(),
                )
                raise VaultValidationError("CORPUS_MATCH", report=report)
        return ValidationReport(
            len(markdown_paths), notes, refs_checked, links_checked,
            corpus_files, matches, archive_hash,
            tree.hexdigest() if restricted_corpus is not None else None,
        )
    except VaultValidationError:
        raise
    except Exception:
        raise VaultValidationError("INTERNAL_ERROR") from None


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise VaultValidationError("INVALID_SCHEMA")


def main(argv: list[str] | None = None) -> int:
    parser = _SafeArgumentParser(description="Offline vault validation")
    parser.add_argument("--root", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--codespring-root", required=True)
    parser.add_argument("--restricted-corpus")
    parser.add_argument("--coverage-manifest")
    parser.add_argument("--check", action="store_true")
    try:
        args = parser.parse_args(argv)
        if not args.check:
            _fail("INVALID_SCHEMA")
        report = validate_vault(
            args.root, args.project_root, args.codespring_root,
            restricted_corpus=args.restricted_corpus,
            coverage_manifest=args.coverage_manifest,
        )
    except VaultValidationError as exc:
        if exc.report is not None:
            print(json.dumps(exc.report.__dict__, sort_keys=True, separators=(",", ":")))
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report.__dict__, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
