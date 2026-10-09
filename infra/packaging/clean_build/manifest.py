"""Deterministic, hash-only source, provenance, and build manifests.

The snapshot and input checks decode supported UTF-8, UTF-16, and UTF-32 text
before using the shared credential-shape scanner. Unknown undecodable files fail
closed unless their suffix is explicitly allowlisted as binary. Binary outputs
are only hashed; binary secret scanning is a separate release gate. No function
in this module runs a build, script, installer, or other artifact.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from leviathan_core.text.credential_patterns import (
    MAX_CREDENTIAL_SCAN_CHARS,
    contains_credential_value,
)

SCHEMA_VERSION = "1.0.0"
SNAPSHOT_SCHEMA = "PKG-002-source-snapshot-1"
PROVENANCE_SCHEMA = "PKG-002-build-provenance-1"
LOCK_PATHS = (
    "apps/desktop/src-tauri/Cargo.lock",
    "apps/terminal/package-lock.json",
    "uv.lock",
)
LOCK_FILENAMES = frozenset({"Cargo.lock", "package-lock.json", "uv.lock"})
BUILDER_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "ARCH",
        "CARGO_BUILD_TARGET",
        "CI",
        "NODE_ENV",
        "OS",
        "RUSTFLAGS",
        "SOURCE_DATE_EPOCH",
    }
)
SNAPSHOT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "node_modules",
    }
)
# Only these known non-text source/input formats may bypass text decoding. This
# is intentionally closed: an unknown undecodable file is ambiguous and fails.
BINARY_FILE_EXTENSIONS = frozenset({".der", ".ico", ".png", ".woff2"})
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.ASCII)
_PATH_COMPONENT_RE = re.compile(r"[A-Za-z0-9._@+-]+\Z", re.ASCII)
_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_SENSITIVE_NAME_RE = re.compile(
    r"(?:secret|token|password|credential|api[_-]?key|authorization)", re.I
)
_WINDOWS_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul", "conin$", "conout$"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class ManifestError(ValueError):
    """Manifest or file evidence is malformed; messages never contain contents."""


class CredentialScanError(ManifestError):
    """Shared scanner detected credential-shaped text; only the relative path is named."""


@dataclass(frozen=True, slots=True)
class FileHashV1:
    """Hash and size of one regular file, named by a portable relative path."""

    path: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        _validate_relative_path(self.path)
        if type(self.sha256) is not str or _SHA256_RE.fullmatch(self.sha256) is None:
            raise ManifestError("invalid file digest")
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ManifestError("invalid file size")


@dataclass(frozen=True, slots=True)
class SourceSnapshotManifestV1:
    """Complete hash inventory of a source snapshot under the standard exclusions."""

    files: tuple[FileHashV1, ...]
    manifest_sha256: str = ""
    schema_version: str = SNAPSHOT_SCHEMA

    def __post_init__(self) -> None:
        _validate_rows("snapshot", self.files)
        if self.schema_version != SNAPSHOT_SCHEMA:
            raise ManifestError("unsupported source snapshot schema")
        expected = _source_snapshot_digest(self.files)
        if self.manifest_sha256 and self.manifest_sha256 != expected:
            raise ManifestError("source snapshot digest mismatch")
        object.__setattr__(self, "manifest_sha256", expected)


@dataclass(frozen=True, slots=True)
class BuildProvenanceV1:
    """Non-secret, deterministic provenance for a single build invocation."""

    source_snapshot_manifest_sha256: str
    lock_files: tuple[FileHashV1, ...]
    toolchain_versions: tuple[tuple[str, str], ...]
    build_commands: tuple[str, ...]
    normalized_timestamps: tuple[tuple[str, str], ...]
    builder_environment: tuple[tuple[str, str], ...]
    provenance_sha256: str = ""
    schema_version: str = PROVENANCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != PROVENANCE_SCHEMA:
            raise ManifestError("unsupported provenance schema")
        if _SHA256_RE.fullmatch(self.source_snapshot_manifest_sha256) is None:
            raise ManifestError("invalid provenance source identity")
        _validate_rows("provenance lock", self.lock_files)
        if not self.lock_files or any(
            Path(row.path).name not in LOCK_FILENAMES for row in self.lock_files
        ):
            raise ManifestError("invalid provenance lock inventory")
        for label, values in (
            ("toolchain", self.toolchain_versions),
            ("normalized timestamp", self.normalized_timestamps),
            ("builder environment", self.builder_environment),
        ):
            if type(values) is not tuple or not values:
                raise ManifestError(f"invalid {label} metadata")
            names = tuple(name for name, _ in values if type(name) is str)
            if (
                len(names) != len(values)
                or names != tuple(sorted(names))
                or len(set(names)) != len(names)
            ):
                raise ManifestError(f"noncanonical {label} metadata")
            for name, value in values:
                if (
                    type(name) is not str
                    or _NAME_RE.fullmatch(name) is None
                    or type(value) is not str
                    or not value
                    or "\x00" in value
                    or contains_credential_value(name)
                    or contains_credential_value(value)
                ):
                    raise ManifestError(f"unsafe {label} metadata")
                if label == "builder environment" and (
                    name not in BUILDER_ENVIRONMENT_ALLOWLIST or _SENSITIVE_NAME_RE.search(name)
                ):
                    raise ManifestError("unapproved builder environment key")
        if type(self.build_commands) is not tuple or not self.build_commands:
            raise ManifestError("build commands are required")
        for command in self.build_commands:
            if (
                type(command) is not str
                or not command.strip()
                or "\x00" in command
                or contains_credential_value(command)
            ):
                raise ManifestError("unsafe build command metadata")
        expected = _provenance_digest(self)
        if self.provenance_sha256 and self.provenance_sha256 != expected:
            raise ManifestError("provenance digest mismatch")
        object.__setattr__(self, "provenance_sha256", expected)


@dataclass(frozen=True, slots=True)
class CleanBuildManifestV1:
    """Canonical inventory binding snapshot identity, inputs, provenance and outputs.

    ``vcs_head`` is optional informational metadata only. The source identity is
    always ``source_snapshot_manifest_sha256`` under the no-commit rule.
    """

    source_files: tuple[FileHashV1, ...]
    input_files: tuple[FileHashV1, ...]
    output_files: tuple[FileHashV1, ...]
    source_snapshot_manifest_sha256: str = ""
    provenance_path: str = "provenance.json"
    provenance_sha256: str = ""
    artifact_path: str = ""
    artifact_sha256: str = ""
    sbom_path: str = ""
    sbom_sha256: str = ""
    vcs_head: str | None = None
    schema_version: str = SCHEMA_VERSION
    manifest_sha256: str = ""
    # Compatibility input only. It is serialized as `vcs_head`, never as identity.
    source_commit: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version != SCHEMA_VERSION:
            raise ManifestError("unsupported manifest schema")
        if self.vcs_head is not None and (
            type(self.vcs_head) is not str or _COMMIT_RE.fullmatch(self.vcs_head) is None
        ):
            raise ManifestError("invalid informational VCS head")
        if self.source_commit is not None:
            if (
                type(self.source_commit) is not str
                or _COMMIT_RE.fullmatch(self.source_commit) is None
            ):
                raise ManifestError("invalid informational VCS head")
            if self.vcs_head is not None and self.vcs_head != self.source_commit:
                raise ManifestError("conflicting informational VCS head")
            object.__setattr__(self, "vcs_head", self.source_commit)
        _validate_rows("source", self.source_files)
        _validate_rows("input", self.input_files)
        _validate_rows("output", self.output_files)
        derived_identity = _source_snapshot_digest(self.source_files)
        if (
            self.source_snapshot_manifest_sha256
            and self.source_snapshot_manifest_sha256 != derived_identity
        ):
            raise ManifestError("source identity does not match snapshot inventory")
        object.__setattr__(self, "source_snapshot_manifest_sha256", derived_identity)

        source_by_path = {row.path: row for row in self.source_files}
        input_by_path = {row.path: row for row in self.input_files}
        for path in _required_lock_paths(source_by_path):
            source_lock = source_by_path[path]
            input_lock = input_by_path.get(path)
            if (
                input_lock is None
                or source_lock.size_bytes == 0
                or input_lock.size_bytes == 0
                or source_lock != input_lock
            ):
                raise ManifestError("required pinned lockfile evidence is invalid")
        outputs = {row.path: row for row in self.output_files}
        for name in ("provenance_path", "artifact_path", "sbom_path"):
            _validate_relative_path(getattr(self, name))
            if getattr(self, name) not in outputs:
                raise ManifestError("required output evidence is missing")
        artifact_row = outputs[self.artifact_path]
        sbom_row = outputs[self.sbom_path]
        if not self.provenance_sha256:
            object.__setattr__(self, "provenance_sha256", outputs[self.provenance_path].sha256)
        if not self.artifact_sha256:
            object.__setattr__(self, "artifact_sha256", artifact_row.sha256)
        if not self.sbom_sha256:
            object.__setattr__(self, "sbom_sha256", sbom_row.sha256)
        for actual, row in (
            (self.provenance_sha256, outputs[self.provenance_path]),
            (self.artifact_sha256, artifact_row),
            (self.sbom_sha256, sbom_row),
        ):
            if (
                type(actual) is not str
                or _SHA256_RE.fullmatch(actual) is None
                or actual != row.sha256
            ):
                raise ManifestError("output digest reference mismatch")
        if self.manifest_sha256 and _SHA256_RE.fullmatch(self.manifest_sha256) is None:
            raise ManifestError("invalid manifest digest")


@dataclass(frozen=True, slots=True)
class VerificationReportV1:
    """Hash-only verification outcome without file contents."""

    verified: bool
    checked_files: int
    source_inventory_sha256: str
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class BuildDifferenceV1:
    path: str
    first_sha256: str | None
    second_sha256: str | None


@dataclass(frozen=True, slots=True)
class BuildComparisonV1:
    equivalent: bool
    differences: tuple[BuildDifferenceV1, ...]
    filesystem_timestamps_ignored: bool = True


def _validate_relative_path(value: str) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > 240
        or "\\" in value
        or value.startswith("/")
    ):
        raise ManifestError("invalid relative path")
    parts = value.split("/")
    for part in parts:
        if (
            not part
            or part in {".", ".."}
            or len(part) > 128
            or part.endswith(".")
            or part.endswith(" ")
            or _PATH_COMPONENT_RE.fullmatch(part) is None
            or part.split(".", 1)[0].casefold() in _WINDOWS_DEVICE_NAMES
        ):
            raise ManifestError("invalid relative path")


def _validate_rows(name: str, rows: tuple[FileHashV1, ...]) -> None:
    if type(rows) is not tuple or not rows or any(type(row) is not FileHashV1 for row in rows):
        raise ManifestError(f"invalid {name} inventory")
    paths = tuple(row.path for row in rows)
    normalized = tuple(path.casefold() for path in paths)
    if len(set(normalized)) != len(paths) or paths != tuple(sorted(paths)):
        raise ManifestError(f"noncanonical {name} inventory")


def _required_lock_paths(rows: dict[str, FileHashV1]) -> tuple[str, ...]:
    discovered = tuple(sorted(path for path in rows if Path(path).name in LOCK_FILENAMES))
    required = set(LOCK_PATHS)
    if not required.issubset(discovered):
        raise ManifestError("required pinned lockfile evidence is missing")
    return discovered


def _is_reparse_point(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _checked_root(root: Path) -> Path:
    absolute = Path(root).absolute()
    for parent in reversed((absolute, *absolute.parents)):
        if _is_reparse_point(parent):
            raise ManifestError("reparse point in inventory root")
    resolved = absolute.resolve(strict=True)
    if not resolved.is_dir():
        raise ManifestError("inventory root is not a directory")
    return resolved


def _file_payload(rows: tuple[FileHashV1, ...]) -> list[dict[str, Any]]:
    return [{"path": row.path, "sha256": row.sha256, "size_bytes": row.size_bytes} for row in rows]


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _source_snapshot_digest(files: tuple[FileHashV1, ...]) -> str:
    return hashlib.sha256(
        _canonical_bytes({"schema_version": SNAPSHOT_SCHEMA, "files": _file_payload(files)})
    ).hexdigest()


def _provenance_payload(provenance: BuildProvenanceV1) -> dict[str, Any]:
    return {
        "build_commands": list(provenance.build_commands),
        "builder_environment": [list(row) for row in provenance.builder_environment],
        "lock_files": _file_payload(provenance.lock_files),
        "normalized_timestamps": [list(row) for row in provenance.normalized_timestamps],
        "schema_version": provenance.schema_version,
        "source_snapshot_manifest_sha256": provenance.source_snapshot_manifest_sha256,
        "toolchain_versions": [list(row) for row in provenance.toolchain_versions],
    }


def _provenance_digest(provenance: BuildProvenanceV1) -> str:
    return hashlib.sha256(_canonical_bytes(_provenance_payload(provenance))).hexdigest()


def _manifest_payload(manifest: CleanBuildManifestV1) -> dict[str, Any]:
    return {
        "artifact_path": manifest.artifact_path,
        "artifact_sha256": manifest.artifact_sha256,
        "input_files": _file_payload(manifest.input_files),
        "output_files": _file_payload(manifest.output_files),
        "provenance_path": manifest.provenance_path,
        "provenance_sha256": manifest.provenance_sha256,
        "schema_version": manifest.schema_version,
        "sbom_path": manifest.sbom_path,
        "sbom_sha256": manifest.sbom_sha256,
        "source_files": _file_payload(manifest.source_files),
        "source_snapshot_manifest_sha256": manifest.source_snapshot_manifest_sha256,
        "vcs_head": manifest.vcs_head,
    }


def _manifest_digest(manifest: CleanBuildManifestV1) -> str:
    return hashlib.sha256(_canonical_bytes(_manifest_payload(manifest))).hexdigest()


def _text_content(data: bytes, relative_path: str) -> str | None:
    """Decode supported text encodings; return None only for known binary types."""
    encodings: list[str] = []
    if data.startswith((b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00")):
        encodings.append("utf-32")
    elif data.startswith(b"\xef\xbb\xbf"):
        encodings.append("utf-8-sig")
    elif data.startswith((b"\xfe\xff", b"\xff\xfe")):
        encodings.append("utf-16")
    else:
        sample = data[:4096]
        if len(sample) >= 8:
            lanes = tuple(sample[index::4] for index in range(4))
            zero_ratios = tuple(
                lane.count(0) / len(lane) if lane else 0.0 for lane in lanes
            )
            if zero_ratios[0] < 0.2 and all(ratio > 0.6 for ratio in zero_ratios[1:]):
                encodings.append("utf-32-le")
            elif zero_ratios[3] < 0.2 and all(ratio > 0.6 for ratio in zero_ratios[:3]):
                encodings.append("utf-32-be")
        if not encodings and len(sample) >= 4:
            even = sample[0::2]
            odd = sample[1::2]
            even_zeros = even.count(0) / len(even) if even else 0.0
            odd_zeros = odd.count(0) / len(odd) if odd else 0.0
            if even_zeros < 0.2 and odd_zeros > 0.35:
                encodings.append("utf-16-le")
            elif odd_zeros < 0.2 and even_zeros > 0.35:
                encodings.append("utf-16-be")
        encodings.append("utf-8")

    for encoding in encodings:
        try:
            text = data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        if "\x00" in text or any(
            ord(char) < 32 and char not in "\t\n\r\f" for char in text
        ):
            continue
        return text

    if Path(relative_path).suffix.casefold() in BINARY_FILE_EXTENSIONS:
        return None
    raise ManifestError(f"file is not recognized as text or allowlisted binary: {relative_path}")


def _scan_text(data: bytes, relative_path: str) -> None:
    text = _text_content(data, relative_path)
    if text is None:
        return
    if len(text) <= MAX_CREDENTIAL_SCAN_CHARS:
        if contains_credential_value(text):
            raise CredentialScanError(f"credential-shaped text in file: {relative_path}")
        return
    # The scanner is intentionally bounded at 64 KiB. Large lockfiles are
    # scanned line by line; shared token patterns are single-line. Inspect
    # adjacent line boundaries as well because bounded whitespace patterns may
    # cross a newline. An overlong line fails closed in the shared scanner.
    lines = text.splitlines()
    if not lines:
        lines = [text]
    for index, line in enumerate(lines):
        if contains_credential_value(line):
            raise CredentialScanError(f"credential-shaped text in file: {relative_path}")
        if index:
            boundary = lines[index - 1][-32:] + "\n" + line[:32]
            if contains_credential_value(boundary):
                raise CredentialScanError(f"credential-shaped text in file: {relative_path}")


def _hash_file(root: Path, relative_path: str, *, scan_text: bool = True) -> FileHashV1:
    _validate_relative_path(relative_path)
    root_path = _checked_root(root)
    candidate = root_path.joinpath(*relative_path.split("/"))
    current = root_path
    for part in relative_path.split("/"):
        current = current / part
        if _is_reparse_point(current):
            raise ManifestError("reparse point in inventory member")
    if not candidate.is_file():
        raise ManifestError("inventory member is not a regular file")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root_path):
        raise ManifestError("inventory member escapes its root")
    value = hashlib.sha256()
    size = 0
    content = bytearray() if scan_text else None
    with resolved.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            value.update(chunk)
            if content is not None:
                content.extend(chunk)
    if content is not None:
        _scan_text(bytes(content), relative_path)
    return FileHashV1(relative_path, value.hexdigest(), size)


def _hash_inventory(
    root: Path, paths: tuple[str, ...], *, scan_text: bool
) -> tuple[FileHashV1, ...]:
    if type(paths) is not tuple or not paths:
        raise ManifestError("inventory paths must be a nonempty tuple")
    if any(type(path) is not str for path in paths) or len(set(paths)) != len(paths):
        raise ManifestError("invalid inventory paths")
    try:
        return tuple(
            _hash_file(Path(root), path, scan_text=scan_text) for path in sorted(paths)
        )
    except ManifestError:
        raise
    except OSError:
        raise ManifestError("inventory file evidence invalid") from None


def hash_inventory(root: Path, paths: tuple[str, ...]) -> tuple[FileHashV1, ...]:
    """Hash explicitly named text/source/input files and scan their decoded text."""
    return _hash_inventory(root, paths, scan_text=True)


def create_source_snapshot_manifest(root: Path) -> SourceSnapshotManifestV1:
    """Inventory every non-excluded file in a clean snapshot; hash-only, no Git calls."""
    try:
        root_path = _checked_root(Path(root))
        paths: list[str] = []
        pending = [root_path]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    relative = path.relative_to(root_path).as_posix()
                    if _is_reparse_point(path):
                        raise ManifestError("reparse points are not accepted")
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name == ".git" and relative != ".git":
                            raise ManifestError("nested Git metadata is not accepted")
                        if entry.name not in SNAPSHOT_EXCLUDED_DIRS:
                            pending.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        if entry.name == ".git" and relative != ".git":
                            raise ManifestError("nested Git metadata is not accepted")
                        if entry.name == ".git" or entry.name.endswith(".pyc"):
                            continue
                        paths.append(relative)
                    else:
                        raise ManifestError("unsupported snapshot entry")
        rows = tuple(_hash_file(root_path, path) for path in sorted(paths))
        return SourceSnapshotManifestV1(rows)
    except ManifestError:
        raise
    except OSError:
        raise ManifestError("source snapshot evidence invalid") from None


def source_snapshot_to_json(manifest: SourceSnapshotManifestV1) -> bytes:
    """Serialize the complete source inventory in canonical, reproducible JSON."""
    if type(manifest) is not SourceSnapshotManifestV1:
        raise ManifestError("source snapshot must be a V1 record")
    payload = {
        "files": _file_payload(manifest.files),
        "manifest_sha256": manifest.manifest_sha256,
        "schema_version": manifest.schema_version,
    }
    return _canonical_bytes(payload) + b"\n"


def source_snapshot_from_json(payload: bytes) -> SourceSnapshotManifestV1:
    """Parse and verify exact canonical source-snapshot JSON."""
    if type(payload) is not bytes:
        raise ManifestError("source snapshot payload must be bytes")
    try:
        raw = json.loads(payload.decode("ascii"))
        if type(raw) is not dict or set(raw) != {"files", "manifest_sha256", "schema_version"}:
            raise ManifestError("invalid source snapshot fields")
        values = raw["files"]
        if type(values) is not list:
            raise ManifestError("invalid source snapshot inventory")
        rows = []
        for item in values:
            if type(item) is not dict or set(item) != {"path", "sha256", "size_bytes"}:
                raise ManifestError("invalid source snapshot file record")
            rows.append(FileHashV1(item["path"], item["sha256"], item["size_bytes"]))
        record = SourceSnapshotManifestV1(
            files=tuple(rows),
            manifest_sha256=raw["manifest_sha256"],
            schema_version=raw["schema_version"],
        )
        if source_snapshot_to_json(record) != payload:
            raise ManifestError("source snapshot is not canonical")
        return record
    except ManifestError:
        raise
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
        raise ManifestError("invalid source snapshot encoding") from None


def verify_source_snapshot(manifest: SourceSnapshotManifestV1, root: Path) -> bool:
    """Require the complete source tree (under standard exclusions) to match its snapshot."""
    if type(manifest) is not SourceSnapshotManifestV1:
        raise ManifestError("source snapshot must be a V1 record")
    current = create_source_snapshot_manifest(root)
    if current != manifest:
        raise ManifestError("source snapshot has missing, extra, or changed files")
    return True


def create_build_provenance(
    source_snapshot: SourceSnapshotManifestV1,
    *,
    toolchain_versions: tuple[tuple[str, str], ...],
    build_commands: tuple[str, ...],
    normalized_timestamps: tuple[tuple[str, str], ...],
    builder_environment: tuple[tuple[str, str], ...],
) -> BuildProvenanceV1:
    """Create typed provenance from snapshot-bound lockfile hashes and explicit metadata."""
    rows = {row.path: row for row in source_snapshot.files}
    locks = _required_lock_paths(rows)
    return BuildProvenanceV1(
        source_snapshot_manifest_sha256=source_snapshot.manifest_sha256,
        lock_files=tuple(rows[path] for path in locks),
        toolchain_versions=toolchain_versions,
        build_commands=build_commands,
        normalized_timestamps=normalized_timestamps,
        builder_environment=builder_environment,
    )


def build_provenance_to_json(provenance: BuildProvenanceV1) -> bytes:
    if type(provenance) is not BuildProvenanceV1:
        raise ManifestError("provenance must be a V1 record")
    payload = _provenance_payload(provenance)
    payload["provenance_sha256"] = _provenance_digest(provenance)
    return _canonical_bytes(payload) + b"\n"


def build_provenance_from_json(payload: bytes) -> BuildProvenanceV1:
    if type(payload) is not bytes:
        raise ManifestError("provenance payload must be bytes")
    try:
        raw = json.loads(payload.decode("ascii"))
        expected = {
            "build_commands",
            "builder_environment",
            "lock_files",
            "normalized_timestamps",
            "provenance_sha256",
            "schema_version",
            "source_snapshot_manifest_sha256",
            "toolchain_versions",
        }
        if type(raw) is not dict or set(raw) != expected:
            raise ManifestError("invalid provenance fields")

        def file_rows(name: str) -> tuple[FileHashV1, ...]:
            values = raw[name]
            if type(values) is not list:
                raise ManifestError("invalid provenance lock inventory")
            result = []
            for item in values:
                if type(item) is not dict or set(item) != {"path", "sha256", "size_bytes"}:
                    raise ManifestError("invalid provenance file record")
                result.append(FileHashV1(item["path"], item["sha256"], item["size_bytes"]))
            return tuple(result)

        def pairs(name: str) -> tuple[tuple[str, str], ...]:
            values = raw[name]
            if type(values) is not list or any(
                type(item) is not list or len(item) != 2 for item in values
            ):
                raise ManifestError("invalid provenance metadata")
            return tuple((item[0], item[1]) for item in values)

        commands = raw["build_commands"]
        if type(commands) is not list:
            raise ManifestError("invalid build commands")
        record = BuildProvenanceV1(
            source_snapshot_manifest_sha256=raw["source_snapshot_manifest_sha256"],
            lock_files=file_rows("lock_files"),
            toolchain_versions=pairs("toolchain_versions"),
            build_commands=tuple(commands),
            normalized_timestamps=pairs("normalized_timestamps"),
            builder_environment=pairs("builder_environment"),
            provenance_sha256=raw["provenance_sha256"],
            schema_version=raw["schema_version"],
        )
        if build_provenance_to_json(record) != payload:
            raise ManifestError("provenance is not canonical")
        return record
    except ManifestError:
        raise
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
        raise ManifestError("invalid provenance encoding") from None


def _manifest_json_payload(manifest: CleanBuildManifestV1) -> dict[str, Any]:
    payload = _manifest_payload(manifest)
    payload["manifest_sha256"] = _manifest_digest(manifest)
    return payload


def create_manifest(
    source_root: Path,
    input_root: Path,
    output_root: Path,
    *,
    source_paths: tuple[str, ...] | None = None,
    source_snapshot: SourceSnapshotManifestV1 | None = None,
    source_snapshot_manifest_sha256: str | None = None,
    source_commit: str | None = None,
    vcs_head: str | None = None,
    input_paths: tuple[str, ...],
    output_paths: tuple[str, ...],
    artifact_path: str = "",
    sbom_path: str = "",
    provenance_path: str = "provenance.json",
) -> CleanBuildManifestV1:
    """Create a manifest bound to a complete hash snapshot and typed provenance file."""
    snapshot = source_snapshot or create_source_snapshot_manifest(source_root)
    if source_snapshot_manifest_sha256 is not None and (
        source_snapshot_manifest_sha256 != snapshot.manifest_sha256
    ):
        raise ManifestError("source snapshot identity mismatch")
    if vcs_head is not None and source_commit is not None and vcs_head != source_commit:
        raise ManifestError("conflicting informational VCS head")
    verify_source_snapshot(snapshot, source_root)
    if source_paths is not None and tuple(sorted(source_paths)) != tuple(
        row.path for row in snapshot.files
    ):
        raise ManifestError("source file selection differs from complete snapshot")
    source_files = snapshot.files
    input_files = hash_inventory(input_root, input_paths)
    # Output artifacts are intentionally hash-only. Text source snapshots and
    # build inputs are scanned; binary artifact scanning is a separate gate.
    output_files = _hash_inventory(output_root, output_paths, scan_text=False)
    output_by_path = {row.path: row for row in output_files}
    if not artifact_path:
        artifact_path = next(
            (
                path
                for path in output_by_path
                if Path(path).suffix.casefold() in {".exe", ".msi", ".bin"}
            ),
            "",
        )
    if not sbom_path:
        sbom_path = next(
            (
                path
                for path in output_by_path
                if "sbom" in Path(path).name.casefold() or "cdx" in Path(path).name.casefold()
            ),
            "",
        )
    if not artifact_path or not sbom_path or provenance_path not in output_by_path:
        raise ManifestError("artifact, SBOM, and provenance output paths are required")
    provenance_file = output_root / Path(*provenance_path.split("/"))
    provenance = build_provenance_from_json(provenance_file.read_bytes())
    if provenance.source_snapshot_manifest_sha256 != snapshot.manifest_sha256:
        raise ManifestError("provenance source identity mismatch")
    source_rows = {row.path: row for row in source_files}
    input_rows = {row.path: row for row in input_files}
    for lock_path in _required_lock_paths(source_rows):
        if source_rows[lock_path] != input_rows.get(lock_path):
            raise ManifestError("build input lock differs from source snapshot")
    if tuple(provenance.lock_files) != tuple(
        source_rows[path] for path in _required_lock_paths(source_rows)
    ):
        raise ManifestError("provenance lock digests differ from source snapshot")
    unsigned = CleanBuildManifestV1(
        source_files=source_files,
        input_files=input_files,
        output_files=output_files,
        source_snapshot_manifest_sha256=snapshot.manifest_sha256,
        provenance_path=provenance_path,
        provenance_sha256=output_by_path[provenance_path].sha256,
        artifact_path=artifact_path,
        artifact_sha256=output_by_path[artifact_path].sha256,
        sbom_path=sbom_path,
        sbom_sha256=output_by_path[sbom_path].sha256,
        vcs_head=vcs_head or source_commit,
    )
    return CleanBuildManifestV1(
        source_files=unsigned.source_files,
        input_files=unsigned.input_files,
        output_files=unsigned.output_files,
        source_snapshot_manifest_sha256=unsigned.source_snapshot_manifest_sha256,
        provenance_path=unsigned.provenance_path,
        provenance_sha256=unsigned.provenance_sha256,
        artifact_path=unsigned.artifact_path,
        artifact_sha256=unsigned.artifact_sha256,
        sbom_path=unsigned.sbom_path,
        sbom_sha256=unsigned.sbom_sha256,
        vcs_head=unsigned.vcs_head,
        manifest_sha256=_manifest_digest(unsigned),
    )


def manifest_to_json(manifest: CleanBuildManifestV1) -> bytes:
    """Serialize with fixed key order, separators, ASCII encoding, and newline."""
    if type(manifest) is not CleanBuildManifestV1:
        raise ManifestError("manifest must be a V1 record")
    digest = _manifest_digest(manifest)
    if manifest.manifest_sha256 and manifest.manifest_sha256 != digest:
        raise ManifestError("manifest digest mismatch")
    return _canonical_bytes(_manifest_json_payload(manifest)) + b"\n"


def manifest_from_json(payload: bytes) -> CleanBuildManifestV1:
    """Parse exact canonical V1 JSON and require all source/provenance digest fields."""
    if type(payload) is not bytes:
        raise ManifestError("manifest payload must be bytes")
    try:
        raw = json.loads(payload.decode("ascii"))
        keys = {
            "artifact_path",
            "artifact_sha256",
            "input_files",
            "manifest_sha256",
            "output_files",
            "provenance_path",
            "provenance_sha256",
            "schema_version",
            "sbom_path",
            "sbom_sha256",
            "source_files",
            "source_snapshot_manifest_sha256",
            "vcs_head",
        }
        if type(raw) is not dict or set(raw) != keys:
            raise ManifestError("invalid manifest fields")

        def parse_rows(name: str) -> tuple[FileHashV1, ...]:
            values = raw[name]
            if type(values) is not list:
                raise ManifestError("invalid inventory encoding")
            rows = []
            for item in values:
                if type(item) is not dict or set(item) != {"path", "sha256", "size_bytes"}:
                    raise ManifestError("invalid file record")
                rows.append(FileHashV1(item["path"], item["sha256"], item["size_bytes"]))
            return tuple(rows)

        manifest = CleanBuildManifestV1(
            source_files=parse_rows("source_files"),
            input_files=parse_rows("input_files"),
            output_files=parse_rows("output_files"),
            source_snapshot_manifest_sha256=raw["source_snapshot_manifest_sha256"],
            provenance_path=raw["provenance_path"],
            provenance_sha256=raw["provenance_sha256"],
            artifact_path=raw["artifact_path"],
            artifact_sha256=raw["artifact_sha256"],
            sbom_path=raw["sbom_path"],
            sbom_sha256=raw["sbom_sha256"],
            vcs_head=raw["vcs_head"],
            schema_version=raw["schema_version"],
            manifest_sha256=raw["manifest_sha256"],
        )
        if (
            _manifest_digest(manifest) != manifest.manifest_sha256
            or manifest_to_json(manifest) != payload
        ):
            raise ManifestError("manifest digest or canonical encoding mismatch")
        return manifest
    except ManifestError:
        raise
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
        raise ManifestError("invalid manifest encoding") from None


def compare_build_manifests(
    first: CleanBuildManifestV1, second: CleanBuildManifestV1
) -> BuildComparisonV1:
    """Compare two synthetic/produced manifests; filesystem mtimes are not hashed."""
    if type(first) is not CleanBuildManifestV1 or type(second) is not CleanBuildManifestV1:
        raise ManifestError("build comparison requires V1 manifests")
    differences: list[BuildDifferenceV1] = []
    if first.source_snapshot_manifest_sha256 != second.source_snapshot_manifest_sha256:
        differences.append(
            BuildDifferenceV1(
                "@source-snapshot",
                first.source_snapshot_manifest_sha256,
                second.source_snapshot_manifest_sha256,
            )
        )
    first_inputs = {row.path: row for row in first.input_files}
    second_inputs = {row.path: row for row in second.input_files}
    first_outputs = {row.path: row for row in first.output_files}
    second_outputs = {row.path: row for row in second.output_files}
    for path in sorted(first_inputs.keys() | second_inputs.keys()):
        left, right = first_inputs.get(path), second_inputs.get(path)
        if left != right:
            differences.append(
                BuildDifferenceV1(
                    "inputs/" + path, left.sha256 if left else None, right.sha256 if right else None
                )
            )
    for path in sorted(first_outputs.keys() | second_outputs.keys()):
        left, right = first_outputs.get(path), second_outputs.get(path)
        if left != right:
            differences.append(
                BuildDifferenceV1(
                    path, left.sha256 if left else None, right.sha256 if right else None
                )
            )
    if first.provenance_sha256 != second.provenance_sha256:
        differences.append(
            BuildDifferenceV1("@provenance", first.provenance_sha256, second.provenance_sha256)
        )
    return BuildComparisonV1(not differences, tuple(differences))
