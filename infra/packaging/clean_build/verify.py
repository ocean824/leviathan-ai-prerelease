"""Fail-closed hash verification for PKG-002 source and build evidence.

Textual source and inputs use the shared credential-shape scanner. Installer
and other binary bytes are hashed only; binary scanning is a separate release
gate. This module does not launch subprocesses or built artifacts.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import cast

from .manifest import (  # type: ignore[import-not-found]
    SNAPSHOT_EXCLUDED_DIRS,
    BuildProvenanceV1,
    CleanBuildManifestV1,
    CredentialScanError,
    FileHashV1,
    ManifestError,
    SourceSnapshotManifestV1,
    VerificationReportV1,
    _checked_root,
    _hash_file,
    _is_reparse_point,
    _manifest_digest,
    _required_lock_paths,
    _source_snapshot_digest,
    build_provenance_from_json,
    build_provenance_to_json,
)
from .manifest import (
    verify_source_snapshot as _verify_source_snapshot,
)


class VerificationError(ValueError):
    """Manifest or on-disk build evidence failed verification."""


def _check(
    root: Path,
    rows: tuple[FileHashV1, ...],
    forbidden_sha256: frozenset[str],
    *,
    allow_source_git_entry: bool = False,
    source_snapshot_exclusions: bool = False,
    scan_text: bool = True,
) -> None:
    root_path = _checked_root(root)
    observed: dict[str, FileHashV1] = {}
    pending = [root_path]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                candidate = Path(entry.path)
                relative = candidate.relative_to(root_path).as_posix()
                if allow_source_git_entry and relative == ".git":
                    if _is_reparse_point(candidate):
                        raise VerificationError("source .git reparse point is not accepted")
                    if entry.is_file(follow_symlinks=False) or entry.is_dir(follow_symlinks=False):
                        continue
                if _is_reparse_point(candidate):
                    raise VerificationError("reparse points are not accepted")
                if entry.is_dir(follow_symlinks=False):
                    if source_snapshot_exclusions and entry.name == ".git":
                        raise VerificationError("nested Git metadata is not accepted")
                    if source_snapshot_exclusions and entry.name in SNAPSHOT_EXCLUDED_DIRS:
                        continue
                    pending.append(candidate)
                elif entry.is_file(follow_symlinks=False):
                    if source_snapshot_exclusions and entry.name.endswith(".pyc"):
                        continue
                    try:
                        observed[relative] = _hash_file(root_path, relative, scan_text=scan_text)
                    except CredentialScanError as exc:
                        raise VerificationError(str(exc)) from None
                    except ManifestError:
                        raise VerificationError("inventory file evidence invalid") from None
                else:
                    raise VerificationError("unsupported inventory member")
    expected = {row.path: row for row in rows}
    if observed.keys() != expected.keys():
        raise VerificationError("inventory does not match the complete file set")
    for path, actual in observed.items():
        row = expected[path]
        if actual.sha256 != row.sha256 or actual.size_bytes != row.size_bytes:
            raise VerificationError("file digest or size mismatch")
        if actual.sha256 in forbidden_sha256:
            raise VerificationError("forbidden file digest present")


def _verify_provenance(manifest: CleanBuildManifestV1, output_root: Path) -> BuildProvenanceV1:
    path = output_root.joinpath(*manifest.provenance_path.split("/"))
    payload = path.read_bytes()
    provenance = build_provenance_from_json(payload)
    if (
        hashlib.sha256(payload).hexdigest() != manifest.provenance_sha256
        or provenance.source_snapshot_manifest_sha256 != manifest.source_snapshot_manifest_sha256
        or build_provenance_to_json(provenance) != payload
    ):
        raise VerificationError("provenance record digest or source identity mismatch")
    source = {row.path: row for row in manifest.source_files}
    inputs = {row.path: row for row in manifest.input_files}
    required = _required_lock_paths(source)
    source_locks = tuple(source[path] for path in required)
    if provenance.lock_files != source_locks:
        raise VerificationError("provenance lock digests do not match source snapshot")
    for path in required:
        if inputs.get(path) != source[path]:
            raise VerificationError("build input lock does not match source snapshot")
    return provenance


def verify_source_snapshot(manifest: SourceSnapshotManifestV1, root: Path) -> bool:
    """Public fail-closed snapshot verifier with no Git or process invocation."""
    try:
        return cast(bool, _verify_source_snapshot(manifest, root))
    except CredentialScanError as exc:
        raise VerificationError(str(exc)) from None
    except (ManifestError, OSError, ValueError, TypeError):
        raise VerificationError("source snapshot evidence invalid") from None


def verify_manifest(
    manifest: CleanBuildManifestV1,
    source_root: Path,
    input_root: Path,
    output_root: Path,
    *,
    forbidden_sha256: tuple[str, ...] = (),
) -> VerificationReportV1:
    """Verify snapshot, locks, provenance, SBOM and outputs using hashes only."""
    if type(manifest) is not CleanBuildManifestV1:
        raise VerificationError("manifest must be a V1 record")
    forbidden: set[str] = set()
    for digest in forbidden_sha256:
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise VerificationError("invalid forbidden digest")
        forbidden.add(digest)
    try:
        actual_manifest_digest = _manifest_digest(manifest)
        if manifest.manifest_sha256 != actual_manifest_digest:
            raise VerificationError("manifest digest mismatch")
        blocked = frozenset(forbidden)
        _check(
            Path(source_root),
            manifest.source_files,
            blocked,
            allow_source_git_entry=True,
            source_snapshot_exclusions=True,
            scan_text=True,
        )
        _check(Path(input_root), manifest.input_files, blocked, scan_text=True)
        _check(Path(output_root), manifest.output_files, blocked, scan_text=False)
        _verify_provenance(manifest, Path(output_root))
        source_identity = _source_snapshot_digest(manifest.source_files)
        if source_identity != manifest.source_snapshot_manifest_sha256:
            raise VerificationError("source snapshot identity mismatch")
    except VerificationError:
        raise
    except (ManifestError, OSError, UnicodeError, ValueError, TypeError, RecursionError):
        raise VerificationError("manifest file evidence invalid") from None
    return VerificationReportV1(
        verified=True,
        checked_files=len(manifest.source_files)
        + len(manifest.input_files)
        + len(manifest.output_files),
        source_inventory_sha256=source_identity,
        manifest_sha256=actual_manifest_digest,
    )
