"""Desktop-only profile classification and pre-API halt-store provisioning."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from leviathan_core.risk.halt_store import (
    HaltStore,
    HaltStoreError,
    ProfileClassification,
    ProfileEvidence,
    ProvisionResult,
)

PROFILE_SCHEMA_VERSION = 1
APP_VERSION = "0.1.0"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CLASSIFICATIONS = {
    item.value for item in ProfileClassification if item is not ProfileClassification.UNKNOWN
}


class ProfileProvisionError(RuntimeError):
    """A redacted operator-facing startup failure."""


def _checked_stat(path: Path) -> os.stat_result | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProfileProvisionError("PROFILE_UNAVAILABLE") from exc
    if stat.S_ISLNK(info.st_mode) or (
        os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ProfileProvisionError("PROFILE_REPARSE_POINT")
    return info


def _read_marker(path: Path) -> tuple[dict[str, object], str] | None:
    info = _checked_stat(path)
    if info is None:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise ProfileProvisionError("PROFILE_MARKER_INVALID")
    try:
        if info.st_size > 16_384:
            raise ProfileProvisionError("PROFILE_MARKER_INVALID")
        raw = path.read_bytes()
        marker = json.loads(raw)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProfileProvisionError("PROFILE_MARKER_INVALID") from exc
    if not isinstance(marker, dict) or set(marker) != {
        "schema_version",
        "halt_store_provisioned",
        "provisioned_by",
        "provisioned_at_utc",
        "classification_used",
    }:
        raise ProfileProvisionError("PROFILE_MARKER_INVALID")
    if (
        type(marker["schema_version"]) is not int
        or marker["schema_version"] != PROFILE_SCHEMA_VERSION
        or marker["halt_store_provisioned"] is not True
        or not isinstance(marker["provisioned_by"], str)
        or not 1 <= len(marker["provisioned_by"]) <= 64
        or not isinstance(marker["provisioned_at_utc"], str)
        or not isinstance(marker["classification_used"], str)
        or marker["classification_used"] not in _CLASSIFICATIONS
    ):
        raise ProfileProvisionError("PROFILE_MARKER_INVALID")
    try:
        timestamp = datetime.fromisoformat(marker["provisioned_at_utc"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProfileProvisionError("PROFILE_MARKER_INVALID") from exc
    if timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
        raise ProfileProvisionError("PROFILE_MARKER_INVALID")
    return marker, hashlib.sha256(raw).hexdigest()


def _write_marker(path: Path, classification: ProfileClassification) -> None:
    marker = {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "halt_store_provisioned": True,
        "provisioned_by": APP_VERSION,
        "provisioned_at_utc": datetime.now(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        "classification_used": classification.value,
    }
    payload = (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".profile-", suffix=".json", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise ProfileProvisionError("PROFILE_MARKER_WRITE_FAILED") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def provision_profile(
    data_root: Path, *, preexisted: bool, entry_digest: str
) -> tuple[Path, ProfileClassification, ProvisionResult]:
    if _SHA256.fullmatch(entry_digest) is None:
        raise ProfileProvisionError("PROFILE_EVIDENCE_INVALID")
    data_dir = data_root / "data"
    marker_path = data_dir / "profile.json"
    store_path = data_dir / "halt-state.sqlite3"
    for path in (data_root, data_dir):
        info = _checked_stat(path)
        if info is None or not stat.S_ISDIR(info.st_mode):
            raise ProfileProvisionError("PROFILE_UNAVAILABLE")
    try:
        for entry in data_dir.iterdir():
            _checked_stat(entry)
    except OSError as exc:
        raise ProfileProvisionError("PROFILE_UNAVAILABLE") from exc
    marker = _read_marker(marker_path)
    store_exists = _checked_stat(store_path) is not None
    if marker is not None:
        if not store_exists:
            raise ProfileProvisionError("HALT_STORE_MISSING")
        classification = ProfileClassification.ALREADY_PROVISIONED
    elif store_exists:
        classification = ProfileClassification.ALREADY_PROVISIONED
    else:
        try:
            residue = any(
                entry.name.lower().startswith("halt-state.sqlite3") for entry in data_dir.iterdir()
            )
        except OSError as exc:
            raise ProfileProvisionError("PROFILE_UNAVAILABLE") from exc
        if residue:
            raise ProfileProvisionError("HALT_STORE_RESIDUE")
        classification = (
            ProfileClassification.PRE_HALT_INSTALL
            if preexisted
            else ProfileClassification.NEVER_PROVISIONED
        )
    references = (
        f"prelaunch_data_dir={'present' if preexisted else 'absent'}",
        f"prelaunch_entries_sha256={entry_digest}",
        f"profile_marker={'sha256:' + marker[1] if marker is not None else 'absent'}",
    )
    evidence = ProfileEvidence(classification, verified=True, references=references)
    try:
        if classification is ProfileClassification.NEVER_PROVISIONED:
            result = HaltStore.provision_new(store_path, data_dir, evidence)
        elif classification is ProfileClassification.PRE_HALT_INSTALL:
            result = HaltStore.provision_legacy(store_path, data_dir, evidence, snapshot=None)
        else:
            store = HaltStore(store_path, data_dir)
            store.close()
            result = ProvisionResult.ALREADY_VALIDATED
    except (HaltStoreError, OSError) as exc:
        raise ProfileProvisionError("HALT_STORE_UNAVAILABLE") from exc
    if result not in (ProvisionResult.CREATED, ProvisionResult.ALREADY_VALIDATED):
        raise ProfileProvisionError("HALT_STORE_UNAVAILABLE")
    if marker is None:
        _write_marker(marker_path, classification)
    return store_path, classification, result
