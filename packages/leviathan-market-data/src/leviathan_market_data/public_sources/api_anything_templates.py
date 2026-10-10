"""Session-free export/import for reviewed api-anything HTTP templates."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import cast

from .api_anything_client import OperationId, PublicOperationError, PublicOperationErrorCode

_SITES: dict[OperationId, str] = {
    "calendar.fed": "fed-calendar",
    "earnings.forward": "earnings-calendar",
    "senate.efd.ptr": "senate-efd",
    "cboe.daily.stats": "cboe-market-stats",
    "cnn.fear_greed": "cnn-fear-greed",
}
_SENSITIVE = re.compile(
    r"cookie|session|authorization|bearer|password|secret|access[_-]?token", re.I
)


def _read_pin(operation_id: str, registry_path: Path) -> dict[str, object]:
    try:
        document = json.loads(registry_path.read_text(encoding="utf-8"))
        pin = document["operations"][operation_id]
        if (
            not isinstance(pin, dict)
            or not isinstance(pin.get("version"), str)
            or not isinstance(pin.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", cast(str, pin.get("sha256")))
            or not isinstance(pin.get("allowed_hosts"), list)
            or not isinstance(pin.get("challenge_hosts"), list)
            or not isinstance(pin.get("review_note"), str)
            or not isinstance(pin.get("tos_review_id"), str)
            or not isinstance(pin.get("template_path"), str)
        ):
            raise ValueError
        _resolve_template_path(registry_path, cast(str, pin["template_path"]))
        return cast(dict[str, object], pin)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise PublicOperationError(PublicOperationErrorCode.TEMPLATE_UNPINNED) from None


def _resolve_template_path(registry_path: Path, relative_path: str) -> Path:
    path = Path(relative_path)
    root = registry_path.resolve().parent
    if path.is_absolute() or any(part in {"..", "."} for part in path.parts):
        raise ValueError("template path must be relative and traversal-free")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root) or resolved == root:
        raise ValueError("template path must stay inside templates")
    return resolved


def _reject_session_material(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _SENSITIVE.search(str(key)):
                raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
            _reject_session_material(item)
    elif isinstance(value, list):
        for item in value:
            _reject_session_material(item)
    elif isinstance(value, str) and _SENSITIVE.search(value):
        raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)


def export_pinned_template(
    operation_id: OperationId,
    *,
    data_dir: str | Path,
    registry_path: str | Path,
    destination: str | Path,
) -> str:
    """Export a locally learned template only when it exactly matches the committed pin."""
    pin = _read_pin(operation_id, Path(registry_path))
    template_path = _resolve_template_path(Path(registry_path), cast(str, pin["template_path"]))
    try:
        raw = template_path.read_bytes()
        parsed = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        raise PublicOperationError(PublicOperationErrorCode.TEMPLATE_UNAVAILABLE) from None
    digest = hashlib.sha256(raw).hexdigest()
    if digest != pin["sha256"]:
        raise PublicOperationError(PublicOperationErrorCode.TEMPLATE_UNPINNED)
    _reject_session_material(parsed)
    envelope = {
        "schema_version": 1,
        "operation_id": operation_id,
        "version": pin["version"],
        "sha256": digest,
        "approval_id": pin["tos_review_id"],
        "allowed_hosts": pin["allowed_hosts"],
        "challenge_hosts": pin["challenge_hosts"],
        "review_note": pin["review_note"],
        "template_base64": base64.b64encode(raw).decode("ascii"),
    }
    Path(destination).write_text(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    return digest


def import_pinned_template(
    bundle_path: str | Path,
    *,
    registry_path: str | Path,
    data_dir: str | Path,
) -> str:
    """Verify a session-free export against the local committed pin, then install for replay."""
    try:
        envelope = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        operation_id = envelope["operation_id"]
        if operation_id not in _SITES or envelope.get("schema_version") != 1:
            raise ValueError
        pin = _read_pin(cast(str, operation_id), Path(registry_path))
        raw = base64.b64decode(envelope["template_base64"], validate=True)
        parsed = json.loads(raw)
        if (
            hashlib.sha256(raw).hexdigest() != envelope.get("sha256")
            or envelope.get("sha256") != pin["sha256"]
            or envelope.get("version") != pin["version"]
            or envelope.get("approval_id") != pin["tos_review_id"]
            or envelope.get("allowed_hosts") != pin["allowed_hosts"]
            or envelope.get("challenge_hosts") != pin["challenge_hosts"]
            or envelope.get("review_note") != pin["review_note"]
        ):
            raise ValueError
        _reject_session_material(parsed)
    except PublicOperationError:
        raise
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID) from None
    install_path = _resolve_template_path(Path(registry_path), cast(str, pin["template_path"]))
    install_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = install_path.with_suffix(".json.tmp")
    temporary.write_bytes(raw)
    temporary.replace(install_path)
    return cast(str, envelope["sha256"])
