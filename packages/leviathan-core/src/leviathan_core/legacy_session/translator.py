"""Pure archived v1.3 read translation; no detection, stores, or transport."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from decimal import Decimal

from .models import (
    _READ_RESULT_ISSUER,
    _WRITE_RESULT_ISSUER,
    ArchivedWriteDecisionV1,
    CanonicalSignalStateV1,
    LegacyBoundaryError,
    LegacyMappingPolicyV1,
    LegacyReadErrorV1,
    LegacyReadRequestV1,
    LegacyReadResultV1,
    LegacySignalPayloadV1,
    LegacySuccessorIdV1,
    MappingField,
    _link_value,
    _text,
    _uuid4,
)

_ENTITY_TYPES = frozenset(("signal", "session", "instrument"))
_ISO_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|\+00:00)$"
)
_NS_PER_SECOND = 1_000_000_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _utc_ns(value: object) -> int | None:
    if not isinstance(value, str) or not _ISO_UTC.fullmatch(value):
        return None
    try:
        fixed = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(fixed)
        offset = parsed.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            return None
        whole = fixed.split(".", 1)[0].removesuffix("+00:00")
        base = datetime.fromisoformat(whole).replace(tzinfo=UTC)
        fraction = fixed.split(".", 1)[1].split("+", 1)[0] if "." in fixed else ""
        epoch = datetime(1970, 1, 1, tzinfo=UTC)
        delta = base - epoch
        return (delta.days * 86400 + delta.seconds) * _NS_PER_SECOND + int(
            fraction.ljust(9, "0") or "0"
        )
    except (OverflowError, ValueError):
        return None


def _headers(policy: LegacyMappingPolicyV1, entity_id: str) -> tuple[tuple[str, str], ...]:
    return (
        ("Deprecation", "true"),
        ("Sunset", policy.sunset_utc),
        ("Link", _link_value(entity_id.lower())),
    )


def _failure(
    status: int,
    code: str,
    request: LegacyReadRequestV1,
    headers: tuple[tuple[str, str], ...],
    paths: tuple[str, ...] = (),
    remediation: str | None = None,
    availability_ns: int | None = None,
) -> LegacyReadResultV1:
    try:
        _text(request.trace_id, "trace_id")
        trace_id = request.trace_id
    except LegacyBoundaryError:
        trace_id = "invalid-trace"
    return _READ_RESULT_ISSUER.issue(
        LegacyReadResultV1(
            status_code=status,
            headers=headers,
            error=LegacyReadErrorV1(
                code=code, trace_id=trace_id, field_paths=paths, remediation=remediation
            ),
            availability_ns=availability_ns,
            _issuer=_READ_RESULT_ISSUER,
        )
    )


def _mapped(
    field: MappingField, value: str | None, policy: LegacyMappingPolicyV1
) -> tuple[str | None, bool, str | None, bool]:
    if value is None:
        defaults = [default for name, default in policy.null_defaults if name == field]
        return (defaults[0] if len(defaults) == 1 else None, False, None, len(defaults) <= 1)
    entries = [
        entry for entry in policy.mappings if entry.field == field and entry.canonical == value
    ]
    exact = [entry for entry in entries if not entry.compatible]
    choices = exact if exact else entries
    if len(choices) != 1:
        return None, False, None, False
    entry = choices[0]
    if entry.compatible and not entry.note:
        return None, False, None, False
    return entry.legacy, entry.compatible, entry.note, True


def translate_legacy_read(
    request: LegacyReadRequestV1,
    snapshot: CanonicalSignalStateV1 | None,
    policy: LegacyMappingPolicyV1,
) -> LegacyReadResultV1:
    """Translate a verified immutable snapshot using only an explicit mapping table."""
    if not isinstance(request, LegacyReadRequestV1):
        raise LegacyBoundaryError("INVALID_REQUEST_TYPE")
    if not isinstance(policy, LegacyMappingPolicyV1):
        raise LegacyBoundaryError("INVALID_POLICY_TYPE")
    base_headers = (("Deprecation", "true"), ("Sunset", policy.sunset_utc))
    paths: list[str] = []
    for field in ("tenant_id", "trace_id"):
        try:
            _text(getattr(request, field), field)
        except LegacyBoundaryError:
            paths.append(field)
    if request.entity_type not in _ENTITY_TYPES:
        paths.append("entity_type")
    if not isinstance(request.entity_id, str) or not _uuid4(request.entity_id):
        paths.append("entity_id")
    start = _utc_ns(request.from_utc) if request.from_utc is not None else None
    end = _utc_ns(request.to_utc) if request.to_utc is not None else None
    if request.from_utc is not None and start is None:
        paths.append("from_utc")
    if request.to_utc is not None and end is None:
        paths.append("to_utc")
    if start is not None and end is not None and start > end:
        paths.extend(("from_utc", "to_utc"))
    if paths:
        return _failure(400, "INVALID_REQUEST", request, base_headers, tuple(sorted(set(paths))))
    headers = _headers(policy, request.entity_id)
    if policy.hard_sunset:
        return _failure(
            410, "LEGACY_ARCHIVED", request, headers, remediation="migrate_to_successor"
        )
    if not _SHA256.fullmatch(policy.schema_sha256):
        return _failure(422, "UNMAPPABLE_STATE", request, headers, ("schema_sha256",))
    if snapshot is not None and not isinstance(snapshot, CanonicalSignalStateV1):
        raise LegacyBoundaryError("INVALID_SOURCE_TYPE")
    if (
        snapshot is None
        or snapshot.tenant_id != request.tenant_id
        or snapshot.entity_type != request.entity_type
        or snapshot.entity_id.lower() != request.entity_id.lower()
    ):
        return _failure(404, "NOT_FOUND", request, headers)
    if snapshot.availability_ns < snapshot.as_of_ns or (
        snapshot.session_start_ns is not None
        and snapshot.session_end_ns is not None
        and snapshot.session_start_ns >= snapshot.session_end_ns
    ):
        return _failure(422, "UNMAPPABLE_STATE", request, headers, ("source_time",))
    clipped = start is not None and start < policy.retention_start_ns
    effective_start = (
        max(start, policy.retention_start_ns) if start is not None else policy.retention_start_ns
    )
    if (
        (end is not None and effective_start > end)
        or snapshot.as_of_ns < effective_start
        or (end is not None and snapshot.as_of_ns > end)
    ):
        return _failure(404, "NOT_FOUND", request, headers)
    if end is not None and snapshot.availability_ns > end:
        return _failure(
            502,
            "UPSTREAM_UNAVAILABLE",
            request,
            headers,
            ("availability_ns",),
            availability_ns=snapshot.availability_ns,
        )
    mapped: dict[str, str | None] = {}
    notes: list[str] = []
    unmappable: list[str] = []
    fields: tuple[MappingField, ...] = ("state", "session", "signal")
    for field in fields:
        legacy, degraded, note, valid = _mapped(field, getattr(snapshot, field), policy)
        mapped[field] = legacy
        if not valid:
            unmappable.append(field)
        if degraded and note is not None:
            notes.append(f"{field}: {note}")
    if unmappable:
        return _failure(422, "UNMAPPABLE_STATE", request, headers, tuple(unmappable))
    confidence = snapshot.confidence
    if confidence is not None and (
        not isinstance(confidence, Decimal)
        or not confidence.is_finite()
        or not 0 <= confidence <= 1
    ):
        return _failure(422, "UNMAPPABLE_STATE", request, headers, ("confidence",))
    return _READ_RESULT_ISSUER.issue(
        LegacyReadResultV1(
            status_code=200,
            headers=headers,
            payload=LegacySignalPayloadV1(
                entity_type=snapshot.entity_type,
                entity_id=snapshot.entity_id,
                state=mapped["state"],
                session=mapped["session"],
                signal=mapped["signal"],
                confidence=confidence,
                session_start_ns=snapshot.session_start_ns,
                session_end_ns=snapshot.session_end_ns,
                evidence=snapshot.evidence,
                as_of_ns=snapshot.as_of_ns,
                availability_ns=snapshot.availability_ns,
                source_version=snapshot.source_version,
                mapping_version=policy.mapping_version,
                schema_sha256=policy.schema_sha256,
                trace_id=snapshot.trace_id,
                degraded=bool(notes),
                mapping_notes=tuple(notes),
                clipped=clipped,
            ),
            schema_sha256=policy.schema_sha256,
            availability_ns=snapshot.availability_ns,
            _issuer=_READ_RESULT_ISSUER,
        )
    )


def deny_archived_write(verb: str, successor_id: LegacySuccessorIdV1) -> ArchivedWriteDecisionV1:
    """Describe the unconditional legacy write denial without dispatching any action."""
    if type(verb) is not str:
        raise LegacyBoundaryError("INVALID_VERB_TYPE", ("verb",))
    if type(successor_id) is not LegacySuccessorIdV1:
        raise LegacyBoundaryError("INVALID_SUCCESSOR", ("successor_id",))
    del verb
    return _WRITE_RESULT_ISSUER.issue(
        ArchivedWriteDecisionV1(
            status_code=410,
            code="LEGACY_ARCHIVED",
            successor_id=successor_id,
            headers=(("Link", _link_value(successor_id.value)),),
            _issuer=_WRITE_RESULT_ISSUER,
        )
    )
