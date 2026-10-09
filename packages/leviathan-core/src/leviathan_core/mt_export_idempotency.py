"""Pure, domain-separated request identity and duplicate-intent decisions.

Idempotency keys are non-secret request identifiers; callers must not place
secrets in them.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import Field

from leviathan_core.numeric import canonical_json, canonical_str
from leviathan_core.seal import Issuer, SealedModel, SealError, require

_PAYLOAD_DOMAIN = b"leviathan.mt_export_idempotency.payload.v1\0"
_KEY_DOMAIN = b"leviathan.mt_export_idempotency.key.v1\0"
_SCOPE_DOMAIN = b"leviathan.mt_export_idempotency.scope.v1\0"
_REQUEST_DOMAIN = b"leviathan.mt_export_idempotency.request.v1\0"
_BINDING_TAG = "mt_export_idemp_binding_v1"
_DECISION_TAG = "mt_export_idemp_decision_v1"
_BINDING_ISSUER = Issuer(_BINDING_TAG)
_DECISION_ISSUER = Issuer(_DECISION_TAG)
_PROJECT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", re.ASCII)
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,127}", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
_MAX_PAYLOAD_BYTES = 1_048_576
_MAX_PAYLOAD_NODES = 20_000
_MAX_PAYLOAD_DEPTH = 64


class ExportActionV1(StrEnum):
    BUILD = "BUILD"
    DEPLOY = "DEPLOY"


class DuplicateIntentStatusV1(StrEnum):
    NEW = "NEW"
    REPLAY = "REPLAY"
    CONFLICT = "CONFLICT"


class IdempotencyError(ValueError):
    """Content-free failure at the request identity boundary."""

    __slots__ = ("code",)
    _CODES = frozenset({"INVALID_REQUEST", "INVALID_BINDING"})

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in self._CODES:
            code = "INVALID_REQUEST"
        self.code = code
        super().__init__(code)


class RequestBindingV1(SealedModel):
    """Issued opaque identity for one project/action/key/content tuple."""

    scope_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class DuplicateIntentDecisionV1(SealedModel):
    """Issued, side-effect-free comparison result with no caller data echoed."""

    status: DuplicateIntentStatusV1
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason_code: Literal["IDEMPOTENCY_CONFLICT"] | None = None


def _sha256(domain: bytes, content: bytes) -> str:
    return hashlib.sha256(domain + content).hexdigest()


def _json_string_length(value: str, remaining: int) -> int:
    """Count ensure_ascii JSON bytes without constructing an escaped copy."""

    length = 2  # surrounding quotes
    if length > remaining:
        raise IdempotencyError("INVALID_REQUEST")
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise IdempotencyError("INVALID_REQUEST")
        if codepoint < 0x20:
            increment = 2 if character in "\b\t\n\f\r" else 6
        elif character in ('"', "\\"):
            increment = 2
        elif codepoint < 0x80:
            increment = 1
        elif codepoint <= 0xFFFF:
            increment = 6
        else:
            increment = 12
        length += increment
        if length > remaining:
            raise IdempotencyError("INVALID_REQUEST")
    return length


def _preflight_canonical_size(payload: object) -> int:
    """Bound canonical output size before NUM-001 materializes its byte string."""

    if type(payload) is not dict:
        raise IdempotencyError("INVALID_REQUEST")

    pending: list[tuple[object, int]] = [(payload, 0)]
    nodes = 0
    encoded_size = 0

    def add_size(size: int) -> None:
        nonlocal encoded_size
        encoded_size += size
        if encoded_size > _MAX_PAYLOAD_BYTES:
            raise IdempotencyError("INVALID_REQUEST")

    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > _MAX_PAYLOAD_NODES or depth > _MAX_PAYLOAD_DEPTH:
            raise IdempotencyError("INVALID_REQUEST")
        if value is None:
            add_size(4)
            continue
        if type(value) is bool:
            add_size(4 if value else 5)
            continue
        if type(value) is int:
            add_size(len(canonical_str(value)))
            continue
        if isinstance(value, str):
            add_size(_json_string_length(value, _MAX_PAYLOAD_BYTES - encoded_size))
            continue
        if isinstance(value, Mapping):
            if type(value) is not dict:
                raise IdempotencyError("INVALID_REQUEST")
            add_size(2 + max(0, len(value) - 1))
            for key, child in value.items():
                if type(key) is not str:
                    raise IdempotencyError("INVALID_REQUEST")
                add_size(_json_string_length(key, _MAX_PAYLOAD_BYTES - encoded_size))
                add_size(1)  # colon
                pending.append((child, depth + 1))
            continue
        if isinstance(value, (list, tuple)):
            if type(value) not in (list, tuple):
                raise IdempotencyError("INVALID_REQUEST")
            add_size(2 + max(0, len(value) - 1))
            pending.extend((child, depth + 1) for child in value)
            continue
        if isinstance(value, Decimal):
            add_size(len(canonical_str(value)))
            continue
        raise IdempotencyError("INVALID_REQUEST")
    return encoded_size


def fingerprint_payload(payload: Mapping[str, object]) -> str:
    """Fingerprint a plain JSON mapping using NUM-001 canonical JSON."""

    try:
        _preflight_canonical_size(payload)
        encoded = canonical_json(payload)
    except IdempotencyError:
        raise
    except Exception:
        raise IdempotencyError("INVALID_REQUEST") from None
    if len(encoded) > _MAX_PAYLOAD_BYTES:
        raise IdempotencyError("INVALID_REQUEST")
    return _sha256(_PAYLOAD_DOMAIN, encoded)


def _validate_identifier(value: object, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise IdempotencyError("INVALID_REQUEST")
    return value


def _normalize_action(action: object) -> ExportActionV1:
    if type(action) is ExportActionV1:
        return action
    if type(action) is str:
        try:
            return ExportActionV1(action)
        except ValueError:
            pass
    raise IdempotencyError("INVALID_REQUEST")


def create_request_binding(
    *,
    project_id: str,
    action: ExportActionV1 | str,
    idempotency_key: str,
    payload: Mapping[str, object],
) -> RequestBindingV1:
    """Bind a scoped key to canonical request content without storing it."""

    project = _validate_identifier(project_id, _PROJECT_ID)
    key = _validate_identifier(idempotency_key, _IDEMPOTENCY_KEY)
    normalized_action = _normalize_action(action)
    payload_digest = fingerprint_payload(payload)
    key_digest = _sha256(_KEY_DOMAIN, key.encode("ascii"))
    scope_digest = _sha256(
        _SCOPE_DOMAIN,
        canonical_json(
            {
                "project_id": project,
                "action": normalized_action.value,
                "key_fingerprint": key_digest,
            }
        ),
    )
    request_digest = _sha256(
        _REQUEST_DOMAIN,
        canonical_json({"scope_fingerprint": scope_digest, "payload_fingerprint": payload_digest}),
    )
    try:
        binding = RequestBindingV1(
            scope_fingerprint=scope_digest,
            payload_fingerprint=payload_digest,
            request_fingerprint=request_digest,
        )
        return _BINDING_ISSUER.issue(binding)
    except Exception:
        raise IdempotencyError("INVALID_REQUEST") from None


def _require_binding(binding: object) -> RequestBindingV1:
    if type(binding) is not RequestBindingV1:
        raise IdempotencyError("INVALID_BINDING")
    try:
        require(binding, _BINDING_TAG)
    except SealError:
        raise IdempotencyError("INVALID_BINDING") from None
    return binding


def decide_duplicate_intent(
    prior: RequestBindingV1 | None,
    candidate: RequestBindingV1,
) -> DuplicateIntentDecisionV1:
    """Compare one prior binding with a candidate; no storage or effects occur."""

    current = _require_binding(candidate)
    previous = None if prior is None else _require_binding(prior)
    status: DuplicateIntentStatusV1
    reason_code: Literal["IDEMPOTENCY_CONFLICT"] | None
    if previous is None or previous.scope_fingerprint != current.scope_fingerprint:
        status = DuplicateIntentStatusV1.NEW
        reason_code = None
    elif previous.payload_fingerprint == current.payload_fingerprint:
        status = DuplicateIntentStatusV1.REPLAY
        reason_code = None
    else:
        status = DuplicateIntentStatusV1.CONFLICT
        reason_code = "IDEMPOTENCY_CONFLICT"

    try:
        decision = DuplicateIntentDecisionV1(
            status=status,
            request_fingerprint=current.request_fingerprint,
            reason_code=reason_code,
        )
        return _DECISION_ISSUER.issue(decision)
    except Exception:
        raise IdempotencyError("INVALID_BINDING") from None


__all__ = [
    "DuplicateIntentDecisionV1",
    "DuplicateIntentStatusV1",
    "ExportActionV1",
    "IdempotencyError",
    "RequestBindingV1",
    "create_request_binding",
    "decide_duplicate_intent",
    "fingerprint_payload",
]
