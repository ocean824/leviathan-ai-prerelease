"""Versioned diagnostic field allowlist and conservative scalar sanitization."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar, TypeAlias
from uuid import UUID

from leviathan_core.observability.context import DiagnosticIdFactoryV1, GeneratedIdV1

MAX_FIELD_BYTES = 8 * 1024
MAX_LINE_BYTES = 64 * 1024
REDACTED = "[REDACTED]"

DiagnosticScalar: TypeAlias = str | int | bool
JsonValue: TypeAlias = DiagnosticScalar | None | list["JsonValue"] | dict[str, "JsonValue"]

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z", re.ASCII)
_CREDENTIAL = re.compile(
    r"bearer|password|secret|token|credential|authorization|cookie|"
    r"api[_-]?key|private[_-]?key|auth[_-]?token|\bkey\b",
    re.IGNORECASE | re.ASCII,
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.ASCII)
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", re.ASCII)
_PHONE = re.compile(r"(?<!\w)\+?\d[\d(). -]{7,}\d(?!\w)", re.ASCII)
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)", re.ASCII)
_TOKEN = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{20,}(?![A-Za-z0-9_+/=-])", re.ASCII)
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]{4,}\.){2}[A-Za-z0-9_-]{4,}(?![A-Za-z0-9_-])",
    re.ASCII,
)
_DECIMAL_TEXT = re.compile(r"-?(?:0|[1-9][0-9]{0,37})(?:\.[0-9]{1,18})?\Z", re.ASCII)
_ULID = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z", re.ASCII)
_TRACE_ID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_SPAN_ID = re.compile(r"[0-9a-f]{16}\Z", re.ASCII)


class DiagnosticFieldType(StrEnum):
    ID = "id"
    COUNT = "count"
    DURATION_NS = "duration_ns"
    ENUM = "enum"
    ERROR_CODE = "error_code"
    DECIMAL = "decimal"
    BOOL = "bool"


class DiagnosticIdGrammar(StrEnum):
    UUID4 = "uuid4"
    ULID = "ulid"
    ORDER = "order"
    TRACE_ID = "trace_id"
    SPAN_ID = "span_id"


class DiagnosticClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"


@dataclass(frozen=True, slots=True)
class DiagnosticFieldSpecV1:
    name: str
    kind: DiagnosticFieldType
    classification: DiagnosticClassification
    allowed_values: tuple[str, ...] = ()
    id_grammar: DiagnosticIdGrammar | None = None
    id_purpose: str | None = None


class DiagnosticFieldRegistryV1:
    """Code-defined v1 field schema; callers cannot register dynamic keys."""

    __slots__ = ()
    VERSION: ClassVar[int] = 1
    _FIELDS: ClassVar[Mapping[str, DiagnosticFieldSpecV1]] = MappingProxyType(
        {
            "event_id": DiagnosticFieldSpecV1(
                "event_id",
                DiagnosticFieldType.ID,
                DiagnosticClassification.INTERNAL,
                id_grammar=DiagnosticIdGrammar.UUID4,
                id_purpose="event",
            ),
            "order_id": DiagnosticFieldSpecV1(
                "order_id",
                DiagnosticFieldType.ID,
                DiagnosticClassification.INTERNAL,
                id_grammar=DiagnosticIdGrammar.ORDER,
                id_purpose="order",
            ),
            "trace_id": DiagnosticFieldSpecV1(
                "trace_id",
                DiagnosticFieldType.ID,
                DiagnosticClassification.INTERNAL,
                id_grammar=DiagnosticIdGrammar.TRACE_ID,
                id_purpose="trace",
            ),
            "span_id": DiagnosticFieldSpecV1(
                "span_id",
                DiagnosticFieldType.ID,
                DiagnosticClassification.INTERNAL,
                id_grammar=DiagnosticIdGrammar.SPAN_ID,
                id_purpose="span",
            ),
            "stage": DiagnosticFieldSpecV1(
                "stage",
                DiagnosticFieldType.ENUM,
                DiagnosticClassification.PUBLIC,
                (
                    "pipeline.decode",
                    "pipeline.normalize",
                    "risk.evaluate",
                    "queue.publish",
                    "queue.consume",
                    "transform",
                    "unknown",
                ),
            ),
            "detail_code": DiagnosticFieldSpecV1(
                "detail_code",
                DiagnosticFieldType.ENUM,
                DiagnosticClassification.INTERNAL,
                ("OBSERVATION", "VALIDATED", "REJECTED", "UNKNOWN"),
            ),
            "count": DiagnosticFieldSpecV1(
                "count", DiagnosticFieldType.COUNT, DiagnosticClassification.PUBLIC
            ),
            "duration_ns": DiagnosticFieldSpecV1(
                "duration_ns", DiagnosticFieldType.DURATION_NS, DiagnosticClassification.PUBLIC
            ),
            "status": DiagnosticFieldSpecV1(
                "status",
                DiagnosticFieldType.ENUM,
                DiagnosticClassification.PUBLIC,
                ("STARTED", "COMPLETED", "FAILED", "PENDING", "ok"),
            ),
            "error_code": DiagnosticFieldSpecV1(
                "error_code", DiagnosticFieldType.ERROR_CODE, DiagnosticClassification.INTERNAL
            ),
            "value": DiagnosticFieldSpecV1(
                "value", DiagnosticFieldType.DECIMAL, DiagnosticClassification.INTERNAL
            ),
            "retryable": DiagnosticFieldSpecV1(
                "retryable", DiagnosticFieldType.BOOL, DiagnosticClassification.PUBLIC
            ),
        }
    )

    @property
    def fields(self) -> Mapping[str, DiagnosticFieldSpecV1]:
        return self._FIELDS

    def get(self, name: str) -> DiagnosticFieldSpecV1 | None:
        return self._FIELDS.get(name)


class DiagnosticFieldError(ValueError):
    """Safe validation error; the caller's key text is never retained or printed."""

    def __init__(self, code: str, key: object) -> None:
        key_bytes = (
            key.encode("utf-8", "surrogatepass") if isinstance(key, str) else b"<non-string>"
        )
        self.code = code
        self.key_sha256 = hashlib.sha256(key_bytes).hexdigest()
        super().__init__(f"{code} key_sha256={self.key_sha256}")


class RedactionError(ValueError):
    """Diagnostic input could not be handled safely; never includes the input."""


def _redaction_reason(value: str) -> str | None:
    if _CREDENTIAL.search(value):
        return "credential"
    if _EMAIL.search(value) or _SSN.search(value) or _PHONE.search(value) or _card_like(value):
        return "pii"
    if _TOKEN.search(value) or any(len(match.group()) >= 20 for match in _JWT.finditer(value)):
        return "token"
    return None


def _card_like(value: str) -> bool:
    for match in _CARD.finditer(value):
        digits = [int(char) for char in match.group() if char.isdigit()]
        if not 13 <= len(digits) <= 19:
            continue
        total = 0
        for index, digit in enumerate(reversed(digits)):
            if index % 2:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        if total % 10 == 0:
            return True
    return False


def _marker(reason: str) -> str:
    return f"[REDACTED:{reason}]"


def _safe_string(value: str, *, check_tokens: bool = True) -> tuple[str, bool]:
    if len(value) > 128:
        return _marker("length"), True
    reason = _redaction_reason(value)
    if reason == "token" and not check_tokens:
        reason = None
    if reason is not None:
        return _marker(reason), True
    if _SAFE_ID.fullmatch(value) is None:
        return _marker("charset"), True
    return value, False


def truncate_utf8(value: str, limit: int = MAX_FIELD_BYTES) -> tuple[str, bool]:
    """Bound serialized JSON bytes and add a visible UTF-8-safe truncation suffix."""
    suffix = "…[truncated]"
    if limit < len(json.dumps(suffix, ensure_ascii=False).encode("utf-8")):
        raise ValueError("serialized field limit is too small")

    def size(candidate: str) -> int:
        return len(json.dumps(candidate, ensure_ascii=False).encode("utf-8"))

    if size(value) <= limit:
        return value, False
    low, high = 0, len(value)
    while low < high:
        middle = (low + high + 1) // 2
        if size(value[:middle] + suffix) <= limit:
            low = middle
        else:
            high = middle - 1
    return value[:low] + suffix, True


def _validate_scalar(
    key: str, value: object, spec: DiagnosticFieldSpecV1, id_factory: DiagnosticIdFactoryV1
) -> tuple[DiagnosticScalar, bool]:
    kind = spec.kind
    if kind == DiagnosticFieldType.ID:
        if (
            spec.id_purpose is None
            or not isinstance(value, GeneratedIdV1)
            or not id_factory.owns(value, spec.id_purpose)
        ):
            raise DiagnosticFieldError("DIAGNOSTIC_FIELD_INVALID", key)
        return value.value, False
    if kind in (DiagnosticFieldType.COUNT, DiagnosticFieldType.DURATION_NS):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10**18:
            raise DiagnosticFieldError("DIAGNOSTIC_FIELD_INVALID", key)
        if _card_like(str(value)):
            return _marker("pii"), True
        return value, False
    if kind == DiagnosticFieldType.BOOL:
        if not isinstance(value, bool):
            raise DiagnosticFieldError("DIAGNOSTIC_FIELD_INVALID", key)
        return value, False
    if kind == DiagnosticFieldType.ENUM:
        if not isinstance(value, str) or value not in spec.allowed_values:
            raise DiagnosticFieldError("DIAGNOSTIC_FIELD_INVALID", key)
        return value, False
    if kind == DiagnosticFieldType.ERROR_CODE:
        if not isinstance(value, str) or value not in (
            "UNKNOWN",
            "INVALID_INPUT",
            "INTERNAL_ERROR",
            "REDACTION_FAILURE",
            "DIAGNOSTIC_FIELD_UNREGISTERED",
        ):
            raise DiagnosticFieldError("DIAGNOSTIC_FIELD_INVALID", key)
        return value, False
    if kind == DiagnosticFieldType.DECIMAL:
        if isinstance(value, Decimal):
            exponent = value.as_tuple().exponent
            if not value.is_finite() or not isinstance(exponent, int) or not -18 <= exponent <= 38:
                raise DiagnosticFieldError("DIAGNOSTIC_FIELD_INVALID", key)
            rendered = format(value, "f")
        elif isinstance(value, str):
            rendered = value
        else:
            raise DiagnosticFieldError("DIAGNOSTIC_FIELD_INVALID", key)
        if _DECIMAL_TEXT.fullmatch(rendered) is None:
            raise DiagnosticFieldError("DIAGNOSTIC_FIELD_INVALID", key)
        return (_marker("pii"), True) if _card_like(rendered) else (rendered, False)
    raise DiagnosticFieldError("DIAGNOSTIC_FIELD_INVALID", key)


def sanitize_fields(
    fields: Mapping[str, object], *, id_factory: DiagnosticIdFactoryV1
) -> tuple[dict[str, DiagnosticScalar], bool, bool]:
    """Return safe scalar fields, truncation flag, and redaction flag."""
    if not isinstance(fields, Mapping):
        raise RedactionError("invalid diagnostic fields")
    registry = DiagnosticFieldRegistryV1()
    safe: dict[str, DiagnosticScalar] = {}
    truncated = False
    redacted = False
    for key, value in fields.items():
        if not isinstance(key, str) or registry.get(key) is None:
            raise DiagnosticFieldError("DIAGNOSTIC_FIELD_UNREGISTERED", key)
        if key in safe:
            raise DiagnosticFieldError("DIAGNOSTIC_FIELD_INVALID", key)
        spec = registry.get(key)
        assert spec is not None
        scalar, replaced = _validate_scalar(key, value, spec, id_factory)
        if isinstance(scalar, str):
            scalar, cut = truncate_utf8(scalar)
            truncated |= cut
        safe[key] = scalar
        redacted |= replaced
    return safe, truncated, redacted


def redact_fields(
    fields: Mapping[str, object], *, id_factory: DiagnosticIdFactoryV1
) -> tuple[dict[str, DiagnosticScalar], bool]:
    """Compatibility helper using the v1 registry; rejects unregistered fields."""
    safe, truncated, _ = sanitize_fields(fields, id_factory=id_factory)
    return safe, truncated


def sanitize_context_value(
    value: str, *, allow_uuid: bool = False, check_tokens: bool = True
) -> tuple[str, bool]:
    """Protect fixed context labels without treating them as dynamic field keys."""
    if allow_uuid:
        try:
            parsed = UUID(value)
        except (TypeError, ValueError, AttributeError):
            pass
        else:
            if parsed.version == 4 and str(parsed) == value:
                return value, False
    safe, redacted = _safe_string(value, check_tokens=check_tokens)
    return ("redacted", True) if redacted else (safe, False)
