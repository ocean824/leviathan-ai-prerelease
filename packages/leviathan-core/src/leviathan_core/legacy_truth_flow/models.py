"""Immutable inputs and response descriptors for archived truth reads."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from decimal import (
    ROUND_HALF_EVEN,
    Decimal,
    DivisionByZero,
    Inexact,
    InvalidOperation,
    Overflow,
    Rounded,
    localcontext,
)
from typing import Literal, NoReturn, SupportsIndex

Dataset = Literal["order_flow", "options"]
EvidenceStatus = Literal[
    "CURRENT", "STALE", "EMBARGOED", "UNENTITLED", "UNKNOWN", "CONFIRMED"
]
_DATASETS = frozenset(("order_flow", "options"))
_STATUSES = frozenset(("CURRENT", "STALE", "EMBARGOED", "UNENTITLED", "UNKNOWN", "CONFIRMED"))
_UTC_ISO = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|\+00:00)$"
)
_SUCCESSOR = re.compile(r"^/[A-Za-z0-9/_-]+$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")


class ArchivedTruthBoundaryError(ValueError):
    """Fixed-code boundary failure without caller-supplied values."""

    def __init__(self, code: str, field_paths: tuple[str, ...] = ()) -> None:
        self.code = code
        self.field_paths = field_paths
        super().__init__(code)


class _FrozenBoundary:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise ArchivedTruthBoundaryError("FROZEN_OBJECT")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        del memo
        raise ArchivedTruthBoundaryError("FROZEN_OBJECT")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise ArchivedTruthBoundaryError("FROZEN_OBJECT")


def _text(value: object, field: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str) or not value or any(
        ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise ArchivedTruthBoundaryError("INVALID_FIELD", (field,))


def _ns(value: object, field: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ArchivedTruthBoundaryError("INVALID_INTEGER", (field,))


def _text_tuple(value: object, field: str) -> None:
    if not isinstance(value, tuple):
        raise ArchivedTruthBoundaryError("INVALID_FIELD", (field,))
    for item in value:
        _text(item, field)


def _headers(value: object) -> None:
    if not isinstance(value, tuple):
        raise ArchivedTruthBoundaryError("INVALID_FIELD", ("headers",))
    for pair in value:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("headers",))
        _text(pair[0], "headers")
        _text(pair[1], "headers")


def _canonical_decimal(value: Decimal) -> str:
    with localcontext() as context:
        context.prec = 34
        context.rounding = ROUND_HALF_EVEN
        for signal in (InvalidOperation, Overflow, DivisionByZero, Inexact, Rounded):
            context.traps[signal] = True
        if value.is_zero():
            return "0"
        plain = format(value, "f")
        return plain.rstrip("0").rstrip(".") if "." in plain else plain


def _exact_decimal(value: Decimal | str | int | None) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, (bool, float)) or not isinstance(value, (Decimal, str, int)):
        raise ArchivedTruthBoundaryError("INVALID_DECIMAL")
    if isinstance(value, str) and len(value) > 256:
        raise ArchivedTruthBoundaryError("PRECISION_EXCEEDED")
    with localcontext() as context:
        context.prec = 34
        context.rounding = ROUND_HALF_EVEN
        for signal in (InvalidOperation, Overflow, DivisionByZero, Inexact, Rounded):
            context.traps[signal] = True
        try:
            result = Decimal(value)
        except InvalidOperation as exc:
            raise ArchivedTruthBoundaryError("INVALID_DECIMAL") from exc
        if not result.is_finite():
            raise ArchivedTruthBoundaryError("INVALID_DECIMAL")
        parts = result.as_tuple()
        significant = len(parts.digits)
        while significant > 1 and parts.digits[significant - 1] == 0:
            significant -= 1
        if significant > 34:
            raise ArchivedTruthBoundaryError("PRECISION_EXCEEDED")
        if abs(result.adjusted()) > 38:
            raise ArchivedTruthBoundaryError("INVALID_DECIMAL")
        if not isinstance(parts.exponent, int):
            raise ArchivedTruthBoundaryError("INVALID_DECIMAL")
        exponent = parts.exponent + len(parts.digits) - significant
        trimmed = Decimal(
            (parts.sign, parts.digits[:significant], exponent)
        )
        canonical = Decimal(_canonical_decimal(trimmed))
        return canonical if len(canonical.as_tuple().digits) <= 34 else trimmed


@dataclass(frozen=True, slots=True)
class ArchivedTruthQueryV1(_FrozenBoundary):
    """Tenant and scope are supplied only after upstream authentication."""

    tenant_id: str
    dataset: str
    start_utc: str
    end_utc: str
    trace_id: str
    symbol: str | None = None
    osi: str | None = None
    side: str | None = None
    venue: str | None = None
    currency: str | None = None
    event_type: str | None = None
    limit: int = 1000
    cursor: str | None = None
    if_none_match: str | None = None
    read_scope_verified: bool = False

    def __post_init__(self) -> None:
        for field in ("tenant_id", "dataset", "start_utc", "end_utc", "trace_id"):
            _text(getattr(self, field), field)
        for field in (
            "symbol", "osi", "side", "venue", "currency", "event_type", "cursor", "if_none_match"
        ):
            _text(getattr(self, field), field, nullable=True)
        _ns(self.limit, "limit")
        if type(self.read_scope_verified) is not bool:
            raise ArchivedTruthBoundaryError("INVALID_BOOL", ("read_scope_verified",))


@dataclass(frozen=True, slots=True)
class _TruthSourceRecordV1(_FrozenBoundary):
    record_id: str
    tenant_id: str
    dataset: Dataset
    timestamp_ns: int
    source_version: str
    symbol: str | None = None
    osi: str | None = None
    side: str | None = None
    venue: str | None = None
    currency: str | None = None
    event_type: str | None = None
    price: Decimal | None = None
    size: Decimal | None = None
    value: Decimal | None = None
    liquidity_flag: str | None = None
    evidence_status: EvidenceStatus = "UNKNOWN"
    availability_ns: int | None = None
    embargo_until_ns: int | None = None
    timestamp_precision: Literal["ns", "us"] = "ns"
    source_dataset: str | None = None
    source_schema_version: str | None = None
    source_license: str | None = None
    source_entitlement: str | None = None
    source_checksum: str | None = None
    source_trace_id: str | None = None
    local_receipt_id: str | None = None
    mapping_key: str | None = None

    def __post_init__(self) -> None:
        for field in ("record_id", "tenant_id", "source_version"):
            _text(getattr(self, field), field)
        if not isinstance(self.dataset, str) or self.dataset not in _DATASETS:
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("dataset",))
        _ns(self.timestamp_ns, "timestamp_ns")
        _ns(self.availability_ns, "availability_ns", nullable=True)
        _ns(self.embargo_until_ns, "embargo_until_ns", nullable=True)
        for field in (
            "symbol", "osi", "side", "venue", "currency", "event_type", "liquidity_flag",
            "source_dataset", "source_schema_version", "source_license", "source_entitlement",
            "source_checksum", "source_trace_id", "local_receipt_id", "mapping_key",
        ):
            _text(getattr(self, field), field, nullable=True)
        if not isinstance(self.evidence_status, str) or self.evidence_status not in _STATUSES:
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("evidence_status",))
        if self.timestamp_precision not in ("ns", "us"):
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("timestamp_precision",))
        if self.timestamp_precision == "us" and self.timestamp_ns % 1000:
            raise ArchivedTruthBoundaryError("INVALID_TIME", ("timestamp_ns",))
        for name in ("price", "size", "value"):
            object.__setattr__(self, name, _exact_decimal(getattr(self, name)))


@dataclass(frozen=True, slots=True)
class LegacyTruthRecordV1(_TruthSourceRecordV1):
    """A record read from an immutable archived table."""


@dataclass(frozen=True, slots=True)
class MappedTruthRecordV1(_TruthSourceRecordV1):
    """An already verified, uniquely mapped new-store source snapshot."""


@dataclass(frozen=True, slots=True)
class ArchivedTruthPolicyV1(_FrozenBoundary):
    sunset_utc: str
    snapshot_version: str
    reads_enabled: bool = True
    proxy_enabled: bool = True
    legacy_dataset_permitted: bool = False
    new_dataset_permitted: bool = False
    allowed_venues: tuple[str, ...] = ()
    allowed_currencies: tuple[str, ...] = ("USD",)
    successor_base: str = "/v2/truth"

    def __post_init__(self) -> None:
        for field in ("sunset_utc", "snapshot_version", "successor_base"):
            _text(getattr(self, field), field)
        if not _UTC_ISO.fullmatch(self.sunset_utc):
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("sunset_utc",))
        try:
            datetime.fromisoformat(self.sunset_utc.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("sunset_utc",)) from exc
        if not _SUCCESSOR.fullmatch(self.successor_base):
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("successor_base",))
        for field in (
            "reads_enabled", "proxy_enabled", "legacy_dataset_permitted", "new_dataset_permitted"
        ):
            if type(getattr(self, field)) is not bool:
                raise ArchivedTruthBoundaryError("INVALID_BOOL", (field,))
        for field in ("allowed_venues", "allowed_currencies"):
            value = getattr(self, field)
            if not isinstance(value, (tuple, list)):
                raise ArchivedTruthBoundaryError("INVALID_FIELD", (field,))
            frozen = tuple(value)
            _text_tuple(frozen, field)
            if field == "allowed_currencies" and any(
                not _CURRENCY.fullmatch(item) for item in frozen
            ):
                raise ArchivedTruthBoundaryError("INVALID_FIELD", (field,))
            object.__setattr__(self, field, frozen)


@dataclass(frozen=True, slots=True)
class ArchivedTruthRecordViewV1(_FrozenBoundary):
    record_id: str
    dataset: Dataset
    symbol: str | None
    osi: str | None
    timestamp_ns: int
    timestamp_precision: Literal["ns", "us"]
    side: str | None
    venue: str | None
    currency: str | None
    event_type: str | None
    price: Decimal | None
    size: Decimal | None
    value: Decimal | None
    liquidity_flag: str | None
    evidence_status: EvidenceStatus
    effective_status: EvidenceStatus
    historical_verdict: None
    confirmation_eligible: bool
    route_permitted: bool
    source: Literal["legacy", "proxy"]
    origin: Literal["LEGACY", "PROXY"]
    schema_version: Literal["legacy-1", "mapped-v2"]
    source_dataset: str | None
    source_schema_version: str | None
    source_version: str
    source_license: str | None
    source_entitlement: str | None
    source_checksum: str | None
    source_trace_id: str | None
    availability_ns: int | None
    embargo_until_ns: int | None
    checksum: str

    def __post_init__(self) -> None:
        for field in ("record_id", "source_version", "checksum"):
            _text(getattr(self, field), field)
        for field in (
            "symbol", "osi", "side", "venue", "currency", "event_type", "liquidity_flag",
            "source_dataset", "source_schema_version", "source_license", "source_entitlement",
            "source_checksum", "source_trace_id",
        ):
            _text(getattr(self, field), field, nullable=True)
        if not isinstance(self.dataset, str) or self.dataset not in _DATASETS:
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("dataset",))
        for field in ("evidence_status", "effective_status"):
            value = getattr(self, field)
            if not isinstance(value, str) or value not in _STATUSES:
                raise ArchivedTruthBoundaryError("INVALID_FIELD", (field,))
        for field, permitted in (
            ("timestamp_precision", ("ns", "us")),
            ("source", ("legacy", "proxy")),
            ("origin", ("LEGACY", "PROXY")),
            ("schema_version", ("legacy-1", "mapped-v2")),
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or value not in permitted:
                raise ArchivedTruthBoundaryError("INVALID_FIELD", (field,))
        if (self.source, self.origin, self.schema_version) not in (
            ("legacy", "LEGACY", "legacy-1"), ("proxy", "PROXY", "mapped-v2")
        ):
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("origin",))
        _ns(self.timestamp_ns, "timestamp_ns")
        _ns(self.availability_ns, "availability_ns", nullable=True)
        _ns(self.embargo_until_ns, "embargo_until_ns", nullable=True)
        if self.timestamp_precision == "us" and self.timestamp_ns % 1000:
            raise ArchivedTruthBoundaryError("INVALID_TIME", ("timestamp_ns",))
        for field in ("confirmation_eligible", "route_permitted"):
            if type(getattr(self, field)) is not bool or getattr(self, field):
                raise ArchivedTruthBoundaryError("INVALID_BOOL", (field,))
        if self.historical_verdict is not None:
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("historical_verdict",))
        for field in ("price", "size", "value"):
            object.__setattr__(self, field, _exact_decimal(getattr(self, field)))


@dataclass(frozen=True, slots=True)
class ArchivedTruthErrorV1(_FrozenBoundary):
    code: str
    trace_id: str
    field_paths: tuple[str, ...] = ()
    migrate_to: str | None = None

    def __post_init__(self) -> None:
        _text(self.code, "code")
        _text(self.trace_id, "trace_id")
        _text_tuple(self.field_paths, "field_paths")
        _text(self.migrate_to, "migrate_to", nullable=True)


@dataclass(frozen=True, slots=True)
class ArchivedTruthResultV1(_FrozenBoundary):
    status_code: int
    headers: tuple[tuple[str, str], ...]
    records: tuple[ArchivedTruthRecordViewV1, ...] = ()
    next_cursor: str | None = None
    error: ArchivedTruthErrorV1 | None = None
    proxy_hit: bool = False

    def __post_init__(self) -> None:
        _ns(self.status_code, "status_code")
        _headers(self.headers)
        if not isinstance(self.records, tuple) or any(
            not isinstance(record, ArchivedTruthRecordViewV1) for record in self.records
        ):
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("records",))
        _text(self.next_cursor, "next_cursor", nullable=True)
        if self.error is not None and not isinstance(self.error, ArchivedTruthErrorV1):
            raise ArchivedTruthBoundaryError("INVALID_FIELD", ("error",))
        if type(self.proxy_hit) is not bool:
            raise ArchivedTruthBoundaryError("INVALID_BOOL", ("proxy_hit",))


@dataclass(frozen=True, slots=True)
class ArchivedTruthWriteDecisionV1(_FrozenBoundary):
    status_code: int
    code: str
    allow: str
    headers: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        _ns(self.status_code, "status_code")
        for field in ("code", "allow"):
            _text(getattr(self, field), field)
        _headers(self.headers)
