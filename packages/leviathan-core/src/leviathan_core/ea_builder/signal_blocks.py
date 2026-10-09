"""Pure, sealed kernels for causal compare, crossover and signal emission."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Literal, TypeVar, cast

from pydantic import field_validator, model_validator

from leviathan_core.numeric import NumericError, parse_decimal, parse_int
from leviathan_core.seal import Issuer, SealedModel, SealError, require

CompareOpV1 = Literal["gt", "lt", "ge", "le"]
CrossDirectionV1 = Literal["above", "below"]
CompareOp = CompareOpV1
CrossDirection = CrossDirectionV1
BoolOperationV1 = Literal["gt", "lt", "ge", "le", "cross_above", "cross_below"]
ReadinessV1 = Literal["ready", "not_ready"]

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class SignalBlockError(Exception):
    """Content-free failure at the EA signal schema or evaluation boundary."""

    def __init__(self, code: str, field: str = "model", error_type: str = "invalid") -> None:
        self.code = code
        self.field = field
        self.error_type = error_type
        super().__init__(code, field, error_type)

    def __str__(self) -> str:
        return f"{self.code}:{self.field}:{self.error_type}"

    def errors(self) -> list[dict[str, str]]:
        return [{"code": self.code, "field": self.field, "type": self.error_type}]


class _SignalModel(SealedModel):
    """Shared immutable schema base; public factories map seal errors safely."""


class NumericV1(_SignalModel):
    schema_version: Literal["1"]
    value: Decimal
    unit: str
    identity_kind: Literal["source", "feature"]
    identity_id: str
    identity_version: int
    identity_digest: str
    symbol: str
    timeframe: str
    bar_id: str
    bar_index: int
    event_ns: int
    effective_ns: int
    available_ns: int
    asof_ns: int
    finalized: Literal[True]

    @field_validator("value", mode="before")
    @classmethod
    def _exact_decimal(cls, value: object) -> Decimal:
        if not isinstance(value, Decimal):
            raise ValueError("invalid decimal")
        return parse_decimal(value, field="value")

    @field_validator("unit", "identity_id", "symbol", "timeframe", "bar_id")
    @classmethod
    def _stable_identifier(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("invalid identifier")
        return value

    @field_validator("identity_version")
    @classmethod
    def _positive_version(cls, value: int) -> int:
        return parse_int(value, field="identity_version", min_value=1, max_value=10**38)

    @field_validator("identity_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("invalid digest")
        return value

    @field_validator("bar_index", "event_ns", "effective_ns", "available_ns", "asof_ns")
    @classmethod
    def _nonnegative_integer(cls, value: int, info: object) -> int:
        field = getattr(info, "field_name", "value")
        return parse_int(value, field=field, min_value=0, max_value=10**38)

    @model_validator(mode="after")
    def _chronology(self) -> NumericV1:
        if not (self.event_ns <= self.available_ns <= self.asof_ns):
            raise ValueError("invalid availability chronology")
        if not (self.effective_ns <= self.available_ns):
            raise ValueError("invalid effective chronology")
        return self


class NumericSeriesV1(_SignalModel):
    schema_version: Literal["1"]
    symbol: str
    timeframe: str
    current: NumericV1
    previous: NumericV1 | None
    asof_ns: int

    @field_validator("symbol", "timeframe")
    @classmethod
    def _stable_identifier(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("invalid identifier")
        return value

    @field_validator("asof_ns")
    @classmethod
    def _asof(cls, value: int) -> int:
        return parse_int(value, field="asof_ns", min_value=0, max_value=10**38)

    @model_validator(mode="after")
    def _scope_and_bar_order(self) -> NumericSeriesV1:
        values = (self.current,) if self.previous is None else (self.previous, self.current)
        for item in values:
            if item.symbol != self.symbol or item.timeframe != self.timeframe:
                raise ValueError("scope mismatch")
            if item.available_ns > self.asof_ns:
                raise ValueError("value unavailable as of cursor")
        if self.previous is not None:
            if self.current.unit != self.previous.unit:
                raise ValueError("unit mismatch")
            if self.current.bar_index != self.previous.bar_index + 1:
                raise ValueError("bars are not adjacent")
            if self.current.bar_id == self.previous.bar_id:
                raise ValueError("bar identities are not distinct")
            if self.current.asof_ns != self.asof_ns or self.previous.asof_ns != self.asof_ns:
                raise ValueError("as-of cursor mismatch")
        elif self.current.asof_ns != self.asof_ns:
            raise ValueError("as-of cursor mismatch")
        return self


class BoolV1(_SignalModel):
    schema_version: Literal["1"]
    status: ReadinessV1
    value: bool | None
    operation: BoolOperationV1
    graph_revision_hash: str
    node_id: str
    symbol: str
    timeframe: str
    finalized_bar_id: str
    event_ns: int
    effective_ns: int
    available_ns: int
    asof_ns: int

    @field_validator("value", mode="before")
    @classmethod
    def _strict_optional_bool(cls, value: object) -> object:
        if value is not None and type(value) is not bool:
            raise ValueError("invalid boolean")
        return value

    @field_validator("graph_revision_hash")
    @classmethod
    def _revision_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("invalid revision hash")
        return value

    @field_validator("operation", "node_id", "symbol", "timeframe", "finalized_bar_id")
    @classmethod
    def _identities(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("invalid identifier")
        return value

    @field_validator("event_ns", "effective_ns", "available_ns", "asof_ns")
    @classmethod
    def _clocks(cls, value: int, info: object) -> int:
        return parse_int(
            value,
            field=getattr(info, "field_name", "clock"),
            min_value=0,
            max_value=10**38,
        )

    @model_validator(mode="after")
    def _readiness(self) -> BoolV1:
        if (self.status == "ready") is not (self.value is not None):
            raise ValueError("invalid readiness")
        if not (self.event_ns <= self.available_ns <= self.asof_ns):
            raise ValueError("invalid availability chronology")
        if not (self.effective_ns <= self.available_ns):
            raise ValueError("invalid effective chronology")
        return self


class _SignalRecord(_SignalModel):
    schema_version: Literal["1"]
    graph_revision_hash: str
    signal_key: str
    symbol: str
    timeframe: str
    finalized_bar_id: str
    event_ns: int
    effective_ns: int
    available_ns: int
    source_node_id: str

    @field_validator("graph_revision_hash")
    @classmethod
    def _revision_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("invalid revision hash")
        return value

    @field_validator("signal_key", "symbol", "timeframe", "finalized_bar_id", "source_node_id")
    @classmethod
    def _identities(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("invalid identifier")
        return value

    @field_validator("event_ns", "effective_ns", "available_ns")
    @classmethod
    def _clocks(cls, value: int, info: object) -> int:
        return parse_int(
            value,
            field=getattr(info, "field_name", "clock"),
            min_value=0,
            max_value=10**38,
        )

    @model_validator(mode="after")
    def _chronology(self) -> _SignalRecord:
        if self.event_ns > self.available_ns or self.effective_ns > self.available_ns:
            raise ValueError("invalid chronology")
        return self

    @property
    def deduplication_key(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.graph_revision_hash,
            self.source_node_id,
            self.symbol,
            self.timeframe,
            self.finalized_bar_id,
            self.signal_key,
        )


class EntrySignalV1(_SignalRecord):
    pass


class ExitSignalV1(_SignalRecord):
    pass


SignalRecordT = TypeVar("SignalRecordT", EntrySignalV1, ExitSignalV1)


_NUMERIC_TAG = "ea001b.numeric.v1"
_SERIES_TAG = "ea001b.numeric_series.v1"
_BOOL_TAG = "ea001b.bool.v1"
_ENTRY_TAG = "ea001b.entry_signal.v1"
_EXIT_TAG = "ea001b.exit_signal.v1"
_NUMERIC_ISSUER = Issuer(_NUMERIC_TAG)
_SERIES_ISSUER = Issuer(_SERIES_TAG)
_BOOL_ISSUER = Issuer(_BOOL_TAG)
_ENTRY_ISSUER = Issuer(_ENTRY_TAG)
_EXIT_ISSUER = Issuer(_EXIT_TAG)


def _issue(model: type[_SignalModel], issuer: Issuer, fields: dict[str, object]) -> object:
    try:
        return issuer.issue(model(**fields))
    except SignalBlockError:
        raise
    except (SealError, NumericError, ValueError, TypeError):
        raise SignalBlockError("INVALID_SIGNAL_MODEL") from None


def make_numeric_v1(
    *,
    schema_version: Literal["1"],
    value: Decimal,
    unit: str,
    identity_kind: Literal["source", "feature"],
    identity_id: str,
    identity_version: int,
    identity_digest: str,
    symbol: str,
    timeframe: str,
    bar_id: str,
    bar_index: int,
    event_ns: int,
    effective_ns: int,
    available_ns: int,
    asof_ns: int,
    finalized: Literal[True],
) -> NumericV1:
    """Validate and issue one exact, finalized source/feature numeric value."""
    return _issue(
        NumericV1,
        _NUMERIC_ISSUER,
        {
            "schema_version": schema_version,
            "value": value,
            "unit": unit,
            "identity_kind": identity_kind,
            "identity_id": identity_id,
            "identity_version": identity_version,
            "identity_digest": identity_digest,
            "symbol": symbol,
            "timeframe": timeframe,
            "bar_id": bar_id,
            "bar_index": bar_index,
            "event_ns": event_ns,
            "effective_ns": effective_ns,
            "available_ns": available_ns,
            "asof_ns": asof_ns,
            "finalized": finalized,
        },
    )  # type: ignore[return-value]


def make_numeric_series_v1(
    *,
    symbol: str,
    timeframe: str,
    current: NumericV1,
    previous: NumericV1 | None,
    asof_ns: int,
) -> NumericSeriesV1:
    """Issue a current/prior finalized series; ``previous=None`` is warmup."""
    _require(current, _NUMERIC_TAG)
    if previous is not None:
        _require(previous, _NUMERIC_TAG)
    return _issue(
        NumericSeriesV1,
        _SERIES_ISSUER,
        {
            "schema_version": "1",
            "symbol": symbol,
            "timeframe": timeframe,
            "current": current,
            "previous": previous,
            "asof_ns": asof_ns,
        },
    )  # type: ignore[return-value]


def _require(obj: object, tag: str) -> None:
    try:
        require(obj, tag)
    except SealError:
        raise SignalBlockError("UNISSUED_SIGNAL_INPUT") from None


def _context(
    operation: str,
    *,
    graph_revision_hash: str,
    node_id: str,
    symbol: str,
    timeframe: str,
    bar_id: str,
    event_ns: int,
    effective_ns: int,
    available_ns: int,
    asof_ns: int,
) -> dict[str, object]:
    return {
        "schema_version": "1",
        "status": "ready",
        "value": False,
        "operation": operation,
        "graph_revision_hash": graph_revision_hash,
        "node_id": node_id,
        "symbol": symbol,
        "timeframe": timeframe,
        "finalized_bar_id": bar_id,
        "event_ns": event_ns,
        "effective_ns": effective_ns,
        "available_ns": available_ns,
        "asof_ns": asof_ns,
    }


def evaluate_compare_v1(
    operation: CompareOpV1,
    left: NumericV1,
    right: NumericV1,
    *,
    graph_revision_hash: str,
    node_id: str,
) -> BoolV1:
    """Evaluate an exact comparison over two values at the same finalized bar."""
    _require(left, _NUMERIC_TAG)
    _require(right, _NUMERIC_TAG)
    if operation not in ("gt", "lt", "ge", "le"):
        raise SignalBlockError("UNSUPPORTED_OPERATOR", "operation")
    if (
        left.unit != right.unit
        or left.symbol != right.symbol
        or left.timeframe != right.timeframe
        or left.bar_id != right.bar_id
        or left.bar_index != right.bar_index
        or left.asof_ns != right.asof_ns
    ):
        raise SignalBlockError("INCOMPATIBLE_SIGNAL_INPUTS")
    if max(left.available_ns, right.available_ns) > left.asof_ns:
        raise SignalBlockError("SIGNAL_INPUT_NOT_AVAILABLE")
    result = _context(
        operation,
        graph_revision_hash=graph_revision_hash,
        node_id=node_id,
        symbol=left.symbol,
        timeframe=left.timeframe,
        bar_id=left.bar_id,
        event_ns=max(left.event_ns, right.event_ns),
        effective_ns=max(left.effective_ns, right.effective_ns),
        available_ns=max(left.available_ns, right.available_ns),
        asof_ns=left.asof_ns,
    )
    predicates = {
        "gt": left.value > right.value,
        "lt": left.value < right.value,
        "ge": left.value >= right.value,
        "le": left.value <= right.value,
    }
    result["value"] = predicates[operation]
    return _issue(BoolV1, _BOOL_ISSUER, result)  # type: ignore[return-value]


def evaluate_crossover_v1(
    direction: CrossDirectionV1,
    left: NumericSeriesV1,
    right: NumericSeriesV1,
    *,
    graph_revision_hash: str,
    node_id: str,
) -> BoolV1:
    """Evaluate a finalized current/prior crossover, retaining warmup as not-ready."""
    _require(left, _SERIES_TAG)
    _require(right, _SERIES_TAG)
    if direction not in ("above", "below"):
        raise SignalBlockError("UNSUPPORTED_OPERATOR", "direction")
    if (
        left.symbol != right.symbol
        or left.timeframe != right.timeframe
        or left.asof_ns != right.asof_ns
    ):
        raise SignalBlockError("INCOMPATIBLE_SIGNAL_INPUTS")
    if left.current.unit != right.current.unit:
        raise SignalBlockError("INCOMPATIBLE_SIGNAL_INPUTS")
    if (
        left.current.bar_id != right.current.bar_id
        or left.current.bar_index != right.current.bar_index
    ):
        raise SignalBlockError("INCOMPATIBLE_SIGNAL_INPUTS")
    if left.previous is None or right.previous is None:
        result = _context(
            f"cross_{direction}",
            graph_revision_hash=graph_revision_hash,
            node_id=node_id,
            symbol=left.symbol,
            timeframe=left.timeframe,
            bar_id=left.current.bar_id,
            event_ns=max(left.current.event_ns, right.current.event_ns),
            effective_ns=max(left.current.effective_ns, right.current.effective_ns),
            available_ns=max(left.current.available_ns, right.current.available_ns),
            asof_ns=left.asof_ns,
        )
        result.update(status="not_ready", value=None)
        return _issue(BoolV1, _BOOL_ISSUER, result)  # type: ignore[return-value]
    lp, rp = left.previous, right.previous
    if (
        left.current.unit != lp.unit
        or right.current.unit != rp.unit
        or left.current.bar_id != right.current.bar_id
        or lp.bar_id != rp.bar_id
        or left.current.bar_id == lp.bar_id
        or lp.bar_index != rp.bar_index
        or lp.bar_index + 1 != left.current.bar_index
    ):
        raise SignalBlockError("INCOMPATIBLE_SIGNAL_INPUTS")
    if (
        max(left.current.available_ns, right.current.available_ns, lp.available_ns, rp.available_ns)
        > left.asof_ns
    ):
        raise SignalBlockError("SIGNAL_INPUT_NOT_AVAILABLE")
    crossed = (
        left.current.value > right.current.value and lp.value <= rp.value
        if direction == "above"
        else left.current.value < right.current.value and lp.value >= rp.value
    )
    result = _context(
        f"cross_{direction}",
        graph_revision_hash=graph_revision_hash,
        node_id=node_id,
        symbol=left.symbol,
        timeframe=left.timeframe,
        bar_id=left.current.bar_id,
        event_ns=max(left.current.event_ns, right.current.event_ns),
        effective_ns=max(left.current.effective_ns, right.current.effective_ns),
        available_ns=max(
            left.current.available_ns,
            right.current.available_ns,
            lp.available_ns,
            rp.available_ns,
        ),
        asof_ns=left.asof_ns,
    )
    result["value"] = crossed
    return _issue(BoolV1, _BOOL_ISSUER, result)  # type: ignore[return-value]


def emit_entry_signal_v1(condition: BoolV1, *, signal_key: str) -> EntrySignalV1 | None:
    """Issue an entry signal for true only; false and warmup emit nothing."""
    return _emit_signal(condition, signal_key=signal_key, model=EntrySignalV1, issuer=_ENTRY_ISSUER)


def emit_exit_signal_v1(condition: BoolV1, *, signal_key: str) -> ExitSignalV1 | None:
    """Issue an exit signal for true only; false and warmup emit nothing."""
    return _emit_signal(condition, signal_key=signal_key, model=ExitSignalV1, issuer=_EXIT_ISSUER)


def _emit_signal(
    condition: BoolV1,
    *,
    signal_key: str,
    model: type[SignalRecordT],
    issuer: Issuer,
) -> SignalRecordT | None:
    _require(condition, _BOOL_TAG)
    if not _IDENTIFIER.fullmatch(signal_key):
        raise SignalBlockError("INVALID_SIGNAL_KEY", "signal_key")
    if condition.status != "ready" or condition.value is not True:
        return None
    record = {
        "schema_version": "1",
        "graph_revision_hash": condition.graph_revision_hash,
        "signal_key": signal_key,
        "symbol": condition.symbol,
        "timeframe": condition.timeframe,
        "finalized_bar_id": condition.finalized_bar_id,
        "event_ns": condition.event_ns,
        "effective_ns": condition.effective_ns,
        "available_ns": condition.available_ns,
        "source_node_id": condition.node_id,
    }
    return cast(SignalRecordT, _issue(model, issuer, record))


__all__ = [
    "BoolOperationV1",
    "BoolV1",
    "CompareOp",
    "CompareOpV1",
    "CrossDirection",
    "CrossDirectionV1",
    "EntrySignalV1",
    "ExitSignalV1",
    "NumericSeriesV1",
    "NumericV1",
    "SignalBlockError",
    "emit_entry_signal_v1",
    "emit_exit_signal_v1",
    "evaluate_compare_v1",
    "evaluate_crossover_v1",
    "make_numeric_series_v1",
    "make_numeric_v1",
]
