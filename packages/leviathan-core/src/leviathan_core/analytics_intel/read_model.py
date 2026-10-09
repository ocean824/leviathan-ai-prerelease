"""Shared immutable policy and read model for overview analytics."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    FloatOperation,
    InvalidOperation,
    Overflow,
    localcontext,
)
from types import MappingProxyType
from typing import Any, Literal, NoReturn, Protocol, SupportsIndex

POLICY_VERSION = "INT-008-POLICY-v1"
_KINDS = frozenset({"echoes", "wyckoff", "market_clock"})


class AnalyticsError(ValueError):
    """Typed, non-echoing validation or calculation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class FrozenValue:
    """Reject copy and deserialization paths that bypass construction checks."""

    def __copy__(self) -> NoReturn:
        raise AnalyticsError("COPY_FORBIDDEN")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        raise AnalyticsError("COPY_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise AnalyticsError("PICKLE_FORBIDDEN")


def decimal_context() -> Context:
    """A fresh context; ambient Decimal settings cannot affect a calculation."""
    context = Context(prec=34, rounding=ROUND_HALF_EVEN, Emin=-999999, Emax=999999)
    for signal in (InvalidOperation, DivisionByZero, Overflow, FloatOperation):
        context.traps[signal] = True
    return context


def checked_decimal(
    value: object,
    *,
    nonnegative: bool = False,
    positive: bool = False,
    input_bound: bool = True,
) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise AnalyticsError("INVALID_DECIMAL")
    representation = value.as_tuple()
    exponent = representation.exponent
    if not isinstance(exponent, int):
        raise AnalyticsError("INVALID_DECIMAL")
    digits = representation.digits
    trailing = 0
    for digit in reversed(digits):
        if digit != 0:
            break
        trailing += 1
    if max(1, len(digits) - trailing) > 34:
        raise AnalyticsError("PRECISION_EXCEEDED")
    if value and input_bound and abs(value.adjusted()) > 38:
        raise AnalyticsError("DECIMAL_OUT_OF_BOUNDS")
    if (nonnegative and value < 0) or (positive and value <= 0):
        raise AnalyticsError("INVALID_DECIMAL")
    if not value:
        return Decimal(0)
    return Decimal((representation.sign, digits[: len(digits) - trailing], exponent + trailing))


def checked_int(value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise AnalyticsError("INVALID_INTEGER")
    return value


def checked_text(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise AnalyticsError("INVALID_TEXT")
    return value


def frozen_map(value: Mapping[str, Decimal]) -> Mapping[str, Decimal]:
    if not isinstance(value, Mapping):
        raise AnalyticsError("INVALID_MAPPING")
    result: dict[str, Decimal] = {}
    for key, item in value.items():
        result[checked_text(key)] = checked_decimal(item)
    return MappingProxyType(dict(sorted(result.items())))


def decimal_string(value: Decimal) -> str:
    checked_decimal(value, input_bound=False)
    with localcontext(decimal_context()):
        normalized = value.normalize()
        return format(normalized, "f" if not value or abs(value.adjusted()) <= 38 else "E")


class CalendarPort(Protocol):
    """Injected exchange-calendar view, including DST and shortened sessions."""

    def session_for_ns(self, event_ns: int) -> str | None: ...

    def trailing_sessions(self, asof_ns: int, count: int) -> tuple[str, ...]: ...

    def hour_for_ns(self, event_ns: int) -> tuple[str, str, int, int] | None:
        """Return session, local hour label, UTC hour start ns, UTC offset minutes."""
        ...

    def hour_end_ns(self, hour_start_ns: int) -> int:
        """Return the actual hour end, including a calendar early close."""
        ...


@dataclass(frozen=True, slots=True)
class PolicyV1(FrozenValue):
    policy_version: str
    kind: Literal["echoes", "wyckoff", "market_clock"]
    domain: object

    def __post_init__(self) -> None:
        if self.policy_version != POLICY_VERSION:
            raise AnalyticsError("UNSUPPORTED_POLICY")
        if self.kind not in _KINDS:
            raise AnalyticsError("UNSUPPORTED_POLICY")
        if getattr(self.domain, "policy_version", None) != POLICY_VERSION:
            raise AnalyticsError("UNSUPPORTED_POLICY")
        if not isinstance(self.domain, FrozenValue):
            raise AnalyticsError("INVALID_POLICY")
        expected = {
            "echoes": ("echoes", "EchoPolicyV1"),
            "wyckoff": ("wyckoff", "WyckoffPolicyV1"),
            "market_clock": ("market_clock", "MarketClockPolicyV1"),
        }[self.kind]
        if (type(self.domain).__module__.split(".")[-1], type(self.domain).__name__) != expected:
            raise AnalyticsError("UNSUPPORTED_POLICY")


def require_policy(policy: object, kind: str, domain_type: type[Any]) -> object:
    if not isinstance(policy, PolicyV1):
        raise AnalyticsError("MISSING_POLICY")
    if policy.kind != kind or not isinstance(policy.domain, domain_type):
        raise AnalyticsError("UNSUPPORTED_POLICY")
    return policy.domain


def _freeze_json(value: object) -> object:
    if value is None or type(value) in (str, int, bool):
        return value
    if isinstance(value, Decimal):
        return decimal_string(value)
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_json(item) for item in value)
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise AnalyticsError("INVALID_PAYLOAD")
        if any(key in value for key in ("route_permit", "order_intent", "order_authority")):
            raise AnalyticsError("INVALID_PAYLOAD")
        return MappingProxyType({key: _freeze_json(item) for key, item in sorted(value.items())})
    raise AnalyticsError("INVALID_PAYLOAD")


def _plain_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class AnalyticsTileV1(FrozenValue):
    kind: Literal["echoes", "wyckoff", "market_clock"]
    instrument_id: str
    venue: str
    session: str
    event_ns: str
    asof_ns: str
    availability_ns: str
    source_version: str
    dataset_version: str
    method_version: str
    parameter_version: str
    calendar_version: str
    policy_version: str
    entitlement: str
    quality: str
    lag_ns: str
    stale: bool
    missing_reason: str | None
    units: str
    sample_count: int
    confidence: Decimal | None
    payload: Mapping[str, object]
    schema_version: str = field(default="1")
    label: str = field(default="MODEL_ESTIMATE")

    def __post_init__(self) -> None:
        if self.kind not in _KINDS or self.policy_version != POLICY_VERSION:
            raise AnalyticsError("INVALID_TILE")
        if self.schema_version != "1" or self.label != "MODEL_ESTIMATE":
            raise AnalyticsError("INVALID_TILE")
        for name in (
            "instrument_id",
            "venue",
            "session",
            "source_version",
            "dataset_version",
            "method_version",
            "parameter_version",
            "calendar_version",
            "entitlement",
            "quality",
            "units",
        ):
            checked_text(getattr(self, name))
        for name in ("event_ns", "asof_ns", "availability_ns", "lag_ns"):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or not value.isascii()
                or not value.isdecimal()
                or str(int(value)) != value
            ):
                raise AnalyticsError("INVALID_TIMESTAMP")
        if int(self.event_ns) > int(self.asof_ns) or int(self.availability_ns) > int(self.asof_ns):
            raise AnalyticsError("FUTURE_DATA")
        if type(self.stale) is not bool:
            raise AnalyticsError("INVALID_BOOLEAN")
        checked_int(self.sample_count)
        if self.confidence is not None:
            confidence = checked_decimal(self.confidence, nonnegative=True)
            if confidence > 1:
                raise AnalyticsError("INVALID_CONFIDENCE")
            object.__setattr__(self, "confidence", confidence)
        if self.missing_reason is not None:
            checked_text(self.missing_reason)
        if self.missing_reason is not None and self.sample_count != 0 and not self.payload:
            raise AnalyticsError("INVALID_TILE")
        if not isinstance(self.payload, Mapping):
            raise AnalyticsError("INVALID_PAYLOAD")
        if any(key in self.payload for key in ("route_permit", "order_intent", "order_authority")):
            raise AnalyticsError("INVALID_PAYLOAD")
        object.__setattr__(self, "payload", _freeze_json(self.payload))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "label": self.label,
            "instrument_id": self.instrument_id,
            "venue": self.venue,
            "session": self.session,
            "event_ns": self.event_ns,
            "asof_ns": self.asof_ns,
            "availability_ns": self.availability_ns,
            "source_version": self.source_version,
            "dataset_version": self.dataset_version,
            "method_version": self.method_version,
            "parameter_version": self.parameter_version,
            "calendar_version": self.calendar_version,
            "policy_version": self.policy_version,
            "entitlement": self.entitlement,
            "quality": self.quality,
            "lag_ns": self.lag_ns,
            "stale": self.stale,
            "missing_reason": self.missing_reason,
            "units": self.units,
            "sample_count": self.sample_count,
            "confidence": decimal_string(self.confidence) if self.confidence is not None else None,
            "payload": _plain_json(self.payload),
        }


def safe_ln(value: Decimal) -> Decimal:
    result: Decimal | None = None
    try:
        with localcontext(decimal_context()) as context:
            if not isinstance(value, Decimal) or not value.is_finite() or value <= 0:
                raise AnalyticsError("INVALID_DECIMAL")
            result = context.ln(value)
    except (InvalidOperation, DivisionByZero, Overflow):
        pass
    if result is None:
        raise AnalyticsError("INVALID_ARITHMETIC")
    return result


def safe_sqrt(value: Decimal) -> Decimal:
    result: Decimal | None = None
    try:
        with localcontext(decimal_context()) as context:
            if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
                raise AnalyticsError("INVALID_DECIMAL")
            result = context.sqrt(value)
    except (InvalidOperation, DivisionByZero, Overflow):
        pass
    if result is None:
        raise AnalyticsError("INVALID_ARITHMETIC")
    return result
