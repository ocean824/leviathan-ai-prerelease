"""Versioned, immutable market-data envelope and exact typed payloads."""

from __future__ import annotations

from collections.abc import Mapping
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    Inexact,
    InvalidOperation,
    Overflow,
    localcontext,
)
from types import MappingProxyType
from typing import Annotated, Any, Literal, Never, Self, SupportsIndex
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)

INT64_MAX = (1 << 63) - 1
INT64_MIN = -(1 << 63)
MARKET_EVENT_VERSION: Literal["leviathan.market-event/1"] = "leviathan.market-event/1"
DECIMAL_PRECISION = 34
DECIMAL_MAX_DIGITS = 50
DECIMAL_MAX_ADJUSTED_EXPONENT = 38
DECIMAL_CONTEXT = Context(
    prec=DECIMAL_PRECISION,
    rounding=ROUND_HALF_EVEN,
    traps=[InvalidOperation, DivisionByZero, Overflow, Inexact],
)


class MarketDataValueError(ValueError):
    """Allowlisted input/policy failure; never includes the rejected value."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MarketDataValidationError(MarketDataValueError):
    """Content-free public view of a Pydantic validation failure."""

    def __init__(self, code: str, *, loc: tuple[str | int, ...] = (),
                 error_type: str = "value_error") -> None:
        self.loc = loc
        self.error_type = error_type
        super().__init__(code)

    def errors(self) -> list[dict[str, object]]:
        return [{"code": self.code, "loc": self.loc, "type": self.error_type}]

    def json(self) -> str:
        import json

        return json.dumps(self.errors(), sort_keys=True, separators=(",", ":"))


class NoCopy:
    """Public immutable value objects refuse serialization and copying."""

    __slots__ = ()

    def __copy__(self) -> Never:
        raise TypeError("COPY_FORBIDDEN")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        raise TypeError("COPY_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("COPY_FORBIDDEN")


class MarketModel(BaseModel, NoCopy):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    @classmethod
    def _sanitize_validation(cls, exc: ValidationError) -> MarketDataValidationError:
        first = exc.errors()[0]
        underlying = first.get("ctx", {}).get("error")
        code = (underlying.code if isinstance(underlying, MarketDataValueError)
                else "INVALID_PAYLOAD")
        first_location = first.get("loc", ())
        if not first_location and isinstance(underlying, MarketDataValidationError):
            first_location = underlying.loc
        field = first_location[0] if first_location else None
        loc: tuple[str | int, ...] = (
            (field,) if isinstance(field, str) and field in cls.model_fields else ()
        )
        return MarketDataValidationError(code, loc=loc,
                                         error_type=str(first.get("type", "value_error")))

    def __init__(self, **data: Any) -> None:
        sanitized: MarketDataValidationError | None = None
        try:
            super().__init__(**data)
        except ValidationError as exc:
            sanitized = type(self)._sanitize_validation(exc)  # noqa: SLF001 - same-class
        if sanitized is not None:
            raise sanitized

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        sanitized: MarketDataValidationError | None = None
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError as exc:
            sanitized = cls._sanitize_validation(exc)
        raise sanitized

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> Self:
        sanitized: MarketDataValidationError | None = None
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError as exc:
            sanitized = cls._sanitize_validation(exc)
        raise sanitized

    @classmethod
    def model_validate_strings(
        cls, obj: Any, **kwargs: Any
    ) -> Self:
        sanitized: MarketDataValidationError | None = None
        try:
            return super().model_validate_strings(obj, **kwargs)
        except ValidationError as exc:
            sanitized = cls._sanitize_validation(exc)
        raise sanitized

    def __setattr__(self, name: str, value: Any) -> Never:
        raise MarketDataValidationError("FROZEN_RECORD",
                                        loc=(name,) if name in type(self).model_fields else ())

    def __delattr__(self, name: str) -> Never:
        raise MarketDataValidationError("FROZEN_RECORD",
                                        loc=(name,) if name in type(self).model_fields else ())

    def model_copy(self, *, update: Any = None, deep: bool = False) -> Self:
        raise TypeError("MODEL_BYPASS_FORBIDDEN")

    @classmethod
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> Self:
        raise TypeError("MODEL_BYPASS_FORBIDDEN")

    def validated_update(self, **changes: object) -> Self:
        """Revalidate every field and rebuild frozen nested values."""
        data = self.model_dump(mode="python")
        data.update(changes)
        return type(self).model_validate(data)

    def __copy__(self) -> Never:
        raise TypeError("COPY_FORBIDDEN")

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Never:
        raise TypeError("COPY_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("COPY_FORBIDDEN")


def exact_decimal(value: str, *, nonnegative: bool = False) -> Decimal:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise MarketDataValueError("INVALID_DECIMAL")
    if any(char not in "0123456789+-.eE" for char in value):
        raise MarketDataValueError("INVALID_DECIMAL")
    if sum(char in "0123456789" for char in value) > DECIMAL_MAX_DIGITS:
        raise MarketDataValueError("PRECISION_EXCEEDED")
    try:
        with localcontext(DECIMAL_CONTEXT):
            number = Decimal(value)
            if not number.is_finite() or (nonnegative and number < 0):
                raise MarketDataValueError("INVALID_DECIMAL")
            digits = number.as_tuple().digits
            if len(digits) > DECIMAL_MAX_DIGITS:
                raise MarketDataValueError("PRECISION_EXCEEDED")
            significant = len(digits)
            if number != 0:
                while significant > 1 and digits[significant - 1] == 0:
                    significant -= 1
            if significant > DECIMAL_PRECISION:
                raise MarketDataValueError("PRECISION_EXCEEDED")
            if number != 0 and abs(number.adjusted()) > DECIMAL_MAX_ADJUSTED_EXPONENT:
                raise MarketDataValueError("DECIMAL_OUT_OF_BOUNDS")
    except InvalidOperation as exc:
        raise MarketDataValueError("INVALID_DECIMAL") from exc
    return number


def canonical_decimal(value: str, *, nonnegative: bool = False) -> str:
    """Format a validated finite Decimal without invoking context rounding."""
    number = exact_decimal(value, nonnegative=nonnegative)
    with localcontext(DECIMAL_CONTEXT):
        if number == 0:
            return "0"
        sign, digits, exponent = number.as_tuple()
        if not isinstance(exponent, int):
            raise MarketDataValueError("INVALID_DECIMAL")
        coefficient = "".join(str(digit) for digit in digits)
        while coefficient.endswith("0") and len(coefficient) > 1:
            coefficient = coefficient[:-1]
            exponent += 1
        if exponent >= 0:
            result = coefficient + "0" * exponent
        elif len(coefficient) + exponent > 0:
            split = len(coefficient) + exponent
            result = coefficient[:split] + "." + coefficient[split:]
        else:
            result = "0." + "0" * -(len(coefficient) + exponent) + coefficient
        return ("-" if sign else "") + result


class PriceValue(MarketModel):
    value: str
    price_ticks: int | None = None

    @field_validator("value")
    @classmethod
    def _finite(cls, value: str) -> str:
        return canonical_decimal(value)

    @field_validator("price_ticks", mode="before")
    @classmethod
    def _ticks(cls, value: int | None) -> int | None:
        if value is not None and (type(value) is not int or not INT64_MIN <= value <= INT64_MAX):
            raise MarketDataValueError("INVALID_INTEGER")
        return value


class TradePayload(MarketModel):
    kind: Literal["trade"] = "trade"
    price: PriceValue
    size: str
    side: Literal["buy", "sell", "unknown"] = "unknown"

    @field_validator("size")
    @classmethod
    def _size(cls, value: str) -> str:
        return canonical_decimal(value, nonnegative=True)


class QuotePayload(MarketModel):
    kind: Literal["quote"] = "quote"
    bid_present: bool = True
    ask_present: bool = True
    bid_price: PriceValue | None = None
    ask_price: PriceValue | None = None
    bid_size: str | None = None
    ask_size: str | None = None
    bid_exchange: str | None = None
    ask_exchange: str | None = None
    bid_time_ns: int | None = None
    ask_time_ns: int | None = None

    @field_validator("bid_size", "ask_size")
    @classmethod
    def _size(cls, value: str | None) -> str | None:
        return canonical_decimal(value, nonnegative=True) if value is not None else None

    @field_validator("bid_present", "ask_present", mode="before")
    @classmethod
    def _present(cls, value: bool) -> bool:
        if type(value) is not bool:
            raise MarketDataValueError("INVALID_BOOLEAN")
        return value

    @field_validator("bid_time_ns", "ask_time_ns", mode="before")
    @classmethod
    def _time(cls, value: int | None) -> int | None:
        if value is not None and type(value) is not int:
            raise MarketDataValueError("INVALID_INTEGER")
        if value is not None and not 0 < value <= INT64_MAX:
            raise MarketDataValueError("INVALID_TIME")
        return value

    @model_validator(mode="after")
    def _sides(self) -> QuotePayload:
        if not self.bid_present and not self.ask_present:
            raise MarketDataValueError("INVALID_QUOTE_SIDE")
        for present, price, size, exchange, time_ns in (
            (self.bid_present, self.bid_price, self.bid_size,
             self.bid_exchange, self.bid_time_ns),
            (self.ask_present, self.ask_price, self.ask_size,
             self.ask_exchange, self.ask_time_ns),
        ):
            if present and (price is None or size is None):
                raise MarketDataValueError("INVALID_QUOTE_SIDE")
            if not present and any(value is not None for value in
                                   (price, size, exchange, time_ns)):
                raise MarketDataValueError("INVALID_QUOTE_SIDE")
        return self


class BookLevel(MarketModel):
    side: Literal["bid", "ask"]
    price: PriceValue
    size: str
    level: int | None = None
    order_id: str | None = None

    @field_validator("size")
    @classmethod
    def _size(cls, value: str) -> str:
        return canonical_decimal(value, nonnegative=True)

    @field_validator("level", mode="before")
    @classmethod
    def _level(cls, value: int | None) -> int | None:
        if value is not None and (type(value) is not int or value < 0):
            raise MarketDataValueError("INVALID_INTEGER")
        return value


class BookDeltaPayload(MarketModel):
    kind: Literal["book_delta"] = "book_delta"
    action: Literal["add", "update", "delete", "clear"]
    side: Literal["bid", "ask"] | None = None
    price: PriceValue | None = None
    size: str | None = None
    level: int | None = None
    order_id: str | None = None

    @field_validator("size")
    @classmethod
    def _size(cls, value: str | None) -> str | None:
        return canonical_decimal(value, nonnegative=True) if value is not None else None

    @field_validator("level", mode="before")
    @classmethod
    def _level(cls, value: int | None) -> int | None:
        if value is not None and (type(value) is not int or value < 0):
            raise MarketDataValueError("INVALID_INTEGER")
        return value


class BookSnapshotPayload(MarketModel):
    kind: Literal["book_snapshot"] = "book_snapshot"
    levels: tuple[BookLevel, ...]


class BarPayload(MarketModel):
    kind: Literal["bar"] = "bar"
    interval: str
    open_time_ns: int
    open: PriceValue
    high: PriceValue
    low: PriceValue
    close: PriceValue
    volume: str

    @field_validator("volume")
    @classmethod
    def _volume(cls, value: str) -> str:
        return canonical_decimal(value, nonnegative=True)

    @field_validator("open_time_ns", mode="before")
    @classmethod
    def _time(cls, value: int) -> int:
        if type(value) is not int:
            raise MarketDataValueError("INVALID_INTEGER")
        if not 0 < value <= INT64_MAX:
            raise MarketDataValueError("INVALID_TIME")
        return value


class StatusPayload(MarketModel):
    kind: Literal["status"] = "status"
    status: str
    reason: str | None = None


class ReferencePayload(MarketModel):
    kind: Literal["reference"] = "reference"
    attributes: Mapping[str, str]

    @field_validator("attributes", mode="after")
    @classmethod
    def _freeze_attributes(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        return MappingProxyType(dict(value))

    @field_serializer("attributes")
    def _serialize_attributes(self, value: Mapping[str, str]) -> dict[str, str]:
        return dict(value)


class CorporateActionPayload(MarketModel):
    kind: Literal["corporate_action"] = "corporate_action"
    action: str
    effective_time_ns: int
    details: Mapping[str, str]

    @field_validator("details", mode="after")
    @classmethod
    def _freeze_details(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        return MappingProxyType(dict(value))

    @field_serializer("details")
    def _serialize_details(self, value: Mapping[str, str]) -> dict[str, str]:
        return dict(value)

    @field_validator("effective_time_ns", mode="before")
    @classmethod
    def _time(cls, value: int) -> int:
        if type(value) is not int:
            raise MarketDataValueError("INVALID_INTEGER")
        if not 0 < value <= INT64_MAX:
            raise MarketDataValueError("INVALID_TIME")
        return value


class NewsPayload(MarketModel):
    kind: Literal["news"] = "news"
    headline: str
    story_ref: str | None = None
    publisher: str | None = None


class ProvenanceTimestamps(MarketModel):
    """Closed set of distinct native timestamp roles, all UTC nanoseconds."""

    exchange: int | None = None
    sip: int | None = None
    trf: int | None = None
    participant: int | None = None
    provider: int | None = None

    @field_validator("exchange", "sip", "trf", "participant", "provider", mode="before")
    @classmethod
    def _timestamp(cls, value: int | None) -> int | None:
        if value is not None and type(value) is not int:
            raise MarketDataValueError("INVALID_INTEGER")
        if value is not None and not 0 < value <= INT64_MAX:
            raise MarketDataValueError("INVALID_TIME")
        return value


SOURCE_ATTRIBUTE_KEYS: Mapping[str, frozenset[str]] = MappingProxyType({
    "databento": frozenset({
        "databento:raw_action_code", "databento:raw_side_code",
        "databento:raw_flags_code", "databento:raw_rtype_code",
    }),
    "massive": frozenset({
        "massive:raw_correction_code", "massive:raw_exchange_code",
        "massive:raw_tape_code", "massive:raw_condition_codes",
    }),
})


class NativeProvenance(MarketModel):
    """Native fields that may affect identity, correction or downstream interpretation."""

    publisher_id: int | None = None
    native_instrument_id: int | str | None = None
    native_exchange_id: int | str | None = None
    rtype: int | None = None
    action: Literal[
        "add", "modify", "delete", "clear", "trade", "fill",
        "cancel", "correct", "status", "unknown",
    ] | None = None
    side: Literal["buy", "sell", "bid", "ask", "unknown"] | None = None
    flags: int | None = None
    trade_conditions: tuple[str, ...] = ()
    correction: Literal["none", "correction", "cancel"] = "none"
    referenced_native_id: str | None = None
    referenced_native_sequence: int | None = None
    trf_id: str | None = None
    ts_in_delta_ns: int | None = None

    @field_validator("publisher_id", "rtype", "flags", "referenced_native_sequence",
                     mode="before")
    @classmethod
    def _unsigned(cls, value: int | None) -> int | None:
        if value is not None and (type(value) is not int or not 0 <= value <= INT64_MAX):
            raise MarketDataValueError("INVALID_INTEGER")
        return value

    @field_validator("native_instrument_id", "native_exchange_id", mode="before")
    @classmethod
    def _instrument(cls, value: int | str | None) -> int | str | None:
        if isinstance(value, bool) or (isinstance(value, int) and not 0 <= value <= INT64_MAX):
            raise MarketDataValueError("INVALID_INTEGER")
        if isinstance(value, str) and (not value or len(value) > 128):
            raise MarketDataValueError("INVALID_NATIVE_ID")
        return value

    @field_validator("ts_in_delta_ns", mode="before")
    @classmethod
    def _delta(cls, value: int | None) -> int | None:
        if value is not None and (type(value) is not int
                                  or not INT64_MIN <= value <= INT64_MAX):
            raise MarketDataValueError("INVALID_INTEGER")
        return value

    @field_validator("trade_conditions")
    @classmethod
    def _conditions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 32 or any(len(code) > 64 or ":" not in code for code in value):
            raise MarketDataValueError("INVALID_TRADE_CONDITIONS")
        return value


MarketPayload = Annotated[
    TradePayload
    | QuotePayload
    | BookDeltaPayload
    | BookSnapshotPayload
    | BarPayload
    | StatusPayload
    | ReferencePayload
    | CorporateActionPayload
    | NewsPayload,
    Field(discriminator="kind"),
]


class NormalizedMarketEventV1(MarketModel):
    schema_version: Literal["leviathan.market-event/1"] = MARKET_EVENT_VERSION
    event_id: UUID
    provider: str
    dataset: str
    venue: str
    native_symbol: str
    leviathan_symbol: str
    instrument_id: str
    instrument_type: str
    channel: str
    event_type: Literal[
        "trade", "quote", "book_delta", "book_snapshot", "bar", "status",
        "reference", "corporate_action", "news",
    ]
    source_mode: Literal["historical", "live", "reconstructed"]
    event_time_ns: int
    source_time_ns: int | None
    exchange_time_ns: int | None
    provenance_timestamps: ProvenanceTimestamps = Field(default_factory=ProvenanceTimestamps)
    ingest_time_ns: int
    processing_time_ns: int
    received_time_ns: int
    native_sequence: int | None
    sequence_synthetic: bool
    native_trade_id: str | None
    source_record_key: str | None = None
    provider_session_id: str | None = None
    session_transition_confirmed: bool = False
    native_provenance: NativeProvenance = Field(default_factory=NativeProvenance)
    source_attributes: Mapping[str, str] = Field(default_factory=dict)
    source_record_ref: str
    source_payload_sha256: str
    mapping_version: str
    identity_policy_version: str
    sequence_policy_version: str = "sequence-policy/1"
    time_policy_version: str = "event-time/1"
    quality_flags: tuple[str, ...]
    reconstructed: bool
    idempotency_key: str
    payload: MarketPayload

    @field_validator(
        "sequence_synthetic", "session_transition_confirmed", "reconstructed",
        mode="before",
    )
    @classmethod
    def _boolean(cls, value: bool) -> bool:
        if type(value) is not bool:
            raise MarketDataValueError("INVALID_BOOLEAN")
        return value

    @field_validator("source_attributes", mode="after")
    @classmethod
    def _freeze_attributes(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        if len(value) > 32 or any(
            len(key) > 80 or len(item) > 256 for key, item in value.items()
        ):
            raise MarketDataValueError("INVALID_SOURCE_ATTRIBUTES")
        return MappingProxyType(dict(value))

    @field_serializer("source_attributes")
    def _serialize_attributes(self, value: Mapping[str, str]) -> dict[str, str]:
        return dict(value)

    @field_validator(
        "event_time_ns", "source_time_ns", "exchange_time_ns", "ingest_time_ns",
        "processing_time_ns", "received_time_ns",
        mode="before",
    )
    @classmethod
    def _timestamp(cls, value: int | None) -> int | None:
        if value is not None and type(value) is not int:
            raise MarketDataValueError("INVALID_INTEGER")
        if value is not None and not 0 < value <= INT64_MAX:
            raise MarketDataValueError("INVALID_TIME")
        return value

    @field_validator("native_sequence", mode="before")
    @classmethod
    def _sequence(cls, value: int | None) -> int | None:
        if value is not None and (type(value) is not int or not 0 <= value <= INT64_MAX):
            raise MarketDataValueError("INVALID_INTEGER")
        return value

    @field_validator(
        "provider", "dataset", "venue", "native_symbol", "leviathan_symbol",
        "instrument_id", "instrument_type", "channel", "source_record_ref",
        "mapping_version", "identity_policy_version", "sequence_policy_version",
        "time_policy_version",
    )
    @classmethod
    def _required_text(cls, value: str) -> str:
        if not value or value.strip() != value:
            raise MarketDataValueError("MISSING_PROVENANCE")
        return value

    @model_validator(mode="after")
    def _payload_matches(self) -> NormalizedMarketEventV1:
        if self.payload.kind != self.event_type:
            raise MarketDataValueError("INVALID_PAYLOAD_KIND")
        if self.source_mode != "live" and "execution_eligible" in self.quality_flags:
            raise MarketDataValueError("OFFLINE_EXECUTION_FORBIDDEN")
        if self.reconstructed != (self.source_mode == "reconstructed"):
            raise MarketDataValueError("INVALID_RECONSTRUCTION_MARKER")
        if self.session_transition_confirmed and not self.provider_session_id:
            raise MarketDataValueError("INVALID_SESSION_TRANSITION")
        allowed = SOURCE_ATTRIBUTE_KEYS.get(self.provider.lower(), frozenset())
        if any(key not in allowed for key in self.source_attributes):
            raise MarketDataValueError("INVALID_SOURCE_ATTRIBUTES")
        return self
