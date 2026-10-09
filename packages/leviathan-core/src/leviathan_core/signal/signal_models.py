import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from typing import Any, ClassVar, Literal, Never, Self, SupportsIndex, TypedDict

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

_DECIMAL_CONTEXT = Context(
    prec=34,
    rounding=ROUND_HALF_EVEN,
    Emax=38,
    Emin=-38,
    traps=[InvalidOperation, DivisionByZero, Overflow],
)


class StructureErrorDetail(TypedDict):
    loc: tuple[str | int, ...]
    type: str
    code: str


class StructureEvaluationError(Exception):
    def __init__(
        self, code: str, loc: tuple[str | int, ...] = (), error_type: str | None = None
    ) -> None:
        self.code = code
        self.loc = loc
        self.error_type = error_type or code
        super().__init__(code)

    def errors(self) -> tuple[StructureErrorDetail, ...]:
        return ({"loc": self.loc, "type": self.error_type, "code": self.code},)

    def json(self) -> str:
        return json.dumps(self.errors(), sort_keys=True, separators=(",", ":"))


class _FrozenStructureModel(BaseModel):
    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, validate_default=True, hide_input_in_errors=True
    )

    @model_validator(mode="wrap")
    @classmethod
    def _redact_validation(
        cls, value: Any, handler: ModelWrapValidatorHandler[Self]
    ) -> Self:
        try:
            return handler(value)
        except ValidationError as error:
            raise _safe_error(error) from None

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: Literal["allow", "ignore", "forbid"] | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        try:
            return super().model_validate_json(
                json_data, strict=strict, extra=extra, context=context,
                by_alias=by_alias, by_name=by_name,
            )
        except ValidationError as error:
            raise _safe_error(error) from None

    def __setattr__(self, name: str, value: Any) -> Never:
        raise StructureEvaluationError("IMMUTABLE")

    def __delattr__(self, name: str) -> Never:
        raise StructureEvaluationError("IMMUTABLE")

    def __copy__(self) -> Never:
        raise StructureEvaluationError("COPY_FORBIDDEN")

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Never:
        raise StructureEvaluationError("COPY_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex, /) -> Never:
        raise StructureEvaluationError("PICKLE_FORBIDDEN")

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Never:
        raise StructureEvaluationError("COPY_FORBIDDEN")

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        super().__pydantic_init_subclass__(**kwargs)
        type.__setattr__(cls, "model_construct", classmethod(_blocked_construct))


def _blocked_construct(cls: type[_FrozenStructureModel], /, **values: Any) -> Never:
    raise StructureEvaluationError("CONSTRUCT_FORBIDDEN")


def _safe_error(error: ValidationError) -> StructureEvaluationError:
    issue = error.errors(include_input=False, include_context=False, include_url=False)[0]
    allowed = {
        field for model in _FrozenStructureModel.__subclasses__() for field in model.model_fields
    }
    loc = tuple(
        part if isinstance(part, int) or part in allowed else "unknown_field"
        for part in issue["loc"]
    )
    return StructureEvaluationError("UNPROCESSABLE_INPUT", loc, issue["type"])


def _price(value: Decimal) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise PydanticCustomError("INVALID_DECIMAL", "INVALID_DECIMAL")
    digits = value.as_tuple().digits
    significant = len(digits)
    while significant > 1 and digits[significant - 1] == 0:
        significant -= 1
    if significant > 34:
        raise PydanticCustomError("PRECISION_EXCEEDED", "PRECISION_EXCEEDED")
    if value and abs(value.adjusted()) > 38:
        raise PydanticCustomError("MAGNITUDE_EXCEEDED", "MAGNITUDE_EXCEEDED")
    return value


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PydanticCustomError("INVALID_TIME", "INVALID_TIME")
    return value


def _ascii_token(value: str) -> str:
    if not isinstance(value, str) or not value or any(not 33 <= ord(char) <= 126 for char in value):
        raise PydanticCustomError("INVALID_TOKEN", "INVALID_TOKEN")
    return value


class StructureContext(_FrozenStructureModel):
    symbol: str = Field(min_length=1)
    venue: str = Field(min_length=1)
    timeframe: str = Field(min_length=1)
    detector_id: str = Field(min_length=1)
    detector_version: str = Field(min_length=1)

    _valid_tokens: ClassVar = field_validator(
        "symbol", "venue", "timeframe", "detector_id", "detector_version", mode="before"
    )(_ascii_token)


class FinalizedStructureBar(_FrozenStructureModel):
    bar_id: str = Field(min_length=1)
    close_time: datetime
    previous_close: Decimal
    close: Decimal
    input_version: str = Field(min_length=1)
    finalized: Literal[True] = True
    gap: bool = False
    stale_input: bool = False
    late_data: bool = False

    _valid_prices: ClassVar = field_validator("previous_close", "close", mode="before")(_price)
    _valid_time: ClassVar = field_validator("close_time", mode="before")(_utc)
    _valid_id: ClassVar = field_validator("bar_id", "input_version", mode="before")(_ascii_token)


class ConfirmedStructurePivot(_FrozenStructureModel):
    pivot_id: str = Field(min_length=1)
    kind: Literal["high", "low"]
    pivot_time: datetime
    confirmed_at: datetime
    price: Decimal
    feature_version: str = Field(min_length=1)

    _valid_price: ClassVar = field_validator("price", mode="before")(_price)
    _valid_time: ClassVar = field_validator("pivot_time", "confirmed_at", mode="before")(_utc)
    _valid_id: ClassVar = field_validator("pivot_id", "feature_version", mode="before")(
        _ascii_token
    )

    @model_validator(mode="after")
    def _chronology(self) -> Self:
        if self.confirmed_at < self.pivot_time:
            raise PydanticCustomError("PIVOT_CHRONOLOGY", "PIVOT_CHRONOLOGY")
        return self


class StructureEvaluation(_FrozenStructureModel):
    context: StructureContext
    bar: FinalizedStructureBar
    pivots: tuple[ConfirmedStructurePivot, ...]
    observed_at: datetime
    watermark: timedelta = timedelta(seconds=2)

    _valid_time: ClassVar = field_validator("observed_at", mode="before")(_utc)

    @model_validator(mode="after")
    def _chronology(self) -> Self:
        if self.watermark < timedelta(0):
            raise PydanticCustomError("POLICY_OUT_OF_BOUNDS", "POLICY_OUT_OF_BOUNDS")
        if self.observed_at < self.bar.close_time:
            raise PydanticCustomError("EVENT_TIME_BEFORE_CLOSE", "EVENT_TIME_BEFORE_CLOSE")
        return self


class SignalQuality(_FrozenStructureModel):
    late_data: bool = False
    gap: bool = False
    stale_input: bool = False
    source_lag_ms: int = Field(ge=0)


def _quality(evaluation: StructureEvaluation, *, gap: bool | None = None) -> SignalQuality:
    bar = evaluation.bar
    elapsed = evaluation.observed_at - bar.close_time
    lag_ms = ((elapsed.days * 86400 + elapsed.seconds) * 1000) + elapsed.microseconds // 1000
    return SignalQuality(
        late_data=bar.late_data,
        gap=bar.gap if gap is None else gap,
        stale_input=bar.stale_input,
        source_lag_ms=lag_ms,
    )


class StructureSignalV1(_FrozenStructureModel):
    id: str
    kind: Literal["INITIAL", "REVISION", "TOMBSTONE"]
    revision_of: str | None
    detector_type: Literal["msb", "bos"]
    direction: Literal["bull", "bear"]
    broken_level: Decimal
    symbol: str
    venue: str
    timeframe: str
    pivot_ids: tuple[str, ...]
    bar_id: str
    ts_event: datetime
    ts_ingest: datetime
    bar_close: datetime
    detector_id: str
    detector_version: str
    input_version: str
    feature_version: str
    finalized: Literal[True]
    confidence: Decimal
    quality: SignalQuality
    dedupe_key: str

    _valid_prices: ClassVar = field_validator("broken_level", "confidence", mode="before")(_price)
    _valid_times: ClassVar = field_validator("ts_event", "ts_ingest", "bar_close", mode="before")(
        _utc
    )

    @model_validator(mode="after")
    def _lineage(self) -> Self:
        with localcontext(_DECIMAL_CONTEXT):
            if self.confidence < 0 or self.confidence > 1:
                raise PydanticCustomError("CONFIDENCE_OUT_OF_RANGE", "CONFIDENCE_OUT_OF_RANGE")
        if (self.kind == "INITIAL") != (self.revision_of is None):
            raise PydanticCustomError("INVALID_REVISION_LINEAGE", "INVALID_REVISION_LINEAGE")
        return self


class StructureGapNoticeV1(_FrozenStructureModel):
    id: str
    dedupe_key: str
    symbol: str
    venue: str
    timeframe: str
    bar_id: str
    ts_event: datetime
    ts_ingest: datetime
    revision_of: str | None
    reason: Literal["LATE_BEYOND_WATERMARK"]
    quality: SignalQuality

    _valid_times: ClassVar = field_validator("ts_event", "ts_ingest", mode="before")(_utc)

    @model_validator(mode="after")
    def _is_gap(self) -> Self:
        if not self.quality.gap:
            raise PydanticCustomError("GAP_REQUIRED", "GAP_REQUIRED")
        return self


StructureEventV1 = StructureSignalV1 | StructureGapNoticeV1
