"""Versioned value objects for the offline four-layer fusion kernel."""

from __future__ import annotations

import json
from collections.abc import Mapping
from decimal import Decimal
from typing import Annotated, Any, Literal, Self, SupportsIndex, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import ErrorDetails, InitErrorDetails

from leviathan_core.numeric import canonical_json, canonical_str, parse_decimal

LayerName = Literal["L1", "L2", "L3", "L4"]
FusionStatus = Literal["CAPITAL_CANDIDATE", "NO_INTENT"]
LayerStatus = Literal["PASS", "FAIL", "STALE", "MISSING"]
IdempotencyCheck = Literal["NOT_PERFORMED", "MATCH", "CONFLICT"]
ClosedId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    ),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]


def finite_decimal(value: str) -> Decimal:
    """Parse a decimal string without admitting binary floats or nonfinite values."""
    return parse_decimal(value, field="value")


def canonical_decimal(value: str) -> str:
    return canonical_str(finite_decimal(value))


class FusionValidationError(ValidationError):
    """Typed public error exposing only safe validation metadata."""

    code = "INVALID_FUSION_INPUT"

    def __str__(self) -> str:
        return self.code

    def errors(
        self,
        *,
        include_url: bool = True,
        include_context: bool = True,
        include_input: bool = True,
    ) -> list[ErrorDetails]:
        details = super().errors(include_url=False, include_context=False, include_input=False)
        safe = [
            {"loc": detail["loc"], "type": detail["type"], "code": self.code} for detail in details
        ]
        return cast(list[ErrorDetails], safe)

    def json(
        self,
        *,
        indent: int | None = None,
        include_url: bool = True,
        include_context: bool = True,
        include_input: bool = True,
    ) -> str:
        return json.dumps(self.errors(), indent=indent, sort_keys=True)


class FusionFrozenError(TypeError):
    """Content-free denial of mutation or unchecked model construction."""

    code = "FROZEN_FUSION_RECORD"

    def __init__(self) -> None:
        super().__init__(self.code)


class FusionModelV1(BaseModel):
    """Immutable, strict contract; unknown fields and versions are errors."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, hide_input_in_errors=True)
    schema_version: Literal["1.0.0"] = "1.0.0"

    @classmethod
    def _public_error(cls, original: ValidationError) -> FusionValidationError:
        lines: list[InitErrorDetails] = []
        for detail in original.errors(include_input=False, include_context=False):
            location = detail.get("loc", ())
            field = location[0] if location and location[0] in cls.model_fields else "__input__"
            line: InitErrorDetails = {
                "type": detail["type"],
                "loc": (field,),
                "input": "<redacted>",
            }
            try:
                ValidationError.from_exception_data(cls.__name__, [line], hide_input=True)
            except (KeyError, TypeError, ValueError):
                line = {
                    "type": "value_error",
                    "loc": (field,),
                    "input": "<redacted>",
                    "ctx": {"error": ValueError("invalid value")},
                }
            lines.append(line)
        return FusionValidationError.from_exception_data(cls.__name__, lines, hide_input=True)

    def __init__(self, /, **data: Any) -> None:
        try:
            super().__init__(**data)
            return
        except ValidationError as original:
            safe = type(self)._public_error(original)  # noqa: SLF001 - same-class
        raise safe

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError as original:
            safe = cls._public_error(original)
        raise safe

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Self:
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError as original:
            safe = cls._public_error(original)
        raise safe

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate_strings(obj, **kwargs)
        except ValidationError as original:
            safe = cls._public_error(original)
        raise safe

    @model_validator(mode="wrap")
    @classmethod
    def redact_validation_error(cls, value: Any, handler: ModelWrapValidatorHandler[Self]) -> Self:
        """Keep rejected caller values out of every public error representation."""
        try:
            return handler(value)
        except ValidationError as original:
            raise cls._public_error(original) from None

    def __setattr__(self, name: str, value: Any) -> None:
        raise FusionFrozenError

    def __delattr__(self, name: str) -> None:
        raise FusionFrozenError

    def __copy__(self) -> Self:
        raise FusionFrozenError

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        raise FusionFrozenError

    def __reduce__(self) -> Any:
        raise FusionFrozenError

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise FusionFrozenError

    def __getstate__(self) -> Any:
        raise FusionFrozenError

    @classmethod
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> Self:
        raise FusionFrozenError

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        raise FusionFrozenError

    def copy(self, **kwargs: Any) -> Self:
        raise FusionFrozenError


class LayerObservationV1(FusionModelV1):
    layer: ClosedId
    source: ClosedId
    source_version: ClosedId
    event_ns: int = Field(ge=0)
    available_ns: int = Field(ge=0)
    semantic_digest: Digest
    integrity: str | None = None
    score: str | None = None
    confidence: str | None = None


class FeatureSnapshotV1(FusionModelV1):
    snapshot_id: ClosedId
    event_ns: int = Field(ge=0)
    available_ns: int = Field(ge=0)


class FeatureAttributionV1(FusionModelV1):
    feature: ClosedId
    contribution: str
    snapshot_id: ClosedId | None = None
    available_ns: int | None = Field(default=None, ge=0)

    @field_validator("contribution")
    @classmethod
    def valid_contribution(cls, value: str) -> str:
        return canonical_decimal(value)


class MarketContextV1(FusionModelV1):
    global_risk_off: bool = False
    halted: bool = False
    truth_rejected: bool = False


class FusionRequestV1(FusionModelV1):
    evaluation_ns: int = Field(ge=0)
    tenant_id: ClosedId
    strategy_revision: ClosedId
    strategy_hash: Digest
    symbol: ClosedId
    window_id: ClosedId
    observations: tuple[LayerObservationV1, ...]
    market_context: MarketContextV1
    feature_snapshots: tuple[FeatureSnapshotV1, ...] = ()
    feature_attributions: tuple[FeatureAttributionV1, ...] = ()
    prior_input_hash: Digest | None = None


class FusionPolicyV1(FusionModelV1):
    policy_id: ClosedId
    policy_version: ClosedId
    window_ns: int = Field(gt=0)
    max_source_skew_ns: int = Field(ge=0)
    min_l2_score: str
    min_l3_confidence: str
    min_l4_score: str
    required_sources: tuple[tuple[LayerName, ClosedId], ...]

    @field_validator("min_l2_score", "min_l3_confidence", "min_l4_score")
    @classmethod
    def valid_threshold(cls, value: str) -> str:
        number = finite_decimal(value)
        if not 0 <= number <= 1:
            raise ValueError("threshold must be within [0, 1]")
        return canonical_decimal(value)

    @model_validator(mode="after")
    def complete_sources(self) -> FusionPolicyV1:
        names = [name for name, _ in self.required_sources]
        if sorted(names) != ["L1", "L2", "L3", "L4"]:
            raise ValueError("required_sources must name L1, L2, L3 and L4 once each")
        if any(not source for _, source in self.required_sources):
            raise ValueError("required source cannot be empty")
        return self


class LayerVerdictV1(FusionModelV1):
    layer: LayerName
    status: LayerStatus
    reason_codes: tuple[str, ...]
    threshold: str
    score: str | None
    source: ClosedId | None
    source_version: ClosedId | None
    event_ns: int | None
    available_ns: int | None


class FusionResultV1(FusionModelV1):
    status: FusionStatus
    idempotency_check: IdempotencyCheck
    reason_codes: tuple[str, ...]
    layer_verdicts: tuple[LayerVerdictV1, ...]
    layer_scores: tuple[tuple[str, str | None], ...]
    attributions: tuple[FeatureAttributionV1, ...]
    rationale: str
    evaluation_ns: int
    input_hash: Digest
    policy_hash: Digest
    idempotency_key: Digest

    def canonical_bytes(self) -> bytes:
        """Stable UTF-8 JSON independent of Python process hash randomization."""
        return canonical_json(self.model_dump(mode="json"))
