"""Pure, versioned point-in-time feature value contracts."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any, Literal, NoReturn, Self, cast

from pydantic import (
    ConfigDict,
    ModelWrapValidatorHandler,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from leviathan_core.numeric import NumericError, parse_decimal
from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.seal import Issuer, SealError, require

_FEATURE_RESULT_SEAL_TAG = "feat001.feature_result.v1"
_FEATURE_RESULT_ISSUER = Issuer(_FEATURE_RESULT_SEAL_TAG)


def _canonical_decimal(value: Decimal) -> str:
    """Render an exact Decimal without context-dependent rounding or scale noise."""
    if value.is_zero():
        return "0"
    plain = format(value, "f")
    return plain.rstrip("0").rstrip(".") if "." in plain else plain


def _decimal_at_boundary(value: object) -> Decimal:
    if isinstance(value, (bool, float)):
        raise ValueError("feature values must not be floats or booleans")
    if not isinstance(value, (Decimal, str, int)):
        raise ValueError("feature values must be exact Decimal, text, or integer")
    try:
        return parse_decimal(value, field="value_decimal")
    except NumericError as error:
        if error.code == "PRECISION_EXCEEDED":
            raise ValueError("feature precision exceeds NUM-001 bounds") from None
        if error.code == "MAGNITUDE_OUT_OF_BOUNDS":
            raise ValueError("feature magnitude exceeds NUM-001 bounds") from None
        raise ValueError("feature value is not a bounded finite decimal") from None


def _vector_at_boundary(value: object) -> tuple[Decimal, ...] | None:
    if value is None:
        return None
    if not isinstance(value, (tuple, list)) or not value:
        raise ValueError("feature vector must be a nonempty tuple or list")
    return tuple(_decimal_at_boundary(element) for element in value)


def _canonical_vector(value: tuple[Decimal, ...] | None) -> list[str] | None:
    return [_canonical_decimal(element) for element in value] if value is not None else None


def _semantic_hash(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_validation_error(model: type[Any], error: ValidationError) -> ValidationError:
    """Rebuild validation details without retaining submitted values or keys."""
    allowed_fields = frozenset(model.model_fields)
    safe_errors: list[dict[str, Any]] = []
    for detail in error.errors():
        raw_location = detail.get("loc", ())
        location = tuple(
            part for part in raw_location if type(part) is str and part in allowed_fields
        )
        safe_errors.append(
            {
                "type": PydanticCustomError("feature_boundary_invalid", "FEATURE_BOUNDARY_INVALID"),
                "loc": location,
                "input": None,
            }
        )
    return ValidationError.from_exception_data(model.__name__, cast(Any, safe_errors))


class FeatureFrozenError(TypeError):
    """A FEAT value object cannot be changed after construction."""

    code = "FROZEN_FEATURE_MODEL"

    def __init__(self) -> None:
        super().__init__(self.code)


class _FeatureModel(LeviathanModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        hide_input_in_errors=True,
    )

    def __init__(self, /, **data: Any) -> None:
        sanitized: ValidationError | None = None
        try:
            super().__init__(**data)
        except ValidationError as error:
            sanitized = _safe_validation_error(type(self), error)
        if sanitized is not None:
            raise sanitized from None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        sanitized: ValidationError | None = None
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError as error:
            sanitized = _safe_validation_error(cls, error)
        if sanitized is None:
            raise AssertionError("validation did not return")
        raise sanitized from None

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Self:
        sanitized: ValidationError | None = None
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError as error:
            sanitized = _safe_validation_error(cls, error)
        if sanitized is None:
            raise AssertionError("JSON validation did not return")
        raise sanitized from None

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        sanitized: ValidationError | None = None
        try:
            return super().model_validate_strings(obj, **kwargs)
        except ValidationError as error:
            sanitized = _safe_validation_error(cls, error)
        if sanitized is None:
            raise AssertionError("string validation did not return")
        raise sanitized from None

    @model_validator(mode="wrap")
    @classmethod
    def _redact_validation_failure(
        cls, value: Any, handler: ModelWrapValidatorHandler[Self]
    ) -> Self:
        sanitized: ValidationError | None = None
        try:
            return handler(value)
        except ValidationError as error:
            sanitized = _safe_validation_error(cls, error)
        if sanitized is None:
            raise AssertionError("validation wrapper did not produce a result")
        raise sanitized

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise FeatureFrozenError()

    def __delattr__(self, _name: str) -> NoReturn:
        raise FeatureFrozenError()

    @model_validator(mode="after")
    def _utf8_text(self) -> Self:
        def check(value: object) -> None:
            if isinstance(value, str):
                try:
                    value.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise ValueError("feature text must be UTF-8 encodable") from exc
            elif isinstance(value, (tuple, list)):
                for element in value:
                    check(element)

        for field_name in type(self).model_fields:
            check(getattr(self, field_name))
        return self


class FeatureDefinitionV1(_FeatureModel):
    """An immutable name/version definition; publication is part of its identity."""

    feature_name: str
    feature_version: str
    value_kind: Literal["decimal", "vector"]
    published: bool

    @field_validator("feature_name", "feature_version")
    @classmethod
    def _nonempty_identity(cls, value: str) -> str:
        if not value or value != value.strip():
            raise ValueError("feature identity must be nonempty and have no edge whitespace")
        return value

    @property
    def semantic_hash(self) -> str:
        return _semantic_hash(
            {
                "feature_name": self.feature_name,
                "feature_version": self.feature_version,
                "published": self.published,
                "value_kind": self.value_kind,
            }
        )


class FeatureObservationV1(_FeatureModel):
    """One source observation, with separate event and knowledge clocks."""

    feature_name: str
    feature_version: str
    instrument_id: str
    source_dataset: str
    source_record_key: str
    event_time_ns: int
    availability_ns: int
    value_decimal: Decimal | None = None
    value_vector: tuple[Decimal, ...] | None = None
    quality: str | None = None
    is_null: bool = False
    local_receipt_ns: int | None = None

    @field_validator(
        "feature_name", "feature_version", "instrument_id", "source_dataset", "source_record_key"
    )
    @classmethod
    def _nonempty_identity(cls, value: str) -> str:
        if not value or value != value.strip():
            raise ValueError("feature identity must be nonempty and have no edge whitespace")
        return value

    @field_validator("value_decimal", mode="before")
    @classmethod
    def _exact_decimal(cls, value: object) -> Decimal | None:
        return None if value is None else _decimal_at_boundary(value)

    @field_validator("value_vector", mode="before")
    @classmethod
    def _exact_vector(cls, value: object) -> tuple[Decimal, ...] | None:
        return _vector_at_boundary(value)

    @field_serializer("value_decimal", when_used="json")
    def _json_decimal(self, value: Decimal | None) -> str | None:
        return _canonical_decimal(value) if value is not None else None

    @field_serializer("value_vector", when_used="json")
    def _json_vector(self, value: tuple[Decimal, ...] | None) -> list[str] | None:
        return _canonical_vector(value)

    @model_validator(mode="after")
    def _validate_value_and_clocks(self) -> FeatureObservationV1:
        if self.availability_ns < self.event_time_ns:
            raise ValueError("availability_ns must be at or after event_time_ns")
        has_decimal = self.value_decimal is not None
        has_vector = self.value_vector is not None
        if self.is_null and (has_decimal or has_vector):
            raise ValueError("null observation cannot carry a value")
        if not self.is_null and has_decimal == has_vector:
            raise ValueError("non-null observation requires exactly one value kind")
        return self

    @property
    def semantic_hash(self) -> str:
        return _semantic_hash(
            {
                "availability_ns": self.availability_ns,
                "event_time_ns": self.event_time_ns,
                "feature_name": self.feature_name,
                "feature_version": self.feature_version,
                "instrument_id": self.instrument_id,
                "is_null": self.is_null,
                "quality": self.quality,
                "source_dataset": self.source_dataset,
                "source_record_key": self.source_record_key,
                "value_decimal": (
                    _canonical_decimal(self.value_decimal)
                    if self.value_decimal is not None
                    else None
                ),
                "value_vector": (_canonical_vector(self.value_vector)),
            }
        )


class FeatureQueryV1(_FeatureModel):
    """A historical feature lookup at an explicit UTC nanosecond cutoff."""

    feature_name: str
    feature_version: str
    instrument_id: str
    asof_ns: int

    @field_validator("feature_name", "feature_version", "instrument_id")
    @classmethod
    def _nonempty_identity(cls, value: str) -> str:
        if not value or value != value.strip():
            raise ValueError("feature identity must be nonempty and have no edge whitespace")
        return value


class FeatureLineageV1(_FeatureModel):
    """Definition and selected observation provenance for a query result."""

    definition_sha256: str
    observation_sha256: str | None = None
    source_dataset: str | None = None
    source_record_key: str | None = None


class FeatureResultV1(_FeatureModel):
    """A selected observation or a genuinely missing historical value."""

    found: bool
    feature_name: str
    feature_version: str
    instrument_id: str
    asof_ns: int
    value_decimal: Decimal | None = None
    value_vector: tuple[Decimal, ...] | None = None
    quality: str | None = None
    is_null: bool = False
    source_dataset: str | None = None
    source_record_key: str | None = None
    event_time_ns: int | None = None
    availability_ns: int | None = None
    source_keys: tuple[str, ...] = ()
    definition_hash: str
    observation_hash: str | None = None
    lineage: FeatureLineageV1

    @field_validator("source_keys", mode="before")
    @classmethod
    def _source_keys_tuple(cls, value: object) -> object:
        # Python-mode lists are intentionally accepted so JSON-parsed arrays can be revalidated.
        return tuple(value) if type(value) is list else value

    def __init__(self, /, **data: Any) -> None:
        """Prevent re-initialization of an issued object before any field writes."""
        already_issued = False
        try:
            require(self, _FEATURE_RESULT_SEAL_TAG)
        except SealError as error:
            already_issued = error.code != "SEAL_NOT_ISSUED"
        else:
            already_issued = True
        if already_issued:
            raise FeatureResultSealError()
        super().__init__(**data)

    @field_validator("value_decimal", mode="before")
    @classmethod
    def _exact_decimal(cls, value: object) -> Decimal | None:
        return None if value is None else _decimal_at_boundary(value)

    @field_validator("value_vector", mode="before")
    @classmethod
    def _exact_vector(cls, value: object) -> tuple[Decimal, ...] | None:
        return _vector_at_boundary(value)

    @field_serializer("value_decimal", when_used="json")
    def _json_decimal(self, value: Decimal | None) -> str | None:
        return _canonical_decimal(value) if value is not None else None

    @field_serializer("value_vector", when_used="json")
    def _json_vector(self, value: tuple[Decimal, ...] | None) -> list[str] | None:
        return _canonical_vector(value)


class FeatureResultSealError(ValueError):
    """Content-free failure to require an issued, unchanged feature result."""

    code = "FEATURE_RESULT_UNTRUSTED"

    def __init__(self) -> None:
        super().__init__(self.code)


def _issue_feature_result(**data: Any) -> FeatureResultV1:
    """Build and issue a feature result for the FEAT-001 query kernel only."""
    result = FeatureResultV1(**data)
    return _FEATURE_RESULT_ISSUER.issue(result)


def require_feature_result(obj: object) -> FeatureResultV1:
    """Return an exact-type, unchanged FEAT-001 result or raise a fixed error."""
    if type(obj) is not FeatureResultV1 or not _FEATURE_RESULT_ISSUER.issued_here(obj):
        raise FeatureResultSealError()
    return obj
