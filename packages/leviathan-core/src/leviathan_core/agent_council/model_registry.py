"""Pure, version-pinned BYO model capability registry values."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any, ClassVar, Literal, Self

from pydantic import Field, StrictInt, field_validator, model_validator

from leviathan_core.numeric import parse_decimal
from leviathan_core.seal import SealedModel, SealError

Provider = Literal["claude", "gemini", "deepseek", "gpt", "ollama"]
Modality = Literal["text", "vision", "audio"]
QualityClass = Literal["basic", "standard", "advanced"]
PrivacyClass = Literal["public", "internal", "restricted"]
BudgetClass = Literal["low", "medium", "high"]

MAX_NS = 2**63 - 1
MAX_TOKENS = 10**9
MAX_COST_USD = Decimal("10000")
MAX_ELAPSED_NS = 7 * 24 * 60 * 60 * 1_000_000_000
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_VERSION = re.compile(r"v[1-9][0-9]{0,8}\Z", re.ASCII)
_SCHEMA = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}@v[1-9][0-9]{0,8}\Z", re.ASCII)
_CREDENTIAL_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z", re.ASCII)


class RouteModelError(ValueError):
    """Fixed, content-free error at a routing model boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _RouteModel(SealedModel):
    _error_code: ClassVar[str] = "ROUTE_MODEL_INVALID"

    def __init__(self, /, **data: Any) -> None:
        try:
            super().__init__(**data)
        except SealError:
            raise RouteModelError(self._error_code) from None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate(obj, **kwargs)
        except SealError:
            raise RouteModelError(cls._error_code) from None

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate_json(json_data, **kwargs)
        except SealError:
            raise RouteModelError(cls._error_code) from None


def _identifier(value: str) -> str:
    if _ID.fullmatch(value) is None:
        raise ValueError("identifier invalid")
    return value


def _version(value: str) -> str:
    if _VERSION.fullmatch(value) is None:
        raise ValueError("version invalid")
    return value


def _schema(value: str) -> str:
    if _SCHEMA.fullmatch(value) is None:
        raise ValueError("schema reference invalid")
    return value


def _unique(values: tuple[str, ...]) -> None:
    if len(set(values)) != len(values):
        raise ValueError("duplicate values")


class ModelCapabilityV1(_RouteModel):
    """Capabilities exposed by a versioned registry entry, never by model output."""

    modalities: tuple[Modality, ...] = Field(min_length=1, max_length=3)
    tools: tuple[str, ...] = Field(default=(), max_length=64)
    output_schemas: tuple[str, ...] = Field(default=(), max_length=64)
    structured_output: bool
    max_context_tokens: StrictInt = Field(gt=0, le=MAX_TOKENS)
    max_output_tokens: StrictInt = Field(gt=0, le=MAX_TOKENS)
    quality_class: QualityClass
    privacy_class: PrivacyClass

    @field_validator("tools")
    @classmethod
    def valid_tools(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _identifier(value)
        _unique(values)
        return values

    @field_validator("output_schemas")
    @classmethod
    def valid_schemas(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _schema(value)
        _unique(values)
        return values

    @model_validator(mode="after")
    def coherent(self) -> ModelCapabilityV1:
        _unique(self.modalities)
        if not self.structured_output and self.output_schemas:
            raise ValueError("schema support requires structured output")
        return self


class ModelRegistryEntryV1(_RouteModel):
    """One approved or denied provider model snapshot; no credential value."""

    entry_id: str
    alias: str
    provider: Provider
    model_id: str
    model_version: str
    registry_version: str
    capability: ModelCapabilityV1
    supported_regions: tuple[str, ...] = Field(min_length=1, max_length=32)
    approved: bool
    available: bool
    available_from_ns: StrictInt = Field(ge=0, le=MAX_NS)
    available_until_ns: StrictInt = Field(gt=0, le=MAX_NS)
    credential_name: str
    input_cost_per_million_tokens_usd: Decimal
    output_cost_per_million_tokens_usd: Decimal
    cost_class: BudgetClass
    latency_class: BudgetClass
    latency_reservation_ns: StrictInt = Field(gt=0, le=MAX_ELAPSED_NS)

    @field_validator("entry_id", "alias", "model_id", "model_version")
    @classmethod
    def valid_ids(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("registry_version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        return _version(value)

    @field_validator("supported_regions")
    @classmethod
    def valid_regions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _identifier(value)
        _unique(values)
        return values

    @field_validator("credential_name")
    @classmethod
    def valid_credential_name(cls, value: str) -> str:
        if _CREDENTIAL_NAME.fullmatch(value) is None:
            raise ValueError("credential name invalid")
        return value

    @field_validator(
        "input_cost_per_million_tokens_usd",
        "output_cost_per_million_tokens_usd",
        mode="before",
    )
    @classmethod
    def valid_rate(cls, value: object) -> Decimal:
        return parse_decimal(value, field="model_rate", min_value="0", max_value=MAX_COST_USD)

    @model_validator(mode="after")
    def coherent(self) -> ModelRegistryEntryV1:
        if self.available_until_ns <= self.available_from_ns:
            raise ValueError("availability window invalid")
        return self


class ModelRegistryV1(_RouteModel):
    """A versioned snapshot; entry order has no routing authority."""

    version: str
    entries: tuple[ModelRegistryEntryV1, ...] = Field(max_length=256)

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        return _version(value)

    @model_validator(mode="after")
    def coherent(self) -> ModelRegistryV1:
        if any(entry.registry_version != self.version for entry in self.entries):
            raise ValueError("registry versions differ")
        _unique(tuple(entry.entry_id for entry in self.entries))
        return self


__all__ = [
    "BudgetClass",
    "Modality",
    "ModelCapabilityV1",
    "ModelRegistryEntryV1",
    "ModelRegistryV1",
    "PrivacyClass",
    "Provider",
    "QualityClass",
    "RouteModelError",
]
