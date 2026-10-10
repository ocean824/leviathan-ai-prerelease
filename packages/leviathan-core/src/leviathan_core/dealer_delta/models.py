"""Typed source inputs and sealed output for the DEX-001 clean-room kernel."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from leviathan_core.decision_fusion.models import FusionModelV1
from leviathan_core.numeric import parse_decimal
from leviathan_core.seal import SealedModel


class _DexModel(FusionModelV1):
    model_config = ConfigDict(revalidate_instances="always")


def _decimal(value: object, name: str, *, minimum: Decimal | None = None) -> Decimal:
    if type(value) is not Decimal:
        raise ValueError("INVALID_DEX_DECIMAL")
    assert isinstance(value, Decimal)
    try:
        return parse_decimal(value, field="dex_input", min_value=minimum)
    except ValueError:
        raise ValueError("INVALID_DEX_DECIMAL") from None


def _ns(value: object) -> int:
    if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
        raise ValueError("INVALID_DEX_TIME")
    return value


class DexOptionEvidenceV1(_DexModel):
    """Per-series delta quote plus OI/multiplier bound to a source record."""

    series_id: str
    expiry: date
    option_type: Literal["CALL", "PUT"]
    delta: Decimal | None
    open_interest: Decimal
    multiplier: Decimal
    delta_observed_ns: int
    delta_available_ns: int
    oi_asof_ns: int
    source_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("series_id")
    @classmethod
    def _series(cls, value: str) -> str:
        if not value or len(value) > 128 or not value.isascii() or value != value.strip():
            raise ValueError("INVALID_DEX_SERIES")
        return value

    @field_validator("delta", mode="before")
    @classmethod
    def _delta(cls, value: object) -> object:
        if value is not None:
            checked = _decimal(value, "delta")
            if not Decimal(-1) <= checked <= Decimal(1):
                raise ValueError("INVALID_DEX_DELTA")
        return value

    @field_validator("open_interest", "multiplier", mode="before")
    @classmethod
    def _positive_inputs(cls, value: object) -> object:
        return _decimal(value, "contract_input", minimum=Decimal(0))

    @field_validator("delta_observed_ns", "delta_available_ns", "oi_asof_ns", mode="before")
    @classmethod
    def _times(cls, value: object) -> int:
        return _ns(value)

    @model_validator(mode="after")
    def _availability(self) -> DexOptionEvidenceV1:
        if self.multiplier <= 0 or self.delta_available_ns < self.delta_observed_ns:
            raise ValueError("INVALID_DEX_AVAILABILITY")
        if self.delta is not None and (
            (self.option_type == "CALL" and not Decimal(0) <= self.delta <= Decimal(1))
            or (self.option_type == "PUT" and not Decimal(-1) <= self.delta <= Decimal(0))
        ):
            raise ValueError("INVALID_DEX_DELTA")
        return self


class DexChainEvidenceV1(_DexModel):
    """Delta-enriched evidence for the same provider chain snapshot used by GEX."""

    chain_snapshot_id: str
    underlier: str
    venue: str
    provider: str
    dataset: str
    observed_ns: int
    available_ns: int
    provenance_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    series: tuple[DexOptionEvidenceV1, ...]

    @field_validator("chain_snapshot_id", "underlier", "venue", "provider", "dataset")
    @classmethod
    def _identity(cls, value: str) -> str:
        if not value or len(value) > 128 or not value.isascii() or value != value.strip():
            raise ValueError("INVALID_DEX_IDENTITY")
        return value

    @field_validator("observed_ns", "available_ns", mode="before")
    @classmethod
    def _times(cls, value: object) -> int:
        return _ns(value)

    @field_validator("series", mode="before")
    @classmethod
    def _series_tuple(cls, value: object) -> object:
        if type(value) is not tuple or not 1 <= len(value) <= 5000:
            raise ValueError("INVALID_DEX_SERIES")
        return value

    @model_validator(mode="after")
    def _coherent(self) -> DexChainEvidenceV1:
        if self.available_ns < self.observed_ns:
            raise ValueError("INVALID_DEX_AVAILABILITY")
        if len({row.series_id for row in self.series}) != len(self.series):
            raise ValueError("DUPLICATE_DEX_SERIES")
        if any(
            row.delta_available_ns > self.available_ns or row.oi_asof_ns > self.available_ns
            for row in self.series
        ):
            raise ValueError("FUTURE_DEX_EVIDENCE")
        return self


class DexPolicyV1(_DexModel):
    """Named dealer-side scenario; this assumption is not observed inventory."""

    policy_id: str
    version: str
    call_dealer_sign: Literal[-1, 0, 1]
    put_dealer_sign: Literal[-1, 0, 1]

    @field_validator("policy_id", "version")
    @classmethod
    def _policy_id(cls, value: str) -> str:
        if not value or len(value) > 128 or not value.isascii() or value != value.strip():
            raise ValueError("INVALID_DEX_POLICY")
        return value


class DexExpiryExposureV1(SealedModel):
    expiry: date
    signed_delta_contracts: Decimal = Field(
        description="Delta-equivalent underlying units; contract multiplier is already applied."
    )
    series_count: int = Field(ge=1, le=5000)

    @field_validator("signed_delta_contracts", mode="before")
    @classmethod
    def _exposure(cls, value: object) -> Decimal:
        return _decimal(value, "signed_delta_contracts")


class DexEstimateV1(SealedModel):
    schema_version: Literal["dex001.estimate.v1"] = "dex001.estimate.v1"
    status: Literal["OK", "MISSING_DELTA"]
    reason: Literal["NONE", "MISSING_DELTA"]
    chain_snapshot_id: str
    underlier: str
    venue: str
    provider: str
    dataset: str
    chain_observed_ns: int
    observed_ns: int
    available_ns: int
    provenance_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_id: str
    policy_version: str
    expiry_exposures: tuple[DexExpiryExposureV1, ...]
    missing_delta_count: int = Field(ge=0, le=5000)
    semantic_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _status(self) -> DexEstimateV1:
        if self.chain_observed_ns > self.observed_ns or self.observed_ns > self.available_ns:
            raise ValueError("INVALID_DEX_RESULT")
        if (self.status == "OK") != (self.reason == "NONE"):
            raise ValueError("INVALID_DEX_RESULT")
        if self.status == "OK" and (not self.expiry_exposures or self.missing_delta_count):
            raise ValueError("INVALID_DEX_RESULT")
        if self.status == "MISSING_DELTA" and (
            self.expiry_exposures or not self.missing_delta_count
        ):
            raise ValueError("INVALID_DEX_RESULT")
        return self


__all__ = [
    "DexChainEvidenceV1",
    "DexEstimateV1",
    "DexExpiryExposureV1",
    "DexOptionEvidenceV1",
    "DexPolicyV1",
]
