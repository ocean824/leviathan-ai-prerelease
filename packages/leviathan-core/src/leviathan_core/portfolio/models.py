"""Versioned, immutable inputs and advisory outputs for PORT-001.

All monetary amounts are in account currency unless a field says otherwise.
Observations must be explicitly validated, as-of pinned, and source versioned.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields, is_dataclass
from decimal import Decimal
from enum import StrEnum
from fractions import Fraction
from typing import Any, SupportsIndex, cast

FORMULA_VERSION = "PORT-FORMULA-v1"
_SOURCE_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,64}", re.ASCII)
_VALIDATION_STATUSES = frozenset({"VALIDATED", "UNVALIDATED", "REJECTED"})
_ASSET_STATUSES = frozenset({"VALIDATED", "GRID_VARIANT", "FAILED_OOS", "PARAMETER_ONLY"})


class SizingInputError(ValueError):
    """Content-free error for malformed public sizing records."""


def _bounded_decimal(value: Decimal) -> None:
    if type(value) is not Decimal or not value.is_finite():
        raise SizingInputError("INVALID_DECIMAL")
    coefficient = value.as_tuple().digits
    significant = len(coefficient)
    while significant > 1 and coefficient[significant - 1] == 0:
        significant -= 1
    if significant > 34 or (not value.is_zero() and abs(value.adjusted()) > 38):
        raise SizingInputError("PRECISION_EXCEEDED")


def _validate_field(value: object) -> None:
    if value is None:
        return
    if type(value) is Decimal:
        _bounded_decimal(value)
    elif type(value) is int:
        if value < 0:
            raise SizingInputError("INVALID_TIMESTAMP")
    elif type(value) is str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise SizingInputError("INVALID_FIELD_TYPE")
    elif type(value) in (SizingMode, SizingStatus):
        return
    elif type(value) is tuple:
        for item in value:
            _validate_field(item)
    elif type(value) not in _RECORD_TYPES:
        raise SizingInputError("INVALID_FIELD_TYPE")


class _FrozenRecord:
    def __post_init__(self) -> None:
        for field in fields(cast(Any, self)):
            value = getattr(self, field.name)
            if field.name == "source_id" and (
                type(value) is not str or not _SOURCE_ID_PATTERN.fullmatch(value)
            ):
                raise SizingInputError("INVALID_SOURCE_ID")
            _validate_field(value)
            if field.name == "validation_status" and value not in _VALIDATION_STATUSES:
                raise SizingInputError("INVALID_VALIDATION_STATUS")
            if (
                field.name == "status"
                and isinstance(self, AssetProvenanceV1)
                and value not in _ASSET_STATUSES
            ):
                raise SizingInputError("INVALID_ASSET_STATUS")

    def __copy__(self) -> None:
        raise SizingInputError("FROZEN_RECORD")

    def __deepcopy__(self, memo: dict[int, object]) -> None:
        raise SizingInputError("FROZEN_RECORD")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise SizingInputError("FROZEN_RECORD")


class SizingMode(StrEnum):
    FIXED = "fixed"
    VOLATILITY_SCALED = "volatility_scaled"
    RISK_PARITY = "risk_parity"
    CAPPED_KELLY = "capped_kelly"
    INVERSE_VOLATILITY = "inverse_volatility"


class SizingStatus(StrEnum):
    SIZE = "SIZE"
    NO_SIZE = "NO_SIZE"


@dataclass(frozen=True, slots=True)
class ObservationV1(_FrozenRecord):
    value: Decimal
    event_ns: int
    available_ns: int
    source_id: str
    source_version: str
    validation_status: str


@dataclass(frozen=True, slots=True)
class PositionV1(_FrozenRecord):
    instrument: str
    instrument_currency: str
    quantity: Decimal  # signed, positive long
    price: ObservationV1
    fx_to_account: ObservationV1
    loss_per_unit: ObservationV1  # adverse loss in instrument currency per unit
    contract_multiplier: Decimal
    as_of_ns: int
    available_ns: int
    source_id: str
    source_version: str
    validation_status: str


@dataclass(frozen=True, slots=True)
class SectorEntryV1(_FrozenRecord):
    instrument: str
    sector: str
    event_ns: int
    available_ns: int
    source_id: str
    source_version: str
    validation_status: str


@dataclass(frozen=True, slots=True)
class ReturnPointV1(_FrozenRecord):
    timestamp_ns: int
    value: Decimal


@dataclass(frozen=True, slots=True)
class ReturnSeriesV1(_FrozenRecord):
    instrument: str
    as_of_ns: int
    available_ns: int
    points: tuple[ReturnPointV1, ...]
    source_id: str
    source_version: str
    validation_status: str


@dataclass(frozen=True, slots=True)
class KellyEstimateV1(_FrozenRecord):
    win_probability: ObservationV1
    net_odds: ObservationV1
    window_start_ns: int
    window_end_ns: int


@dataclass(frozen=True, slots=True)
class RiskBudgetV1(_FrozenRecord):
    instrument: str
    fraction: Decimal

    def __post_init__(self) -> None:
        _FrozenRecord.__post_init__(self)
        if self.fraction < 0:
            raise SizingInputError("NEGATIVE_RISK_BUDGET")


@dataclass(frozen=True, slots=True)
class AssetProvenanceV1(_FrozenRecord):
    asset_id: str
    status: str  # VALIDATED, GRID_VARIANT, FAILED_OOS, PARAMETER_ONLY


@dataclass(frozen=True, slots=True)
class HardCapsV1(_FrozenRecord):
    per_symbol_notional: Decimal
    per_sector_notional: Decimal
    gross_notional: Decimal
    net_notional: Decimal
    max_leverage: Decimal
    per_trade_loss: Decimal
    portfolio_heat: Decimal

    def __post_init__(self) -> None:
        _FrozenRecord.__post_init__(self)
        if any(getattr(self, field.name) < 0 for field in fields(self)):
            raise SizingInputError("NEGATIVE_HARD_CAP")


@dataclass(frozen=True, slots=True)
class SizingRequestV1(_FrozenRecord):
    tenant_id: str
    strategy_revision_hash: str
    portfolio_revision_hash: str
    instrument: str
    side: str  # BUY or SELL; order direction, not position sign
    instrument_currency: str
    account_currency: str
    evaluation_ns: int
    equity: ObservationV1
    positions: tuple[PositionV1, ...]
    sector_map: tuple[SectorEntryV1, ...]
    price: ObservationV1
    fx_to_account: ObservationV1
    return_series: tuple[ReturnSeriesV1, ...]
    kelly_estimate: KellyEstimateV1 | None
    worst_case_loss_per_unit: ObservationV1
    contract_multiplier: Decimal
    lot_step: Decimal
    min_notional: Decimal
    lookback_count: int | None
    annualization_factor: Decimal | None
    risk_rail_policy_digest: str
    candidate_provenance: AssetProvenanceV1 | None


@dataclass(frozen=True, slots=True)
class SizingPolicyV1(_FrozenRecord):
    mode: SizingMode
    fixed_quantity: Decimal | None
    risk_budget_fractions: tuple[RiskBudgetV1, ...]
    fractional_kelly_factor: Decimal | None
    gross_exposure_target: Decimal | None
    caps: HardCapsV1
    max_age_ns: int
    policy_digest: str

    def __post_init__(self) -> None:
        _FrozenRecord.__post_init__(self)
        if type(self.caps) is not HardCapsV1 or type(self.mode) is not SizingMode:
            raise SizingInputError("INVALID_POLICY")
        if type(self.risk_budget_fractions) is not tuple or any(
            type(item) is not RiskBudgetV1 for item in self.risk_budget_fractions
        ):
            raise SizingInputError("INVALID_POLICY")
        for value in (
            self.fixed_quantity,
            self.fractional_kelly_factor,
            self.gross_exposure_target,
        ):
            if value is not None and (type(value) is not Decimal or value <= 0):
                raise SizingInputError("INVALID_POLICY")
        if self.fractional_kelly_factor is not None and self.fractional_kelly_factor > 1:
            raise SizingInputError("INVALID_POLICY")
        if type(self.max_age_ns) is not int or self.max_age_ns < 0:
            raise SizingInputError("INVALID_POLICY")
        if type(self.policy_digest) is not str or not self.policy_digest:
            raise SizingInputError("INVALID_POLICY")
        required_by_mode = {
            SizingMode.FIXED: self.fixed_quantity is not None,
            SizingMode.VOLATILITY_SCALED: bool(self.risk_budget_fractions),
            SizingMode.RISK_PARITY: self.gross_exposure_target is not None,
            SizingMode.INVERSE_VOLATILITY: self.gross_exposure_target is not None,
            SizingMode.CAPPED_KELLY: self.fractional_kelly_factor is not None,
        }
        if not required_by_mode[self.mode]:
            raise SizingInputError("MISSING_MODE_POLICY_INPUT")
        fractions = [entry.fraction for entry in self.risk_budget_fractions]
        if len({entry.instrument for entry in self.risk_budget_fractions}) != len(fractions):
            raise SizingInputError("INVALID_RISK_BUDGET")
        if (
            any(value <= 0 or value > 1 for value in fractions)
            or sum((Fraction(value) for value in fractions), Fraction(0)) > 1
        ):
            raise SizingInputError("INVALID_RISK_BUDGET")


@dataclass(frozen=True, slots=True)
class CapHitV1(_FrozenRecord):
    code: str
    unclamped_quantity: Decimal
    clamped_quantity: Decimal


@dataclass(frozen=True, slots=True)
class ExposureSnapshotV1(_FrozenRecord):
    symbol_notional: Decimal
    sector_notional: Decimal
    gross_notional: Decimal
    net_notional: Decimal
    leverage: Decimal
    projected_worst_case_loss: Decimal
    portfolio_heat: Decimal


@dataclass(frozen=True, slots=True)
class SizingResultV1(_FrozenRecord):
    status: SizingStatus
    proposed_quantity: Decimal
    unclamped_quantity: Decimal
    reasons: tuple[str, ...]
    cap_hits: tuple[CapHitV1, ...]
    exposures: ExposureSnapshotV1 | None
    input_hash: str
    policy_hash: str
    as_of_age_ns: int | None
    calculation_trace: tuple[str, ...]
    formula_version: str = FORMULA_VERSION

    def canonical_bytes(self) -> bytes:
        """Stable UTF-8 JSON suitable for replay and independent process comparison."""
        return canonical_bytes(self)


_RECORD_TYPES = (
    ObservationV1,
    PositionV1,
    SectorEntryV1,
    ReturnPointV1,
    ReturnSeriesV1,
    KellyEstimateV1,
    RiskBudgetV1,
    AssetProvenanceV1,
    HardCapsV1,
    SizingRequestV1,
    SizingPolicyV1,
    CapHitV1,
    ExposureSnapshotV1,
    SizingResultV1,
)


def _canonical_decimal(value: Decimal) -> str:
    _bounded_decimal(value)
    if value.is_zero():
        return "0"
    sign, coefficient, exponent = value.as_tuple()
    assert isinstance(exponent, int)
    digits = list(coefficient)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    return ("-" if sign else "") + "".join(map(str, digits)) + "e" + str(exponent)


def _canonical(value: Any) -> Any:
    if isinstance(value, Decimal):
        return _canonical_decimal(value)
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        data = {field.name: _canonical(getattr(value, field.name)) for field in fields(value)}
        if isinstance(value, SizingRequestV1):
            for name in ("positions", "sector_map", "return_series"):
                data[name].sort(key=lambda item: item["instrument"])
        elif isinstance(value, SizingPolicyV1):
            data["risk_budget_fractions"].sort(key=lambda item: item["instrument"])
        return data
    if isinstance(value, (tuple, list)):
        return [_canonical(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    # An invalid caller type is still representable in a denied audit result.
    return f"INVALID_TYPE:{type(value).__module__}.{type(value).__qualname__}"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
