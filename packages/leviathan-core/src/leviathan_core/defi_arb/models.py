"""Strict synthetic evidence and policy for offline arbitrage arithmetic."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, SupportsIndex

from leviathan_core.numeric import NumericError, parse_decimal, parse_int
from leviathan_core.seal import SealedModel

_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z", re.ASCII)
_MAX_UNITS = (1 << 256) - 1
_MAX_NS = (1 << 63) - 1
_MAX_LEGS = 8
_MAX_TOKENS = 9


class ArbInputError(ValueError):
    """A content-free, stable input rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _Record:
    def __copy__(self) -> Any:
        raise ArbInputError("FORBIDDEN_OPERATION")

    def __deepcopy__(self, memo: dict[int, object]) -> Any:
        raise ArbInputError("FORBIDDEN_OPERATION")

    def __reduce__(self) -> Any:
        raise ArbInputError("FORBIDDEN_OPERATION")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise ArbInputError("FORBIDDEN_OPERATION")


def _id(value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ArbInputError("INVALID_IDENTIFIER")
    return value


def _int(value: object, *, minimum: int = 0, maximum: int = _MAX_UNITS) -> int:
    try:
        return parse_int(value, field="integer", min_value=minimum, max_value=maximum)
    except NumericError:
        raise ArbInputError("INVALID_INTEGER") from None


def _decimal(value: object, *, positive: bool = False) -> Decimal:
    if type(value) not in (Decimal, str, int):
        raise ArbInputError("INVALID_DECIMAL")
    try:
        result = parse_decimal(value, field="decimal")
    except NumericError:
        raise ArbInputError("INVALID_DECIMAL") from None
    if positive and result <= 0:
        raise ArbInputError("OUT_OF_RANGE")
    return result


def _ids(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or not 1 <= len(value) <= 128:
        raise ArbInputError("POLICY_INCOMPLETE")
    checked = tuple(_id(item) for item in value)
    if len(set(checked)) != len(checked):
        raise ArbInputError("POLICY_OUT_OF_BOUNDS")
    return checked


@dataclass(frozen=True, slots=True)
class TokenV1(_Record):
    chain_id: str
    token_id: str
    decimals: int
    oracle_price: Decimal
    oracle_as_of_ns: int
    oracle_digest: str

    def __post_init__(self) -> None:
        _id(self.chain_id)
        _id(self.token_id)
        _int(self.decimals, maximum=36)
        object.__setattr__(self, "oracle_price", _decimal(self.oracle_price, positive=True))
        _int(self.oracle_as_of_ns, maximum=_MAX_NS)
        _id(self.oracle_digest)


@dataclass(frozen=True, slots=True)
class SwapLegV1(_Record):
    pool_type: str
    pool_id: str
    venue_id: str
    token_in: str
    token_out: str
    reserve_in_units: int
    reserve_out_units: int
    max_input_units: int
    fee_bp: int
    min_output_units: int
    reserve_as_of_ns: int
    reserve_digest: str

    def __post_init__(self) -> None:
        for value in (
            self.pool_type,
            self.pool_id,
            self.venue_id,
            self.token_in,
            self.token_out,
            self.reserve_digest,
        ):
            _id(value)
        _int(self.reserve_in_units, minimum=1)
        _int(self.reserve_out_units, minimum=1)
        _int(self.max_input_units, minimum=1)
        _int(self.fee_bp, maximum=9_999)
        _int(self.min_output_units, minimum=1)
        _int(self.reserve_as_of_ns, maximum=_MAX_NS)
        if self.max_input_units > self.reserve_in_units:
            raise ArbInputError("INSUFFICIENT_LIQUIDITY")


@dataclass(frozen=True, slots=True)
class FlashLoanV1(_Record):
    provider_id: str
    token_id: str
    principal_units: int
    principal: Decimal
    fee_bp: int

    def __post_init__(self) -> None:
        _id(self.provider_id)
        _id(self.token_id)
        _int(self.principal_units, minimum=1)
        object.__setattr__(self, "principal", _decimal(self.principal, positive=True))
        _int(self.fee_bp, maximum=9_999)


@dataclass(frozen=True, slots=True)
class GasEvidenceV1(_Record):
    gas_units: int
    max_fee_per_gas_units: int
    native_token_id: str
    gas_digest: str

    def __post_init__(self) -> None:
        _int(self.gas_units, minimum=1)
        _int(self.max_fee_per_gas_units, minimum=1)
        _id(self.native_token_id)
        _id(self.gas_digest)


@dataclass(frozen=True, slots=True)
class ForkSnapshotV1(_Record):
    chain_id: str
    snapshot_id: str
    block_hash: str
    snapshot_digest: str

    def __post_init__(self) -> None:
        for value in (self.chain_id, self.snapshot_id, self.block_hash, self.snapshot_digest):
            _id(value)


@dataclass(frozen=True, slots=True)
class ArbRouteV1(_Record):
    route_id: str
    mode: str
    chain_id: str
    snapshot_id: str
    block_hash: str
    quoted_at_ns: int
    deadline_ns: int
    flash_loan: FlashLoanV1
    legs: tuple[SwapLegV1, ...]
    tokens: tuple[TokenV1, ...]
    gas: GasEvidenceV1
    input_digest: str

    def __post_init__(self) -> None:
        for value in (
            self.route_id,
            self.mode,
            self.chain_id,
            self.snapshot_id,
            self.block_hash,
            self.input_digest,
        ):
            _id(value)
        _int(self.quoted_at_ns, maximum=_MAX_NS)
        _int(self.deadline_ns, maximum=_MAX_NS)
        if type(self.flash_loan) is not FlashLoanV1 or type(self.gas) is not GasEvidenceV1:
            raise ArbInputError("INVALID_ROUTE")
        self.flash_loan.__post_init__()
        self.gas.__post_init__()
        if (
            type(self.legs) is not tuple
            or not 1 <= len(self.legs) <= _MAX_LEGS
            or any(type(leg) is not SwapLegV1 for leg in self.legs)
        ):
            raise ArbInputError("INVALID_ROUTE")
        if (
            type(self.tokens) is not tuple
            or not 1 <= len(self.tokens) <= _MAX_TOKENS
            or any(type(token) is not TokenV1 for token in self.tokens)
        ):
            raise ArbInputError("INVALID_ROUTE")
        if len({token.token_id for token in self.tokens}) != len(self.tokens):
            raise ArbInputError("INVALID_ROUTE")
        token_ids = {token.token_id for token in self.tokens}
        if self.flash_loan.token_id not in token_ids or self.gas.native_token_id not in token_ids:
            raise ArbInputError("INVALID_ROUTE")
        seen_pools: set[tuple[str, str]] = set()
        for leg in self.legs:
            leg.__post_init__()
            selector = (leg.venue_id, leg.pool_id)
            if selector in seen_pools:
                raise ArbInputError("DUPLICATE_POOL")
            seen_pools.add(selector)
            if leg.token_in not in token_ids or leg.token_out not in token_ids:
                raise ArbInputError("INVALID_ROUTE")
        for token in self.tokens:
            token.__post_init__()


@dataclass(frozen=True, slots=True)
class ArbPolicyV1(_Record):
    allowed_chains: tuple[str, ...]
    allowed_tokens: tuple[str, ...]
    allowed_venues: tuple[str, ...]
    allowed_flash_providers: tuple[str, ...]
    max_principal_units: int
    max_gas_units: int
    max_fee_per_gas_units: int
    max_gas_cost_value: Decimal
    max_price_impact_bps: int
    max_slippage_bps: int
    max_oracle_deviation_bps: int
    min_profit_value: Decimal
    max_reserve_age_ns: int
    max_oracle_age_ns: int
    max_quote_age_ns: int

    def __post_init__(self) -> None:
        for name in (
            "allowed_chains",
            "allowed_tokens",
            "allowed_venues",
            "allowed_flash_providers",
        ):
            _ids(getattr(self, name))
        _int(self.max_principal_units, minimum=1)
        _int(self.max_gas_units, minimum=1)
        _int(self.max_fee_per_gas_units, minimum=1)
        object.__setattr__(self, "max_gas_cost_value", _decimal(self.max_gas_cost_value))
        if self.max_gas_cost_value < 0:
            raise ArbInputError("POLICY_OUT_OF_BOUNDS")
        _int(self.max_price_impact_bps, maximum=10_000)
        _int(self.max_slippage_bps, maximum=10_000)
        _int(self.max_oracle_deviation_bps, maximum=10_000)
        object.__setattr__(self, "min_profit_value", _decimal(self.min_profit_value))
        if self.min_profit_value < 0:
            raise ArbInputError("POLICY_OUT_OF_BOUNDS")
        _int(self.max_reserve_age_ns, maximum=_MAX_NS)
        _int(self.max_oracle_age_ns, maximum=_MAX_NS)
        _int(self.max_quote_age_ns, maximum=500_000_000)


class SimulationResultV1(SealedModel):
    status: str
    reason_codes: tuple[str, ...]
    proceeds_units: int
    repayment_units: int
    repayment_covered: bool
    flash_fee_units: int
    gas_cost_value: Decimal
    min_profit_value: Decimal
    price_impact_bps_exact: tuple[tuple[int, int], ...]
    slippage_bps_exact: tuple[tuple[int, int], ...]
    oracle_deviation_bps_exact: tuple[tuple[int, int], ...]
    swap_fee_units_exact: tuple[tuple[int, int], ...]
    confidence: str
    evidence_digest: str


__all__ = [
    "ArbInputError",
    "ArbPolicyV1",
    "ArbRouteV1",
    "FlashLoanV1",
    "ForkSnapshotV1",
    "GasEvidenceV1",
    "SimulationResultV1",
    "SwapLegV1",
    "TokenV1",
]
