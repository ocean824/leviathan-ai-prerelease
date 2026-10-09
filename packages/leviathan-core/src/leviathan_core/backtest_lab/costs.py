"""Exact fee, rebate and explicitly requested financing calculations."""

from __future__ import annotations

import re
from dataclasses import InitVar, dataclass
from decimal import Decimal
from fractions import Fraction
from typing import Literal, NoReturn, SupportsIndex

from leviathan_core.numeric import Ratio
from leviathan_core.seal import Issuer, SealError, require

from .orders import (
    _MAX_UTC_NS,
    FillKernelError,
    FillPolicyError,
    FillValidationError,
    _decimal,
    _FrozenInput,
    _ns,
    _text,
)

_CURRENCY = re.compile(r"[A-Z]{3}\Z", re.ASCII)
_FINANCING_ISSUER = Issuer("bt003.financing.v1")
_RATES_ISSUER = Issuer("bt003.financing_rates.v1")


def _currency(value: object) -> None:
    if type(value) is not str or _CURRENCY.fullmatch(value) is None:
        raise FillValidationError("INVALID_CURRENCY") from None


def _minor_units(value: object) -> None:
    if type(value) is not int or not 0 <= value <= 6:
        raise FillValidationError("INVALID_MINOR_UNIT_SCALE") from None


def _round_half_even(value: Fraction) -> int:
    negative = value < 0
    numerator = abs(value.numerator)
    quotient, remainder = divmod(numerator, value.denominator)
    twice = remainder * 2
    if twice > value.denominator or (twice == value.denominator and quotient % 2):
        quotient += 1
    return -quotient if negative else quotient


def _reported(value: Fraction, minor_units: int) -> Decimal:
    rounded = _round_half_even(value * (10**minor_units))
    sign = 1 if rounded < 0 else 0
    digits = tuple(int(char) for char in str(abs(rounded)))
    return Decimal((sign, digits, -minor_units))


def _fraction(value: Decimal) -> Fraction:
    return Fraction(value)


@dataclass(frozen=True, slots=True)
class FeeModelV1(_FrozenInput):
    version: str
    currency: str
    minor_units: int
    fee_per_share: Decimal
    fee_bps: Decimal
    rebate_per_share: Decimal
    rebate_bps: Decimal
    minimum_order_fee: Decimal | None = None
    maximum_order_fee: Decimal | None = None

    def __post_init__(self) -> None:
        if not _text(self.version):
            raise FillValidationError("INVALID_MODEL_VERSION") from None
        _currency(self.currency)
        _minor_units(self.minor_units)
        object.__setattr__(self, "fee_per_share", _decimal(self.fee_per_share, nonnegative=True))
        object.__setattr__(self, "fee_bps", _decimal(self.fee_bps, nonnegative=True))
        object.__setattr__(
            self, "rebate_per_share", _decimal(self.rebate_per_share, nonnegative=True)
        )
        object.__setattr__(self, "rebate_bps", _decimal(self.rebate_bps, nonnegative=True))
        for name in ("minimum_order_fee", "maximum_order_fee"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _decimal(value, nonnegative=True))
        if (
            self.minimum_order_fee is not None and self.maximum_order_fee is not None
            and self.minimum_order_fee > self.maximum_order_fee
        ):
            raise FillValidationError("INVALID_ORDER_FEE_BOUNDS") from None


@dataclass(frozen=True, slots=True)
class FinancingRatesV1(_FrozenInput):
    """APR rates against an explicit per-unit reference price and period basis."""

    version: str
    currency: str
    minor_units: int
    reference_price: Decimal
    period_ns: int
    borrow_apr: Decimal | None
    long_financing_apr: Decimal | None

    def __post_init__(self) -> None:
        try:
            require(self, _RATES_ISSUER.tag)
        except SealError as exc:
            if exc.code != "SEAL_NOT_ISSUED":
                raise FillValidationError("FINANCING_RATES_REINIT") from None
        else:
            raise FillValidationError("FINANCING_RATES_REINIT") from None
        if not _text(self.version):
            raise FillValidationError("INVALID_MODEL_VERSION") from None
        _currency(self.currency)
        _minor_units(self.minor_units)
        object.__setattr__(self, "reference_price", _decimal(self.reference_price, positive=True))
        if type(self.period_ns) is not int or not 0 < self.period_ns <= _MAX_UTC_NS:
            raise FillValidationError("INVALID_FINANCING_PERIOD") from None
        for name in ("borrow_apr", "long_financing_apr"):
            value = getattr(self, name)
            if value is not None:
                normalized = _decimal(value, nonnegative=True)
                object.__setattr__(self, name, normalized)
        _RATES_ISSUER.issue(self)


class _FinancingResultBoundary(_FrozenInput):
    def __getattribute__(self, name: str) -> object:
        if name in {
            "position_side", "quantity", "entry_ns", "exit_ns", "elapsed_ns",
            "amount_exact", "amount", "currency", "status", "rates_version",
        }:
            try:
                require(self, _FINANCING_ISSUER.tag)
            except SealError as exc:
                if exc.code == "SEAL_NOT_ISSUED":
                    return object.__getattribute__(self, name)
                raise FillKernelError("FINANCING_RESULT_TAMPERED") from None
        return object.__getattribute__(self, name)


@dataclass(frozen=True, slots=True)
class FinancingAccrualV1(_FinancingResultBoundary):
    position_side: Literal["LONG", "SHORT"]
    quantity: Decimal
    entry_ns: int
    exit_ns: int
    elapsed_ns: int
    amount_exact: Ratio
    amount: Decimal
    currency: str
    status: Literal["ACCRUED", "NOT_DECLARED"]
    rates_version: str
    _issuer: InitVar[Issuer | None] = None

    def __post_init__(self, _issuer: Issuer | None) -> None:
        try:
            require(self, _FINANCING_ISSUER.tag)
        except SealError as exc:
            if exc.code != "SEAL_NOT_ISSUED":
                raise FillKernelError("FINANCING_RESULT_TAMPERED") from None
        else:
            raise FillKernelError("FINANCING_RESULT_REINIT") from None
        if _issuer is not _FINANCING_ISSUER:
            raise FillKernelError("FINANCING_RESULT_UNISSUED") from None
        if type(self.position_side) is not str or self.position_side not in ("LONG", "SHORT"):
            raise FillValidationError("INVALID_POSITION_SIDE") from None
        object.__setattr__(self, "quantity", _decimal(self.quantity, positive=True))
        _ns(self.entry_ns)
        _ns(self.exit_ns)
        if self.exit_ns < self.entry_ns or self.elapsed_ns != self.exit_ns - self.entry_ns:
            raise FillValidationError("INVALID_FINANCING_HORIZON") from None
        if type(self.amount_exact) is not Ratio:
            raise FillValidationError("INVALID_FINANCING_AMOUNT") from None
        object.__setattr__(self, "amount", _decimal(self.amount, nonnegative=True))
        _currency(self.currency)
        if type(self.status) is not str or self.status not in ("ACCRUED", "NOT_DECLARED"):
            raise FillValidationError("INVALID_FINANCING_STATUS") from None
        if not _text(self.rates_version):
            raise FillValidationError("INVALID_MODEL_VERSION") from None
        _FINANCING_ISSUER.issue(self)

    def __copy__(self) -> NoReturn:
        raise FillKernelError("COPY_FORBIDDEN") from None

    def __deepcopy__(self, memo: object) -> NoReturn:
        del memo
        raise FillKernelError("COPY_FORBIDDEN") from None

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise FillKernelError("PICKLE_FORBIDDEN") from None

    def __setstate__(self, state: object) -> NoReturn:
        del state
        raise FillKernelError("RESTORE_FORBIDDEN") from None

    def require_integrity(self) -> FinancingAccrualV1:
        try:
            return require(self, _FINANCING_ISSUER.tag)
        except SealError:
            raise FillKernelError("FINANCING_RESULT_TAMPERED") from None


def accrue_financing(
    position_side: Literal["LONG", "SHORT"],
    quantity: Decimal,
    entry_ns: int,
    exit_ns: int,
    rates: FinancingRatesV1,
) -> FinancingAccrualV1:
    """Accrue one caller-declared horizon; no position holding time is inferred."""
    if type(position_side) is not str or position_side not in ("LONG", "SHORT"):
        raise FillValidationError("INVALID_POSITION_SIDE") from None
    normalized_quantity = _decimal(quantity, positive=True)
    start = _ns(entry_ns)
    end = _ns(exit_ns)
    if end < start:
        raise FillValidationError("INVALID_FINANCING_HORIZON") from None
    if type(rates) is not FinancingRatesV1:
        raise FillValidationError("INVALID_FINANCING_RATES") from None
    try:
        require(rates, _RATES_ISSUER.tag)
    except SealError:
        raise FillKernelError("FINANCING_RATES_TAMPERED") from None
    rate = rates.borrow_apr if position_side == "SHORT" else rates.long_financing_apr
    status: Literal["ACCRUED", "NOT_DECLARED"] = "ACCRUED"
    if rate is None:
        if position_side == "SHORT":
            raise FillPolicyError("BORROW_RATE_REQUIRED") from None
        amount = Decimal(0)
        exact = Fraction(0)
        status = "NOT_DECLARED"
    else:
        exact = (
            _fraction(normalized_quantity)
            * _fraction(rates.reference_price)
            * _fraction(rate)
            * Fraction(end - start, rates.period_ns)
        )
        amount = _reported(exact, rates.minor_units)
    result = FinancingAccrualV1(
        position_side=position_side,
        quantity=normalized_quantity,
        entry_ns=start,
        exit_ns=end,
        elapsed_ns=end - start,
        amount_exact=Ratio(exact.numerator, exact.denominator),
        amount=amount,
        currency=rates.currency,
        status=status,
        rates_version=rates.version,
        _issuer=_FINANCING_ISSUER,
    )
    return result.require_integrity()
