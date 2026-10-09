"""Deterministic, diagnostic-only aggregation of portfolio loss-to-stop heat.

The function consumes one immutable input snapshot and performs no policy
decision, account mutation, route authorization, or LIVE transition.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from typing import Final, NoReturn

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerPortError,
    require_account_view,
)
from leviathan_core.numeric.errors import NumericError
from leviathan_core.numeric.parse import parse_decimal
from leviathan_core.portfolio.models import ObservationV1, PositionV1

_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", re.ASCII)
_CURRENCY: Final[re.Pattern[str]] = re.compile(r"[A-Z]{3}", re.ASCII)
_FORMULA_VERSION: Final[str] = "RISK-004-LOSS-TO-STOP-HEAT-v1"
_MAX_AGE_NS: Final[int] = 300_000_000_000  # RISK-004's existing data freshness bound.
_MAX_POSITIONS: Final[int] = 4096  # RISK-004's existing position-state bound.
_ZERO: Final[Decimal] = Decimal(0)


class PortfolioAggregationError(ValueError):
    """Closed, content-free error surface for portfolio aggregation."""

    _CODES: Final[frozenset[str]] = frozenset(
        {
            "INPUT_INVALID",
            "SNAPSHOT_MISMATCH",
            "DUPLICATE_POSITION",
            "POSITION_ACCOUNT_MISMATCH",
            "EQUITY_MISSING",
            "STOP_MISSING",
            "CURRENCY_MISMATCH",
            "STALE_EVIDENCE",
            "ARITHMETIC_BOUND",
        }
    )

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in self._CODES:
            code = "INPUT_INVALID"
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PortfolioAggregationPositionV1:
    """A position plus its membership in the enclosing aggregation snapshot."""

    snapshot_id: str
    snapshot_version: str
    as_of_ns: int
    equity_currency: str
    position_id: str
    portfolio_id: str
    strategy_id: str
    position: PositionV1


@dataclass(frozen=True, slots=True)
class PortfolioAggregationSnapshotV1:
    """One immutable, versioned account and position snapshot."""

    snapshot_id: str
    snapshot_version: str
    as_of_ns: int
    account_view: AccountViewV1
    positions: tuple[PortfolioAggregationPositionV1, ...]


@dataclass(frozen=True, slots=True)
class PortfolioHeatGroupV1:
    portfolio_id: str
    strategy_id: str
    heat: Decimal


@dataclass(frozen=True, slots=True)
class PortfolioAggregationResultV1:
    """Read-only diagnostic data; this type carries no authority capability."""

    snapshot_id: str
    snapshot_version: str
    account_id: str
    equity_currency: str
    equity_amount: Decimal
    total_heat: Decimal
    groups: tuple[PortfolioHeatGroupV1, ...]
    digest: str
    formula_version: str = _FORMULA_VERSION


def _fail(code: str) -> NoReturn:
    raise PortfolioAggregationError(code)


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _decimal_text(value: Decimal) -> str:
    """Canonical exact decimal text independent of exponent/trailing zero form."""
    if type(value) is not Decimal:
        _fail("INPUT_INVALID")
    try:
        value = parse_decimal(value, field="value")
    except NumericError:
        _fail("INPUT_INVALID")
    if value.is_zero():
        return "0"
    sign, digits_tuple, exponent = value.as_tuple()
    if type(exponent) is not int:
        _fail("INPUT_INVALID")
    digits = list(digits_tuple)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    coefficient = "".join(str(digit) for digit in digits)
    return ("-" if sign else "") + coefficient + "e" + str(exponent)


def _observation_payload(value: ObservationV1) -> dict[str, object]:
    return {
        "value": _decimal_text(value.value),
        "event_ns": value.event_ns,
        "available_ns": value.available_ns,
        "source_id": value.source_id,
        "source_version": value.source_version,
        "validation_status": value.validation_status,
    }


def _position_payload(row: PortfolioAggregationPositionV1) -> dict[str, object]:
    position = row.position
    return {
        "snapshot_id": row.snapshot_id,
        "snapshot_version": row.snapshot_version,
        "as_of_ns": row.as_of_ns,
        "equity_currency": row.equity_currency,
        "position_id": row.position_id,
        "portfolio_id": row.portfolio_id,
        "strategy_id": row.strategy_id,
        "position": {
            "instrument": position.instrument,
            "instrument_currency": position.instrument_currency,
            "quantity": _decimal_text(position.quantity),
            "price": _observation_payload(position.price),
            "fx_to_account": _observation_payload(position.fx_to_account),
            "loss_per_unit": _observation_payload(position.loss_per_unit),
            "contract_multiplier": _decimal_text(position.contract_multiplier),
            "as_of_ns": position.as_of_ns,
            "available_ns": position.available_ns,
            "source_id": position.source_id,
            "source_version": position.source_version,
            "validation_status": position.validation_status,
        },
    }


def _valid_observation(value: object, *, as_of_ns: int, positive: bool) -> bool:
    if type(value) is not ObservationV1:
        return False
    if type(value.value) is not Decimal:
        _fail("INPUT_INVALID")
    try:
        bounded_value = parse_decimal(value.value, field="value")
    except NumericError:
        _fail("INPUT_INVALID")
    return not (
        (positive and bounded_value <= _ZERO)
        or (not positive and bounded_value < _ZERO)
        or type(value.validation_status) is not str
        or value.validation_status != "VALIDATED"
        or type(value.event_ns) is not int
        or type(value.available_ns) is not int
        or value.event_ns < 0
        or value.available_ns < value.event_ns
        or value.available_ns > as_of_ns
        or as_of_ns - value.event_ns > _MAX_AGE_NS
        or not _identifier(value.source_id)
        or not _identifier(value.source_version)
    )


def _validate_snapshot(snapshot: object) -> tuple[PortfolioAggregationSnapshotV1, AccountViewV1]:
    if type(snapshot) is not PortfolioAggregationSnapshotV1:
        _fail("INPUT_INVALID")
    assert isinstance(snapshot, PortfolioAggregationSnapshotV1)
    if (
        not _identifier(snapshot.snapshot_id)
        or not _identifier(snapshot.snapshot_version)
        or type(snapshot.as_of_ns) is not int
        or snapshot.as_of_ns < 0
        or type(snapshot.positions) is not tuple
        or len(snapshot.positions) > _MAX_POSITIONS
        or any(type(row) is not PortfolioAggregationPositionV1 for row in snapshot.positions)
    ):
        _fail("INPUT_INVALID")
    try:
        account_view = require_account_view(snapshot.account_view)
    except (BrokerPortError, TypeError, ValueError):
        _fail("INPUT_INVALID")
    if account_view.equity is None:
        _fail("EQUITY_MISSING")
    equity = account_view.equity
    if equity is None:
        _fail("EQUITY_MISSING")
    if not _CURRENCY.fullmatch(equity.currency) or type(equity.amount) is not Decimal:
        _fail("EQUITY_MISSING")
    try:
        bounded_equity = parse_decimal(equity.amount, field="value")
    except NumericError:
        _fail("INPUT_INVALID")
    if bounded_equity <= _ZERO:
        _fail("EQUITY_MISSING")
    if type(account_view.positions) is not tuple:
        _fail("INPUT_INVALID")
    for pair in account_view.positions:
        if type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not str:
            _fail("INPUT_INVALID")
        if type(pair[1]) is not Decimal:
            _fail("INPUT_INVALID")
        try:
            parse_decimal(pair[1], field="value")
        except NumericError:
            _fail("INPUT_INVALID")
    if (
        type(equity.broker_observed_at_ns) is not int
        or equity.broker_observed_at_ns > snapshot.as_of_ns
        or snapshot.as_of_ns - equity.broker_observed_at_ns > _MAX_AGE_NS
    ):
        _fail("STALE_EVIDENCE")
    return snapshot, account_view


def _validate_row(
    row: PortfolioAggregationPositionV1,
    *,
    snapshot: PortfolioAggregationSnapshotV1,
    equity_currency: str,
) -> PositionV1:
    if (
        not _identifier(row.snapshot_id)
        or not _identifier(row.snapshot_version)
        or type(row.as_of_ns) is not int
        or type(row.equity_currency) is not str
        or not _CURRENCY.fullmatch(row.equity_currency)
        or not all(
            _identifier(value) for value in (row.position_id, row.portfolio_id, row.strategy_id)
        )
    ):
        _fail("INPUT_INVALID")
    if (
        row.snapshot_id != snapshot.snapshot_id
        or row.snapshot_version != snapshot.snapshot_version
        or row.as_of_ns != snapshot.as_of_ns
    ):
        _fail("SNAPSHOT_MISMATCH")
    if row.equity_currency != equity_currency:
        _fail("CURRENCY_MISMATCH")
    position = row.position
    if type(position) is not PositionV1:
        _fail("INPUT_INVALID")
    if type(position.quantity) is not Decimal or type(position.contract_multiplier) is not Decimal:
        _fail("INPUT_INVALID")
    try:
        parse_decimal(position.quantity, field="value")
        bounded_multiplier = parse_decimal(position.contract_multiplier, field="value")
    except NumericError:
        _fail("INPUT_INVALID")
    if (
        not _identifier(position.instrument)
        or type(position.instrument_currency) is not str
        or _CURRENCY.fullmatch(position.instrument_currency) is None
        or bounded_multiplier <= _ZERO
        or type(position.validation_status) is not str
        or type(position.as_of_ns) is not int
        or position.as_of_ns < 0
        or position.as_of_ns > snapshot.as_of_ns
        or snapshot.as_of_ns - position.as_of_ns > _MAX_AGE_NS
        or type(position.available_ns) is not int
        or position.available_ns < position.as_of_ns
        or position.available_ns > snapshot.as_of_ns
        or not _identifier(position.source_id)
        or not _identifier(position.source_version)
    ):
        _fail("STALE_EVIDENCE")
    if position.validation_status != "VALIDATED":
        _fail("STALE_EVIDENCE")
    if not _valid_observation(position.price, as_of_ns=snapshot.as_of_ns, positive=True):
        _fail("STALE_EVIDENCE")
    if not _valid_observation(position.fx_to_account, as_of_ns=snapshot.as_of_ns, positive=True):
        _fail("STALE_EVIDENCE")
    if not _valid_observation(position.loss_per_unit, as_of_ns=snapshot.as_of_ns, positive=True):
        _fail("STOP_MISSING")
    return position


def _heat(position: PositionV1) -> Fraction:
    # Keep the RISK-004 product exact without applying NUM-001 bounds to an
    # intermediate. Final group/total outputs are checked once they are known.
    return (
        abs(Fraction(position.quantity))
        * Fraction(position.loss_per_unit.value)
        * Fraction(position.contract_multiplier)
        * Fraction(position.fx_to_account.value)
    )


def _bounded_fraction_decimal(value: Fraction) -> Decimal:
    """Convert an exact finite decimal rational, enforcing NUM-001 at output."""
    if value == 0:
        return _ZERO
    denominator = value.denominator
    twos = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    fives = 0
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        _fail("ARITHMETIC_BOUND")
    scale = max(twos, fives)
    coefficient = abs(value.numerator) * (2 ** (scale - twos)) * (5 ** (scale - fives))
    digits = tuple(int(digit) for digit in str(coefficient))
    decimal_value = Decimal((1 if value.numerator < 0 else 0, digits, -scale))
    try:
        return parse_decimal(decimal_value, field="value")
    except NumericError:
        _fail("ARITHMETIC_BOUND")


def _digest(
    snapshot: PortfolioAggregationSnapshotV1,
    account_view: AccountViewV1,
    rows: tuple[PortfolioAggregationPositionV1, ...],
    groups: tuple[PortfolioHeatGroupV1, ...],
    total_heat: Decimal,
) -> str:
    equity = account_view.equity
    assert equity is not None
    payload = {
        "formula_version": _FORMULA_VERSION,
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_version": snapshot.snapshot_version,
        "as_of_ns": snapshot.as_of_ns,
        "account_id": account_view.account_id,
        "broker_revision": account_view.broker_revision,
        "account_positions": [
            [instrument, _decimal_text(quantity)] for instrument, quantity in account_view.positions
        ],
        "equity": {
            "currency": equity.currency,
            "amount": _decimal_text(equity.amount),
            "kind": equity.kind.value,
            "broker_observed_at_ns": equity.broker_observed_at_ns,
            "semantics_declared_by": equity.semantics_declared_by,
        },
        "positions": [_position_payload(row) for row in rows],
        "groups": [
            [group.portfolio_id, group.strategy_id, _decimal_text(group.heat)] for group in groups
        ],
        "total_heat": _decimal_text(total_heat),
    }
    try:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()
    except (UnicodeEncodeError, TypeError, ValueError):
        _fail("INPUT_INVALID")


def aggregate_portfolio_heat(
    snapshot: PortfolioAggregationSnapshotV1,
) -> PortfolioAggregationResultV1:
    """Aggregate exact, per-position stop heat from a single account snapshot.

    All evidence must be VALIDATED, as-of coherent with the enclosing
    snapshot, and within RISK-004's existing 300-second freshness bound. No
    additional freshness or risk limit is introduced here.
    """
    snapshot, account_view = _validate_snapshot(snapshot)
    assert account_view.equity is not None
    equity_currency = account_view.equity.currency

    seen: set[str] = set()
    row_heat: list[PortfolioAggregationPositionV1] = []
    by_instrument: dict[str, Fraction] = {}
    by_group: dict[tuple[str, str], Fraction] = {}
    try:
        for row in snapshot.positions:
            if row.position_id in seen:
                _fail("DUPLICATE_POSITION")
            seen.add(row.position_id)
            position = _validate_row(row, snapshot=snapshot, equity_currency=equity_currency)
            heat = _heat(position)
            row_heat.append(row)
            by_instrument[position.instrument] = (
                by_instrument.get(position.instrument, Fraction(0)) + Fraction(position.quantity)
            )
            group = (row.portfolio_id, row.strategy_id)
            by_group[group] = by_group.get(group, Fraction(0)) + heat
        expected_positions = {
            instrument: quantity
            for instrument, quantity in account_view.positions
            if quantity != _ZERO
        }
        by_instrument = {
            instrument: quantity
            for instrument, quantity in by_instrument.items()
            if quantity != 0
        }
        total_heat_fraction = sum(by_group.values(), Fraction(0))
        total_heat = _bounded_fraction_decimal(total_heat_fraction)
        groups = tuple(
            PortfolioHeatGroupV1(
                portfolio_id,
                strategy_id,
                _bounded_fraction_decimal(by_group[(portfolio_id, strategy_id)]),
            )
            for portfolio_id, strategy_id in sorted(by_group)
        )
        if by_instrument != {
            instrument: Fraction(quantity) for instrument, quantity in expected_positions.items()
        }:
            _fail("POSITION_ACCOUNT_MISMATCH")
        ordered_rows = tuple(sorted(row_heat, key=lambda row: row.position_id))
        digest = _digest(snapshot, account_view, ordered_rows, groups, total_heat)
    except PortfolioAggregationError:
        raise
    except NumericError:
        _fail("ARITHMETIC_BOUND")
    except (ArithmeticError, AttributeError, TypeError, ValueError):
        _fail("INPUT_INVALID")

    return PortfolioAggregationResultV1(
        snapshot_id=snapshot.snapshot_id,
        snapshot_version=snapshot.snapshot_version,
        account_id=account_view.account_id,
        equity_currency=equity_currency,
        equity_amount=account_view.equity.amount,
        total_heat=total_heat,
        groups=groups,
        digest=digest,
    )
