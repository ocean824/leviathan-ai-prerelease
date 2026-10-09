from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from itertools import permutations

import pytest

from leviathan_core.execution.broker_port_v1 import (
    EquityEvidenceKindV1,
    _issue_account_view,
    _issue_equity_evidence,
)
from leviathan_core.portfolio.models import ObservationV1, PositionV1
from leviathan_core.risk_limits.portfolio_aggregation import (
    PortfolioAggregationError,
    PortfolioAggregationPositionV1,
    PortfolioAggregationSnapshotV1,
    aggregate_portfolio_heat,
)

D = Decimal
AS_OF = 2_000_000_000_000
SNAPSHOT_ID = "snapshot-acceptance-001"
SNAPSHOT_VERSION = "snapshot-revision-17"


def _observation(
    value: str, *, event_ns: int = AS_OF, available_ns: int = AS_OF, source: str = "price-source"
) -> ObservationV1:
    return ObservationV1(
        D(value), event_ns, available_ns, source, "synthetic-v1", "VALIDATED"
    )


def _position(
    instrument: str,
    quantity: str,
    *,
    loss_per_unit: str = "1",
    multiplier: str = "1",
    fx: str = "1",
    instrument_currency: str = "USD",
    position_as_of: int = AS_OF,
    evidence_event: int | None = None,
) -> PositionV1:
    event_ns = position_as_of if evidence_event is None else evidence_event
    return PositionV1(
        instrument=instrument,
        instrument_currency=instrument_currency,
        quantity=D(quantity),
        price=_observation("100", event_ns=event_ns, source="mark"),
        fx_to_account=_observation(fx, event_ns=event_ns, source="fx"),
        loss_per_unit=_observation(loss_per_unit, event_ns=event_ns, source="stop"),
        contract_multiplier=D(multiplier),
        as_of_ns=position_as_of,
        available_ns=position_as_of,
        source_id="position-source",
        source_version="positions-v1",
        validation_status="VALIDATED",
    )


def _attribution(
    key: str,
    position: PositionV1,
    *,
    portfolio: str = "portfolio-a",
    strategy: str = "strategy-a",
    snapshot_id: str = SNAPSHOT_ID,
    snapshot_version: str = SNAPSHOT_VERSION,
    as_of_ns: int = AS_OF,
    equity_currency: str = "USD",
) -> PortfolioAggregationPositionV1:
    return PortfolioAggregationPositionV1(
        snapshot_id=snapshot_id,
        snapshot_version=snapshot_version,
        as_of_ns=as_of_ns,
        equity_currency=equity_currency,
        position_id=key,
        portfolio_id=portfolio,
        strategy_id=strategy,
        position=position,
    )


def _account(
    positions: tuple[tuple[str, Decimal], ...],
    *,
    equity_currency: str = "USD",
    equity_amount: str = "250000.00",
    observed_at_ns: int = AS_OF,
):
    equity = _issue_equity_evidence(
        equity_currency,
        D(equity_amount),
        EquityEvidenceKindV1.TOTAL_EQUITY,
        observed_at_ns,
        "synthetic-account-adapter",
    )
    return _issue_account_view(
        "synthetic-account-acceptance",
        (),
        positions,
        41,
        (),
        datetime(1970, 1, 1, tzinfo=UTC),
        complete=True,
        equity=equity,
    )


def _snapshot(
    rows: tuple[PortfolioAggregationPositionV1, ...],
    *,
    account=None,
    as_of_ns: int = AS_OF,
    snapshot_id: str = SNAPSHOT_ID,
    snapshot_version: str = SNAPSHOT_VERSION,
) -> PortfolioAggregationSnapshotV1:
    if account is None:
        quantities: dict[str, Decimal] = {}
        for row in rows:
            instrument = row.position.instrument
            quantities[instrument] = quantities.get(instrument, D("0")) + row.position.quantity
        account = _account(tuple(sorted((key, val) for key, val in quantities.items() if val)))
    return PortfolioAggregationSnapshotV1(
        snapshot_id, snapshot_version, as_of_ns, account, rows
    )


def _assert_code(code: str, snapshot: object) -> None:
    with pytest.raises(PortfolioAggregationError) as caught:
        aggregate_portfolio_heat(snapshot)  # type: ignore[arg-type]
    assert caught.value.code == code
    assert str(caught.value) == code


def test_heat_uses_exact_loss_to_stop_formula_and_sorted_groups() -> None:
    rows = (
        _attribution(
            "position-es",
            _position("SYNTH-ES", "1.5", loss_per_unit="0.123", multiplier="2", fx="1.1"),
            portfolio="fund-b",
            strategy="mean-reversion",
        ),
        _attribution(
            "position-eur",
            _position(
                "SYNTH-EUR", "-2", loss_per_unit="3", multiplier="1.25", fx="0.8",
                instrument_currency="EUR",
            ),
            portfolio="fund-a",
            strategy="carry",
        ),
    )
    account = _account((("SYNTH-ES", D("1.5")), ("SYNTH-EUR", D("-2"))))

    result = aggregate_portfolio_heat(_snapshot(rows, account=account))

    assert result.total_heat == D("6.4059")
    assert result.equity_amount == D("250000.00")
    assert [(group.portfolio_id, group.strategy_id, group.heat) for group in result.groups] == [
        ("fund-a", "carry", D("6")),
        ("fund-b", "mean-reversion", D("0.4059")),
    ]
    assert result.formula_version == "RISK-004-LOSS-TO-STOP-HEAT-v1"
    assert len(result.digest) == 64
    assert not hasattr(result, "authorize_route")


def test_digest_and_groups_are_independent_of_position_input_order() -> None:
    first = _attribution("position-1", _position("AAA", "2", loss_per_unit="0.25"))
    second = _attribution(
        "position-2",
        _position("BBB", "-3", loss_per_unit="0.125"),
        portfolio="portfolio-b",
        strategy="strategy-z",
    )
    account = _account((("AAA", D("2")), ("BBB", D("-3"))))
    forward = _snapshot((first, second), account=account)
    reversed_input = replace(forward, positions=(second, first))

    left = aggregate_portfolio_heat(forward)
    right = aggregate_portfolio_heat(reversed_input)

    assert left.digest == right.digest
    assert left.groups == right.groups
    assert left.total_heat == right.total_heat == D("0.875")


def test_reviewer_abc_fixture_is_invariant_across_every_permutation() -> None:
    rows = (
        _attribution("position-a", _position("SYNTH-X", "1e38", loss_per_unit="1e-38")),
        _attribution("position-b", _position("SYNTH-X", "1", loss_per_unit="1e4")),
        _attribution("position-c", _position("SYNTH-X", "-1e38", loss_per_unit="1e-38")),
    )
    account = _account((("SYNTH-X", Decimal("1")),))
    results = [
        aggregate_portfolio_heat(_snapshot(ordering, account=account))
        for ordering in permutations(rows)
    ]

    assert len(results) == 6
    assert all(result.total_heat == D("10002") for result in results)
    assert all(result.digest == results[0].digest for result in results)
    assert all(result.groups == results[0].groups for result in results)


def test_general_shuffled_inputs_preserve_result_and_digest() -> None:
    rows = (
        _attribution("position-a", _position("AAA", "2", loss_per_unit="0.25")),
        _attribution(
            "position-b", _position("BBB", "-3", loss_per_unit="0.125"),
            portfolio="portfolio-b", strategy="strategy-z",
        ),
        _attribution(
            "position-c", _position("CCC", "4", loss_per_unit="0.5", multiplier="2"),
            portfolio="portfolio-c", strategy="strategy-a",
        ),
        _attribution(
            "position-d", _position("AAA", "1", loss_per_unit="3"),
            portfolio="portfolio-b", strategy="strategy-z",
        ),
    )
    account = _account(
        (("AAA", Decimal("3")), ("BBB", Decimal("-3")), ("CCC", Decimal("4")))
    )
    results = [
        aggregate_portfolio_heat(_snapshot(ordering, account=account))
        for ordering in permutations(rows)
    ]

    assert len(results) == 24
    assert all(result.digest == results[0].digest for result in results)
    assert all(result.groups == results[0].groups for result in results)
    assert all(result.total_heat == Decimal("7.875") for result in results)


@pytest.mark.parametrize(
    "tampered_value",
    ("1.12345678901234567890123456789012345", "1e39"),
    ids=("excess-significant-digits", "out-of-range-exponent"),
)
def test_object_setattr_tampered_decimal_is_rejected_at_aggregation(
    tampered_value: str,
) -> None:
    position = _position("AAA", "1")
    assert position.loss_per_unit is not None
    object.__setattr__(position.loss_per_unit, "value", Decimal(tampered_value))
    row = _attribution("tampered-decimal", position)

    _assert_code("INPUT_INVALID", lambda: aggregate_portfolio_heat(_snapshot((row,))))


def test_mixed_snapshot_version_time_and_equity_currency_are_rejected() -> None:
    base = _attribution("position-1", _position("AAA", "1"))
    for altered in (
        replace(base, snapshot_id="other-snapshot"),
        replace(base, snapshot_version="other-version"),
        replace(base, as_of_ns=AS_OF - 1),
        replace(base, equity_currency="EUR"),
    ):
        expected = "CURRENCY_MISMATCH" if altered.equity_currency == "EUR" else "SNAPSHOT_MISMATCH"
        _assert_code(expected, _snapshot((altered,)))


def test_duplicate_identity_and_account_position_mismatch_are_rejected() -> None:
    first = _attribution("same-position-id", _position("AAA", "1"))
    duplicate = _attribution("same-position-id", _position("BBB", "1"))
    _assert_code("DUPLICATE_POSITION", _snapshot((first, duplicate)))

    mismatch = _snapshot((first,), account=_account((("AAA", D("2")),)))
    _assert_code("POSITION_ACCOUNT_MISMATCH", mismatch)


def test_opposing_positions_add_heat_and_cancel_only_in_account_quantity_crosscheck() -> None:
    long_row = _attribution("long", _position("SYNTH-X", "4", loss_per_unit="2"))
    short_row = _attribution(
        "short", _position("SYNTH-X", "-4", loss_per_unit="2"), portfolio="portfolio-b"
    )
    result = aggregate_portfolio_heat(_snapshot((long_row, short_row), account=_account(())))

    assert result.total_heat == D("16")
    assert [group.heat for group in result.groups] == [D("8"), D("8")]


def test_freshness_boundary_is_inclusive_and_older_evidence_is_rejected() -> None:
    boundary = AS_OF - 300_000_000_000
    position = _position("AAA", "1", position_as_of=boundary)
    valid_row = _attribution("position-1", position)
    valid = aggregate_portfolio_heat(
        _snapshot((valid_row,), account=_account((("AAA", D("1")),), observed_at_ns=AS_OF))
    )
    assert valid.total_heat == D("1")

    too_old = replace(position, as_of_ns=boundary - 1, available_ns=boundary - 1)
    _assert_code("STALE_EVIDENCE", _snapshot((_attribution("position-1", too_old),)))


def test_absent_equity_and_missing_stop_fail_without_partial_result() -> None:
    row = _attribution("position-1", _position("AAA", "1"))
    without_equity = _issue_account_view(
        "synthetic-account-acceptance",
        (),
        (("AAA", D("1")),),
        41,
        (),
        datetime(1970, 1, 1, tzinfo=UTC),
        complete=True,
    )
    _assert_code("EQUITY_MISSING", _snapshot((row,), account=without_equity))

    missing_stop = replace(_position("AAA", "1"), loss_per_unit=None)
    _assert_code("STOP_MISSING", _snapshot((_attribution("position-1", missing_stop),)))


def test_empty_portfolio_returns_zero_heat_and_arithmetic_overflow_is_closed() -> None:
    empty = aggregate_portfolio_heat(_snapshot((), account=_account(())))
    assert empty.total_heat == D("0")
    assert empty.groups == ()

    huge = _position(
        "AAA", "1e38", loss_per_unit="1e38", multiplier="1e38", fx="1e38"
    )
    _assert_code("ARITHMETIC_BOUND", _snapshot((_attribution("huge-position", huge),)))
