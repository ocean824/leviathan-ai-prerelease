from __future__ import annotations

import random
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from decimal import Decimal, localcontext
from itertools import permutations

import pytest

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    EquityEvidenceKindV1,
    EquityEvidenceV1,
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

_D = Decimal
_AS_OF = 1_000_000_000_000
_SNAPSHOT_ID = "snapshot-risk-1"
_SNAPSHOT_VERSION = "revision-7"


def _observation(
    value: str, *, event_ns: int = _AS_OF, available_ns: int = _AS_OF
) -> ObservationV1:
    return ObservationV1(
        value=_D(value),
        event_ns=event_ns,
        available_ns=available_ns,
        source_id="synthetic-source",
        source_version="synthetic-v1",
        validation_status="VALIDATED",
    )


def _position(
    instrument: str,
    quantity: str,
    *,
    loss: str = "2",
    multiplier: str = "1",
    fx: str = "1",
    currency: str = "USD",
    as_of_ns: int = _AS_OF,
    available_ns: int = _AS_OF,
    stop_status: str = "VALIDATED",
) -> PositionV1:
    return PositionV1(
        instrument=instrument,
        instrument_currency=currency,
        quantity=_D(quantity),
        price=_observation("10", event_ns=as_of_ns, available_ns=available_ns),
        fx_to_account=_observation(fx, event_ns=as_of_ns, available_ns=available_ns),
        loss_per_unit=ObservationV1(
            value=_D(loss),
            event_ns=as_of_ns,
            available_ns=available_ns,
            source_id="synthetic-stop",
            source_version="stop-v1",
            validation_status=stop_status,
        ),
        contract_multiplier=_D(multiplier),
        as_of_ns=as_of_ns,
        available_ns=available_ns,
        source_id="synthetic-position",
        source_version="positions-v1",
        validation_status="VALIDATED",
    )


def _row(
    position_id: str,
    position: PositionV1,
    *,
    portfolio_id: str = "portfolio-a",
    strategy_id: str = "strategy-a",
    snapshot_id: str = _SNAPSHOT_ID,
    snapshot_version: str = _SNAPSHOT_VERSION,
    as_of_ns: int = _AS_OF,
    equity_currency: str = "USD",
) -> PortfolioAggregationPositionV1:
    return PortfolioAggregationPositionV1(
        snapshot_id=snapshot_id,
        snapshot_version=snapshot_version,
        as_of_ns=as_of_ns,
        equity_currency=equity_currency,
        position_id=position_id,
        portfolio_id=portfolio_id,
        strategy_id=strategy_id,
        position=position,
    )


def _account_view(
    positions: tuple[tuple[str, Decimal], ...] = (("XYZ", _D("3")),),
    *,
    equity: EquityEvidenceV1 | None = None,
) -> AccountViewV1:
    if equity is None:
        equity = _issue_equity_evidence(
            "USD", _D("1000"), EquityEvidenceKindV1.TOTAL_EQUITY, _AS_OF, "synthetic-adapter"
        )
    return _issue_account_view(
        "synthetic-account",
        (),
        positions,
        7,
        (),
        datetime(1970, 1, 1, tzinfo=UTC),
        complete=True,
        equity=equity,
    )


def _snapshot(
    rows: tuple[PortfolioAggregationPositionV1, ...] | None = None,
    *,
    account_view: AccountViewV1 | None = None,
) -> PortfolioAggregationSnapshotV1:
    if rows is None:
        rows = (
            _row("position-1", _position("XYZ", "1", loss="2", multiplier="3", fx="1.1")),
            _row(
                "position-2",
                _position("XYZ", "2", loss="0.5", multiplier="2", fx="1"),
                portfolio_id="portfolio-b",
                strategy_id="strategy-b",
            ),
        )
    return PortfolioAggregationSnapshotV1(
        snapshot_id=_SNAPSHOT_ID,
        snapshot_version=_SNAPSHOT_VERSION,
        as_of_ns=_AS_OF,
        account_view=account_view or _account_view(),
        positions=rows,
    )


def _assert_code(code: str, fn: object) -> None:
    with pytest.raises(PortfolioAggregationError) as caught:
        fn()  # type: ignore[operator]
    assert caught.value.code == code
    assert str(caught.value) == code


def test_aggregates_risk_004_loss_to_stop_heat_exactly_by_portfolio_and_strategy() -> None:
    result = aggregate_portfolio_heat(_snapshot())

    # |1|*2*3*1.1 + |2|*0.5*2*1 = 6.6 + 2 = 8.6
    assert result.total_heat == _D("8.6")
    assert [(group.portfolio_id, group.strategy_id, group.heat) for group in result.groups] == [
        ("portfolio-a", "strategy-a", _D("6.6")),
        ("portfolio-b", "strategy-b", _D("2")),
    ]
    assert result.equity_currency == "USD"
    assert result.equity_amount == _D("1000")
    assert result.formula_version == "RISK-004-LOSS-TO-STOP-HEAT-v1"
    assert len(result.digest) == 64


def test_digest_is_independent_of_input_row_order() -> None:
    snapshot = _snapshot()
    reversed_snapshot = replace(snapshot, positions=tuple(reversed(snapshot.positions)))

    first = aggregate_portfolio_heat(snapshot)
    second = aggregate_portfolio_heat(reversed_snapshot)

    assert first.digest == second.digest
    assert first.groups == second.groups
    assert first.total_heat == second.total_heat


def test_reviewer_offsetting_position_fixture_is_order_independent() -> None:
    rows = (
        _row("position-a", _position("XYZ", "1e38", loss="1e-38")),
        _row("position-b", _position("XYZ", "1", loss="1e4")),
        _row("position-c", _position("XYZ", "-1e38", loss="1e-38")),
    )
    account = _account_view((("XYZ", _D("1")),))

    results = [
        aggregate_portfolio_heat(_snapshot(tuple(order), account_view=account))
        for order in permutations(rows)
    ]

    assert all(result.total_heat == _D("10002") for result in results)
    assert all(result == results[0] for result in results)
    assert all(result.digest == results[0].digest for result in results)


def test_randomized_position_shuffles_have_identical_result_and_digest() -> None:
    rows = (
        _row("position-a", _position("XYZ", "1e34", loss="1e-38")),
        _row("position-b", _position("XYZ", "-1e34", loss="1e-38")),
        _row("position-c", _position("XYZ", "7", loss="3.125")),
        _row("position-d", _position("XYZ", "-2", loss="0.875")),
    )
    account = _account_view((("XYZ", _D("5")),))
    expected = aggregate_portfolio_heat(_snapshot(rows, account_view=account))
    rng = random.Random(4107)

    for _ in range(40):
        shuffled = list(rows)
        rng.shuffle(shuffled)
        actual = aggregate_portfolio_heat(_snapshot(tuple(shuffled), account_view=account))
        assert actual == expected
        assert actual.digest == expected.digest


def test_rejects_num001_bypass_in_injected_price_observation() -> None:
    position = _position("XYZ", "3")
    object.__setattr__(position.price, "value", _D("1.12345678901234567890123456789012345"))
    row = _row("position-1", position)

    _assert_code("INPUT_INVALID", lambda: aggregate_portfolio_heat(_snapshot((row,))))


@pytest.mark.parametrize("field", ["quantity", "contract_multiplier", "stop", "fx"])
def test_revalidates_every_position_decimal_after_construction(field: str) -> None:
    position = _position("XYZ", "3")
    injected = _D("1.12345678901234567890123456789012345")
    if field in {"quantity", "contract_multiplier"}:
        object.__setattr__(position, field, injected)
    else:
        observation = position.loss_per_unit if field == "stop" else position.fx_to_account
        object.__setattr__(observation, "value", injected)
    row = _row("position-1", position)

    _assert_code("INPUT_INVALID", lambda: aggregate_portfolio_heat(_snapshot((row,))))


def test_revalidates_injected_equity_decimal_after_construction() -> None:
    account = _account_view()
    assert account.equity is not None
    object.__setattr__(account.equity, "amount", _D("1.12345678901234567890123456789012345"))
    row = _row("position-1", _position("XYZ", "3"))

    _assert_code(
        "INPUT_INVALID",
        lambda: aggregate_portfolio_heat(_snapshot((row,), account_view=account)),
    )


def test_calculation_ignores_ambient_decimal_context_and_stays_exact() -> None:
    row = _row("position-1", _position("XYZ", "1.5", loss="0.123", multiplier="2", fx="1.1"))
    account = _account_view((("XYZ", _D("1.5")),))
    snapshot = _snapshot((row,), account_view=account)

    with localcontext() as context:
        context.prec = 2
        result = aggregate_portfolio_heat(snapshot)

    assert result.total_heat == _D("0.4059")


def test_opposing_positions_add_loss_heat_instead_of_netting_it_away() -> None:
    long_position = _position("XYZ", "2", loss="5")
    short_position = _position("XYZ", "-2", loss="5")
    rows = (
        _row("long-position", long_position),
        _row("short-position", short_position, portfolio_id="portfolio-b"),
    )

    result = aggregate_portfolio_heat(_snapshot(rows, account_view=_account_view(())))

    assert result.total_heat == _D("20")


def test_risk_004_freshness_accepts_the_exact_age_boundary() -> None:
    boundary_event = _AS_OF - 300_000_000_000
    position = _position("XYZ", "3", as_of_ns=boundary_event, available_ns=boundary_event)

    result = aggregate_portfolio_heat(_snapshot((_row("position-1", position),)))

    assert result.total_heat == _D("6")


def test_rejects_mixed_snapshot_version_and_as_of_references() -> None:
    valid = _row("position-1", _position("XYZ", "3"))
    cases = (
        (replace(valid, snapshot_id="another-snapshot"), "SNAPSHOT_MISMATCH"),
        (replace(valid, snapshot_version="another-version"), "SNAPSHOT_MISMATCH"),
        (replace(valid, as_of_ns=_AS_OF - 1), "SNAPSHOT_MISMATCH"),
    )
    for row, code in cases:
        _assert_code(code, lambda row=row: aggregate_portfolio_heat(_snapshot((row,))))


def test_rejects_mixed_equity_currency_and_wrong_account_positions() -> None:
    usd_position = _row("position-1", _position("XYZ", "3"), equity_currency="EUR")
    _assert_code("CURRENCY_MISMATCH", lambda: aggregate_portfolio_heat(_snapshot((usd_position,))))

    wrong_account = _account_view((("XYZ", _D("2")),))
    valid_row = _row("position-1", _position("XYZ", "3"))
    _assert_code(
        "POSITION_ACCOUNT_MISMATCH",
        lambda: aggregate_portfolio_heat(_snapshot((valid_row,), account_view=wrong_account)),
    )


def test_rejects_duplicate_position_identity() -> None:
    row = _row("position-1", _position("XYZ", "3"))
    _assert_code(
        "DUPLICATE_POSITION",
        lambda: aggregate_portfolio_heat(_snapshot((row, row))),
    )


def test_missing_equity_or_stop_fails_closed() -> None:
    no_equity = _issue_account_view(
        "synthetic-account",
        (),
        (("XYZ", _D("3")),),
        7,
        (),
        datetime(1970, 1, 1, tzinfo=UTC),
        complete=True,
        equity=None,
    )
    row = _row("position-1", _position("XYZ", "3"))
    _assert_code(
        "EQUITY_MISSING",
        lambda: aggregate_portfolio_heat(_snapshot((row,), account_view=no_equity)),
    )

    unvalidated_stop = _row("position-1", _position("XYZ", "3", stop_status="UNVALIDATED"))
    _assert_code(
        "STOP_MISSING",
        lambda: aggregate_portfolio_heat(_snapshot((unvalidated_stop,))),
    )


def test_rejects_stale_and_future_evidence_using_risk_004_freshness() -> None:
    old_event = _AS_OF - 300_000_000_001
    stale_position = replace(
        _position("XYZ", "3"),
        price=_observation("10", event_ns=old_event, available_ns=old_event),
    )
    stale = _row("position-1", stale_position)
    _assert_code("STALE_EVIDENCE", lambda: aggregate_portfolio_heat(_snapshot((stale,))))

    future_observation = replace(
        _position("XYZ", "3"),
        price=_observation("10", event_ns=_AS_OF, available_ns=_AS_OF + 1),
    )
    future = _row("position-1", future_observation)
    _assert_code("STALE_EVIDENCE", lambda: aggregate_portfolio_heat(_snapshot((future,))))


def test_numeric_overflow_is_reported_as_a_content_free_bound_error() -> None:
    row = _row(
        "position-1",
        _position("XYZ", "1e38", loss="1e38", multiplier="1e38", fx="1"),
    )
    _assert_code("ARITHMETIC_BOUND", lambda: aggregate_portfolio_heat(_snapshot((row,))))


def test_zero_position_set_is_a_diagnostic_zero_not_authority() -> None:
    result = aggregate_portfolio_heat(_snapshot((), account_view=_account_view(())))

    assert result.total_heat == _D("0")
    assert result.groups == ()
    assert not hasattr(result, "authorize")
    with pytest.raises(FrozenInstanceError):
        result.total_heat = _D("1")  # type: ignore[misc]
