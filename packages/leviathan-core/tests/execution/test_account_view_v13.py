from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BalanceV1,
    BrokerOutcomeUnknown,
    BrokerPortError,
    BrokerUnknownCode,
    _issue_account_view,
    _issue_balance,
)

_SINCE = datetime(2026, 10, 1, tzinfo=UTC)


def _view(**kwargs: object) -> AccountViewV1:
    return _issue_account_view("synthetic-account", (), (), 1, (), _SINCE, complete=True, **kwargs)


def test_v12_call_shape_remains_valid_and_optional_evidence_stays_absent() -> None:
    view = _issue_account_view("synthetic-account", (), (), 1, (), _SINCE, complete=True)

    assert view.balances is None
    assert view.broker_observed_at is None
    assert view.session_id is None
    view.assert_sealed()


def test_balance_record_is_exact_bounded_and_sealed() -> None:
    balance = _issue_balance("USD", Decimal("1234.5600"))
    balance.assert_sealed()
    assert balance.currency == "USD"
    assert balance.amount == Decimal("1234.56")

    for currency, amount in (
        ("usd", Decimal("1")),
        ("US", Decimal("1")),
        ("US1", Decimal("1")),
        ("USD", 1),
        ("USD", True),
        ("USD", 1.0),
        ("USD", Decimal("NaN")),
        ("USD", Decimal("Infinity")),
        ("USD", Decimal("1E+100000")),
        ("USD", Decimal("1" * 35)),
    ):
        with pytest.raises(BrokerPortError) as error:
            _issue_balance(currency, amount)
        assert error.value.code == "INVALID_ACCOUNT_BALANCE"


def test_balance_tuple_requires_issued_sorted_unique_records() -> None:
    usd = _issue_balance("USD", Decimal("100"))
    eur = _issue_balance("EUR", Decimal("90"))
    view = _view(balances=(eur, usd))
    assert view.balances == (eur, usd)
    view.assert_sealed()

    for balances in (
        [eur, usd],
        (usd, eur),
        (usd, usd),
        (object(),),
    ):
        with pytest.raises(BrokerPortError) as error:
            _view(balances=balances)
        assert error.value.code == "INVALID_ACCOUNT_VIEW"


def test_broker_time_is_utc_normalized_and_kept_distinct_from_local_window() -> None:
    supplied = datetime(2026, 10, 2, 3, 30, tzinfo=timezone(timedelta(hours=3)))
    view = _view(broker_observed_at=supplied)

    assert view.broker_observed_at == datetime(2026, 10, 2, 0, 30, tzinfo=UTC)
    assert view.broker_observed_at is not view.executions_since
    view.assert_sealed()

    for invalid in (datetime(2026, 10, 2), "2026-10-02T00:00:00Z"):
        with pytest.raises(BrokerPortError) as error:
            _view(broker_observed_at=invalid)
        assert error.value.code == "INVALID_BROKER_OBSERVED_AT"


def test_session_identifier_is_optional_opaque_and_validated() -> None:
    view = _view(session_id="paper-session:opaque-1")
    assert view.session_id == "paper-session:opaque-1"
    view.assert_sealed()

    for invalid in ("", "bad value", "é-session", "x" * 129, 1):
        with pytest.raises(BrokerPortError) as error:
            _view(session_id=invalid)
        assert error.value.code == "INVALID_BROKER_SESSION_ID"


def test_new_fields_participate_in_seal_and_unavailable_complete_view_stays_unknown() -> None:
    balance = _issue_balance("USD", Decimal("100"))
    view = _view(
        balances=(balance,),
        broker_observed_at=datetime(2026, 10, 2, tzinfo=UTC),
        session_id="paper-session-1",
    )
    object.__setattr__(balance, "amount", Decimal("0"))
    with pytest.raises(BrokerPortError) as error:
        view.assert_sealed()
    assert error.value.code == "BROKER_RECORD_TAMPERED"

    with pytest.raises(BrokerOutcomeUnknown) as unknown:
        _issue_account_view("synthetic-account", (), (), 1, (), _SINCE, complete=False)
    assert unknown.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value


def test_old_direct_constructor_stays_unissued_and_cannot_fabricate_evidence() -> None:
    with pytest.raises(BrokerPortError) as error:
        AccountViewV1("synthetic-account", (), (), 1, (), _SINCE)
    assert error.value.code == "UNISSUED_BROKER_RECORD"

    with pytest.raises(BrokerPortError) as balance_error:
        BalanceV1("USD", Decimal("1"))
    assert balance_error.value.code == "UNISSUED_BROKER_RECORD"
