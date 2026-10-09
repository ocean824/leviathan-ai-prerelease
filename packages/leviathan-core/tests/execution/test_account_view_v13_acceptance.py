"""Independent contract acceptance for the additive AccountViewV1 v1.3 fields."""

from __future__ import annotations

import copy
import pickle
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BalanceV1,
    BrokerEnvironment,
    BrokerOutcomeUnknown,
    BrokerPortError,
    BrokerUnknownCode,
    BrokerVenue,
    _issue_account_view,
    _issue_balance,
    _issue_venue_identity,
)
from leviathan_core.execution.reconciliation import (
    LocalLedgerEvidenceV1,
    ObservationSource,
    ReconcileStatus,
    VerificationStatus,
    build_broker_snapshot,
    reconcile_account,
)
from leviathan_core.seal import SealError

ACCOUNT = "synthetic-account-001"
INSTRUMENT = "SYNTH-001"
NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
EXECUTIONS_SINCE = NOW - timedelta(minutes=5)
NOW_NS = 1_791_201_600_000_000_000
MAX_AGE_NS = 300_000_000_000


def _balance(currency: str = "USD", amount: Decimal = Decimal("100.25")) -> BalanceV1:
    return _issue_balance(currency, amount)


def _view(
    *,
    balances: tuple[BalanceV1, ...] | None = None,
    broker_observed_at: datetime | None = None,
    session_id: str | None = None,
) -> AccountViewV1:
    return _issue_account_view(
        ACCOUNT,
        (),
        (),
        7,
        (),
        EXECUTIONS_SINCE,
        complete=True,
        balances=balances,
        broker_observed_at=broker_observed_at,
        session_id=session_id,
    )


def _legacy_view() -> AccountViewV1:
    # The exact pre-v1.3 six-positional-argument call remains supported.
    return _issue_account_view(ACCOUNT, (), (), 7, (), EXECUTIONS_SINCE, complete=True)


def _reconcile(view: AccountViewV1, environment: BrokerEnvironment):
    venue = _issue_venue_identity(BrokerVenue.IBKR_TWS, environment, ACCOUNT)
    snapshot = build_broker_snapshot(view, venue, observed_at_ns=NOW_NS)
    ledger = LocalLedgerEvidenceV1(
        environment=environment,
        account_id=ACCOUNT,
        venue=BrokerVenue.IBKR_TWS,
        orders=(),
        executions=(),
        positions=(),
        ledger_revision=1,
        complete=True,
    )
    result = reconcile_account(
        snapshot,
        ledger,
        venue,
        now_ns=NOW_NS,
        max_age_ns=MAX_AGE_NS,
    )
    return snapshot, result


def _assert_code(action, code: str) -> None:
    with pytest.raises(BrokerPortError) as caught:
        action()
    assert caught.value.code == code
    assert str(caught.value) == code
    assert caught.value.args == (code,)


def test_v12_factory_call_shape_remains_source_compatible_and_defaults_are_absent() -> None:
    view = _legacy_view()

    assert type(view) is AccountViewV1
    assert view.account_id == ACCOUNT
    assert view.balances is None
    assert view.broker_observed_at is None
    assert view.session_id is None
    view.assert_sealed()


def test_incomplete_provider_response_stays_unknown_not_absent_or_zero() -> None:
    with pytest.raises(BrokerOutcomeUnknown) as caught:
        _issue_account_view(
            ACCOUNT,
            (),
            (),
            7,
            (),
            EXECUTIONS_SINCE,
            complete=False,
        )
    assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value
    assert str(caught.value) == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value


def test_balances_are_exact_per_currency_records_without_fx_or_aggregation() -> None:
    usd = _balance("USD", Decimal("100.2500"))
    eur = _balance("EUR", Decimal("-12.75"))
    view = _view(balances=(eur, usd))

    assert [(item.currency, item.amount) for item in view.balances or ()] == [
        ("EUR", Decimal("-12.75")),
        ("USD", Decimal("100.2500")),
    ]
    assert view.balances[0].amount == Decimal("-12.75")
    view.assert_sealed()
    usd.assert_sealed()


@pytest.mark.parametrize(
    ("currency", "amount"),
    [
        ("usd", Decimal("1")),
        ("US1", Decimal("1")),
        ("USD", 1.0),
        ("USD", True),
        ("USD", Decimal("NaN")),
        ("USD", Decimal("Infinity")),
        ("USD", Decimal("1e100")),
    ],
)
def test_invalid_balance_fields_reject_with_content_free_error(
    currency: str, amount: object
) -> None:
    _assert_code(lambda: _issue_balance(currency, amount), "INVALID_ACCOUNT_BALANCE")


def test_balance_tuple_must_be_immutable_sorted_unique_and_issued() -> None:
    usd = _balance("USD")
    eur = _balance("EUR")
    _assert_code(
        lambda: _issue_account_view(
            ACCOUNT, (), (), 7, (), EXECUTIONS_SINCE, complete=True, balances=[eur, usd]
        ),
        "INVALID_ACCOUNT_VIEW",
    )
    _assert_code(
        lambda: _view(balances=(usd, eur)),
        "INVALID_ACCOUNT_VIEW",
    )
    _assert_code(
        lambda: _view(balances=(usd, _balance("USD", Decimal("2")))),
        "INVALID_ACCOUNT_VIEW",
    )
    _assert_code(
        lambda: BalanceV1("EUR", Decimal("1")),
        "UNISSUED_BROKER_RECORD",
    )


def test_broker_observation_time_normalizes_to_utc_and_is_not_local_time() -> None:
    offset_time = datetime(2026, 10, 5, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    view = _view(
        balances=(_balance("USD"),),
        broker_observed_at=offset_time,
        session_id="synthetic-session-7",
    )
    assert view.broker_observed_at == NOW
    assert view.broker_observed_at is not None
    assert view.broker_observed_at.tzinfo is UTC

    snapshot, result = _reconcile(view, BrokerEnvironment.PAPER)
    assert snapshot.observed_at_ns == NOW_NS
    assert snapshot.observation_source is ObservationSource.LOCAL_OBSERVED_AT
    assert result.observed_at_ns == NOW_NS
    assert result.observation_source is ObservationSource.LOCAL_OBSERVED_AT
    assert view.broker_observed_at == NOW


def test_absent_provider_time_stays_absent_despite_local_observation_time() -> None:
    view = _legacy_view()
    snapshot, result = _reconcile(view, BrokerEnvironment.PAPER)

    assert view.broker_observed_at is None
    assert snapshot.observed_at_ns == NOW_NS
    assert snapshot.observation_source is ObservationSource.LOCAL_OBSERVED_AT
    assert result.observed_at_ns == NOW_NS
    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert result.session_status is VerificationStatus.UNVERIFIED


def test_invalid_optional_broker_time_and_session_are_rejected_without_echo() -> None:
    _assert_code(
        lambda: _view(broker_observed_at=datetime(2026, 10, 5, 12, 0)),
        "INVALID_BROKER_OBSERVED_AT",
    )
    _assert_code(
        lambda: _view(session_id="session-secret with spaces"),
        "INVALID_BROKER_SESSION_ID",
    )


def test_balance_and_view_seals_reject_forgery_mutation_copy_and_pickle() -> None:
    balance = _balance()
    view = _view(balances=(balance,))

    for record in (balance, view):
        with pytest.raises((BrokerPortError, SealError, TypeError)):
            copy.copy(record)
        with pytest.raises((BrokerPortError, SealError, TypeError)):
            copy.deepcopy(record)
        with pytest.raises((BrokerPortError, SealError, TypeError)):
            pickle.dumps(record)

    object.__setattr__(balance, "amount", Decimal("999"))
    with pytest.raises(BrokerPortError):
        balance.assert_sealed()
    with pytest.raises(BrokerPortError):
        view.assert_sealed()


@pytest.mark.parametrize("environment", [BrokerEnvironment.PAPER, BrokerEnvironment.DEMO])
def test_absent_v13_evidence_does_not_block_paper_or_demo_but_stays_unverified(
    environment: BrokerEnvironment,
) -> None:
    _, result = _reconcile(_legacy_view(), environment)

    assert result.account_status is ReconcileStatus.MATCHED
    assert result.submission_blocked is False
    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert result.session_status is VerificationStatus.UNVERIFIED


def test_absent_v13_evidence_never_grants_live_verification() -> None:
    _, result = _reconcile(_legacy_view(), BrokerEnvironment.LIVE)

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert result.session_status is VerificationStatus.UNVERIFIED
    assert result.submission_blocked is True
    assert {"BALANCES_UNVERIFIED", "SESSION_UNVERIFIED"}.issubset(set(result.divergence_codes))


def test_present_v13_fields_do_not_promote_current_reconciliation_consumer() -> None:
    view = _view(
        balances=(_balance("USD", Decimal("1000.00")),),
        broker_observed_at=NOW,
        session_id="synthetic-live-session",
    )
    snapshot, result = _reconcile(view, BrokerEnvironment.LIVE)

    assert snapshot.observation_source is ObservationSource.LOCAL_OBSERVED_AT
    assert result.observation_source is ObservationSource.LOCAL_OBSERVED_AT
    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert result.session_status is VerificationStatus.UNVERIFIED
    assert result.submission_blocked is True
