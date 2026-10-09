"""AccountViewV1 v1.3 evidence reconciliation regressions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BalanceV1,
    BrokerEnvironment,
    BrokerVenue,
    VenueIdentityV1,
    _issue_account_view,
    _issue_balance,
    _issue_venue_identity,
)
from leviathan_core.execution.reconciliation import (
    LocalLedgerEvidenceV1,
    ReconcileStatus,
    VerificationStatus,
    build_broker_snapshot,
    reconcile_account,
)

_NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
_MAX_AGE_NS = 300_000_000_000


def _to_ns(value: datetime) -> int:
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def _venue(environment: BrokerEnvironment) -> VenueIdentityV1:
    return _issue_venue_identity(BrokerVenue.ALPACA, environment, "account-v13")


def _view(
    *,
    balances: tuple[BalanceV1, ...] | None = (_issue_balance("USD", Decimal("125.50")),),
    broker_observed_at: datetime | None = _NOW,
    session_id: str | None = "session-7",
    account_id: str = "account-v13",
) -> AccountViewV1:
    return _issue_account_view(
        account_id,
        (),
        (),
        7,
        (),
        _NOW,
        complete=True,
        balances=balances,
        broker_observed_at=broker_observed_at,
        session_id=session_id,
    )


def _ledger(
    *,
    environment: BrokerEnvironment,
    balances: tuple[tuple[str, Decimal], ...] | None = (("USD", Decimal("125.50")),),
    previous_session_id: str | None = "session-7",
    previous_session_verified: bool = False,
    complete: bool = True,
    venue: BrokerVenue = BrokerVenue.ALPACA,
) -> LocalLedgerEvidenceV1:
    return LocalLedgerEvidenceV1(
        environment=environment,
        account_id="account-v13",
        orders=(),
        executions=(),
        positions=(),
        ledger_revision=7,
        venue=venue,
        complete=complete,
        balances=balances,
        previous_session_id=previous_session_id,
        previous_session_verified=previous_session_verified,
    )


def _reconcile(
    *,
    environment: BrokerEnvironment = BrokerEnvironment.LIVE,
    view: AccountViewV1 | None = None,
    ledger: LocalLedgerEvidenceV1 | None = None,
    now: datetime = _NOW,
):
    venue = _venue(environment)
    snapshot = build_broker_snapshot(view or _view(), venue, observed_at_ns=_to_ns(now))
    return reconcile_account(
        snapshot,
        ledger or _ledger(environment=environment),
        venue,
        now_ns=_to_ns(now),
        max_age_ns=_MAX_AGE_NS,
    )


def test_exact_complete_balances_with_fresh_time_and_stable_session_verify_live() -> None:
    result = _reconcile()

    assert result.balances_status is VerificationStatus.VERIFIED
    assert result.session_status is VerificationStatus.UNVERIFIED
    assert result.account_status is ReconcileStatus.MATCHED
    assert result.submission_blocked
    assert result.broker_observed_at == _NOW
    assert result.session_id == "session-7"


def test_trusted_previous_session_verifies_both_live_statuses_and_unblocks() -> None:
    result = _reconcile(
        ledger=_ledger(
            environment=BrokerEnvironment.LIVE,
            previous_session_id="session-7",
            previous_session_verified=True,
        )
    )

    assert result.balances_status is VerificationStatus.VERIFIED
    assert result.session_status is VerificationStatus.VERIFIED
    assert not result.submission_blocked


def test_balance_mismatch_never_verifies_and_blocks_live() -> None:
    result = _reconcile(
        ledger=_ledger(
            environment=BrokerEnvironment.LIVE,
            balances=(("USD", Decimal("125.51")),),
        )
    )

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert "BALANCE_MISMATCH" in result.divergence_codes
    assert result.submission_blocked


def test_absent_or_incomplete_balances_never_verify_and_block_live() -> None:
    absent = _reconcile(
        view=_view(balances=None),
        ledger=_ledger(environment=BrokerEnvironment.LIVE, balances=None),
    )
    incomplete = _reconcile(ledger=_ledger(environment=BrokerEnvironment.LIVE, complete=False))

    assert absent.balances_status is VerificationStatus.UNVERIFIED
    assert incomplete.balances_status is VerificationStatus.UNVERIFIED
    assert absent.submission_blocked
    assert incomplete.submission_blocked


def test_changed_or_unanchored_session_never_verifies_live() -> None:
    changed = _reconcile(view=_view(session_id="session-8"))
    unanchored = _reconcile(
        ledger=_ledger(environment=BrokerEnvironment.LIVE, previous_session_id=None)
    )

    assert changed.balances_status is VerificationStatus.UNVERIFIED
    assert "SESSION_CHANGED" in changed.divergence_codes
    assert changed.submission_blocked
    assert unanchored.balances_status is VerificationStatus.UNVERIFIED
    assert "SESSION_UNVERIFIED" in unanchored.divergence_codes
    assert unanchored.submission_blocked


def test_stale_provider_time_is_reported_and_never_verifies_live() -> None:
    result = _reconcile(view=_view(broker_observed_at=_NOW - timedelta(minutes=6)))

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert "STALE" in result.divergence_codes
    assert result.submission_blocked


def test_exact_balances_from_another_snapshot_account_never_verify_live() -> None:
    result = _reconcile(view=_view(account_id="other-account"))

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert "ACCOUNT_SCOPE_MISMATCH" in result.divergence_codes
    assert result.submission_blocked


def test_exact_balances_with_wrong_ledger_venue_never_verify_live() -> None:
    result = _reconcile(
        ledger=_ledger(environment=BrokerEnvironment.LIVE, venue=BrokerVenue.IBKR_TWS)
    )

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert "LOCAL_VENUE_MISMATCH" in result.divergence_codes
    assert result.submission_blocked


def test_account_view_v13_evidence_does_not_block_paper_or_demo() -> None:
    for environment in (BrokerEnvironment.PAPER, BrokerEnvironment.DEMO):
        mismatch = _reconcile(
            environment=environment,
            ledger=_ledger(
                environment=environment,
                balances=(("USD", Decimal("999")),),
            ),
        )
        stale = _reconcile(
            environment=environment,
            view=_view(broker_observed_at=_NOW - timedelta(minutes=6)),
        )

        assert mismatch.balances_status is VerificationStatus.UNVERIFIED
        assert not mismatch.submission_blocked
        assert stale.balances_status is VerificationStatus.UNVERIFIED
        assert "STALE" in stale.divergence_codes
        assert not stale.submission_blocked
