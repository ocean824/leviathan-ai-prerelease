"""Independent acceptance coverage for AccountViewV1 v1.3 reconciliation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

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
    ReconcileResultV1,
    ReconcileStatus,
    VerificationStatus,
    build_broker_snapshot,
    reconcile_account,
)

_NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
_MAX_AGE_NS = 300_000_000_000
_BALANCES = (("USD", Decimal("125.50")),)


def _to_ns(value: datetime) -> int:
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def _venue(environment: BrokerEnvironment) -> VenueIdentityV1:
    return _issue_venue_identity(BrokerVenue.ALPACA, environment, "acceptance-account")


def _view(
    *,
    account_id: str = "acceptance-account",
    balances: tuple[BalanceV1, ...] | None = (_issue_balance("USD", Decimal("125.50")),),
    observed_at: datetime | None = _NOW,
    session_id: str | None = "session-7",
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
        broker_observed_at=observed_at,
        session_id=session_id,
    )


def _ledger(
    environment: BrokerEnvironment,
    *,
    venue: BrokerVenue = BrokerVenue.ALPACA,
    balances: tuple[tuple[str, Decimal], ...] | None = _BALANCES,
    previous_session_id: str | None = "session-7",
    previous_session_verified: bool = False,
    complete: bool = True,
) -> LocalLedgerEvidenceV1:
    return LocalLedgerEvidenceV1(
        environment=environment,
        account_id="acceptance-account",
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
    environment: BrokerEnvironment,
    *,
    view: AccountViewV1 | None = None,
    ledger: LocalLedgerEvidenceV1 | None = None,
) -> ReconcileResultV1:
    expected_venue = _venue(environment)
    snapshot = build_broker_snapshot(
        view if view is not None else _view(), expected_venue, observed_at_ns=_to_ns(_NOW)
    )
    return reconcile_account(
        snapshot,
        ledger if ledger is not None else _ledger(environment),
        expected_venue,
        now_ns=_to_ns(_NOW),
        max_age_ns=_MAX_AGE_NS,
    )


def test_exact_balance_evidence_verifies_only_with_fresh_time_and_stable_session() -> None:
    result = _reconcile(BrokerEnvironment.LIVE)

    assert result.balances_status is VerificationStatus.VERIFIED
    assert result.broker_observed_at == _NOW
    assert result.session_id == "session-7"
    assert result.divergence_codes == ()
    assert result.account_status is ReconcileStatus.MATCHED
    assert result.submission_blocked is True


def test_exact_balance_and_verified_session_evidence_unblocks_live() -> None:
    result = _reconcile(
        BrokerEnvironment.LIVE,
        ledger=_ledger(
            BrokerEnvironment.LIVE,
            previous_session_id="session-7",
            previous_session_verified=True,
        ),
    )

    assert result.balances_status is VerificationStatus.VERIFIED
    assert result.session_status is VerificationStatus.VERIFIED
    assert result.divergence_codes == ()
    assert result.submission_blocked is False


def test_fresh_exact_balance_from_another_account_is_not_verified_live() -> None:
    result = _reconcile(
        BrokerEnvironment.LIVE,
        view=_view(account_id="different-account"),
    )

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert "ACCOUNT_SCOPE_MISMATCH" in result.divergence_codes
    assert result.submission_blocked is True


def test_exact_balances_with_wrong_local_ledger_venue_are_not_verified_live() -> None:
    result = _reconcile(
        BrokerEnvironment.LIVE,
        ledger=_ledger(BrokerEnvironment.LIVE, venue=BrokerVenue.IBKR_TWS),
    )

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert "LOCAL_VENUE_MISMATCH" in result.divergence_codes
    assert result.submission_blocked is True


@pytest.mark.parametrize(
    ("case", "expected_code"),
    [
        ("both-absent", "BALANCES_UNVERIFIED"),
        ("local-absent", "BALANCES_UNVERIFIED"),
        ("incomplete-ledger", "LOCAL_LEDGER_INCOMPLETE"),
        ("different-currency", "BALANCE_MISMATCH"),
        ("different-amount", "BALANCE_MISMATCH"),
    ],
)
def test_absent_partial_or_mismatched_balances_never_verify_live(
    case: str,
    expected_code: str,
) -> None:
    view = _view()
    ledger_kwargs: dict[str, object] = {}
    if case == "both-absent":
        view = _view(balances=None)
        ledger_kwargs["balances"] = None
    elif case == "local-absent":
        ledger_kwargs["balances"] = None
    elif case == "incomplete-ledger":
        ledger_kwargs["complete"] = False
    elif case == "different-currency":
        ledger_kwargs["balances"] = (("EUR", Decimal("125.50")),)
    elif case == "different-amount":
        ledger_kwargs["balances"] = (("USD", Decimal("125.51")),)
    result = _reconcile(
        BrokerEnvironment.LIVE,
        view=view,
        ledger=_ledger(BrokerEnvironment.LIVE, **ledger_kwargs),  # type: ignore[arg-type]
    )

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert result.submission_blocked is True
    assert expected_code in result.divergence_codes


@pytest.mark.parametrize(
    ("view_session", "ledger_session", "expected_code"),
    [
        ("session-8", "session-7", "SESSION_CHANGED"),
        (None, "session-7", "SESSION_UNVERIFIED"),
        ("session-7", None, "SESSION_UNVERIFIED"),
    ],
)
def test_missing_or_changed_session_never_verifies_live(
    view_session: str | None,
    ledger_session: str | None,
    expected_code: str,
) -> None:
    result = _reconcile(
        BrokerEnvironment.LIVE,
        view=_view(session_id=view_session),
        ledger=_ledger(BrokerEnvironment.LIVE, previous_session_id=ledger_session),
    )

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert expected_code in result.divergence_codes
    assert result.submission_blocked is True


def test_stale_provider_timestamp_is_reported_and_blocks_live() -> None:
    result = _reconcile(
        BrokerEnvironment.LIVE,
        view=_view(observed_at=_NOW - timedelta(minutes=6)),
    )

    assert result.broker_observed_at == _NOW - timedelta(minutes=6)
    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert "STALE" in result.divergence_codes
    assert result.submission_blocked is True


@pytest.mark.parametrize("environment", [BrokerEnvironment.PAPER, BrokerEnvironment.DEMO])
@pytest.mark.parametrize(
    "case,expected_codes",
    [
        ("absent", set()),
        ("mismatch", set()),
        ("session", {"SESSION_CHANGED"}),
        ("stale", {"STALE"}),
    ],
)
def test_paper_and_demo_evidence_warnings_do_not_block_submission(
    environment: BrokerEnvironment,
    case: str,
    expected_codes: set[str],
) -> None:
    view = _view()
    ledger_kwargs: dict[str, object] = {}
    if case == "absent":
        view = _view(balances=None)
        ledger_kwargs["balances"] = None
    elif case == "mismatch":
        ledger_kwargs["balances"] = (("USD", Decimal("0")),)
    elif case == "session":
        view = _view(session_id="new-session")
    elif case == "stale":
        view = _view(observed_at=_NOW - timedelta(minutes=6))
    result = _reconcile(
        environment,
        view=view,
        ledger=_ledger(environment, **ledger_kwargs),  # type: ignore[arg-type]
    )

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert expected_codes.issubset(result.divergence_codes)
    assert result.submission_blocked is False


def test_paper_evidence_that_is_exact_remains_nonblocking_and_verified() -> None:
    result = _reconcile(BrokerEnvironment.PAPER)

    assert result.balances_status is VerificationStatus.VERIFIED
    assert result.submission_blocked is False
