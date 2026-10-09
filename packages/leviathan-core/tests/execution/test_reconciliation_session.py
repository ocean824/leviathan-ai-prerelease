"""Session identity verification requires a trusted, scoped anchor."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from session_anchor_support import issue_verified_session_start_anchor

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerVenue,
    VenueIdentityV1,
    _issue_account_view,
    _issue_balance,
    _issue_venue_identity,
)
from leviathan_core.execution.reconciliation import (
    LocalLedgerEvidenceV1,
    ReconcileError,
    ReconcileResultV1,
    VerificationStatus,
    VerifiedSessionStartAnchorV1,
    build_broker_snapshot,
    reconcile_account,
    reconcile_once,
)
from leviathan_core.seal import SealError

_NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
_MAX_AGE_NS = 300_000_000_000
_ACCOUNT = "session-account"
_SESSION = "session-current"


def _to_ns(value: datetime) -> int:
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def _venue(environment: BrokerEnvironment = BrokerEnvironment.LIVE) -> VenueIdentityV1:
    return _issue_venue_identity(BrokerVenue.ALPACA, environment, _ACCOUNT)


def _view(
    *,
    session_id: str | None = _SESSION,
    account_id: str = _ACCOUNT,
    observed_at: datetime = _NOW,
) -> AccountViewV1:
    return _issue_account_view(
        account_id,
        (),
        (),
        7,
        (),
        _NOW,
        complete=True,
        balances=(_issue_balance("USD", Decimal("125.50")),),
        broker_observed_at=observed_at,
        session_id=session_id,
    )


def _ledger(
    *,
    previous_session_id: str | None = None,
    previous_session_verified: bool = False,
    environment: BrokerEnvironment = BrokerEnvironment.LIVE,
    venue: BrokerVenue = BrokerVenue.ALPACA,
) -> LocalLedgerEvidenceV1:
    return LocalLedgerEvidenceV1(
        environment=environment,
        account_id=_ACCOUNT,
        orders=(),
        executions=(),
        positions=(),
        ledger_revision=7,
        venue=venue,
        balances=(("USD", Decimal("125.50")),),
        previous_session_id=previous_session_id,
        previous_session_verified=previous_session_verified,
    )


def _reconcile(
    *,
    view: AccountViewV1 | None = None,
    ledger: LocalLedgerEvidenceV1 | None = None,
    anchor: VerifiedSessionStartAnchorV1 | None = None,
    expected_venue: VenueIdentityV1 | None = None,
    now: datetime = _NOW,
):
    expected = expected_venue or _venue()
    snapshot = build_broker_snapshot(view or _view(), expected, observed_at_ns=_to_ns(now))
    return reconcile_account(
        snapshot,
        ledger or _ledger(environment=expected.environment),
        expected,
        now_ns=_to_ns(now),
        max_age_ns=_MAX_AGE_NS,
        session_start_anchor=anchor,
    )


def test_prior_session_requires_explicit_ledger_verification_marker() -> None:
    untrusted = _reconcile(
        ledger=_ledger(previous_session_id=_SESSION, previous_session_verified=False)
    )
    trusted = _reconcile(
        ledger=_ledger(previous_session_id=_SESSION, previous_session_verified=True)
    )

    assert untrusted.session_status is VerificationStatus.UNVERIFIED
    assert untrusted.submission_blocked
    assert trusted.balances_status is VerificationStatus.VERIFIED
    assert trusted.session_status is VerificationStatus.VERIFIED
    assert not trusted.submission_blocked
    assert "SESSION_UNVERIFIED" not in trusted.divergence_codes


def test_first_observation_can_verify_only_with_matching_sealed_start_anchor() -> None:
    anchor = issue_verified_session_start_anchor(
        BrokerEnvironment.LIVE, _ACCOUNT, BrokerVenue.ALPACA, _SESSION
    )
    result = _reconcile(anchor=anchor)

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert result.session_status is VerificationStatus.VERIFIED
    assert result.submission_blocked
    assert "SESSION_UNVERIFIED" not in result.divergence_codes


@pytest.mark.parametrize("environment", [BrokerEnvironment.PAPER, BrokerEnvironment.DEMO])
def test_verified_session_anchor_keeps_paper_and_demo_nonblocking(
    environment: BrokerEnvironment,
) -> None:
    expected = _venue(environment)
    anchor = issue_verified_session_start_anchor(
        environment, _ACCOUNT, BrokerVenue.ALPACA, _SESSION
    )
    result = _reconcile(
        anchor=anchor,
        expected_venue=expected,
        ledger=_ledger(environment=environment),
    )

    assert result.session_status is VerificationStatus.VERIFIED
    assert not result.submission_blocked


@pytest.mark.parametrize(
    ("anchor_account", "anchor_venue", "anchor_environment"),
    [
        ("different-account", BrokerVenue.ALPACA, BrokerEnvironment.LIVE),
        (_ACCOUNT, BrokerVenue.IBKR_TWS, BrokerEnvironment.LIVE),
        (_ACCOUNT, BrokerVenue.ALPACA, BrokerEnvironment.DEMO),
    ],
)
def test_start_anchor_must_match_exact_snapshot_scope(
    anchor_account: str,
    anchor_venue: BrokerVenue,
    anchor_environment: BrokerEnvironment,
) -> None:
    anchor = issue_verified_session_start_anchor(
        anchor_environment, anchor_account, anchor_venue, _SESSION
    )
    result = _reconcile(anchor=anchor)

    assert result.session_status is VerificationStatus.UNVERIFIED
    assert "SESSION_UNVERIFIED" in result.divergence_codes


def test_absent_session_id_never_verifies_even_with_matching_start_anchor() -> None:
    anchor = issue_verified_session_start_anchor(
        BrokerEnvironment.LIVE, _ACCOUNT, BrokerVenue.ALPACA, _SESSION
    )
    result = _reconcile(view=_view(session_id=None), anchor=anchor)

    assert result.session_status is VerificationStatus.UNVERIFIED
    assert "SESSION_UNVERIFIED" in result.divergence_codes


def test_stale_provider_time_prevents_session_verification() -> None:
    anchor = issue_verified_session_start_anchor(
        BrokerEnvironment.LIVE, _ACCOUNT, BrokerVenue.ALPACA, _SESSION
    )
    result = _reconcile(view=_view(observed_at=_NOW - timedelta(minutes=6)), anchor=anchor)

    assert result.session_status is VerificationStatus.UNVERIFIED
    assert "STALE" in result.divergence_codes


def test_wrong_account_identity_prevents_session_verification() -> None:
    anchor = issue_verified_session_start_anchor(
        BrokerEnvironment.LIVE, _ACCOUNT, BrokerVenue.ALPACA, _SESSION
    )
    result = _reconcile(view=_view(account_id="other-account"), anchor=anchor)

    assert result.session_status is VerificationStatus.UNVERIFIED
    assert "ACCOUNT_SCOPE_MISMATCH" in result.divergence_codes


def test_wrong_ledger_venue_prevents_session_verification() -> None:
    anchor = issue_verified_session_start_anchor(
        BrokerEnvironment.LIVE, _ACCOUNT, BrokerVenue.ALPACA, _SESSION
    )
    result = _reconcile(ledger=_ledger(venue=BrokerVenue.IBKR_TWS), anchor=anchor)

    assert result.session_status is VerificationStatus.UNVERIFIED
    assert "LOCAL_VENUE_MISMATCH" in result.divergence_codes


def test_reconcile_once_forwards_injected_start_anchor() -> None:
    expected = _venue()
    anchor = issue_verified_session_start_anchor(
        BrokerEnvironment.LIVE, _ACCOUNT, BrokerVenue.ALPACA, _SESSION
    )

    class Broker:
        venue = expected

        def read_account_view(self, account_id: str) -> AccountViewV1:
            assert account_id == _ACCOUNT
            return _view()

    class Ledger:
        def __init__(self) -> None:
            self.appended: list[ReconcileResultV1] = []

        async def account_evidence(
            self, environment: BrokerEnvironment, account_id: str
        ) -> LocalLedgerEvidenceV1:
            assert environment is BrokerEnvironment.LIVE
            assert account_id == _ACCOUNT
            return _ledger()

        async def append_reconciliation(
            self, result: ReconcileResultV1, *, expected_ledger_revision: int
        ) -> None:
            assert expected_ledger_revision == 7
            self.appended.append(result)

    ledger = Ledger()
    result = asyncio.run(
        reconcile_once(
            Broker(),
            ledger,
            expected,
            observed_at_ns=_to_ns(_NOW),
            now_ns=_to_ns(_NOW),
            max_age_ns=_MAX_AGE_NS,
            session_start_anchor=anchor,
        )
    )

    assert result.session_status is VerificationStatus.VERIFIED
    assert ledger.appended == [result]


def test_unissued_start_anchor_is_rejected_by_seal() -> None:
    forged = VerifiedSessionStartAnchorV1(
        environment=BrokerEnvironment.LIVE,
        account_id=_ACCOUNT,
        venue=BrokerVenue.ALPACA,
        session_id=_SESSION,
        verified=True,
    )

    with pytest.raises(SealError):
        _reconcile(anchor=forged)


def test_tampered_start_anchor_is_rejected_by_seal() -> None:
    anchor = issue_verified_session_start_anchor(
        BrokerEnvironment.LIVE, _ACCOUNT, BrokerVenue.ALPACA, _SESSION
    )
    object.__setattr__(anchor, "account_id", "different-account")

    with pytest.raises(SealError):
        _reconcile(anchor=anchor)


@pytest.mark.parametrize(
    ("account_id", "session_id"),
    [("bad account", _SESSION), (_ACCOUNT, "bad session")],
)
def test_malformed_start_anchor_identifiers_have_typed_anchor_error(
    account_id: str, session_id: str
) -> None:
    anchor = issue_verified_session_start_anchor(
        BrokerEnvironment.LIVE, account_id, BrokerVenue.ALPACA, session_id
    )

    with pytest.raises(ReconcileError, match="INVALID_SESSION_START_ANCHOR"):
        _reconcile(anchor=anchor)


def test_verified_previous_session_requires_an_identifier() -> None:
    with pytest.raises(ReconcileError, match="INVALID_LEDGER_EVIDENCE"):
        _ledger(previous_session_verified=True)
