"""Independent acceptance tests for anchored broker-session verification."""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import cast

import pytest
from session_anchor_support import issue_verified_session_start_anchor

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerPortError,
    BrokerPortV1,
    BrokerVenue,
    VenueIdentityV1,
    _issue_account_view,
    _issue_balance,
    _issue_venue_identity,
)
from leviathan_core.execution.reconciliation import (
    LocalLedgerEvidenceV1,
    ReconcileError,
    ReconcilePortV1,
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
_ACCOUNT = "session-acceptance-account"
_SESSION = "broker-session-current"
_BALANCES = (("USD", Decimal("125.50")),)


def _to_ns(value: datetime) -> int:
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def _venue(
    environment: BrokerEnvironment = BrokerEnvironment.LIVE,
    venue: BrokerVenue = BrokerVenue.ALPACA,
    account_id: str = _ACCOUNT,
) -> VenueIdentityV1:
    return _issue_venue_identity(venue, environment, account_id)


def _view(
    *,
    session_id: str | None = _SESSION,
    account_id: str = _ACCOUNT,
    observed_at: datetime | None = _NOW,
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
    account_id: str = _ACCOUNT,
) -> LocalLedgerEvidenceV1:
    return LocalLedgerEvidenceV1(
        environment=environment,
        account_id=account_id,
        orders=(),
        executions=(),
        positions=(),
        ledger_revision=7,
        venue=venue,
        balances=_BALANCES,
        previous_session_id=previous_session_id,
        previous_session_verified=previous_session_verified,
    )


def _anchor(
    *,
    environment: BrokerEnvironment = BrokerEnvironment.LIVE,
    account_id: str = _ACCOUNT,
    venue: BrokerVenue = BrokerVenue.ALPACA,
    session_id: str = _SESSION,
) -> VerifiedSessionStartAnchorV1:
    return issue_verified_session_start_anchor(environment, account_id, venue, session_id)


def _reconcile(
    *,
    view: AccountViewV1 | None = None,
    ledger: LocalLedgerEvidenceV1 | None = None,
    anchor: VerifiedSessionStartAnchorV1 | None = None,
    expected_venue: VenueIdentityV1 | None = None,
    now: datetime = _NOW,
) -> ReconcileResultV1:
    expected = expected_venue or _venue()
    broker_view = view or _view()
    snapshot = build_broker_snapshot(broker_view, expected, observed_at_ns=_to_ns(now))
    return reconcile_account(
        snapshot,
        ledger or _ledger(environment=expected.environment, account_id=expected.account_id),
        expected,
        now_ns=_to_ns(now),
        max_age_ns=_MAX_AGE_NS,
        session_start_anchor=anchor,
    )


def test_first_observation_requires_matching_verified_session_start_anchor() -> None:
    result = _reconcile(anchor=_anchor())

    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert result.session_status is VerificationStatus.VERIFIED
    assert result.divergence_codes == ()
    assert result.broker_observed_at == _NOW
    assert result.session_id == _SESSION
    assert result.submission_blocked is True


def test_matching_previous_session_requires_durable_verified_marker() -> None:
    unmarked = _reconcile(
        ledger=_ledger(previous_session_id=_SESSION, previous_session_verified=False)
    )
    marked = _reconcile(
        ledger=_ledger(previous_session_id=_SESSION, previous_session_verified=True)
    )

    assert unmarked.session_status is VerificationStatus.UNVERIFIED
    assert unmarked.divergence_codes == ()
    assert unmarked.balances_status is VerificationStatus.VERIFIED
    assert unmarked.submission_blocked is True
    assert marked.session_status is VerificationStatus.VERIFIED
    assert "SESSION_UNVERIFIED" not in marked.divergence_codes
    assert marked.balances_status is VerificationStatus.VERIFIED
    assert marked.submission_blocked is False


@pytest.mark.parametrize(
    ("anchor_environment", "anchor_account", "anchor_venue", "anchor_session"),
    [
        (BrokerEnvironment.LIVE, "another-account", BrokerVenue.ALPACA, _SESSION),
        (BrokerEnvironment.LIVE, _ACCOUNT, BrokerVenue.IBKR_TWS, _SESSION),
        (BrokerEnvironment.DEMO, _ACCOUNT, BrokerVenue.ALPACA, _SESSION),
        (BrokerEnvironment.LIVE, _ACCOUNT, BrokerVenue.ALPACA, "another-session"),
    ],
)
def test_start_anchor_scope_and_session_must_match_exactly(
    anchor_environment: BrokerEnvironment,
    anchor_account: str,
    anchor_venue: BrokerVenue,
    anchor_session: str,
) -> None:
    result = _reconcile(
        anchor=_anchor(
            environment=anchor_environment,
            account_id=anchor_account,
            venue=anchor_venue,
            session_id=anchor_session,
        )
    )

    assert result.session_status is VerificationStatus.UNVERIFIED
    assert "SESSION_UNVERIFIED" in result.divergence_codes


@pytest.mark.parametrize(
    ("view_session", "previous_session", "expected_code"),
    [
        (None, None, "SESSION_UNVERIFIED"),
        ("session-after-reconnect", _SESSION, "SESSION_CHANGED"),
    ],
)
def test_absent_or_changed_session_never_verifies(
    view_session: str | None,
    previous_session: str | None,
    expected_code: str,
) -> None:
    result = _reconcile(
        view=_view(session_id=view_session),
        ledger=_ledger(
            previous_session_id=previous_session,
            previous_session_verified=previous_session is not None,
        ),
        anchor=_anchor() if view_session is None else None,
    )

    assert result.session_status is VerificationStatus.UNVERIFIED
    assert expected_code in result.divergence_codes


def test_malformed_broker_session_id_is_rejected_at_the_issued_view_boundary() -> None:
    with pytest.raises(BrokerPortError, match="INVALID_BROKER_SESSION_ID"):
        _view(session_id="session id with spaces")


def test_malformed_anchor_session_id_cannot_verify() -> None:
    malformed_anchor = _anchor(session_id="session id with spaces")

    with pytest.raises(ReconcileError, match="INVALID_SESSION_START_ANCHOR"):
        _reconcile(anchor=malformed_anchor)


def test_stale_provider_snapshot_does_not_verify_even_with_matching_anchor() -> None:
    result = _reconcile(
        view=_view(observed_at=_NOW - timedelta(minutes=6)),
        anchor=_anchor(),
    )

    assert result.session_status is VerificationStatus.UNVERIFIED
    assert "STALE" in result.divergence_codes


def test_live_blocks_valid_first_session_anchor_when_balances_are_unverified() -> None:
    view = _issue_account_view(
        _ACCOUNT,
        (),
        (),
        7,
        (),
        _NOW,
        complete=True,
        balances=None,
        broker_observed_at=_NOW,
        session_id=_SESSION,
    )
    result = _reconcile(view=view, anchor=_anchor())

    assert result.session_status is VerificationStatus.VERIFIED
    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert result.submission_blocked is True


def test_account_scope_and_local_venue_mismatch_prevent_verification() -> None:
    account_mismatch = _reconcile(
        view=_view(account_id="different-account"),
        anchor=_anchor(),
    )
    venue_mismatch = _reconcile(
        ledger=_ledger(venue=BrokerVenue.IBKR_TWS),
        anchor=_anchor(),
    )

    assert account_mismatch.session_status is VerificationStatus.UNVERIFIED
    assert "ACCOUNT_SCOPE_MISMATCH" in account_mismatch.divergence_codes
    assert venue_mismatch.session_status is VerificationStatus.UNVERIFIED
    assert "LOCAL_VENUE_MISMATCH" in venue_mismatch.divergence_codes


@pytest.mark.parametrize("environment", [BrokerEnvironment.PAPER, BrokerEnvironment.DEMO])
def test_paper_and_demo_remain_nonblocking_without_verified_session(
    environment: BrokerEnvironment,
) -> None:
    result = _reconcile(
        view=_view(session_id="new-session"),
        ledger=_ledger(
            environment=environment,
            previous_session_id=_SESSION,
            previous_session_verified=True,
        ),
        expected_venue=_venue(environment),
    )

    assert result.session_status is VerificationStatus.UNVERIFIED
    assert "SESSION_CHANGED" in result.divergence_codes
    assert result.submission_blocked is False


@pytest.mark.parametrize("copy_method", [copy.copy, copy.deepcopy])
def test_copied_start_anchor_is_not_accepted(
    copy_method: Callable[[VerifiedSessionStartAnchorV1], VerifiedSessionStartAnchorV1],
) -> None:
    with pytest.raises(SealError) as error:
        copy_method(_anchor())

    assert error.value.code == "SEAL_FORBIDDEN_OPERATION"


def test_tampered_start_anchor_is_not_accepted() -> None:
    anchor = _anchor()
    object.__setattr__(anchor, "account_id", "different-account")

    with pytest.raises(SealError) as error:
        _reconcile(anchor=anchor)

    assert error.value.code == "SEAL_TAMPERED"


def test_forged_start_anchor_is_not_accepted() -> None:
    forged = VerifiedSessionStartAnchorV1(
        environment=BrokerEnvironment.LIVE,
        account_id=_ACCOUNT,
        venue=BrokerVenue.ALPACA,
        session_id=_SESSION,
        verified=True,
    )

    with pytest.raises(SealError) as error:
        _reconcile(anchor=forged)

    assert error.value.code == "SEAL_NOT_ISSUED"


def test_reconcile_once_forwards_the_verified_start_anchor() -> None:
    expected = _venue()
    anchor = _anchor()

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
            cast(BrokerPortV1, Broker()),
            cast(ReconcilePortV1, ledger),
            expected,
            observed_at_ns=_to_ns(_NOW),
            now_ns=_to_ns(_NOW),
            max_age_ns=_MAX_AGE_NS,
            session_start_anchor=anchor,
        )
    )

    assert result.session_status is VerificationStatus.VERIFIED
    assert ledger.appended == [result]
