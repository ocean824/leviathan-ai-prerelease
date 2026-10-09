"""Test-only issuance for explicitly verified session-start evidence."""

from __future__ import annotations

from leviathan_core.execution.broker_port_v1 import BrokerEnvironment, BrokerVenue
from leviathan_core.execution.reconciliation import (
    _SESSION_START_ANCHOR_ISSUER,
    VerifiedSessionStartAnchorV1,
)


def issue_verified_session_start_anchor(
    environment: BrokerEnvironment,
    account_id: str,
    venue: BrokerVenue,
    session_id: str,
) -> VerifiedSessionStartAnchorV1:
    """Issue synthetic, scoped anchor evidence for tests only."""
    return _SESSION_START_ANCHOR_ISSUER.issue(
        VerifiedSessionStartAnchorV1(
            environment=environment,
            account_id=account_id,
            venue=venue,
            session_id=session_id,
            verified=True,
        )
    )
