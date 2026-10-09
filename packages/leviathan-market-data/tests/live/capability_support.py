"""Test-only helper for trusted-provider capability fixtures.

This module is in the tests tree and is never imported by package source.
Production capability issuance remains restricted to reviewed adapter registration.
"""

from __future__ import annotations

from leviathan_market_data.live.replay import (
    TrustedProviderCapabilityV1,
    _issue_trusted_provider_capability,
)


def issue_test_capability(
    source: object, provider_id: str
) -> TrustedProviderCapabilityV1:
    """Issue a capability bound to one synthetic source-port instance."""
    return _issue_trusted_provider_capability(source, provider_id)
