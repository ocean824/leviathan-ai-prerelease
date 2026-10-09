"""Fail-closed boundary for live order activation."""

from __future__ import annotations

from typing import Protocol


class LiveActivationGatePortV1(Protocol):
    """Synchronous, fail-closed live activation decision port."""

    def live_account_enabled(self, account_id: str) -> bool:
        """Return whether the exact account has live activation enabled."""
        ...


class DeniedLiveGateV1:
    """Default live gate; denies every account until a gate is injected."""

    def live_account_enabled(self, account_id: str) -> bool:
        del account_id
        return False
