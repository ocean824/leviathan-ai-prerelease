"""Test-only support for creating authentic AGENT-004 replay outcomes.

Production code must obtain replay outcomes through its replay adapter. This
module is the sole test-tree boundary allowed to call the private issuer.
"""

from __future__ import annotations

from typing import Any

from leviathan_core.agent_council.runner_models import (
    ReplayOutcomeV1,
    _issue_replay_outcome,
)


def issue_fixture_replay_outcome(**fields: Any) -> ReplayOutcomeV1:
    """Run ReplayOutcomeV1 validation and issue a sealed fixture outcome."""
    return _issue_replay_outcome(**fields)


__all__ = ["issue_fixture_replay_outcome"]
