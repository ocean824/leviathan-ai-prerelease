"""OMEGA context credential scanning delegates to the shared scanner."""

from __future__ import annotations

import pytest

import leviathan_core.omega_link.task_bridge as task_bridge
from leviathan_core.omega_link.task_bridge import HandoffRequestV1, TaskBridgeError


def _request(question: str) -> HandoffRequestV1:
    return HandoffRequestV1(
        type="research",
        priority="normal",
        assigned_to="agent-1",
        ttl_ms=1_000,
        sla_ms=1_000,
        context={"question": question},
    )


def test_task_bridge_no_longer_owns_credential_regex_table() -> None:
    assert not hasattr(task_bridge, "_CONTEXT_VALUE_PATTERNS")


def test_credential_detection_delegates_string_scanning_to_shared_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    def scan(value: str) -> bool:
        seen.append(value)
        return value == "synthetic-marker"

    monkeypatch.setattr(task_bridge, "contains_credential_value", scan)

    assert task_bridge._contains_credential_value("synthetic-marker")
    assert seen == ["synthetic-marker"]


def test_shared_pypi_pattern_is_denied_without_retaining_or_echoing_value() -> None:
    candidate = "pypi-testfixturetoken"

    with pytest.raises(TaskBridgeError) as caught:
        _request(candidate).canonical_context()

    assert caught.value.code == "CONTEXT_SECRET_DENIED"
    assert caught.value.args == ("CONTEXT_SECRET_DENIED",)
    assert candidate not in str(caught.value)
    assert candidate not in repr(caught.value)
    assert candidate not in repr(caught.value.args)


@pytest.mark.parametrize("prose", ("pypi", "pypi package index", "ordinary research question"))
def test_non_credential_prose_remains_accepted(prose: str) -> None:
    canonical, digest = _request(prose).canonical_context()

    assert canonical is not None
    assert len(digest) == 64
