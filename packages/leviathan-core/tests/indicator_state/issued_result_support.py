"""Test helpers for obtaining IND-001 results through the real kernel path."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, cast

from leviathan_core.indicator_state.kernel import batch
from leviathan_core.indicator_state.models import (
    _RESULT_ISSUER,
    FinalBarV1,
    IndicatorDefinitionV1,
    IndicatorResultV1,
)


def issue_result_from_kernel(
    finalized_bars: Iterable[FinalBarV1],
    definition: IndicatorDefinitionV1,
    asof_ns: int,
    *,
    result_index: int = -1,
) -> IndicatorResultV1:
    """Return a kernel-issued result selected from a batch calculation."""
    results = batch(finalized_bars, definition, asof_ns)
    try:
        return results[result_index]
    except IndexError as exc:
        raise ValueError("kernel fixture did not produce a result at that index") from exc


def issue_fixture_result(**fields: object) -> IndicatorResultV1:
    """Validate a synthetic result payload, then seal it for adapter fixtures."""
    candidate = IndicatorResultV1(**cast(Any, fields))
    return _RESULT_ISSUER.issue(candidate)


__all__ = ["issue_fixture_result", "issue_result_from_kernel"]
