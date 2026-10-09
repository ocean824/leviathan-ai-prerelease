"""Worker regressions for adapter-issued context integrity."""

from __future__ import annotations

import json
from dataclasses import fields
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.dark_pool.finra_adapter import (
    DarkAggregateContextV1,
    parse_finra_aggregate_fixture,
    require_dark_context,
)
from leviathan_core.dark_pool.models import DarkLensError

FIXTURES = Path(__file__).parent / "fixtures" / "finra"
OBSERVED_NS = 1_800_604_804_000_000_000


def test_reinitializing_issued_dark_context_is_rejected_without_mutation() -> None:
    payload = json.loads((FIXTURES / "weekly_ats_synthetic.json").read_text(encoding="utf-8"))
    context = parse_finra_aggregate_fixture(payload, observed_ns=OBSERVED_NS)[0]
    before = context.metric_value
    values = {item.name: getattr(context, item.name) for item in fields(context)}
    values["metric_value"] = Decimal("999")

    with pytest.raises(DarkLensError) as caught:
        DarkAggregateContextV1.__init__(context, **values)

    assert caught.value.code == "UNISSUED_CONTEXT"
    assert context.metric_value == before == Decimal("120000")
    assert require_dark_context(context) is context
