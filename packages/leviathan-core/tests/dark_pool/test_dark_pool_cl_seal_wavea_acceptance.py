"""Independent CL-SEAL-WAVEA acceptance checks for DP-001 context seals."""

from __future__ import annotations

import json
from dataclasses import fields
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.dark_pool import (
    AggregateContextV1,
    DarkLensError,
    DarkLensPolicyV1,
    DarkLensSnapshotV1,
    ExchangeSessionV1,
    VenueRuleV1,
    calculate,
)
from leviathan_core.dark_pool.finra_adapter import (
    DarkAggregateContextV1,
    parse_finra_aggregate_fixture,
    require_dark_context,
)

_CONTEXT_FIELDS = {
    "instrument_id": "SYNTH-X",
    "source_id": "FINRA",
    "dataset_id": "delayed-v1",
    "venue": "ATS",
    "native_id": "aggregate-1",
    "event_ns": 120,
    "published_ns": 130,
    "available_ns": 140,
    "exchange_tz": "UTC",
    "calendar_version": "test-calendar-v1",
    "release_vintage": "120-300:revision-1",
    "entitlement_status": "UNVERIFIED",
    "source_state": "AGGREGATE_ONLY",
    "source_file_sha256": "a" * 64,
    "api_revision": "fixture-api-v1",
    "tier": "ATS",
    "security_id": "SYNTH-X",
    "period_start_ns": 100,
    "period_end_ns": 120,
    "metric_name": "share_volume",
    "metric_unit": "shares",
    "metric_value": Decimal("120"),
    "received_ns": 135,
    "publication_schedule_id": "synthetic-release-v1",
    "revision_id": "revision-1",
    "supersedes_revision_id": None,
    "verification": "SYNTHETIC_TEST",
    "license_status": "SYNTHETIC_ONLY",
}


def _plain_context() -> AggregateContextV1:
    return AggregateContextV1(
        instrument_id="SYNTH-X",
        source_id="FINRA",
        dataset_id="delayed-v1",
        venue="ATS",
        native_id="aggregate-1",
        event_ns=120,
        published_ns=130,
        available_ns=140,
        exchange_tz="UTC",
        calendar_version="test-calendar-v1",
        release_vintage="120-300:revision-1",
    )


def _unissued_dark_context() -> DarkAggregateContextV1:
    candidate = object.__new__(DarkAggregateContextV1)
    for item in fields(DarkAggregateContextV1):
        object.__setattr__(candidate, item.name, _CONTEXT_FIELDS[item.name])
    return candidate


def _issued_dark_context() -> DarkAggregateContextV1:
    fixture_path = Path(__file__).parent / "fixtures" / "finra" / "weekly_ats_synthetic.json"
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    return parse_finra_aggregate_fixture(
        payload,
        observed_ns=1_800_604_804_000_000_000,
    )[0]


def _snapshot(context: AggregateContextV1) -> DarkLensSnapshotV1:
    return DarkLensSnapshotV1(
        aggregate_context=(context,),
        calendar=(
            ExchangeSessionV1(
                date(1970, 1, 1),
                0,
                1000,
                "UTC",
                "test-calendar-v1",
                "00:00",
                0,
            ),
        ),
        venue_registry=(VenueRuleV1("ATS", "OFF_EXCHANGE"),),
    )


def _policy() -> DarkLensPolicyV1:
    return DarkLensPolicyV1(
        instrument_id="SYNTH-X",
        window_start_ns=100,
        window_end_ns=300,
        calendar_version="test-calendar-v1",
        min_notional=Decimal("100"),
        min_lit_volume=Decimal("10"),
    )


def test_calculate_rejects_unissued_dark_aggregate_context() -> None:
    with pytest.raises(DarkLensError) as caught:
        calculate(_snapshot(_unissued_dark_context()), _policy(), 200)

    assert caught.value.code == "INVALID_CONTEXT"


def test_calculate_still_accepts_plain_aggregate_context_as_data() -> None:
    result = calculate(_snapshot(_plain_context()), _policy(), 200)

    assert result.aggregate_context_ids
    assert result.source_state == "AGGREGATE_ONLY"
    assert result.ranked_prints == ()


def test_issued_dark_context_rejects_reinitialization_without_mutation() -> None:
    issued = _issued_dark_context()
    original_metric = issued.metric_value
    fields_by_name = {item.name: getattr(issued, item.name) for item in fields(issued)}
    fields_by_name["metric_value"] = Decimal("999")

    with pytest.raises(DarkLensError) as caught:
        issued.__init__(**fields_by_name)

    assert caught.value.code == "UNISSUED_CONTEXT"
    assert issued.metric_value == original_metric
    assert require_dark_context(issued) is issued
