"""Independent DP-002 contract checks using synthetic FINRA-shaped data only."""

from __future__ import annotations

import copy
import json
import pickle
import weakref
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.dark_pool.finra_adapter import (
    DarkAggregateContextV1,
    parse_finra_aggregate_fixture,
    require_dark_context,
)
from leviathan_core.dark_pool.models import AggregateContextV1, DarkLensError, DarkPrintV1

FIXTURES = Path(__file__).parent / "fixtures" / "finra"
ATS_OBSERVED_NS = 1_800_604_804_000_000_000
OTC_OBSERVED_NS = 1_800_604_813_000_000_000


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _parse(payload: dict[str, Any], *, observed_ns: int = ATS_OBSERVED_NS):
    return parse_finra_aggregate_fixture(payload, observed_ns=observed_ns)


def _rejected(
    payload: dict[str, Any],
    *,
    code: str,
    observed_ns: int = ATS_OBSERVED_NS,
) -> None:
    with pytest.raises(DarkLensError) as caught:
        _parse(payload, observed_ns=observed_ns)
    assert caught.value.code == code
    assert "SYNTHETIC_SECRET_CANARY" not in str(caught.value)
    assert "SYNTHETIC_SECRET_CANARY" not in repr(caught.value.args)


def _remove_publication(payload: dict[str, Any]) -> None:
    payload["rows"][0].pop("published_ns")


def _mismatch_publication(payload: dict[str, Any]) -> None:
    payload["rows"][0]["published_ns"] = 1_800_604_801_000_000_001


def _receive_before_publication(payload: dict[str, Any]) -> None:
    payload["rows"][0]["received_ns"] = 1_800_604_800_999_999_999


def _available_before_receipt(payload: dict[str, Any]) -> None:
    payload["rows"][0]["available_ns"] = 1_800_604_801_999_999_999


def _available_after_observation(payload: dict[str, Any]) -> None:
    payload["rows"][0]["available_ns"] = ATS_OBSERVED_NS + 1


def test_weekly_ats_correction_retains_both_aggregate_vintages() -> None:
    result = _parse(_fixture("weekly_ats_synthetic.json"))

    assert len(result) == 2
    first, correction = result
    assert type(first) is DarkAggregateContextV1
    assert type(correction) is DarkAggregateContextV1
    assert isinstance(first, AggregateContextV1)
    assert require_dark_context(first) is first
    assert require_dark_context(correction) is correction
    assert first.source_state == "AGGREGATE_ONLY"
    assert first.entitlement_status == "UNVERIFIED"
    assert first.license_status == "SYNTHETIC_ONLY"
    assert first.verification == "SYNTHETIC_TEST"
    assert first.source_file_sha256 == "a" * 64
    assert first.api_revision == "fixture-api-v1"
    assert first.tier == "ATS"
    assert first.security_id == "SYNTH-X"
    assert first.metric_name == "share_volume"
    assert first.metric_unit == "shares"
    assert first.metric_value == Decimal("120000")
    assert first.publication_schedule_id == "synthetic-ats-release-calendar-v1"
    assert first.published_ns == 1_800_604_801_000_000_000
    assert first.received_ns == 1_800_604_802_000_000_000
    assert first.available_ns == 1_800_604_803_000_000_000
    assert first.revision_id == "rev-1"
    assert first.supersedes_revision_id is None
    assert correction.revision_id == "rev-2"
    assert correction.supersedes_revision_id == "rev-1"
    assert correction.metric_value == Decimal("121000")
    assert not any(isinstance(item, DarkPrintV1) for item in result)


def test_tier_specific_publication_is_explicit_and_schedule_bound() -> None:
    ats = _parse(_fixture("weekly_ats_synthetic.json"))
    otc = _parse(_fixture("weekly_otc_synthetic.json"), observed_ns=OTC_OBSERVED_NS)

    assert {item.tier for item in (*ats, *otc)} == {"ATS", "OTC"}
    ats_release = ats[0].published_ns
    otc_release = otc[0].published_ns
    assert otc_release > ats_release
    assert ats_release == 1_800_604_801_000_000_000
    assert otc_release == 1_800_604_810_000_000_000
    assert otc[0].publication_schedule_id == "synthetic-otc-release-calendar-v1"
    assert otc[0].event_ns == otc[0].period_end_ns
    assert otc[0].source_state == "AGGREGATE_ONLY"


def test_identical_duplicate_revision_collapses_but_conflicting_duplicate_rejects() -> None:
    payload = _fixture("weekly_ats_synthetic.json")
    payload["rows"] = [payload["rows"][0], copy.deepcopy(payload["rows"][0])]
    assert len(_parse(payload)) == 1

    payload["rows"][1]["metric_value"] = "120001"
    _rejected(payload, code="CONFLICTING_DUPLICATE")


def test_future_correction_is_invisible_and_original_vintage_remains_visible() -> None:
    payload = _fixture("weekly_ats_synthetic.json")
    payload["rows"][1]["available_ns"] = ATS_OBSERVED_NS + 1

    result = _parse(payload, observed_ns=ATS_OBSERVED_NS)

    assert tuple(item.revision_id for item in result) == ("rev-1",)
    assert result[0].metric_value == Decimal("120000")


def test_correction_is_applied_at_exact_availability_boundary() -> None:
    payload = _fixture("weekly_ats_synthetic.json")
    correction = payload["rows"][1]
    observed_ns = correction["available_ns"]

    result = _parse(payload, observed_ns=observed_ns)

    assert tuple(item.revision_id for item in result) == ("rev-1", "rev-2")
    assert result[-1].metric_value == Decimal("121000")


def test_not_yet_visible_original_is_excluded() -> None:
    payload = _fixture("weekly_ats_synthetic.json")
    payload["rows"] = [payload["rows"][0]]
    payload["rows"][0]["available_ns"] = ATS_OBSERVED_NS + 1

    assert _parse(payload, observed_ns=ATS_OBSERVED_NS) == ()


@pytest.mark.parametrize(
    ("mutate", "code", "observed_ns"),
    [
        (_remove_publication, "INVALID_ENVELOPE", ATS_OBSERVED_NS),
        (_mismatch_publication, "PUBLICATION_SCHEDULE_MISMATCH", ATS_OBSERVED_NS),
        (_available_before_receipt, "INVALID_PUBLICATION", ATS_OBSERVED_NS),
        (_receive_before_publication, "INVALID_PUBLICATION", ATS_OBSERVED_NS),
    ],
)
def test_missing_or_inconsistent_publication_evidence_is_rejected(
    mutate, code, observed_ns
) -> None:
    payload = _fixture("weekly_ats_synthetic.json")
    payload["rows"] = [payload["rows"][0]]
    mutate(payload)
    _rejected(payload, code=code, observed_ns=observed_ns)


def test_revision_must_link_to_existing_predecessor_and_old_vintage_is_preserved() -> None:
    payload = _fixture("weekly_ats_synthetic.json")
    payload["rows"][1]["supersedes_revision_id"] = "absent-revision"
    _rejected(payload, code="ORPHAN_REVISION")

    valid = _parse(_fixture("weekly_ats_synthetic.json"))
    assert tuple(item.revision_id for item in valid) == ("rev-1", "rev-2")
    assert valid[0].metric_value == Decimal("120000")
    assert valid[1].metric_value == Decimal("121000")


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"schema": "unexpected-schema"}, "INVALID_ENVELOPE"),
        ({"verification": "VERIFIED_REAL"}, "UNVERIFIED_SOURCE"),
        ({"license_status": "LICENSED"}, "UNLICENSED_SOURCE"),
        ({"source_file_sha256": "not-a-digest"}, "INVALID_SOURCE_HASH"),
        ({"tier": "DARK_POOL"}, "INVALID_TIER"),
        ({"api_revision": "SYNTHETIC_SECRET_CANARY\r\nbad"}, "INVALID_ENVELOPE"),
    ],
)
def test_invalid_source_identity_or_usage_claims_fail_closed(change, code) -> None:
    payload = _fixture("weekly_ats_synthetic.json")
    payload.update(change)
    _rejected(payload, code=code)


def test_only_factory_issued_weakrefable_aggregate_context_is_accepted() -> None:
    issued = _parse(_fixture("weekly_ats_synthetic.json"))[0]
    assert weakref.ref(issued)() is issued
    assert require_dark_context(issued) is issued

    try:
        replaced = replace(issued)
    except DarkLensError:
        pass
    else:
        with pytest.raises(DarkLensError):
            require_dark_context(replaced)
    with pytest.raises(DarkLensError):
        copy.copy(issued)
    with pytest.raises(DarkLensError):
        copy.deepcopy(issued)
    with pytest.raises(DarkLensError):
        pickle.dumps(issued)
    with pytest.raises(DarkLensError):
        require_dark_context({"source_state": "AGGREGATE_ONLY"})
