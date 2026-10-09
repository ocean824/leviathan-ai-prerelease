"""Independent acceptance tests for archived order-flow/options truth reads."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from leviathan_core.legacy_truth_flow import (
    ArchivedTruthBoundaryError,
    ArchivedTruthPolicyV1,
    ArchivedTruthQueryV1,
    ArchivedTruthResultV1,
    ArchivedTruthWriteDecisionV1,
    LegacyTruthRecordV1,
    MappedTruthRecordV1,
    deny_archived_truth_write,
    translate_archived_truth,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "scenarios.json").read_text(encoding="utf-8")
)
TENANT = FIXTURE["query"]["tenant_scope"]
TRACE_ID = "trace-truth-synthetic-001"
START = "2025-12-18T00:00:00Z"
END = "2025-12-19T00:00:00Z"


def _query(
    *,
    dataset: str = "order_flow",
    start_utc: str = START,
    end_utc: str = END,
    symbol: str | None = "SYNTH",
    osi: str | None = None,
    side: str | None = None,
    venue: str | None = None,
    currency: str | None = None,
    event_type: str | None = None,
    limit: int = 1000,
    cursor: str | None = None,
    if_none_match: str | None = None,
) -> ArchivedTruthQueryV1:
    return ArchivedTruthQueryV1(
        tenant_id=TENANT,
        dataset=dataset,
        start_utc=start_utc,
        end_utc=end_utc,
        trace_id=TRACE_ID,
        symbol=symbol,
        osi=osi,
        side=side,
        venue=venue,
        currency=currency,
        event_type=event_type,
        limit=limit,
        cursor=cursor,
        if_none_match=if_none_match,
        read_scope_verified=True,
    )


def _policy(**overrides: object) -> ArchivedTruthPolicyV1:
    fields: dict[str, object] = {
        "sunset_utc": "2030-01-01T00:00:00Z",
        "snapshot_version": "synthetic-snapshot-v3",
        "reads_enabled": True,
        "proxy_enabled": True,
        "legacy_dataset_permitted": True,
        "new_dataset_permitted": True,
        "allowed_venues": ("SYNTH-VENUE",),
        "allowed_currencies": ("USD",),
        "successor_base": "/v2/truth",
    }
    fields.update(overrides)
    return ArchivedTruthPolicyV1(**fields)


def _legacy(**overrides: object) -> LegacyTruthRecordV1:
    fields: dict[str, object] = {
        "record_id": "legacy-synthetic-001",
        "tenant_id": TENANT,
        "dataset": "order_flow",
        "timestamp_ns": 1_766_016_000_000_000_000,
        "source_version": "legacy-source-v1.3",
        "symbol": "SYNTH",
        "side": "BUY",
        "venue": "SYNTH-VENUE",
        "currency": "USD",
        "price": "10.25",
        "size": "3",
        "value": "10.25",
        "liquidity_flag": "SYNTHETIC",
        "evidence_status": "UNKNOWN",
        "availability_ns": 1_766_016_000_000_000_001,
        "timestamp_precision": "ns",
        "source_dataset": "licensed-synthetic-feed",
        "source_schema_version": "truth-source-v2",
        "source_license": "synthetic-license",
        "source_entitlement": "synthetic-entitlement",
        "source_checksum": "source-checksum-synthetic",
        "source_trace_id": "source-trace-synthetic",
        "local_receipt_id": "receipt-one",
    }
    fields.update(overrides)
    return LegacyTruthRecordV1(**fields)


def _mapped(**overrides: object) -> MappedTruthRecordV1:
    fields: dict[str, object] = {
        "record_id": "mapped-synthetic-001",
        "tenant_id": TENANT,
        "dataset": "order_flow",
        "timestamp_ns": 1_766_016_000_000_000_000,
        "source_version": "mapped-source-v2",
        "symbol": "SYNTH",
        "side": "BUY",
        "venue": "SYNTH-VENUE",
        "currency": "USD",
        "price": "10.25",
        "size": "3",
        "value": "10.25",
        "liquidity_flag": "SYNTHETIC",
        "evidence_status": "UNKNOWN",
        "availability_ns": 1_766_016_000_000_000_001,
        "timestamp_precision": "ns",
        "source_dataset": "licensed-synthetic-feed",
        "source_schema_version": "truth-source-v2",
        "source_license": "synthetic-license",
        "source_entitlement": "synthetic-entitlement",
        "source_checksum": "source-checksum-synthetic",
        "source_trace_id": "source-trace-synthetic",
        "local_receipt_id": "receipt-two",
        "mapping_key": "mapping-synthetic-unique",
    }
    fields.update(overrides)
    return MappedTruthRecordV1(**fields)


def _query_mapped(
    query: ArchivedTruthQueryV1,
    legacy_rows: tuple[LegacyTruthRecordV1, ...],
    callback: Callable[[], tuple[MappedTruthRecordV1, ...]] | None,
    policy: ArchivedTruthPolicyV1 | None = None,
) -> ArchivedTruthResultV1:
    return translate_archived_truth(query, legacy_rows, callback, policy or _policy())


def test_matching_legacy_record_wins_and_proxy_callback_is_not_invoked() -> None:
    mapped_query = Mock(return_value=(_mapped(),))
    result = _query_mapped(_query(), (_legacy(),), mapped_query)
    assert result.status_code == 200
    assert len(result.records) == 1
    assert result.records[0].source == "legacy"
    assert result.records[0].schema_version == "legacy-1"
    assert not result.proxy_hit
    mapped_query.assert_not_called()


def test_proxy_occurs_only_for_absent_legacy_with_both_permissions_and_flag() -> None:
    callback = Mock(return_value=(_mapped(),))
    result = _query_mapped(_query(), (), callback)
    assert result.status_code == 200
    assert result.records[0].source == "proxy"
    assert result.records[0].schema_version == "mapped-v2"
    assert result.proxy_hit
    callback.assert_called_once_with()


def test_proxy_disabled_returns_not_found_without_lookup() -> None:
    callback = Mock(return_value=(_mapped(),))
    result = _query_mapped(_query(), (), callback, _policy(proxy_enabled=False))
    assert result.status_code == 404
    assert not result.records
    assert not result.proxy_hit
    callback.assert_not_called()


def test_unpermitted_proxy_never_queries_or_returns_new_dataset_rows() -> None:
    callback = Mock(return_value=(_mapped(),))
    result = _query_mapped(_query(), (), callback, _policy(new_dataset_permitted=False))
    assert result.status_code == 403
    assert result.error is not None
    assert result.error.code == "FORBIDDEN_NEW_DATASET"
    assert not result.records
    assert not result.proxy_hit
    callback.assert_not_called()


def test_missing_mapped_callback_returns_not_found_and_does_not_fabricate_data() -> None:
    result = _query_mapped(_query(), (), None)
    assert result.status_code == 404
    assert not result.records


def test_proxy_requires_a_unique_mapping_key() -> None:
    callback = Mock(return_value=(_mapped(mapping_key=None),))
    result = _query_mapped(_query(), (), callback)
    assert result.status_code == 404
    assert not result.records


def test_checksum_is_stable_across_local_receipt_ids_and_source_precedence() -> None:
    legacy = _legacy(local_receipt_id="legacy-receipt")
    mapped = _mapped(local_receipt_id="mapped-receipt")
    legacy_result = _query_mapped(_query(), (legacy,), None)
    proxy_result = _query_mapped(_query(), (), lambda: (mapped,))
    assert legacy_result.records[0].checksum == proxy_result.records[0].checksum
    assert legacy_result.records[0].checksum


def test_provenance_retains_source_version_trace_checksum_license_and_precision() -> None:
    result = _query_mapped(_query(), (_legacy(),), None)
    record = result.records[0]
    assert record.origin == "LEGACY"
    assert record.source == "legacy"
    assert record.source_version == "legacy-source-v1.3"
    assert record.timestamp_precision == "ns"
    assert record.source_license == "synthetic-license"
    assert record.source_entitlement == "synthetic-entitlement"
    assert record.source_checksum == "source-checksum-synthetic"
    assert record.source_trace_id == "source-trace-synthetic"
    assert record.confirmation_eligible is False
    assert record.route_permitted is False


@pytest.mark.parametrize("status", FIXTURE["evidence_statuses"])
def test_non_current_evidence_status_is_preserved_without_confirmation_or_route(
    status: str,
) -> None:
    result = _query_mapped(_query(), (_legacy(evidence_status=status),), None)
    record = result.records[0]
    assert record.evidence_status == status
    assert record.confirmation_eligible is False
    assert record.route_permitted is False


def test_embargo_timestamp_does_not_turn_evidence_into_confirmation() -> None:
    result = _query_mapped(
        _query(),
        (_legacy(evidence_status="CONFIRMED", embargo_until_ns=1_800_000_000_000_000_000),),
        None,
    )
    record = result.records[0]
    assert record.evidence_status == "CONFIRMED"
    assert record.effective_status == "EMBARGOED"
    assert record.price is None
    assert record.value is None
    assert record.confirmation_eligible is False
    assert record.route_permitted is False


def test_semantically_identical_local_replay_has_stable_checksum() -> None:
    first = _query_mapped(_query(), (_legacy(local_receipt_id="receipt-a"),), None)
    second = _query_mapped(_query(), (_legacy(local_receipt_id="receipt-b"),), None)
    assert first.records[0].checksum == second.records[0].checksum


def test_same_cursor_repeats_identical_page_and_cursor_result() -> None:
    rows = (
        _legacy(record_id="legacy-a"),
        _legacy(record_id="legacy-b", timestamp_ns=1_766_016_000_000_000_002),
    )
    query = _query(limit=1, cursor="stable-cursor")
    first = _query_mapped(query, rows, None)
    second = _query_mapped(query, rows, None)
    assert first.records == second.records
    assert first.next_cursor == second.next_cursor


def test_if_none_match_returns_not_modified_descriptor_for_same_content() -> None:
    initial = _query_mapped(_query(), (_legacy(),), None)
    etag = dict(initial.headers).get("ETag")
    assert etag
    repeated = _query_mapped(
        _query(if_none_match=etag),
        (_legacy(),),
        None,
    )
    assert repeated.status_code == 304


def test_page_etag_changes_for_distinct_bodies_with_same_semantic_checksum() -> None:
    rows = (
        _legacy(record_id="legacy-a"),
        _legacy(record_id="legacy-b"),
    )
    first = _query_mapped(_query(limit=1), rows, None)
    first_etag = dict(first.headers).get("ETag")
    assert first_etag
    assert first.next_cursor
    assert first.records[0].record_id == "legacy-a"

    second = _query_mapped(
        _query(limit=1, cursor=first.next_cursor, if_none_match=first_etag),
        rows,
        None,
    )
    second_etag = dict(second.headers).get("ETag")
    assert second.status_code == 200
    assert second.records[0].record_id == "legacy-b"
    assert first.records[0].checksum == second.records[0].checksum
    assert first.records[0] != second.records[0]
    assert second_etag and second_etag != first_etag


def test_page_etag_changes_when_source_license_changes_with_same_semantic_checksum() -> None:
    first = _query_mapped(_query(), (_legacy(source_license="license-A"),), None)
    first_etag = dict(first.headers).get("ETag")
    assert first_etag
    second = _query_mapped(
        _query(if_none_match=first_etag), (_legacy(source_license="license-B"),), None
    )
    second_etag = dict(second.headers).get("ETag")
    assert first.records[0].checksum == second.records[0].checksum
    assert first.records[0].source_license == "license-A"
    assert second.records[0].source_license == "license-B"
    assert first.records[0] != second.records[0]
    assert second.status_code == 200
    assert second_etag and second_etag != first_etag


def test_wrong_public_boundary_types_raise_fixed_typed_errors_without_echo() -> None:
    policy = _policy()
    cases = (
        (
            object(),
            (),
            None,
            policy,
            "INVALID_QUERY_TYPE",
            ("query",),
        ),
        (
            _query(),
            (),
            None,
            object(),
            "INVALID_POLICY_TYPE",
            ("policy",),
        ),
        (
            _query(),
            object(),
            None,
            policy,
            "INVALID_RECORD_TYPE",
            ("legacy_records",),
        ),
        (
            _query(),
            (object(),),
            None,
            policy,
            "INVALID_RECORD_TYPE",
            ("legacy_records",),
        ),
        (
            _query(),
            (),
            lambda: object(),
            policy,
            "INVALID_RECORD_TYPE",
            ("mapped_records",),
        ),
        (
            _query(),
            (),
            lambda: (object(),),
            policy,
            "INVALID_RECORD_TYPE",
            ("mapped_records",),
        ),
    )
    for query, legacy_records, mapped_records, current_policy, code, paths in cases:
        with pytest.raises(ArchivedTruthBoundaryError) as error:
            translate_archived_truth(
                query, legacy_records, mapped_records, current_policy  # type: ignore[arg-type]
            )
        assert error.value.code == code
        assert error.value.field_paths == paths
        assert str(error.value) == code


def test_invalid_window_over_31_days_is_rejected() -> None:
    end = (datetime.fromisoformat(START.replace("Z", "+00:00")) + timedelta(days=32)).isoformat()
    query = _query(end_utc=end)
    result = _query_mapped(query, (), None)
    assert result.status_code == 400
    assert result.error is not None


def test_exactly_31_day_window_is_included_and_31_days_plus_one_ns_is_rejected() -> None:
    start = "2025-12-18T00:00:00Z"
    end = "2026-01-18T00:00:00Z"
    exact = _query_mapped(_query(start_utc=start, end_utc=end), (), None)
    over = _query_mapped(
        _query(start_utc=start, end_utc="2026-01-18T00:00:00.000000001Z"), (), None
    )
    assert exact.status_code == 404
    assert over.status_code == 400
    assert over.error is not None


def test_policy_replace_revalidates_boolean_permission_gate() -> None:
    with pytest.raises(ArchivedTruthBoundaryError) as error:
        replace(_policy(), new_dataset_permitted="false")
    assert error.value.code == "INVALID_BOOL"


@pytest.mark.parametrize(
    "query",
    [
        _query(dataset="options", symbol=None, osi="bad-osi"),
        _query(side="HOLD"),
        _query(venue="UNAPPROVED-VENUE"),
        _query(currency="XYZ"),
        _query(symbol=None, osi=None),
    ],
)
def test_invalid_osi_side_venue_currency_or_missing_identity_is_rejected(
    query: ArchivedTruthQueryV1,
) -> None:
    result = _query_mapped(query, (), None)
    assert result.status_code == 400
    assert result.error is not None


def test_reads_disabled_returns_sunset_descriptor_with_migration_target() -> None:
    result = _query_mapped(
        _query(),
        (_legacy(),),
        None,
        _policy(reads_enabled=False),
    )
    assert result.status_code == 410
    assert result.error is not None
    assert result.error.migrate_to == "/v2/truth"


@pytest.mark.parametrize("verb", FIXTURE["mutating_verbs"])
def test_every_mutating_method_has_405_write_denial(verb: str) -> None:
    decision: ArchivedTruthWriteDecisionV1 = deny_archived_truth_write(verb, _policy())
    assert decision.status_code == FIXTURE["write_status"]
    assert decision.allow == FIXTURE["write_allow"]
    assert dict(decision.headers)["Allow"] == FIXTURE["write_allow"]


def test_cross_tenant_record_is_indistinguishable_from_missing() -> None:
    request = _query()
    hidden = _query_mapped(request, (_legacy(tenant_id="tenant-synthetic-b"),), None)
    absent = _query_mapped(request, (), None)
    assert hidden.status_code == absent.status_code == 404
    assert hidden.error is not None and absent.error is not None
    assert hidden.error.code == absent.error.code
    assert not hidden.records and not absent.records
