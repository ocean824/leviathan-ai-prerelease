"""Worker checks for immutable archived truth reads."""

import copy
import pickle
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal, localcontext

import pytest

from leviathan_core.legacy_truth_flow import (
    ArchivedTruthBoundaryError,
    ArchivedTruthPolicyV1,
    ArchivedTruthQueryV1,
    LegacyTruthRecordV1,
    MappedTruthRecordV1,
    deny_archived_truth_write,
    translate_archived_truth,
)

_T0 = 1_767_225_600_000_000_000


def _query(**changes: object) -> ArchivedTruthQueryV1:
    values = {
        "tenant_id": "tenant-a",
        "dataset": "order_flow",
        "start_utc": "2026-01-01T00:00:00Z",
        "end_utc": "2026-01-02T00:00:00Z",
        "trace_id": "trace-1",
        "symbol": "AAPL",
        "read_scope_verified": True,
    }
    values.update(changes)
    return ArchivedTruthQueryV1(**values)


def _policy(**changes: object) -> ArchivedTruthPolicyV1:
    values = {
        "sunset_utc": "2027-01-01T00:00:00Z",
        "snapshot_version": "archive-fixture-1",
        "legacy_dataset_permitted": True,
        "new_dataset_permitted": True,
        "allowed_venues": ("XNAS",),
    }
    values.update(changes)
    return ArchivedTruthPolicyV1(**values)


def _legacy(**changes: object) -> LegacyTruthRecordV1:
    values = {
        "record_id": "legacy-1",
        "tenant_id": "tenant-a",
        "dataset": "order_flow",
        "timestamp_ns": _T0,
        "source_version": "archive-v1",
        "symbol": "AAPL",
        "side": "BUY",
        "venue": "XNAS",
        "currency": "USD",
        "price": Decimal("100.00"),
        "size": Decimal("2.0"),
        "evidence_status": "CURRENT",
        "source_license": "LICENSED_FIXTURE",
        "source_checksum": "raw-source-checksum",
    }
    values.update(changes)
    return LegacyTruthRecordV1(**values)


def _mapped(**changes: object) -> MappedTruthRecordV1:
    values = {
        "record_id": "new-store-999",
        "tenant_id": "tenant-a",
        "dataset": "order_flow",
        "timestamp_ns": _T0,
        "source_version": "new-v2",
        "symbol": "AAPL",
        "side": "BUY",
        "venue": "XNAS",
        "currency": "USD",
        "price": Decimal("100"),
        "size": Decimal("2"),
        "evidence_status": "CURRENT",
        "source_license": "LICENSED_FIXTURE",
        "source_checksum": "other-source-checksum",
        "mapping_key": "unique-map-1",
    }
    values.update(changes)
    return MappedTruthRecordV1(**values)


def test_legacy_first_and_proxy_permission() -> None:
    calls = 0

    def supplier() -> tuple[MappedTruthRecordV1, ...]:
        nonlocal calls
        calls += 1
        return (_mapped(),)

    direct = translate_archived_truth(_query(), (_legacy(),), supplier, _policy())
    assert direct.status_code == 200 and direct.records[0].origin == "LEGACY"
    assert calls == 0
    assert direct.records[0].source_checksum == "raw-source-checksum"

    disabled = translate_archived_truth(_query(), (), supplier, _policy(proxy_enabled=False))
    assert disabled.status_code == 404 and calls == 0
    forbidden = translate_archived_truth(
        _query(), (), supplier, _policy(new_dataset_permitted=False)
    )
    assert forbidden.status_code == 403 and calls == 0
    assert forbidden.error is not None and forbidden.error.code == "FORBIDDEN_NEW_DATASET"

    proxy = translate_archived_truth(_query(), (), supplier, _policy())
    assert proxy.status_code == 200 and proxy.records[0].origin == "PROXY"
    assert proxy.proxy_hit and calls == 1
    assert proxy.records[0].checksum == direct.records[0].checksum
    assert dict(proxy.headers)["ETag"] != dict(direct.headers)["ETag"]


def test_cursor_etag_and_time_validation() -> None:
    rows = (_legacy(), _legacy(record_id="legacy-2", timestamp_ns=_T0 + 1))
    first = translate_archived_truth(_query(limit=1), rows, None, _policy())
    assert first.status_code == 200 and first.next_cursor is not None
    second = translate_archived_truth(
        _query(limit=1, cursor=first.next_cursor), rows, None, _policy()
    )
    repeat = translate_archived_truth(
        _query(limit=1, cursor=first.next_cursor), rows, None, _policy()
    )
    assert second.records == repeat.records and second.next_cursor == repeat.next_cursor
    etag = dict(first.headers)["ETag"]
    unchanged = translate_archived_truth(_query(limit=1, if_none_match=etag), rows, None, _policy())
    assert unchanged.status_code == 304 and unchanged.records == ()
    assert translate_archived_truth(
        _query(end_utc="2026-03-01T00:00:00Z"), rows, None, _policy()
    ).error.code == "INVALID_TIME_RANGE"


def test_stale_embargoed_unknown_and_privacy() -> None:
    for status in ("STALE", "UNKNOWN", "UNENTITLED"):
        response = translate_archived_truth(
            _query(), (_legacy(evidence_status=status),), None, _policy()
        )
        assert response.records[0].evidence_status == status
        assert response.records[0].confirmation_eligible is False
        assert response.records[0].route_permitted is False
        if status == "UNENTITLED":
            assert response.records[0].price is None
    embargoed = translate_archived_truth(
        _query(), (_legacy(embargo_until_ns=_T0 + 4 * 86_400_000_000_000),), None, _policy()
    )
    assert embargoed.records[0].evidence_status == "CURRENT"
    assert embargoed.records[0].effective_status == "EMBARGOED"
    assert embargoed.records[0].price is None
    assert translate_archived_truth(
        _query(), (_legacy(tenant_id="other"),), None, _policy(proxy_enabled=False)
    ).status_code == 404


def test_bad_identifier_writes_and_freeze() -> None:
    assert translate_archived_truth(
        _query(dataset="options", symbol=None, osi="AAPL260117C150"), (), None, _policy()
    ).error.code == "INVALID_IDENTIFIER"
    for verb in ("POST", "PUT", "PATCH", "DELETE"):
        denial = deny_archived_truth_write(verb, _policy())
        assert denial.status_code == 405
        assert denial.allow == "GET,HEAD"
        assert dict(denial.headers)["Allow"] == "GET,HEAD"
    assert translate_archived_truth(
        _query(), (_legacy(),), None, _policy(reads_enabled=False)
    ).status_code == 410
    with pytest.raises(FrozenInstanceError):
        _legacy().price = Decimal("9")  # type: ignore[misc]


def test_precision_boolean_integer_and_ambient_decimal_context() -> None:
    with pytest.raises(ArchivedTruthBoundaryError) as precision:
        _legacy(price=Decimal("0." + "1" * 35))
    assert precision.value.code == "PRECISION_EXCEEDED"
    with pytest.raises(ArchivedTruthBoundaryError) as timestamp:
        _legacy(timestamp_ns=True)
    assert timestamp.value.code == "INVALID_INTEGER"
    with pytest.raises(ArchivedTruthBoundaryError, match="INVALID_INTEGER"):
        _query(limit=True)
    with pytest.raises(ArchivedTruthBoundaryError, match="INVALID_BOOL"):
        _policy(new_dataset_permitted="false")
    normal = translate_archived_truth(_query(), (_legacy(price="10.2500"),), None, _policy())
    with localcontext() as context:
        context.prec = 2
        context.Emax = 5
        constrained = translate_archived_truth(
            _query(), (_legacy(price="10.2500"),), None, _policy()
        )
    assert normal.records[0].checksum == constrained.records[0].checksum
    assert str(normal.records[0].price) == str(constrained.records[0].price) == "10.25"
    edge = _legacy(price=Decimal("1e38"))
    assert replace(edge, price=edge.price).price == edge.price
    trailing_zeros = _legacy(price=Decimal("1." + "0" * 40))
    assert trailing_zeros.price == Decimal("1")
    assert str(trailing_zeros.price) == "1"
    expanded = _legacy(price=Decimal("1" + "0" * 34))
    assert expanded.price == Decimal("1E+34")
    assert replace(expanded, price=expanded.price).price == expanded.price


def test_copy_pickle_and_replace_revalidation() -> None:
    record = _legacy()
    result = translate_archived_truth(_query(), (record,), None, _policy())
    for value in (record, _policy(), result, result.records[0]):
        with pytest.raises(ArchivedTruthBoundaryError, match="FROZEN_OBJECT"):
            copy.copy(value)
        with pytest.raises(ArchivedTruthBoundaryError, match="FROZEN_OBJECT"):
            copy.deepcopy(value)
        with pytest.raises(ArchivedTruthBoundaryError, match="FROZEN_OBJECT"):
            pickle.dumps(value)
    canonical = replace(record, price=Decimal("100.00"))
    assert str(canonical.price) == "100"
    with pytest.raises(ArchivedTruthBoundaryError):
        replace(result, headers=[])


def test_policy_and_view_replace_validate_complete_bounds() -> None:
    policy = _policy()
    for changes in (
        {"sunset_utc": "2030-02-30T00:00:00Z"},
        {"successor_base": "https://invalid.example/v2"},
        {"allowed_currencies": ["usd"]},
    ):
        with pytest.raises(ArchivedTruthBoundaryError):
            replace(policy, **changes)
    record = translate_archived_truth(_query(), (_legacy(),), None, policy).records[0]
    for changes in (
        {"origin": "PROXY"},
        {"evidence_status": "FRESH"},
        {"timestamp_ns": True},
        {"source_license": []},
    ):
        with pytest.raises(ArchivedTruthBoundaryError):
            replace(record, **changes)
    malformed = translate_archived_truth(
        _query(start_utc="٢٠٢٦-01-01T00:00:00Z"), (), None, policy
    )
    assert malformed.status_code == 400


def test_etag_covers_page_identity_and_returned_provenance() -> None:
    rows = (_legacy(record_id="legacy-a"), _legacy(record_id="legacy-b"))
    first = translate_archived_truth(_query(limit=1), rows, None, _policy())
    assert first.next_cursor is not None
    first_etag = dict(first.headers)["ETag"]
    second = translate_archived_truth(
        _query(limit=1, cursor=first.next_cursor, if_none_match=first_etag), rows, None, _policy()
    )
    assert second.status_code == 200
    assert second.records[0].record_id == "legacy-b"
    assert dict(second.headers)["ETag"] != first_etag
    assert second.records[0].checksum == first.records[0].checksum

    original = translate_archived_truth(_query(), (_legacy(),), None, _policy())
    changed = translate_archived_truth(
        _query(if_none_match=dict(original.headers)["ETag"]),
        (_legacy(source_license="ANOTHER_LICENSE"),),
        None,
        _policy(),
    )
    assert changed.status_code == 200
    assert changed.records[0].checksum == original.records[0].checksum
    assert dict(changed.headers)["ETag"] != dict(original.headers)["ETag"]
    assert dict(changed.headers)["Content-Type"] == "application/json"
    changed_sunset = translate_archived_truth(
        _query(if_none_match=dict(original.headers)["ETag"]),
        (_legacy(),),
        None,
        _policy(sunset_utc="2028-01-01T00:00:00Z"),
    )
    assert changed_sunset.status_code == 200
    assert dict(changed_sunset.headers)["ETag"] != dict(original.headers)["ETag"]


def test_public_translator_rejects_wrong_argument_types_without_echo() -> None:
    cases = (
        (object(), (), None, _policy(), "INVALID_QUERY_TYPE", ("query",)),
        (_query(), (), None, object(), "INVALID_POLICY_TYPE", ("policy",)),
        (_query(), (object(),), None, _policy(), "INVALID_RECORD_TYPE", ("legacy_records",)),
        (_query(), object(), None, _policy(), "INVALID_RECORD_TYPE", ("legacy_records",)),
        (_query(), (), lambda: (object(),), _policy(), "INVALID_RECORD_TYPE", ("mapped_records",)),
    )
    for query, legacy, mapped, policy, code, paths in cases:
        with pytest.raises(ArchivedTruthBoundaryError) as error:
            translate_archived_truth(query, legacy, mapped, policy)  # type: ignore[arg-type]
        assert error.value.code == code
        assert error.value.field_paths == paths
        assert str(error.value) == code
        assert error.value.args == (code,)
    with pytest.raises(ArchivedTruthBoundaryError) as write_error:
        deny_archived_truth_write("POST", object())  # type: ignore[arg-type]
    assert write_error.value.code == "INVALID_POLICY_TYPE"
