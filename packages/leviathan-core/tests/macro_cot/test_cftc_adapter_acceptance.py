from __future__ import annotations

import copy
import hashlib
import pickle
import socket
import urllib.request
from dataclasses import fields, replace
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.macro_cot.cftc_adapter import (
    CFTCAdaptedReleaseV1,
    CFTCAdapterError,
    CFTCAsOfViewV1,
    CFTCSourceEnvelopeV1,
    parse_cftc_release,
    select_cftc_asof,
)
from leviathan_core.macro_cot.models import COTMarketMapV1

FIXTURES = Path(__file__).parent / "fixtures" / "cftc"
REPORT_DAY = date(2026, 9, 15)
REPORT_NS = (REPORT_DAY - date(1970, 1, 1)).days * 86_400_000_000_000
PUBLISHED_NS = REPORT_NS + 3 * 86_400_000_000_000 + 19_800_000_000_000
RECEIVED_NS = PUBLISHED_NS + 1_000_000_000
AVAILABLE_NS = RECEIVED_NS + 1_000_000_000
COLUMNS = (
    ("report_date", "report_date"),
    ("report_family", "report_family"),
    ("cftc_market_code", "cftc_market_code"),
    ("mm_long", "mm_long"),
    ("mm_short", "mm_short"),
    ("open_interest", "open_interest"),
    ("mm_spreading", "mm_spreading"),
)


def _mapping() -> COTMarketMapV1:
    return COTMarketMapV1(
        market_id="energy",
        version="cftc-map-v1",
        constituent_ids=("c1", "c2"),
        effective_from=date(2020, 1, 1),
        constituent_codes=(("c1", "001"), ("c2", "002")),
    )


def _bytes(name: str = "synthetic_disaggregated.csv") -> bytes:
    return (FIXTURES / name).read_bytes()


def _envelope(
    payload: bytes | None = None,
    *,
    file_id: str = "fixture-cftc-001",
    revision: int = 0,
    preliminary: bool = False,
    published: int | None = PUBLISHED_NS,
    received: int = RECEIVED_NS,
    available: int = AVAILABLE_NS,
    layout: str = "synthetic-disaggregated-csv-v1",
    column_map: tuple[tuple[str, str], ...] = COLUMNS,
    report_family: str = "Disaggregated Futures",
    file_sha256: str | None = None,
) -> CFTCSourceEnvelopeV1:
    data = _bytes() if payload is None else payload
    return CFTCSourceEnvelopeV1(
        file_id=file_id,
        payload_bytes=data,
        file_sha256=hashlib.sha256(data).hexdigest() if file_sha256 is None else file_sha256,
        file_revision=revision,
        is_preliminary=preliminary,
        report_family=report_family,
        market_code_namespace="CFTC",
        market_id="energy",
        mapping_version="cftc-map-v1",
        units="contracts",
        column_map=column_map,
        source_url="https://fixtures.invalid/cftc/recorded.csv",
        published_ns=published,
        received_ns=received,
        available_ns=available,
        layout_id=layout,
    )


def _parse(**kwargs) -> CFTCAdaptedReleaseV1:
    return parse_cftc_release(_envelope(**kwargs), _mapping())


def test_recorded_fixture_maps_exact_constituent_rows_and_is_idempotent():
    envelope = _envelope()
    parsed = parse_cftc_release(envelope, _mapping())
    assert parsed.status == "READY"
    assert parsed.file_sha256 == hashlib.sha256(_bytes()).hexdigest()
    assert parsed.source_url == "https://fixtures.invalid/cftc/recorded.csv"
    assert [(row.constituent_id, row.cftc_market_code) for row in parsed.vintages] == [
        ("c1", "001"),
        ("c2", "002"),
    ]
    assert [row.report_date for row in parsed.vintages] == [REPORT_DAY, REPORT_DAY]
    assert [row.revision for row in parsed.vintages] == [0, 0]
    assert parsed.vintages[0].mm_long == 130
    assert parsed.vintages[0].mm_short == 70
    assert parsed.vintages[0].open_interest == 1000
    assert parsed.vintages[0].mm_spreading == 10
    assert parse_cftc_release(envelope, _mapping()) == parsed


def test_asof_visibility_filters_before_revision_reconciliation():
    final = _parse(file_id="final", revision=0, published=PUBLISHED_NS)
    later_preliminary = _parse(
        file_id="later-prelim",
        revision=8,
        preliminary=True,
        published=PUBLISHED_NS + 10,
        received=RECEIVED_NS + 10,
        available=AVAILABLE_NS + 10,
    )
    early = select_cftc_asof((final, later_preliminary), _mapping(), AVAILABLE_NS)
    assert early.visible_vintages == final.vintages
    assert early.selected_revision_ids == (("c1", REPORT_DAY, 0), ("c2", REPORT_DAY, 0))
    assert not early.is_revised
    late = select_cftc_asof((final, later_preliminary), _mapping(), AVAILABLE_NS + 10)
    assert len(late.visible_vintages) == 4
    assert late.selected_revision_ids == (("c1", REPORT_DAY, 0), ("c2", REPORT_DAY, 0))
    assert late.is_revised


def test_unknown_publication_time_is_never_visible_as_of():
    unknown = _parse(file_id="unknown-time", published=None)
    assert unknown.status == "VINTAGE_UNKNOWN"
    assert unknown.reason_codes == ("VINTAGE_UNKNOWN",)
    view = select_cftc_asof((unknown,), _mapping(), AVAILABLE_NS + 10**15)
    assert view.visible_vintages == ()
    assert view.status == "VINTAGE_UNKNOWN"
    assert view.reason_codes == ("VINTAGE_UNKNOWN",)


def test_tuesday_report_is_hidden_until_delayed_friday_publication_and_availability():
    release = _parse()
    for cut in (PUBLISHED_NS - 1, PUBLISHED_NS, RECEIVED_NS - 1, RECEIVED_NS, AVAILABLE_NS - 1):
        view = select_cftc_asof((release,), _mapping(), cut)
        assert view.visible_vintages == ()
        assert view.status == "UNAVAILABLE"
    visible = select_cftc_asof((release,), _mapping(), AVAILABLE_NS)
    assert all(row.report_date == REPORT_DAY for row in visible.visible_vintages)
    assert visible.status == "READY"


def test_missing_week_gap_and_latest_report_revision_label():
    current = _parse(file_id="current", revision=0)
    older_payload = _bytes().replace(b"2026-09-15", b"2026-09-01")
    older_revised = _parse(payload=older_payload, file_id="older-revised", revision=1)
    view = select_cftc_asof((older_revised, current), _mapping(), AVAILABLE_NS)
    assert view.gap_report_dates == (REPORT_DAY,)
    assert view.is_revised is False


def test_optional_constituent_id_must_match_cftc_code_binding():
    lines = _bytes().decode("ascii").splitlines()
    lines[0] += ",constituent_id"
    lines[1] += ",wrong-constituent"
    lines[2] += ",c2"
    payload = ("\n".join(lines) + "\n").encode("ascii")
    mapped_columns = (*COLUMNS, ("constituent_id", "constituent_id"))
    with pytest.raises(CFTCAdapterError) as caught:
        _parse(payload=payload, column_map=mapped_columns)
    assert caught.value.reason_code == "MAPPING_AMBIGUOUS"


@pytest.mark.parametrize("missing", ["mapping", "header", "value"])
def test_missing_mm_spreading_contract_component_is_schema_error(missing: str):
    payload = _bytes()
    column_map = COLUMNS
    if missing == "mapping":
        column_map = tuple(pair for pair in COLUMNS if pair[0] != "mm_spreading")
    elif missing == "header":
        lines = payload.decode("ascii").splitlines()
        lines = [",".join(line.split(",")[:-1]) for line in lines]
        payload = ("\n".join(lines) + "\n").encode("ascii")
    else:
        payload = payload.replace(b",10\n", b",\n", 1)
    with pytest.raises(CFTCAdapterError) as caught:
        _parse(payload=payload, column_map=column_map)
    assert caught.value.reason_code == "SCHEMA_MISSING_COLUMN"


@pytest.mark.parametrize(
    ("fixture", "code"),
    [
        ("missing_open_interest.csv", "SCHEMA_MISSING_COLUMN"),
        ("duplicate_conflict.csv", "SOURCE_CONFLICT"),
        ("mixed_report_family.csv", "MIXED_REPORT_FAMILY"),
        ("negative_position.csv", "INVALID_POSITION"),
    ],
)
def test_bad_recorded_csv_fails_closed_without_echoing_input(fixture: str, code: str):
    payload = _bytes(fixture)
    envelope = _envelope(payload)
    with pytest.raises(CFTCAdapterError) as caught:
        parse_cftc_release(envelope, _mapping())
    assert caught.value.reason_code == code
    assert fixture not in str(caught.value)
    assert payload.decode() not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize(
    ("payload", "column_map", "layout", "code"),
    [
        (None, COLUMNS, "other-layout", "UNSUPPORTED_LAYOUT"),
        (
            b"not the hashed bytes",
            COLUMNS,
            "synthetic-disaggregated-csv-v1",
            "SOURCE_HASH_MISMATCH",
        ),
        (
            None,
            tuple(pair for pair in COLUMNS if pair[0] != "open_interest"),
            "synthetic-disaggregated-csv-v1",
            "SCHEMA_MISSING_COLUMN",
        ),
    ],
)
def test_envelope_rejects_wrong_layout_hash_and_column_contract(payload, column_map, layout, code):
    if payload is not None:
        with pytest.raises(CFTCAdapterError) as caught:
            _envelope(payload=payload, file_sha256="0" * 64)
    else:
        with pytest.raises(CFTCAdapterError) as caught:
            _envelope(column_map=column_map, layout=layout)
    assert caught.value.reason_code == code


def test_unknown_code_and_mapping_effectivity_are_rejected():
    payload = _bytes().replace(b",002,", b",999,")
    with pytest.raises(CFTCAdapterError) as unknown:
        _parse(payload=payload)
    assert unknown.value.reason_code == "UNKNOWN_MARKET_CODE"

    mapping = COTMarketMapV1(
        market_id="energy",
        version="cftc-map-v1",
        constituent_ids=("c1", "c2"),
        effective_from=date(2026, 9, 16),
        constituent_codes=(("c1", "001"), ("c2", "002")),
    )
    with pytest.raises(CFTCAdapterError) as ineffective:
        parse_cftc_release(_envelope(), mapping)
    assert ineffective.value.reason_code == "MAPPING_VERSION_NOT_EFFECTIVE"


def test_whole_contract_decimal_lexemes_are_canonical_but_fractional_counts_reject():
    whole = _bytes().replace(b",130,70,1000,10", b",130.0,70.00,1000.0,10.0")
    parsed = _parse(payload=whole)
    assert parsed.vintages[0].mm_long == 130
    assert parsed.vintages[0].mm_short == 70
    fractional = _bytes().replace(b",130,70,1000,10", b",130.5,70,1000,10")
    with pytest.raises(CFTCAdapterError) as caught:
        _parse(payload=fractional)
    assert caught.value.reason_code == "INVALID_POSITION"


def test_report_family_and_release_time_are_checked():
    with pytest.raises(CFTCAdapterError) as family:
        _envelope(report_family="Futures Only")
    assert family.value.reason_code == "REPORT_FAMILY_MISMATCH"
    with pytest.raises(CFTCAdapterError) as before_report:
        _parse(published=REPORT_NS - 1, received=REPORT_NS, available=REPORT_NS)
    assert before_report.value.reason_code == "RELEASE_BEFORE_REPORT"
    with pytest.raises(CFTCAdapterError) as invalid_order:
        _envelope(published=RECEIVED_NS + 1, received=RECEIVED_NS, available=AVAILABLE_NS)
    assert invalid_order.value.reason_code == "INVALID_RELEASE_TIME"


@pytest.mark.parametrize(
    "bounds",
    [
        {"effective_from": datetime(2020, 1, 1)},
        {"effective_from": date(2020, 1, 1), "effective_to": datetime(2027, 1, 1)},
    ],
)
def test_datetime_effective_mapping_bounds_are_ambiguous(bounds):
    values = {
        "market_id": "energy",
        "version": "cftc-map-v1",
        "constituent_ids": ("c1", "c2"),
        "effective_from": date(2020, 1, 1),
        "constituent_codes": (("c1", "001"), ("c2", "002")),
    }
    values.update(bounds)
    mapping = COTMarketMapV1(**values)
    with pytest.raises(CFTCAdapterError) as caught:
        parse_cftc_release(_envelope(), mapping)
    assert caught.value.reason_code == "MAPPING_AMBIGUOUS"


def test_conflicting_source_file_identity_rejects_but_future_file_does_not_leak():
    first = _parse(file_id="same-file")
    changed = _bytes().replace(b",130,70,", b",131,70,")
    second = _parse(payload=changed, file_id="same-file")
    with pytest.raises(CFTCAdapterError) as conflict:
        select_cftc_asof((first, second), _mapping(), AVAILABLE_NS)
    assert conflict.value.reason_code == "SOURCE_CONFLICT"

    future = _parse(
        file_id="future",
        revision=2,
        published=PUBLISHED_NS + 100,
        received=RECEIVED_NS + 100,
        available=AVAILABLE_NS + 100,
    )
    baseline = select_cftc_asof((first,), _mapping(), AVAILABLE_NS)
    inserted = select_cftc_asof((first, future), _mapping(), AVAILABLE_NS)
    assert inserted == baseline


def test_source_adapter_never_opens_network_connections(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    assert parse_cftc_release(_envelope(), _mapping()).status == "READY"


@pytest.mark.parametrize("bad", [True, False])
def test_bool_is_not_accepted_as_revision_or_asof_integer(bad: bool):
    with pytest.raises(CFTCAdapterError):
        _envelope(revision=bad)
    release = _parse()
    with pytest.raises(CFTCAdapterError):
        select_cftc_asof((release,), _mapping(), bad)


@pytest.mark.parametrize("value", [CFTCAdaptedReleaseV1, CFTCAsOfViewV1])
def test_result_direct_construction_replace_and_clone_are_blocked(value):
    def direct_call():
        if value is CFTCAdaptedReleaseV1:
            return value(
                file_id="f",
                file_sha256="0" * 64,
                source_url="https://fixtures.invalid/x",
                market_id="energy",
                mapping_version="m",
                status="READY",
                vintages=(_parse().vintages[0],),
                published_ns=PUBLISHED_NS,
                received_ns=RECEIVED_NS,
                available_ns=AVAILABLE_NS,
            )
        return value(
            market_id="energy",
            mapping_version="m",
            asof_ns=AVAILABLE_NS,
            status="READY",
            visible_vintages=(_parse().vintages[0],),
            selected_revision_ids=(),
            is_revised=False,
            gap_report_dates=(),
            reason_codes=(),
        )

    with pytest.raises(CFTCAdapterError) as direct:
        direct_call()
    assert direct.value.reason_code == "RESULT_NOT_ISSUED"
    result = (
        _parse()
        if value is CFTCAdaptedReleaseV1
        else select_cftc_asof((_parse(),), _mapping(), AVAILABLE_NS)
    )
    with pytest.raises(CFTCAdapterError) as replaced:
        replace(result)
    assert replaced.value.reason_code == "RESULT_NOT_ISSUED"
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(result)


def test_envelope_copy_and_pickle_are_forbidden():
    envelope = _envelope()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(envelope)


def _dataclass_values(value):
    return {item.name: getattr(value, item.name) for item in fields(value)}


def _dataclass_snapshot_with_unset(value):
    snapshot = {}
    for item in fields(value):
        try:
            snapshot[item.name] = (True, getattr(value, item.name))
        except AttributeError:
            snapshot[item.name] = (False, None)
    return snapshot


def test_envelope_reinitialization_is_blocked_before_mutation():
    envelope = _envelope()
    before = (envelope.file_id, envelope.file_sha256, envelope.payload_bytes)
    values = _dataclass_values(envelope)
    values["file_sha256"] = "0" * 64
    with pytest.raises(CFTCAdapterError) as caught:
        envelope.__init__(**values)
    assert caught.value.reason_code == "RECORD_FROZEN"
    assert (envelope.file_id, envelope.file_sha256, envelope.payload_bytes) == before


@pytest.mark.parametrize("field,value", [("payload_bytes", b"tampered"), ("file_sha256", "0" * 64)])
def test_mutated_envelope_payload_or_hash_fails_parse(field: str, value: object):
    envelope = _envelope()
    object.__setattr__(envelope, field, value)
    with pytest.raises(CFTCAdapterError) as caught:
        parse_cftc_release(envelope, _mapping())
    assert caught.value.reason_code == "SOURCE_HASH_MISMATCH"


@pytest.mark.parametrize("result_kind", ["release", "view"])
def test_failed_issued_result_reinitialization_preserves_original(result_kind: str):
    release = _parse()
    result = (
        release
        if result_kind == "release"
        else select_cftc_asof((release,), _mapping(), AVAILABLE_NS)
    )
    before = _dataclass_values(result)
    with pytest.raises(CFTCAdapterError) as caught:
        result.__init__(**before)
    assert caught.value.reason_code == "RESULT_NOT_ISSUED"
    assert _dataclass_values(result) == before
    selected = select_cftc_asof((release,), _mapping(), AVAILABLE_NS)
    assert selected.status == "READY"
    if result_kind == "view":
        assert selected == result


@pytest.mark.parametrize("result_kind", ["release", "view"])
def test_state_and_dict_replacement_attempts_leave_issued_results_unchanged(result_kind: str):
    release = _parse()
    result = (
        release
        if result_kind == "release"
        else select_cftc_asof((release,), _mapping(), AVAILABLE_NS)
    )
    before = _dataclass_values(result)
    state_setter = getattr(result, "__setstate__", None)
    assert callable(state_setter)
    with pytest.raises(CFTCAdapterError) as state_error:
        state_setter({"status": "FORGED"})
    assert state_error.value.reason_code == "RESULT_NOT_ISSUED"
    with pytest.raises((AttributeError, TypeError, CFTCAdapterError)):
        object.__setattr__(result, "__dict__", {"status": "FORGED"})
    assert _dataclass_values(result) == before


@pytest.mark.parametrize("nested", [False, True])
def test_object_setattr_tampering_invalidates_issued_release_at_selection(nested: bool):
    release = _parse()
    if nested:
        object.__setattr__(release.vintages[0], "mm_long", Decimal("999"))
    else:
        object.__setattr__(release, "file_id", "tampered-file")
    with pytest.raises(CFTCAdapterError) as caught:
        select_cftc_asof((release,), _mapping(), AVAILABLE_NS)
    assert caught.value.reason_code == "RESULT_NOT_ISSUED"


@pytest.mark.parametrize("result_kind", ["release", "view"])
def test_deleted_first_slot_blocks_forged_reinitialization_without_other_mutation(result_kind: str):
    release = _parse()
    result = (
        release
        if result_kind == "release"
        else select_cftc_asof((release,), _mapping(), AVAILABLE_NS)
    )
    before = _dataclass_values(result)
    first_slot = fields(result)[0].name
    object.__delattr__(result, first_slot)
    after_delete = _dataclass_snapshot_with_unset(result)
    assert after_delete[first_slot] == (False, None)

    init_values = dict(before)
    init_values[first_slot] = "forged-identity"
    if result_kind == "release":
        init_values.update(status="VINTAGE_UNKNOWN", vintages=())
    else:
        init_values.update(status="UNAVAILABLE", visible_vintages=())
    with pytest.raises(CFTCAdapterError) as caught:
        result.__init__(**init_values)
    assert caught.value.reason_code == "RESULT_NOT_ISSUED"
    assert _dataclass_snapshot_with_unset(result) == after_delete
