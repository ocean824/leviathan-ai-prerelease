"""Independent acceptance tests for archived signal/session/state reads."""

from __future__ import annotations

import copy
import json
import pickle
import socket
from dataclasses import fields, replace
from decimal import ROUND_UP, Decimal, localcontext
from pathlib import Path
from unittest.mock import patch

import pytest

from leviathan_core.legacy_session import (
    ArchivedWriteDecisionV1,
    CanonicalSignalStateV1,
    LegacyBoundaryError,
    LegacyEnumMappingV1,
    LegacyMappingPolicyV1,
    LegacyReadRequestV1,
    LegacyReadResultV1,
    LegacySuccessorIdV1,
    deny_archived_write,
    translate_legacy_read,
)
from leviathan_core.seal import SealError, require, verify

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "mappings.json").read_text(encoding="utf-8")
)
TENANT = "tenant-synthetic-a"
ENTITY_ID = "347e8ca3-e4bb-4b2d-b8a0-e8b335ed59ee"
TRACE_ID = "trace-synthetic-001"


def _policy(
    mappings: tuple[LegacyEnumMappingV1, ...] | None = None,
    *,
    hard_sunset: bool = False,
    null_defaults: tuple[tuple[str, str], ...] = (),
) -> LegacyMappingPolicyV1:
    if mappings is None:
        row = FIXTURE["exact"]
        mappings = (
            LegacyEnumMappingV1(
                field=row["field"],
                canonical=row["canonical"],
                legacy=row["legacy"],
                compatible=row["compatible"],
            ),
        )
    return LegacyMappingPolicyV1(
        mapping_version=FIXTURE["mapping_version"],
        schema_sha256=FIXTURE["schema_sha256"],
        mappings=mappings,
        sunset_utc=FIXTURE["sunset_utc"],
        retention_start_ns=FIXTURE["retention_start_ns"],
        hard_sunset=hard_sunset,
        null_defaults=null_defaults,
    )


def _request(
    *,
    tenant_id: str = TENANT,
    entity_type: str = "signal",
    entity_id: str = ENTITY_ID,
    from_utc: str | None = None,
    to_utc: str | None = None,
) -> LegacyReadRequestV1:
    return LegacyReadRequestV1(
        tenant_id=tenant_id,
        entity_type=entity_type,
        entity_id=entity_id,
        trace_id=TRACE_ID,
        from_utc=from_utc,
        to_utc=to_utc,
    )


def _snapshot(**overrides: object) -> CanonicalSignalStateV1:
    fields: dict[str, object] = {
        "tenant_id": TENANT,
        "entity_type": "signal",
        "entity_id": ENTITY_ID,
        "as_of_ns": 1_730_000_000_000_000_000,
        "availability_ns": 1_730_000_000_000_000_001,
        "source_version": "canonical-snapshot-v7",
        "trace_id": TRACE_ID,
        "state": "ACTIVE",
        "session": None,
        "signal": None,
        "confidence": Decimal("0.75"),
        "session_start_ns": FIXTURE["dst_boundary_ns"][0],
        "session_end_ns": FIXTURE["dst_boundary_ns"][1],
        "evidence": ("synthetic-evidence-1",),
    }
    fields.update(overrides)
    return CanonicalSignalStateV1(**fields)


def test_exact_mapping_preserves_source_asof_evidence_and_schema_provenance() -> None:
    result: LegacyReadResultV1 = translate_legacy_read(_request(), _snapshot(), _policy())
    assert result.status_code == 200
    assert result.payload is not None
    assert result.payload.state == "RUNNING"
    assert result.payload.as_of_ns == 1_730_000_000_000_000_000
    assert result.payload.source_version == "canonical-snapshot-v7"
    assert result.availability_ns == 1_730_000_000_000_000_001
    assert result.payload.availability_ns == result.availability_ns
    assert result.payload.mapping_version == FIXTURE["mapping_version"]
    assert result.payload.schema_sha256 == FIXTURE["schema_sha256"]
    assert result.payload.trace_id == TRACE_ID
    assert result.payload.evidence == ("synthetic-evidence-1",)


def test_compatible_superset_mapping_is_degraded_with_the_declared_note() -> None:
    row = FIXTURE["compatible"]
    mapping = LegacyEnumMappingV1(**row)
    snapshot = _snapshot(state=None, session="PREMARKET_AND_REGULAR")
    result = translate_legacy_read(_request(), snapshot, _policy((mapping,)))
    assert result.payload is not None
    assert result.payload.session == "REGULAR_ONLY"
    assert result.payload.degraded
    assert any(row["note"] in note for note in result.payload.mapping_notes)


def test_unmappable_enum_reports_code_and_offending_field_path() -> None:
    result = translate_legacy_read(_request(), _snapshot(state="UNMAPPED_SYNTHETIC"), _policy(()))
    assert result.payload is None
    assert result.error is not None
    assert result.error.code == "UNMAPPABLE_STATE"
    assert "state" in result.error.field_paths


@pytest.mark.parametrize("entity_type", ["signal", "session", "instrument"])
def test_supported_entity_types_translate(entity_type: str) -> None:
    snapshot = _snapshot(entity_type=entity_type)
    result = translate_legacy_read(_request(entity_type=entity_type), snapshot, _policy())
    assert result.status_code == 200


@pytest.mark.parametrize(
    "request_overrides",
    [
        {"entity_id": "not-a-uuid"},
        {"entity_type": "unknown"},
        {"from_utc": "not-a-timestamp"},
        {"from_utc": "2024-01-02T00:00:00Z", "to_utc": "2024-01-01T00:00:00Z"},
    ],
)
def test_invalid_identity_type_or_utc_range_is_rejected(request_overrides: dict[str, str]) -> None:
    result = translate_legacy_read(_request(**request_overrides), _snapshot(), _policy())
    assert result.status_code == 400
    assert result.error is not None


def test_retention_boundary_is_clamped_and_reported() -> None:
    result = translate_legacy_read(
        _request(from_utc="2020-01-01T00:00:00Z"),
        _snapshot(),
        _policy(),
    )
    assert result.payload is not None
    assert result.payload.clipped


def test_null_fields_do_not_gain_invented_confidence_or_enum_values() -> None:
    result = translate_legacy_read(_request(), _snapshot(state=None, confidence=None), _policy(()))
    assert result.payload is not None
    assert result.payload.state is None
    assert result.payload.confidence is None


def test_cross_tenant_snapshot_is_indistinguishable_from_missing_snapshot() -> None:
    request = _request()
    other_tenant = _snapshot(tenant_id="tenant-synthetic-b")
    hidden = translate_legacy_read(request, other_tenant, _policy())
    absent = translate_legacy_read(request, None, _policy())
    assert hidden.status_code == absent.status_code == 404
    assert hidden.error is not None and absent.error is not None
    assert hidden.error.code == absent.error.code
    assert hidden.payload is None and absent.payload is None


@pytest.mark.parametrize(
    "start_ns,end_ns",
    [
        (FIXTURE["dst_boundary_ns"][0], FIXTURE["dst_boundary_ns"][1]),
        (FIXTURE["early_close_ns"][0], FIXTURE["early_close_ns"][1]),
    ],
)
def test_utc_session_boundaries_preserve_exact_ns(start_ns: int, end_ns: int) -> None:
    snapshot = _snapshot(session_start_ns=start_ns, session_end_ns=end_ns)
    result = translate_legacy_read(_request(), snapshot, _policy())
    assert result.payload is not None
    assert result.payload.session_start_ns == start_ns
    assert result.payload.session_end_ns == end_ns


@pytest.mark.parametrize("verb", ["POST", "PUT", "PATCH", "DELETE"])
def test_every_mutating_http_verb_has_archived_write_denial(verb: str) -> None:
    successor_id = LegacySuccessorIdV1(FIXTURE["successor_id"])
    decision: ArchivedWriteDecisionV1 = deny_archived_write(verb, successor_id)
    expected_path = f"/signals/{FIXTURE['successor_id']}"
    assert decision.status_code == 410
    assert decision.code == "LEGACY_ARCHIVED"
    assert decision.successor_id == successor_id
    assert decision.successor == expected_path
    assert expected_path in dict(decision.headers)["Link"]


def test_hard_sunset_denies_reads_with_migration_guidance() -> None:
    result = translate_legacy_read(_request(), _snapshot(), _policy(hard_sunset=True))
    assert result.status_code == 410
    assert result.error is not None
    assert f"/signals/{ENTITY_ID}" in dict(result.headers)["Link"]


def test_translation_leaves_the_injected_snapshot_unchanged() -> None:
    snapshot = _snapshot()
    before = (snapshot.state, snapshot.confidence, snapshot.evidence, snapshot.source_version)
    translate_legacy_read(_request(), snapshot, _policy())
    after = (snapshot.state, snapshot.confidence, snapshot.evidence, snapshot.source_version)
    assert after == before


def test_snapshot_available_after_requested_upper_time_is_never_returned_as_200() -> None:
    snapshot = _snapshot(
        as_of_ns=1_730_000_000_000_000_000,
        availability_ns=1_730_000_000_000_000_100,
    )
    result = translate_legacy_read(
        _request(to_utc="2024-10-27T03:33:20Z"),
        snapshot,
        _policy(),
    )
    assert result.status_code == 502
    assert result.error is not None
    assert result.error.code == "UPSTREAM_UNAVAILABLE"
    assert result.payload is None


def test_snapshot_available_exactly_at_requested_upper_time_is_included() -> None:
    cutoff_ns = 1_730_000_000_000_000_000
    result = translate_legacy_read(
        _request(to_utc="2024-10-27T03:33:20Z"),
        _snapshot(as_of_ns=cutoff_ns, availability_ns=cutoff_ns),
        _policy(),
    )
    assert result.status_code == 200
    assert result.payload is not None
    assert result.availability_ns == cutoff_ns


def test_retention_floor_is_used_when_from_utc_is_absent() -> None:
    floor = FIXTURE["retention_start_ns"]
    snapshot = _snapshot(as_of_ns=floor - 1, availability_ns=floor)
    result = translate_legacy_read(_request(), snapshot, _policy())
    assert result.status_code == 404
    assert result.payload is None or result.payload.as_of_ns >= floor
    if result.payload is not None:
        assert result.payload.clipped


def test_snapshot_at_retention_floor_is_included_when_from_utc_is_absent() -> None:
    floor = FIXTURE["retention_start_ns"]
    result = translate_legacy_read(
        _request(),
        _snapshot(as_of_ns=floor, availability_ns=floor),
        _policy(),
    )
    assert result.status_code == 200
    assert result.payload is not None
    assert result.payload.as_of_ns == floor


def test_unicode_digits_are_rejected_by_ascii_utc_timestamp_grammar() -> None:
    result = translate_legacy_read(
        _request(from_utc="٢٠٢٤-10-27T03:33:20Z"),
        _snapshot(),
        _policy(),
    )
    assert result.status_code == 400
    assert result.error is not None


def test_request_with_crlf_entity_id_is_rejected_without_link_injection() -> None:
    result = translate_legacy_read(
        _request(entity_id=f"{ENTITY_ID}\r\nX-Injected: yes"),
        _snapshot(),
        _policy(),
    )
    assert result.status_code == 400
    assert all(key.lower() != "link" for key, _ in result.headers)


def test_crlf_successor_is_rejected_before_write_descriptor_creation() -> None:
    with pytest.raises(LegacyBoundaryError) as error:
        LegacySuccessorIdV1("347e8ca3-e4bb-4b2d-b8a0-e8b335ed59ee\r\nX-Injected: yes")
    assert error.value.code == "INVALID_SUCCESSOR"


@pytest.mark.parametrize("successor", ["//evil", "/\\evil", "%2F%2Fevil", "https://x"])
def test_external_or_encoded_successor_never_produces_a_foreign_link(
    successor: str,
) -> None:
    with pytest.raises(LegacyBoundaryError) as constructor_error:
        LegacySuccessorIdV1(successor)
    assert constructor_error.value.code == "INVALID_SUCCESSOR"

    with pytest.raises(LegacyBoundaryError) as write_error:
        deny_archived_write("POST", successor)
    assert write_error.value.code == "INVALID_SUCCESSOR"


def test_wrong_request_object_raises_typed_boundary_error() -> None:
    with pytest.raises(LegacyBoundaryError) as error:
        translate_legacy_read(object(), _snapshot(), _policy())  # type: ignore[arg-type]
    assert error.value.code == "INVALID_REQUEST_TYPE"


def test_read_translation_is_offline_and_uses_only_the_injected_snapshot() -> None:
    def no_socket(*args, **kwargs):
        raise AssertionError("legacy translator attempted network access")

    with patch.object(socket, "socket", side_effect=no_socket):
        result = translate_legacy_read(_request(), _snapshot(), _policy())

    assert result.status_code == 200
    assert result.payload is not None
    assert result.payload.source_version == "canonical-snapshot-v7"


def test_unmapped_state_errors_never_echo_caller_values() -> None:
    canary = "SYNTHETIC-UNMAPPED-CANARY-704"
    result = translate_legacy_read(_request(), _snapshot(state=canary), _policy(()))

    assert result.status_code == 422
    assert result.error is not None
    assert result.error.code == "UNMAPPABLE_STATE"
    assert result.error.field_paths == ("state",)
    assert canary not in str(result.error)
    assert canary not in repr(result.error)


@pytest.mark.parametrize(
    "field,value",
    [
        ("as_of_ns", True),
        ("availability_ns", False),
        ("session_start_ns", True),
        ("session_end_ns", False),
    ],
)
def test_timestamp_integer_fields_reject_booleans(field: str, value: bool) -> None:
    with pytest.raises(LegacyBoundaryError) as error:
        _snapshot(**{field: value})
    assert error.value.code == "INVALID_TIME"


def test_policy_confidence_and_mapping_outputs_are_replay_stable() -> None:
    request = _request()
    snapshot = _snapshot(confidence=Decimal("0.50"))
    first = translate_legacy_read(request, snapshot, _policy())
    replay = translate_legacy_read(request, snapshot, _policy())
    with localcontext() as ambient:
        ambient.prec = 3
        ambient.rounding = ROUND_UP
        changed_context = translate_legacy_read(request, snapshot, _policy())

    assert replay == first
    assert changed_context == first
    assert first.payload is not None
    assert first.payload.confidence == Decimal("0.5")


@pytest.mark.parametrize(
    "factory",
    [
        lambda: _snapshot(as_of_ns=-10, availability_ns=-9),
        lambda: _snapshot(session_start_ns=-100, session_end_ns=-1),
        lambda: LegacyMappingPolicyV1(
            mapping_version=FIXTURE["mapping_version"],
            schema_sha256=FIXTURE["schema_sha256"],
            mappings=(),
            sunset_utc=FIXTURE["sunset_utc"],
            retention_start_ns=-1,
        ),
    ],
)
def test_negative_utc_ns_values_raise_typed_time_error(factory) -> None:
    with pytest.raises(LegacyBoundaryError) as error:
        factory()
    assert error.value.code == "INVALID_TIME"


def test_policy_replace_revalidates_negative_retention_floor() -> None:
    with pytest.raises(LegacyBoundaryError) as error:
        replace(_policy(), retention_start_ns=-1)
    assert error.value.code == "INVALID_TIME"


def test_policy_rejects_duplicate_and_conflicting_mappings_on_construction_and_replace() -> None:
    exact_row = LegacyEnumMappingV1(**FIXTURE["exact"])
    conflicting_row = LegacyEnumMappingV1(
        field=exact_row.field,
        canonical=exact_row.canonical,
        legacy="CONFLICTING_LEGACY_VALUE",
    )
    with pytest.raises(LegacyBoundaryError):
        _policy((exact_row, exact_row))
    with pytest.raises(LegacyBoundaryError):
        replace(_policy((exact_row,)), mappings=(exact_row, conflicting_row))
    with pytest.raises(LegacyBoundaryError):
        replace(
            _policy(),
            null_defaults=(("state", "DEFAULT_A"), ("state", "DEFAULT_B")),
        )


@pytest.mark.parametrize(
    "make_mapping",
    [
        lambda: LegacyEnumMappingV1(
            field="state", canonical="ACTIVE", legacy="RUNNING", compatible="false"
        ),
        lambda: LegacyMappingPolicyV1(
            mapping_version=FIXTURE["mapping_version"],
            schema_sha256=FIXTURE["schema_sha256"],
            mappings=(),
            sunset_utc=FIXTURE["sunset_utc"],
            retention_start_ns=FIXTURE["retention_start_ns"],
            hard_sunset="false",
        ),
    ],
)
def test_string_false_is_rejected_instead_of_becoming_truthy(make_mapping) -> None:
    with pytest.raises(LegacyBoundaryError) as error:
        make_mapping()
    assert error.value.code == "INVALID_MAPPING"


def test_confidence_requires_a_bounded_decimal_and_normalizes_equal_scales() -> None:
    at_precision_limit = Decimal("0." + "1" * 34)
    accepted = translate_legacy_read(
        _request(), _snapshot(confidence=at_precision_limit), _policy()
    )
    assert accepted.payload is not None
    assert accepted.payload.confidence == at_precision_limit

    result = translate_legacy_read(_request(), _snapshot(confidence=Decimal("0.50")), _policy())
    assert result.payload is not None
    assert result.payload.confidence == Decimal("0.5")
    assert str(result.payload.confidence) == "0.5"
    with pytest.raises(LegacyBoundaryError) as precision_error:
        _snapshot(confidence=Decimal("0." + "1" * 35))
    assert precision_error.value.code == "PRECISION_EXCEEDED"
    with pytest.raises(LegacyBoundaryError):
        _snapshot(confidence=Decimal("1E-999999"))
    with pytest.raises(LegacyBoundaryError):
        _snapshot(confidence=Decimal("1.01"))
    with pytest.raises(LegacyBoundaryError):
        _snapshot(confidence=0.5)


def test_models_freeze_evidence_and_result_across_replace_and_pickle() -> None:
    nested_evidence = ["synthetic-evidence"]
    try:
        snapshot = _snapshot(evidence=(nested_evidence,))
    except LegacyBoundaryError:
        snapshot = None
    else:
        nested_evidence.append("mutated")
        assert snapshot.evidence == ("synthetic-evidence",)

    result = translate_legacy_read(_request(), _snapshot(), _policy())
    with pytest.raises(LegacyBoundaryError):
        replace(result, headers=result.headers)
    with pytest.raises(LegacyBoundaryError):
        replace(result, headers=[])

    with pytest.raises(LegacyBoundaryError):
        LegacyReadResultV1(status_code=200, headers=())

    with pytest.raises((TypeError, ValueError)):
        replace(result, _seal=result._seal)

    for operation in (copy.copy, copy.deepcopy, lambda value: pickle.loads(pickle.dumps(value))):
        with pytest.raises(LegacyBoundaryError) as error:
            operation(result)
        assert error.value.code == "FROZEN_OBJECT"

    decision = deny_archived_write("POST", LegacySuccessorIdV1(FIXTURE["successor_id"]))
    for value in (_request(), _snapshot(), _policy(), result.payload, result, decision):
        for operation in (
            copy.copy,
            copy.deepcopy,
            lambda item: pickle.loads(pickle.dumps(item)),
        ):
            with pytest.raises(LegacyBoundaryError) as error:
                operation(value)
            assert error.value.code == "FROZEN_OBJECT"


def _dataclass_state(value: object) -> tuple[tuple[str, object], ...]:
    return tuple((field.name, getattr(value, field.name)) for field in fields(value))


@pytest.mark.parametrize("issued_kind", ["read", "write"])
def test_issued_outputs_reject_reinitialization_and_state_replacement_without_mutation(
    issued_kind: str,
) -> None:
    if issued_kind == "read":
        issued = translate_legacy_read(_request(), _snapshot(), _policy())
    else:
        issued = deny_archived_write("POST", LegacySuccessorIdV1(FIXTURE["successor_id"]))

    before = _dataclass_state(issued)
    with pytest.raises(LegacyBoundaryError) as reinit_error:
        if issued_kind == "read":
            type(issued).__init__(
                issued, status_code=400, headers=issued.headers, _issuer=issued._seal
            )
        else:
            type(issued).__init__(
                issued,
                status_code=200,
                code="CANARY_FORGED",
                successor_id=issued.successor_id,
                headers=issued.headers,
                _issuer=issued._seal,
            )
    assert reinit_error.value.code == "INVALID_RESULT_ISSUER"
    assert _dataclass_state(issued) == before


@pytest.mark.parametrize("issued_kind", ["read", "write"])
def test_issued_outputs_reject_setstate_without_mutation(issued_kind: str) -> None:
    if issued_kind == "read":
        issued = translate_legacy_read(_request(), _snapshot(), _policy())
    else:
        issued = deny_archived_write("POST", LegacySuccessorIdV1(FIXTURE["successor_id"]))
    before = _dataclass_state(issued)

    with pytest.raises(LegacyBoundaryError) as state_error:
        issued.__setstate__({"status_code": 400})
    assert state_error.value.code == "FROZEN_OBJECT"
    assert _dataclass_state(issued) == before


@pytest.mark.parametrize("issued_kind", ["read", "write"])
def test_issued_outputs_have_no_replaceable_instance_dict(issued_kind: str) -> None:
    if issued_kind == "read":
        issued = translate_legacy_read(_request(), _snapshot(), _policy())
    else:
        issued = deny_archived_write("POST", LegacySuccessorIdV1(FIXTURE["successor_id"]))
    before = _dataclass_state(issued)

    with pytest.raises(AttributeError):
        object.__setattr__(issued, "__dict__", {"status_code": 400})
    assert _dataclass_state(issued) == before


@pytest.mark.parametrize("issued_kind", ["read", "write"])
def test_seal_registry_binds_issued_identity_and_content(issued_kind: str) -> None:
    if issued_kind == "read":
        issued = translate_legacy_read(_request(), _snapshot(), _policy())
        tag = "lss001.read.v1"
    else:
        issued = deny_archived_write("POST", LegacySuccessorIdV1(FIXTURE["successor_id"]))
        tag = "lss001.write.v1"

    assert verify(issued, tag)
    twin = object.__new__(type(issued))
    for field in fields(issued):
        object.__setattr__(twin, field.name, getattr(issued, field.name))
    assert twin == issued
    assert not verify(twin, tag)
    with pytest.raises(SealError) as identity_error:
        require(twin, tag)
    assert identity_error.value.code == "SEAL_NOT_ISSUED"

    object.__setattr__(issued, "status_code", 400)
    assert not verify(issued, tag)
    with pytest.raises(SealError) as tamper_error:
        require(issued, tag)
    assert tamper_error.value.code == "SEAL_TAMPERED"


def test_result_and_error_replace_reject_open_status_and_error_codes() -> None:
    result = translate_legacy_read(_request(), _snapshot(), _policy())
    with pytest.raises(LegacyBoundaryError):
        replace(result, status_code=999)

    failed = translate_legacy_read(_request(), _snapshot(state="UNMAPPED"), _policy(()))
    assert failed.error is not None
    with pytest.raises(LegacyBoundaryError):
        replace(failed.error, code="ALLOW_TRADE")


def test_successful_result_rejects_link_to_a_different_valid_successor_uuid() -> None:
    result = translate_legacy_read(_request(), _snapshot(), _policy())
    assert result.status_code == 200
    other_successor = "e8222c7a-921a-4e58-8616-2108f91a117f"
    changed_headers = tuple(
        (
            name,
            f'</signals/{other_successor}>; rel="successor"' if name == "Link" else value,
        )
        for name, value in result.headers
    )
    assert result.payload is not None
    assert dict(result.headers)["Link"] == (
        f'</signals/{result.payload.entity_id}>; rel="successor"'
    )
    with pytest.raises(LegacyBoundaryError):
        replace(result, headers=changed_headers)


def test_successful_payload_rejects_inverted_session_interval_and_reattachment() -> None:
    result = translate_legacy_read(_request(), _snapshot(), _policy())
    assert result.payload is not None
    assert result.payload.session_end_ns is not None
    equal_boundary_payload = replace(result.payload, session_start_ns=result.payload.session_end_ns)
    assert equal_boundary_payload.session_start_ns == equal_boundary_payload.session_end_ns
    invalid_start = result.payload.session_end_ns + 1

    with pytest.raises(LegacyBoundaryError) as payload_error:
        replace(result.payload, session_start_ns=invalid_start)
    assert payload_error.value.code == "INVALID_TIME"

    with pytest.raises(LegacyBoundaryError) as result_error:
        replace(
            result,
            payload=replace(result.payload, session_start_ns=invalid_start),
        )
    assert result_error.value.code == "INVALID_TIME"

    with pytest.raises(LegacyBoundaryError):
        replace(result, payload=result.payload)
