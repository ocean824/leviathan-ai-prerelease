"""Worker checks for the pure archived session translator."""

import copy
import pickle
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from hashlib import sha256
from uuid import uuid4

import pytest

from leviathan_core.legacy_session import (
    CanonicalSignalStateV1,
    LegacyBoundaryError,
    LegacyEnumMappingV1,
    LegacyMappingPolicyV1,
    LegacyReadRequestV1,
    LegacySuccessorIdV1,
    deny_archived_write,
    translate_legacy_read,
)
from leviathan_core.legacy_session.models import _READ_RESULT_ISSUER

_ID = str(uuid4())


def _policy(**changes: object) -> LegacyMappingPolicyV1:
    values = {
        "mapping_version": "fixture-1",
        "schema_sha256": sha256(b"legacy-v1.3-fixture").hexdigest(),
        "mappings": (
            LegacyEnumMappingV1("state", "READY", "ACTIVE"),
            LegacyEnumMappingV1("state", "READY_SUPERSET", "ACTIVE", True, "reduced detail"),
            LegacyEnumMappingV1("session", "NY", "NEW_YORK"),
            LegacyEnumMappingV1("signal", "LONG", "BUY"),
        ),
        "sunset_utc": "2027-01-01T00:00:00Z",
        "retention_start_ns": 1_700_000_000_000_000_000,
    }
    values.update(changes)
    return LegacyMappingPolicyV1(**values)


def _request(**changes: object) -> LegacyReadRequestV1:
    values = {"tenant_id": "tenant-a", "entity_type": "signal", "entity_id": _ID, "trace_id": "t1"}
    values.update(changes)
    return LegacyReadRequestV1(**values)


def _snapshot(**changes: object) -> CanonicalSignalStateV1:
    values = {
        "tenant_id": "tenant-a",
        "entity_type": "signal",
        "entity_id": _ID,
        "as_of_ns": 1_750_000_000_000_000_000,
        "availability_ns": 1_750_000_000_000_000_001,
        "source_version": "canonical-7",
        "trace_id": "source-trace",
        "state": "READY",
        "session": "NY",
        "signal": "LONG",
        "confidence": Decimal("0.75"),
        "session_start_ns": 1_750_000_000_000_000_000,
        "session_end_ns": 1_750_000_000_000_000_100,
        "evidence": ("immutable-key",),
    }
    values.update(changes)
    return CanonicalSignalStateV1(**values)


def test_exact_degraded_and_unmappable() -> None:
    exact = translate_legacy_read(_request(), _snapshot(), _policy())
    assert exact.status_code == 200 and exact.payload is not None
    assert exact.payload.state == "ACTIVE"
    assert exact.payload.degraded is False
    assert exact.payload.confidence == Decimal("0.75")
    assert exact.payload.source_version == "canonical-7"
    assert exact.schema_sha256 == _policy().schema_sha256
    assert exact.payload.schema_sha256 == exact.schema_sha256
    assert exact.payload.session_start_ns == 1_750_000_000_000_000_000

    approximate = translate_legacy_read(_request(), _snapshot(state="READY_SUPERSET"), _policy())
    assert approximate.payload is not None
    assert approximate.payload.degraded is True
    assert approximate.payload.mapping_notes == ("state: reduced detail",)

    missing = translate_legacy_read(_request(), _snapshot(state="UNRECOGNIZED"), _policy())
    assert missing.status_code == 422
    assert missing.error is not None and missing.error.field_paths == ("state",)
    assert "UNRECOGNIZED" not in repr(missing.error)


def test_request_privacy_clamp_and_sunset() -> None:
    assert (
        translate_legacy_read(_request(entity_id="not-a-uuid"), None, _policy()).status_code == 400
    )
    assert (
        translate_legacy_read(_request(), _snapshot(tenant_id="other"), _policy()).status_code
        == 404
    )
    clipped = translate_legacy_read(
        _request(from_utc="2023-01-01T00:00:00Z"), _snapshot(), _policy()
    )
    assert clipped.payload is not None and clipped.payload.clipped
    assert (
        translate_legacy_read(
            _request(from_utc="2025-01-01T00:00:00-05:00"), _snapshot(), _policy()
        ).status_code
        == 400
    )
    assert (
        translate_legacy_read(_request(), _snapshot(), _policy(hard_sunset=True)).status_code == 410
    )


def test_utc_boundary_and_immutable_source() -> None:
    # Adjacent UTC instants can straddle both spring and fall local clock changes.
    for start, end in (
        (1_741_503_599_000_000_000, 1_741_503_600_000_000_000),
        (1_762_066_799_000_000_000, 1_762_066_800_000_000_000),
    ):
        result = translate_legacy_read(
            _request(), _snapshot(session_start_ns=start, session_end_ns=end), _policy()
        )
        assert result.payload is not None
        assert (result.payload.session_start_ns, result.payload.session_end_ns) == (start, end)
    with pytest.raises(FrozenInstanceError):
        _snapshot().state = "MUTATED"  # type: ignore[misc]


def test_all_writes_denied() -> None:
    for verb in ("POST", "PUT", "PATCH", "DELETE"):
        decision = deny_archived_write(verb, LegacySuccessorIdV1(_ID))
        assert (decision.status_code, decision.code) == (410, "LEGACY_ARCHIVED")
        assert decision.headers[0][0] == "Link"
        assert decision.successor == f"/signals/{_ID}"


def test_point_in_time_availability_and_implicit_retention_floor() -> None:
    unavailable = translate_legacy_read(
        _request(to_utc="2025-06-15T15:06:40Z"), _snapshot(), _policy()
    )
    assert unavailable.status_code == 502
    assert unavailable.error is not None and unavailable.error.code == "UPSTREAM_UNAVAILABLE"
    assert unavailable.availability_ns == _snapshot().availability_ns
    before_retention = translate_legacy_read(
        _request(),
        _snapshot(
            as_of_ns=1_699_999_999_999_999_999,
            availability_ns=1_700_000_000_000_000_000,
        ),
        _policy(),
    )
    assert before_retention.status_code == 404
    complete = translate_legacy_read(_request(), _snapshot(), _policy())
    assert complete.payload is not None
    assert complete.availability_ns == complete.payload.availability_ns


def test_header_grammar_and_typed_boundary_errors() -> None:
    injected = translate_legacy_read(
        _request(entity_id=_ID + "\r\nX-Injected: yes"), None, _policy()
    )
    assert injected.status_code == 400
    assert all("\r" not in value and "\n" not in value for _, value in injected.headers)
    with pytest.raises(LegacyBoundaryError) as successor_error:
        deny_archived_write("PATCH", "/v2/signals/x\r\nX-Injected: yes")
    assert successor_error.value.code == "INVALID_SUCCESSOR"
    with pytest.raises(LegacyBoundaryError, match="INVALID_SUCCESSOR"):
        LegacySuccessorIdV1("/v2\nX-Injected")
    with pytest.raises(LegacyBoundaryError) as request_error:
        translate_legacy_read("wrong type", None, _policy())  # type: ignore[arg-type]
    assert request_error.value.code == "INVALID_REQUEST_TYPE"
    malformed = translate_legacy_read(_request(from_utc=123), None, _policy())  # type: ignore[arg-type]
    assert malformed.status_code == 400
    assert translate_legacy_read(
        _request(from_utc="٢٠٢٥-06-15T15:06:40Z"), None, _policy()
    ).status_code == 400


def test_cycle_two_closed_policy_outputs_and_fixed_links() -> None:
    with pytest.raises(LegacyBoundaryError, match="INVALID_MAPPING"):
        LegacyEnumMappingV1("state", "OTHER", "OLD", compatible=True)
    policy = _policy()
    with pytest.raises(LegacyBoundaryError, match="INVALID_MAPPING"):
        replace(policy, mappings=(*policy.mappings, policy.mappings[0]))
    with pytest.raises(LegacyBoundaryError, match="INVALID_MAPPING"):
        replace(policy, null_defaults=(("state", "A"), ("state", "B")))

    success = translate_legacy_read(_request(), _snapshot(), policy)
    assert dict(success.headers)["Link"] == f'</signals/{_ID}>; rel="successor"'
    with pytest.raises(LegacyBoundaryError, match="INVALID_RESULT"):
        replace(success, status_code=999)
    with pytest.raises(LegacyBoundaryError, match="INVALID_RESULT"):
        replace(success, headers=(*success.headers[:-1], ("Link", '<//evil>; rel="successor"')))
    failed = translate_legacy_read(_request(), _snapshot(state="UNMAPPED"), policy)
    assert failed.error is not None
    with pytest.raises(LegacyBoundaryError, match="INVALID_RESULT"):
        replace(failed.error, code="ALLOW_TRADE")


def test_cycle_three_sealed_result_link_and_payload_interval() -> None:
    result = translate_legacy_read(_request(), _snapshot(), _policy())
    assert result.payload is not None
    other_id = str(uuid4())
    wrong_link = (*result.headers[:-1], ("Link", f'</signals/{other_id}>; rel="successor"'))
    with pytest.raises(LegacyBoundaryError, match="INVALID_RESULT_ISSUER"):
        replace(result, headers=wrong_link)
    with pytest.raises(LegacyBoundaryError, match="INVALID_RESULT"):
        replace(result, headers=wrong_link, _issuer=_READ_RESULT_ISSUER)
    with pytest.raises(LegacyBoundaryError, match="INVALID_RESULT_ISSUER"):
        replace(result, headers=result.headers)
    with pytest.raises((TypeError, ValueError)):
        replace(result, _seal=True)
    with pytest.raises(LegacyBoundaryError, match="INVALID_RESULT_ISSUER"):
        type(result)(
            status_code=200,
            headers=result.headers,
            payload=result.payload,
            schema_sha256=result.schema_sha256,
            availability_ns=result.availability_ns,
        )
    assert result.payload.session_end_ns is not None
    with pytest.raises(LegacyBoundaryError, match="INVALID_TIME"):
        replace(result.payload, session_start_ns=result.payload.session_end_ns + 1)
    assert replace(
        result.payload, session_start_ns=result.payload.session_end_ns
    ).session_start_ns == result.payload.session_end_ns

    decision = deny_archived_write("POST", LegacySuccessorIdV1(_ID))
    with pytest.raises(LegacyBoundaryError, match="INVALID_RESULT_ISSUER"):
        replace(decision, headers=decision.headers)
    with pytest.raises((TypeError, ValueError)):
        replace(decision, _seal=True)


def test_typed_booleans_nonnegative_ns_and_exact_confidence() -> None:
    with pytest.raises(LegacyBoundaryError) as time_error:
        _snapshot(as_of_ns=-1)
    assert time_error.value.code == "INVALID_TIME"
    with pytest.raises(LegacyBoundaryError, match="INVALID_MAPPING"):
        LegacyEnumMappingV1("state", "READY", "ACTIVE", compatible="false")  # type: ignore[arg-type]
    with pytest.raises(LegacyBoundaryError, match="INVALID_MAPPING"):
        _policy(hard_sunset="false")
    first = _snapshot(confidence=Decimal("0.5"))
    second = _snapshot(confidence=Decimal("0.50"))
    assert first.confidence == second.confidence == Decimal("0.5")
    assert str(first.confidence) == str(second.confidence)
    with pytest.raises(LegacyBoundaryError, match="INVALID_CONFIDENCE"):
        _snapshot(confidence=Decimal("1E-999999"))
    with pytest.raises(LegacyBoundaryError) as precision_error:
        _snapshot(confidence=Decimal("0." + "1" * 35))
    assert precision_error.value.code == "PRECISION_EXCEEDED"
    trailing_zeros = _snapshot(confidence=Decimal("1." + "0" * 40))
    assert trailing_zeros.confidence == Decimal("1")
    assert str(trailing_zeros.confidence) == "1"


def test_copy_pickle_replace_and_deep_freeze() -> None:
    snapshot = _snapshot()
    result = translate_legacy_read(_request(), snapshot, _policy())
    for value in (snapshot, _policy(), result):
        with pytest.raises(LegacyBoundaryError, match="FROZEN_OBJECT"):
            copy.copy(value)
        with pytest.raises(LegacyBoundaryError, match="FROZEN_OBJECT"):
            copy.deepcopy(value)
        with pytest.raises(LegacyBoundaryError, match="FROZEN_OBJECT"):
            pickle.dumps(value)
    with pytest.raises(LegacyBoundaryError):
        _snapshot(evidence=(["e1"],))
    with pytest.raises(LegacyBoundaryError):
        replace(result, headers=[])
    reconstructed = replace(snapshot, confidence=Decimal("0.50"), evidence=["immutable"])
    assert reconstructed.evidence == ("immutable",)
    assert str(reconstructed.confidence) == "0.5"
