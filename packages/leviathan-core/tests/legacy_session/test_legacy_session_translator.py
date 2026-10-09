"""Worker checks for the staged v1.3 fixture translator's shared boundaries."""

from dataclasses import replace
from decimal import Decimal, localcontext

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
from leviathan_core.seal import SealError, require, verify

_ENTITY_ID = "907689ec-2f57-4458-91e7-81fe3852ecfa"
_READ_TAG = "lss001.read.v1"
_WRITE_TAG = "lss001.write.v1"


def _read(confidence: Decimal = Decimal("0.5000")):
    request = LegacyReadRequestV1("tenant", "signal", _ENTITY_ID, "trace")
    snapshot = CanonicalSignalStateV1(
        tenant_id="tenant",
        entity_type="signal",
        entity_id=_ENTITY_ID,
        as_of_ns=1_750_000_000_000_000_000,
        availability_ns=1_750_000_000_000_000_000,
        source_version="synthetic-v1.3",
        trace_id="source-trace",
        state="READY",
        confidence=confidence,
        session_start_ns=1_750_000_000_000_000_000,
        session_end_ns=1_750_000_000_000_000_100,
        evidence=("synthetic-evidence",),
    )
    policy = LegacyMappingPolicyV1(
        mapping_version="synthetic-v1.3",
        schema_sha256="a" * 64,
        mappings=(LegacyEnumMappingV1("state", "READY", "ACTIVE"),),
        sunset_utc="2027-01-01T00:00:00Z",
        retention_start_ns=0,
    )
    return translate_legacy_read(request, snapshot, policy)


def test_fixture_results_use_shared_identity_and_content_seals() -> None:
    result = _read()
    decision = deny_archived_write("PATCH", LegacySuccessorIdV1(_ENTITY_ID))
    assert result.status_code == 200 and result.payload is not None
    assert result.payload.state == "ACTIVE"
    assert verify(result, _READ_TAG) and require(result, _READ_TAG) is result
    assert verify(decision, _WRITE_TAG) and require(decision, _WRITE_TAG) is decision
    assert not verify(result, _WRITE_TAG) and not verify(decision, _READ_TAG)

    with pytest.raises(LegacyBoundaryError) as copied_seal:
        replace(result, _issuer=result._seal)
    assert copied_seal.value.code == "INVALID_RESULT_ISSUER"
    with pytest.raises((TypeError, ValueError)):
        replace(result, _seal=result._seal)
    assert verify(result, _READ_TAG)


def test_issued_results_reject_reinitialization_and_detect_tamper() -> None:
    result = _read()
    assert result.payload is not None
    with pytest.raises(LegacyBoundaryError) as reinit:
        type(result).__init__(
            result,
            result.status_code,
            result.headers,
            result.payload,
            result.error,
            result.schema_sha256,
            result.availability_ns,
            result._seal,
        )
    assert reinit.value.code == "INVALID_RESULT_ISSUER"
    assert verify(result, _READ_TAG)
    with pytest.raises(LegacyBoundaryError) as setstate:
        result.__setstate__({"headers": ()})
    assert setstate.value.code == "FROZEN_OBJECT"
    with pytest.raises(AttributeError):
        object.__setattr__(result, "__dict__", {})

    object.__setattr__(result.payload, "state", "FORGED")
    assert not verify(result, _READ_TAG)
    with pytest.raises(SealError) as tampered:
        require(result, _READ_TAG)
    assert tampered.value.code == "SEAL_TAMPERED"


def test_confidence_uses_exact_bounded_numeric_canonicalization() -> None:
    with localcontext() as context:
        context.prec = 2
        context.Emax = 2
        context.Emin = -2
        result = _read(Decimal("0.1234567890123456789012345678901234"))
    assert result.payload is not None
    assert str(result.payload.confidence) == "0.1234567890123456789012345678901234"
    assert str(_read().payload.confidence) == "0.5"  # type: ignore[union-attr]
    with pytest.raises(LegacyBoundaryError) as precision:
        _read(Decimal("0." + "1" * 35))
    assert precision.value.code == "PRECISION_EXCEEDED"
