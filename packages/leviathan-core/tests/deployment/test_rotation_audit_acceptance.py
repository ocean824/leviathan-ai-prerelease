"""Independent contract probes for DEP-ROTATION-AUDIT-001."""

from __future__ import annotations

import re

import pytest
from pydantic import BaseModel

from leviathan_core.deployment_rotation_audit import (
    RotationAuditError,
    create_rotation_audit_event,
    derive_restart_required_intent,
    require_restart_required_intent,
    require_rotation_audit_event,
)

NOW_NS = 1_800_000_000_000_000_000
BINDING_REF = "vault://leviathan-ai/live/aws/ORDER_API_KEY"


def _event(
    *,
    requires_restart: bool = True,
    prior_version_id: str = "version-17",
    new_version_id: str = "version-18",
    clock_ns=lambda: NOW_NS,
):
    return create_rotation_audit_event(
        binding_ref=BINDING_REF,
        prior_version_id=prior_version_id,
        new_version_id=new_version_id,
        requires_restart=requires_restart,
        clock_ns=clock_ns,
    )


def _assert_content_free(error: RotationAuditError, code: str, *sentinels: str) -> None:
    assert error.code == code
    rendered = str(error)
    assert rendered == code
    assert error.args == (code,)
    for sentinel in sentinels:
        assert sentinel not in rendered
        assert sentinel not in repr(error)


def _field_values(record: BaseModel) -> list[object]:
    return list(record.model_dump(mode="python").values())


def test_logical_reference_is_reduced_to_opaque_binding_identity() -> None:
    prior_label = "release-2026-10-06-1"
    new_label = "release-2026-10-06-2"
    event = _event(prior_version_id=prior_label, new_version_id=new_label)
    verified = require_rotation_audit_event(event)
    intent = derive_restart_required_intent(verified)
    assert intent is not None
    intent = require_restart_required_intent(intent)

    assert re.fullmatch(r"[0-9a-f]{64}", event.binding_id)
    assert event.binding_id in repr(event)
    assert BINDING_REF not in repr(event)
    assert BINDING_REF not in repr(intent)
    assert all(BINDING_REF not in str(value) for value in _field_values(event))
    assert all(BINDING_REF not in str(value) for value in _field_values(intent))
    assert re.fullmatch(r"[0-9a-f]{64}", event.prior_version_id_digest)
    assert re.fullmatch(r"[0-9a-f]{64}", event.new_version_id_digest)
    assert event.prior_version_id_digest == intent.prior_version_id_digest
    assert event.new_version_id_digest == intent.new_version_id_digest
    assert event.prior_version_id_digest != event.new_version_id_digest
    assert event.rotated_at_ns == intent.rotated_at_ns == NOW_NS
    assert intent.binding_id == event.binding_id
    assert re.fullmatch(r"[0-9a-f]{64}", intent.rotation_event_digest)
    for raw_label in (prior_label, new_label):
        for record in (event, intent):
            assert raw_label not in repr(record)
            assert raw_label not in record.model_dump_json()
            assert raw_label not in _field_values(record)


def test_prior_and_new_versions_must_differ() -> None:
    with pytest.raises(RotationAuditError) as failure:
        _event(prior_version_id="same-version", new_version_id="same-version")
    _assert_content_free(failure.value, "VERSION_UNCHANGED")


def test_rotation_uses_injected_clock_once_and_emits_no_intent_when_restart_is_false() -> None:
    clock_calls: list[int] = []

    def trusted_clock() -> int:
        clock_calls.append(1)
        return NOW_NS

    event = _event(requires_restart=False, clock_ns=trusted_clock)
    assert clock_calls == [1]
    assert event.rotated_at_ns == NOW_NS
    assert derive_restart_required_intent(require_rotation_audit_event(event)) is None


def test_invalid_clock_fails_closed_with_content_free_reason() -> None:
    for invalid_clock_value in (-1, True, 1 << 63):
        with pytest.raises(RotationAuditError) as failure:
            _event(clock_ns=lambda value=invalid_clock_value: value)
        _assert_content_free(failure.value, "CLOCK_INVALID")


def test_secret_looking_raw_value_is_rejected_without_echo() -> None:
    secret_looking = "sk_live_ACCEPTANCE_SENTINEL_9382"
    with pytest.raises(RotationAuditError) as failure:
        create_rotation_audit_event(
            binding_ref=secret_looking,
            prior_version_id="version-17",
            new_version_id="version-18",
            requires_restart=True,
            clock_ns=lambda: NOW_NS,
        )
    _assert_content_free(failure.value, "INVALID_BINDING_REFERENCE", secret_looking)


def test_tampered_issued_event_is_rejected() -> None:
    event = _event()
    object.__setattr__(event, "new_version_id_digest", "0" * 64)
    with pytest.raises(RotationAuditError) as failure:
        require_rotation_audit_event(event)
    _assert_content_free(failure.value, "EVENT_TAMPERED")


def test_tampered_issued_restart_intent_is_rejected() -> None:
    intent = derive_restart_required_intent(require_rotation_audit_event(_event()))
    assert intent is not None
    object.__setattr__(intent, "binding_id", "0" * 64)
    with pytest.raises(RotationAuditError) as failure:
        require_restart_required_intent(intent)
    _assert_content_free(failure.value, "INTENT_TAMPERED")


@pytest.mark.parametrize(
    "raw_version_id",
    [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.signaturepart",
        "sk_live_syntheticsecretvalue",
        "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        "xoxb-1234567890-abcdef1234567890",
        "AKIAIOSFODNN7EXAMPLE",
        "akiaiosfodnn7example",
        "a1b2c3d4e5f6a7b8c9d0e1f2",
    ],
)
@pytest.mark.parametrize("version_field", ["prior_version_id", "new_version_id"])
def test_secret_shaped_and_high_entropy_version_ids_are_rejected_without_echo(
    raw_version_id: str, version_field: str
) -> None:
    identifiers = {
        "prior_version_id": "version-17",
        "new_version_id": "version-18",
    }
    identifiers[version_field] = raw_version_id
    with pytest.raises(RotationAuditError) as failure:
        _event(**identifiers)
    _assert_content_free(failure.value, "INVALID_VERSION_ID", raw_version_id)
