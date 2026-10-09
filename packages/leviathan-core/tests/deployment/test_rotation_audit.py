from __future__ import annotations

import copy
import hashlib
import pickle

import pytest
from pydantic import BaseModel

from leviathan_core.deployment_rotation_audit import (
    RestartRequiredDeploymentAuditIntentV1,
    RotationAuditCode,
    RotationAuditError,
    RotationAuditEventV1,
    create_rotation_audit_event,
    derive_restart_required_intent,
    require_restart_required_intent,
    require_rotation_audit_event,
)
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import SealError

_REFERENCE = "vault://leviathan-ai/development/aws-secrets-manager/DB_PASSWORD"
_MAX_NS = (1 << 63) - 1


def _event(*, requires_restart: bool = True):
    calls = 0

    def clock() -> int:
        nonlocal calls
        calls += 1
        return 1_800_000_000_123_456_789

    result = create_rotation_audit_event(
        binding_ref=_REFERENCE,
        prior_version_id="version-1",
        new_version_id="version-2",
        requires_restart=requires_restart,
        clock_ns=clock,
    )
    assert calls == 1
    return result


def _assert_error(code: RotationAuditCode, callback) -> None:
    with pytest.raises(RotationAuditError) as captured:
        callback()
    assert captured.value.code == code.value
    assert str(captured.value) == code.value
    assert captured.value.args == (code.value,)


def test_event_contains_only_domain_separated_binding_identity_and_trusted_time() -> None:
    calls: list[int] = []

    def clock() -> int:
        calls.append(1)
        return 1_800_000_000_123_456_789

    event = create_rotation_audit_event(
        binding_ref=_REFERENCE,
        prior_version_id="version-1",
        new_version_id="version-2",
        requires_restart=True,
        clock_ns=clock,
    )

    expected_binding_id = hashlib.sha256(
        canonical_json(
            {
                "domain": "leviathan.dep.rotation.binding.v1",
                "binding_ref": _REFERENCE,
            }
        )
    ).hexdigest()
    assert calls == [1]
    assert event.binding_id == expected_binding_id
    assert event.rotated_at_ns == 1_800_000_000_123_456_789
    expected_prior_version_digest = hashlib.sha256(
        canonical_json(
            {
                "domain": "leviathan.dep.rotation.version.v1",
                "version_id": "version-1",
            }
        )
    ).hexdigest()
    expected_new_version_digest = hashlib.sha256(
        canonical_json(
            {
                "domain": "leviathan.dep.rotation.version.v1",
                "version_id": "version-2",
            }
        )
    ).hexdigest()
    assert event.prior_version_id_digest == expected_prior_version_digest
    assert event.new_version_id_digest == expected_new_version_digest
    assert require_rotation_audit_event(event) is event
    serialized = event.model_dump_json()
    assert _REFERENCE not in serialized
    assert "DB_PASSWORD" not in serialized
    assert "binding_ref" not in serialized
    assert "version-1" not in serialized
    assert "version-2" not in repr(event)


def test_restart_intent_is_sealed_and_bound_to_the_complete_rotation_event() -> None:
    event = _event()
    intent = derive_restart_required_intent(event)

    assert type(intent) is RestartRequiredDeploymentAuditIntentV1
    assert intent is not None
    assert require_restart_required_intent(intent) is intent
    assert intent.binding_id == event.binding_id
    assert intent.prior_version_id_digest == event.prior_version_id_digest
    assert intent.new_version_id_digest == event.new_version_id_digest
    assert intent.rotated_at_ns == event.rotated_at_ns
    assert intent.requires_restart is True
    assert len(intent.rotation_event_digest) == 64
    assert _REFERENCE not in intent.model_dump_json()
    assert "version-1" not in intent.model_dump_json()
    assert "version-2" not in repr(intent)


def test_no_restart_event_produces_no_deployment_restart_intent() -> None:
    assert derive_restart_required_intent(_event(requires_restart=False)) is None


@pytest.mark.parametrize(
    "binding_ref",
    [
        "",
        "vault://other-project/development/aws-secrets-manager/DB_PASSWORD",
        "vault://leviathan-ai/staging/aws-secrets-manager/DB_PASSWORD",
        "vault://leviathan-ai/development/AWS/DB_PASSWORD",
        "sk_live_SECRET_CANARY_VALUE",
        "API_TOKEN_CANARY_VALUE",
    ],
)
def test_invalid_or_secret_shaped_binding_reference_is_rejected_without_echo(
    binding_ref: str,
) -> None:
    canary = "SECRET_CANARY_VALUE" if "CANARY" in binding_ref else ""
    _assert_error(
        RotationAuditCode.INVALID_BINDING_REFERENCE,
        lambda: create_rotation_audit_event(
            binding_ref=binding_ref,
            prior_version_id="version-1",
            new_version_id="version-2",
            requires_restart=True,
            clock_ns=lambda: 1,
        ),
    )
    try:
        create_rotation_audit_event(
            binding_ref=binding_ref,
            prior_version_id="version-1",
            new_version_id="version-2",
            requires_restart=True,
            clock_ns=lambda: 1,
        )
    except RotationAuditError as exc:
        if canary:
            assert canary not in str(exc)
            assert canary not in repr(exc)


@pytest.mark.parametrize(
    ("prior_version_id", "new_version_id"),
    [
        ("version-1", "version-1"),
        ("sk_live_CANARY_SECRET_VALUE", "version-2"),
        ("version-1", "password-canary"),
        ("version/1", "version-2"),
    ],
)
def test_invalid_or_equal_version_identifiers_fail_closed(
    prior_version_id: str, new_version_id: str
) -> None:
    expected = (
        RotationAuditCode.VERSION_UNCHANGED
        if prior_version_id == new_version_id
        else RotationAuditCode.INVALID_VERSION_ID
    )
    _assert_error(
        expected,
        lambda: create_rotation_audit_event(
            binding_ref=_REFERENCE,
            prior_version_id=prior_version_id,
            new_version_id=new_version_id,
            requires_restart=True,
            clock_ns=lambda: 1,
        ),
    )


@pytest.mark.parametrize(
    "version_id",
    [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature-canary-value",
        "eyjhbgljijoxx.eyjzdwi6mtizndu2nzg5ma.signaturevalue",
        "sk_live_canarytokenvalue",
        "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        "xoxb-canarytokenvalue",
        "akiaiosfodnn7example",
        "9fe2a0d4c8b17e6a3d5c0b9f8a1e6d2c",
    ],
)
def test_token_shaped_version_ids_are_rejected_without_echo(version_id: str) -> None:
    with pytest.raises(RotationAuditError) as captured:
        create_rotation_audit_event(
            binding_ref=_REFERENCE,
            prior_version_id=version_id,
            new_version_id="version-2",
            requires_restart=True,
            clock_ns=lambda: 10,
        )
    assert captured.value.code == RotationAuditCode.INVALID_VERSION_ID.value
    assert version_id not in str(captured.value)
    assert version_id not in repr(captured.value)
    assert "version_id" not in repr(captured.value)


@pytest.mark.parametrize("requires_restart", [0, 1, None, "true"])
def test_restart_flag_requires_exact_bool(requires_restart: object) -> None:
    _assert_error(
        RotationAuditCode.INVALID_RESTART_FLAG,
        lambda: create_rotation_audit_event(
            binding_ref=_REFERENCE,
            prior_version_id="version-1",
            new_version_id="version-2",
            requires_restart=requires_restart,  # type: ignore[arg-type]
            clock_ns=lambda: 1,
        ),
    )


class _IntSubclass(int):
    pass


@pytest.mark.parametrize("now_ns", [True, 1.0, "1", None, -1, _MAX_NS + 1, _IntSubclass(5)])
def test_invalid_clock_values_fail_without_echo(now_ns: object) -> None:
    calls = 0

    def clock() -> int:
        nonlocal calls
        calls += 1
        return now_ns  # type: ignore[return-value]

    _assert_error(
        RotationAuditCode.CLOCK_INVALID,
        lambda: create_rotation_audit_event(
            binding_ref=_REFERENCE,
            prior_version_id="version-1",
            new_version_id="version-2",
            requires_restart=True,
            clock_ns=clock,
        ),
    )
    assert calls == 1


def test_clock_failure_is_content_free_and_called_once() -> None:
    calls = 0

    def clock() -> int:
        nonlocal calls
        calls += 1
        raise RuntimeError("SECRET_CANARY_VALUE")

    try:
        create_rotation_audit_event(
            binding_ref=_REFERENCE,
            prior_version_id="version-1",
            new_version_id="version-2",
            requires_restart=True,
            clock_ns=clock,
        )
    except RotationAuditError as exc:
        assert exc.code == RotationAuditCode.CLOCK_INVALID.value
        assert "SECRET_CANARY_VALUE" not in str(exc)
        assert "SECRET_CANARY_VALUE" not in repr(exc)
    else:
        pytest.fail("invalid clock should fail closed")
    assert calls == 1


def test_validation_precedes_hashing_and_clock_read() -> None:
    calls = 0

    def clock() -> int:
        nonlocal calls
        calls += 1
        return 1

    _assert_error(
        RotationAuditCode.INVALID_VERSION_ID,
        lambda: create_rotation_audit_event(
            binding_ref=_REFERENCE,
            prior_version_id="SECRET_CANARY_VALUE",
            new_version_id="version-2",
            requires_restart=True,
            clock_ns=clock,
        ),
    )
    assert calls == 0


def test_direct_construction_and_deserialization_cannot_issue_events() -> None:
    values = {
        "binding_id": "0" * 64,
        "prior_version_id_digest": "1" * 64,
        "new_version_id_digest": "2" * 64,
        "rotated_at_ns": 1,
        "requires_restart": True,
    }
    _assert_error(
        RotationAuditCode.EVENT_UNISSUED,
        lambda: RotationAuditEventV1(**values),
    )
    _assert_error(
        RotationAuditCode.EVENT_UNISSUED,
        lambda: RotationAuditEventV1.model_validate(values),
    )
    with pytest.raises(SealError):
        RotationAuditEventV1.model_construct(**values)
    _assert_error(
        RotationAuditCode.INTENT_UNISSUED,
        lambda: RestartRequiredDeploymentAuditIntentV1(
            **{
                **values,
                "rotation_event_digest": "1" * 64,
            }
        ),
    )


def test_unissued_and_tampered_events_or_intents_are_rejected() -> None:
    event = _event()
    intent = derive_restart_required_intent(event)
    assert intent is not None

    unissued_event = object.__new__(RotationAuditEventV1)
    _assert_error(
        RotationAuditCode.EVENT_UNISSUED,
        lambda: require_rotation_audit_event(unissued_event),
    )
    object.__setattr__(event, "new_version_id_digest", "3" * 64)
    _assert_error(
        RotationAuditCode.EVENT_TAMPERED,
        lambda: require_rotation_audit_event(event),
    )
    object.__setattr__(intent, "new_version_id_digest", "3" * 64)
    _assert_error(
        RotationAuditCode.INTENT_TAMPERED,
        lambda: require_restart_required_intent(intent),
    )


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_issued_event_and_intent_reject_copy_and_pickle(operation) -> None:
    event = _event()
    intent = derive_restart_required_intent(event)
    assert intent is not None
    for value in (event, intent):
        with pytest.raises(SealError):
            operation(value)


def test_issued_event_rejects_pydantic_bypasses_and_reinitialization() -> None:
    event = _event()
    with pytest.raises(SealError):
        event.model_copy(update={"new_version_id_digest": "9" * 64})
    with pytest.raises(SealError):
        RotationAuditEventV1.model_construct(
            binding_id="0" * 64,
            prior_version_id_digest="1" * 64,
            new_version_id_digest="2" * 64,
            rotated_at_ns=1,
            requires_restart=True,
        )
    with pytest.raises(SealError):
        BaseModel.__init__(
            event,
            binding_id="0" * 64,
            prior_version_id_digest="1" * 64,
            new_version_id_digest="9" * 64,
            rotated_at_ns=1,
            requires_restart=True,
        )


@pytest.mark.parametrize("now_ns", [0, _MAX_NS])
def test_clock_accepts_inclusive_utc_ns_range(now_ns: int) -> None:
    event = create_rotation_audit_event(
        binding_ref=_REFERENCE,
        prior_version_id="version-1",
        new_version_id="version-2",
        requires_restart=True,
        clock_ns=lambda: now_ns,
    )
    assert event.rotated_at_ns == now_ns
