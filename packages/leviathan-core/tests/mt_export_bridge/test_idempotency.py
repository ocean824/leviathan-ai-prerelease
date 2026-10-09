from __future__ import annotations

import copy
import hashlib
import pickle
from decimal import Decimal

import pytest

from leviathan_core import mt_export_idempotency as idempotency
from leviathan_core.mt_export_idempotency import (
    DuplicateIntentStatusV1,
    ExportActionV1,
    IdempotencyError,
    RequestBindingV1,
    create_request_binding,
    decide_duplicate_intent,
    fingerprint_payload,
)
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import SealError


def _binding(
    *,
    project_id: str = "project-alpha",
    action: ExportActionV1 | str = ExportActionV1.BUILD,
    idempotency_key: str = "retry-001",
    payload: dict[str, object] | None = None,
) -> RequestBindingV1:
    return create_request_binding(
        project_id=project_id,
        action=action,
        idempotency_key=idempotency_key,
        payload={"artifact": "ea-1", "params": {"period": 5}} if payload is None else payload,
    )


def test_payload_fingerprint_uses_domain_separated_canonical_json() -> None:
    payload = {"z": [True, Decimal("1.25")], "a": {"name": "sample"}}
    expected = hashlib.sha256(
        b"leviathan.mt_export_idempotency.payload.v1\0" + canonical_json(payload)
    ).hexdigest()

    assert fingerprint_payload(payload) == expected


@pytest.mark.parametrize(
    "payload",
    [
        {"ascii": "ordinary text"},
        {"escaped": 'quote " slash \\ tab\t newline\n control\x01'},
        {"unicode": "é漢字😀"},
        {"nested": {"é😀": ["\x00", "雪", False]}},
    ],
)
def test_bounded_preflight_size_matches_canonical_json(payload: dict[str, object]) -> None:
    assert idempotency._preflight_canonical_size(payload) == len(canonical_json(payload))


def test_payload_at_exact_canonical_byte_limit_is_accepted() -> None:
    overhead = len(b'{"blob":""}')
    payload = {"blob": "x" * (idempotency._MAX_PAYLOAD_BYTES - overhead)}

    assert idempotency._preflight_canonical_size(payload) == idempotency._MAX_PAYLOAD_BYTES
    assert len(canonical_json(payload)) == idempotency._MAX_PAYLOAD_BYTES
    assert fingerprint_payload(payload)


def test_payload_fingerprint_is_stable_under_mapping_order_and_exact_numbers() -> None:
    left = {"params": {"b": Decimal("1.50"), "a": 2}, "artifact": "ea"}
    right = {"artifact": "ea", "params": {"a": 2, "b": Decimal("1.5")}}

    assert fingerprint_payload(left) == fingerprint_payload(right)


def test_payload_types_remain_distinct_and_float_is_rejected() -> None:
    assert fingerprint_payload({"value": 1}) != fingerprint_payload({"value": "1"})
    with pytest.raises(IdempotencyError) as raised:
        fingerprint_payload({"value": 1.0})
    assert raised.value.code == "INVALID_REQUEST"
    assert str(raised.value) == "INVALID_REQUEST"


def test_binding_fingerprint_is_stable_and_does_not_retain_raw_request_values() -> None:
    key_canary = "sk_test_fake_canary"
    payload_canary = "payload_private_canary"
    first = _binding(idempotency_key=key_canary, payload={"data": payload_canary})
    replay = _binding(
        idempotency_key=key_canary,
        payload={"data": payload_canary},
    )
    serialized = repr(first.model_dump())

    assert first.request_fingerprint == replay.request_fingerprint
    assert first.scope_fingerprint == replay.scope_fingerprint
    assert key_canary not in serialized
    assert payload_canary not in serialized


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"project_id": "project-beta"}, DuplicateIntentStatusV1.NEW),
        ({"action": ExportActionV1.DEPLOY}, DuplicateIntentStatusV1.NEW),
        ({"idempotency_key": "retry-002"}, DuplicateIntentStatusV1.NEW),
        ({"payload": {"artifact": "ea-2"}}, DuplicateIntentStatusV1.CONFLICT),
    ],
)
def test_duplicate_decision_scopes_replay_and_conflict(changes, expected) -> None:
    prior = _binding()
    candidate = _binding(**changes)

    result = decide_duplicate_intent(prior, candidate)

    assert result.status is expected
    if expected is DuplicateIntentStatusV1.CONFLICT:
        assert result.reason_code == "IDEMPOTENCY_CONFLICT"
    else:
        assert result.reason_code is None


def test_duplicate_replay_and_first_intent_preserve_candidate_identity() -> None:
    first = _binding()
    replay = _binding()

    new = decide_duplicate_intent(None, first)
    repeated = decide_duplicate_intent(first, replay)

    assert new.status is DuplicateIntentStatusV1.NEW
    assert repeated.status is DuplicateIntentStatusV1.REPLAY
    assert new.request_fingerprint == repeated.request_fingerprint == first.request_fingerprint


@pytest.mark.parametrize(
    "key",
    ["", " leading", "trailing ", "bad/slash", "ümlaut", "x" * 129, "\n"],
)
def test_malformed_and_oversized_keys_fail_with_content_free_error(key: str) -> None:
    with pytest.raises(IdempotencyError) as raised:
        _binding(idempotency_key=key)

    assert raised.value.code == "INVALID_REQUEST"
    assert not key or key not in str(raised.value)
    assert raised.value.__cause__ is None


@pytest.mark.parametrize("project_id", ["", "bad/project", "x" * 129, "é"])
def test_invalid_project_identifiers_are_rejected(project_id: str) -> None:
    with pytest.raises(IdempotencyError) as raised:
        _binding(project_id=project_id)
    assert raised.value.code == "INVALID_REQUEST"


def test_invalid_action_is_rejected_without_echoing_input() -> None:
    with pytest.raises(IdempotencyError) as raised:
        _binding(action="LIVE_ORDER_SECRET")
    assert raised.value.code == "INVALID_REQUEST"
    assert "LIVE_ORDER_SECRET" not in str(raised.value)


@pytest.mark.parametrize(
    "payload",
    [
        {1: "non-string key"},
        {"bad": object()},
        {"oversized": "x" * (1_048_577)},
    ],
)
def test_invalid_or_oversized_payloads_fail_closed(payload: dict[object, object]) -> None:
    with pytest.raises(IdempotencyError) as raised:
        fingerprint_payload(payload)
    assert raised.value.code == "INVALID_REQUEST"
    assert raised.value.__cause__ is None


def test_cyclic_payload_fails_closed() -> None:
    payload: dict[str, object] = {}
    payload["self"] = payload

    with pytest.raises(IdempotencyError) as raised:
        fingerprint_payload(payload)

    assert raised.value.code == "INVALID_REQUEST"
    assert raised.value.__cause__ is None


def test_oversized_payload_is_rejected_before_canonical_serialization(monkeypatch) -> None:
    called = False

    def observe_serialization(payload: object) -> bytes:
        nonlocal called
        called = True
        return canonical_json(payload)

    monkeypatch.setattr(idempotency, "canonical_json", observe_serialization)
    payload = {"blob": "x" * (8 * 1024 * 1024)}

    with pytest.raises(IdempotencyError) as raised:
        idempotency.fingerprint_payload(payload)

    assert raised.value.code == "INVALID_REQUEST"
    assert not called


def test_only_issued_bindings_can_be_used_for_duplicate_decisions() -> None:
    binding = _binding()
    forged = RequestBindingV1.model_validate(binding.model_dump())

    with pytest.raises(IdempotencyError) as raised:
        decide_duplicate_intent(forged, binding)

    assert raised.value.code == "INVALID_BINDING"
    assert raised.value.__cause__ is None


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_issued_binding_rejects_copy_and_pickle(operation) -> None:
    binding = _binding()

    with pytest.raises(SealError):
        operation(binding)


def test_issued_models_reject_pydantic_bypass_and_assignment() -> None:
    binding = _binding()
    decision = decide_duplicate_intent(None, binding)

    copied = binding.model_copy(update={"payload_fingerprint": "0" * 64})
    with pytest.raises(IdempotencyError) as raised:
        decide_duplicate_intent(copied, binding)
    assert raised.value.code == "INVALID_BINDING"
    with pytest.raises(SealError):
        RequestBindingV1.model_construct(scope_fingerprint="0" * 64)
    with pytest.raises(SealError):
        decision.status = DuplicateIntentStatusV1.CONFLICT
