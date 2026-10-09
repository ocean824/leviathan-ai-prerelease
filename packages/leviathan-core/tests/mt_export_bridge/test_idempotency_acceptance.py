"""Independent acceptance tests for MT export request idempotency."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping
from decimal import Decimal
from typing import Any

import pytest

import leviathan_core.mt_export_idempotency as idempotency
from leviathan_core.mt_export_idempotency import (
    _MAX_PAYLOAD_BYTES,
    DuplicateIntentStatusV1,
    ExportActionV1,
    IdempotencyError,
    RequestBindingV1,
    _preflight_canonical_size,
    create_request_binding,
    decide_duplicate_intent,
    fingerprint_payload,
)
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import SealError

_PROJECT = "project-alpha"
_KEY = "retry-001"
_PAYLOAD: dict[str, object] = {"artifact": "ea-1", "params": {"period": 5}}
_PAYLOAD_DOMAIN = b"leviathan.mt_export_idempotency.payload.v1\0"


def _binding(
    *,
    project_id: str = _PROJECT,
    action: ExportActionV1 | str = ExportActionV1.BUILD,
    idempotency_key: str = _KEY,
    payload: Mapping[str, object] | None = None,
) -> RequestBindingV1:
    return create_request_binding(
        project_id=project_id,
        action=action,
        idempotency_key=idempotency_key,
        payload=_PAYLOAD if payload is None else payload,
    )


def test_payload_fingerprint_matches_domain_separated_canonical_json() -> None:
    payload = {"artifact": "ea-1", "params": {"period": Decimal("5.00")}}
    expected = hashlib.sha256(_PAYLOAD_DOMAIN + canonical_json(payload)).hexdigest()

    assert fingerprint_payload(payload) == expected
    assert len(expected) == 64
    assert expected == expected.lower()


def test_nested_mapping_order_and_decimal_spelling_do_not_change_fingerprint() -> None:
    left = {"z": [True, Decimal("1.50")], "params": {"b": 2, "a": "x"}}
    right = {"params": {"a": "x", "b": 2}, "z": [True, Decimal("1.5")]}
    before = copy.deepcopy(left)

    left_fingerprint = fingerprint_payload(left)
    right_fingerprint = fingerprint_payload(right)

    assert left_fingerprint == right_fingerprint
    assert left == before


@pytest.mark.parametrize(
    "payload",
    [
        {"text": 'quote=" slash=\\ control=\x01 line=\n'},
        {"text": "é漢\u2028"},
        {"text": "🚀"},
    ],
    ids=["ascii-escapes", "bmp-unicode", "supplementary-unicode"],
)
def test_preflight_byte_count_matches_canonical_json_for_string_encodings(
    payload: dict[str, object],
) -> None:
    canonical = canonical_json(payload)

    assert _preflight_canonical_size(payload) == len(canonical)


def test_exact_one_mibibyte_canonical_payload_is_accepted() -> None:
    payload = {"x": "x" * (_MAX_PAYLOAD_BYTES - 8)}

    assert _preflight_canonical_size(payload) == _MAX_PAYLOAD_BYTES
    assert len(fingerprint_payload(payload)) == 64


def test_eight_mibibyte_payload_is_rejected_before_canonical_serializer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {"large": "x" * (8 * 1024 * 1024)}
    serializer_called = False

    def unexpected_serializer_call(_: Mapping[str, object]) -> bytes:
        nonlocal serializer_called
        serializer_called = True
        raise AssertionError("canonical serializer must not receive oversized payload")

    monkeypatch.setattr(idempotency, "canonical_json", unexpected_serializer_call)

    with pytest.raises(IdempotencyError) as raised:
        fingerprint_payload(payload)

    assert raised.value.code == "INVALID_REQUEST"
    assert str(raised.value) == "INVALID_REQUEST"
    assert raised.value.__cause__ is None
    assert serializer_called is False


def test_identical_content_produces_the_same_payload_and_request_fingerprints() -> None:
    first = _binding()
    repeated = _binding(payload={"params": {"period": 5}, "artifact": "ea-1"})

    assert first.payload_fingerprint == repeated.payload_fingerprint
    assert first.scope_fingerprint == repeated.scope_fingerprint
    assert first.request_fingerprint == repeated.request_fingerprint


def test_build_and_deploy_requests_are_domain_separated() -> None:
    build = _binding(action=ExportActionV1.BUILD)
    deploy = _binding(action=ExportActionV1.DEPLOY)

    assert build.payload_fingerprint == deploy.payload_fingerprint
    assert build.scope_fingerprint != deploy.scope_fingerprint
    assert build.request_fingerprint != deploy.request_fingerprint
    assert decide_duplicate_intent(build, deploy).status is DuplicateIntentStatusV1.NEW
    assert decide_duplicate_intent(deploy, build).status is DuplicateIntentStatusV1.NEW


@pytest.mark.parametrize("scope_change", ["project", "key"])
def test_project_or_key_change_creates_a_new_scope(scope_change: str) -> None:
    prior = _binding()
    if scope_change == "project":
        candidate = _binding(project_id="project-beta")
    else:
        candidate = _binding(idempotency_key="retry-002")

    decision = decide_duplicate_intent(prior, candidate)

    assert decision.status is DuplicateIntentStatusV1.NEW
    assert decision.reason_code is None
    assert decision.request_fingerprint == candidate.request_fingerprint


def test_same_intent_replays_deterministically_and_preserves_candidate_identity() -> None:
    prior = _binding()
    candidate = _binding()

    first = decide_duplicate_intent(prior, candidate)
    second = decide_duplicate_intent(prior, candidate)

    assert first.status is DuplicateIntentStatusV1.REPLAY
    assert first.reason_code is None
    assert first.request_fingerprint == candidate.request_fingerprint
    assert first.model_dump() == second.model_dump()


def test_changed_payload_in_same_scope_is_a_fixed_deterministic_conflict() -> None:
    prior = _binding()
    candidate = _binding(payload={"artifact": "ea-1", "params": {"period": 10}})

    first = decide_duplicate_intent(prior, candidate)
    second = decide_duplicate_intent(prior, candidate)

    assert first.status is DuplicateIntentStatusV1.CONFLICT
    assert first.reason_code == "IDEMPOTENCY_CONFLICT"
    assert first.request_fingerprint == candidate.request_fingerprint
    assert first.model_dump() == second.model_dump()


def test_first_binding_is_new_and_returns_only_the_candidate_identity() -> None:
    candidate = _binding()

    decision = decide_duplicate_intent(None, candidate)

    assert decision.status is DuplicateIntentStatusV1.NEW
    assert decision.reason_code is None
    assert decision.request_fingerprint == candidate.request_fingerprint


def test_binding_and_decision_do_not_echo_the_raw_key_or_payload() -> None:
    key_canary = "sk_test_acceptance_canary"
    payload_canary = "private_payload_acceptance_canary"
    payload: dict[str, object] = {"data": payload_canary, "nested": {"n": 7}}
    binding = _binding(idempotency_key=key_canary, payload=payload)
    decision = decide_duplicate_intent(None, binding)
    binding_text = binding.model_dump_json()
    decision_text = decision.model_dump_json()

    assert set(binding.model_dump()) == {
        "scope_fingerprint",
        "payload_fingerprint",
        "request_fingerprint",
    }
    assert set(decision.model_dump()) == {"status", "request_fingerprint", "reason_code"}
    assert key_canary not in binding_text + decision_text
    assert payload_canary not in binding_text + decision_text
    assert payload_canary not in str(binding.model_dump())


@pytest.mark.parametrize(
    "key",
    ["", " leading", "trailing ", "bad/slash", "ümlaut", "x" * 129, "\n"],
)
def test_malformed_and_oversized_keys_fail_with_content_free_errors(key: str) -> None:
    with pytest.raises(IdempotencyError) as raised:
        _binding(idempotency_key=key)

    assert raised.value.code == "INVALID_REQUEST"
    assert str(raised.value) == "INVALID_REQUEST"
    assert raised.value.__cause__ is None
    if key:
        assert key not in str(raised.value)


@pytest.mark.parametrize(
    "payload",
    [
        {"oversized": "x" * 1_048_577},
        {"float": 1.0},
        {1: "non-string-key"},
        {"unsupported": object()},
    ],
)
def test_oversized_or_noncanonical_payloads_fail_closed(payload: dict[Any, object]) -> None:
    with pytest.raises(IdempotencyError) as raised:
        fingerprint_payload(payload)

    assert raised.value.code == "INVALID_REQUEST"
    assert str(raised.value) == "INVALID_REQUEST"
    assert raised.value.__cause__ is None


def test_only_issued_bindings_can_be_used_as_prior_duplicate_evidence() -> None:
    issued = _binding()
    forged = RequestBindingV1.model_validate(issued.model_dump())

    with pytest.raises(IdempotencyError) as raised:
        decide_duplicate_intent(forged, issued)

    assert raised.value.code == "INVALID_BINDING"
    assert str(raised.value) == "INVALID_BINDING"
    assert raised.value.__cause__ is None


def test_copied_and_tampered_bindings_cannot_be_used_for_a_decision() -> None:
    issued = _binding()

    with pytest.raises(SealError):
        copy.copy(issued)

    tampered = issued.model_copy(update={"payload_fingerprint": "0" * 64})
    with pytest.raises(IdempotencyError) as raised:
        decide_duplicate_intent(tampered, issued)

    assert raised.value.code == "INVALID_BINDING"


def test_duplicate_comparison_is_pure_and_does_not_mutate_bindings() -> None:
    prior = _binding()
    candidate = _binding(payload={"artifact": "ea-1", "params": {"period": 10}})
    prior_before = prior.model_dump()
    candidate_before = candidate.model_dump()

    first = decide_duplicate_intent(prior, candidate)
    second = decide_duplicate_intent(prior, candidate)

    assert first.model_dump() == second.model_dump()
    assert prior.model_dump() == prior_before
    assert candidate.model_dump() == candidate_before
