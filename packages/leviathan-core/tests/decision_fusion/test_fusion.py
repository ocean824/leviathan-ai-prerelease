"""Focused kernel tests; independent acceptance cases live in a separate file."""

import copy
import json
import pickle
from decimal import localcontext

import pytest
from pydantic import ValidationError

from leviathan_core.decision_fusion import (
    FeatureAttributionV1,
    FeatureSnapshotV1,
    FusionFrozenError,
    FusionPolicyV1,
    FusionRequestV1,
    FusionValidationError,
    LayerObservationV1,
    MarketContextV1,
    evaluate,
)
from leviathan_core.decision_fusion.models import canonical_decimal


def observation(layer: str, *, event_ns: int = 900, available_ns: int = 950) -> LayerObservationV1:
    return LayerObservationV1(
        layer=layer,
        source=f"source-{layer}",
        source_version="v1",
        event_ns=event_ns,
        available_ns=available_ns,
        semantic_digest={"L1": "1", "L2": "2", "L3": "3", "L4": "4"}[layer] * 64,
        integrity="ok" if layer == "L1" else None,
        score="0.8" if layer in {"L2", "L4"} else None,
        confidence="0.8" if layer == "L3" else None,
    )


def policy() -> FusionPolicyV1:
    return FusionPolicyV1(
        policy_id="fusion-policy",
        policy_version="1.0.0",
        window_ns=250,
        max_source_skew_ns=100,
        min_l2_score="0.7",
        min_l3_confidence="0.7",
        min_l4_score="0.7",
        required_sources=tuple((layer, f"source-{layer}") for layer in ("L1", "L2", "L3", "L4")),
    )


def request(**changes: object) -> FusionRequestV1:
    values: dict[str, object] = {
        "evaluation_ns": 1000,
        "tenant_id": "tenant",
        "strategy_revision": "rev-1",
        "strategy_hash": "a" * 64,
        "symbol": "ABC",
        "window_id": "window-1",
        "observations": tuple(observation(layer) for layer in ("L1", "L2", "L3", "L4")),
        "market_context": MarketContextV1(),
    }
    values.update(changes)
    return FusionRequestV1.model_validate(values)


def test_candidate_is_deterministic_and_advisory() -> None:
    original = request()
    first = evaluate(original, policy())
    replay = evaluate(request(observations=tuple(reversed(original.observations))), policy())
    assert first.status == "CAPITAL_CANDIDATE"
    assert first.idempotency_check == "NOT_PERFORMED"
    assert first.reason_codes == ()
    assert first.canonical_bytes() == replay.canonical_bytes()
    assert "route" not in first.canonical_bytes().decode()


def test_missing_future_and_conflicting_inputs_fail_closed() -> None:
    original = request()
    missing = evaluate(request(observations=original.observations[:3]), policy())
    assert missing.status == "NO_INTENT"
    assert missing.layer_verdicts[3].status == "MISSING"
    assert "MISSING_LAYER" in missing.reason_codes

    future = evaluate(
        request(
            feature_snapshots=(
                FeatureSnapshotV1(snapshot_id="late", event_ns=900, available_ns=1001),
            )
        ),
        policy(),
    )
    assert future.reason_codes == ("FUTURE_FEATURE",)

    changed = (*original.observations, observation("L4", event_ns=901))
    conflict = evaluate(request(observations=changed), policy())
    assert conflict.status == "NO_INTENT"
    assert "CONFLICTING_LAYER" in conflict.reason_codes


def test_reuse_of_semantic_key_with_changed_content_is_conflict() -> None:
    original = request()
    prior = evaluate(original, policy())
    updated = request(
        strategy_hash="b" * 64,
        prior_input_hash=prior.input_hash,
    )
    result = evaluate(updated, policy())
    assert result.idempotency_key == prior.idempotency_key
    assert result.input_hash != prior.input_hash
    assert result.idempotency_check == "CONFLICT"
    assert result.reason_codes == ("IDEMPOTENCY_CONFLICT",)

    matched = evaluate(request(prior_input_hash=prior.input_hash), policy())
    assert matched.idempotency_check == "MATCH"
    assert matched.status == "CAPITAL_CANDIDATE"
    assert matched.input_hash == prior.input_hash


@pytest.mark.parametrize(
    "policy_change",
    [
        {"min_l2_score": "0.9"},
        {"policy_id": "another-policy"},
        {"policy_version": "2.0.0"},
    ],
)
def test_policy_change_conflicts_with_prior_input_hash(policy_change: dict[str, str]) -> None:
    original_policy = policy()
    first = evaluate(request(), original_policy)
    changed_policy = FusionPolicyV1.model_validate(
        {
            **original_policy.model_dump(),
            **policy_change,
        }
    )
    changed = evaluate(request(prior_input_hash=first.input_hash), changed_policy)
    assert changed.idempotency_key == first.idempotency_key
    assert changed.policy_hash != first.policy_hash
    assert changed.input_hash != first.input_hash
    assert changed.idempotency_check == "CONFLICT"
    assert "IDEMPOTENCY_CONFLICT" in changed.reason_codes
    assert changed.status == "NO_INTENT"


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("tenant_id", "tenant\r\nX-Injected: yes"),
        ("symbol", "SYNTH\nextra"),
        ("symbol", "SYNTH\n"),
        ("strategy_hash", "x"),
        ("strategy_hash", "A" * 64),
    ],
)
def test_closed_request_fields_reject_invalid_values_without_echo(
    field: str, bad_value: str
) -> None:
    with pytest.raises(FusionValidationError) as caught:
        FusionRequestV1.model_validate({**request().model_dump(), field: bad_value})
    assert bad_value not in str(caught.value)
    assert bad_value not in caught.value.json()


def test_closed_source_and_digest_reject_invalid_values_without_echo() -> None:
    for field, bad_value in (("source", "snowman-☃\r\n"), ("semantic_digest", "not-a-digest")):
        with pytest.raises(FusionValidationError) as caught:
            LayerObservationV1.model_validate(
                {
                    **observation("L1").model_dump(),
                    field: bad_value,
                }
            )
        assert bad_value not in str(caught.value)
        assert bad_value not in caught.value.json()
    with pytest.raises(FusionValidationError):
        FusionPolicyV1.model_validate(
            {
                **policy().model_dump(),
                "required_sources": (
                    ("L1", "snowman-☃"),
                    ("L2", "source-L2"),
                    ("L3", "source-L3"),
                    ("L4", "source-L4"),
                ),
            }
        )


def test_future_or_unlinked_attribution_does_not_change_prior_candidate() -> None:
    visible = FeatureSnapshotV1(snapshot_id="visible", event_ns=900, available_ns=950)
    future = FeatureSnapshotV1(snapshot_id="future", event_ns=900, available_ns=1001)
    linked = FeatureAttributionV1(
        feature="visible-feature", contribution="0.5", snapshot_id="visible"
    )
    baseline = evaluate(
        request(feature_snapshots=(visible,), feature_attributions=(linked,)), policy()
    )
    additions = (
        FeatureAttributionV1(feature="future-snapshot", contribution="1", snapshot_id="future"),
        FeatureAttributionV1(feature="future-timestamp", contribution="1", available_ns=1001),
        FeatureAttributionV1(feature="unlinked", contribution="1"),
    )
    later = evaluate(
        request(feature_snapshots=(visible, future), feature_attributions=(linked, *additions)),
        policy(),
    )
    assert baseline.status == "CAPITAL_CANDIDATE"
    assert baseline.attributions == (linked,)
    assert later.canonical_bytes() == baseline.canonical_bytes()


def test_combined_reason_codes_are_sorted_and_unique() -> None:
    original = request()
    future_event = LayerObservationV1.model_validate(
        {
            **original.observations[0].model_dump(),
            "event_ns": 1001,
        }
    )
    future_available = LayerObservationV1.model_validate(
        {
            **original.observations[1].model_dump(),
            "available_ns": 1001,
        }
    )
    result = evaluate(
        request(observations=(future_event, future_available, *original.observations[2:])), policy()
    )
    assert result.reason_codes == tuple(sorted(set(result.reason_codes)))
    assert result.reason_codes.count("FUTURE_LAYER") == 1


def test_frozen_schema_rejects_extra_fields_and_invalid_policy() -> None:
    with pytest.raises(ValidationError):
        FusionRequestV1.model_validate({**request().model_dump(), "route_permit": True})
    with pytest.raises(ValidationError):
        FusionPolicyV1.model_validate({**policy().model_dump(), "min_l2_score": "NaN"})


def test_public_validation_errors_hide_rejected_values_in_all_entry_points() -> None:
    secret = "SECRET bad id"
    values = {**observation("L1").model_dump(), "event_ns": secret, secret: "payload"}
    for validate in (
        lambda: LayerObservationV1.model_validate(values),
        lambda: LayerObservationV1.model_validate_json(json.dumps(values)),
    ):
        with pytest.raises(ValidationError) as caught:
            validate()
        error = caught.value
        assert isinstance(error, FusionValidationError)
        assert error.code == "INVALID_FUSION_INPUT"
        assert all(
            secret not in rendered
            for rendered in (str(error), repr(error.args), repr(error.errors()), error.json())
        )
        assert all(set(detail) == {"loc", "type", "code"} for detail in error.errors())
        assert all(set(detail) == {"loc", "type", "code"} for detail in json.loads(error.json()))


def test_future_available_additions_do_not_change_an_earlier_asof_result() -> None:
    visible = FeatureSnapshotV1(snapshot_id="visible", event_ns=900, available_ns=950)
    original = request(feature_snapshots=(visible,))
    baseline = evaluate(original, policy())
    future_layer = LayerObservationV1.model_validate(
        {
            **observation("L2").model_dump(),
            "available_ns": 1001,
            "semantic_digest": "f" * 64,
        }
    )
    future_feature = FeatureSnapshotV1(snapshot_id="future", event_ns=900, available_ns=1001)
    with_later = request(
        observations=(*original.observations, future_layer),
        feature_snapshots=(visible, future_feature),
    )
    assert baseline.canonical_bytes() == evaluate(with_later, policy()).canonical_bytes()


def test_frozen_models_block_mutation_copy_pickle_and_unchecked_construction() -> None:
    model = request()
    with pytest.raises(FusionFrozenError) as assigned:
        model.symbol = "SECRET assignment"  # type: ignore[misc]
    assert "SECRET assignment" not in str(assigned.value)
    assert "SECRET assignment" not in repr(assigned.value.args)
    with pytest.raises(FusionFrozenError):
        del model.symbol
    for attempt in (
        lambda: copy.copy(model),
        lambda: copy.deepcopy(model),
        lambda: pickle.dumps(model),
        lambda: model.model_copy(update={"symbol": "changed"}),
        lambda: FusionRequestV1.model_construct(symbol="changed"),
    ):
        with pytest.raises(FusionFrozenError):
            attempt()


def test_canonical_decimal_is_exact_under_restrictive_ambient_context() -> None:
    value = "0.1234567890123456789012345678901234"
    with localcontext() as ambient:
        ambient.prec = 2
        ambient.Emax = 2
        assert canonical_decimal(value) == value
    with pytest.raises(ValueError, match="MAGNITUDE_OUT_OF_BOUNDS"):
        canonical_decimal("1E+100000")
