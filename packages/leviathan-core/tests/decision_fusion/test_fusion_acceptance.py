"""Independent contract acceptance tests for the four-layer fusion kernel."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

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

FIXTURE = Path(__file__).parent / "fixtures" / "fusion_valid_boundary.json"
LAYERS = ("L1", "L2", "L3", "L4")
NOW_NS = 1_000_000_000
WINDOW_NS = 250_000_000


def fixture_data() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def observations_from(
    rows: list[dict[str, Any]] | None = None,
) -> tuple[LayerObservationV1, ...]:
    data = fixture_data()["request"]["observations"] if rows is None else rows
    return tuple(LayerObservationV1(**item) for item in data)


def make_policy(**overrides: Any) -> FusionPolicyV1:
    fields = dict(fixture_data()["policy"])
    fields.update(overrides)
    fields["required_sources"] = tuple(tuple(item) for item in fields["required_sources"])
    return FusionPolicyV1(**fields)


def make_request(
    *,
    rows: list[dict[str, Any]] | None = None,
    market: dict[str, bool] | None = None,
    features: tuple[FeatureSnapshotV1, ...] = (),
    attributions: tuple[FeatureAttributionV1, ...] = (),
    prior_input_hash: str | None = None,
) -> FusionRequestV1:
    fields = dict(fixture_data()["request"])
    fields["observations"] = observations_from(rows)
    fields["market_context"] = MarketContextV1(
        **(fields["market_context"] if market is None else market)
    )
    fields["feature_snapshots"] = features
    fields["feature_attributions"] = attributions
    fields["prior_input_hash"] = prior_input_hash
    return FusionRequestV1(**fields)


def rows_with_change(layer: str, **changes: Any) -> list[dict[str, Any]]:
    rows = fixture_data()["request"]["observations"]
    for item in rows:
        if item["layer"] == layer:
            item.update(changes)
            break
    return rows


def reason_set(result: Any) -> set[str]:
    return set(result.reason_codes)


def assert_validation_error_redacts(error: FusionValidationError, secret: str) -> None:
    rendered = (str(error), repr(error.args), repr(error.errors()), error.json())
    assert all(secret not in view for view in rendered)
    for detail in error.errors():
        assert "input" not in detail
        assert "ctx" not in detail
        assert "url" not in detail
    for detail in json.loads(error.json()):
        assert "input" not in detail
        assert "ctx" not in detail
        assert "url" not in detail


def test_public_model_validation_does_not_echo_invalid_timestamp_input() -> None:
    secret = "SECRET bad id"

    with pytest.raises(FusionValidationError) as caught:
        LayerObservationV1(
            layer="L1",
            source="synthetic-l1",
            source_version="v1",
            event_ns=secret,
            available_ns=NOW_NS,
            semantic_digest="a" * 64,
            integrity="ok",
        )

    assert_validation_error_redacts(caught.value, secret)


@pytest.mark.parametrize(
    "operation", ["known_assignment", "unknown_assignment", "known_deletion", "unknown_deletion"]
)
def test_frozen_fusion_records_reject_assignment_and_deletion_without_echoing_canary(
    operation: str,
) -> None:
    canary = "SECRET bad id"
    request = make_request()

    with pytest.raises(FusionFrozenError) as caught:
        if operation == "known_assignment":
            request.tenant_id = canary
        elif operation == "unknown_assignment":
            setattr(request, canary, canary)
        elif operation == "known_deletion":
            del request.tenant_id
        else:
            delattr(request, canary)

    error = caught.value
    assert error.code == "FROZEN_FUSION_RECORD"
    assert canary not in str(error)
    assert canary not in repr(error.args)
    assert canary not in repr(getattr(error, "context", None))


def test_all_four_layers_pass_at_the_inclusive_window_boundary() -> None:
    policy = make_policy()
    request = make_request()

    result = evaluate(request, policy)

    assert result.status == "CAPITAL_CANDIDATE"
    assert result.idempotency_check == "NOT_PERFORMED"
    assert tuple(item.layer for item in result.layer_verdicts) == LAYERS
    assert all(item.status == "PASS" for item in result.layer_verdicts)
    assert tuple(result.layer_scores) == (
        ("L1", None),
        ("L2", "0.8"),
        ("L3", "0.8"),
        ("L4", "0.8"),
    )


@pytest.mark.parametrize("missing_layer", LAYERS)
def test_every_single_missing_layer_fails_closed(missing_layer: str) -> None:
    rows = [
        row for row in fixture_data()["request"]["observations"] if row["layer"] != missing_layer
    ]

    result = evaluate(make_request(rows=rows), make_policy())

    assert result.status == "NO_INTENT"
    assert "MISSING_LAYER" in reason_set(result)
    verdict = next(item for item in result.layer_verdicts if item.layer == missing_layer)
    assert verdict.status == "MISSING"


@pytest.mark.parametrize("layer", LAYERS)
def test_each_stale_layer_fails_closed(layer: str) -> None:
    result = evaluate(
        make_request(rows=rows_with_change(layer, event_ns=NOW_NS - WINDOW_NS - 1)),
        make_policy(),
    )

    assert result.status == "NO_INTENT"
    assert "STALE_LAYER" in reason_set(result)


@pytest.mark.parametrize("layer", LAYERS)
def test_future_available_layer_fails_closed(layer: str) -> None:
    result = evaluate(
        make_request(rows=rows_with_change(layer, available_ns=NOW_NS + 1)),
        make_policy(),
    )

    assert result.status == "NO_INTENT"
    assert "FUTURE_LAYER" in reason_set(result)


def test_future_duplicate_is_filtered_before_layer_resolution_and_identity() -> None:
    rows = fixture_data()["request"]["observations"]
    visible_l2 = next(item for item in rows if item["layer"] == "L2")
    future_duplicate = {
        **visible_l2,
        "available_ns": NOW_NS + 1,
        "semantic_digest": "f" * 64,
        "score": "0.1",
    }

    visible = evaluate(make_request(rows=rows), make_policy())
    with_future = evaluate(make_request(rows=[*rows, future_duplicate]), make_policy())

    assert visible.status == "CAPITAL_CANDIDATE"
    assert with_future.status == "CAPITAL_CANDIDATE"
    assert with_future.canonical_bytes() == visible.canonical_bytes()


@pytest.mark.parametrize("layer", LAYERS)
def test_future_event_time_fails_closed(layer: str) -> None:
    result = evaluate(
        make_request(rows=rows_with_change(layer, event_ns=NOW_NS + 1)),
        make_policy(),
    )

    assert result.status == "NO_INTENT"
    assert "FUTURE_LAYER" in reason_set(result)


@pytest.mark.parametrize(
    ("layer", "changes", "expected_reason"),
    [
        ("L1", {"integrity": "corrupt"}, "INVALID_LAYER_DATA"),
        ("L2", {"score": "0.699"}, "BELOW_THRESHOLD"),
        ("L3", {"confidence": "0.699"}, "BELOW_THRESHOLD"),
        ("L4", {"score": "0.699"}, "BELOW_THRESHOLD"),
    ],
)
def test_each_layer_specific_integrity_or_threshold_gate_is_required(
    layer: str, changes: dict[str, str], expected_reason: str
) -> None:
    result = evaluate(
        make_request(rows=rows_with_change(layer, **changes)),
        make_policy(),
    )

    assert result.status == "NO_INTENT"
    assert expected_reason in reason_set(result)


def test_threshold_equalities_are_inclusive() -> None:
    rows = fixture_data()["request"]["observations"]
    for item in rows:
        if item["layer"] == "L2":
            item["score"] = "0.7"
        elif item["layer"] == "L3":
            item["confidence"] = "0.7"
        elif item["layer"] == "L4":
            item["score"] = "0.7"

    result = evaluate(make_request(rows=rows), make_policy())

    assert result.status == "CAPITAL_CANDIDATE"


@pytest.mark.parametrize(
    ("layer", "field"),
    [("L2", "score"), ("L3", "confidence"), ("L4", "score")],
)
@pytest.mark.parametrize(
    ("value", "expected_status"),
    [("0.699999999999999999", "NO_INTENT"), ("0.700000000000000001", "CAPITAL_CANDIDATE")],
    ids=["one-decimal-unit-below-threshold", "one-decimal-unit-above-threshold"],
)
def test_threshold_comparison_is_exact_on_both_sides(
    layer: str, field: str, value: str, expected_status: str
) -> None:
    rows = fixture_data()["request"]["observations"]
    for item in rows:
        if item["layer"] == layer:
            item[field] = value

    result = evaluate(make_request(rows=rows), make_policy())

    assert result.status == expected_status
    if expected_status == "NO_INTENT":
        assert "BELOW_THRESHOLD" in reason_set(result)


def test_unsupported_layer_is_not_ignored_as_an_optional_input() -> None:
    rows = fixture_data()["request"]["observations"]
    rows.append(
        {
            **rows[0],
            "layer": "L5",
            "source": "synthetic-l5",
            "semantic_digest": "5" * 64,
        }
    )

    result = evaluate(make_request(rows=rows), make_policy())

    assert result.status == "NO_INTENT"
    assert "UNSUPPORTED_LAYER" in reason_set(result)


def test_source_mismatch_and_excessive_event_skew_fail_closed() -> None:
    mismatched_source = evaluate(
        make_request(rows=rows_with_change("L2", source="unregistered-source")),
        make_policy(),
    )
    skewed = evaluate(
        make_request(rows=rows_with_change("L4", event_ns=NOW_NS - WINDOW_NS + 50_001)),
        make_policy(),
    )

    assert mismatched_source.status == "NO_INTENT"
    assert "UNSUPPORTED_SOURCE" in reason_set(mismatched_source)
    assert skewed.status == "NO_INTENT"
    assert "SOURCE_SKEW" in reason_set(skewed)


def test_duplicate_and_conflicting_layer_observations_fail_closed() -> None:
    rows = fixture_data()["request"]["observations"]
    duplicate = [*rows, dict(rows[0])]
    conflict = [*rows, {**rows[0], "semantic_digest": "f" * 64}]

    duplicate_result = evaluate(make_request(rows=duplicate), make_policy())
    conflict_result = evaluate(make_request(rows=conflict), make_policy())

    assert duplicate_result.status == "NO_INTENT"
    assert "DUPLICATE_LAYER" in reason_set(duplicate_result)
    assert conflict_result.status == "NO_INTENT"
    assert "CONFLICTING_LAYER" in reason_set(conflict_result)


@pytest.mark.parametrize(
    ("market", "expected_reason"),
    [
        ({"global_risk_off": True, "halted": False, "truth_rejected": False}, "RISK_OFF"),
        ({"global_risk_off": False, "halted": True, "truth_rejected": False}, "MARKET_HALT"),
        ({"global_risk_off": False, "halted": False, "truth_rejected": True}, "TRUTH_REJECTED"),
    ],
)
def test_truth_rejection_risk_off_and_halt_suppress_candidate(
    market: dict[str, bool], expected_reason: str
) -> None:
    result = evaluate(make_request(market=market), make_policy())

    assert result.status == "NO_INTENT"
    assert expected_reason in reason_set(result)


def test_future_feature_availability_fails_even_with_earlier_event_time() -> None:
    feature = FeatureSnapshotV1(
        snapshot_id="synthetic-feature-1",
        event_ns=NOW_NS - 1,
        available_ns=NOW_NS + 1,
    )

    result = evaluate(make_request(features=(feature,)), make_policy())

    assert result.status == "NO_INTENT"
    assert "FUTURE_FEATURE" in reason_set(result)


def test_future_snapshot_is_filtered_before_identity_when_visible_snapshot_exists() -> None:
    visible = FeatureSnapshotV1(
        snapshot_id="synthetic-visible-feature",
        event_ns=NOW_NS - 1,
        available_ns=NOW_NS - 1,
    )
    future = FeatureSnapshotV1(
        snapshot_id="synthetic-future-feature",
        event_ns=NOW_NS - 2,
        available_ns=NOW_NS + 1,
    )

    visible_result = evaluate(make_request(features=(visible,)), make_policy())
    future_added = evaluate(make_request(features=(visible, future)), make_policy())

    assert visible_result.status == "CAPITAL_CANDIDATE"
    assert future_added.status == "CAPITAL_CANDIDATE"
    assert future_added.canonical_bytes() == visible_result.canonical_bytes()


def test_stale_feature_and_more_than_five_attributions_are_handled_explicitly() -> None:
    stale_feature = FeatureSnapshotV1(
        snapshot_id="synthetic-old-feature",
        event_ns=NOW_NS - WINDOW_NS - 1,
        available_ns=NOW_NS - 1,
    )
    stale = evaluate(make_request(features=(stale_feature,)), make_policy())
    attributions = tuple(
        FeatureAttributionV1(feature=f"synthetic-feature-{index}", contribution=str(index))
        for index in range(8)
    )
    attributed = evaluate(make_request(attributions=attributions), make_policy())

    assert stale.status == "NO_INTENT"
    assert "STALE_FEATURE" in reason_set(stale)
    assert attributed.status == "CAPITAL_CANDIDATE"
    assert len(attributed.attributions) <= 5


def test_repeated_input_and_observation_permutations_are_byte_identical() -> None:
    observations = fixture_data()["request"]["observations"]
    policy = make_policy()
    first = evaluate(make_request(rows=observations), policy)
    replay = evaluate(make_request(rows=observations), policy)
    permuted = evaluate(make_request(rows=list(reversed(observations))), policy)

    assert first.canonical_bytes() == replay.canonical_bytes()
    assert first.canonical_bytes() == permuted.canonical_bytes()
    assert first.idempotency_key == replay.idempotency_key == permuted.idempotency_key


def test_changed_content_with_prior_hash_is_an_idempotency_conflict() -> None:
    policy = make_policy()
    original = evaluate(make_request(), policy)
    changed = make_request(
        rows=rows_with_change("L4", semantic_digest="e" * 64),
        prior_input_hash=original.input_hash,
    )

    result = evaluate(changed, policy)

    assert result.status == "NO_INTENT"
    assert "IDEMPOTENCY_CONFLICT" in reason_set(result)
    assert result.idempotency_check == "CONFLICT"


@pytest.mark.parametrize(
    "policy_change",
    [
        {"policy_id": "synthetic-policy-other"},
        {"policy_version": "v2"},
        {"min_l2_score": "0.75"},
    ],
)
def test_same_key_with_changed_policy_is_an_idempotency_conflict(
    policy_change: dict[str, str],
) -> None:
    original_policy = make_policy()
    original = evaluate(make_request(), original_policy)
    changed_policy = make_policy(**policy_change)
    replay = evaluate(
        make_request(prior_input_hash=original.input_hash),
        changed_policy,
    )

    assert replay.idempotency_key == original.idempotency_key
    assert replay.policy_hash != original.policy_hash
    assert replay.input_hash != original.input_hash
    assert replay.status == "NO_INTENT"
    assert replay.idempotency_check == "CONFLICT"
    assert "IDEMPOTENCY_CONFLICT" in reason_set(replay)


@pytest.mark.parametrize(
    ("invalid_field", "invalid_value"),
    [
        ("tenant_id", "synthetic-tenant\r\nSECRET"),
        ("source", "synthetic-é-SECRET"),
        ("strategy_hash", "G" * 64),
        ("semantic_digest", "g" * 64),
        ("prior_input_hash", "a" * 63),
    ],
    ids=["crlf-identity", "non-ascii-source", "uppercase-digest", "non-hex-digest", "short-digest"],
)
def test_closed_identity_source_and_digest_values_reject_without_echo(
    invalid_field: str, invalid_value: str
) -> None:
    with pytest.raises(FusionValidationError) as caught:
        if invalid_field == "tenant_id":
            fields = dict(fixture_data()["request"])
            fields["tenant_id"] = invalid_value
            fields["observations"] = observations_from()
            fields["market_context"] = MarketContextV1(**fields["market_context"])
            FusionRequestV1(**fields)
        elif invalid_field in {"source", "semantic_digest"}:
            rows = fixture_data()["request"]["observations"]
            rows[1][invalid_field] = invalid_value
            make_request(rows=rows)
        elif invalid_field == "strategy_hash":
            fields = dict(fixture_data()["request"])
            fields["strategy_hash"] = invalid_value
            fields["observations"] = observations_from()
            fields["market_context"] = MarketContextV1(**fields["market_context"])
            FusionRequestV1(**fields)
        else:
            make_request(prior_input_hash=invalid_value)

    assert_validation_error_redacts(caught.value, invalid_value)


def test_unlinked_and_future_attributions_cannot_change_an_earlier_candidate() -> None:
    visible_snapshot = FeatureSnapshotV1(
        snapshot_id="visible-feature",
        event_ns=NOW_NS - 1,
        available_ns=NOW_NS - 1,
    )
    linked = FeatureAttributionV1(
        feature="visible-feature-value",
        contribution="0.4",
        snapshot_id=visible_snapshot.snapshot_id,
    )
    unlinked = FeatureAttributionV1(feature="unlinked-canary", contribution="900")
    future_linked = FeatureAttributionV1(
        feature="future-canary",
        contribution="800",
        snapshot_id=visible_snapshot.snapshot_id,
        available_ns=NOW_NS + 1,
    )
    baseline = evaluate(
        make_request(features=(visible_snapshot,), attributions=(linked,)), make_policy()
    )
    with_untrusted_attributions = evaluate(
        make_request(
            features=(visible_snapshot,),
            attributions=(linked, unlinked, future_linked),
        ),
        make_policy(),
    )

    assert baseline.status == "CAPITAL_CANDIDATE"
    assert with_untrusted_attributions.status == "CAPITAL_CANDIDATE"
    assert with_untrusted_attributions.attributions == baseline.attributions
    assert with_untrusted_attributions.canonical_bytes() == baseline.canonical_bytes()


def test_future_only_attribution_is_excluded_from_input_and_result() -> None:
    future_only = FeatureAttributionV1(
        feature="future-only",
        contribution="1",
        available_ns=NOW_NS + 1,
    )
    baseline = evaluate(make_request(), make_policy())
    with_future = evaluate(make_request(attributions=(future_only,)), make_policy())

    assert with_future.status == "CAPITAL_CANDIDATE"
    assert with_future.attributions == ()
    assert with_future.canonical_bytes() == baseline.canonical_bytes()


def test_reason_codes_are_sorted_unique_when_future_layer_reasons_combine() -> None:
    rows = fixture_data()["request"]["observations"]
    late_l2 = next(item for item in rows if item["layer"] == "L2")
    second_late_l2 = {
        **late_l2,
        "semantic_digest": "f" * 64,
        "event_ns": NOW_NS + 1,
        "score": "0.1",
    }
    future = evaluate(make_request(rows=[*rows, second_late_l2]), make_policy())

    assert future.status == "NO_INTENT"
    assert future.reason_codes == tuple(sorted(set(future.reason_codes)))
    assert future.reason_codes.count("FUTURE_LAYER") == 1


def test_matching_prior_hash_is_explicitly_reported() -> None:
    policy = make_policy()
    original = evaluate(make_request(), policy)
    replay = evaluate(make_request(prior_input_hash=original.input_hash), policy)

    assert replay.status == "CAPITAL_CANDIDATE"
    assert replay.idempotency_check == "MATCH"
    assert "IDEMPOTENCY_CONFLICT" not in reason_set(replay)


def test_identical_request_is_byte_identical_across_processes() -> None:
    expected = evaluate(make_request(), make_policy()).canonical_bytes().decode("utf-8")
    module_dir = str(Path(__file__).parent)
    child_code = (
        "import sys; "
        f"sys.path.insert(0, {module_dir!r}); "
        "from test_fusion_acceptance import make_request, make_policy; "
        "from leviathan_core.decision_fusion import evaluate; "
        "print(evaluate(make_request(), make_policy()).canonical_bytes().decode('utf-8'))"
    )
    child = subprocess.run(
        [sys.executable, "-c", child_code],
        check=True,
        capture_output=True,
        text=True,
    )

    assert child.stdout.rstrip("\r\n") == expected


def test_fusion_candidate_is_not_a_route_permit_or_order_authorization() -> None:
    result = evaluate(make_request(), make_policy())

    assert result.status == "CAPITAL_CANDIDATE"
    assert not any(
        hasattr(result, name)
        for name in ("permit", "route", "order", "execution_token", "authorization")
    )
    assert "permit" not in result.canonical_bytes().decode("utf-8").lower()
    assert "order" not in result.canonical_bytes().decode("utf-8").lower()
