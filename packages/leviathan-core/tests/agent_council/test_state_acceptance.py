"""Independent adversarial acceptance tests for AGENT-001's bounded state kernel."""

from __future__ import annotations

import copy
import json
import pickle
import socket
import urllib.request
from decimal import Decimal, localcontext
from pathlib import Path
from typing import cast

import pytest

from leviathan_core.agent_council import (
    ActorAuthorityV1,
    CouncilEventV1,
    CouncilFrozenError,
    CouncilStateV1,
    CouncilValidationError,
    DatasetSnapshotRefV1,
    EvidenceClaimV1,
    EvidenceError,
    ExperimentSpecV1,
    HypothesisV1,
    IdentityConflictError,
    ParameterError,
    PrecisionExceededError,
    SignalRefV1,
    StateIntegrityError,
    TimeWindowV1,
    TransitionError,
    TypedParamV1,
    canonicalize_parameters,
    derive_experiment_id,
    issue_critic_evidence,
    issue_holdout_evidence,
    new_council_state,
    propose_experiment_identity,
    propose_transition,
    restore_verified_state,
)

NOW = 10_000_000_000
SIGNAL = SignalRefV1(signal_id="signal-breakout", version="v3")
AUTHOR = ActorAuthorityV1(actor_id="author", kind="human", roles=("researcher",))
OPERATOR = ActorAuthorityV1(actor_id="operator", kind="agent", roles=("operator",))
REVIEWER = ActorAuthorityV1(actor_id="reviewer", kind="human", roles=("reviewer",))
SCRIBE = ActorAuthorityV1(actor_id="scribe", kind="human", roles=("scribe",))
ACTORS = {actor.actor_id: actor for actor in (AUTHOR, OPERATOR, REVIEWER, SCRIBE)}


def hypothesis() -> HypothesisV1:
    return HypothesisV1(
        hypothesis_id="hypothesis-1",
        version=1,
        strategy_name="breakout study",
        signal_refs=(SIGNAL,),
        markets=("NQ",),
        horizon=TimeWindowV1(start_ns=1_000_000_000, end_ns=8_000_000_000),
        target_metrics=("sharpe", "max_drawdown"),
        max_leverage=Decimal("2"),
        max_loss_per_trade=Decimal("0.01"),
        seed_policy="fixed",
        seed=42,
        source_hashes=("a" * 64,),
    )


def make_state(**overrides: object):
    budgets: dict[str, object] = {
        "max_iterations": 3,
        "max_actions": 20,
        "max_runtime_ns": 5_000_000_000,
        "max_cost_usd": Decimal("20"),
        "max_no_progress_events": 3,
    }
    budgets.update(overrides)
    return new_council_state(
        hypothesis(),
        session_id="session-1",
        hypothesis_author_id="author",
        now_ns=NOW,
        **budgets,
    )


def event(sequence: int, event_type: str, actor_id: str, **fields: object) -> CouncilEventV1:
    return CouncilEventV1.model_validate(
        {
            "session_id": "session-1",
            "sequence": sequence,
            "event_type": event_type,
            "actor_id": actor_id,
            "at_ns": NOW + sequence,
            **fields,
        }
    )


def step(
    state,
    next_event: CouncilEventV1,
    *,
    authorize=ACTORS.get,
    **transition_args: object,
):
    return propose_transition(
        state,
        next_event,
        now_ns=NOW + next_event.sequence,
        authorize_actor=authorize,
        **transition_args,
    )


def ready_for_critique():
    current = make_state()
    current = step(current, event(1, "start_research", "author")).proposed_state
    current = step(
        current, event(2, "request_experiment", "author", experiment_id="experiment-1")
    ).proposed_state
    current = step(
        current,
        event(
            3,
            "experiment_completed",
            "operator",
            experiment_id="experiment-1",
            result_digest="c" * 64,
        ),
    ).proposed_state
    return step(current, event(4, "request_critique", "author")).proposed_state


def valid_approval(*, sequence: int = 5, **overrides: object) -> CouncilEventV1:
    fields: dict[str, object] = {
        "leak_checks_passed": True,
        "thresholds_passed": True,
        "critic_evidence_ref": "sha256:independent-critic",
        "holdout_evidence_ref": "sha256:holdout-result",
    }
    fields.update(overrides)
    return event(sequence, "approve", "reviewer", **fields)


class FakeVerifier:
    def __init__(self) -> None:
        self.result: object = True

    def verify_critic(self, claim: EvidenceClaimV1) -> bool:
        return cast(bool, self.result)

    def verify_holdout(self, claim: EvidenceClaimV1) -> bool:
        return cast(bool, self.result)


def evidence_args(
    state,
    *,
    experiment_id: str | None = None,
    revision_hash: str | None = None,
    result_digest: str | None = None,
):
    verifier = FakeVerifier()
    claim = EvidenceClaimV1(
        experiment_id=experiment_id or state.current_experiment_id,
        revision_content_hash=revision_hash or state.revision_content_hash,
        result_digest=result_digest or state.current_result_digest,
        evidence_digest="e" * 64,
    )
    return {
        "evidence_verifier": verifier,
        "critic_evidence": issue_critic_evidence(claim, verifier),
        "holdout_evidence": issue_holdout_evidence(claim, verifier),
    }


def test_hypothesis_requires_strict_decimal_guardrails_and_nonfuture_horizon() -> None:
    with pytest.raises(CouncilValidationError):
        HypothesisV1.model_validate({**hypothesis().model_dump(), "max_leverage": 2.0})
    with pytest.raises(CouncilValidationError):
        HypothesisV1.model_validate({**hypothesis().model_dump(), "route_to_broker": True})
    with pytest.raises(ValueError, match="future"):
        new_council_state(
            hypothesis(),
            session_id="session-1",
            hypothesis_author_id="author",
            now_ns=7_000_000_000,
            max_iterations=2,
            max_actions=10,
            max_runtime_ns=1_000_000_000,
            max_cost_usd=Decimal("1"),
            max_no_progress_events=2,
        )


def test_public_validation_errors_do_not_echo_untrusted_input() -> None:
    canary = "council-validation-canary-SECRET-84721"
    bad_hypothesis = {**hypothesis().model_dump(), "max_leverage": canary}

    with pytest.raises(CouncilValidationError) as caught:
        HypothesisV1.model_validate(bad_hypothesis)

    error = caught.value
    rendered = " ".join(
        (str(error), repr(error.args), repr(error.errors()), error.json())
    )
    assert canary not in rendered
    assert error.code == "COUNCIL_VALIDATION_ERROR"
    assert error.__context__ is None
    assert error.issues
    assert all(
        len(issue) == 2 and isinstance(issue[0], tuple) and isinstance(issue[1], str)
        for issue in error.issues
    )
    assert all(set(issue) <= {"loc", "type", "code"} for issue in error.errors())


def test_unknown_validation_field_name_is_redacted_from_public_error() -> None:
    field_canary = "private_unknown_field_CANARY_613"
    value_canary = "private_unknown_value_CANARY_914"
    bad_hypothesis = {
        **hypothesis().model_dump(),
        field_canary: value_canary,
    }

    with pytest.raises(CouncilValidationError) as caught:
        HypothesisV1.model_validate(bad_hypothesis)

    error = caught.value
    rendered = " ".join(
        (
            str(error),
            repr(error.args),
            repr(error.issues),
            repr(error.errors()),
            error.json(),
        )
    )
    assert field_canary not in rendered
    assert value_canary not in rendered
    assert error.errors()[0]["loc"] == ("<unknown>",)


def test_frozen_model_assignment_and_deletion_raise_sanitized_typed_error() -> None:
    model = event(1, "heartbeat", "operator")
    canary = "frozen-value-canary-516"

    with pytest.raises(CouncilFrozenError) as assignment:
        model.reason = canary
    with pytest.raises(CouncilFrozenError) as deletion:
        del model.reason

    for error in (assignment.value, deletion.value):
        assert error.code == "FROZEN_RECORD"
        assert canary not in str(error)
        assert canary not in repr(error.args)
        assert canary not in repr(error.errors())
        assert canary not in error.json()


def test_experiment_identity_is_stable_for_same_payload_and_conflicts_on_change() -> None:
    dataset = DatasetSnapshotRefV1(
        snapshot_id="snapshot-1",
        version=1,
        content_hash="b" * 64,
        horizon=TimeWindowV1(start_ns=1_000_000_000, end_ns=8_000_000_000),
    )
    common = dict(
        hypothesis_id="hypothesis-1",
        hypothesis_version=1,
        dataset=dataset,
        signal_refs=(SIGNAL,),
        engine_version="engine-v1",
        seed=42,
        train_window=TimeWindowV1(start_ns=1_000_000_000, end_ns=4_000_000_000),
        test_window=TimeWindowV1(start_ns=4_000_000_000, end_ns=8_000_000_000),
        idempotency_key="request-1",
    )
    first = ExperimentSpecV1(
        **common,
        typed_parameters=canonicalize_parameters(
            {"alpha": Decimal("1.00"), "count": 2}
        ),
    )
    same = ExperimentSpecV1(
        **common,
        typed_parameters=canonicalize_parameters(
            {"count": 2, "alpha": Decimal("1.0")}
        ),
    )
    assert derive_experiment_id(first) == derive_experiment_id(same)
    identity, by_key = propose_experiment_identity(first, {})
    assert propose_experiment_identity(same, by_key) == (identity, by_key)

    raw_first = ExperimentSpecV1(
        **common, parameters_json='{"alpha": 1, "count": 2}'
    )
    raw_same = ExperimentSpecV1(
        **common, parameters_json='{"count":2,"alpha":1}'
    )
    assert derive_experiment_id(raw_first) == derive_experiment_id(raw_same)
    raw_identity, raw_by_key = propose_experiment_identity(raw_first, {})
    assert propose_experiment_identity(raw_same, raw_by_key) == (
        raw_identity,
        raw_by_key,
    )

    changed = ExperimentSpecV1(
        **common, typed_parameters=canonicalize_parameters({"count": 3})
    )
    with pytest.raises(IdentityConflictError):
        propose_experiment_identity(changed, by_key)

    with pytest.raises(CouncilValidationError):
        ExperimentSpecV1(
            **{
                **common,
                "test_window": TimeWindowV1(
                    start_ns=3_000_000_000, end_ns=8_000_000_000
                ),
            },
            parameters_json="{}",
        )


def test_tagged_decimal_parameters_keep_identity_through_model_round_trips() -> None:
    dataset = DatasetSnapshotRefV1(
        snapshot_id="snapshot-tagged-decimal",
        version=1,
        content_hash="b" * 64,
        horizon=TimeWindowV1(start_ns=1_000_000_000, end_ns=8_000_000_000),
    )
    common = dict(
        hypothesis_id="hypothesis-1",
        hypothesis_version=1,
        dataset=dataset,
        signal_refs=(SIGNAL,),
        engine_version="engine-v1",
        seed=42,
        train_window=TimeWindowV1(start_ns=1_000_000_000, end_ns=4_000_000_000),
        test_window=TimeWindowV1(start_ns=4_000_000_000, end_ns=8_000_000_000),
        idempotency_key="tagged-decimal-round-trip",
    )
    original = ExperimentSpecV1(**common, typed_parameters={"x": Decimal("1")})
    explicit_typed = ExperimentSpecV1(
        **common,
        typed_parameters=(TypedParamV1(name="x", kind="decimal", value="1"),),
    )
    from_mapping = ExperimentSpecV1.model_validate(original.model_dump())
    from_json = ExperimentSpecV1.model_validate_json(original.model_dump_json())
    fresh_typed = ExperimentSpecV1(
        **common,
        typed_parameters=original.typed_parameters,
        parameters_json=original.parameters_json,
    )
    raw_json = ExperimentSpecV1(**common, parameters_json='{"x":1}')
    raw_from_mapping = ExperimentSpecV1.model_validate(raw_json.model_dump())
    raw_from_json = ExperimentSpecV1.model_validate_json(raw_json.model_dump_json())
    fresh_raw_json = ExperimentSpecV1(
        **common, parameters_json=raw_json.parameters_json
    )
    ordinary_reserved_key = ExperimentSpecV1(
        **common,
        parameters_json='{"__leviathan_parameters_v2__":"ordinary"}',
    )
    with pytest.raises(CouncilValidationError):
        ExperimentSpecV1(
            **common,
            parameters_json=(
                '{"__leviathan_parameters_v2__":["map",'
                '[["x",["decimal","1"]]]]}'
            ),
        )
    for unsupported_number in ('{"x":1.0}', '{"x":1e0}'):
        with pytest.raises(CouncilValidationError):
            ExperimentSpecV1(**common, parameters_json=unsupported_number)

    expected_id = derive_experiment_id(original)
    assert derive_experiment_id(explicit_typed) == expected_id
    assert explicit_typed.typed_parameters == canonicalize_parameters(
        {"x": Decimal("1")}
    )
    assert derive_experiment_id(from_mapping) == expected_id
    assert derive_experiment_id(from_json) == expected_id
    assert derive_experiment_id(fresh_typed) == expected_id
    assert raw_json.typed_parameters == (
        TypedParamV1(name="x", kind="int", value="1"),
    )
    assert derive_experiment_id(raw_json) != expected_id
    assert derive_experiment_id(fresh_raw_json) == derive_experiment_id(raw_json)
    assert derive_experiment_id(raw_from_mapping) == derive_experiment_id(raw_json)
    assert derive_experiment_id(raw_from_json) == derive_experiment_id(raw_json)
    assert ordinary_reserved_key.typed_parameters == (
        TypedParamV1(
            name="__leviathan_parameters_v2__", kind="str", value="ordinary"
        ),
    )
    assert derive_experiment_id(ordinary_reserved_key) != expected_id


def test_holdout_snapshots_cannot_train_and_split_windows_stay_in_snapshot() -> None:
    holdout = DatasetSnapshotRefV1(
        snapshot_id="holdout-1",
        version=1,
        content_hash="c" * 64,
        horizon=TimeWindowV1(start_ns=1_000_000_000, end_ns=8_000_000_000),
        is_holdout=True,
    )
    with pytest.raises(CouncilValidationError):
        ExperimentSpecV1(
            hypothesis_id="hypothesis-1",
            hypothesis_version=1,
            dataset=holdout,
            signal_refs=(SIGNAL,),
            engine_version="engine-v1",
            parameters_json="{}",
            seed=42,
            train_window=TimeWindowV1(start_ns=1_000_000_000, end_ns=4_000_000_000),
            test_window=TimeWindowV1(start_ns=4_000_000_000, end_ns=8_000_000_000),
            idempotency_key="holdout-request",
        )

    valid_holdout = ExperimentSpecV1(
        hypothesis_id="hypothesis-1",
        hypothesis_version=1,
        dataset=holdout,
        signal_refs=(SIGNAL,),
        engine_version="engine-v1",
        parameters_json="{}",
        seed=42,
        train_window=None,
        test_window=TimeWindowV1(start_ns=1_000_000_000, end_ns=8_000_000_000),
        idempotency_key="holdout-only-request",
    )
    assert valid_holdout.dataset.is_holdout is True
    assert valid_holdout.train_window is None


def test_no_promotion_without_completed_experiment_independent_critic_and_holdout() -> None:
    current = ready_for_critique()

    for missing in (
        {"critic_evidence_ref": None},
        {"holdout_evidence_ref": None},
        {"leak_checks_passed": False},
        {"thresholds_passed": False},
    ):
        with pytest.raises(TransitionError):
            step(current, valid_approval(**missing))

    agent_reviewer = ActorAuthorityV1(
        actor_id="reviewer", kind="agent", roles=("reviewer",)
    )
    with pytest.raises(TransitionError, match="agent cannot"):
        step(
            current,
            valid_approval(),
            authorize=lambda actor_id: (
                agent_reviewer if actor_id == "reviewer" else ACTORS.get(actor_id)
            ),
        )

    author_with_reviewer_role = ActorAuthorityV1(
        actor_id="author", kind="human", roles=("researcher", "reviewer")
    )
    self_approval = event(
        5,
        "approve",
        "author",
        leak_checks_passed=True,
        thresholds_passed=True,
        critic_evidence_ref="sha256:critic",
        holdout_evidence_ref="sha256:holdout",
    )
    with pytest.raises(TransitionError, match="own work"):
        step(
            current,
            self_approval,
            authorize=lambda actor_id: (
                author_with_reviewer_role if actor_id == "author" else ACTORS.get(actor_id)
            ),
        )

    approved = step(current, valid_approval(), **evidence_args(current))
    assert approved.proposed_state.status == "approved"
    assert approved.proposed_state.final_decision_event_id == "session-1:5"
    assert approved.proposed_state.events[-1].critic_evidence_ref == "e" * 64
    assert approved.proposed_state.events[-1].holdout_evidence_ref == "e" * 64
    with pytest.raises(TransitionError):
        step(approved.proposed_state, valid_approval(sequence=6))


def test_no_progress_and_all_budgets_terminate_before_exceeding_limits() -> None:
    current = make_state(max_no_progress_events=2)
    current = step(current, event(1, "start_research", "author")).proposed_state
    current = step(current, event(2, "heartbeat", "operator")).proposed_state
    no_progress = step(current, event(3, "heartbeat", "operator"))
    assert no_progress.proposed_state.status == "error"
    assert no_progress.terminal_reason == "no_progress_limit_reached"
    assert no_progress.proposed_state.actions_used == 3
    assert no_progress.proposed_state.events[-1].accepted is False
    with pytest.raises(TransitionError):
        step(no_progress.proposed_state, event(4, "heartbeat", "operator"))

    by_iteration = make_state(max_iterations=1)
    by_iteration = step(by_iteration, event(1, "start_research", "author")).proposed_state
    by_iteration = step(
        by_iteration, event(2, "request_experiment", "author", experiment_id="exp-1")
    ).proposed_state
    by_iteration = step(
        by_iteration,
        event(
            3,
            "experiment_completed",
            "operator",
            experiment_id="exp-1",
            result_digest="d" * 64,
        ),
    ).proposed_state
    iteration_terminal = step(
        by_iteration,
        event(4, "request_experiment", "author", experiment_id="exp-2"),
    )
    assert iteration_terminal.proposed_state.status == "error"
    assert iteration_terminal.proposed_state.iteration_count <= 1
    assert iteration_terminal.proposed_state.events[-1].accepted is False
    assert iteration_terminal.proposed_state.requested_experiment_ids == ("exp-1",)
    assert iteration_terminal.terminal_reason == "iteration_budget_exhausted"

    by_cost = make_state(max_cost_usd=Decimal("1"))
    cost_terminal = step(by_cost, event(1, "start_research", "author", cost_usd=Decimal("2")))
    assert cost_terminal.proposed_state.status == "error"
    assert cost_terminal.proposed_state.cost_spent_usd <= Decimal("1")
    assert cost_terminal.proposed_state.events[-1].accepted is False
    assert cost_terminal.terminal_reason == "cost_budget_exhausted"

    by_action = make_state(max_actions=1)
    action_terminal = step(by_action, event(1, "start_research", "author"))
    assert action_terminal.proposed_state.status == "error"
    assert action_terminal.proposed_state.actions_used == 1
    assert action_terminal.terminal_reason == "action_budget_exhausted"

    by_time = make_state(max_runtime_ns=1)
    time_terminal = propose_transition(
        by_time,
        event(1, "start_research", "author"),
        now_ns=by_time.deadline_ns,
        authorize_actor=ACTORS.get,
    )
    assert time_terminal.proposed_state.status == "error"
    assert time_terminal.terminal_reason == "time_budget_exhausted"


def test_cancel_rollback_and_publication_are_proposals_without_external_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("state kernel attempted an external side effect")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)

    current = make_state()
    cancel_event = event(1, "cancel", "operator", reason="operator requested stop")
    canceled = step(current, cancel_event)
    assert current.status == "draft"
    assert canceled.proposed_state.status == "canceled"
    assert canceled.cancellation_intent is True
    assert canceled.proposed_state.events == (cancel_event,)
    with pytest.raises(TransitionError):
        step(canceled.proposed_state, event(2, "heartbeat", "operator"))

    current = ready_for_critique()
    approved = step(current, valid_approval(), **evidence_args(current))
    published_event = event(
        6, "publication_recorded", "scribe", publication_receipt_ref="receipt:local-preview"
    )
    published = step(approved.proposed_state, published_event)
    assert published.proposed_state.status == "published"
    assert published.proposed_state.events[-1].publication_receipt_ref == "receipt:local-preview"
    assert published.cancellation_intent is False

    reviewer_authority = ActorAuthorityV1(
        actor_id="author", kind="human", roles=("researcher", "reviewer")
    )
    with pytest.raises(TransitionError, match="own approval"):
        step(
            published.proposed_state,
            event(7, "rollback", "author", reason="self rollback"),
            authorize=lambda actor_id: (
                reviewer_authority if actor_id == "author" else ACTORS.get(actor_id)
            ),
        )

    rolled_back = step(
        published.proposed_state,
        event(7, "rollback", "reviewer", reason="holdout evidence was withdrawn"),
    )
    assert rolled_back.proposed_state.status == "rolled_back"
    assert (
        rolled_back.proposed_state.final_decision_event_id
        == approved.proposed_state.final_decision_event_id
    )
    assert rolled_back.proposed_state.events[-1].reason == "holdout evidence was withdrawn"
    assert rolled_back.cancellation_intent is True
    with pytest.raises(TransitionError):
        step(rolled_back.proposed_state, event(8, "rollback", "reviewer", reason="again"))


def test_event_roles_are_resolved_by_trusted_callback_and_unknown_fields_fail() -> None:
    current = make_state()
    untrusted_role_claim = event(1, "start_research", "attacker")
    with pytest.raises(TransitionError, match="trusted authorization"):
        step(current, untrusted_role_claim, authorize=lambda _actor: None)

    with pytest.raises(CouncilValidationError):
        CouncilEventV1.model_validate(
            {**untrusted_role_claim.model_dump(), "actor_role": "reviewer"}
        )

    with pytest.raises(TransitionError):
        propose_transition(
            current,
            untrusted_role_claim,
            now_ns=NOW + 1,
            authorize_actor=ACTORS.get,
        )


def test_parameter_decimal_encoding_is_exact_context_independent_and_typed() -> None:
    first = Decimal("1.234567890123456789012345678901")
    second = Decimal("1.234567890123456789012345678902")
    assert canonicalize_parameters({"x": first}) != canonicalize_parameters({"x": second})

    with localcontext() as context:
        context.prec = 8
        low_precision = canonicalize_parameters({"x": Decimal("1.234567890123456789")})
    with localcontext() as context:
        context.prec = 50
        high_precision = canonicalize_parameters({"x": Decimal("1.234567890123456789")})
    assert low_precision == high_precision

    decimal_value = canonicalize_parameters({"x": Decimal("1")})
    ordinary_old_marker = canonicalize_parameters({"__decimal__": "1"})
    assert decimal_value != ordinary_old_marker
    with pytest.raises(ParameterError):
        canonicalize_parameters({"x": {"__decimal__": "1"}})
    long_spelling_of_one = Decimal("1." + "0" * 40)
    assert long_spelling_of_one == Decimal("1")
    assert canonicalize_parameters({"x": long_spelling_of_one}) == decimal_value

    over_precision = Decimal("1." + "2345678901234567890123456789012345")
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        canonicalize_parameters({"x": over_precision})

    with pytest.raises(ParameterError):
        canonicalize_parameters({"x": Decimal("1E+100000")})
    with pytest.raises(ParameterError):
        canonicalize_parameters({"x": "\ud800"})
    with pytest.raises(ParameterError):
        canonicalize_parameters({"x": "z" * 65536})
    nested: object = "leaf"
    for _ in range(128):
        nested = [nested]
    with pytest.raises(ParameterError):
        canonicalize_parameters({"x": nested})

    with pytest.raises(ParameterError, match="integer parameter exceeds bounds") as failure:
        canonicalize_parameters({"x": 10**5000})
    assert len(str(failure.value)) < 256


def test_unverified_loaded_or_copied_states_cannot_reach_approval() -> None:
    state = make_state()
    forged = json.loads(state.model_dump_json())
    forged.update(
        status="approved",
        events=[event(1, "approve", "author").model_dump(mode="json")],
        actions_used=1,
        final_decision_event_id=f"{state.session_id}:1",
    )
    with pytest.raises(StateIntegrityError):
        CouncilStateV1.model_validate(forged)
    with pytest.raises(StateIntegrityError):
        CouncilStateV1.model_validate_json(json.dumps(forged))
    with pytest.raises(StateIntegrityError):
        CouncilStateV1(**state.model_dump())
    with pytest.raises(StateIntegrityError):
        CouncilStateV1.model_validate_strings(state.model_dump())
    with pytest.raises(StateIntegrityError):
        state.model_copy(update={"status": "approved"})
    with pytest.raises(StateIntegrityError):
        CouncilStateV1.model_construct(**state.model_dump())
    if hasattr(copy, "replace"):
        with pytest.raises(StateIntegrityError):
            copy.replace(state, status="approved")
    for clone in (copy.copy, copy.deepcopy, lambda value: pickle.loads(pickle.dumps(value))):
        with pytest.raises(StateIntegrityError):
            clone(state)

    serialized = state.model_dump_json()
    with pytest.raises(StateIntegrityError):
        restore_verified_state(serialized, verify_chain=lambda _digest, _payload: False)
    tampered = json.loads(serialized)
    tampered["status"] = "approved"
    with pytest.raises(StateIntegrityError):
        restore_verified_state(
            json.dumps(tampered), verify_chain=lambda _digest, _payload: True
        )


def test_evidence_tokens_must_be_verified_and_bound_to_experiment_and_revision() -> None:
    current = ready_for_critique()
    with pytest.raises(TransitionError):
        step(current, valid_approval())

    for mismatch in (
        {"experiment_id": "other-experiment"},
        {"revision_hash": "f" * 64},
        {"result_digest": "d" * 64},
    ):
        with pytest.raises(TransitionError):
            step(current, valid_approval(), **evidence_args(current, **mismatch))

    accepted = step(current, valid_approval(), **evidence_args(current))
    assert accepted.proposed_state.status == "approved"


@pytest.mark.parametrize("verdict", ("false", 1))
def test_verifier_non_boolean_results_fail_at_issuance_and_approval(
    verdict: object,
) -> None:
    current = ready_for_critique()
    claim = EvidenceClaimV1(
        experiment_id=current.current_experiment_id,
        revision_content_hash=current.revision_content_hash,
        result_digest=current.current_result_digest,
        evidence_digest="e" * 64,
    )
    rejecting_verifier = FakeVerifier()
    rejecting_verifier.result = verdict

    with pytest.raises(EvidenceError, match="VERIFIER_RESULT_INVALID"):
        issue_critic_evidence(claim, rejecting_verifier)
    with pytest.raises(EvidenceError, match="VERIFIER_RESULT_INVALID"):
        issue_holdout_evidence(claim, rejecting_verifier)

    verified_args = evidence_args(current)
    verifier = verified_args["evidence_verifier"]
    assert isinstance(verifier, FakeVerifier)
    verifier.result = verdict
    with pytest.raises(TransitionError, match="VERIFIER_RESULT_INVALID"):
        step(current, valid_approval(), **verified_args)


def test_cost_rounding_up_cannot_hide_a_budget_overrun() -> None:
    limit = Decimal("1.0000000000000000000000000001")
    current = make_state(max_cost_usd=limit)
    current = step(
        current,
        event(1, "start_research", "author", cost_usd=Decimal("1")),
    ).proposed_state
    overrun = step(
        current,
        event(2, "heartbeat", "operator", cost_usd=Decimal("1E-28")),
    )

    assert overrun.proposed_state.status == "error"
    assert overrun.proposed_state.events[-1].accepted is False
    assert overrun.terminal_reason == "cost_budget_exhausted"
    assert overrun.proposed_state.cost_spent_usd <= limit


def test_event_cost_validation_cannot_be_bypassed_by_copy_or_construct() -> None:
    valid_event = event(1, "start_research", "author", cost_usd=Decimal("1"))
    accepted = step(make_state(), valid_event)

    with pytest.raises(CouncilValidationError):
        valid_event.model_copy(update={"cost_usd": Decimal("-8")})
    with pytest.raises(ValueError):
        CouncilEventV1.model_construct(
            session_id="session-1",
            sequence=2,
            event_type="heartbeat",
            actor_id="operator",
            at_ns=NOW + 2,
            cost_usd=Decimal("-8"),
        )

    assert accepted.proposed_state.cost_spent_usd == Decimal("1")


def test_cost_conversion_uses_kernel_decimal_context_under_low_ambient_emax() -> None:
    current = make_state(max_cost_usd=Decimal("2"))

    with localcontext() as context:
        context.Emax = 9
        accepted = step(
            current,
            event(1, "start_research", "author", cost_usd=Decimal("1")),
        )

    assert accepted.proposed_state.cost_spent_usd == Decimal("1")
    assert accepted.proposed_state.status == "researching"


def test_parameter_order_and_decimal_spelling_do_not_change_identity() -> None:
    dataset = DatasetSnapshotRefV1(
        snapshot_id="snapshot-raw-json",
        version=1,
        content_hash="b" * 64,
        horizon=TimeWindowV1(start_ns=1_000_000_000, end_ns=8_000_000_000),
    )
    common = dict(
        hypothesis_id="hypothesis-1",
        hypothesis_version=1,
        dataset=dataset,
        signal_refs=(SIGNAL,),
        engine_version="engine-v1",
        seed=42,
        train_window=TimeWindowV1(start_ns=1_000_000_000, end_ns=4_000_000_000),
        test_window=TimeWindowV1(start_ns=4_000_000_000, end_ns=8_000_000_000),
        idempotency_key="raw-json-request",
    )
    first = ExperimentSpecV1(
        **common, parameters_json='{"alpha": 1, "count": 2}'
    )
    equivalent = ExperimentSpecV1(
        **common, parameters_json='{"count":2,"alpha":1}'
    )

    assert derive_experiment_id(first) == derive_experiment_id(equivalent)
    identity, by_key = propose_experiment_identity(first, {})
    assert propose_experiment_identity(equivalent, by_key) == (identity, by_key)

    decimal_first = ExperimentSpecV1(
        **common,
        typed_parameters=canonicalize_parameters({"alpha": Decimal("1.00")}),
    )
    decimal_equivalent = ExperimentSpecV1(
        **common,
        typed_parameters=canonicalize_parameters({"alpha": Decimal("1.0")}),
    )
    assert derive_experiment_id(decimal_first) == derive_experiment_id(
        decimal_equivalent
    )


def test_terminal_cancel_cost_overrun_is_recorded_exactly_and_blocks_approval() -> None:
    current = make_state(max_cost_usd=Decimal("1"))
    over_budget_cancel = step(
        current,
        event(
            1,
            "cancel",
            "operator",
            cost_usd=Decimal("2"),
            reason="stop after budget overrun",
        ),
    )

    assert over_budget_cancel.proposed_state.status == "BUDGET_EXCEEDED"
    assert over_budget_cancel.proposed_state.termination_reason == "BUDGET_EXCEEDED"
    assert over_budget_cancel.proposed_state.cost_spent_usd == Decimal("2")
    assert over_budget_cancel.proposed_state.budget_overrun_usd == Decimal("1")
    assert over_budget_cancel.proposed_state.events[-1].accepted is True
    assert over_budget_cancel.proposed_state.events[-1].cost_usd == Decimal("2")
    assert over_budget_cancel.cancellation_intent is True

    with pytest.raises(TransitionError):
        step(over_budget_cancel.proposed_state, valid_approval(sequence=2))


def test_revision_churn_with_identical_content_is_no_progress() -> None:
    current = make_state(max_no_progress_events=1)
    current = step(current, event(1, "start_research", "author")).proposed_state
    current = step(
        current, event(2, "request_experiment", "author", experiment_id="exp-1")
    ).proposed_state
    current = step(
        current,
        event(
            3,
            "experiment_completed",
            "operator",
            experiment_id="exp-1",
            result_digest="a" * 64,
        ),
    ).proposed_state
    current = step(current, event(4, "request_critique", "author")).proposed_state
    current = step(
        current,
        event(5, "request_revisions", "reviewer", reason="revise hypothesis"),
    ).proposed_state
    same_content_new_revision = hypothesis().model_copy(update={"version": 2})
    churn = step(
        current,
        event(6, "revise", "author", revision=same_content_new_revision),
    )

    assert churn.proposed_state.status == "error"
    assert churn.terminal_reason == "no_progress_limit_reached"


def test_signal_reorder_only_revision_is_no_progress() -> None:
    two_signal_hypothesis = hypothesis().model_copy(
        update={
            "signal_refs": (
                SIGNAL,
                SignalRefV1(signal_id="signal-volume", version="v1"),
            )
        }
    )
    current = new_council_state(
        two_signal_hypothesis,
        session_id="session-1",
        hypothesis_author_id="author",
        now_ns=NOW,
        max_iterations=3,
        max_actions=20,
        max_runtime_ns=5_000_000_000,
        max_cost_usd=Decimal("20"),
        max_no_progress_events=1,
    )
    current = step(current, event(1, "start_research", "author")).proposed_state
    current = step(
        current, event(2, "request_experiment", "author", experiment_id="order-exp")
    ).proposed_state
    current = step(
        current,
        event(
            3,
            "experiment_completed",
            "operator",
            experiment_id="order-exp",
            result_digest="a" * 64,
        ),
    ).proposed_state
    current = step(current, event(4, "request_critique", "author")).proposed_state
    current = step(
        current,
        event(5, "request_revisions", "reviewer", reason="reorder signals"),
    ).proposed_state
    reordered = two_signal_hypothesis.model_copy(
        update={
            "version": 2,
            "signal_refs": tuple(reversed(two_signal_hypothesis.signal_refs)),
        }
    )

    result = step(current, event(6, "revise", "author", revision=reordered))

    assert result.proposed_state.status == "error"
    assert result.terminal_reason == "no_progress_limit_reached"
    assert result.proposed_state.events[-1].accepted is False


def test_stale_experiment_completion_has_specific_terminal_reason() -> None:
    current = step(make_state(), event(1, "start_research", "author")).proposed_state
    current = step(
        current, event(2, "request_experiment", "author", experiment_id="current-exp")
    ).proposed_state

    with pytest.raises(TransitionError, match="STALE_EXPERIMENT"):
        step(
            current,
            event(
                3,
                "experiment_completed",
                "operator",
                experiment_id="old-exp",
                result_digest="b" * 64,
            ),
        )
