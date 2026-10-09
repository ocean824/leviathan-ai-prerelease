"""Contract tests for the pure AGENT-001 state and identity kernel."""

import copy
import json
import pickle
from decimal import Decimal, localcontext

import pytest

from leviathan_core.agent_council import (
    ActorAuthorityV1,
    CouncilEventV1,
    CouncilStateV1,
    CouncilValidationError,
    CriticEvidenceV1,
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
SIGNAL = SignalRefV1(signal_id="breakout", version="v2")
AUTHOR = ActorAuthorityV1(actor_id="author", kind="human", roles=("researcher",))
OPERATOR = ActorAuthorityV1(actor_id="operator", kind="agent", roles=("operator",))
REVIEWER = ActorAuthorityV1(actor_id="reviewer", kind="human", roles=("reviewer",))
SCRIBE = ActorAuthorityV1(actor_id="scribe", kind="human", roles=("scribe",))
ACTORS = {actor.actor_id: actor for actor in (AUTHOR, OPERATOR, REVIEWER, SCRIBE)}


def hypothesis() -> HypothesisV1:
    return HypothesisV1(
        hypothesis_id="h1",
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


def state(**budgets: object):  # type: ignore[no-untyped-def]
    values = {
        "max_iterations": 3,
        "max_actions": 20,
        "max_runtime_ns": 5_000_000_000,
        "max_cost_usd": Decimal("20"),
        "max_no_progress_events": 3,
    }
    values.update(budgets)
    return new_council_state(
        hypothesis(), session_id="s1", hypothesis_author_id="author", now_ns=NOW, **values
    )


def event(sequence: int, event_type: str, actor_id: str, **fields: object) -> CouncilEventV1:
    return CouncilEventV1.model_validate(
        {
            "session_id": "s1",
            "sequence": sequence,
            "event_type": event_type,
            "actor_id": actor_id,
            "at_ns": NOW + sequence,
            **fields,
        }
    )


def step(current, next_event: CouncilEventV1, **proof: object):  # type: ignore[no-untyped-def]
    return propose_transition(
        current, next_event, now_ns=NOW + next_event.sequence, authorize_actor=ACTORS.get,
        **proof,
    )


class FakeVerifier:
    def verify_critic(self, _claim: EvidenceClaimV1) -> bool:
        return True

    def verify_holdout(self, _claim: EvidenceClaimV1) -> bool:
        return True


def evidence_for(current: CouncilStateV1) -> dict[str, object]:
    assert current.current_experiment_id is not None
    assert current.current_result_digest is not None
    verifier = FakeVerifier()
    binding = dict(
        experiment_id=current.current_experiment_id,
        revision_content_hash=current.revision_content_hash,
        result_digest=current.current_result_digest,
    )
    critic = EvidenceClaimV1(**binding, evidence_digest="c" * 64)
    holdout = EvidenceClaimV1(**binding, evidence_digest="e" * 64)
    return {
        "evidence_verifier": verifier,
        "critic_evidence": issue_critic_evidence(critic, verifier),
        "holdout_evidence": issue_holdout_evidence(holdout, verifier),
    }


def ready_for_review():  # type: ignore[no-untyped-def]
    current = state()
    current = step(current, event(1, "start_research", "author")).proposed_state
    current = step(
        current, event(2, "request_experiment", "author", experiment_id="exp_1")
    ).proposed_state
    current = step(
        current, event(
            3, "experiment_completed", "operator",
            experiment_id="exp_1", result_digest="d" * 64,
        )
    ).proposed_state
    return step(current, event(4, "request_critique", "author")).proposed_state


def test_hypothesis_requires_decimal_and_injected_nonfuture_clock() -> None:
    assert HypothesisV1.model_validate_json(hypothesis().model_dump_json()) == hypothesis()
    with pytest.raises(CouncilValidationError):
        HypothesisV1.model_validate({**hypothesis().model_dump(), "max_leverage": 2.0})
    with pytest.raises(CouncilValidationError):
        HypothesisV1.model_validate({**hypothesis().model_dump(), "route_to_broker": True})
    with pytest.raises(ValueError, match="future"):
        new_council_state(
            hypothesis(),
            session_id="s1",
            hypothesis_author_id="author",
            now_ns=7_000_000_000,
            max_iterations=2,
            max_actions=10,
            max_runtime_ns=1_000_000_000,
            max_cost_usd=Decimal("1"),
            max_no_progress_events=2,
        )


def test_experiment_identity_is_canonical_and_key_conflicts() -> None:
    dataset = DatasetSnapshotRefV1(
        snapshot_id="ds1",
        version=1,
        content_hash="b" * 64,
        horizon=TimeWindowV1(start_ns=1_000_000_000, end_ns=8_000_000_000),
    )
    common = dict(
        hypothesis_id="h1",
        hypothesis_version=1,
        dataset=dataset,
        signal_refs=(SIGNAL,),
        engine_version="r1",
        seed=42,
        train_window=TimeWindowV1(start_ns=1_000_000_000, end_ns=4_000_000_000),
        test_window=TimeWindowV1(start_ns=4_000_000_000, end_ns=8_000_000_000),
        idempotency_key="key1",
    )
    one = ExperimentSpecV1(
        **common, typed_parameters=canonicalize_parameters({"alpha": Decimal("1.00"), "n": 2})
    )
    two = ExperimentSpecV1(
        **common, typed_parameters=canonicalize_parameters({"n": 2, "alpha": Decimal("1.0")})
    )
    assert derive_experiment_id(one) == derive_experiment_id(two)
    identity, registry = propose_experiment_identity(one, {})
    assert propose_experiment_identity(two, registry) == (identity, registry)
    changed = ExperimentSpecV1(**common, typed_parameters=canonicalize_parameters({"n": 3}))
    with pytest.raises(IdentityConflictError):
        propose_experiment_identity(changed, registry)
    rerun = ExperimentSpecV1(
        **{**common, "idempotency_key": "key2"},
        typed_parameters=one.typed_parameters,
        run_version=2,
        parent_experiment_id=identity,
    )
    assert derive_experiment_id(rerun) != identity
    with pytest.raises(CouncilValidationError):
        ExperimentSpecV1(
            **{**common, "test_window": TimeWindowV1(start_ns=3_000_000_000, end_ns=8_000_000_000)},
            parameters_json="{}",
        )


def test_role_and_evidence_gates_prevent_self_approval() -> None:
    current = ready_for_review()
    approval = dict(
        leak_checks_passed=True,
        thresholds_passed=True,
        critic_evidence_ref="sha256:critic",
        holdout_evidence_ref="sha256:holdout",
    )
    with pytest.raises(TransitionError, match="trusted role"):
        step(current, event(5, "approve", "author", **approval))
    author_with_reviewer_role = ActorAuthorityV1(
        actor_id="author", kind="human", roles=("researcher", "reviewer")
    )
    with pytest.raises(TransitionError, match="own work"):
        propose_transition(
            current,
            event(5, "approve", "author", **approval),
            now_ns=NOW + 5,
            authorize_actor=lambda actor_id: (
                author_with_reviewer_role if actor_id == "author" else ACTORS.get(actor_id)
            ),
        )
    agent_reviewer = ActorAuthorityV1(actor_id="reviewer", kind="agent", roles=("reviewer",))
    with pytest.raises(TransitionError, match="agent cannot"):
        propose_transition(
            current,
            event(5, "approve", "reviewer", **approval),
            now_ns=NOW + 5,
            authorize_actor=lambda actor_id: (
                agent_reviewer if actor_id == "reviewer" else ACTORS.get(actor_id)
            ),
        )
    with pytest.raises(TransitionError, match="tokens"):
        step(current, event(5, "approve", "reviewer", **approval))
    approved = step(current, event(5, "approve", "reviewer", **approval), **evidence_for(current))
    assert approved.proposed_state.status == "approved"
    assert approved.proposed_state.final_decision_event_id == "s1:5"
    with pytest.raises(TransitionError):
        step(approved.proposed_state, event(6, "approve", "reviewer", **approval))
    with pytest.raises(TransitionError, match="required trusted role"):
        step(approved.proposed_state, event(6, "publication_recorded", "operator"))
    late_publication = propose_transition(
        approved.proposed_state,
        event(6, "publication_recorded", "scribe", publication_receipt_ref="receipt:late"),
        now_ns=approved.proposed_state.deadline_ns,
        authorize_actor=ACTORS.get,
    )
    assert late_publication.proposed_state.status == "error"
    assert late_publication.proposed_state.events[-1].accepted is False
    assert late_publication.terminal_reason == "time_budget_exhausted"
    published = step(
        approved.proposed_state,
        event(6, "publication_recorded", "scribe", publication_receipt_ref="receipt:1"),
    )
    assert published.proposed_state.status == "published"
    assert published.cancellation_intent is False
    rolled_back = step(
        published.proposed_state,
        event(7, "rollback", "reviewer", reason="holdout evidence was withdrawn"),
    )
    assert rolled_back.proposed_state.status == "rolled_back"
    assert rolled_back.cancellation_intent is True
    assert rolled_back.proposed_state.final_decision_event_id == "s1:5"


def test_cancel_is_traceable_proposal_and_replay_fails() -> None:
    current = state()
    cancel = event(1, "cancel", "operator", reason="operator requested stop")
    result = step(current, cancel)
    assert current.status == "draft"
    assert result.expected_previous_sequence == 0
    assert result.cancellation_intent is True
    assert result.proposed_state.events == (cancel,)
    with pytest.raises(TransitionError):
        step(result.proposed_state, cancel)
    with pytest.raises(TransitionError, match="required validated contracts"):
        propose_transition(current, None, now_ns=NOW, authorize_actor=ACTORS.get)  # type: ignore[arg-type]


def test_no_progress_and_budget_terminate_without_effect() -> None:
    current = state(max_no_progress_events=2)
    current = step(current, event(1, "start_research", "author")).proposed_state
    current = step(current, event(2, "heartbeat", "operator")).proposed_state
    result = step(current, event(3, "heartbeat", "operator"))
    assert result.proposed_state.status == "error"
    assert result.terminal_reason == "no_progress_limit_reached"
    assert result.cancellation_intent is True
    with pytest.raises(ValueError, match="max_actions"):
        state(max_actions=0)


def test_exhausted_action_budget_cannot_create_a_final_approval() -> None:
    current = state(max_actions=5)
    for next_event in (
        event(1, "start_research", "author"),
        event(2, "request_experiment", "author", experiment_id="exp_1"),
        event(3, "experiment_completed", "operator", experiment_id="exp_1", result_digest="d" * 64),
        event(4, "request_critique", "author"),
    ):
        current = step(current, next_event).proposed_state
    result = step(
        current,
        event(
            5,
            "approve",
            "reviewer",
            leak_checks_passed=True,
            thresholds_passed=True,
            critic_evidence_ref="sha256:critic",
            holdout_evidence_ref="sha256:holdout",
        ),
        **evidence_for(current),
    )
    assert result.proposed_state.status == "error"
    assert result.terminal_reason == "action_budget_exhausted"
    assert result.proposed_state.final_decision_event_id is None


def test_holdout_training_and_event_role_claim_are_rejected() -> None:
    holdout = DatasetSnapshotRefV1(
        snapshot_id="holdout",
        version=1,
        content_hash="c" * 64,
        horizon=TimeWindowV1(start_ns=1_000_000_000, end_ns=8_000_000_000),
        is_holdout=True,
    )
    with pytest.raises(CouncilValidationError):
        ExperimentSpecV1(
            hypothesis_id="h1",
            hypothesis_version=1,
            dataset=holdout,
            signal_refs=(SIGNAL,),
            engine_version="e1",
            parameters_json="{}",
            seed=42,
            train_window=TimeWindowV1(start_ns=1_000_000_000, end_ns=4_000_000_000),
            test_window=TimeWindowV1(start_ns=4_000_000_000, end_ns=8_000_000_000),
            idempotency_key="h1",
        )
    with pytest.raises(CouncilValidationError):
        CouncilEventV1.model_validate(
            {
                **event(1, "start_research", "author").model_dump(),
                "actor_role": "reviewer",
            }
        )


def test_states_require_trusted_issuance_and_verified_chain_on_load() -> None:
    current = state()
    forged = {**current.model_dump(), "status": "approved"}
    with pytest.raises(StateIntegrityError):
        CouncilStateV1.model_validate(forged)
    with pytest.raises(StateIntegrityError):
        CouncilStateV1.model_validate_json(json.dumps(forged, default=str))
    with pytest.raises(StateIntegrityError):
        current.model_copy(update={"status": "approved"})
    with pytest.raises(StateIntegrityError):
        copy.copy(current)
    with pytest.raises(StateIntegrityError):
        copy.deepcopy(current)
    with pytest.raises(StateIntegrityError):
        copy.replace(current, status="approved")
    with pytest.raises(StateIntegrityError):
        pickle.dumps(current)
    serialized = current.model_dump_json()
    assert restore_verified_state(
        serialized,
        verify_chain=lambda session, digest: (
            session == "s1" and digest == current.transition_chain_digest
        ),
    ) == current
    with pytest.raises(StateIntegrityError):
        restore_verified_state(serialized, verify_chain=lambda _session, _digest: False)
    tampered = json.loads(serialized)
    tampered["hypothesis_author_id"] = "attacker"
    with pytest.raises(StateIntegrityError):
        restore_verified_state(json.dumps(tampered), verify_chain=lambda _session, _digest: True)


def test_fabricated_or_mismatched_evidence_never_approves() -> None:
    current = ready_for_review()
    approval = event(
        5, "approve", "reviewer",
        leak_checks_passed=True, thresholds_passed=True,
        critic_evidence_ref="fake", holdout_evidence_ref="fake",
    )
    with pytest.raises(TransitionError, match="tokens"):
        step(current, approval)
    proof = evidence_for(current)
    verifier = proof["evidence_verifier"]
    wrong_claim = EvidenceClaimV1(
        experiment_id="other-exp",
        revision_content_hash=current.revision_content_hash,
        result_digest=current.current_result_digest,
        evidence_digest="f" * 64,
    )
    with pytest.raises(EvidenceError):
        CriticEvidenceV1(wrong_claim, verifier)  # type: ignore[arg-type]
    with pytest.raises(TransitionError, match="bound"):
        step(
            current,
            approval,
            evidence_verifier=verifier,
            critic_evidence=issue_critic_evidence(wrong_claim, verifier),
            holdout_evidence=proof["holdout_evidence"],
        )


def test_decimal_parameters_are_context_stable_and_typed_without_marker_collision() -> None:
    first = Decimal("1.234567890123456789012345678901")
    second = Decimal("1.234567890123456789012345678902")
    with localcontext() as context:
        context.prec = 8
        low_precision = canonicalize_parameters({"x": first})
    with localcontext() as context:
        context.prec = 50
        high_precision = canonicalize_parameters({"x": first})
    assert low_precision == high_precision
    assert canonicalize_parameters({"x": second}) != low_precision
    assert canonicalize_parameters({"x": Decimal("1")}) != canonicalize_parameters(
        {"x": "1"}
    )


def test_cost_rounds_up_and_budget_uses_exact_comparison() -> None:
    current = state(max_cost_usd=Decimal("1.0000000000000000000000000001"))
    current = step(
        current, event(1, "start_research", "author", cost_usd=Decimal("1"))
    ).proposed_state
    tiny = event(2, "heartbeat", "operator", cost_usd=Decimal("1E-28"))
    assert tiny.cost_usd == Decimal("1E-18")
    denied = step(current, tiny)
    assert denied.proposed_state.status == "error"
    assert denied.proposed_state.events[-1].accepted is False
    assert denied.proposed_state.cost_spent_usd == Decimal("1")


def test_unchanged_revision_counts_no_progress_and_stale_completion_fails() -> None:
    current = state(max_no_progress_events=3)
    current = step(current, event(1, "start_research", "author")).proposed_state
    current = step(
        current, event(2, "request_experiment", "author", experiment_id="exp_1")
    ).proposed_state
    current = step(current, event(
        3, "experiment_completed", "operator", experiment_id="exp_1", result_digest="d" * 64,
    )).proposed_state
    current = step(current, event(4, "request_critique", "author")).proposed_state
    current = step(
        current, event(5, "request_revisions", "reviewer", reason="retry")
    ).proposed_state
    same_content = hypothesis().model_copy(update={"version": 2})
    current = step(current, event(6, "revise", "author", revision=same_content)).proposed_state
    assert current.no_progress_count == 1
    current = step(
        current, event(7, "request_experiment", "author", experiment_id="exp_2")
    ).proposed_state
    with pytest.raises(TransitionError, match="STALE_EXPERIMENT"):
        step(current, event(
            8, "experiment_completed", "operator", experiment_id="exp_1", result_digest="d" * 64,
        ))
    with pytest.raises(TransitionError, match="current experiment"):
        step(current, event(8, "request_critique", "author"))


def test_parameter_bounds_precede_expansion_and_unicode_errors_are_typed() -> None:
    with pytest.raises(ParameterError, match="bounds"):
        canonicalize_parameters({"x": Decimal("1E+100000")})
    with pytest.raises(ParameterError, match="Unicode"):
        canonicalize_parameters({"x": "\ud800"})
    with pytest.raises(ParameterError, match="64 KiB"):
        canonicalize_parameters("{" + " " * 70000 + "}")
    with pytest.raises(ParameterError, match="nesting depth"):
        canonicalize_parameters('{"x":' + "[" * 33 + "0" + "]" * 33 + "}")


def test_event_copy_revalidates_cost_and_unchecked_construction_is_blocked() -> None:
    current = state(max_cost_usd=Decimal("10"))
    current = step(
        current, event(1, "start_research", "author", cost_usd=Decimal("9"))
    ).proposed_state
    request = event(2, "request_experiment", "author", experiment_id="exp_1")
    with pytest.raises(CouncilValidationError) as invalid_cost:
        request.model_copy(update={"cost_usd": Decimal("-8")})
    assert invalid_cost.value.errors()[0]["loc"] == ("cost_usd",)
    with pytest.raises(ValueError, match="unchecked model construction"):
        CouncilEventV1.model_construct(**request.model_dump())
    assert current.cost_spent_usd == Decimal("9")


def test_cost_conversion_ignores_ambient_decimal_exponent_limit() -> None:
    with localcontext() as ambient:
        ambient.Emax = 9
        costly = event(1, "start_research", "author", cost_usd=Decimal("1"))
        current = step(state(max_cost_usd=Decimal("20")), costly).proposed_state
    assert costly.cost_usd == Decimal("1")
    assert current.cost_spent_usd == Decimal("1")


def test_identity_normalizes_raw_parameter_json_on_copy_and_hash() -> None:
    dataset = DatasetSnapshotRefV1(
        snapshot_id="ds1", version=1, content_hash="b" * 64,
        horizon=TimeWindowV1(start_ns=1_000_000_000, end_ns=8_000_000_000),
    )
    spec = ExperimentSpecV1(
        hypothesis_id="h1", hypothesis_version=1, dataset=dataset,
        signal_refs=(SIGNAL,), engine_version="r1",
        parameters_json='{"b": 1, "a": 2}', seed=42,
        train_window=TimeWindowV1(start_ns=1_000_000_000, end_ns=4_000_000_000),
        test_window=TimeWindowV1(start_ns=4_000_000_000, end_ns=8_000_000_000),
        idempotency_key="same-parameters",
    )
    equivalent = spec.model_copy(update={"parameters_json": '{"a":2,"b":1}'})
    assert equivalent.parameters_json == spec.parameters_json
    assert derive_experiment_id(equivalent) == derive_experiment_id(spec)
    identity, registry = propose_experiment_identity(spec, {})
    assert propose_experiment_identity(equivalent, registry) == (identity, registry)


def test_schema_typed_decimal_and_ordinary_json_have_distinct_ids() -> None:
    dataset = DatasetSnapshotRefV1(
        snapshot_id="ds1", version=1, content_hash="b" * 64,
        horizon=TimeWindowV1(start_ns=1_000_000_000, end_ns=8_000_000_000),
    )
    common = dict(
        hypothesis_id="h1", hypothesis_version=1, dataset=dataset,
        signal_refs=(SIGNAL,), engine_version="r1", seed=42,
        train_window=TimeWindowV1(start_ns=1_000_000_000, end_ns=4_000_000_000),
        test_window=TimeWindowV1(start_ns=4_000_000_000, end_ns=8_000_000_000),
        idempotency_key="same-key",
    )
    decimal_spec = ExperimentSpecV1(
        **common, typed_parameters=canonicalize_parameters({"x": Decimal("1")}),
    )
    ordinary_spec = ExperimentSpecV1(**common, parameters_json='{"x":1}')
    decimal_id, bindings = propose_experiment_identity(decimal_spec, {})
    assert decimal_spec.parameters_json is None
    assert decimal_spec.typed_parameters == (TypedParamV1(name="x", kind="decimal", value="1"),)
    assert derive_experiment_id(ExperimentSpecV1(
        **common, typed_parameters={"x": Decimal("1")},
    )) == decimal_id
    assert derive_experiment_id(ExperimentSpecV1(
        **common, typed_parameters=(TypedParamV1(name="x", kind="decimal", value="1"),),
    )) == decimal_id
    assert derive_experiment_id(ordinary_spec) != decimal_id
    assert ordinary_spec.typed_parameters == (TypedParamV1(name="x", kind="int", value="1"),)
    with pytest.raises(IdentityConflictError):
        propose_experiment_identity(ordinary_spec, bindings)
    assert derive_experiment_id(ExperimentSpecV1(
        **common, typed_parameters=decimal_spec.typed_parameters,
    )) == decimal_id
    assert derive_experiment_id(ExperimentSpecV1(
        **common, parameters_json=ordinary_spec.parameters_json,
    )) == derive_experiment_id(ordinary_spec)
    assert derive_experiment_id(
        ExperimentSpecV1.model_validate(decimal_spec.model_dump())
    ) == decimal_id
    assert derive_experiment_id(
        ExperimentSpecV1.model_validate_json(decimal_spec.model_dump_json())
    ) == decimal_id
    assert derive_experiment_id(
        ExperimentSpecV1.model_validate_json(ordinary_spec.model_dump_json())
    ) == derive_experiment_id(ordinary_spec)
    reserved_key = ExperimentSpecV1(
        **common, parameters_json='{"__leviathan_parameters_v2__":"ordinary"}',
    )
    assert reserved_key.typed_parameters == (
        TypedParamV1(name="__leviathan_parameters_v2__", kind="str", value="ordinary"),
    )
    assert derive_experiment_id(reserved_key) != decimal_id
    with pytest.raises(CouncilValidationError):
        ExperimentSpecV1(
            **common,
            parameters_json='{"__leviathan_parameters_v2__":["map",[["x",["decimal","1"]]]]}',
        )
    with pytest.raises(CouncilValidationError):
        ExperimentSpecV1(**common, parameters_json='{"x":1.0}')
    with pytest.raises(CouncilValidationError):
        ExperimentSpecV1(**common, parameters_json='{"x":1e0}')


def test_verifier_results_must_be_literal_true_at_issue_and_approval() -> None:
    current = ready_for_review()
    claim = EvidenceClaimV1(
        experiment_id=current.current_experiment_id,
        revision_content_hash=current.revision_content_hash,
        result_digest=current.current_result_digest,
        evidence_digest="e" * 64,
    )

    class MutableVerifier:
        result: object = True

        def verify_critic(self, _claim: EvidenceClaimV1) -> object:
            return self.result

        def verify_holdout(self, _claim: EvidenceClaimV1) -> object:
            return self.result

    verifier = MutableVerifier()
    critic = issue_critic_evidence(claim, verifier)
    holdout = issue_holdout_evidence(claim, verifier)
    for invalid in ("false", 1, False):
        verifier.result = invalid
        with pytest.raises(EvidenceError, match="VERIFIER_RESULT_INVALID"):
            issue_critic_evidence(claim, verifier)
        with pytest.raises(EvidenceError, match="VERIFIER_RESULT_INVALID"):
            issue_holdout_evidence(claim, verifier)
        with pytest.raises(TransitionError, match="VERIFIER_RESULT_INVALID"):
            step(current, event(
                5, "approve", "reviewer",
                leak_checks_passed=True, thresholds_passed=True,
            ), evidence_verifier=verifier, critic_evidence=critic, holdout_evidence=holdout)


def test_terminal_cost_overrun_is_exact_audited_and_blocks_approval() -> None:
    result = step(state(max_cost_usd=Decimal("1")), event(
        1, "cancel", "operator", cost_usd=Decimal("2"), reason="stop",
    ))
    current = result.proposed_state
    assert current.status == "BUDGET_EXCEEDED"
    assert current.termination_reason == "BUDGET_EXCEEDED"
    assert current.cost_spent_usd == Decimal("2")
    assert current.budget_overrun_usd == Decimal("1")
    assert current.events[-1].accepted is True
    assert current.events[-1].cost_usd == Decimal("2")
    assert result.cancellation_intent is True
    with pytest.raises(TransitionError, match="invalid from current"):
        step(current, event(2, "approve", "reviewer"))


def test_decimal_significance_strips_trailing_zeros_before_precision_check() -> None:
    assert canonicalize_parameters({"x": Decimal("1." + "0" * 40)}) == (
        canonicalize_parameters({"x": Decimal("1")})
    )
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        canonicalize_parameters({"x": Decimal("1." + "2" * 34)})


def test_large_integer_parameter_fails_before_python_string_conversion() -> None:
    with pytest.raises(ParameterError, match="integer parameter exceeds bounds") as error:
        canonicalize_parameters({"x": 10**5000})
    assert "5000" not in str(error.value)


def test_public_validation_errors_do_not_echo_input_or_raw_pydantic_metadata() -> None:
    canary = "SENSITIVE_CANARY_3749"
    invalid = {**hypothesis().model_dump(), "max_leverage": canary}
    valid_event = event(1, "start_research", "author")
    invalid_event = {**valid_event.model_dump(), "cost_usd": canary}
    attempts = (
        lambda: HypothesisV1.model_validate(invalid),
        lambda: CouncilEventV1(**invalid_event),
        lambda: CouncilEventV1.model_validate_json(json.dumps(invalid_event)),
        lambda: valid_event.model_copy(update={"cost_usd": canary}),
    )
    for attempt in attempts:
        with pytest.raises(CouncilValidationError) as failure:
            attempt()
        error = failure.value
        for view in (str(error), repr(error.args), repr(error.errors()), error.json()):
            assert canary not in view
            assert "input" not in view
            assert "ctx" not in view
            assert "url" not in view
        assert error.code == "COUNCIL_VALIDATION_ERROR"
        assert error.errors()[0]["loc"] in {("max_leverage",), ("cost_usd",)}
