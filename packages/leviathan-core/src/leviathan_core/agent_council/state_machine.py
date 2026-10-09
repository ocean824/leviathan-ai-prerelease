"""Pure role-gated council transitions; persistence and effects live elsewhere."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from decimal import Decimal
from typing import Any

from .experiment_identity import ParameterError, PrecisionExceededError, canonical_decimal
from .state_models import (
    ActorAuthorityV1,
    CouncilEventV1,
    CouncilStateV1,
    CriticEvidenceV1,
    EvidenceVerifier,
    HoldoutEvidenceV1,
    HypothesisV1,
    StateIntegrityError,
    TransitionResultV1,
    _budget_overrun,
    _cost_units,
    _issue_state,
    _units_to_decimal,
)


class TransitionError(ValueError):
    """A council transition has failed closed without changing state."""


def _canonical_bytes(value: object) -> bytes:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return serialized.encode("ascii")


def _semantic_hash(hypothesis: HypothesisV1) -> str:
    from leviathan_core.agent_revision_hash import council_state_semantic

    return council_state_semantic(hypothesis).sha256_hex


def _expected_chain_digest(state: CouncilStateV1) -> str:
    genesis = {
        "session_id": state.session_id,
        "initial_hypothesis": state.initial_hypothesis.model_dump(mode="json"),
        "hypothesis_author_id": state.hypothesis_author_id,
        "started_at_ns": state.started_at_ns,
        "deadline_ns": state.deadline_ns,
        "max_iterations": state.max_iterations,
        "max_actions": state.max_actions,
        "max_cost_usd": canonical_decimal(state.max_cost_usd),
        "max_no_progress_events": state.max_no_progress_events,
    }
    chain = hashlib.sha256(_canonical_bytes(genesis)).digest()
    for event in state.events:
        chain = hashlib.sha256(chain + _canonical_bytes(event.model_dump(mode="json"))).digest()
    snapshot = state.model_dump(mode="json", exclude={"events", "transition_chain_digest"})
    return hashlib.sha256(chain + _canonical_bytes(snapshot)).hexdigest()


def _seal_state(data: dict[str, Any]) -> CouncilStateV1:
    provisional = _issue_state(**{**data, "transition_chain_digest": "0" * 64})
    digest = _expected_chain_digest(provisional)
    return _issue_state(**{**data, "transition_chain_digest": digest})


def _verify_state(state: CouncilStateV1) -> None:
    if not hmac.compare_digest(state.transition_chain_digest, _expected_chain_digest(state)):
        raise StateIntegrityError("state transition chain failed integrity verification")


def restore_verified_state(
    serialized_json: str,
    *,
    verify_chain: Callable[[str, str], bool],
) -> CouncilStateV1:
    """Load a state only when its digest matches a trusted durable anchor."""

    if not isinstance(serialized_json, str) or not callable(verify_chain):
        raise StateIntegrityError("serialized state and trusted chain verifier are required")
    try:
        encoded = serialized_json.encode("utf-8")
        if len(encoded) > 8 * 1024 * 1024:
            raise StateIntegrityError("serialized council state exceeds size bound")
        parsed = json.loads(serialized_json)
        if not isinstance(parsed, dict):
            raise StateIntegrityError("serialized council state must be an object")
        parsed["hypothesis"] = HypothesisV1.model_validate_json(
            json.dumps(parsed["hypothesis"])
        )
        parsed["initial_hypothesis"] = HypothesisV1.model_validate_json(
            json.dumps(parsed["initial_hypothesis"])
        )
        parsed["events"] = tuple(
            CouncilEventV1.model_validate_json(json.dumps(item)) for item in parsed["events"]
        )
        parsed["requested_experiment_ids"] = tuple(parsed["requested_experiment_ids"])
        parsed["completed_experiment_ids"] = tuple(parsed["completed_experiment_ids"])
        state = _issue_state(**parsed)
        _verify_state(state)
        if verify_chain(state.session_id, state.transition_chain_digest) is not True:
            raise StateIntegrityError("state digest is absent from trusted durable anchor")
    except StateIntegrityError:
        raise
    except Exception:
        raise StateIntegrityError("serialized council state failed verification") from None
    return state


_ROLES: dict[str, frozenset[str]] = {
    "start_research": frozenset({"researcher"}),
    "request_experiment": frozenset({"researcher", "operator"}),
    "experiment_completed": frozenset({"operator"}),
    "experiment_failed": frozenset({"operator"}),
    "request_critique": frozenset({"researcher"}),
    "request_revisions": frozenset({"reviewer"}),
    "revise": frozenset({"researcher"}),
    "approve": frozenset({"reviewer"}),
    "publication_recorded": frozenset({"scribe"}),
    "rollback": frozenset({"reviewer"}),
    "heartbeat": frozenset({"operator"}),
    "cancel": frozenset({"operator"}),
    "fail": frozenset({"operator"}),
}
_TRANSITIONS: dict[str, frozenset[str]] = {
    "start_research": frozenset({"draft"}),
    "request_experiment": frozenset({"researching", "experimenting"}),
    "experiment_completed": frozenset({"experimenting"}),
    "experiment_failed": frozenset({"experimenting"}),
    "request_critique": frozenset({"experimenting"}),
    "request_revisions": frozenset({"critique_pending"}),
    "revise": frozenset({"revisions_required"}),
    "approve": frozenset({"critique_pending"}),
    "publication_recorded": frozenset({"approved"}),
    "rollback": frozenset({"approved", "published"}),
    "heartbeat": frozenset(
        {
            "draft", "researching", "experimenting", "critique_pending",
            "revisions_required", "approved",
        }
    ),
    "cancel": frozenset(
        {
            "draft", "researching", "experimenting", "critique_pending",
            "revisions_required", "approved",
        }
    ),
    "fail": frozenset(
        {
            "draft", "researching", "experimenting", "critique_pending",
            "revisions_required", "approved",
        }
    ),
}


def new_council_state(
    hypothesis: HypothesisV1,
    *,
    session_id: str,
    hypothesis_author_id: str,
    now_ns: int,
    max_iterations: int,
    max_actions: int,
    max_runtime_ns: int,
    max_cost_usd: Decimal,
    max_no_progress_events: int,
) -> CouncilStateV1:
    """Create a bounded initial state at an injected UTC-ns clock value.

    The caller must authenticate ``hypothesis_author_id`` at its boundary.
    Product policy caps reject numerically finite but operationally unbounded loops.
    """

    if isinstance(now_ns, bool) or not isinstance(now_ns, int) or now_ns <= 0:
        raise ValueError("now_ns must be a positive UTC-ns integer")
    if hypothesis.horizon.end_ns > now_ns:
        raise ValueError("hypothesis horizon cannot end in the future")
    limits = (
        ("max_iterations", max_iterations, 1000),
        ("max_actions", max_actions, 10000),
        ("max_runtime_ns", max_runtime_ns, 7 * 24 * 60 * 60 * 1_000_000_000),
        ("max_no_progress_events", max_no_progress_events, 100),
    )
    for name, value, cap in limits:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= cap:
            raise ValueError(f"{name} must be a positive integer no greater than {cap}")
    if not isinstance(max_cost_usd, Decimal) or not max_cost_usd.is_finite():
        raise ValueError("max_cost_usd must be a finite Decimal")
    try:
        max_cost_usd = Decimal(canonical_decimal(max_cost_usd))
    except PrecisionExceededError:
        raise ValueError("PRECISION_EXCEEDED") from None
    except ParameterError:
        raise ValueError("max_cost_usd is outside the canonical Decimal contract") from None
    if not 0 < max_cost_usd <= Decimal("10000"):
        raise ValueError("max_cost_usd must be between 0 and 10000")
    return _seal_state(dict(
        session_id=session_id,
        hypothesis=hypothesis,
        initial_hypothesis=hypothesis,
        revision_content_hash=_semantic_hash(hypothesis),
        hypothesis_author_id=hypothesis_author_id,
        status="draft",
        started_at_ns=now_ns,
        deadline_ns=now_ns + max_runtime_ns,
        max_iterations=max_iterations,
        max_actions=max_actions,
        max_cost_usd=max_cost_usd,
        max_no_progress_events=max_no_progress_events,
    ))


def _authorize(
    event: CouncilEventV1, authorize_actor: Callable[[str], ActorAuthorityV1 | None]
) -> ActorAuthorityV1:
    authority = authorize_actor(event.actor_id)
    if not isinstance(authority, ActorAuthorityV1) or authority.actor_id != event.actor_id:
        raise TransitionError("actor has no trusted authorization")
    if not _ROLES[event.event_type].intersection(authority.roles):
        raise TransitionError("actor lacks the required trusted role")
    if (
        event.event_type in {"approve", "publication_recorded", "rollback"}
        and authority.kind != "human"
    ):
        raise TransitionError("an agent cannot approve or publish")
    return authority


def _require_ref(value: str | None, name: str) -> None:
    if value is None or not value.strip():
        raise TransitionError(f"{name} is required")


def _verify_evidence(
    state: CouncilStateV1,
    verifier: EvidenceVerifier | None,
    critic: CriticEvidenceV1 | None,
    holdout: HoldoutEvidenceV1 | None,
) -> tuple[str, str]:
    if (
        verifier is None
        or type(critic) is not CriticEvidenceV1
        or type(holdout) is not HoldoutEvidenceV1
        or not critic.issued_by(verifier)
        or not holdout.issued_by(verifier)
    ):
        raise TransitionError("trusted critic and holdout evidence tokens are required")
    binding = (
        state.current_experiment_id,
        state.revision_content_hash,
        state.current_result_digest,
    )
    for token in (critic, holdout):
        claim = token.claim
        if (claim.experiment_id, claim.revision_content_hash, claim.result_digest) != binding:
            raise TransitionError("evidence is not bound to the current experiment result")
    critic_valid: object
    try:
        critic_valid = verifier.verify_critic(critic.claim)
    except Exception:
        critic_valid = None
    if type(critic_valid) is not bool or critic_valid is not True:
        raise TransitionError("VERIFIER_RESULT_INVALID")
    holdout_valid: object
    try:
        holdout_valid = verifier.verify_holdout(holdout.claim)
    except Exception:
        holdout_valid = None
    if type(holdout_valid) is not bool or holdout_valid is not True:
        raise TransitionError("VERIFIER_RESULT_INVALID")
    return critic.claim.evidence_digest, holdout.claim.evidence_digest


def propose_transition(
    state: CouncilStateV1,
    event: CouncilEventV1,
    *,
    now_ns: int,
    authorize_actor: Callable[[str], ActorAuthorityV1 | None],
    evidence_verifier: EvidenceVerifier | None = None,
    critic_evidence: CriticEvidenceV1 | None = None,
    holdout_evidence: HoldoutEvidenceV1 | None = None,
) -> TransitionResultV1:
    """Return an atomic compare-and-swap proposal; execute no work or I/O.

    ``authorize_actor`` must consult a trusted external identity boundary. The
    event contains no role claim, so untrusted event data cannot grant itself one.
    """

    if not isinstance(state, CouncilStateV1) or not isinstance(event, CouncilEventV1):
        raise TransitionError("state and event are required validated contracts")
    _verify_state(state)
    if not event.accepted:
        raise TransitionError("caller cannot premark an event as rejected")
    if not callable(authorize_actor):
        raise TransitionError("trusted actor authorization is required")
    if event.session_id != state.session_id:
        raise TransitionError("event belongs to another session")
    expected_sequence = len(state.events) + 1
    if event.sequence != expected_sequence:
        raise TransitionError("event sequence gap or replay")
    if isinstance(now_ns, bool) or not isinstance(now_ns, int) or now_ns < state.started_at_ns:
        raise TransitionError("invalid injected clock")
    if event.at_ns > now_ns or event.at_ns < state.started_at_ns:
        raise TransitionError("event timestamp is outside the observed clock")
    if state.events and event.at_ns < state.events[-1].at_ns:
        raise TransitionError("event timestamp regressed")
    if state.hypothesis.horizon.end_ns > now_ns:
        raise TransitionError("hypothesis horizon ends in the future")
    if state.status not in _TRANSITIONS[event.event_type]:
        raise TransitionError("event is invalid from current council state")
    _authorize(event, authorize_actor)

    updates: dict[str, object] = {}
    event_type = event.event_type
    if event_type == "start_research":
        updates["status"] = "researching"
    elif event_type == "request_experiment":
        _require_ref(event.experiment_id, "experiment_id")
        if event.experiment_id in state.requested_experiment_ids:
            raise TransitionError("an experiment ID cannot be requested twice")
        updates["status"] = "experimenting"
        updates["requested_experiment_ids"] = (*state.requested_experiment_ids, event.experiment_id)
        updates["iteration_count"] = state.iteration_count + 1
        updates["current_experiment_id"] = event.experiment_id
        updates["current_result_digest"] = None
    elif event_type == "experiment_completed":
        _require_ref(event.experiment_id, "experiment_id")
        if event.experiment_id != state.current_experiment_id:
            raise TransitionError("STALE_EXPERIMENT")
        if event.experiment_id in state.completed_experiment_ids:
            raise TransitionError("a completed experiment is immutable")
        _require_ref(event.result_digest, "result_digest")
        updates["completed_experiment_ids"] = (*state.completed_experiment_ids, event.experiment_id)
        updates["current_result_digest"] = event.result_digest
        updates["last_result_digest"] = event.result_digest
    elif event_type == "experiment_failed":
        _require_ref(event.experiment_id, "experiment_id")
        _require_ref(event.reason, "reason")
        if event.experiment_id != state.current_experiment_id:
            raise TransitionError("STALE_EXPERIMENT")
        if event.experiment_id in state.completed_experiment_ids:
            raise TransitionError("a completed experiment is immutable")
    elif event_type == "request_critique":
        if state.current_experiment_id is None or state.current_result_digest is None:
            raise TransitionError("critique needs a completed current experiment")
        updates["status"] = "critique_pending"
    elif event_type == "request_revisions":
        _require_ref(event.reason, "reason")
        updates["status"] = "revisions_required"
    elif event_type == "revise":
        if event.revision is None:
            raise TransitionError("revision hypothesis is required")
        if (
            event.revision.hypothesis_id != state.hypothesis.hypothesis_id
            or event.revision.version != state.hypothesis.version + 1
        ):
            raise TransitionError("revision must advance the same hypothesis by one version")
        if event.revision.horizon.end_ns > now_ns:
            raise TransitionError("revision horizon ends in the future")
        updates["status"] = "researching"
        updates["hypothesis"] = event.revision
        updates["revision_content_hash"] = _semantic_hash(event.revision)
        updates["current_experiment_id"] = None
        updates["current_result_digest"] = None
    elif event_type == "approve":
        if event.actor_id == state.hypothesis_author_id:
            raise TransitionError("hypothesis author cannot review their own work")
        if state.final_decision_event_id is not None:
            raise TransitionError("duplicate final decision")
        if state.current_experiment_id is None or state.current_result_digest is None:
            raise TransitionError("approval needs a completed current experiment")
        if event.leak_checks_passed is not True or event.thresholds_passed is not True:
            raise TransitionError("leak and threshold gates must pass")
        critic_digest, holdout_digest = _verify_evidence(
            state, evidence_verifier, critic_evidence, holdout_evidence
        )
        event = event.model_copy(update={
            "critic_evidence_ref": critic_digest,
            "holdout_evidence_ref": holdout_digest,
        })
        updates["status"] = "approved"
        updates["final_decision_event_id"] = f"{state.session_id}:{event.sequence}"
    elif event_type == "publication_recorded":
        _require_ref(event.publication_receipt_ref, "publication_receipt_ref")
        updates["status"] = "published"
        updates["termination_reason"] = "research_published"
    elif event_type == "rollback":
        if event.actor_id == state.hypothesis_author_id:
            raise TransitionError("hypothesis author cannot roll back their own approval")
        _require_ref(event.reason, "reason")
        updates["status"] = "rolled_back"
        updates["termination_reason"] = event.reason
    elif event_type == "cancel":
        _require_ref(event.reason, "reason")
        updates["status"] = "canceled"
        updates["termination_reason"] = event.reason
    elif event_type == "fail":
        _require_ref(event.reason, "reason")
        updates["status"] = "error"
        updates["termination_reason"] = event.reason

    if event_type in {"heartbeat", "experiment_failed"}:
        no_progress = state.no_progress_count + 1
    elif event_type == "revise":
        no_progress = (
            state.no_progress_count + 1
            if updates["revision_content_hash"] == state.revision_content_hash
            else 0
        )
    elif event_type == "experiment_completed":
        no_progress = (
            state.no_progress_count + 1
            if event.result_digest == state.last_result_digest else 0
        )
    else:
        no_progress = state.no_progress_count
    actions_used = state.actions_used + 1
    cost_spent_units = state.cost_spent_units + _cost_units(event.cost_usd)
    cost_spent = _units_to_decimal(cost_spent_units)
    updates.update(
        events=(*state.events, event),
        actions_used=actions_used,
        cost_spent_units=cost_spent_units,
        cost_spent_usd=cost_spent,
        no_progress_count=no_progress,
    )
    if event_type in {"cancel", "fail", "rollback"} and cost_spent > state.max_cost_usd:
        updates["status"] = "BUDGET_EXCEEDED"
        updates["termination_reason"] = "BUDGET_EXCEEDED"
        updates["budget_overrun_usd"] = _budget_overrun(cost_spent, state.max_cost_usd)
    budget_reason: str | None = None
    iteration_count = state.iteration_count + (1 if event_type == "request_experiment" else 0)
    # A publication receipt is still subject to the council deadline and budget.
    # Explicit cancel, failure and rollback remain available for safe termination.
    if event_type not in {"cancel", "fail", "rollback"}:
        if now_ns >= state.deadline_ns:
            budget_reason = "time_budget_exhausted"
        elif cost_spent >= state.max_cost_usd:
            budget_reason = "cost_budget_exhausted"
        elif actions_used >= state.max_actions:
            budget_reason = "action_budget_exhausted"
        elif iteration_count > state.max_iterations:
            budget_reason = "iteration_budget_exhausted"
        elif no_progress >= state.max_no_progress_events:
            budget_reason = "no_progress_limit_reached"
        if budget_reason is not None:
            rejected_event = event.model_copy(update={"accepted": False})
            updates = {
                "status": "error",
                "termination_reason": budget_reason,
                "events": (*state.events, rejected_event),
                "actions_used": actions_used,
                "cost_spent_units": state.cost_spent_units,
                "cost_spent_usd": state.cost_spent_usd,
                "no_progress_count": no_progress,
            }

    proposed_state = _seal_state({**state.model_dump(), **updates})
    cancellation_intent = proposed_state.status in {
        "rolled_back", "canceled", "error", "BUDGET_EXCEEDED",
    }
    return TransitionResultV1(
        proposed_state=proposed_state,
        expected_previous_sequence=expected_sequence - 1,
        cancellation_intent=cancellation_intent,
        terminal_reason=proposed_state.termination_reason,
    )
