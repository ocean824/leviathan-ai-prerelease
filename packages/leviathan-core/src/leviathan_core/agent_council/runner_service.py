"""Bounded orchestration over injected queue, replay, storage and gate ports."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import cast

from leviathan_core.agent_revision_hash import RevisionHashError, hypothesis_full_revision
from leviathan_core.numeric import canonical_json, exact_add
from leviathan_core.security import (
    ActionV1,
    AuthorizationContextV1,
    AuthorizationDecisionV1,
    AuthorizationPolicyV1,
    EffectV1,
    ResourceV1,
    TrustedPrincipalV1,
    authorize,
)

from .critic_policy import require_critique_decision
from .experiment_identity import derive_experiment_id
from .leak_models import LeakDecisionV1, MetricEvidenceV1
from .leak_rules import require_leak_decision
from .runner_models import (
    CancelReceiptV1,
    CouncilRunCommandV1,
    CouncilRunEventV1,
    CriticGatePort,
    EventStorePort,
    EventStreamPort,
    LeakGatePort,
    QueueReceiptV1,
    ReplayOutcomeV1,
    ReplayPort,
    RunnerClock,
    RunnerError,
    RunQueuePort,
    RunStatePort,
    RunStatusV1,
    _issue_event,
    _issue_status,
    command_digest,
    require_event,
    require_replay_outcome,
    require_status,
)
from .state_machine import _semantic_hash

_TERMINAL = frozenset({"COMPLETED", "PARTIAL_COMPLETED", "FAILED", "CANCELED", "CANCEL_FAILED"})
_CANCEL_LIMIT_NS = 5_000_000_000


def _strict_int(value: object) -> bool:
    return type(value) is int and value >= 0


def _status_values(status: RunStatusV1) -> dict[str, object]:
    return status.model_dump(mode="python", exclude={"_guard"})


def _run_resource_id(identity: str) -> str:
    resource_id = f"agent-run:{identity}"
    if len(resource_id) <= 128:
        return resource_id
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"agent-run:sha256:{digest}"


def _terminal_reason(reason: str) -> str:
    # Closed, content-free public terminal reasons.
    if reason in {
        "RUNS_COMPLETED",
        "PARTIAL_RUNS_COMPLETED",
        "NO_PROGRESS_LIMIT_REACHED",
        "QUORUM_NOT_MET",
        "LEAK_FAILURE",
        "CRITIC_FAILURE",
        "REPLAY_FAILURE",
        "EVALUATION_BUDGET_EXCEEDED",
        "ACTION_BUDGET_EXCEEDED",
        "TIME_BUDGET_EXCEEDED",
        "DATA_GAP_RETRIES_EXHAUSTED",
        "CANCEL_CONFIRMED",
        "CANCEL_TIMEOUT",
        "CANCEL_PORT_INVALID",
        "CANCEL_CLOCK_INVALID",
        "LEAK_GATE_UNAVAILABLE",
        "LEAK_GATE_INVALID",
        "LEAK_EVIDENCE_MISSING",
        "LEAK_BINDING_MISMATCH",
        "REPLAY_METRICS_INVALID",
        "RUN_PROCESSING_FAILURE",
        "AUTHORIZATION_DENIED",
        "IDEMPOTENCY_CONFLICT",
        "RUN_STATE_CONFLICT",
        "RUN_STORAGE_FAILURE",
    }:
        return reason
    return "RUN_FAILURE"


class CouncilRunnerService:
    """Advance a council run one replay action at a time, with explicit bounds.

    The service owns no external effects. Every effect is an injected port call;
    event-store append completes before event-stream publication.
    """

    def __init__(
        self,
        *,
        authorization_policy: AuthorizationPolicyV1,
        service_principal: TrustedPrincipalV1,
        queue: RunQueuePort,
        state: RunStatePort,
        event_store: EventStorePort,
        event_stream: EventStreamPort,
        replay: ReplayPort,
        leak_gate: LeakGatePort,
        critic_gate: CriticGatePort,
        clock: RunnerClock,
    ) -> None:
        if (
            type(authorization_policy) is not AuthorizationPolicyV1
            or type(service_principal) is not TrustedPrincipalV1
        ):
            raise RunnerError("AUTHORIZATION_DENIED")
        self._authorization_policy = authorization_policy
        self._service_principal = service_principal
        self._queue = queue
        self._state = state
        self._event_store = event_store
        self._event_stream = event_stream
        self._replay = replay
        self._leak_gate = leak_gate
        self._critic_gate = critic_gate
        self._clock = clock

    def _authorize(self, principal: object, action: str, resource_id: str) -> None:
        if type(principal) is not TrustedPrincipalV1:
            raise RunnerError("AUTHORIZATION_DENIED")
        try:
            at_ns = self._now()
            at = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=at_ns // 1000)
            resource = ResourceV1(
                resource_id=resource_id,
                project_id=principal.project_id,
                env=principal.env,
                venue=principal.venue,
                portfolio=principal.portfolio,
                strategy=principal.strategy,
            )
            context = AuthorizationContextV1(
                project_id=principal.project_id,
                env=principal.env,
                at=at,
                venue=principal.venue,
                portfolio=principal.portfolio,
                strategy=principal.strategy,
            )
            decision = authorize(
                principal,
                ActionV1(action),
                resource,
                context,
                self._authorization_policy,
            )
        except Exception:
            raise RunnerError("AUTHORIZATION_DENIED") from None
        if type(decision) is not AuthorizationDecisionV1 or decision.decision is not EffectV1.ALLOW:
            raise RunnerError("AUTHORIZATION_DENIED")

    @staticmethod
    def _require_owner(
        principal: object, owner_id: str, owner_project_id: str
    ) -> TrustedPrincipalV1:
        if (
            type(principal) is not TrustedPrincipalV1
            or principal.principal_id != owner_id
            or principal.project_id != owner_project_id
        ):
            raise RunnerError("AUTHORIZATION_DENIED")
        return principal

    def _now(self) -> int:
        try:
            value = self._clock.now_ns()
        except Exception:
            raise RunnerError("RUN_CLOCK_INVALID") from None
        if not _strict_int(value) or value == 0:
            raise RunnerError("RUN_CLOCK_INVALID")
        return value

    def _monotonic_ns(self) -> int:
        try:
            value = self._clock.monotonic_ns()
        except Exception:
            raise RunnerError("RUN_CLOCK_INVALID") from None
        if not _strict_int(value):
            raise RunnerError("RUN_CLOCK_INVALID")
        return value

    def _emit(
        self,
        session_id: str,
        event_type: str,
        *,
        experiment_id: str | None = None,
        result_digest: str | None = None,
        run_id: str | None = None,
        reason: str | None = None,
    ) -> CouncilRunEventV1:
        try:
            last_sequence = self._event_store.last_sequence(session_id)
            if type(last_sequence) is not int or last_sequence < 0 or last_sequence >= 10000:
                raise RunnerError("RUN_STORAGE_FAILURE")
            sequence = last_sequence + 1
            event = _issue_event(
                session_id=session_id,
                sequence=sequence,
                event_type=event_type,
                at_ns=self._now(),
                experiment_id=experiment_id,
                run_id=run_id,
                result_digest=result_digest,
                reason=reason,
            )
            if self._event_store.append(event) is not True:
                raise RunnerError("RUN_STORAGE_FAILURE")
            self._event_stream.publish(event)
            return require_event(event)
        except RunnerError:
            raise
        except Exception:
            raise RunnerError("RUN_STORAGE_FAILURE") from None

    def _save(self, previous: RunStatusV1 | None, status: RunStatusV1) -> RunStatusV1:
        try:
            if self._state.compare_and_set_status(previous, status) is not True:
                raise RunnerError("RUN_STATE_CONFLICT")
            return require_status(status)
        except RunnerError:
            raise
        except Exception:
            raise RunnerError("RUN_STORAGE_FAILURE") from None

    def enqueue(self, command: CouncilRunCommandV1, principal: TrustedPrincipalV1) -> RunStatusV1:
        """Authorize and atomically queue an idempotent immutable command."""
        if type(command) is not CouncilRunCommandV1:
            raise RunnerError("RUN_COMMAND_INVALID")
        try:
            checked = CouncilRunCommandV1.model_validate(command.model_dump(mode="python"))
            if (
                type(principal) is not TrustedPrincipalV1
                or principal.principal_id != checked.actor_id
            ):
                raise RunnerError("AUTHORIZATION_DENIED")
            owner = principal
            self._authorize(owner, "agent.run.enqueue", _run_resource_id(checked.idempotency_key))
        except RunnerError:
            raise
        except Exception:
            raise RunnerError("AUTHORIZATION_DENIED") from None
        digest = command_digest(checked)
        hypothesis_digest = _semantic_hash(checked.hypothesis)
        try:
            existing_by_key = self._queue.find_by_idempotency_key(
                checked.idempotency_key, owner.principal_id, owner.project_id
            )
            existing = existing_by_key
            if existing is None:
                existing = self._queue.find_by_hypothesis_digest(
                    hypothesis_digest, owner.principal_id, owner.project_id
                )
            if existing is not None:
                if type(existing) is not QueueReceiptV1:
                    raise RunnerError("RUN_STORAGE_FAILURE")
                if (
                    existing.owner_principal_id != owner.principal_id
                    or existing.owner_project_id != owner.project_id
                ):
                    raise RunnerError("AUTHORIZATION_DENIED")
                if (
                    existing.hypothesis_digest != hypothesis_digest
                    or existing.command_digest != digest
                ):
                    raise RunnerError("IDEMPOTENCY_CONFLICT")
                return self._complete_queued_receipt(existing, checked, digest)
            receipt = self._queue.enqueue(
                checked.idempotency_key,
                digest,
                hypothesis_digest,
                owner.principal_id,
                owner.project_id,
                checked,
            )
            if (
                type(receipt) is not QueueReceiptV1
                or receipt.command_digest != digest
                or receipt.hypothesis_digest != hypothesis_digest
                or receipt.owner_principal_id != owner.principal_id
                or receipt.owner_project_id != owner.project_id
            ):
                raise RunnerError("RUN_STORAGE_FAILURE")
            return self._complete_queued_receipt(receipt, checked, digest)
        except RunnerError:
            raise
        except Exception:
            raise RunnerError("RUN_STORAGE_FAILURE") from None

    def _complete_queued_receipt(
        self, receipt: QueueReceiptV1, requested: CouncilRunCommandV1, digest: str
    ) -> RunStatusV1:
        """Complete status/event writes after a crash between injected ports."""
        try:
            if (
                type(receipt) is not QueueReceiptV1
                or receipt.command_digest != digest
                or receipt.hypothesis_digest != _semantic_hash(requested.hypothesis)
            ):
                raise RunnerError("RUN_STORAGE_FAILURE")
            stored = self._queue.get_command(receipt.session_id)
            if type(stored) is not CouncilRunCommandV1:
                raise RunnerError("RUN_STORAGE_FAILURE")
            stored = CouncilRunCommandV1.model_validate(stored.model_dump(mode="python"))
            if (
                command_digest(stored) != receipt.command_digest
                or stored.actor_id != receipt.owner_principal_id
            ):
                raise RunnerError("RUN_STORAGE_FAILURE")
            status = self._state.get_status(receipt.session_id)
            if status is None:
                status = _issue_status(
                    session_id=receipt.session_id,
                    command_digest=receipt.command_digest,
                    owner_principal_id=receipt.owner_principal_id,
                    owner_project_id=receipt.owner_project_id,
                    status="QUEUED",
                    started_at_ns=self._now(),
                    actions_used=0,
                    runs_attempted=0,
                    successful_runs=0,
                    failed_runs=0,
                    next_experiment_index=0,
                    completed_run_ids=(),
                    failed_run_ids=(),
                    cost_spent_usd=Decimal(0),
                    elapsed_ns=0,
                    compute_units=0,
                    data_gap_retries=0,
                    termination_reason=None,
                )
                try:
                    status = self._save(None, status)
                except RunnerError as error:
                    if error.code != "RUN_STATE_CONFLICT":
                        raise
                    status = self._state.get_status(receipt.session_id)
                    if status is None:
                        raise
            status = require_status(status)
            if (
                status.command_digest != receipt.command_digest
                or status.owner_principal_id != receipt.owner_principal_id
                or status.owner_project_id != receipt.owner_project_id
            ):
                raise RunnerError("RUN_STORAGE_FAILURE")
            if (
                status.status == "QUEUED"
                and self._event_store.last_sequence(receipt.session_id) == 0
            ):
                self._emit(receipt.session_id, "QUEUED")
            return status
        except RunnerError:
            raise
        except Exception:
            raise RunnerError("RUN_STORAGE_FAILURE") from None

    def recover(self, session_id: str) -> RunStatusV1:
        """Reload a sealed status from the injected durable state port."""
        if type(session_id) is not str or not session_id or len(session_id) > 128:
            raise RunnerError("RUN_SESSION_INVALID")
        self._authorize(self._service_principal, "agent.run.advance", _run_resource_id(session_id))
        try:
            status = self._state.get_status(session_id)
            command = self._queue.get_command(session_id)
        except Exception:
            raise RunnerError("RUN_STORAGE_FAILURE") from None
        if status is None:
            raise RunnerError("RUN_SESSION_MISSING")
        status = require_status(status)
        if type(command) is not CouncilRunCommandV1:
            raise RunnerError("RUN_STORAGE_FAILURE")
        try:
            checked = CouncilRunCommandV1.model_validate(command.model_dump(mode="python"))
        except Exception:
            raise RunnerError("RUN_STORAGE_FAILURE") from None
        if (
            status.owner_principal_id != checked.actor_id
            or command_digest(checked) != status.command_digest
        ):
            raise RunnerError("RUN_STORAGE_FAILURE")
        if status.status == "CANCEL_REQUESTED":
            return self._complete_cancel(status)
        return status

    def read_status(self, session_id: str, principal: TrustedPrincipalV1) -> RunStatusV1:
        """Read one run status as its trusted owner."""
        if type(session_id) is not str or not session_id or len(session_id) > 128:
            raise RunnerError("RUN_SESSION_INVALID")
        self._authorize(principal, "agent.run.read", _run_resource_id(session_id))
        try:
            status = self._state.get_status(session_id)
            command = self._queue.get_command(session_id)
        except Exception:
            raise RunnerError("RUN_STORAGE_FAILURE") from None
        if status is None or command is None:
            raise RunnerError("AUTHORIZATION_DENIED")
        if type(command) is not CouncilRunCommandV1:
            raise RunnerError("RUN_STORAGE_FAILURE")
        status = require_status(status)
        checked = CouncilRunCommandV1.model_validate(command.model_dump(mode="python"))
        self._require_owner(principal, status.owner_principal_id, status.owner_project_id)
        if status.command_digest != command_digest(checked):
            raise RunnerError("RUN_STORAGE_FAILURE")
        return status

    def _finish(
        self,
        prior: RunStatusV1,
        status_name: str,
        reason: str,
        *,
        event_type: str,
        experiment_id: str | None = None,
        run_id: str | None = None,
        result_digest: str | None = None,
        **changes: object,
    ) -> RunStatusV1:
        values = _status_values(prior)
        values.update(changes)
        values.update(status=status_name, termination_reason=_terminal_reason(reason))
        saved = self._save(prior, _issue_status(**values))
        self._emit(
            prior.session_id,
            event_type,
            experiment_id=experiment_id,
            run_id=run_id,
            result_digest=result_digest,
            reason=saved.termination_reason,
        )
        return saved

    def advance(self, session_id: str) -> RunStatusV1:
        """Perform at most one replay attempt or one final critic evaluation."""
        prior = self.recover(session_id)
        if prior.status in _TERMINAL:
            return prior
        if prior.status == "CANCEL_REQUESTED":
            raise RunnerError("RUN_CANCEL_PENDING")
        command = self._queue.get_command(session_id)
        if type(command) is not CouncilRunCommandV1:
            raise RunnerError("RUN_STORAGE_FAILURE")
        try:
            command = CouncilRunCommandV1.model_validate(command.model_dump(mode="python"))
        except Exception:
            raise RunnerError("RUN_STORAGE_FAILURE") from None
        if command_digest(command) != prior.command_digest:
            raise RunnerError("RUN_STORAGE_FAILURE")
        now = self._now()
        elapsed_wall = now - prior.started_at_ns
        if elapsed_wall < 0 or elapsed_wall >= command.budget.max_elapsed_ns:
            return self._finish(
                prior,
                "FAILED",
                "TIME_BUDGET_EXCEEDED",
                event_type="FAILED",
                elapsed_ns=max(prior.elapsed_ns, max(elapsed_wall, 0)),
            )
        if prior.actions_used >= command.budget.max_actions:
            return self._finish(prior, "FAILED", "ACTION_BUDGET_EXCEEDED", event_type="FAILED")

        remaining_runs = len(command.experiments) - prior.next_experiment_index
        if prior.successful_runs + remaining_runs < command.budget.min_successful_runs:
            return self._finish(prior, "FAILED", "QUORUM_NOT_MET", event_type="FAILED")
        if prior.next_experiment_index >= len(command.experiments):
            return self._evaluate_critic(command, prior)

        critic_groups = len({derive_experiment_id(item) for item in command.experiments})
        required_actions = prior.actions_used + remaining_runs + critic_groups
        if required_actions > command.budget.max_actions:
            return self._finish(prior, "FAILED", "ACTION_BUDGET_EXCEEDED", event_type="FAILED")

        experiment = command.experiments[prior.next_experiment_index]
        expected_id = derive_experiment_id(experiment)
        expected_run_id = experiment.idempotency_key
        if prior.status == "QUEUED":
            started = self._save(
                prior, _issue_status(**{**_status_values(prior), "status": "RUNNING"})
            )
            self._emit(session_id, "STARTED")
            prior = started
        try:
            checkpointed = self._state.get_outcomes(session_id)
            if type(checkpointed) is not tuple or len(checkpointed) > 64:
                raise RunnerError("RUN_STORAGE_FAILURE")
            checkpointed = tuple(require_replay_outcome(item) for item in checkpointed)
            outcome = next((item for item in checkpointed if item.run_id == expected_run_id), None)
            if outcome is None:
                outcome = self._replay.execute(experiment, command)
            outcome = require_replay_outcome(outcome)
        except Exception:
            return self._finish(
                prior,
                "FAILED",
                "REPLAY_FAILURE",
                event_type="RUN_FAILED",
                experiment_id=expected_id,
                actions_used=prior.actions_used + 1,
                runs_attempted=prior.runs_attempted + 1,
                failed_runs=prior.failed_runs + 1,
                next_experiment_index=prior.next_experiment_index + 1,
                failed_run_ids=(*prior.failed_run_ids, expected_run_id),
                run_id=expected_run_id,
                elapsed_ns=max(prior.elapsed_ns, elapsed_wall),
            )
        if (
            outcome.experiment_id != expected_id
            or outcome.run_id != expected_run_id
            or outcome.snapshot_hash != experiment.dataset.content_hash
            or outcome.seed != experiment.seed
            or outcome.engine_version != experiment.engine_version
            or outcome.signals_digest != _signals_digest(experiment)
        ):
            return self._finish(
                prior,
                "FAILED",
                "REPLAY_FAILURE",
                event_type="RUN_FAILED",
                experiment_id=expected_id,
                actions_used=prior.actions_used + 1,
                runs_attempted=prior.runs_attempted + 1,
                failed_runs=prior.failed_runs + 1,
                next_experiment_index=prior.next_experiment_index + 1,
                failed_run_ids=(*prior.failed_run_ids, expected_run_id),
                run_id=expected_run_id,
                elapsed_ns=max(prior.elapsed_ns, elapsed_wall),
            )

        actions_used = prior.actions_used + 1
        cost = _add_decimal(prior.cost_spent_usd, outcome.cost_usd)
        elapsed_ns = max(prior.elapsed_ns, elapsed_wall)
        replay_elapsed = prior.elapsed_ns + outcome.elapsed_ns
        elapsed_ns = max(elapsed_ns, replay_elapsed)
        compute_units = prior.compute_units + outcome.compute_units
        if (
            actions_used > command.budget.max_actions
            or cost > command.budget.max_cost_usd
            or elapsed_ns > command.budget.max_elapsed_ns
            or compute_units > command.budget.max_compute_units
        ):
            return self._finish(
                prior,
                "FAILED",
                "EVALUATION_BUDGET_EXCEEDED",
                event_type="RUN_FAILED",
                experiment_id=expected_id,
                result_digest=outcome.result_digest,
                actions_used=actions_used,
                runs_attempted=prior.runs_attempted + 1,
                failed_runs=prior.failed_runs + 1,
                next_experiment_index=prior.next_experiment_index + 1,
                failed_run_ids=(*prior.failed_run_ids, expected_run_id),
                cost_spent_usd=cost,
                elapsed_ns=elapsed_ns,
                compute_units=compute_units,
                run_id=expected_run_id,
            )

        if any(
            item.run_id != expected_run_id and item.result_digest == outcome.result_digest
            for item in checkpointed
        ):
            return self._finish(
                prior,
                "FAILED",
                "NO_PROGRESS_LIMIT_REACHED",
                event_type="RUN_FAILED",
                experiment_id=expected_id,
                result_digest=outcome.result_digest,
                actions_used=actions_used,
                runs_attempted=prior.runs_attempted + 1,
                failed_runs=prior.failed_runs + 1,
                next_experiment_index=prior.next_experiment_index + 1,
                failed_run_ids=(*prior.failed_run_ids, expected_run_id),
                cost_spent_usd=cost,
                elapsed_ns=elapsed_ns,
                compute_units=compute_units,
                run_id=expected_run_id,
            )

        if outcome.outcome == "DATA_GAP":
            retries = prior.data_gap_retries + 1
            values = _status_values(prior)
            values.update(
                status="PAUSED_DATA_GAP"
                if retries <= command.budget.max_data_gap_retries
                else "FAILED",
                actions_used=actions_used,
                elapsed_ns=elapsed_ns,
                cost_spent_usd=cost,
                compute_units=compute_units,
                data_gap_retries=retries,
                termination_reason=None
                if retries <= command.budget.max_data_gap_retries
                else "DATA_GAP_RETRIES_EXHAUSTED",
            )
            if retries > command.budget.max_data_gap_retries:
                values.update(
                    runs_attempted=prior.runs_attempted + 1,
                    failed_runs=prior.failed_runs + 1,
                    next_experiment_index=prior.next_experiment_index + 1,
                    failed_run_ids=(*prior.failed_run_ids, expected_run_id),
                )
            saved = self._save(prior, _issue_status(**values))
            self._emit(
                session_id,
                "DATA_GAP" if saved.status == "PAUSED_DATA_GAP" else "FAILED",
                experiment_id=expected_id,
                run_id=expected_run_id,
                reason=saved.termination_reason or "DATA_GAP_RETRY",
            )
            return saved

        try:
            if outcome.outcome == "COMPLETED":
                try:
                    existing_leak = self._state.get_leak(session_id, expected_run_id)
                except Exception:
                    raise RunnerError("RUN_STORAGE_FAILURE") from None
                if existing_leak is not None:
                    try:
                        leak = require_leak_decision(existing_leak)
                    except Exception:
                        raise RunnerError("LEAK_GATE_INVALID") from None
                else:
                    try:
                        raw_leak = self._leak_gate.evaluate(outcome)
                    except Exception:
                        raise RunnerError("LEAK_GATE_UNAVAILABLE") from None
                    try:
                        leak = require_leak_decision(raw_leak)
                    except Exception:
                        raise RunnerError("LEAK_GATE_INVALID") from None
                if (
                    leak.experiment_id != expected_id
                    or leak.revision_hash != _revision_hash(command)
                    or leak.snapshot_hash != experiment.dataset.content_hash
                    or leak.input_rows != outcome.input_rows
                ):
                    raise RunnerError("LEAK_BINDING_MISMATCH")
                if len(outcome.metrics) != 1 or any(
                    type(metric) is not MetricEvidenceV1
                    or metric.experiment_id != expected_id
                    or metric.run_id != expected_run_id
                    or metric.revision_hash != _revision_hash(command)
                    or metric.author_id != command.actor_id
                    or metric.result_digest != outcome.result_digest
                    or metric.status != "completed"
                    or metric.cost_usd != outcome.cost_usd
                    or metric.elapsed_ns != outcome.elapsed_ns
                    or metric.compute_units != outcome.compute_units
                    for metric in outcome.metrics
                ):
                    raise RunnerError("REPLAY_METRICS_INVALID")
                if (
                    not any(
                        item.run_id == expected_run_id
                        and item.result_digest == outcome.result_digest
                        for item in self._state.get_outcomes(session_id)
                    )
                    and self._state.append_outcome(session_id, outcome) is not True
                ):
                    raise RunnerError("RUN_STORAGE_FAILURE")
                if (
                    existing_leak is None
                    and self._state.append_leak(session_id, expected_run_id, leak) is not True
                ):
                    raise RunnerError("RUN_STORAGE_FAILURE")
                if not leak.passed:
                    ids = (*prior.failed_run_ids, expected_run_id)
                    return self._finish(
                        prior,
                        "FAILED",
                        "LEAK_FAILURE",
                        event_type="RUN_FAILED",
                        experiment_id=expected_id,
                        result_digest=outcome.result_digest,
                        actions_used=actions_used,
                        runs_attempted=prior.runs_attempted + 1,
                        failed_runs=prior.failed_runs + 1,
                        next_experiment_index=prior.next_experiment_index + 1,
                        failed_run_ids=ids,
                        cost_spent_usd=cost,
                        elapsed_ns=elapsed_ns,
                        compute_units=compute_units,
                        data_gap_retries=0,
                        run_id=expected_run_id,
                    )
                # Persist immediately so restart/recovery cannot invent a replay result.
                # Outcome and leak ports must be idempotent by session + experiment ID.
            elif outcome.outcome == "FAILED":
                already_stored = any(
                    item.run_id == expected_run_id and item.result_digest == outcome.result_digest
                    for item in self._state.get_outcomes(session_id)
                )
                if (
                    not already_stored
                    and self._state.append_outcome(session_id, outcome) is not True
                ):
                    raise RunnerError("RUN_STORAGE_FAILURE")
                values = _status_values(prior)
                values.update(
                    status="RUNNING",
                    actions_used=actions_used,
                    runs_attempted=prior.runs_attempted + 1,
                    failed_runs=prior.failed_runs + 1,
                    next_experiment_index=prior.next_experiment_index + 1,
                    failed_run_ids=(*prior.failed_run_ids, expected_run_id),
                    cost_spent_usd=cost,
                    elapsed_ns=elapsed_ns,
                    compute_units=compute_units,
                    data_gap_retries=0,
                    termination_reason=None,
                )
                saved = self._save(prior, _issue_status(**values))
                self._emit(
                    session_id,
                    "RUN_FAILED",
                    experiment_id=expected_id,
                    result_digest=outcome.result_digest,
                    reason="REPLAY_FAILURE",
                    run_id=expected_run_id,
                )
                if saved.next_experiment_index == len(command.experiments):
                    return self._evaluate_critic(command, saved)
                return saved
            else:
                raise RunnerError("REPLAY_FAILURE")
        except RunnerError as error:
            if error.code == "RUN_STORAGE_FAILURE":
                raise
            reason = (
                error.code
                if error.code
                in {
                    "LEAK_GATE_UNAVAILABLE",
                    "LEAK_GATE_INVALID",
                    "LEAK_BINDING_MISMATCH",
                    "REPLAY_METRICS_INVALID",
                }
                else "RUN_PROCESSING_FAILURE"
            )
            return self._finish(
                prior,
                "FAILED",
                reason,
                event_type="RUN_FAILED",
                experiment_id=expected_id,
                result_digest=outcome.result_digest,
                actions_used=actions_used,
                runs_attempted=prior.runs_attempted + 1,
                failed_runs=prior.failed_runs + 1,
                next_experiment_index=prior.next_experiment_index + 1,
                failed_run_ids=(*prior.failed_run_ids, expected_run_id),
                cost_spent_usd=cost,
                elapsed_ns=elapsed_ns,
                compute_units=compute_units,
                data_gap_retries=0,
                run_id=expected_run_id,
            )
        except Exception:
            return self._finish(
                prior,
                "FAILED",
                "RUN_PROCESSING_FAILURE",
                event_type="RUN_FAILED",
                experiment_id=expected_id,
                result_digest=outcome.result_digest,
                actions_used=actions_used,
                runs_attempted=prior.runs_attempted + 1,
                failed_runs=prior.failed_runs + 1,
                next_experiment_index=prior.next_experiment_index + 1,
                failed_run_ids=(*prior.failed_run_ids, expected_run_id),
                cost_spent_usd=cost,
                elapsed_ns=elapsed_ns,
                compute_units=compute_units,
                data_gap_retries=0,
                run_id=expected_run_id,
            )

        successes = prior.successful_runs + 1
        ids = (*prior.completed_run_ids, expected_run_id)
        values = _status_values(prior)
        values.update(
            status="RUNNING",
            actions_used=actions_used,
            runs_attempted=prior.runs_attempted + 1,
            successful_runs=successes,
            next_experiment_index=prior.next_experiment_index + 1,
            completed_run_ids=ids,
            cost_spent_usd=cost,
            elapsed_ns=elapsed_ns,
            compute_units=compute_units,
            data_gap_retries=0,
            termination_reason=None,
        )
        saved = self._save(prior, _issue_status(**values))
        self._emit(
            session_id,
            "RUN_SUCCEEDED",
            experiment_id=expected_id,
            result_digest=outcome.result_digest,
            run_id=expected_run_id,
        )
        if saved.next_experiment_index == len(command.experiments):
            return self._evaluate_critic(command, saved)
        return saved

    def _evaluate_critic(self, command: CouncilRunCommandV1, prior: RunStatusV1) -> RunStatusV1:
        try:
            stored_outcomes = self._state.get_outcomes(prior.session_id)
            if type(stored_outcomes) is not tuple or len(stored_outcomes) > 64:
                raise RunnerError("RUN_STORAGE_FAILURE")
            outcomes = tuple(require_replay_outcome(item) for item in stored_outcomes)
        except Exception:
            return self._finish(prior, "FAILED", "REPLAY_FAILURE", event_type="FAILED")
        successful_outcomes = tuple(item for item in outcomes if item.outcome == "COMPLETED")
        if len(successful_outcomes) != prior.successful_runs:
            return self._finish(prior, "FAILED", "QUORUM_NOT_MET", event_type="FAILED")
        if prior.successful_runs < command.budget.min_successful_runs:
            return self._finish(prior, "FAILED", "QUORUM_NOT_MET", event_type="FAILED")
        groups: dict[str, list[ReplayOutcomeV1]] = {}
        for outcome in successful_outcomes:
            groups.setdefault(outcome.experiment_id, []).append(outcome)
        if prior.actions_used + len(groups) > command.budget.max_actions:
            return self._finish(prior, "FAILED", "ACTION_BUDGET_EXCEEDED", event_type="FAILED")
        critic_actions = 0
        for experiment_id, group_values in groups.items():
            group = tuple(group_values)
            raw_leaks = tuple(
                self._state.get_leak(prior.session_id, outcome.run_id) for outcome in group
            )
            if any(type(leak) is not LeakDecisionV1 for leak in raw_leaks):
                return self._finish(prior, "FAILED", "LEAK_EVIDENCE_MISSING", event_type="FAILED")
            try:
                leaks = tuple(
                    require_leak_decision(cast(LeakDecisionV1, leak)) for leak in raw_leaks
                )
            except Exception:
                return self._finish(prior, "FAILED", "LEAK_GATE_INVALID", event_type="FAILED")
            critic_actions += 1
            try:
                decision = require_critique_decision(self._critic_gate.evaluate(group, leaks))
            except Exception:
                return self._finish(
                    prior,
                    "FAILED",
                    "CRITIC_FAILURE",
                    event_type="FAILED",
                    actions_used=prior.actions_used + critic_actions,
                )
            if (
                decision.experiment_id != experiment_id
                or decision.revision_hash != _revision_hash(command)
                or decision.snapshot_hash != command.snapshot.content_hash
                or decision.leak_digest != _leak_digest(leaks[-1])
                or decision.completed_runs != len(group)
                or not decision.passed
            ):
                return self._finish(
                    prior,
                    "FAILED",
                    "CRITIC_FAILURE",
                    event_type="FAILED",
                    actions_used=prior.actions_used + critic_actions,
                )
        final_status = "PARTIAL_COMPLETED" if prior.failed_runs else "COMPLETED"
        reason = "RUNS_COMPLETED" if final_status == "COMPLETED" else "PARTIAL_RUNS_COMPLETED"
        return self._finish(
            prior,
            final_status,
            reason,
            event_type=final_status,
            actions_used=prior.actions_used + critic_actions,
        )

    def request_cancel(self, session_id: str, principal: TrustedPrincipalV1) -> RunStatusV1:
        """Cancel with one port call measured by the injected clock."""
        if type(session_id) is not str or not session_id or len(session_id) > 128:
            raise RunnerError("RUN_SESSION_INVALID")
        self._authorize(principal, "agent.run.cancel", _run_resource_id(session_id))
        try:
            prior = self._state.get_status(session_id)
            command = self._queue.get_command(session_id)
        except Exception:
            raise RunnerError("RUN_STORAGE_FAILURE") from None
        if prior is None or command is None:
            raise RunnerError("AUTHORIZATION_DENIED")
        if type(command) is not CouncilRunCommandV1:
            raise RunnerError("RUN_STORAGE_FAILURE")
        prior = require_status(prior)
        self._require_owner(principal, prior.owner_principal_id, prior.owner_project_id)
        checked = CouncilRunCommandV1.model_validate(command.model_dump(mode="python"))
        if (
            checked.actor_id != prior.owner_principal_id
            or command_digest(checked) != prior.command_digest
        ):
            raise RunnerError("RUN_STORAGE_FAILURE")
        if prior.status in _TERMINAL:
            return prior
        if prior.status == "CANCEL_REQUESTED":
            pending = prior
        else:
            pending = self._save(
                prior,
                _issue_status(**{**_status_values(prior), "status": "CANCEL_REQUESTED"}),
            )
            self._emit(session_id, "CANCEL_REQUESTED")
        return self._complete_cancel(pending)

    def _complete_cancel(self, pending: RunStatusV1) -> RunStatusV1:
        """Resume one persisted cancel request without replaying experiment work."""
        session_id = pending.session_id
        try:
            call_started_ns = self._monotonic_ns()
        except RunnerError:
            return self._finish(
                pending,
                "CANCEL_FAILED",
                "CANCEL_CLOCK_INVALID",
                event_type="CANCEL_FAILED",
            )
        try:
            receipt = self._replay.cancel(session_id)
        except Exception:
            receipt = None
        try:
            call_finished_ns = self._monotonic_ns()
        except RunnerError:
            return self._finish(
                pending,
                "CANCEL_FAILED",
                "CANCEL_CLOCK_INVALID",
                event_type="CANCEL_FAILED",
            )
        measured_elapsed_ns = call_finished_ns - call_started_ns
        if measured_elapsed_ns < 0:
            return self._finish(
                pending,
                "CANCEL_FAILED",
                "CANCEL_CLOCK_INVALID",
                event_type="CANCEL_FAILED",
            )
        if type(receipt) is not CancelReceiptV1 or type(receipt.confirmed) is not bool:
            return self._finish(
                pending, "CANCEL_FAILED", "CANCEL_PORT_INVALID", event_type="CANCEL_FAILED"
            )
        if measured_elapsed_ns > _CANCEL_LIMIT_NS or receipt.confirmed is not True:
            return self._finish(
                pending,
                "CANCEL_FAILED",
                "CANCEL_TIMEOUT",
                event_type="CANCEL_FAILED",
                elapsed_ns=max(pending.elapsed_ns, measured_elapsed_ns),
            )
        return self._finish(
            pending,
            "CANCELED",
            "CANCEL_CONFIRMED",
            event_type="CANCELED",
            elapsed_ns=max(pending.elapsed_ns, measured_elapsed_ns),
        )

    def run_until_terminal(self, session_id: str) -> RunStatusV1:
        """Convenience bounded driver; every iteration consumes the action cap."""
        status = self.recover(session_id)
        command = self._queue.get_command(session_id)
        if type(command) is not CouncilRunCommandV1:
            raise RunnerError("RUN_STORAGE_FAILURE")
        try:
            command = CouncilRunCommandV1.model_validate(command.model_dump(mode="python"))
        except Exception:
            raise RunnerError("RUN_STORAGE_FAILURE") from None
        for _ in range(command.budget.max_actions + 1):
            if status.status in _TERMINAL:
                return status
            previous = status
            status = self.advance(session_id)
            if status == previous:
                return self._finish(status, "FAILED", "RUN_STATE_CONFLICT", event_type="FAILED")
        if status.status not in _TERMINAL:
            return self._finish(status, "FAILED", "ACTION_BUDGET_EXCEEDED", event_type="FAILED")
        return status


def _signals_digest(experiment: object) -> str:
    try:
        payload = [ref.model_dump(mode="json") for ref in experiment.signal_refs]  # type: ignore[attr-defined]
        return hashlib.sha256(canonical_json(payload)).hexdigest()
    except Exception:
        raise RunnerError("REPLAY_BINDING_MISMATCH") from None


def _revision_hash(command: CouncilRunCommandV1) -> str:
    try:
        return hypothesis_full_revision(command).sha256_hex
    except RevisionHashError:
        raise RunnerError("RUN_COMMAND_INVALID") from None


def _leak_digest(leak: LeakDecisionV1) -> str:
    try:
        return hashlib.sha256(canonical_json(leak.model_dump(mode="python"))).hexdigest()
    except Exception:
        raise RunnerError("LEAK_BINDING_MISMATCH") from None


def _add_decimal(left: Decimal, right: Decimal) -> Decimal:
    try:
        value = exact_add(left, right)
        if value < 0:
            raise ValueError("negative")
        return Decimal(str(value))
    except Exception:
        raise RunnerError("RUN_BUDGET_INVALID") from None


__all__ = ["CouncilRunnerService"]
