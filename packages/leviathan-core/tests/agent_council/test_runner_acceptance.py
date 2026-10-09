"""Independent contract acceptance for the offline bounded council runner."""

from __future__ import annotations

import hashlib
import socket
from datetime import UTC, datetime
from decimal import Decimal
from urllib import request

import pytest

from leviathan_core.agent_council.critic_policy import evaluate_critique
from leviathan_core.agent_council.experiment_identity import derive_experiment_id
from leviathan_core.agent_council.leak_models import (
    CritiqueMetricsV1,
    CritiquePolicyV1,
    FeatureAsOfV1,
    LabelWindowV1,
    LeakEvidenceV1,
    MetricEvidenceV1,
    MetricThresholdV1,
    NamedMetricV1,
    SplitMembershipV1,
)
from leviathan_core.agent_council.leak_rules import evaluate_leaks
from leviathan_core.agent_council.runner_models import (
    CancelReceiptV1,
    CouncilRunCommandV1,
    CouncilRunEventV1,
    QueueReceiptV1,
    ReplayOutcomeV1,
    RunBudgetV1,
    RunnerError,
    RunStatusV1,
    _issue_replay_outcome,
    _issue_status,
    require_event,
    require_replay_outcome,
    require_status,
)
from leviathan_core.agent_council.runner_service import CouncilRunnerService
from leviathan_core.agent_council.state_models import (
    DatasetSnapshotRefV1,
    ExperimentSpecV1,
    HypothesisV1,
    SignalRefV1,
    TimeWindowV1,
)
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import SealError
from leviathan_core.security import (
    AuthorizationPolicyV1,
    EffectV1,
    PolicyRuleV1,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_core.security.authz_models import _VERIFIER_MARKER

HASH = "a" * 64
SIGNAL = SignalRefV1(signal_id="close-v1", version="1")
RUN_ACTIONS = (
    "agent.run.enqueue",
    "agent.run.cancel",
    "agent.run.read",
    "agent.run.advance",
)
POLICY_START = datetime(1970, 1, 1, tzinfo=UTC)
POLICY_END = datetime(2500, 1, 1, tzinfo=UTC)


def trusted_principal(
    principal_id: str = "researcher-1", project_id: str = "leviathan-ai"
) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id=principal_id,
        project_id=project_id,
        roles=("runner.researcher",),
        env="development",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=_VERIFIER_MARKER
    )


OWNER_PRINCIPAL = trusted_principal()


def authorization_policy(
    actions: tuple[str, ...] = RUN_ACTIONS,
) -> AuthorizationPolicyV1:
    allow = PolicyRuleV1(
        rule_id="runner.allow",
        effect=EffectV1.ALLOW,
        roles=("runner.researcher",),
        actions=actions,
        resources=("*",),
        env="development",
        not_before=POLICY_START,
        not_after=POLICY_END,
    )
    return AuthorizationPolicyV1("v1", "leviathan-ai", POLICY_END, (allow,))


def budget(**changes: object) -> RunBudgetV1:
    values: dict[str, object] = {
        "max_runs": 2,
        "min_successful_runs": 1,
        "max_actions": 4,
        "max_elapsed_ns": 1_000_000,
        "max_compute_units": 100,
        "max_cost_usd": Decimal("10.00"),
        "max_data_gap_retries": 1,
    }
    values.update(changes)
    return RunBudgetV1(**values)


def hypothesis(**changes: object) -> HypothesisV1:
    values: dict[str, object] = {
        "hypothesis_id": "hypothesis-1",
        "version": 1,
        "strategy_name": "synthetic-strategy",
        "signal_refs": (SIGNAL,),
        "markets": ("SYNTH",),
        "horizon": TimeWindowV1(start_ns=1, end_ns=1000),
        "target_metrics": ("sharpe_ratio",),
        "max_leverage": Decimal("1"),
        "max_loss_per_trade": Decimal("0.01"),
        "seed_policy": "fixed",
        "seed": 17,
        "source_hashes": (HASH,),
    }
    values.update(changes)
    return HypothesisV1(**values)


def snapshot() -> DatasetSnapshotRefV1:
    return DatasetSnapshotRefV1(
        snapshot_id="snapshot-1",
        version=1,
        content_hash=HASH,
        horizon=TimeWindowV1(start_ns=1, end_ns=1000),
    )


def experiment(*, key: str = "experiment-key") -> ExperimentSpecV1:
    return ExperimentSpecV1(
        hypothesis_id="hypothesis-1",
        hypothesis_version=1,
        dataset=snapshot(),
        signal_refs=(SIGNAL,),
        engine_version="engine-v1",
        parameters_json='{"window":20}',
        seed=17,
        train_window=TimeWindowV1(start_ns=100, end_ns=200),
        test_window=TimeWindowV1(start_ns=300, end_ns=400),
        idempotency_key=key,
    )


def command(*, experiments: tuple[ExperimentSpecV1, ...] | None = None,
            run_budget: RunBudgetV1 | None = None,
            key: str = "command-key", seed: int = 17,
            actor_id: str = "researcher-1") -> CouncilRunCommandV1:
    return CouncilRunCommandV1(
        idempotency_key=key,
        actor_id=actor_id,
        hypothesis=hypothesis(),
        snapshot=snapshot(),
        experiments=experiments if experiments is not None else (experiment(),),
        seed=seed,
        calendar_id="synthetic-calendar-v1",
        slippage_model_id="synthetic-slippage-v1",
        latency_model_id="synthetic-latency-v1",
        budget=run_budget or budget(),
    )


def revision_hash(value: HypothesisV1) -> str:
    return hashlib.sha256(canonical_json(value.model_dump(mode="json"))).hexdigest()


def signals_digest(value: ExperimentSpecV1) -> str:
    payload = [reference.model_dump(mode="json") for reference in value.signal_refs]
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def leak_evidence_for(
    run_command: CouncilRunCommandV1,
    run_experiment: ExperimentSpecV1,
    *,
    leaking: bool = False,
) -> LeakEvidenceV1:
    feature_available = 151 if leaking else 150
    return LeakEvidenceV1(
        experiment_id=derive_experiment_id(run_experiment),
        revision_hash=revision_hash(run_command.hypothesis),
        snapshot_hash=run_command.snapshot.content_hash,
        train_window=TimeWindowV1(start_ns=100, end_ns=200),
        test_window=TimeWindowV1(start_ns=300, end_ns=400),
        holdout_window=TimeWindowV1(start_ns=500, end_ns=600),
        features=(
            FeatureAsOfV1(
                signal_id=SIGNAL.signal_id,
                sample_at_ns=150,
                available_at_ns=feature_available,
                offset_ns=0,
            ),
        ),
        labels=(
            LabelWindowV1( sample_at_ns=190, label_start_ns=190,
                           label_end_ns=200, split="train"),
            LabelWindowV1(sample_at_ns=350, label_start_ns=350,
                          label_end_ns=360, split="test"),
            LabelWindowV1(sample_at_ns=550, label_start_ns=550,
                          label_end_ns=560, split="holdout"),
        ),
        normalization_fit_window=TimeWindowV1(start_ns=110, end_ns=190),
        split_memberships=(
            SplitMembershipV1(row_digest="1" * 64, split="train"),
            SplitMembershipV1(row_digest="2" * 64, split="test"),
            SplitMembershipV1(row_digest="3" * 64, split="holdout"),
        ),
        engine_version=run_experiment.engine_version,
        holdout_used_for_training=False,
    )


def metric_policy() -> CritiquePolicyV1:
    return CritiquePolicyV1(
        version="runner-critic-v1",
        thresholds=(
            MetricThresholdV1(
                name="sharpe_ratio", comparison="gte", threshold=Decimal("1")
            ),
        ),
        minimum_completed_runs=1,
        max_input_rows=100,
        max_runs=64,
        max_metrics=5,
        max_evaluation_cost_usd=Decimal("100"),
        max_elapsed_ns=1_000_000_000,
        max_compute_units=100_000,
    )


class FakeQueue:
    def __init__(self) -> None:
        self.commands: dict[str, CouncilRunCommandV1] = {}
        self.receipts: dict[tuple[str, str, str], QueueReceiptV1] = {}
        self.hypothesis_receipts: dict[tuple[str, str, str], QueueReceiptV1] = {}
        self.counter = 0

    def find_by_idempotency_key(
        self, key: str, owner_principal_id: str, owner_project_id: str
    ) -> QueueReceiptV1 | None:
        return self.receipts.get((owner_principal_id, owner_project_id, key))

    def find_by_hypothesis_digest(
        self, digest: str, owner_principal_id: str, owner_project_id: str
    ) -> QueueReceiptV1 | None:
        return self.hypothesis_receipts.get(
            (owner_principal_id, owner_project_id, digest)
        )

    def enqueue(
        self,
        key: str,
        digest: str,
        hypothesis_digest: str,
        owner_principal_id: str,
        owner_project_id: str,
        value: CouncilRunCommandV1,
    ) -> QueueReceiptV1:
        self.counter += 1
        receipt = QueueReceiptV1(
            session_id=f"session-{self.counter}",
            command_digest=digest,
            hypothesis_digest=hypothesis_digest,
            owner_principal_id=owner_principal_id,
            owner_project_id=owner_project_id,
            created=True,
        )
        owner = (owner_principal_id, owner_project_id)
        self.receipts[(*owner, key)] = receipt
        self.hypothesis_receipts[(*owner, hypothesis_digest)] = receipt
        self.commands[receipt.session_id] = value
        return receipt

    def get_command(self, session_id: str) -> CouncilRunCommandV1 | None:
        return self.commands.get(session_id)


class FakeState:
    def __init__(self) -> None:
        self.statuses: dict[str, RunStatusV1] = {}
        self.outcomes: dict[str, list[ReplayOutcomeV1]] = {}
        self.leaks: dict[str, dict[str, object]] = {}

    def get_status(self, session_id: str) -> RunStatusV1 | None:
        return self.statuses.get(session_id)

    def compare_and_set_status(
        self, expected: RunStatusV1 | None, value: RunStatusV1
    ) -> bool:
        current = self.statuses.get(value.session_id)
        if (expected is None and current is not None) or (
            expected is not None and current != expected
        ):
            return False
        self.statuses[value.session_id] = value
        return True

    def get_outcomes(self, session_id: str) -> tuple[ReplayOutcomeV1, ...]:
        return tuple(self.outcomes.get(session_id, ()))

    def append_outcome(self, session_id: str, outcome: ReplayOutcomeV1) -> bool:
        existing = self.outcomes.setdefault(session_id, [])
        for item in existing:
            if item.run_id == outcome.run_id:
                return item == outcome
        existing.append(outcome)
        return True

    def get_leaks(self, session_id: str) -> tuple[object, ...]:
        return tuple(self.leaks.get(session_id, {}).values())

    def get_leak(self, session_id: str, run_id: str) -> object | None:
        return self.leaks.get(session_id, {}).get(run_id)

    def append_leak(self, session_id: str, run_id: str, leak: object) -> bool:
        existing = self.leaks.setdefault(session_id, {}).get(run_id)
        if existing is not None:
            return existing == leak
        self.leaks[session_id][run_id] = leak
        return True


class FakeEventStore:
    def __init__(self) -> None:
        self.events: list[CouncilRunEventV1] = []

    def last_sequence(self, session_id: str) -> int:
        matching = [event.sequence for event in self.events if event.session_id == session_id]
        return max(matching, default=0)

    def append(self, event: CouncilRunEventV1) -> bool:
        if event.sequence != self.last_sequence(event.session_id) + 1:
            return False
        self.events.append(event)
        return True


class FakeEventStream:
    def __init__(self, store: FakeEventStore) -> None:
        self.store = store
        self.events: list[CouncilRunEventV1] = []

    def publish(self, event: CouncilRunEventV1) -> None:
        assert event in self.store.events
        self.events.append(event)


class FakeReplay:
    def __init__(
        self,
        outcomes: tuple[tuple[str, Decimal, int, int], ...] = (
            ("COMPLETED", Decimal("0.1"), 1, 1),
        ),
        *,
        cancel: CancelReceiptV1 | None = None,
        repeat_result_digest: bool = False,
    ) -> None:
        self.outcome_specs = outcomes
        self.cancel_receipt = cancel or CancelReceiptV1(confirmed=True, elapsed_ns=1)
        self.repeat_result_digest = repeat_result_digest
        self.calls: list[str] = []
        self.cancel_calls = 0
        self.provider_calls = 0

    def execute(
        self, run_experiment: ExperimentSpecV1, run_command: CouncilRunCommandV1
    ) -> ReplayOutcomeV1:
        index = len(self.calls)
        self.calls.append(run_experiment.idempotency_key)
        outcome, cost, elapsed, compute = self.outcome_specs[index]
        result_digest = (
            hashlib.sha256(b"same-result").hexdigest()
            if self.repeat_result_digest
            else hashlib.sha256(f"result-{index}".encode()).hexdigest()
        )
        return _issue_replay_outcome(
            experiment_id=derive_experiment_id(run_experiment),
            run_id=run_experiment.idempotency_key,
            result_digest=result_digest,
            snapshot_hash=run_experiment.dataset.content_hash,
            signals_digest=signals_digest(run_experiment),
            engine_version=run_experiment.engine_version,
            seed=run_experiment.seed,
            outcome=outcome,
            cost_usd=cost,
            elapsed_ns=elapsed,
            compute_units=compute,
            artifact_refs=(),
            input_rows=3 if outcome == "COMPLETED" else 0,
            metrics=(
                (
                    MetricEvidenceV1(
                        experiment_id=derive_experiment_id(run_experiment),
                        run_id=run_experiment.idempotency_key,
                        author_id=run_command.actor_id,
                        revision_hash=revision_hash(run_command.hypothesis),
                        result_digest=result_digest,
                        status="completed",
                        critique_metrics=CritiqueMetricsV1(
                            version="v1",
                            metrics=(
                                NamedMetricV1(
                                    name="sharpe_ratio", value=Decimal("2")
                                ),
                            ),
                        ),
                        risk_flags=(),
                        cost_usd=cost,
                        elapsed_ns=elapsed,
                        compute_units=compute,
                    ),
                )
                if outcome == "COMPLETED"
                else ()
            ),
            reason="SYNTHETIC_DATA_GAP" if outcome == "DATA_GAP" else None,
        )

    def cancel(self, _session_id: str) -> CancelReceiptV1:
        self.cancel_calls += 1
        return self.cancel_receipt


class FakeLeakGate:
    def __init__(self, run_command: CouncilRunCommandV1, *, leaking: bool = False) -> None:
        self.run_command = run_command
        self.leaking = leaking
        self.calls = 0

    def evaluate(self, outcome: ReplayOutcomeV1) -> object:
        self.calls += 1
        run_experiment = next(
            item for item in self.run_command.experiments
            if derive_experiment_id(item) == outcome.experiment_id
        )
        return evaluate_leaks(
            leak_evidence_for(self.run_command, run_experiment, leaking=self.leaking)
        )


class FakeCriticGate:
    def __init__(self, run_command: CouncilRunCommandV1) -> None:
        self.run_command = run_command
        self.calls = 0

    def evaluate(self, outcomes: tuple[ReplayOutcomeV1, ...], leaks: tuple[object, ...]) -> object:
        self.calls += 1
        last = outcomes[-1]
        metric_evidence = tuple(
            metric for outcome in outcomes for metric in outcome.metrics
        )
        decision = evaluate_critique(
            metric_policy(),
            metric_evidence,
            leaks[-1],
            input_rows=leaks[-1].input_rows,
        )
        assert decision.experiment_id == last.experiment_id
        return decision


class FakeClock:
    def __init__(
        self,
        values: tuple[int, ...] = (),
        *,
        monotonic_values: tuple[int, ...] = (),
    ) -> None:
        self.values = values
        self.index = 0
        self.monotonic_values = monotonic_values
        self.monotonic_index = 0

    def now_ns(self) -> int:
        if not self.values:
            return 100
        value = self.values[min(self.index, len(self.values) - 1)]
        self.index += 1
        return value

    def monotonic_ns(self) -> int:
        if not self.monotonic_values:
            return 1_000 + self.monotonic_index
        value = self.monotonic_values[
            min(self.monotonic_index, len(self.monotonic_values) - 1)
        ]
        self.monotonic_index += 1
        return value


def service_for(
    run_command: CouncilRunCommandV1,
    *,
    principal: TrustedPrincipalV1 = OWNER_PRINCIPAL,
    service_principal: TrustedPrincipalV1 = OWNER_PRINCIPAL,
    policy: AuthorizationPolicyV1 | None = None,
    replay: FakeReplay | None = None,
    leak_gate: FakeLeakGate | None = None,
    critic_gate: FakeCriticGate | None = None,
    state: FakeState | None = None,
    queue: FakeQueue | None = None,
    event_store: FakeEventStore | None = None,
    clock: FakeClock | None = None,
) -> tuple[CouncilRunnerService, dict[str, object]]:
    effective_policy = policy or authorization_policy()
    fake_queue = queue or FakeQueue()
    fake_state = state or FakeState()
    stored_events = event_store or FakeEventStore()
    event_stream = FakeEventStream(stored_events)
    fake_replay = replay or FakeReplay()
    fake_leaks = leak_gate or FakeLeakGate(run_command)
    fake_critic = critic_gate or FakeCriticGate(run_command)
    service = CouncilRunnerService(
        authorization_policy=effective_policy,
        service_principal=service_principal,
        queue=fake_queue,
        state=fake_state,
        event_store=stored_events,
        event_stream=event_stream,
        replay=fake_replay,
        leak_gate=fake_leaks,
        critic_gate=fake_critic,
        clock=clock or FakeClock(),
    )
    return service, {
        "principal": principal,
        "service_principal": service_principal,
        "authorization_policy": effective_policy,
        "queue": fake_queue,
        "state": fake_state,
        "event_store": stored_events,
        "event_stream": event_stream,
        "replay": fake_replay,
        "leak_gate": fake_leaks,
        "critic_gate": fake_critic,
    }


def test_run_budget_is_mandatory_exact_and_strictly_bounded() -> None:
    with pytest.raises(RunnerError) as missing:
        RunBudgetV1(max_runs=1)  # type: ignore[call-arg]
    assert missing.value.code == "RUN_MODEL_INVALID"

    assert budget(max_cost_usd=Decimal("0.100000000000000001")).max_cost_usd == Decimal(
        "0.100000000000000001"
    )
    for changes in (
        {"max_runs": 0},
        {"max_actions": True},
        {"max_data_gap_retries": -1},
        {"max_elapsed_ns": 7 * 24 * 60 * 60 * 1_000_000_000 + 1},
        {"max_cost_usd": 0.1},
        {"max_cost_usd": Decimal("NaN")},
        {"max_runs": 1, "min_successful_runs": 2},
    ):
        with pytest.raises(RunnerError):
            budget(**changes)


def test_command_requires_budget_and_binds_finite_experiment_grid() -> None:
    with pytest.raises(RunnerError) as missing:
        CouncilRunCommandV1(  # type: ignore[call-arg]
            idempotency_key="k", actor_id="researcher", hypothesis=hypothesis(),
            snapshot=snapshot(), experiments=(experiment(),), seed=17,
            calendar_id="cal", slippage_model_id="slip", latency_model_id="latency",
        )
    assert missing.value.code == "RUN_MODEL_INVALID"
    with pytest.raises(RunnerError):
        command(experiments=())
    with pytest.raises(RunnerError):
        command(run_budget=budget(max_runs=1), experiments=(experiment(), experiment(key="other")))
    with pytest.raises(RunnerError) as mismatch:
        command(seed=18)
    assert mismatch.value.code in {"RUN_COMMAND_INVALID", "RUN_MODEL_INVALID"}


def test_run_status_event_and_replay_models_cannot_be_forged_at_public_boundary() -> None:
    with pytest.raises(RunnerError) as status_error:
        RunStatusV1(session_id="forged", command_digest=HASH, status="QUEUED")  # type: ignore[call-arg]
    assert status_error.value.code == "RUN_STATUS_UNISSUED"
    with pytest.raises(RunnerError) as event_error:
        CouncilRunEventV1(session_id="forged", sequence=1, event_type="QUEUED", at_ns=1)
    assert event_error.value.code == "RUN_EVENT_UNISSUED"
    with pytest.raises(RunnerError) as replay_error:
        ReplayOutcomeV1(experiment_id="forged", result_digest=HASH, snapshot_hash=HASH,
                        signals_digest=HASH, engine_version="e", seed=0, outcome="COMPLETED",
                        cost_usd=Decimal(0), elapsed_ns=0, compute_units=0, artifact_refs=())
    assert replay_error.value.code == "REPLAY_OUTCOME_UNISSUED"


def test_issued_runner_records_reject_setstate_without_losing_issuance() -> None:
    run_command = command()
    service, ports = service_for(run_command)
    status = service.enqueue(run_command, OWNER_PRINCIPAL)
    event = ports["event_store"].events[0]  # type: ignore[attr-defined]
    replay_outcome = ports["replay"].execute(  # type: ignore[attr-defined]
        run_command.experiments[0], run_command
    )

    for record, require_issued in (
        (status, require_status),
        (event, require_event),
        (replay_outcome, require_replay_outcome),
    ):
        with pytest.raises(SealError) as forbidden:
            record.__setstate__({"tamper": "acceptance-canary"})
        assert forbidden.value.code == "SEAL_FORBIDDEN_OPERATION"
        assert require_issued(record) is record


def test_queue_ack_is_not_success_and_idempotent_enqueue_does_not_replay() -> None:
    run_command = command()
    service, ports = service_for(run_command)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    duplicate = service.enqueue(run_command, OWNER_PRINCIPAL)

    assert queued.status == duplicate.status == "QUEUED"
    assert queued.session_id == duplicate.session_id
    assert ports["replay"].calls == []  # type: ignore[attr-defined]
    assert [event.event_type for event in ports["event_store"].events] == ["QUEUED"]  # type: ignore[attr-defined]
    assert [event.sequence for event in ports["event_stream"].events] == [1]  # type: ignore[attr-defined]


def test_identical_hypothesis_from_different_owners_gets_distinct_sessions() -> None:
    owner_one = OWNER_PRINCIPAL
    owner_two = trusted_principal("researcher-2", "leviathan-ai")
    command_one = command(key="shared-key", actor_id=owner_one.principal_id)
    command_two = command(key="shared-key", actor_id=owner_two.principal_id)
    service, ports = service_for(command_one)

    first = service.enqueue(command_one, owner_one)
    second = service.enqueue(command_two, owner_two)

    assert first.session_id != second.session_id
    assert first.owner_principal_id == owner_one.principal_id
    assert second.owner_principal_id == owner_two.principal_id
    assert first.owner_project_id == second.owner_project_id == "leviathan-ai"
    assert ports["queue"].counter == 2  # type: ignore[attr-defined]
    assert service.enqueue(command_one, owner_one).session_id == first.session_id


def test_same_hypothesis_with_different_command_payload_fails_idempotency() -> None:
    original = command()
    service, _ports = service_for(original)
    service.enqueue(original, OWNER_PRINCIPAL)
    changed = command(
        experiments=(experiment(key="different-experiment"),),
        key="different-command-key",
    )

    with pytest.raises(RunnerError) as conflict:
        service.enqueue(changed, OWNER_PRINCIPAL)
    assert conflict.value.code == "IDEMPOTENCY_CONFLICT"


def test_enqueue_requires_trusted_owner_and_explicit_authorization_policy() -> None:
    run_command = command()
    service, ports = service_for(run_command)
    untrusted_claims = PrincipalV1(
        principal_id="researcher-1",
        project_id="leviathan-ai",
        roles=("runner.researcher",),
        env="development",
    )
    with pytest.raises(RunnerError) as untrusted:
        service.enqueue(run_command, untrusted_claims)  # type: ignore[arg-type]
    assert untrusted.value.code == "AUTHORIZATION_DENIED"
    assert ports["queue"].counter == 0  # type: ignore[attr-defined]

    denied_service, denied_ports = service_for(
        run_command, policy=authorization_policy(actions=("agent.run.read",))
    )
    with pytest.raises(RunnerError) as denied:
        denied_service.enqueue(run_command, OWNER_PRINCIPAL)
    assert denied.value.code == "AUTHORIZATION_DENIED"
    assert denied_ports["queue"].counter == 0  # type: ignore[attr-defined]


def test_status_and_cancel_are_bound_to_persisted_principal_and_project() -> None:
    run_command = command()
    replay = FakeReplay()
    service, ports = service_for(run_command, replay=replay)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)

    for other in (
        trusted_principal("researcher-2", "leviathan-ai"),
        trusted_principal("researcher-1", "other-project"),
    ):
        with pytest.raises(RunnerError) as read_denied:
            service.read_status(queued.session_id, other)
        assert read_denied.value.code == "AUTHORIZATION_DENIED"
        with pytest.raises(RunnerError) as cancel_denied:
            service.request_cancel(queued.session_id, other)
        assert cancel_denied.value.code == "AUTHORIZATION_DENIED"

    assert service.read_status(queued.session_id, OWNER_PRINCIPAL) == queued
    assert replay.cancel_calls == 0
    assert [event.event_type for event in ports["event_store"].events] == [  # type: ignore[attr-defined]
        "QUEUED"
    ]


def test_owner_mismatch_and_missing_id_are_indistinguishable() -> None:
    run_command = command()
    replay = FakeReplay()
    service, _ports = service_for(run_command, replay=replay)
    owned = service.enqueue(run_command, OWNER_PRINCIPAL)
    caller = trusted_principal("researcher-2", "leviathan-ai")

    def denial_for(operation: str, session_id: str) -> tuple[object, ...]:
        with pytest.raises(RunnerError) as denied:
            if operation == "read":
                service.read_status(session_id, caller)
            else:
                service.request_cancel(session_id, caller)
        return type(denied.value), denied.value.code, denied.value.args, str(denied.value)

    for operation in ("read", "cancel"):
        assert denial_for(operation, owned.session_id) == denial_for(
            operation, "unknown-session"
        )
    assert replay.cancel_calls == 0


@pytest.mark.parametrize(
    ("outcomes", "run_budget", "reason"),
    [
        ((("COMPLETED", Decimal("11"), 1, 1),), budget(), "EVALUATION_BUDGET_EXCEEDED"),
        ((("COMPLETED", Decimal("1"), 1_000_001, 1),), budget(), "EVALUATION_BUDGET_EXCEEDED"),
        ((("COMPLETED", Decimal("1"), 1, 101),), budget(), "EVALUATION_BUDGET_EXCEEDED"),
        ((("COMPLETED", Decimal("1"), 1, 1),), budget(max_actions=1), "ACTION_BUDGET_EXCEEDED"),
    ],
)
def test_budget_overrun_is_terminal_and_gates_do_not_run(
    outcomes: tuple[tuple[str, Decimal, int, int], ...],
    run_budget: RunBudgetV1,
    reason: str,
) -> None:
    run_command = command(run_budget=run_budget)
    replay = FakeReplay(outcomes)
    leaks = FakeLeakGate(run_command)
    critic = FakeCriticGate(run_command)
    service, _ports = service_for(run_command, replay=replay, leak_gate=leaks, critic_gate=critic)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    terminal = service.run_until_terminal(queued.session_id)

    assert terminal.status == "FAILED"
    assert terminal.termination_reason == reason
    assert terminal.actions_used <= run_budget.max_actions
    assert (
        terminal.cost_spent_usd <= run_budget.max_cost_usd
        or reason == "EVALUATION_BUDGET_EXCEEDED"
    )
    assert leaks.calls == 0
    assert critic.calls == 0


def test_data_gap_retries_stop_at_declared_limit() -> None:
    run_command = command(run_budget=budget(max_data_gap_retries=0))
    replay = FakeReplay((("DATA_GAP", Decimal("0"), 1, 1),))
    service, ports = service_for(run_command, replay=replay)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    terminal = service.run_until_terminal(queued.session_id)

    assert terminal.status == "FAILED"
    assert terminal.termination_reason == "DATA_GAP_RETRIES_EXHAUSTED"
    assert terminal.data_gap_retries == 1
    assert terminal.actions_used == 1
    assert len(replay.calls) == 1
    assert ports["critic_gate"].calls == 0  # type: ignore[attr-defined]


def test_time_budget_expires_before_replay_work() -> None:
    run_command = command(run_budget=budget(max_elapsed_ns=10))
    replay = FakeReplay()
    clock = FakeClock((100, 100, 100, 100, 110, 110))
    service, _ports = service_for(run_command, replay=replay, clock=clock)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    terminal = service.advance(queued.session_id)

    assert terminal.status == "FAILED"
    assert terminal.termination_reason == "TIME_BUDGET_EXCEEDED"
    assert terminal.actions_used == 0
    assert replay.calls == []


def test_budget_overrun_is_totaled_exactly_before_leak_or_critic_evaluation() -> None:
    run_command = command(
        experiments=(experiment(), experiment(key="experiment-key-2")),
        run_budget=budget(
            max_runs=2,
            min_successful_runs=1,
            max_actions=5,
            max_cost_usd=Decimal("1"),
            max_compute_units=10,
        ),
    )
    replay = FakeReplay(
        (
            ("COMPLETED", Decimal("1"), 1, 10),
            ("COMPLETED", Decimal("0.01"), 1, 1),
        )
    )
    service, ports = service_for(run_command, replay=replay)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    first = service.advance(queued.session_id)
    assert first.status == "RUNNING"
    leak_calls_before_overrun = ports["leak_gate"].calls  # type: ignore[attr-defined]
    critic_calls_before_overrun = ports["critic_gate"].calls  # type: ignore[attr-defined]
    terminal = service.advance(queued.session_id)

    assert terminal.status == "FAILED"
    assert terminal.termination_reason == "EVALUATION_BUDGET_EXCEEDED"
    assert terminal.cost_spent_usd == Decimal("1.01")
    assert terminal.compute_units == 11
    assert replay.calls == [
        run_command.experiments[0].idempotency_key,
        run_command.experiments[1].idempotency_key,
    ]
    assert ports["leak_gate"].calls == leak_calls_before_overrun  # type: ignore[attr-defined]
    assert ports["critic_gate"].calls == critic_calls_before_overrun  # type: ignore[attr-defined]


def test_leak_failure_is_terminal_before_critic_and_preserves_failure() -> None:
    run_command = command()
    leaks = FakeLeakGate(run_command, leaking=True)
    critic = FakeCriticGate(run_command)
    service, ports = service_for(run_command, leak_gate=leaks, critic_gate=critic)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    terminal = service.run_until_terminal(queued.session_id)

    assert terminal.status == "FAILED"
    assert terminal.termination_reason == "LEAK_FAILURE"
    assert terminal.failed_runs == 1
    assert terminal.failed_run_ids == (run_command.experiments[0].idempotency_key,)
    assert leaks.calls == 1
    assert critic.calls == 0
    assert len(ports["state"].get_outcomes(queued.session_id)) == 1  # type: ignore[attr-defined]


def test_partial_quorum_keeps_failed_run_visible_and_never_calls_provider() -> None:
    run_command = command(
        experiments=(experiment(), experiment(key="experiment-key-2")),
        run_budget=budget(max_runs=2, min_successful_runs=1, max_actions=5),
    )
    replay = FakeReplay(
        (
            ("COMPLETED", Decimal("0.1"), 1, 1),
            ("FAILED", Decimal("0.2"), 1, 1),
        )
    )
    service, _ports = service_for(run_command, replay=replay)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    terminal = service.run_until_terminal(queued.session_id)

    assert terminal.status == "PARTIAL_COMPLETED"
    assert terminal.termination_reason == "PARTIAL_RUNS_COMPLETED"
    assert terminal.successful_runs == 1
    assert terminal.failed_runs == 1
    assert terminal.failed_run_ids == (run_command.experiments[1].idempotency_key,)
    assert replay.provider_calls == 0


def test_repeated_result_digest_terminates_as_no_progress_before_second_leak_gate() -> None:
    run_command = command(
        experiments=(experiment(), experiment(key="experiment-key-2")),
        run_budget=budget(max_runs=2, min_successful_runs=1, max_actions=5),
    )
    replay = FakeReplay(
        (
            ("COMPLETED", Decimal("0.1"), 1, 1),
            ("COMPLETED", Decimal("0.1"), 1, 1),
        ),
        repeat_result_digest=True,
    )
    leaks = FakeLeakGate(run_command)
    critic = FakeCriticGate(run_command)
    service, _ports = service_for(
        run_command, replay=replay, leak_gate=leaks, critic_gate=critic
    )
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    service.advance(queued.session_id)
    terminal = service.advance(queued.session_id)

    assert terminal.status == "FAILED"
    assert terminal.termination_reason == "NO_PROGRESS_LIMIT_REACHED"
    assert terminal.failed_run_ids == (run_command.experiments[1].idempotency_key,)
    assert terminal.cost_spent_usd == Decimal("0.2")
    assert len(replay.calls) == 2
    assert leaks.calls == 1
    assert critic.calls == 0


def test_passed_leak_and_critic_gates_complete_only_after_stored_events() -> None:
    run_command = command()
    service, ports = service_for(run_command)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    terminal = service.run_until_terminal(queued.session_id)

    assert terminal.status == "COMPLETED"
    assert terminal.successful_runs == 1
    assert terminal.failed_runs == 0
    assert terminal.termination_reason == "RUNS_COMPLETED"
    stored = ports["event_store"].events  # type: ignore[attr-defined]
    published = ports["event_stream"].events  # type: ignore[attr-defined]
    assert [event.sequence for event in stored] == list(range(1, len(stored) + 1))
    assert stored == published
    assert [event.event_type for event in stored] == [
        "QUEUED", "STARTED", "RUN_SUCCEEDED", "COMPLETED"
    ]
    assert ports["replay"].provider_calls == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("receipt", "status", "reason"),
    [
        (
            CancelReceiptV1(confirmed=True, elapsed_ns=5_000_000_000),
            "CANCELED",
            "CANCEL_CONFIRMED",
        ),
        (
            CancelReceiptV1(confirmed=False, elapsed_ns=5_000_000_001),
            "CANCEL_FAILED",
            "CANCEL_TIMEOUT",
        ),
    ],
)
def test_cancel_requires_a_valid_bounded_confirmation(
    receipt: CancelReceiptV1, status: str, reason: str
) -> None:
    run_command = command()
    replay = FakeReplay(cancel=receipt)
    service, ports = service_for(run_command, replay=replay)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    terminal = service.request_cancel(queued.session_id, OWNER_PRINCIPAL)

    assert terminal.status == status
    assert terminal.termination_reason == reason
    assert replay.cancel_calls == 1
    assert ports["replay"].calls == []  # type: ignore[attr-defined]


def test_cancel_timeout_uses_measured_port_duration() -> None:
    measured = 5_000_000_001
    clock = FakeClock(monotonic_values=(200, 200 + measured))
    run_command = command()
    replay = FakeReplay(cancel=CancelReceiptV1(confirmed=True, elapsed_ns=1))
    service, _ports = service_for(run_command, replay=replay, clock=clock)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)

    terminal = service.request_cancel(queued.session_id, OWNER_PRINCIPAL)

    assert terminal.status == "CANCEL_FAILED"
    assert terminal.termination_reason == "CANCEL_TIMEOUT"
    assert terminal.elapsed_ns == measured
    assert replay.cancel_calls == 1


def test_cancel_rejects_a_backwards_injected_clock() -> None:
    clock = FakeClock(monotonic_values=(300, 299))
    run_command = command()
    replay = FakeReplay(cancel=CancelReceiptV1(confirmed=True, elapsed_ns=1))
    service, _ports = service_for(run_command, replay=replay, clock=clock)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)

    terminal = service.request_cancel(queued.session_id, OWNER_PRINCIPAL)

    assert terminal.status == "CANCEL_FAILED"
    assert terminal.termination_reason == "CANCEL_CLOCK_INVALID"
    assert replay.cancel_calls == 1


def test_advance_recovers_pending_cancel_without_replaying_or_duplicate_event() -> None:
    run_command = command()
    replay = FakeReplay()
    service, ports = service_for(run_command, replay=replay)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    pending_fields = queued.model_dump(mode="python")
    pending_fields["status"] = "CANCEL_REQUESTED"
    pending = _issue_status(**pending_fields)
    ports["state"].statuses[queued.session_id] = pending  # type: ignore[attr-defined]

    terminal = service.advance(queued.session_id)

    assert terminal.status == "CANCELED"
    assert terminal.termination_reason == "CANCEL_CONFIRMED"
    assert replay.calls == []
    assert replay.cancel_calls == 1
    assert [event.event_type for event in ports["event_store"].events] == [  # type: ignore[attr-defined]
        "QUEUED",
        "CANCELED",
    ]


def test_restart_recovery_uses_stored_typed_status_without_duplicate_enqueue() -> None:
    run_command = command()
    first, ports = service_for(run_command)
    queued = first.enqueue(run_command, OWNER_PRINCIPAL)
    second, _ = service_for(
        run_command,
        state=ports["state"],  # type: ignore[arg-type]
        queue=ports["queue"],  # type: ignore[arg-type]
        event_store=ports["event_store"],  # type: ignore[arg-type]
    )

    recovered = second.recover(queued.session_id)
    assert require_status(recovered) is recovered
    assert recovered.status == "QUEUED"
    assert second.advance(queued.session_id).status == "COMPLETED"
    assert len(ports["event_store"].events) == 4  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("remove_status", "remove_queued_event"),
    [(True, False), (False, True), (True, True)],
)
def test_reenqueue_repairs_missing_initial_status_or_queued_event(
    remove_status: bool, remove_queued_event: bool
) -> None:
    run_command = command()
    first, ports = service_for(run_command)
    queued = first.enqueue(run_command, OWNER_PRINCIPAL)
    state = ports["state"]
    event_store = ports["event_store"]
    if remove_status:
        state.statuses.pop(queued.session_id)  # type: ignore[attr-defined]
    if remove_queued_event:
        event_store.events.clear()  # type: ignore[attr-defined]

    repaired_service, _ = service_for(
        run_command,
        state=state,  # type: ignore[arg-type]
        queue=ports["queue"],  # type: ignore[arg-type]
        event_store=event_store,  # type: ignore[arg-type]
    )
    repaired = repaired_service.enqueue(run_command, OWNER_PRINCIPAL)

    assert repaired.session_id == queued.session_id
    assert repaired.status == "QUEUED"
    assert require_status(state.get_status(queued.session_id))  # type: ignore[attr-defined]
    assert [event.event_type for event in event_store.events] == ["QUEUED"]  # type: ignore[attr-defined]


def test_network_access_is_forbidden_during_fake_runner_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("runner acceptance must not use network I/O")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(request, "urlopen", no_network)
    run_command = command()
    replay = FakeReplay()
    service, _ports = service_for(run_command, replay=replay)
    queued = service.enqueue(run_command, OWNER_PRINCIPAL)
    terminal = service.run_until_terminal(queued.session_id)

    assert terminal.status == "COMPLETED"
    assert replay.provider_calls == 0
