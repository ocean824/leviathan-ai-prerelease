"""Independent contract acceptance for the offline AGENT-005 scribe."""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from replay_outcome_support import issue_fixture_replay_outcome

from leviathan_core.agent_council.critic_policy import (
    ReviewerEvidenceClaimV1,
    critique_policy_digest,
    evaluate_critique,
    issue_reviewer_evidence,
)
from leviathan_core.agent_council.experiment_identity import derive_experiment_id
from leviathan_core.agent_council.leak_models import (
    CritiqueMetricsV1,
    CritiquePolicyV1,
    FeatureAsOfV1,
    LabelWindowV1,
    LeakDecisionV1,
    LeakEvidenceV1,
    MetricEvidenceV1,
    MetricThresholdV1,
    NamedMetricV1,
    SplitMembershipV1,
)
from leviathan_core.agent_council.leak_rules import evaluate_leaks
from leviathan_core.agent_council.publication_models import (
    MAX_PUBLICATION_TOTAL_BYTES,
    PublicationPlotV1,
    ScribeError,
    require_manifest,
    require_publication_result,
    require_summary_intent,
)
from leviathan_core.agent_council.runner_models import (
    CouncilRunCommandV1,
    CouncilRunEventV1,
    QueueReceiptV1,
    ReplayOutcomeV1,
    RunBudgetV1,
    RunStatusV1,
)
from leviathan_core.agent_council.runner_service import CouncilRunnerService
from leviathan_core.agent_council.scribe_service import (
    COUNCIL_VAULT_PREFIX,
    ScribePublicationService,
)
from leviathan_core.agent_council.state_machine import (
    new_council_state,
    propose_transition,
)
from leviathan_core.agent_council.state_models import (
    ActorAuthorityV1,
    CouncilEventV1,
    DatasetSnapshotRefV1,
    EvidenceClaimV1,
    ExperimentSpecV1,
    HypothesisV1,
    SignalRefV1,
    TimeWindowV1,
    issue_critic_evidence,
    issue_holdout_evidence,
)
from leviathan_core.numeric import canonical_json
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
REVISION_RESULT_DIGEST = "c" * 64
BASE_NS = 10_000_000_000
POLICY_START = datetime(1970, 1, 1, tzinfo=UTC)
POLICY_END = datetime(2500, 1, 1, tzinfo=UTC)
SIGNAL = SignalRefV1(signal_id="close-v1", version="1")
TRAIN = TimeWindowV1(start_ns=100, end_ns=200)
TEST = TimeWindowV1(start_ns=300, end_ns=400)
HOLDOUT = TimeWindowV1(start_ns=500, end_ns=600)


def hypothesis(
    *, strategy_name: str = "synthetic strategy", signal_version: str = "1"
) -> HypothesisV1:
    return HypothesisV1(
        hypothesis_id="hypothesis-1",
        version=1,
        strategy_name=strategy_name,
        signal_refs=(SignalRefV1(signal_id="close-v1", version=signal_version),),
        markets=("SYNTH",),
        horizon=TimeWindowV1(start_ns=1_000_000_000, end_ns=8_000_000_000),
        target_metrics=("sharpe_ratio",),
        max_leverage=Decimal("1"),
        max_loss_per_trade=Decimal("0.01"),
        seed_policy="fixed",
        seed=17,
        source_hashes=(HASH,),
    )


def snapshot() -> DatasetSnapshotRefV1:
    return DatasetSnapshotRefV1(
        snapshot_id="snapshot-1",
        version=1,
        content_hash=HASH,
        horizon=TimeWindowV1(start_ns=1, end_ns=1000),
    )


def experiment(*, signal_version: str = "1") -> ExperimentSpecV1:
    return ExperimentSpecV1(
        hypothesis_id="hypothesis-1",
        hypothesis_version=1,
        dataset=snapshot(),
        signal_refs=(SignalRefV1(signal_id="close-v1", version=signal_version),),
        engine_version="engine-v1",
        parameters_json='{"window":20}',
        seed=17,
        train_window=TRAIN,
        test_window=TEST,
        idempotency_key="run-1",
    )


def revision_digest(value: HypothesisV1) -> str:
    return hashlib.sha256(canonical_json(value.model_dump(mode="json"))).hexdigest()


def signal_digest(value: ExperimentSpecV1) -> str:
    refs = [item.model_dump(mode="json") for item in value.signal_refs]
    return hashlib.sha256(canonical_json(refs)).hexdigest()


def leak_evidence_for(
    command: CouncilRunCommandV1,
    run: ExperimentSpecV1,
    *,
    leaking: bool = False,
) -> LeakEvidenceV1:
    return LeakEvidenceV1(
        experiment_id=derive_experiment_id(run),
        revision_hash=revision_digest(command.hypothesis),
        snapshot_hash=run.dataset.content_hash,
        train_window=TRAIN,
        test_window=TEST,
        holdout_window=HOLDOUT,
        features=(
            FeatureAsOfV1(
                signal_id=SIGNAL.signal_id,
                sample_at_ns=150,
                available_at_ns=151 if leaking else 150,
                offset_ns=0,
            ),
        ),
        labels=(
            LabelWindowV1(
                sample_at_ns=190,
                label_start_ns=190,
                label_end_ns=200,
                split="train",
            ),
            LabelWindowV1(
                sample_at_ns=350,
                label_start_ns=350,
                label_end_ns=360,
                split="test",
            ),
            LabelWindowV1(
                sample_at_ns=550,
                label_start_ns=550,
                label_end_ns=560,
                split="holdout",
            ),
        ),
        normalization_fit_window=TimeWindowV1(start_ns=110, end_ns=190),
        split_memberships=(
            SplitMembershipV1(row_digest="1" * 64, split="train"),
            SplitMembershipV1(row_digest="2" * 64, split="test"),
            SplitMembershipV1(row_digest="3" * 64, split="holdout"),
        ),
        engine_version=run.engine_version,
        holdout_used_for_training=False,
    )


def metric_policy() -> CritiquePolicyV1:
    return CritiquePolicyV1(
        version="scribe-critic-v1",
        thresholds=(
            MetricThresholdV1(
                name="sharpe_ratio", comparison="gte", threshold=Decimal("1")
            ),
        ),
        minimum_completed_runs=1,
        max_input_rows=100,
        max_runs=10,
        max_metrics=5,
        max_evaluation_cost_usd=Decimal("100"),
        max_elapsed_ns=1_000_000_000,
        max_compute_units=100_000,
    )


class _RunQueue:
    def __init__(self) -> None:
        self.receipt: QueueReceiptV1 | None = None
        self.commands: dict[str, CouncilRunCommandV1] = {}

    def find_by_idempotency_key(
        self, key: str, owner_principal_id: str, owner_project_id: str
    ) -> QueueReceiptV1 | None:
        receipt = self.receipt
        if receipt is None or (key, owner_principal_id, owner_project_id) != (
            self.commands[receipt.session_id].idempotency_key,
            receipt.owner_principal_id,
            receipt.owner_project_id,
        ):
            return None
        return receipt

    def find_by_hypothesis_digest(
        self, digest: str, owner_principal_id: str, owner_project_id: str
    ) -> QueueReceiptV1 | None:
        receipt = self.receipt
        if receipt is None or (
            digest,
            owner_principal_id,
            owner_project_id,
        ) != (
            receipt.hypothesis_digest,
            receipt.owner_principal_id,
            receipt.owner_project_id,
        ):
            return None
        return receipt

    def enqueue(
        self,
        key: str,
        digest: str,
        hypothesis_digest: str,
        owner_principal_id: str,
        owner_project_id: str,
        command: CouncilRunCommandV1,
    ) -> QueueReceiptV1:
        receipt = QueueReceiptV1(
            session_id="session-scribe-1",
            command_digest=digest,
            hypothesis_digest=hypothesis_digest,
            owner_principal_id=owner_principal_id,
            owner_project_id=owner_project_id,
            created=True,
        )
        self.receipt = receipt
        self.commands[receipt.session_id] = command
        return receipt

    def get_command(self, session_id: str) -> CouncilRunCommandV1 | None:
        return self.commands.get(session_id)


class _RunState:
    def __init__(self) -> None:
        self.statuses: dict[str, RunStatusV1] = {}
        self.outcomes: dict[str, list[ReplayOutcomeV1]] = {}
        self.leaks: dict[str, dict[str, LeakDecisionV1]] = {}

    def get_status(self, session_id: str) -> RunStatusV1 | None:
        return self.statuses.get(session_id)

    def compare_and_set_status(
        self, expected: RunStatusV1 | None, value: RunStatusV1
    ) -> bool:
        current = self.statuses.get(value.session_id)
        if current != expected:
            return False
        self.statuses[value.session_id] = value
        return True

    def get_outcomes(self, session_id: str) -> tuple[ReplayOutcomeV1, ...]:
        return tuple(self.outcomes.get(session_id, ()))

    def append_outcome(self, session_id: str, outcome: ReplayOutcomeV1) -> bool:
        records = self.outcomes.setdefault(session_id, [])
        if any(item.run_id == outcome.run_id for item in records):
            return any(item.run_id == outcome.run_id and item == outcome for item in records)
        records.append(outcome)
        return True

    def get_leaks(self, session_id: str) -> tuple[LeakDecisionV1, ...]:
        return tuple(self.leaks.get(session_id, {}).values())

    def get_leak(self, session_id: str, run_id: str) -> LeakDecisionV1 | None:
        return self.leaks.get(session_id, {}).get(run_id)

    def append_leak(self, session_id: str, run_id: str, leak: LeakDecisionV1) -> bool:
        entries = self.leaks.setdefault(session_id, {})
        if run_id in entries:
            return entries[run_id] == leak
        entries[run_id] = leak
        return True


class _EventStore:
    def __init__(self) -> None:
        self.events: list[CouncilRunEventV1] = []

    def last_sequence(self, session_id: str) -> int:
        return max(
            (event.sequence for event in self.events if event.session_id == session_id),
            default=0,
        )

    def append(self, event: CouncilRunEventV1) -> bool:
        if event.sequence != self.last_sequence(event.session_id) + 1:
            return False
        self.events.append(event)
        return True


class _EventStream:
    def __init__(self) -> None:
        self.events: list[CouncilRunEventV1] = []

    def publish(self, event: CouncilRunEventV1) -> None:
        self.events.append(event)


class _Clock:
    def __init__(self, now_ns: int = 100) -> None:
        self.value = now_ns

    def now_ns(self) -> int:
        return self.value

    def monotonic_ns(self) -> int:
        self.value += 1
        return self.value


class _RunnerReplay:
    def __init__(self) -> None:
        self.calls = 0

    def execute(
        self, run: ExperimentSpecV1, command: CouncilRunCommandV1
    ) -> ReplayOutcomeV1:
        self.calls += 1
        result_digest = REVISION_RESULT_DIGEST
        metric = MetricEvidenceV1(
            experiment_id=derive_experiment_id(run),
            run_id=run.idempotency_key,
            author_id=command.actor_id,
            revision_hash=revision_digest(command.hypothesis),
            result_digest=result_digest,
            status="completed",
            critique_metrics=CritiqueMetricsV1(
                version="1",
                metrics=(NamedMetricV1(name="sharpe_ratio", value=Decimal("2")),),
            ),
            risk_flags=(),
            cost_usd=Decimal("0.25"),
            elapsed_ns=5,
            compute_units=1,
        )
        return issue_fixture_replay_outcome(
            experiment_id=derive_experiment_id(run),
            run_id=run.idempotency_key,
            result_digest=result_digest,
            snapshot_hash=run.dataset.content_hash,
            signals_digest=signal_digest(run),
            engine_version=run.engine_version,
            seed=run.seed,
            outcome="COMPLETED",
            cost_usd=Decimal("0.25"),
            elapsed_ns=5,
            compute_units=1,
            artifact_refs=(),
            input_rows=3,
            metrics=(metric,),
            reason=None,
        )

    def cancel(self, _session_id: str):
        raise AssertionError("publication fixture must not cancel runner work")


class _LeakGate:
    def __init__(self, command: CouncilRunCommandV1) -> None:
        self.command = command
        self.decision: LeakDecisionV1 | None = None

    def evaluate(self, _outcome: ReplayOutcomeV1) -> LeakDecisionV1:
        self.decision = evaluate_leaks(
            leak_evidence_for(self.command, self.command.experiments[0])
        )
        return self.decision


class _CriticGate:
    def __init__(self) -> None:
        self.decision = None

    def evaluate(self, outcomes, leaks):
        leak = leaks[-1]
        metric_evidence = tuple(metric for item in outcomes for metric in item.metrics)
        self.decision = evaluate_critique(
            metric_policy(), metric_evidence, leak, input_rows=leak.input_rows
        )
        return self.decision


def _trusted_principal(principal_id: str, roles: tuple[str, ...]) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id=principal_id,
        project_id="leviathan-ai",
        roles=roles,
        env="development",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=_VERIFIER_MARKER
    )


def _authorization_policy(
    actions: tuple[str, ...], roles: tuple[str, ...], *, project_id: str = "leviathan-ai"
) -> AuthorizationPolicyV1:
    return AuthorizationPolicyV1(
        version="v1",
        project_id=project_id,
        expires_at=POLICY_END,
        rules=(
            PolicyRuleV1(
                rule_id="acceptance-allow",
                effect=EffectV1.ALLOW,
                roles=roles,
                actions=actions,
                resources=("*",),
                env="development",
                not_before=POLICY_START,
                not_after=POLICY_END,
            ),
        ),
    )


def _approved_state(
    run_command: CouncilRunCommandV1,
    outcome: ReplayOutcomeV1,
    *,
    session_id: str = "session-scribe-1",
):
    researcher = ActorAuthorityV1(actor_id="author", kind="human", roles=("researcher",))
    operator = ActorAuthorityV1(actor_id="operator", kind="agent", roles=("operator",))
    reviewer_actor = ActorAuthorityV1(actor_id="reviewer-1", kind="human", roles=("reviewer",))
    actors = {item.actor_id: item for item in (researcher, operator, reviewer_actor)}
    state = new_council_state(
        run_command.hypothesis,
        session_id=session_id,
        hypothesis_author_id=run_command.actor_id,
        now_ns=BASE_NS,
        max_iterations=2,
        max_actions=12,
        max_runtime_ns=5_000_000_000,
        max_cost_usd=Decimal("5"),
        max_no_progress_events=2,
    )

    def advance(sequence: int, event_type: str, actor_id: str, **fields: object):
        event = CouncilEventV1.model_validate(
            {
                "session_id": state.session_id,
                "sequence": sequence,
                "event_type": event_type,
                "actor_id": actor_id,
                "at_ns": BASE_NS + sequence,
                **fields,
            }
        )
        return propose_transition(
            state,
            event,
            now_ns=BASE_NS + sequence,
            authorize_actor=actors.get,
        )

    state = advance(1, "start_research", "author").proposed_state
    state = advance(
        2,
        "request_experiment",
        "author",
        experiment_id=outcome.experiment_id,
    ).proposed_state
    state = advance(
        3,
        "experiment_completed",
        "operator",
        experiment_id=outcome.experiment_id,
        result_digest=outcome.result_digest,
    ).proposed_state
    state = advance(4, "request_critique", "author").proposed_state
    verifier = _EvidenceVerifier()
    claim = EvidenceClaimV1(
        experiment_id=state.current_experiment_id,
        revision_content_hash=state.revision_content_hash,
        result_digest=state.current_result_digest,
        evidence_digest="e" * 64,
    )
    approval_event = CouncilEventV1.model_validate(
        {
            "session_id": state.session_id,
            "sequence": 5,
            "event_type": "approve",
            "actor_id": "reviewer-1",
            "at_ns": BASE_NS + 5,
            "leak_checks_passed": True,
            "thresholds_passed": True,
            "critic_evidence_ref": "sha256:acceptance-critic",
            "holdout_evidence_ref": "sha256:acceptance-holdout",
        }
    )
    return propose_transition(
        state,
        approval_event,
        now_ns=BASE_NS + 5,
        authorize_actor=actors.get,
        evidence_verifier=verifier,
        critic_evidence=issue_critic_evidence(claim, verifier),
        holdout_evidence=issue_holdout_evidence(claim, verifier),
    ).proposed_state


class _EvidenceVerifier:
    def verify_critic(self, _claim: EvidenceClaimV1) -> bool:
        return True

    def verify_holdout(self, _claim: EvidenceClaimV1) -> bool:
        return True


def _runner_fixture(
    *,
    strategy_name: str = "synthetic strategy",
    state_session_id: str = "session-scribe-1",
    signal_version: str = "1",
):
    run_hypothesis = hypothesis(strategy_name=strategy_name, signal_version=signal_version)
    run_snapshot = snapshot()
    run = experiment(signal_version=signal_version)
    run_command = CouncilRunCommandV1(
        idempotency_key="command-scribe-1",
        actor_id="author",
        hypothesis=run_hypothesis,
        snapshot=run_snapshot,
        experiments=(run,),
        seed=17,
        calendar_id="synthetic-calendar-v1",
        slippage_model_id="synthetic-slippage-v1",
        latency_model_id="synthetic-latency-v1",
        budget=RunBudgetV1(
            max_runs=1,
            min_successful_runs=1,
            max_actions=5,
            max_elapsed_ns=1_000_000_000,
            max_compute_units=100,
            max_cost_usd=Decimal("5"),
            max_data_gap_retries=0,
        ),
    )
    state_port = _RunState()
    queue = _RunQueue()
    event_store = _EventStore()
    stream = _EventStream()
    replay = _RunnerReplay()
    leak_gate = _LeakGate(run_command)
    critic_gate = _CriticGate()
    runner_principal = _trusted_principal("author", ("runner.researcher",))
    runner_policy = _authorization_policy(
        ("agent.run.enqueue", "agent.run.advance"), ("runner.researcher",)
    )
    runner = CouncilRunnerService(
        authorization_policy=runner_policy,
        service_principal=runner_principal,
        queue=queue,
        state=state_port,
        event_store=event_store,
        event_stream=stream,
        replay=replay,
        leak_gate=leak_gate,
        critic_gate=critic_gate,
        clock=_Clock(),
    )
    queued = runner.enqueue(run_command, runner_principal)
    terminal = runner.run_until_terminal(queued.session_id)
    assert terminal.status == "COMPLETED"
    assert replay.calls == 1
    outcomes = state_port.get_outcomes(queued.session_id)
    assert len(outcomes) == 1
    assert leak_gate.decision is not None
    assert critic_gate.decision is not None
    approved = _approved_state(run_command, outcomes[0], session_id=state_session_id)
    assert approved.status == "approved"
    return approved, outcomes, leak_gate.decision, critic_gate.decision, run_command


class _VaultPort:
    vault_id = "vault-acceptance"
    allowed_prefix = COUNCIL_VAULT_PREFIX

    def __init__(self, root: Path) -> None:
        self.root = root
        self.create_attempts: list[tuple[str, bytes]] = []
        self.offline_remaining = 0
        self.offline_after_successful_creates: int | None = None
        self.successful_creates = 0
        self.retry_delays: list[int] = []
        self.corrupt_after_create = False

    def _path(self, path: str) -> Path:
        if not path.startswith(self.allowed_prefix):
            raise ValueError("out of fake-vault scope")
        pieces = path[len(self.allowed_prefix) :].split("/")
        if not pieces or any(part in {"", ".", ".."} for part in pieces):
            raise ValueError("invalid fake-vault path")
        root = self.root.resolve()
        target = self.root.joinpath(*pieces).resolve()
        if not target.is_relative_to(root):
            raise ValueError("fake-vault symlink escaped its root")
        return target

    def read(self, path: str) -> bytes | None:
        target = self._path(path)
        if not target.exists():
            return None
        content = target.read_bytes()
        return b"corrupt-readback" if self.corrupt_after_create else content

    def create_no_overwrite(self, path: str, content: bytes) -> str:
        self.create_attempts.append((path, content))
        if self.offline_remaining:
            self.offline_remaining -= 1
            return "OFFLINE"
        if (
            self.offline_after_successful_creates is not None
            and self.successful_creates >= self.offline_after_successful_creates
        ):
            return "OFFLINE"
        target = self._path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with target.open("xb") as handle:
                handle.write(content)
        except FileExistsError:
            return "EXISTS"
        self.successful_creates += 1
        if self.corrupt_after_create:
            target.write_bytes(b"corrupt-readback")
        return "CREATED"

    def wait_before_retry(self, delay_ns: int) -> None:
        self.retry_delays.append(delay_ns)

    def bytes_by_relative_path(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.root).as_posix(): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }


def _service(
    root: Path,
    *,
    vault: _VaultPort | None = None,
    chain_result: object = True,
    now_ns: int = BASE_NS + 1000,
    actions: tuple[str, ...] = (
        "council.publication.review",
        "council.publication.publish",
    ),
) -> tuple[ScribePublicationService, _VaultPort]:
    port = vault or _VaultPort(root)
    policy = _authorization_policy(actions, ("reviewer", "scribe"))
    service = ScribePublicationService(
        port,
        policy,
        _Clock(now_ns),
        lambda _session_id, _digest: chain_result,
    )
    return service, port


def _publish_inputs(
    *,
    strategy_name: str = "synthetic strategy",
    state_session_id: str = "session-scribe-1",
    signal_version: str = "1",
):
    return _runner_fixture(
        strategy_name=strategy_name,
        state_session_id=state_session_id,
        signal_version=signal_version,
    )


def _plots() -> tuple[PublicationPlotV1, ...]:
    return (
        PublicationPlotV1(
            name="performance",
            media_type="image/png",
            content=_minimal_png(),
        ),
    )


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    chunk_data = kind + payload
    return (
        struct.pack(">I", len(payload))
        + chunk_data
        + struct.pack(">I", zlib.crc32(chunk_data) & 0xFFFFFFFF)
    )


def _minimal_png() -> bytes:
    header = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    image_data = zlib.compress(b"\x00\x00\x00\x00\xff")
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", image_data)
        + _png_chunk(b"IEND", b"")
    )


def _trusted_scribe_pair():
    return (
        _trusted_principal("reviewer-1", ("reviewer",)),
        _trusted_principal("scribe-1", ("scribe",)),
    )


def _publish(service: ScribePublicationService, inputs, **overrides):
    state, outcomes, leak, critique, *_ = inputs
    reviewer, publisher = _trusted_scribe_pair()
    values = {
        "state": state,
        "outcomes": outcomes,
        "leak_decision": leak,
        "critique_decision": critique,
        "plots": _plots(),
        "reviewer": reviewer,
        "publisher": publisher,
    }
    values.update(overrides)
    return service.publish(**values)


def test_success_requires_trusted_inputs_and_readback_for_every_publication_file(
    tmp_path: Path,
) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path)

    result = _publish(service, inputs)

    assert require_publication_result(result).status == "synced"
    manifest = require_manifest(result.manifest)
    intent = require_summary_intent(result.summary_intent)
    assert manifest.session_id == inputs[0].session_id
    assert manifest.vault_id == vault.vault_id
    assert manifest.reviewer_id is None
    assert manifest.review_basis == "CRITIC_PASS"
    assert manifest.publisher_id == "scribe-1"
    assert manifest.state_semantic_hash == inputs[0].revision_content_hash
    assert manifest.hypothesis_revision_hash == revision_digest(inputs[4].hypothesis)
    assert intent.idempotency_key == f"council-publication:{manifest.session_id}"
    assert intent.path == manifest.path
    records = {item.path: item for item in manifest.files}
    assert {
        "TLDR.md",
        "hypothesis.md",
        "critique.md",
        "metrics.json",
        "checksums.json",
        "artifacts/plot-0001.png",
    } <= records.keys()
    persisted = vault.bytes_by_relative_path()
    metrics_bytes = persisted[f"{manifest.session_id}/metrics.json"]
    metric_rows = json.loads(metrics_bytes)["runs"]
    assert len(metric_rows) == len(inputs[1])
    assert [row["run_index"] for row in metric_rows] == list(
        range(1, len(inputs[1]) + 1)
    )
    assert all("run_id" not in row for row in metric_rows)
    assert all("run_id_sha256" not in row for row in metric_rows)
    assert all(
        outcome.run_id.encode("utf-8") not in metrics_bytes
        for outcome in inputs[1]
    )
    assert all(path.startswith(f"{manifest.session_id}/") for path in persisted)
    for relative, record in records.items():
        content = persisted[f"{manifest.session_id}/{relative}"]
        assert len(content) == record.size_bytes
        assert hashlib.sha256(content).hexdigest() == record.sha256
    checksums = json.loads(persisted[f"{manifest.session_id}/checksums.json"])
    assert {item["path"] for item in checksums["files"]} == records.keys() - {
        "checksums.json"
    }


def test_credential_looking_signal_version_is_not_published_or_hashed(
    tmp_path: Path,
) -> None:
    signal_version = "sk_live_CANARYTOKEN0123456789"
    inputs = _publish_inputs(signal_version=signal_version)
    service, vault = _service(tmp_path)

    result = _publish(service, inputs)

    manifest = require_manifest(result.manifest)
    files = vault.bytes_by_relative_path()
    all_output = result.model_dump_json() + manifest.model_dump_json()
    all_output += "".join(content.decode("latin1") for content in files.values())
    assert signal_version not in all_output
    assert hashlib.sha256(signal_version.encode("utf-8")).hexdigest() not in all_output


def test_path_bearing_signal_version_is_denied_before_vault_write(
    tmp_path: Path,
) -> None:
    signal_version = "../private-CANARY"
    inputs = _publish_inputs(signal_version=signal_version)
    service, vault = _service(tmp_path)

    with pytest.raises(ScribeError) as denied:
        _publish(service, inputs)

    assert denied.value.code == "PUBLICATION_INPUT_INVALID"
    assert signal_version not in str(denied.value)
    assert denied.value.__cause__ is None
    assert denied.value.__context__ is None
    assert vault.create_attempts == []

@pytest.mark.parametrize(
    "secret",
    [
        "postgresql://admin:CANARY_DBPASS@db.internal:5432/prod",
        "sk_live_CANARYKEY0123456789abcdef",
        "ghp_CANARY0123456789abcdef0123456789",
        "xoxb-123456789012-1234567890123-CANARYTOKEN",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDQU5BUlkifQ.SIGNATURECANARY",
        "Authorization header Bearer CANARYTOKEN0123456789",
        "the password is CANARY_TEXT_SECRET",
        "https://db.internal/?api_key=CANARY_QUERY_SECRET",
        "password=CANARY_ASSIGNMENT_SECRET",
    ],
)
def test_strategy_secret_formats_are_absent_from_every_publication_output(
    tmp_path: Path, secret: str
) -> None:
    long_strategy_text = f"Research strategy notes include {secret}; " + (
        "synthetic narrative " * 16
    )
    inputs = _publish_inputs(strategy_name=long_strategy_text)
    service, vault = _service(tmp_path)

    result = _publish(service, inputs)

    manifest = require_manifest(result.manifest)
    published = vault.bytes_by_relative_path()
    serialized_outputs = (
        result.model_dump_json().encode(),
        manifest.model_dump_json().encode(),
        *published.values(),
    )
    secret_bytes = secret.encode()
    assert all(secret_bytes not in content for content in serialized_outputs)
    assert result.status == "synced"


def test_plain_critic_pass_does_not_require_or_record_a_reviewer(tmp_path: Path) -> None:
    inputs = _publish_inputs()
    service, _vault = _service(tmp_path)

    result = _publish(service, inputs, reviewer=None)

    manifest = require_manifest(result.manifest)
    assert result.status == "synced"
    assert manifest.reviewer_id is None
    assert manifest.review_basis == "CRITIC_PASS"


def test_existing_identical_publication_is_never_overwritten_and_intent_is_stable(
    tmp_path: Path,
) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path)

    first = _publish(service, inputs)
    before = vault.bytes_by_relative_path()
    first_intent = require_summary_intent(first.summary_intent)
    first_attempts = len(vault.create_attempts)
    second = _publish(service, inputs)

    assert second.status == "synced"
    assert require_manifest(second.manifest).path == require_manifest(first.manifest).path
    assert vault.bytes_by_relative_path() == before
    assert len(vault.create_attempts) > first_attempts
    second_intent = require_summary_intent(second.summary_intent)
    assert second_intent.idempotency_key == first_intent.idempotency_key
    assert second_intent.publication_digest == first_intent.publication_digest


def test_approved_state_can_publish_after_council_deadline(tmp_path: Path) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path, now_ns=inputs[0].deadline_ns + 1)

    result = _publish(service, inputs)

    assert result.status == "synced"
    assert require_manifest(result.manifest).session_id == inputs[0].session_id
    assert vault.create_attempts


def test_conflict_gets_bounded_suffix_and_an_explicit_preserving_record(
    tmp_path: Path,
) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path)
    base = f"{COUNCIL_VAULT_PREFIX}{inputs[0].session_id}"
    requested = f"{base}/TLDR.md"
    occupied = b"pre-existing-authoritative-publication"
    target = vault._path(requested)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(occupied)

    result = _publish(service, inputs)

    manifest = require_manifest(result.manifest)
    assert manifest.path == f"{base}-1"
    assert target.read_bytes() == occupied
    assert len(manifest.conflicts) == 1
    conflict = manifest.conflicts[0]
    assert conflict.requested_path == requested
    assert conflict.published_path == f"{manifest.path}/TLDR.md"
    assert conflict.existing_sha256 == hashlib.sha256(occupied).hexdigest()
    assert conflict.requested_sha256 == hashlib.sha256(
        vault.bytes_by_relative_path()[
            f"{manifest.path.rsplit('/', 1)[-1]}/TLDR.md"
        ]
    ).hexdigest()


@pytest.mark.parametrize("wrong_role", ["researcher", "reviewer"])
def test_missing_trusted_publish_authority_denies_before_any_vault_write(
    tmp_path: Path, wrong_role: str
) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path)
    reviewer, _publisher = _trusted_scribe_pair()
    wrong_publisher = _trusted_principal("wrong-publisher", (wrong_role,))

    with pytest.raises(ScribeError) as denied:
        _publish(service, inputs, reviewer=reviewer, publisher=wrong_publisher)

    assert denied.value.code == "AUTHORIZATION_DENIED"
    assert vault.create_attempts == []

def test_policy_denial_is_content_free_and_happens_before_vault_mutation(
    tmp_path: Path,
) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path, actions=("council.publication.review",))
    canary = "publish-policy-canary-secret-9813"

    with pytest.raises(ScribeError) as denied:
        _publish(service, inputs, reviewer=_trusted_principal(canary, ("reviewer",)))

    assert denied.value.code == "AUTHORIZATION_DENIED"
    assert canary not in str(denied.value)
    assert denied.value.__context__ is None
    assert vault.create_attempts == []


def test_state_chain_verifier_requires_literal_true_and_denies_without_writes(
    tmp_path: Path,
) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path, chain_result=1)

    with pytest.raises(ScribeError) as denied:
        _publish(service, inputs)

    assert denied.value.code == "STATE_UNTRUSTED"
    assert denied.value.__context__ is None
    assert vault.create_attempts == []


def test_invalid_vault_scope_is_rejected_at_service_construction(tmp_path: Path) -> None:
    vault = _VaultPort(tmp_path)
    vault.allowed_prefix = "/Leviathan/Other/"

    with pytest.raises(ScribeError) as invalid:
        _service(tmp_path, vault=vault)

    assert invalid.value.code == "VAULT_SCOPE_INVALID"
    assert vault.create_attempts == []


def test_failed_leak_gate_blocks_publication_even_with_replay_and_critic_evidence(
    tmp_path: Path,
) -> None:
    inputs = _publish_inputs()
    run_command = inputs[4]
    failed_leak = evaluate_leaks(
        leak_evidence_for(run_command, run_command.experiments[0], leaking=True)
    )
    service, vault = _service(tmp_path)

    with pytest.raises(ScribeError) as denied:
        _publish(service, inputs, leak_decision=failed_leak)

    assert denied.value.code == "PUBLICATION_GATE_DENIED"
    assert vault.create_attempts == []


def test_metric_only_failure_needs_a_separate_trusted_reviewer_exception(
    tmp_path: Path,
) -> None:
    inputs = _publish_inputs()
    state, outcomes, leak, _passing_critique, _command = inputs
    policy = CritiquePolicyV1(
        version="exception-policy-v1",
        thresholds=(
            MetricThresholdV1(
                name="sharpe_ratio", comparison="gte", threshold=Decimal("3")
            ),
        ),
        minimum_completed_runs=1,
        max_input_rows=100,
        max_runs=10,
        max_metrics=5,
        max_evaluation_cost_usd=Decimal("100"),
        max_elapsed_ns=1_000_000_000,
        max_compute_units=100_000,
    )

    class _ReviewerVerifier:
        def verify(self, _claim) -> bool:
            return True

    claim = ReviewerEvidenceClaimV1(
        experiment_id=leak.experiment_id,
        revision_hash=leak.revision_hash,
        author_id=state.hypothesis_author_id,
        reviewer_id="reviewer-1",
        metric_names=("sharpe_ratio",),
        policy_digest=critique_policy_digest(policy),
        reason="Synthetic independent publication exception.",
    )
    reviewer_evidence = issue_reviewer_evidence(claim, _ReviewerVerifier())
    exception_decision = evaluate_critique(
        policy,
        outcomes[0].metrics,
        leak,
        input_rows=leak.input_rows,
        reviewer_evidence=reviewer_evidence,
    )
    assert exception_decision.status == "METRIC_FAILURE"
    assert exception_decision.passed is False
    assert exception_decision.publication_exception is not None
    service, vault = _service(tmp_path)

    result = _publish(service, inputs, critique_decision=exception_decision)

    assert result.status == "synced"
    manifest = require_manifest(result.manifest)
    assert manifest.reviewer_id == "reviewer-1"
    assert manifest.review_basis == "METRIC_EXCEPTION"
    assert vault.create_attempts


def test_metric_exception_cannot_be_reused_by_another_reviewer(tmp_path: Path) -> None:
    inputs = _publish_inputs()
    state, outcomes, leak, _passing_critique, _command = inputs
    policy = CritiquePolicyV1(
        version="exception-policy-v1",
        thresholds=(
            MetricThresholdV1(
                name="sharpe_ratio", comparison="gte", threshold=Decimal("3")
            ),
        ),
        minimum_completed_runs=1,
        max_input_rows=100,
        max_runs=10,
        max_metrics=5,
        max_evaluation_cost_usd=Decimal("100"),
        max_elapsed_ns=1_000_000_000,
        max_compute_units=100_000,
    )

    class _ReviewerVerifier:
        def verify(self, _claim) -> bool:
            return True

    claim = ReviewerEvidenceClaimV1(
        experiment_id=leak.experiment_id,
        revision_hash=leak.revision_hash,
        author_id=state.hypothesis_author_id,
        reviewer_id="reviewer-1",
        metric_names=("sharpe_ratio",),
        policy_digest=critique_policy_digest(policy),
        reason="Synthetic independent publication exception.",
    )
    reviewer_evidence = issue_reviewer_evidence(claim, _ReviewerVerifier())
    exception_decision = evaluate_critique(
        policy,
        outcomes[0].metrics,
        leak,
        input_rows=leak.input_rows,
        reviewer_evidence=reviewer_evidence,
    )
    service, vault = _service(tmp_path)
    other_reviewer = _trusted_principal("reviewer-2", ("reviewer",))

    with pytest.raises(ScribeError) as denied:
        _publish(service, inputs, critique_decision=exception_decision, reviewer=other_reviewer)

    assert denied.value.code == "PUBLICATION_GATE_DENIED"
    assert vault.create_attempts == []


def test_plot_name_is_not_published_and_uses_generated_png_path(tmp_path: Path) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path)
    canary = "plot-canary-secret-9813"
    plot = PublicationPlotV1(
        name=canary,
        media_type="image/png",
        content=_minimal_png(),
    )

    result = _publish(service, inputs, plots=(plot,))

    manifest = require_manifest(result.manifest)
    plot_record = next(
        item for item in manifest.files if item.path == "artifacts/plot-0001.png"
    )
    published = vault.bytes_by_relative_path()
    all_output = result.model_dump_json() + manifest.model_dump_json()
    all_output += "".join(content.decode("latin1") for content in published.values())
    assert canary not in all_output
    assert published[f"{manifest.session_id}/{plot_record.path}"] == _minimal_png()

@pytest.mark.parametrize(
    "svg",
    [
        b"<svg><script>alert(1)</script></svg>",
        b'<svg><image xlink:href="https://attacker.example/pixel.png"/></svg>',
        b'<svg onload="fetch(1)"></svg>',
    ],
)
def test_active_or_external_svg_is_rejected_before_any_vault_write(
    tmp_path: Path, svg: bytes
) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path)

    with pytest.raises(ScribeError) as rejected:
        plot = PublicationPlotV1(name="unsafe-svg", media_type="image/svg+xml", content=svg)
        _publish(service, inputs, plots=(plot,))

    assert rejected.value.code == "PUBLICATION_MODEL_INVALID"
    assert vault.create_attempts == []


@pytest.mark.parametrize(
    "png",
    [
        b"<html><script>alert(1)</script></html>",
        b"x",
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", b"\x00" * 8)
        + _png_chunk(b"IEND", b""),
        _minimal_png()[:-1] + bytes([_minimal_png()[-1] ^ 0x01]),
    ],
    ids=("html-disguised", "one-byte", "malformed-ihdr", "malformed-crc"),
)
def test_malformed_or_disguised_png_is_rejected_before_any_vault_write(
    tmp_path: Path, png: bytes
) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path)
    plot = PublicationPlotV1(name="invalid-png", media_type="image/png", content=png)

    with pytest.raises(ScribeError) as rejected:
        _publish(service, inputs, plots=(plot,))

    assert rejected.value.code == "PUBLICATION_INPUT_INVALID"
    assert vault.create_attempts == []


def test_structurally_valid_minimal_png_is_published_and_verified(tmp_path: Path) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path)
    png = _minimal_png()
    plot = PublicationPlotV1(name="minimal", media_type="image/png", content=png)

    result = _publish(service, inputs, plots=(plot,))

    manifest = require_manifest(result.manifest)
    record = next(item for item in manifest.files if item.path == "artifacts/plot-0001.png")
    assert result.status == "synced"
    assert record.size_bytes == len(png)
    assert record.sha256 == hashlib.sha256(png).hexdigest()
    assert vault.bytes_by_relative_path()[f"{manifest.session_id}/artifacts/plot-0001.png"] == png


def test_readback_mismatch_returns_error_without_manifest_or_summary_intent(
    tmp_path: Path,
) -> None:
    inputs = _publish_inputs()
    vault = _VaultPort(tmp_path)
    vault.corrupt_after_create = True
    service, _ = _service(tmp_path, vault=vault)

    result = _publish(service, inputs)

    assert require_publication_result(result).status == "error"
    assert result.error_code == "VAULT_POSTCONDITION_FAILED"
    assert result.manifest is None
    assert result.summary_intent is None
    assert result.attempts == 1
    assert len(vault.create_attempts) == 1


def test_offline_retries_use_fixed_backoff_and_are_bounded(tmp_path: Path) -> None:
    inputs = _publish_inputs()
    vault = _VaultPort(tmp_path)
    vault.offline_remaining = 3
    service, _ = _service(tmp_path, vault=vault)

    result = _publish(service, inputs)

    assert require_publication_result(result).status == "synced"
    assert result.attempts == 4
    assert vault.retry_delays == [10_000_000, 20_000_000, 40_000_000]
    assert len(vault.create_attempts) >= 4


def test_persistently_offline_vault_returns_error_after_four_attempts(
    tmp_path: Path,
) -> None:
    inputs = _publish_inputs()
    vault = _VaultPort(tmp_path)
    vault.offline_remaining = 99
    service, _ = _service(tmp_path, vault=vault)

    result = _publish(service, inputs)

    assert require_publication_result(result).status == "error"
    assert result.error_code == "VAULT_UNAVAILABLE"
    assert result.manifest is None
    assert result.summary_intent is None
    assert result.attempts == 4
    assert len(vault.create_attempts) == 4
    assert vault.retry_delays == [10_000_000, 20_000_000, 40_000_000]


def test_checksums_are_last_and_absent_when_outage_precedes_final_create(
    tmp_path: Path,
) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path / "complete")

    result = _publish(service, inputs)

    assert result.status == "synced"
    assert vault.create_attempts[-1][0].endswith("/checksums.json")

    partial_inputs = _publish_inputs()
    outage_root = tmp_path / "outage"
    outage_vault = _VaultPort(outage_root)
    outage_vault.offline_after_successful_creates = 4
    outage_service, _ = _service(outage_root, vault=outage_vault)

    partial = _publish(outage_service, partial_inputs)

    assert partial.status == "error"
    assert partial.error_code == "VAULT_UNAVAILABLE"
    assert partial.manifest is None
    assert partial.summary_intent is None
    assert not any(
        path.endswith("/checksums.json")
        for path, _content in outage_vault.create_attempts
    )
    assert not any(
        path.endswith("/checksums.json")
        for path in outage_vault.bytes_by_relative_path()
    )


def test_total_payload_over_200_mib_is_rejected_before_any_write(tmp_path: Path) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path)
    large_plot = b"x" * (24 * 1024 * 1024)
    plots = tuple(
        PublicationPlotV1(
            name=f"plot-{index}", media_type="image/png", content=large_plot
        )
        for index in range(9)
    )

    with pytest.raises(ScribeError) as too_large:
        _publish(service, inputs, plots=plots)

    assert too_large.value.code == "PUBLICATION_TOO_LARGE"
    assert too_large.value.http_status == 413
    assert vault.create_attempts == []
    assert MAX_PUBLICATION_TOTAL_BYTES == 200 * 1024 * 1024


def test_single_plot_over_25_mib_returns_413_before_any_write(tmp_path: Path) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path)
    oversized = PublicationPlotV1(
        name="oversized",
        media_type="image/png",
        content=b"x" * (25 * 1024 * 1024 + 1),
    )

    with pytest.raises(ScribeError) as too_large:
        _publish(service, inputs, plots=(oversized,))

    assert too_large.value.code == "PUBLICATION_TOO_LARGE"
    assert too_large.value.http_status == 413
    assert vault.create_attempts == []


def test_tampered_path_component_is_rejected_before_vault_access(tmp_path: Path) -> None:
    inputs = _publish_inputs()
    state = inputs[0]
    object.__setattr__(state, "session_id", "../outside")
    service, vault = _service(tmp_path)

    with pytest.raises(ScribeError) as denied:
        _publish(service, inputs)

    assert denied.value.code == "PUBLICATION_INPUT_INVALID"
    assert vault.create_attempts == []
    assert not (tmp_path.parent / "outside").exists()


@pytest.mark.parametrize("session_id", ["CON", "NUL", "AUX", "COM1", "LPT1", "PRN", "session."])
def test_windows_alias_session_components_are_rejected_before_vault_access(
    tmp_path: Path, session_id: str
) -> None:
    inputs = _publish_inputs(state_session_id=session_id)
    service, vault = _service(tmp_path)

    with pytest.raises(ScribeError) as rejected:
        _publish(service, inputs)

    assert rejected.value.code == "PUBLICATION_INPUT_INVALID"
    assert vault.create_attempts == []


def test_scoped_vault_rejects_symlink_escape_without_external_file_creation(
    tmp_path: Path,
) -> None:
    inputs = _publish_inputs()
    vault_root = tmp_path / "vault"
    outside = tmp_path / "outside"
    outside.mkdir()
    symlink_target = vault_root / "Leviathan" / "Council" / inputs[0].session_id
    symlink_target.parent.mkdir(parents=True)
    try:
        symlink_target.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {type(error).__name__}")
    service, vault = _service(vault_root)

    with pytest.raises(ScribeError) as denied:
        _publish(service, inputs)

    assert denied.value.code == "VAULT_UNAVAILABLE"
    assert vault.create_attempts == []
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("name", ["CON", "NUL", "AUX", "COM1", "LPT1", "PRN", "plot."])
def test_windows_alias_plot_components_are_rejected_before_vault_access(
    tmp_path: Path, name: str
) -> None:
    inputs = _publish_inputs()
    service, vault = _service(tmp_path)

    with pytest.raises(ScribeError) as rejected:
        plot = PublicationPlotV1(name=name, media_type="image/png", content=_minimal_png())
        _publish(service, inputs, plots=(plot,))

    assert rejected.value.code == "PUBLICATION_MODEL_INVALID"
    assert vault.create_attempts == []
