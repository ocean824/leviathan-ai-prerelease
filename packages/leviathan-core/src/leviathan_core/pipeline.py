"""LiveFlowPipeline — the 14-step Live Market Flow as one orchestrator.

Replay-first: the same pipeline that will judge live setups judges
fixture replays. Every path through this pipeline ends in a
TradeJournalRecord — approved trades via the paper simulator, everything
else as a journaled block. Hidden failure modes are forbidden.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from leviathan_core.contracts import assert_trade_is_executable
from leviathan_core.decision.engine import CouncilDecisionEngine
from leviathan_core.execution.paper_sim import PaperExecutionEngine
from leviathan_core.risk.transaction_port import (
    CANDIDATE_SCHEMA,
    DRAFT_SCHEMA,
    ClaimReceipt,
    candidate_identity,
)
from leviathan_core.risk.veto_engine import VetoEngine
from leviathan_core.schemas import (
    AccountState,
    Bar,
    BrokerPath,
    CandidateSetup,
    DecisionPacket,
    EconomicEvent,
    ExecutionIntent,
    GateFinding,
    KillState,
    MarketState,
    OrderType,
    Permission,
    RiskAction,
    RiskGateContext,
    RiskSnapshot,
    RiskVerdict,
    StrategyGenome,
    TimeInForce,
    TradeJournalRecord,
    TradeOutcome,
    TruthValidationResult,
    new_id,
)
from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.journal import _issue_trade_journal_record, require_trade_journal_record
from leviathan_core.schemas.risk import _issue_risk_verdict, require_risk_verdict
from leviathan_core.seal import Issuer, SealError
from leviathan_core.seal import require as _require_sealed
from leviathan_core.state.range_tracker import RangeContext, RangeTracker
from leviathan_core.state.session_classifier import SessionContext, classify_session
from leviathan_core.truth.provider import TruthProvider


class PipelineResult(LeviathanModel):
    setup: CandidateSetup
    session: SessionContext
    range_context: RangeContext | None
    truth: TruthValidationResult
    decision: DecisionPacket
    verdict: RiskVerdict
    final_verdict: RiskVerdict | None
    findings: tuple[GateFinding, ...]
    intent: ExecutionIntent | None
    journal_record: TradeJournalRecord | None
    status: str = "completed"
    final: bool = True
    audit_sink_failure: bool = False
    failure_reason: str | None = None

    def __init__(self, **data: Any) -> None:
        try:
            _require_sealed(self, _PIPELINE_RESULT_ISSUER.tag)
        except SealError as exc:
            if exc.args == ("SEAL_NOT_ISSUED",):
                super().__init__(**data)
                return
            raise SealError("SEAL_FORBIDDEN_OPERATION") from None
        raise SealError("SEAL_FORBIDDEN_OPERATION")


_PIPELINE_RESULT_ISSUER = Issuer("c101.pipeline_result.v1")


def _issue_pipeline_result(value: PipelineResult) -> PipelineResult:
    if type(value) is not PipelineResult:
        raise SealError("SEAL_INVALID_MODEL")
    try:
        timestamp = value.setup.timestamp
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise SealError("SEAL_INVALID_MODEL") from None
        if timestamp.tzinfo is not UTC:
            utc_setup = value.setup.model_copy(update={"timestamp": timestamp.astimezone(UTC)})
            value = value.model_copy(update={"setup": utc_setup})
    except SealError:
        raise
    except Exception:
        raise SealError("SEAL_INVALID_MODEL") from None
    _require_pipeline_result_components(value)
    return _PIPELINE_RESULT_ISSUER.issue(value)


def require_pipeline_result(value: object) -> PipelineResult:
    if type(value) is not PipelineResult:
        raise SealError("SEAL_INVALID_MODEL")
    result = _require_sealed(value, _PIPELINE_RESULT_ISSUER.tag)
    _require_pipeline_result_components(result)
    return result


def _require_pipeline_result_components(value: PipelineResult) -> None:
    """Recheck trusted nested records and final-state links at consumption."""
    require_risk_verdict(value.verdict)
    if value.final_verdict is not None:
        require_risk_verdict(value.final_verdict)
    if value.journal_record is not None:
        require_trade_journal_record(value.journal_record)
    has_final_pair = value.final_verdict is not None and value.journal_record is not None
    if (
        value.final is not has_final_pair
        or value.verdict.decision_id != value.decision.decision_id
        or (
            value.final_verdict is not None
            and value.final_verdict.decision_id != value.decision.decision_id
        )
        or (
            value.journal_record is not None
            and (
                value.journal_record.decision_id != value.decision.decision_id
                or value.journal_record.setup_id != value.setup.setup_id
            )
        )
    ):
        raise SealError("SEAL_INVALID_MODEL")


def _risk_verdict_is_issued(value: RiskVerdict) -> bool:
    try:
        require_risk_verdict(value)
    except SealError as exc:
        if exc.args == ("SEAL_NOT_ISSUED",):
            return False
        raise
    return True


def _trade_journal_record_is_issued(value: TradeJournalRecord) -> bool:
    try:
        require_trade_journal_record(value)
    except SealError as exc:
        if exc.args == ("SEAL_NOT_ISSUED",):
            return False
        raise
    return True


class PreparedReplay(LeviathanModel):
    """Frozen candidate data; this has no execution authority."""

    setup: CandidateSetup
    session: SessionContext
    range_context: RangeContext | None
    truth: TruthValidationResult
    decision: DecisionPacket
    assessment: RiskVerdict
    risk_snapshot: RiskSnapshot | None
    bars: tuple[Bar, ...]
    context: RiskGateContext | None
    requested_size: Decimal
    stop_loss: Decimal | None
    take_profit: Decimal | None

    @property
    def actionable(self) -> bool:
        return (
            self.decision.permission is Permission.APPROVE
            and self.assessment.action in (RiskAction.ALLOW, RiskAction.REDUCE_SIZE)
            and self.assessment.execution_capable
        )

    def candidate_payload(self, policy_digest: str) -> dict[str, Any]:
        """Complete inert candidate; initial kill state is evidence, never final authority."""
        return {
            "schema": CANDIDATE_SCHEMA,
            "prepared": self.model_dump(mode="json"),
            "policy_digest": policy_digest,
            "execution": {
                "broker_path": BrokerPath.PAPER_SIM.value,
                "order_type": OrderType.MARKET.value,
                "time_in_force": TimeInForce.DAY.value,
            },
        }

    def candidate_identity(self, policy_digest: str) -> str:
        return candidate_identity(self.candidate_payload(policy_digest))

    def paper_draft(self, policy_digest: str) -> dict[str, Any]:
        """Derive every inert order field from the candidate consumed after claim."""
        if not self.actionable or self.risk_snapshot is None or not self.bars:
            raise ValueError("candidate has no actionable paper draft")
        entry = self.bars[0].open
        size = self.assessment.adjusted_size or self.requested_size
        stop = self.stop_loss if self.stop_loss is not None else entry * Decimal("0.995")
        target = self.take_profit if self.take_profit is not None else entry * Decimal("1.01")
        return {
            "schema": DRAFT_SCHEMA,
            "candidate_identity": self.candidate_identity(policy_digest),
            "decision_id": self.decision.decision_id,
            "setup_id": self.setup.setup_id,
            "instrument": self.setup.instrument,
            "entry_price": str(entry),
            "requested_size": str(self.requested_size),
            "adjusted_size": str(size),
            "stop_loss": str(stop),
            "take_profit": str(target),
            "risk_session_id": self.risk_snapshot.session_id,
            "policy_digest": policy_digest,
            "broker_path": BrokerPath.PAPER_SIM.value,
            "order_type": OrderType.MARKET.value,
            "time_in_force": TimeInForce.DAY.value,
        }


class LiveFlowPipeline:
    def __init__(
        self,
        truth_provider: TruthProvider,
        decision_engine: CouncilDecisionEngine,
        veto_engine: VetoEngine,
        paper_engine: PaperExecutionEngine,
        risk_lock_sha256: str = "",
        kill_state_provider: Callable[[], KillState] | None = None,
    ) -> None:
        self._truth = truth_provider
        self._council = decision_engine
        self._veto = veto_engine
        self._paper = paper_engine
        self._lock_sha = risk_lock_sha256
        self._kill_state_provider = kill_state_provider

    def prepare_replay(
        self,
        setup: CandidateSetup,
        bars: tuple[Bar, ...],
        account: AccountState,
        genome: StrategyGenome | None = None,
        prior_state: MarketState = MarketState.COMPRESSION,
        requested_size: Decimal = Decimal("1"),
        stop_loss: Decimal | None = None,
        take_profit: Decimal | None = None,
        events: tuple[EconomicEvent, ...] = (),
        sector: str = "unclassified",
        context: RiskGateContext | None = None,
    ) -> PreparedReplay:
        session = classify_session(setup.timestamp)
        range_context = self._track_range(bars)
        truth = self._truth.validate(setup)
        decision = self._council.decide(
            setup, truth, session, prior_state=prior_state, genome=genome
        )
        assessment = _issue_risk_verdict(
            self._veto.assess_candidate(
                decision,
                account,
                instrument=setup.instrument,
                requested_size=requested_size,
                at=setup.timestamp,
                sector=sector,
                upcoming_events=events,
                context=context,
                execution_input_error=self._execution_input_error(
                    bars, requested_size, stop_loss, take_profit
                ),
            )
        )
        risk_snapshot = None
        if (
            decision.permission is Permission.APPROVE
            and assessment.action in (RiskAction.ALLOW, RiskAction.REDUCE_SIZE)
            and assessment.execution_capable
        ):
            risk_snapshot = RiskSnapshot(
                session_id=new_id("session"),
                max_daily_drawdown_pct=Decimal("3.0"),
                max_position_size=assessment.adjusted_size or requested_size,
                allowed_instruments=(setup.instrument,),
                frozen_at=context.as_of if context is not None else self._now(bars),
                risk_lock_sha256=self._lock_sha,
            )
        return PreparedReplay(
            setup=setup,
            session=session,
            range_context=range_context,
            truth=truth,
            decision=decision,
            assessment=assessment,
            risk_snapshot=risk_snapshot,
            bars=bars,
            context=context,
            requested_size=requested_size,
            stop_loss=stop_loss,
            take_profit=take_profit,
        )

    def consume_claimed(
        self,
        prepared: PreparedReplay,
        receipt: ClaimReceipt,
    ) -> tuple[RiskVerdict, ExecutionIntent | None, TradeJournalRecord]:
        """Synchronous paper consumption after a confirmed durable CAS claim."""
        if (
            receipt.decision_id != prepared.decision.decision_id
            or receipt.policy_digest != self._lock_sha
            or receipt.candidate_identity != prepared.candidate_identity(self._lock_sha)
            or not receipt.token
        ):
            raise ValueError("claim receipt does not match the decision")
        if not prepared.actionable:
            raise ValueError("nonactionable attempt cannot be consumed")
        setup, decision, assessment = prepared.setup, prepared.decision, prepared.assessment
        bars = prepared.bars
        draft = prepared.paper_draft(self._lock_sha)
        size = Decimal(draft["adjusted_size"])
        entry_price = Decimal(draft["entry_price"])
        stop = Decimal(draft["stop_loss"])
        target = Decimal(draft["take_profit"])
        risk = prepared.risk_snapshot
        if risk is None:
            raise ValueError("authorized risk snapshot is missing")
        assert_trade_is_executable(decision, risk, instrument=setup.instrument)

        # The same lock linearizes a committed halt with this entire final
        # synchronous check -> intent -> pure paper consumption seam.
        with self._veto.halt_authority.route_interlock():
            latest = prepared.context
            if latest is not None and self._kill_state_provider is not None:
                latest = latest.model_copy(update={"kill": self._kill_state_provider()})
            guard = self._veto.route_guard
            findings = (
                guard.check(latest)
                if guard is not None
                else (GateFinding.ROUTE_GUARD_UNCONFIGURED,)
            )
            if not self._veto.policy_is_bound:
                findings = tuple(dict.fromkeys((*findings, GateFinding.LOCK_TAMPERED)))
            if self._veto.halt_authority.halted:
                findings = tuple(dict.fromkeys((*findings, GateFinding.GLOBAL_KILL)))
            if findings:
                final = _issue_risk_verdict(
                    self._veto.guard_verdict(decision.decision_id, findings)
                )
                return final, None, self._journal_block(setup, decision, final)

            intent = self._make_intent(decision, risk, size, stop, target)
            record = _issue_trade_journal_record(
                self._paper.simulate(
                    intent, decision.direction, entry_price, bars, risk, setup_id=setup.setup_id
                )
            )
        return assessment, intent, record

    @staticmethod
    def _make_intent(
        decision: DecisionPacket,
        risk: RiskSnapshot,
        size: Decimal,
        stop: Decimal,
        target: Decimal,
    ) -> ExecutionIntent:
        return ExecutionIntent(
            decision_id=decision.decision_id,
            risk_session_id=risk.session_id,
            broker_path=BrokerPath.PAPER_SIM,
            order_type=OrderType.MARKET,
            size=size,
            stop_loss=stop,
            take_profit=target,
            time_in_force=TimeInForce.DAY,
        )

    def block_prepared(
        self,
        prepared: PreparedReplay,
        verdict: RiskVerdict | None = None,
    ) -> tuple[RiskVerdict, TradeJournalRecord]:
        # Legacy callers still receive a result, but caller-built inputs do not
        # acquire trusted issuance merely by passing through this wrapper.
        issue_output = _risk_verdict_is_issued(prepared.assessment) and (
            verdict is None or _risk_verdict_is_issued(verdict)
        )
        final = verdict if verdict is not None else prepared.assessment
        if prepared.decision.permission is not Permission.APPROVE and final.action in (
            RiskAction.ALLOW,
            RiskAction.REDUCE_SIZE,
        ):
            final = RiskVerdict(
                decision_id=prepared.decision.decision_id,
                action=(
                    RiskAction.WAIT
                    if prepared.decision.permission is Permission.WAIT
                    else RiskAction.REJECT
                ),
                reason=f"council_permission_{prepared.decision.permission.value}",
                adjusted_size=None,
                halts_engaged=final.halts_engaged,
                execution_capable=False,
                findings=final.findings,
            )
        if issue_output:
            final = _issue_risk_verdict(final)
        return final, self._journal_block(
            prepared.setup, prepared.decision, final, issue=issue_output
        )

    def result_from_prepared(
        self,
        prepared: PreparedReplay,
        final_verdict: RiskVerdict | None,
        intent: ExecutionIntent | None,
        journal: TradeJournalRecord | None,
        *,
        status: str = "completed",
        audit_sink_failure: bool = False,
        failure_reason: str | None = None,
    ) -> PipelineResult:
        # Issuance is transitive: this wrapper may preserve legacy caller data,
        # but it cannot turn any unissued nested record into a trusted result.
        all_components_issued = _risk_verdict_is_issued(prepared.assessment)
        if final_verdict is not None:
            all_components_issued = _risk_verdict_is_issued(final_verdict) and all_components_issued
        if journal is not None:
            all_components_issued = (
                _trade_journal_record_is_issued(journal) and all_components_issued
            )
        result = PipelineResult(
            setup=prepared.setup,
            session=prepared.session,
            range_context=prepared.range_context,
            truth=prepared.truth,
            decision=prepared.decision,
            verdict=prepared.assessment,
            final_verdict=final_verdict,
            findings=(
                final_verdict.findings
                if final_verdict is not None
                else (GateFinding.AUDIT_SINK_FAILURE,)
                if audit_sink_failure
                else ()
            ),
            intent=intent,
            journal_record=journal,
            status=status,
            final=final_verdict is not None and journal is not None,
            audit_sink_failure=audit_sink_failure,
            failure_reason=failure_reason,
        )
        return _issue_pipeline_result(result) if all_components_issued else result

    def run_replay(
        self,
        setup: CandidateSetup,
        bars: tuple[Bar, ...],
        account: AccountState,
        genome: StrategyGenome | None = None,
        prior_state: MarketState = MarketState.COMPRESSION,
        requested_size: Decimal = Decimal("1"),
        stop_loss: Decimal | None = None,
        take_profit: Decimal | None = None,
        events: tuple[EconomicEvent, ...] = (),
        sector: str = "unclassified",
        context: RiskGateContext | None = None,
        *,
        fixture_only: bool = False,
    ) -> PipelineResult:
        if not fixture_only:
            raise RuntimeError("nondurable replay is restricted to explicit test fixtures")
        # Steps 2-5: session, range, state context.
        session = classify_session(setup.timestamp)
        range_context = self._track_range(bars)

        # Steps 6-8: truth validation (events feed the veto engine below).
        truth = self._truth.validate(setup)

        # Step 9: capital permission.
        decision = self._council.decide(
            setup, truth, session, prior_state=prior_state, genome=genome
        )
        execution_input_error = self._execution_input_error(
            bars, requested_size, stop_loss, take_profit
        )

        # Step 10: sovereign risk.
        verdict = _issue_risk_verdict(
            self._veto.assess(
                decision,
                account,
                instrument=setup.instrument,
                requested_size=requested_size,
                at=setup.timestamp,
                sector=sector,
                upcoming_events=events,
                context=context,
                execution_input_error=execution_input_error,
            )
        )

        # Steps 11-13: execute via paper spine, or journal the block.
        if (
            decision.permission is Permission.APPROVE
            and verdict.action in (RiskAction.ALLOW, RiskAction.REDUCE_SIZE)
            and verdict.execution_capable
        ):
            final_verdict, intent, record = self._execute(
                setup, decision, verdict, bars, requested_size, stop_loss, take_profit, context
            )
        else:
            final_verdict = verdict
            intent = None
            record = self._journal_block(setup, decision, verdict)

        return _issue_pipeline_result(
            PipelineResult(
                setup=setup,
                session=session,
                range_context=range_context,
                truth=truth,
                decision=decision,
                verdict=verdict,
                final_verdict=final_verdict,
                findings=final_verdict.findings,
                intent=intent,
                journal_record=record,
            )
        )

    def _track_range(self, bars: tuple[Bar, ...]) -> RangeContext | None:
        if not bars:
            return None
        tracker = RangeTracker()
        context: RangeContext | None = None
        for bar in bars:
            context = tracker.update(bar)
        return context

    def _execution_input_error(
        self,
        bars: tuple[Bar, ...],
        requested_size: Decimal,
        stop_loss: Decimal | None,
        take_profit: Decimal | None,
    ) -> str | None:
        if not bars:
            return "execution_input_invalid:bars_empty"
        if not bars[0].open.is_finite() or bars[0].open <= 0:
            return "execution_input_invalid:entry_price"
        if not requested_size.is_finite() or requested_size <= 0:
            return "execution_input_invalid:requested_size"
        if stop_loss is not None and (not stop_loss.is_finite() or stop_loss <= 0):
            return "execution_input_invalid:stop_loss"
        if take_profit is not None and (not take_profit.is_finite() or take_profit <= 0):
            return "execution_input_invalid:take_profit"
        return None

    def _execute(
        self,
        setup: CandidateSetup,
        decision: DecisionPacket,
        verdict: RiskVerdict,
        bars: tuple[Bar, ...],
        requested_size: Decimal,
        stop_loss: Decimal | None,
        take_profit: Decimal | None,
        context: RiskGateContext | None,
    ) -> tuple[RiskVerdict, ExecutionIntent | None, TradeJournalRecord]:
        require_risk_verdict(verdict)
        size = verdict.adjusted_size or requested_size
        entry_price = bars[0].open
        stop = stop_loss if stop_loss is not None else entry_price * Decimal("0.995")
        target = take_profit if take_profit is not None else entry_price * Decimal("1.01")

        # RiskSnapshot is frozen BEFORE the intent exists (contract rule 3).
        risk = RiskSnapshot(
            session_id=new_id("session"),
            max_daily_drawdown_pct=Decimal("3.0"),
            max_position_size=size,
            allowed_instruments=(setup.instrument,),
            frozen_at=context.as_of if context is not None else self._now(bars),
            risk_lock_sha256=self._lock_sha,
        )
        assert_trade_is_executable(decision, risk, instrument=setup.instrument)

        guard = self._veto.route_guard

        def recheck_route() -> tuple[GateFinding, ...]:
            latest_context = context
            if latest_context is not None and self._kill_state_provider is not None:
                latest_context = latest_context.model_copy(
                    update={"kill": self._kill_state_provider()}
                )
            if guard is None:
                return (GateFinding.ROUTE_GUARD_UNCONFIGURED,)
            findings = guard.check(latest_context)
            if not self._veto.policy_is_bound and GateFinding.LOCK_TAMPERED not in findings:
                findings = (*findings, GateFinding.LOCK_TAMPERED)
            return findings

        findings = recheck_route()
        final_verdict = _issue_risk_verdict(
            self._veto.finalize_route(
                require_risk_verdict(verdict), findings, authorization_check=recheck_route
            )
        )
        if final_verdict.action not in (RiskAction.ALLOW, RiskAction.REDUCE_SIZE):
            return final_verdict, None, self._journal_block(setup, decision, final_verdict)

        revoked = self._veto.reconcile_route(require_risk_verdict(verdict), recheck_route)
        if revoked is not None:
            revoked = _issue_risk_verdict(revoked)
            return revoked, None, self._journal_block(setup, decision, revoked)

        intent = self._make_intent(decision, risk, size, stop, target)
        record = _issue_trade_journal_record(
            self._paper.simulate(
                intent, decision.direction, entry_price, bars, risk, setup_id=setup.setup_id
            )
        )
        return final_verdict, intent, record

    def _journal_block(
        self,
        setup: CandidateSetup,
        decision: DecisionPacket,
        verdict: RiskVerdict,
        *,
        issue: bool = True,
    ) -> TradeJournalRecord:
        if issue:
            require_risk_verdict(verdict)
        record = TradeJournalRecord(
            trade_id=new_id("trade"),
            setup_id=setup.setup_id,
            decision_id=decision.decision_id,
            outcome=TradeOutcome.BLOCKED,
            post_trade_notes=(
                f"blocked: permission={decision.permission.value} "
                f"risk={verdict.action.value} reason={verdict.reason} "
                f"halts={','.join(verdict.halts_engaged)}"
            ),
        )
        return _issue_trade_journal_record(record) if issue else record

    def _now(self, bars: tuple[Bar, ...]) -> datetime:
        return bars[0].timestamp
