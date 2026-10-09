"""Durable paper replay route. SQLite route_attempts is the sole authority."""

from decimal import Decimal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from leviathan_store.risk_txn import RouteAttemptStore, RouteTransitionError

from leviathan_api.demo import (
    DEMO_BARS,
    DEMO_GENOME,
    DEMO_REQUIRED_STREAMS,
    DEMO_SETUP,
    DEMO_STOP,
    DEMO_STREAM_FRESHNESS,
    DEMO_TARGET,
    DEMO_TRUTH,
)
from leviathan_core.pipeline import (
    LiveFlowPipeline,
    PipelineResult,
    PreparedReplay,
    require_pipeline_result,
)
from leviathan_core.risk.transaction_port import RiskDecisionPort
from leviathan_core.schemas import AccountState, KillState, RiskGateContext, new_id
from leviathan_core.schemas.journal import require_trade_journal_record
from leviathan_core.schemas.risk import require_risk_verdict
from leviathan_core.truth.provider import StaticTruthProvider

router = APIRouter(prefix="/pipeline", tags=["pipeline"])


def _attempt_store(request: Request) -> RouteAttemptStore:
    state = request.app.state.leviathan
    return RouteAttemptStore(
        request.app.state.sessionmaker,
        integrity_key=state.ledger_integrity_key,
    )


def _required_result(result: PipelineResult) -> dict[str, object]:
    return require_pipeline_result(result).model_dump(mode="json")


def _incomplete(
    pipeline: LiveFlowPipeline,
    prepared: PreparedReplay,
    reason: str = "audit_sink_failure",
) -> JSONResponse:
    result = pipeline.result_from_prepared(
        prepared,
        None,
        None,
        None,
        status="incomplete",
        audit_sink_failure=reason == "audit_sink_failure",
        failure_reason=reason,
    )
    return JSONResponse(status_code=503, content=result.model_dump(mode="json"))


@router.get("/attempts/{decision_id}", response_model=None)
async def read_attempt(request: Request, decision_id: str) -> dict[str, object] | JSONResponse:
    """Read durable outcome by ID; unresolved work is never replayed here."""
    port: RiskDecisionPort = _attempt_store(request)
    try:
        view = await port.read_view(decision_id)
    except RouteTransitionError as error:
        if error.args in {
            ("INTEGRITY_KEY_UNAVAILABLE",),
            ("UNISSUED_PERSISTED",),
        }:
            reason = error.args[0]
            return {
                "decision_id": decision_id,
                "status": "unverified",
                "verification": "UNVERIFIED",
                "reason": reason,
                "final": False,
                "final_verdict": None,
                "journal_record": None,
                "audit_sink_failure": False,
            }
        return JSONResponse(
            status_code=503,
            content={
                "decision_id": decision_id,
                "status": "unknown",
                "verification": "UNVERIFIED",
                "final": False,
                "final_verdict": None,
                "journal_record": None,
                "audit_sink_failure": True,
            },
        )
    except Exception:
        return JSONResponse(
            status_code=503,
            content={
                "decision_id": decision_id,
                "status": "unknown",
                "final": False,
                "final_verdict": None,
                "journal_record": None,
                "audit_sink_failure": True,
            },
        )
    if view is None:
        return JSONResponse(status_code=404, content={"decision_id": decision_id})
    return view


@router.post("/replay", response_model=None)
async def run_replay(request: Request) -> dict[str, object] | JSONResponse:
    state = request.app.state.leviathan
    pipeline = LiveFlowPipeline(
        truth_provider=StaticTruthProvider(DEMO_TRUTH),
        decision_engine=state.council,
        veto_engine=state.veto,
        paper_engine=state.paper,
        risk_lock_sha256=state.settings.risk_lock_sha256,
        kill_state_provider=lambda: KillState(
            global_kill=state.halts.halted,
            killed_providers=tuple(sorted(state.killed_providers)),
        ),
    )
    account = AccountState(equity=Decimal(100000), daily_pnl_pct=Decimal(0))
    context = RiskGateContext(
        as_of=DEMO_BARS[-1].timestamp,
        required=DEMO_REQUIRED_STREAMS,
        observed=DEMO_STREAM_FRESHNESS,
        kill=KillState(
            global_kill=state.halts.halted,
            killed_providers=tuple(sorted(state.killed_providers)),
        ),
    )
    prepared = pipeline.prepare_replay(
        DEMO_SETUP,
        DEMO_BARS,
        account,
        genome=DEMO_GENOME,
        requested_size=Decimal(1),
        stop_loss=DEMO_STOP,
        take_profit=DEMO_TARGET,
        context=context,
    )
    # No fallback adapter. A fresh POST creates a new ID; only this ID is
    # deduplicated by the route_attempts primary key and CAS claim.
    port: RiskDecisionPort = _attempt_store(request)
    evidence = {"candidate": prepared.candidate_payload(state.settings.risk_lock_sha256)}
    try:
        require_risk_verdict(prepared.assessment)
        await port.prepare(prepared.setup, prepared.decision, prepared.assessment, evidence)
    except Exception:
        return _incomplete(pipeline, prepared)

    if not prepared.actionable:
        final, journal = pipeline.block_prepared(prepared)
        try:
            require_risk_verdict(final)
            require_trade_journal_record(journal)
            await port.complete(None, prepared.setup, prepared.decision, final, journal)
        except Exception:
            return _incomplete(pipeline, prepared)
        result = pipeline.result_from_prepared(prepared, final, None, journal, status="blocked")
        return _required_result(result)

    # This is inert data, not an ExecutionIntent or simulator instruction.
    draft = prepared.paper_draft(state.settings.risk_lock_sha256)
    try:
        await port.authorize(prepared.decision.decision_id, draft)
        receipt = await port.claim(prepared.decision.decision_id, new_id("claim"))
        if receipt is None:
            return _incomplete(pipeline, prepared, "claim_not_confirmed")
    except Exception:
        # Any raised commit may have landed. Never infer rollback or simulate.
        return _incomplete(pipeline, prepared)

    try:
        final, intent, journal = pipeline.consume_claimed(prepared, receipt)
    except Exception:
        # The durable claim remains unresolved; no automatic replay.
        return _incomplete(pipeline, prepared, "paper_simulator_failure")
    try:
        require_risk_verdict(final)
        require_trade_journal_record(journal)
        await port.complete(receipt, prepared.setup, prepared.decision, final, journal)
    except Exception:
        return _incomplete(pipeline, prepared)
    result = pipeline.result_from_prepared(
        prepared,
        final,
        intent,
        journal,
        status="completed" if intent is not None else "blocked",
    )
    return _required_result(result)
