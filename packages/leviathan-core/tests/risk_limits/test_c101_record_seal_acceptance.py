"""Independent acceptance for source-issued C-101 risk and journal records."""

from __future__ import annotations

import copy
import hashlib
import json
import pickle
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from itertools import count
from pathlib import Path
from typing import Any, cast

import pytest

from leviathan_core import pipeline as pipeline_module
from leviathan_core.decision import engine as decision_engine_module
from leviathan_core.decision.engine import CouncilDecisionEngine
from leviathan_core.execution import paper_sim as paper_sim_module
from leviathan_core.execution.paper_sim import PaperExecutionEngine
from leviathan_core.pipeline import (
    LiveFlowPipeline,
    PipelineResult,
    PreparedReplay,
    require_pipeline_result,
)
from leviathan_core.risk.audit import RiskAuditLog
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.risk.policy import load_risk_policy
from leviathan_core.risk.route_guard import RouteGuard
from leviathan_core.risk.veto_engine import VetoEngine
from leviathan_core.schemas import (
    AccountState,
    Bar,
    CandidateSetup,
    KillState,
    RequiredStream,
    RiskGateContext,
    StrategyGenome,
    StreamFreshness,
    TruthValidationResult,
)
from leviathan_core.schemas.enums import RiskAction, TradeOutcome
from leviathan_core.schemas.journal import (
    TradeJournalRecord,
    require_trade_journal_record,
)
from leviathan_core.schemas.risk import RiskVerdict, require_risk_verdict
from leviathan_core.seal import SealError
from leviathan_core.truth.provider import StaticTruthProvider

_ROOT = Path(__file__).resolve().parents[4]
_REPLAY_FIXTURE = (
    _ROOT / "packages" / "leviathan-core" / "tests" / "fixtures" / "replay_nq_breakout.json"
)
_LOCK_FILE = _ROOT / "tests" / "fixtures" / "risk_lock" / "risk_governance.lock.yaml"
_LOCK_SHA256 = "46a03497679f8a59c82229ba28cef4bf56b7c1d7c30ae936016f876c9eaf3c51"

_JOURNAL_GOLDEN = (
    b'{"trade_id":"trade_golden","setup_id":"setup_golden",'
    b'"decision_id":"decision_golden","entry":"100.25",'
    b'"exit":"101.50","mae":"-0.75","mfe":"2.00",'
    b'"outcome":"win","post_trade_notes":"paper_sim target_hit pnl=1.25"}'
)
_JOURNAL_GOLDEN_SHA256 = "d03924afd7824b3efefbf71c099bd3129f43ba2577302fdc729a972b84f1ab0d"


def _risk_verdict() -> RiskVerdict:
    return RiskVerdict(
        decision_id="decision_acceptance",
        action=RiskAction.REJECT,
        reason="fixture_block",
        execution_capable=False,
    )


def _trade_journal_record() -> TradeJournalRecord:
    return TradeJournalRecord(
        trade_id="trade_golden",
        setup_id="setup_golden",
        decision_id="decision_golden",
        entry=Decimal("100.25"),
        exit=Decimal("101.50"),
        mae=Decimal("-0.75"),
        mfe=Decimal("2.00"),
        outcome=TradeOutcome.WIN,
        post_trade_notes="paper_sim target_hit pnl=1.25",
    )


def _caller_journal(prepared: PreparedReplay) -> TradeJournalRecord:
    """Build a valid legacy caller value linked to the prepared decision."""
    return TradeJournalRecord(
        trade_id="trade_caller_built",
        setup_id=prepared.setup.setup_id,
        decision_id=prepared.decision.decision_id,
        entry=Decimal("100.25"),
        exit=Decimal("101.50"),
        mae=Decimal("-0.75"),
        mfe=Decimal("2.00"),
        outcome=TradeOutcome.BLOCKED,
        post_trade_notes="legacy caller supplied record",
    )


def _caller_allow(prepared: PreparedReplay) -> RiskVerdict:
    """Construct the forged, execution-capable legacy input from the P1 case."""
    return RiskVerdict(
        decision_id=prepared.decision.decision_id,
        action=RiskAction.ALLOW,
        reason="caller_supplied_allow",
        adjusted_size=Decimal("999999999999"),
        execution_capable=True,
    )


def _replay() -> dict[str, object]:
    return cast(dict[str, object], json.loads(_REPLAY_FIXTURE.read_text(encoding="utf-8")))


def _bars() -> tuple[Bar, ...]:
    start = datetime(2026, 4, 15, 14, 35, tzinfo=UTC)
    ohlc = (
        ("18250", "18258", "18246", "18255"),
        ("18255", "18262", "18248", "18260"),
        ("18260", "18266", "18255", "18264"),
        ("18264", "18272", "18260", "18270"),
    )
    return tuple(
        Bar(
            instrument="NQ",
            timestamp=start + timedelta(minutes=index),
            open=Decimal(open_),
            high=Decimal(high),
            low=Decimal(low),
            close=Decimal(close),
            volume=Decimal(1000),
        )
        for index, (open_, high, low, close) in enumerate(ohlc)
    )


def _pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> LiveFlowPipeline:
    sequence = count()

    def stable_id(prefix: str) -> str:
        return f"{prefix}_acceptance_{next(sequence)}"

    monkeypatch.setattr(pipeline_module, "new_id", stable_id)
    monkeypatch.setattr(decision_engine_module, "new_id", stable_id)
    monkeypatch.setattr(paper_sim_module, "new_id", stable_id)

    truth_data = _replay()["truth_validation"]
    truth = StaticTruthProvider(TruthValidationResult.model_validate(truth_data))
    return LiveFlowPipeline(
        truth_provider=truth,
        decision_engine=CouncilDecisionEngine(),
        veto_engine=VetoEngine(
            policy=load_risk_policy(_LOCK_FILE),
            halt_authority=HaltAuthority(),
            audit_log=RiskAuditLog(tmp_path / "c101-acceptance-audit.jsonl"),
            route_guard=RouteGuard(_LOCK_FILE, _LOCK_SHA256),
        ),
        paper_engine=PaperExecutionEngine(slippage=Decimal("0.25")),
        risk_lock_sha256=_LOCK_SHA256,
    )


def _inputs() -> tuple[CandidateSetup, StrategyGenome]:
    fixture = _replay()
    return (
        CandidateSetup.model_validate(fixture["candidate_setup"]),
        StrategyGenome.model_validate(fixture["strategy_genome"]),
    )


def _gate_context(bars: tuple[Bar, ...]) -> RiskGateContext:
    at = bars[-1].timestamp
    return RiskGateContext(
        as_of=at,
        required=(RequiredStream(stream_id="bars.1m", symbol="NQ", provider="demo"),),
        observed=(
            StreamFreshness(
                stream_id="bars.1m",
                symbol="NQ",
                provider="demo",
                source_ts=at,
                exchange_ts=at,
                received_at=at,
            ),
        ),
        kill=KillState(),
    )


def _run_replay(
    pipeline: LiveFlowPipeline,
    *,
    daily_pnl_pct: Decimal = Decimal("0"),
) -> PipelineResult:
    setup, genome = _inputs()
    bars = _bars()
    return pipeline.run_replay(
        setup,
        bars,
        AccountState(equity=Decimal("100000"), daily_pnl_pct=daily_pnl_pct),
        genome=genome,
        requested_size=Decimal("1"),
        stop_loss=Decimal("18240"),
        take_profit=Decimal("18270"),
        context=_gate_context(bars),
        fixture_only=True,
    )


def _blocked_result_parts(
    pipeline: LiveFlowPipeline,
) -> tuple[PreparedReplay, RiskVerdict, TradeJournalRecord]:
    setup, genome = _inputs()
    bars = _bars()
    prepared = pipeline.prepare_replay(
        setup,
        bars,
        AccountState(equity=Decimal("100000"), daily_pnl_pct=Decimal("-3.5")),
        genome=genome,
        requested_size=Decimal("1"),
        stop_loss=Decimal("18240"),
        take_profit=Decimal("18270"),
        context=_gate_context(bars),
    )
    final_verdict, journal = pipeline.block_prepared(prepared)
    return prepared, final_verdict, journal


@pytest.mark.parametrize(
    ("record_factory", "require_record"),
    [
        (_risk_verdict, require_risk_verdict),
        (_trade_journal_record, require_trade_journal_record),
    ],
)
def test_unissued_schema_instances_are_rejected_at_require_boundary(
    record_factory: Callable[[], RiskVerdict | TradeJournalRecord],
    require_record: Callable[[object], object],
) -> None:
    value = record_factory()

    # Schema construction remains available for parsing and validation; it does
    # not confer source issuance authority.
    assert type(value) in (RiskVerdict, TradeJournalRecord)
    with pytest.raises(SealError, match="SEAL_NOT_ISSUED") as error:
        require_record(value)
    assert str(error.value) == "SEAL_NOT_ISSUED"


@pytest.mark.parametrize(
    ("require_record", "wrong_value"),
    [
        (require_risk_verdict, _trade_journal_record),
        (require_trade_journal_record, _risk_verdict),
        (require_risk_verdict, lambda: object()),
        (require_trade_journal_record, lambda: object()),
    ],
)
def test_require_helpers_reject_wrong_types_with_content_free_error(
    require_record: Callable[[object], object],
    wrong_value: Callable[[], object],
) -> None:
    with pytest.raises(SealError, match="SEAL_INVALID_MODEL") as error:
        require_record(wrong_value())
    assert str(error.value) == "SEAL_INVALID_MODEL"


def test_unissued_records_remain_unissued_after_copy_pickle_or_model_construct() -> None:
    risk = _risk_verdict()
    journal = _trade_journal_record()
    candidates = (
        (require_risk_verdict, copy.copy(risk)),
        (require_risk_verdict, copy.deepcopy(risk)),
        (require_risk_verdict, pickle.loads(pickle.dumps(risk))),
        (
            require_risk_verdict,
            RiskVerdict.model_construct(
                decision_id="unissued", action=RiskAction.REJECT, reason="unissued"
            ),
        ),
        (require_trade_journal_record, copy.copy(journal)),
        (require_trade_journal_record, copy.deepcopy(journal)),
        (require_trade_journal_record, pickle.loads(pickle.dumps(journal))),
        (
            require_trade_journal_record,
            TradeJournalRecord.model_construct(
                trade_id="unissued",
                setup_id="unissued",
                decision_id="unissued",
                outcome=TradeOutcome.BLOCKED,
            ),
        ),
    )

    for require_record, candidate in candidates:
        with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
            require_record(candidate)


def test_prechange_journal_json_bytes_are_unchanged() -> None:
    payload = _trade_journal_record().model_dump_json().encode("utf-8")

    assert payload == _JOURNAL_GOLDEN
    assert hashlib.sha256(payload).hexdigest() == _JOURNAL_GOLDEN_SHA256


def test_pipeline_issues_records_at_successful_replay_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run_replay(_pipeline(tmp_path, monkeypatch))

    assert require_pipeline_result(result) is result
    assert require_risk_verdict(result.verdict) is result.verdict
    assert result.final_verdict is not None
    assert require_risk_verdict(result.final_verdict) is result.final_verdict
    assert result.journal_record is not None
    assert require_trade_journal_record(result.journal_record) is result.journal_record
    assert result.intent is not None
    assert result.journal_record.outcome is TradeOutcome.WIN


def test_pipeline_issues_blocked_final_records_without_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run_replay(_pipeline(tmp_path, monkeypatch), daily_pnl_pct=Decimal("-3.5"))

    assert require_pipeline_result(result) is result
    assert require_risk_verdict(result.verdict) is result.verdict
    assert result.final_verdict is not None
    assert require_risk_verdict(result.final_verdict) is result.final_verdict
    assert result.journal_record is not None
    assert require_trade_journal_record(result.journal_record) is result.journal_record
    assert result.intent is None
    assert result.journal_record.outcome is TradeOutcome.BLOCKED


def test_caller_built_allow_and_matching_journal_return_legacy_result_unissued(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = _pipeline(tmp_path, monkeypatch)
    prepared, _issued_final, _issued_journal = _blocked_result_parts(pipeline)
    forged_allow = _caller_allow(prepared)
    caller_journal = _caller_journal(prepared)

    # Legacy callers still get a result. The pipeline must not confer issuance
    # authority on either caller-provided record or their containing result.
    result = pipeline.result_from_prepared(
        prepared.model_copy(update={"assessment": forged_allow}),
        forged_allow,
        None,
        caller_journal,
    )

    assert type(result) is PipelineResult
    assert result.verdict is forged_allow
    assert result.final_verdict is forged_allow
    assert result.journal_record is caller_journal
    with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
        require_risk_verdict(forged_allow)
    with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
        require_trade_journal_record(caller_journal)
    with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
        require_pipeline_result(result)


def test_block_prepared_preserves_caller_built_allow_without_issuing_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = _pipeline(tmp_path, monkeypatch)
    prepared, _issued_final, _issued_journal = _blocked_result_parts(pipeline)
    forged_allow = _caller_allow(prepared)
    caller_prepared = prepared.model_copy(update={"assessment": forged_allow})

    final_verdict, journal = pipeline.block_prepared(caller_prepared, forged_allow)
    assert type(final_verdict) is RiskVerdict
    assert type(journal) is TradeJournalRecord

    # A subsequent legacy result build also returns normally, but cannot make
    # this mixed caller input trusted.
    result = pipeline.result_from_prepared(caller_prepared, final_verdict, None, journal)
    assert type(result) is PipelineResult
    with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
        require_pipeline_result(result)


def test_mixed_issued_and_caller_built_inputs_do_not_issue_pipeline_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = _pipeline(tmp_path, monkeypatch)
    prepared, issued_final, issued_journal = _blocked_result_parts(pipeline)
    assert require_risk_verdict(prepared.assessment) is prepared.assessment
    assert require_risk_verdict(issued_final) is issued_final
    assert require_trade_journal_record(issued_journal) is issued_journal

    caller_final = RiskVerdict(
        decision_id=prepared.decision.decision_id,
        action=RiskAction.REJECT,
        reason="legacy caller result",
        execution_capable=False,
    )
    result = pipeline.result_from_prepared(prepared, caller_final, None, issued_journal)

    assert type(result) is PipelineResult
    assert result.verdict is prepared.assessment
    assert result.final_verdict is caller_final
    assert result.journal_record is issued_journal
    with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
        require_pipeline_result(result)


def test_pipeline_require_rejects_unissued_clone_and_wrong_types(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run_replay(_pipeline(tmp_path, monkeypatch))
    clone = PipelineResult(**result.model_dump())
    incomplete_final_data = result.model_dump()
    incomplete_final_data.update(final_verdict=None, journal_record=None, final=True)
    incomplete_final = PipelineResult(**incomplete_final_data)

    with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
        require_pipeline_result(clone)
    with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
        require_pipeline_result(incomplete_final)
    with pytest.raises(SealError, match="SEAL_INVALID_MODEL"):
        require_pipeline_result(object())
    with pytest.raises(SealError, match="SEAL_INVALID_MODEL"):
        require_risk_verdict(result.journal_record)
    with pytest.raises(SealError, match="SEAL_INVALID_MODEL"):
        require_trade_journal_record(result.verdict)


def test_issued_values_reject_copy_pickle_and_model_construct_clones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run_replay(_pipeline(tmp_path, monkeypatch))
    assert result.final_verdict is not None and result.journal_record is not None
    issued_values = (
        (require_risk_verdict, result.verdict),
        (require_risk_verdict, result.final_verdict),
        (require_trade_journal_record, result.journal_record),
        (require_pipeline_result, result),
    )

    for require_value, value in issued_values:
        clones = (
            copy.copy(value),
            copy.deepcopy(value),
            value.model_copy(),
            pickle.loads(pickle.dumps(value)),
            cast(Any, type(value)).model_construct(),
        )
        for clone in clones:
            with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
                require_value(clone)


def test_tamper_after_issue_is_detected_at_each_public_require_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run_replay(_pipeline(tmp_path, monkeypatch))
    assert result.final_verdict is not None and result.journal_record is not None

    object.__setattr__(result.verdict, "reason", "tampered")
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        require_risk_verdict(result.verdict)

    journal = _run_replay(_pipeline(tmp_path, monkeypatch)).journal_record
    assert journal is not None
    object.__setattr__(journal, "post_trade_notes", "tampered")
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        require_trade_journal_record(journal)

    result = _run_replay(_pipeline(tmp_path, monkeypatch))
    object.__setattr__(result, "status", "tampered")
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        require_pipeline_result(result)


def test_issued_values_refuse_reinitialization_before_state_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run_replay(_pipeline(tmp_path, monkeypatch))
    assert result.final_verdict is not None and result.journal_record is not None
    issued_values = (
        (result.verdict, require_risk_verdict),
        (result.journal_record, require_trade_journal_record),
        (result, require_pipeline_result),
    )

    for value, require_value in issued_values:
        original = value.model_dump_json()
        with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
            cast(Any, type(value)).__init__(value, **value.model_dump())
        assert value.model_dump_json() == original
        assert require_value(value) is value


def test_pipeline_result_rejects_mismatched_final_record_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = _pipeline(tmp_path, monkeypatch)
    first_prepared, first_final, first_journal = _blocked_result_parts(pipeline)
    _second_prepared, second_final, second_journal = _blocked_result_parts(pipeline)

    valid = pipeline.result_from_prepared(first_prepared, first_final, None, first_journal)
    assert require_pipeline_result(valid) is valid

    with pytest.raises(SealError, match="SEAL_INVALID_MODEL"):
        pipeline.result_from_prepared(first_prepared, second_final, None, second_journal)


def test_issued_pipeline_result_normalizes_offset_setup_timestamp_to_utc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = _pipeline(tmp_path, monkeypatch)
    prepared, final_verdict, journal = _blocked_result_parts(pipeline)
    offset_setup = prepared.setup.model_copy(
        update={
            "timestamp": datetime(
                2026,
                4,
                15,
                20,
                5,
                tzinfo=timezone(timedelta(hours=5, minutes=30)),
            )
        }
    )
    offset_prepared = prepared.model_copy(update={"setup": offset_setup})

    result = pipeline.result_from_prepared(offset_prepared, final_verdict, None, journal)

    assert result.setup.timestamp == datetime(2026, 4, 15, 14, 35, tzinfo=UTC)
    assert result.setup.timestamp.tzinfo is UTC
    assert require_pipeline_result(result) is result


def test_pipeline_result_issuance_rejects_naive_setup_timestamp_with_fixed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = _pipeline(tmp_path, monkeypatch)
    prepared, final_verdict, journal = _blocked_result_parts(pipeline)
    naive_setup = prepared.setup.model_copy(update={"timestamp": datetime(2026, 4, 15, 14, 35)})
    naive_prepared = prepared.model_copy(update={"setup": naive_setup})

    with pytest.raises(SealError, match="SEAL_INVALID_MODEL") as error:
        pipeline.result_from_prepared(naive_prepared, final_verdict, None, journal)

    assert error.value.__cause__ is None
    assert error.value.args == ("SEAL_INVALID_MODEL",)
