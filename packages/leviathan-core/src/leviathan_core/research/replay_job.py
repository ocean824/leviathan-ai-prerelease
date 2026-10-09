"""Deterministic, fixture-only bar replay through the guarded paper route.

The transaction port in this module is deliberately nondurable and is never
injected into the API.  A COMPLETE marker, rather than a JSONL entry, is the
authority for a published fixture result.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from itertools import pairwise
from pathlib import Path
from types import UnionType
from typing import Any, Literal, Union, get_args, get_origin

from pydantic import Field, StrictInt, ValidationError, model_validator
from pydantic_core import PydanticCustomError

from leviathan_core.decision.engine import CouncilDecisionEngine
from leviathan_core.execution.paper_sim import PaperExecutionEngine
from leviathan_core.pipeline import (
    LiveFlowPipeline,
    PipelineResult,
    PreparedReplay,
    require_pipeline_result,
)
from leviathan_core.risk.audit import RiskAuditLog
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.risk.policy import load_risk_policy_bytes
from leviathan_core.risk.route_guard import RouteGuard
from leviathan_core.risk.transaction_port import ClaimReceipt, RiskDecisionPort
from leviathan_core.risk.veto_engine import VetoEngine
from leviathan_core.schemas import (
    AccountState,
    Bar,
    CandidateSetup,
    DecisionPacket,
    EconomicEvent,
    ExecutionIntent,
    MarketState,
    Permission,
    RiskAction,
    RiskGateContext,
    RiskVerdict,
    StrategyGenome,
    TradeJournalRecord,
    TradeOutcome,
    TruthValidationResult,
)
from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.journal import require_trade_journal_record
from leviathan_core.schemas.risk import require_risk_verdict
from leviathan_core.seal import Issuer, SealError
from leviathan_core.seal import require as _seal_require
from leviathan_core.state.range_tracker import RangeContext
from leviathan_core.state.session_classifier import SessionContext
from leviathan_core.truth.provider import StaticTruthProvider

INPUT_SCHEMA = "leviathan.replay-input/1"
RESULT_SCHEMA = "leviathan.replay-result/1"
ENGINE_VERSION = "bar-bracket/1"
_SHA_HEX = frozenset("0123456789abcdef")
_TIMESTAMP_PREFIX = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.([0-9]+))?"
)
_TIMESTAMP_FULL = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z"
)
_TIME_KEYS = frozenset({
    "timestamp", "scheduled_at", "as_of", "source_ts", "exchange_ts",
    "received_at", "kill_expires_at",
})
_ROLE_PROFILES: dict[tuple[str, str], dict[str, int]] = {
    ("static_genome/1", "1"): {"primary": 1, "hedge": 1},
}


class ReplayJobError(ValueError):
    """A typed rejection that must never publish a successful result."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _nonempty(value: str, label: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{label} must be nonempty")


def _complete_fields(raw: Any, model_type: type[LeviathanModel], path: str) -> None:
    """Require fields with model defaults to be declared in fixture JSON too."""
    if not isinstance(raw, dict):
        return  # Pydantic supplies the type error.
    for name, field in model_type.model_fields.items():
        if name not in raw:
            raise ValueError(f"{path}.{name} must be explicitly present")
        annotation = field.annotation
        if annotation is not None:
            _complete_nested(raw[name], annotation, f"{path}.{name}")


def _complete_nested(raw: Any, annotation: Any, path: str) -> None:
    if isinstance(annotation, type) and issubclass(annotation, LeviathanModel):
        _complete_fields(raw, annotation, path)
        return
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin in (Union, UnionType):
        if raw is not None:
            for candidate in args:
                if candidate is not type(None):
                    _complete_nested(raw, candidate, path)
        return
    if origin in (tuple, list) and isinstance(raw, list) and args:
        for index, item in enumerate(raw):
            _complete_nested(item, args[0], f"{path}[{index}]")


class ReplayDataset(LeviathanModel):
    dataset_id: str
    dataset_version: str
    universe_version: str
    adjustment_mode: Literal["raw"]
    bars: tuple[Bar, ...]
    bars_sha256: str


class ReplayStrategy(LeviathanModel):
    strategy_ref: Literal["static_genome/1"]
    strategy_version: Literal["1"]
    genome: StrategyGenome


class ReplayTruth(LeviathanModel):
    truth_provider: Literal["static_truth/1"]
    result: TruthValidationResult


class ReplayDecisionInputs(LeviathanModel):
    prior_state: MarketState
    requested_size: Decimal
    stop_loss: Decimal | None
    take_profit: Decimal | None
    sector: str
    events: tuple[EconomicEvent, ...]


class ReplayFillModel(LeviathanModel):
    model_id: Literal["paper_bar_bracket/1"]
    slippage: Decimal
    order_type: Literal["market"]
    time_in_force: Literal["DAY"]
    same_bar_priority: Literal["stop_first"]


class ReplayStreamTopology(LeviathanModel):
    role: Literal["primary", "hedge"]
    stream_id: str
    instrument: str
    provider: str
    timeframe: str


class ReplayRiskInputs(LeviathanModel):
    context: RiskGateContext
    role_cardinality: dict[str, StrictInt]
    stream_topology: tuple[ReplayStreamTopology, ...]
    expected_lock_sha256: str
    initial_halts: tuple[str, ...]
    audit_policy: Literal["required_fsync/1"]


class ReplayRunSpec(LeviathanModel):
    schema_version: Literal["leviathan.replay-input/1"]
    engine_version: Literal["bar-bracket/1"]
    dataset: ReplayDataset
    strategy: ReplayStrategy
    setup: CandidateSetup
    truth: ReplayTruth
    account: AccountState
    decision_inputs: ReplayDecisionInputs
    fill_model: ReplayFillModel
    risk: ReplayRiskInputs
    seed: int = Field(ge=0, strict=True)

    @model_validator(mode="before")
    @classmethod
    def _complete_manifest(cls, raw: Any) -> Any:
        _check_timestamp_grammar(raw)
        _complete_fields(raw, cls, "manifest")
        return raw

    @model_validator(mode="after")
    def _validate_semantics(self) -> ReplayRunSpec:
        data = self.dataset
        _validate_time_and_numeric(self)
        for label, value in (
            ("dataset_id", data.dataset_id),
            ("dataset_version", data.dataset_version),
            ("universe_version", data.universe_version),
            ("strategy_id", self.strategy.genome.strategy_id),
            ("setup_id", self.setup.setup_id),
            ("sector", self.decision_inputs.sector),
        ):
            _nonempty(value, label)
        if not data.bars:
            raise ValueError("bars must be nonempty")
        if self.truth.result.setup_id != self.setup.setup_id:
            raise ValueError("truth.setup_id must match setup.setup_id")
        if self.setup.instrument != data.bars[0].instrument:
            raise ValueError("setup instrument must match bars")
        previous: datetime | None = None
        for bar in data.bars:
            if bar.instrument != self.setup.instrument:
                raise ValueError("mixed instruments are unsupported")
            if previous is not None and bar.timestamp <= previous:
                raise ValueError("bar timestamps must strictly increase")
            previous = bar.timestamp
            if any(not price.is_finite() or price <= 0 for price in (
                bar.open, bar.high, bar.low, bar.close
            )) or not bar.volume.is_finite() or bar.volume < 0:
                raise ValueError("bar price/volume is invalid")
        values = (
            self.account.equity, self.account.daily_pnl_pct,
            self.account.weekly_pnl_pct, self.account.trailing_dd_pct,
            self.decision_inputs.requested_size, self.fill_model.slippage,
        )
        if any(not item.is_finite() for item in values):
            raise ValueError("nonfinite numeric input")
        if self.decision_inputs.requested_size <= 0 or self.fill_model.slippage < 0:
            raise ValueError("requested_size must be positive and slippage nonnegative")
        for optional in (self.decision_inputs.stop_loss, self.decision_inputs.take_profit):
            if optional is not None and (not optional.is_finite() or optional <= 0):
                raise ValueError("stop_loss/take_profit must be positive and finite")
        if not _is_sha256(data.bars_sha256) or not _is_sha256(self.risk.expected_lock_sha256):
            raise ValueError("hash fields must be lowercase SHA-256 hex")
        if len(set(self.risk.initial_halts)) != len(self.risk.initial_halts):
            raise ValueError("initial_halts must be unique")
        for halt in self.risk.initial_halts:
            _nonempty(halt, "initial halt")
        self._validate_topology()
        if self.account.equity <= 0:
            raise ValueError("account equity must be positive")
        for position in self.account.open_positions:
            if position.size <= 0 or position.entry_price <= 0:
                raise ValueError("open position size and entry price must be positive")
        actual_bars_sha = _sha256(canonical_bytes(data.bars))
        if actual_bars_sha != data.bars_sha256:
            raise ValueError("bars_sha256 mismatch")
        return self

    def _validate_topology(self) -> None:
        """Prove the versioned role rule and C-101 streams describe one topology."""
        risk = self.risk
        expected_roles = _ROLE_PROFILES[(
            self.strategy.strategy_ref, self.strategy.strategy_version
        )]
        if risk.role_cardinality != expected_roles:
            raise PydanticCustomError(
                "input_topology_invalid", "role cardinality differs from strategy version"
            )
        topology = risk.stream_topology
        counts = {role: sum(item.role == role for item in topology) for role in expected_roles}
        if counts != expected_roles:
            raise PydanticCustomError(
                "input_topology_invalid", "stream roles do not satisfy declared cardinality"
            )
        keys: list[tuple[str, str, str]] = []
        for item in topology:
            if any(not value or not value.strip() for value in (
                item.stream_id, item.instrument, item.provider, item.timeframe
            )):
                raise PydanticCustomError(
                    "input_topology_invalid", "stream identity and timeframe must be nonempty"
                )
            if item.role == "primary" and (
                item.instrument != self.setup.instrument
                or item.timeframe != self.strategy.genome.timeframe
            ):
                raise PydanticCustomError(
                    "input_topology_invalid", "primary instrument/timeframe differs from strategy"
                )
            if item.role == "hedge" and item.instrument == self.setup.instrument:
                raise PydanticCustomError(
                    "input_topology_invalid", "hedge instrument must differ from primary"
                )
            keys.append((item.stream_id, item.instrument, item.provider))
        if len(set(keys)) != len(keys):
            raise PydanticCustomError(
                "input_topology_invalid", "duplicate stream topology identity"
            )
        required = [(item.stream_id, item.symbol, item.provider) for item in risk.context.required]
        observed = [(item.stream_id, item.symbol, item.provider) for item in risk.context.observed]
        if (
            len(required) != len(keys) or len(observed) != len(keys)
            or set(required) != set(keys) or set(observed) != set(keys)
        ):
            raise PydanticCustomError(
                "input_topology_invalid", "required/observed streams differ from topology"
            )


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in _SHA_HEX for char in value)


def _validate_time_and_numeric(value: Any) -> None:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("all timestamps must be timezone-aware")
    elif isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("nonfinite decimal input")
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("nonfinite float input")
    elif isinstance(value, LeviathanModel):
        for name in type(value).model_fields:
            _validate_time_and_numeric(getattr(value, name))
    elif isinstance(value, (list, tuple)):
        for item in value:
            _validate_time_and_numeric(item)
    elif isinstance(value, dict):
        for item in value.values():
            _validate_time_and_numeric(item)


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        raise ReplayJobError("INVALID_NUMERIC", "nonfinite decimal")
    if not value:
        return "0"
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _canonical_tree(value: Any) -> Any:
    if isinstance(value, LeviathanModel):
        return _canonical_tree(value.model_dump(mode="python"))
    if isinstance(value, Enum):
        return _canonical_tree(value.value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ReplayJobError("INVALID_TIMESTAMP", "naive datetime")
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, Decimal):
        return _decimal_text(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ReplayJobError("INVALID_NUMERIC", "nonfinite float")
        return _decimal_text(Decimal(str(value)))
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, (tuple, list)):
        return [_canonical_tree(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReplayJobError("INVALID_CANONICAL_KEY", "object keys must be strings")
            nfc_key = unicodedata.normalize("NFC", key)
            if nfc_key in normalized:
                raise ReplayJobError("CANONICAL_KEY_COLLISION", nfc_key)
            normalized[nfc_key] = _canonical_tree(item)
        return normalized
    raise ReplayJobError("INVALID_CANONICAL_TYPE", type(value).__name__)


def canonical_bytes(value: Any) -> bytes:
    """Typed values to NFC, sorted-key, compact UTF-8 JSON without a newline.

    Decimal and finite float values become plain decimal strings.  Datetimes
    become UTC timestamps with exactly six fractional digits.  Arrays retain
    their declared order, and NFC key collisions fail rather than overwrite.
    """
    tree = _canonical_tree(value)
    return json.dumps(
        tree, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    seen: set[str] = set()
    for key, value in pairs:
        normalized = unicodedata.normalize("NFC", key)
        if normalized in seen:
            raise ReplayJobError("CANONICAL_KEY_COLLISION", normalized)
        seen.add(normalized)
        result[key] = value
    return result


def _check_timestamp_grammar(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in _TIME_KEYS and item is not None:
                if not isinstance(item, str):
                    raise ReplayJobError("TIMESTAMP_INVALID", f"{key} must be RFC 3339 text")
                prefix = _TIMESTAMP_PREFIX.match(item)
                fraction = prefix.group(1) if prefix is not None else None
                if fraction is not None and len(fraction) > 6:
                    raise ReplayJobError(
                        "TIMESTAMP_PRECISION_UNSUPPORTED", f"{key} exceeds six digits"
                    )
                if _TIMESTAMP_FULL.fullmatch(item) is None:
                    raise ReplayJobError(
                        "TIMESTAMP_INVALID", f"{key} requires uppercase Z RFC 3339"
                    )
            _check_timestamp_grammar(item)
    elif isinstance(value, list):
        for item in value:
            _check_timestamp_grammar(item)


def _load_spec(path: Path) -> ReplayRunSpec:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReplayJobError("INVALID_MANIFEST", str(exc)) from exc
    if not isinstance(raw, dict):
        raise ReplayJobError("INVALID_MANIFEST", "manifest must be an object")
    _check_timestamp_grammar(raw)
    if raw.get("schema_version") != INPUT_SCHEMA or raw.get("engine_version") != ENGINE_VERSION:
        raise ReplayJobError("UNSUPPORTED_VERSION", "replay input or engine version")
    strategy = raw.get("strategy")
    if isinstance(strategy, dict) and (
        strategy.get("strategy_ref") != "static_genome/1"
        or strategy.get("strategy_version") != "1"
    ):
        raise ReplayJobError("UNSUPPORTED_VERSION", "strategy ref/version")
    truth = raw.get("truth")
    if isinstance(truth, dict) and truth.get("truth_provider") != "static_truth/1":
        raise ReplayJobError("UNSUPPORTED_VERSION", "truth provider")
    fill = raw.get("fill_model")
    if isinstance(fill, dict) and fill.get("model_id") != "paper_bar_bracket/1":
        raise ReplayJobError("UNSUPPORTED_VERSION", "fill model")
    dataset = raw.get("dataset")
    if isinstance(dataset, dict) and dataset.get("adjustment_mode") != "raw":
        raise ReplayJobError("UNSUPPORTED_MODE", "dataset adjustment mode")
    if isinstance(fill, dict) and any((
        fill.get("order_type") != "market", fill.get("time_in_force") != "DAY",
        fill.get("same_bar_priority") != "stop_first",
    )):
        raise ReplayJobError("UNSUPPORTED_MODE", "paper fill settings")
    risk = raw.get("risk")
    if isinstance(risk, dict) and risk.get("audit_policy") != "required_fsync/1":
        raise ReplayJobError("UNSUPPORTED_MODE", "audit policy")
    if isinstance(risk, dict):
        topology = risk.get("stream_topology")
        if "role_cardinality" not in risk or not isinstance(topology, list):
            raise ReplayJobError("INPUT_TOPOLOGY_INVALID", "role rule/topology is missing")
        required_keys = {"role", "stream_id", "instrument", "provider", "timeframe"}
        if any(not isinstance(item, dict) or not required_keys <= item.keys() for item in topology):
            raise ReplayJobError("INPUT_TOPOLOGY_INVALID", "stream topology entry is incomplete")
    try:
        return ReplayRunSpec.model_validate(raw)
    except ValidationError as exc:
        if any(
            error["type"] == "input_topology_invalid"
            or error["loc"][:2] in (
                ("risk", "role_cardinality"), ("risk", "stream_topology")
            )
            for error in exc.errors()
        ):
            raise ReplayJobError("INPUT_TOPOLOGY_INVALID", str(exc)) from exc
        raise ReplayJobError("INVALID_MANIFEST", str(exc)) from exc
    except ValueError as exc:
        raise ReplayJobError("INVALID_MANIFEST", str(exc)) from exc


class _FixtureDecisionPort(RiskDecisionPort):
    """Single-use C-101 transaction sequence with no production persistence."""

    def __init__(self, prepared: PreparedReplay, policy_digest: str) -> None:
        self.prepared = prepared
        self.policy_digest = policy_digest
        self.state: str | None = None
        self.token: str | None = None
        self.final_verdict: RiskVerdict | None = None
        self.journal: TradeJournalRecord | None = None
        self.events: list[dict[str, Any]] = []

    def _event(self, phase: str, verdict: RiskVerdict, final: bool) -> None:
        self.events.append({
            "phase": phase,
            "seq": len(self.events) + 1,
            "action": verdict.action.value,
            "reason": verdict.reason,
            "findings": [finding.value for finding in verdict.findings],
            "final": final,
        })

    async def prepare(
        self, setup: CandidateSetup, decision: DecisionPacket,
        assessment: RiskVerdict, evidence: dict[str, Any],
    ) -> None:
        if self.state is not None or (
            setup != self.prepared.setup or decision != self.prepared.decision
            or assessment != self.prepared.assessment
            or evidence != {"candidate": self.prepared.candidate_payload(self.policy_digest)}
        ):
            raise ReplayJobError("TRANSACTION_INVALID", "invalid fixture candidate")
        self.state = "PENDING"
        self._event("assessment", assessment, False)

    async def authorize(self, decision_id: str, paper_draft: dict[str, Any]) -> None:
        if (
            self.state != "PENDING" or not self.prepared.actionable
            or decision_id != self.prepared.decision.decision_id
            or paper_draft != self.prepared.paper_draft(self.policy_digest)
        ):
            raise ReplayJobError("TRANSACTION_INVALID", "invalid fixture authorization")
        self.state = "AUTHORIZED"
        self._event("authorization", self.prepared.assessment, False)

    async def claim(self, decision_id: str, token: str) -> ClaimReceipt | None:
        if (
            self.state != "AUTHORIZED" or decision_id != self.prepared.decision.decision_id
            or not token
        ):
            return None
        self.state = "IN_PROGRESS"
        self.token = token
        self._event("claim", self.prepared.assessment, False)
        return ClaimReceipt(
            decision_id, token, 2, self.policy_digest,
            self.prepared.candidate_identity(self.policy_digest),
        )

    async def complete(
        self, receipt: ClaimReceipt | None, setup: CandidateSetup,
        decision: DecisionPacket, verdict: RiskVerdict, journal: TradeJournalRecord,
    ) -> None:
        if (
            setup != self.prepared.setup or decision != self.prepared.decision
            or verdict.decision_id != decision.decision_id
            or journal.decision_id != decision.decision_id
            or journal.setup_id != setup.setup_id
        ):
            raise ReplayJobError("TRANSACTION_INVALID", "terminal links differ")
        if receipt is None:
            if self.state != "PENDING" or self.prepared.actionable:
                raise ReplayJobError("TRANSACTION_INVALID", "unclaimed block differs")
            if verdict != self.prepared.assessment:
                permission = self.prepared.decision.permission
                expected_action = (
                    RiskAction.WAIT if permission is Permission.WAIT else RiskAction.REJECT
                )
                if (
                    permission is Permission.APPROVE
                    or self.prepared.assessment.action
                    not in (RiskAction.ALLOW, RiskAction.REDUCE_SIZE)
                    or not self.prepared.assessment.execution_capable
                    or verdict.action is not expected_action
                    or verdict.reason != f"council_permission_{permission.value}"
                    or verdict.adjusted_size is not None
                    or verdict.execution_capable
                    or verdict.findings != self.prepared.assessment.findings
                    or verdict.halts_engaged != self.prepared.assessment.halts_engaged
                    or journal.post_trade_notes != (
                        f"blocked: permission={permission.value} "
                        f"risk={verdict.action.value} reason={verdict.reason} "
                        f"halts={','.join(self.prepared.assessment.halts_engaged)}"
                    )
                ):
                    raise ReplayJobError("TRANSACTION_INVALID", "unclaimed block differs")
            if verdict.action in (RiskAction.ALLOW, RiskAction.REDUCE_SIZE):
                raise ReplayJobError(
                    "TRANSACTION_INCOMPLETE", "unclaimed allow assessment cannot complete"
                )
        elif (
            self.state != "IN_PROGRESS" or self.token != receipt.token
            or receipt.decision_id != decision.decision_id or receipt.version != 2
            or receipt.policy_digest != self.policy_digest
            or receipt.candidate_identity != self.prepared.candidate_identity(self.policy_digest)
        ):
            raise ReplayJobError("TRANSACTION_INVALID", "claim receipt differs")
        executed = receipt is not None and verdict.action in (
            RiskAction.ALLOW, RiskAction.REDUCE_SIZE
        )
        if executed and verdict != self.prepared.assessment:
            raise ReplayJobError("TRANSACTION_INVALID", "executed verdict differs")
        if not executed and (
            journal.outcome is not TradeOutcome.BLOCKED
            or journal.entry is not None or journal.exit is not None
            or journal.mae is not None or journal.mfe is not None
        ):
            raise ReplayJobError("TRANSACTION_INVALID", "blocked route has executed journal")
        self.state = "COMPLETED" if executed else "BLOCKED"
        self.final_verdict = verdict
        self.journal = journal
        self._event("completion", verdict, True)

    async def read_view(self, decision_id: str) -> dict[str, Any] | None:
        if decision_id != self.prepared.decision.decision_id or self.state is None:
            return None
        terminal = self.state in ("COMPLETED", "BLOCKED")
        return {
            "decision_id": decision_id, "status": self.state.lower(),
            "final": terminal,
            "final_verdict": self.final_verdict.model_dump(mode="python")
            if terminal and self.final_verdict else None,
            "journal_record": self.journal.model_dump(mode="python")
            if terminal and self.journal else None,
        }


@dataclass(frozen=True)
class ReplayArtifacts:
    input_sha256: str
    result_sha256: str
    input_path: Path
    result_path: Path
    complete_path: Path

_VERIFIED_REPLAY_ISSUER = Issuer("research.replay_artifacts.verified.v1")


_REPLAY_ARTIFACT_NAMES = frozenset(
    {
        "input.canonical.json",
        "input.sha256",
        "result.canonical.json",
        "result.sha256",
        "diagnostics.json",
        "risk_audit.jsonl",
    }
)


class VerifiedReplayArtifactsV1(LeviathanModel):
    """Read-back checked C-102 evidence with no filesystem authority."""

    schema_version: Literal["leviathan.replay-verified/1"]
    status: Literal["COMPLETE"]
    input_sha256: str
    result_sha256: str
    artifact_root: str
    strategy_ref: str
    strategy_id: str
    strategy_version: str
    dataset_id: str
    dataset_version: str
    bars_sha256: str
    first_bar_ns: StrictInt
    last_bar_ns: StrictInt
    truth_provider: str
    truth_status: str
    truth_sha256: str
    verified_lock_sha256: str
    result_status: str
    artifact_sha256: tuple[tuple[str, str], ...]
    provenance: Literal["C102_COMPLETE_REHASHED"]


class ReplayResultArtifactV1(LeviathanModel):
    """Strict typed form of the persisted C-102 semantic result projection."""

    schema_version: Literal["leviathan.replay-result/1"]
    input_sha256: str
    bars_sha256: str
    verified_lock_sha256: str
    engine_version: Literal["bar-bracket/1"]
    seed: StrictInt
    status: Literal["completed", "blocked"]
    session: SessionContext
    range: RangeContext | None
    truth: TruthValidationResult
    decision: DecisionPacket
    assessment: RiskVerdict
    final_verdict: RiskVerdict
    audit_events: tuple[dict[str, Any], ...]
    intent: ExecutionIntent | None
    journal: TradeJournalRecord


def require_verified_replay_artifacts(value: object) -> VerifiedReplayArtifactsV1:
    """Require an exact, locally issued replay read-back result."""
    if type(value) is not VerifiedReplayArtifactsV1:
        raise ReplayJobError("ARTIFACT_INVALID", "replay artifact evidence is invalid")
    try:
        return _seal_require(value, _VERIFIED_REPLAY_ISSUER.tag)
    except SealError:
        raise ReplayJobError("ARTIFACT_INVALID", "replay artifact evidence is invalid") from None


def _timestamp_ns(value: datetime) -> int:
    delta = value.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000



async def _route(spec: ReplayRunSpec, lock_path: Path, output_dir: Path) -> tuple[
    PipelineResult, _FixtureDecisionPort
]:
    expected = spec.risk.expected_lock_sha256
    try:
        lock_bytes = lock_path.read_bytes()
    except OSError as exc:
        raise ReplayJobError("LOCK_INVALID", "fixture lock cannot be read") from exc
    if _sha256(lock_bytes) != expected:
        raise ReplayJobError("LOCK_HASH_MISMATCH", "fixture lock differs from pinned hash")
    try:
        policy = load_risk_policy_bytes(lock_bytes)
    except Exception as exc:
        raise ReplayJobError("LOCK_INVALID", "fixture lock policy is invalid") from exc
    halts = HaltAuthority()
    for reason in spec.risk.initial_halts:
        halts.engage(reason)
    guard = RouteGuard(lock_path, expected, bound_policy_sha256=expected)
    veto = VetoEngine(
        policy, halts, RiskAuditLog(output_dir / "c101_diagnostic.jsonl"),
        lock_path=lock_path, expected_lock_sha256=expected, route_guard=guard,
    )
    pipeline = LiveFlowPipeline(
        StaticTruthProvider(spec.truth.result), CouncilDecisionEngine(), veto,
        PaperExecutionEngine(spec.fill_model.slippage), risk_lock_sha256=expected,
        kill_state_provider=lambda: spec.risk.context.kill,
    )
    decision_inputs = spec.decision_inputs
    # RangeTracker groups by datetime.date(); feed it UTC so two manifests
    # describing the same instants have the same semantics and canonical bytes.
    utc_bars = tuple(
        bar.model_copy(update={"timestamp": bar.timestamp.astimezone(UTC)})
        for bar in spec.dataset.bars
    )
    prepared = pipeline.prepare_replay(
        spec.setup, utc_bars, spec.account, genome=spec.strategy.genome,
        prior_state=decision_inputs.prior_state,
        requested_size=decision_inputs.requested_size,
        stop_loss=decision_inputs.stop_loss,
        take_profit=decision_inputs.take_profit,
        events=decision_inputs.events, sector=decision_inputs.sector,
        context=spec.risk.context,
    )
    port = _FixtureDecisionPort(prepared, expected)
    await port.prepare(
        prepared.setup, prepared.decision, prepared.assessment,
        {"candidate": prepared.candidate_payload(expected)},
    )
    if prepared.actionable:
        await port.authorize(prepared.decision.decision_id, prepared.paper_draft(expected))
        receipt = await port.claim(prepared.decision.decision_id, "fixture-claim")
        if receipt is None:
            raise ReplayJobError("TRANSACTION_INCOMPLETE", "claim was not confirmed")
        final, intent, journal = pipeline.consume_claimed(prepared, receipt)
        await port.complete(receipt, prepared.setup, prepared.decision, final, journal)
    else:
        final, journal = pipeline.block_prepared(prepared)
        intent = None
        await port.complete(None, prepared.setup, prepared.decision, final, journal)
    view = await port.read_view(prepared.decision.decision_id)
    if (
        view is None or view["final"] is not True
        or port.final_verdict != final or port.journal != journal
    ):
        raise ReplayJobError("TRANSACTION_INCOMPLETE", "terminal readback is not final")
    # Check the fixture locator again after the guarded route. A changed file
    # cannot publish an approved or blocked success from old policy bytes.
    try:
        observed = _sha256(lock_path.read_bytes())
    except OSError as exc:
        raise ReplayJobError("LOCK_HASH_MISMATCH", "post-route lock unreadable") from exc
    if observed != expected:
        raise ReplayJobError("LOCK_HASH_MISMATCH", "post-route lock changed")
    result = pipeline.result_from_prepared(
        prepared, final, intent, journal,
        status="completed" if intent is not None else "blocked",
    )
    return result, port


def _semantic_result(
    spec: ReplayRunSpec, result: PipelineResult, port: _FixtureDecisionPort,
    input_sha: str,
) -> dict[str, Any]:
    result = _require_complete_pipeline_result(result)
    setup_id = result.setup.setup_id
    decision_id = result.decision.decision_id
    journal = result.journal_record
    final_verdict = result.final_verdict
    if final_verdict is None or journal is None:
        raise ReplayJobError("TRANSACTION_INCOMPLETE", "nullable final cannot be published")
    if (
        result.truth.setup_id != setup_id or result.decision.setup_id != setup_id
        or result.verdict.decision_id != decision_id
        or final_verdict.decision_id != decision_id
        or journal.setup_id != setup_id or journal.decision_id != decision_id
    ):
        raise ReplayJobError("LINK_MISMATCH", "setup/decision/journal links differ")
    intent = result.intent
    if intent is not None and (
        intent.decision_id != decision_id
        or port.prepared.risk_snapshot is None
        or intent.risk_session_id != port.prepared.risk_snapshot.session_id
    ):
        raise ReplayJobError("LINK_MISMATCH", "intent risk link differs")
    if result.status == "blocked" and intent is not None:
        raise ReplayJobError("LINK_MISMATCH", "blocked route has intent")
    truth = result.truth.model_dump(mode="python")
    truth["setup_id"] = "setup"
    decision = result.decision.model_dump(mode="python")
    decision.update(decision_id="decision", setup_id="setup")
    assessment = result.verdict.model_dump(mode="python")
    assessment["decision_id"] = "decision"
    final = final_verdict.model_dump(mode="python")
    final["decision_id"] = "decision"
    journal_data = journal.model_dump(mode="python")
    journal_data.update(trade_id="trade", setup_id="setup", decision_id="decision")
    intent_data = None
    if intent is not None:
        intent_data = intent.model_dump(mode="python")
        intent_data.update(decision_id="decision", risk_session_id="risk_session")
    return {
        "schema_version": RESULT_SCHEMA,
        "input_sha256": input_sha,
        "bars_sha256": spec.dataset.bars_sha256,
        "verified_lock_sha256": spec.risk.expected_lock_sha256,
        "engine_version": spec.engine_version,
        "seed": spec.seed,
        "status": result.status,
        "session": result.session,
        "range": result.range_context,
        "truth": truth,
        "decision": decision,
        "assessment": assessment,
        "final_verdict": final,
        "audit_events": _diagnostic_events(port),
        "intent": intent_data,
        "journal": journal_data,
    }


def _atomic_bytes(path: Path, data: bytes) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _diagnostic_events(port: _FixtureDecisionPort) -> list[dict[str, Any]]:
    """The exact records shared by the semantic result and diagnostic file."""
    return [
        {**event, "decision_id": "decision", "authority": "fixture_nondurable_diagnostic"}
        for event in port.events
    ]


def _diagnostic_bytes(port: _FixtureDecisionPort) -> bytes:
    # The JSONL projection is explicitly nonauthoritative under C-101 v0.4.
    return b"".join(_diagnostic_line(event) for event in _diagnostic_events(port))

def _diagnostic_line(event: dict[str, Any]) -> bytes:
    """Preserve the exact JSONL line bytes used by C-102 publication."""
    return json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _require_complete_pipeline_result(value: object) -> PipelineResult:
    """Require issued terminal C-101 records before replay publication."""
    try:
        result = require_pipeline_result(value)
        if (
            not result.final
            or result.status not in {"completed", "blocked"}
            or result.final_verdict is None
            or result.journal_record is None
        ):
            raise ReplayJobError("TRANSACTION_INCOMPLETE", "nullable final cannot be published")
        require_risk_verdict(result.final_verdict)
        require_trade_journal_record(result.journal_record)
        return result
    except SealError:
        raise ReplayJobError(
            "TRANSACTION_INCOMPLETE", "pipeline evidence is not issued"
        ) from None



def _verify_diagnostic(path: Path, port: _FixtureDecisionPort) -> None:
    if port.final_verdict is None:
        raise ReplayJobError("AUDIT_SINK_FAILURE", "transaction has no final verdict")
    try:
        observed = path.read_bytes()
    except OSError as exc:
        raise ReplayJobError("AUDIT_SINK_FAILURE", "diagnostic readback failed") from exc
    if (
        not port.events or port.events[-1]["phase"] != "completion"
        or port.events[-1]["final"] is not True
        or port.events[-1]["action"] != port.final_verdict.action.value
        or observed != _diagnostic_bytes(port)
    ):
        raise ReplayJobError("AUDIT_SINK_FAILURE", "diagnostic event set differs")


def _publish_failure(output_dir: Path, error: ReplayJobError) -> None:
    """Leave only nonauthoritative terminal failure evidence in a fresh run dir."""
    audit = {
        "phase": "failure", "seq": 1, "action": "reject", "reason": error.code,
        "findings": [error.code], "final": True, "decision_id": None,
        "authority": "fixture_nondurable_diagnostic", "terminal_failure": True,
    }
    diagnostic = {
        "schema_version": "leviathan.replay-diagnostics/1",
        "status": "failed", "error_code": error.code,
        "transaction_authority": "isolated_nondurable_fixture_port",
        "jsonl_authority": "diagnostic_only",
    }
    try:
        _atomic_bytes(output_dir / "risk_audit.jsonl", canonical_bytes(audit) + b"\n")
        _atomic_bytes(output_dir / "diagnostics.json", canonical_bytes(diagnostic))
    except OSError as exc:
        raise ReplayJobError(
            "AUDIT_SINK_FAILURE", "terminal failure evidence could not be written"
        ) from exc


def run_replay_job(fixture: Path, risk_lock: Path, output_dir: Path) -> ReplayArtifacts:
    """Run a declared fixture and publish only a complete checked artifact set."""
    if output_dir.exists():
        if not output_dir.is_dir():
            raise ReplayJobError("OUTPUT_NOT_EMPTY", "output path is not a directory")
        if any(output_dir.iterdir()):
            raise ReplayJobError("OUTPUT_NOT_EMPTY", "existing output directory is nonempty")
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReplayJobError("OUTPUT_UNAVAILABLE", "output directory cannot be created") from exc
    if any(output_dir.iterdir()):
        raise ReplayJobError("OUTPUT_NOT_EMPTY", "output directory became nonempty")
    result_path = output_dir / "result.canonical.json"
    complete_path = output_dir / "COMPLETE"
    try:
        spec = _load_spec(fixture)
        input_bytes = canonical_bytes(spec)
        input_sha = _sha256(input_bytes)
        result, port = asyncio.run(_route(spec, risk_lock, output_dir))
        audit_path = output_dir / "risk_audit.jsonl"
        try:
            _atomic_bytes(audit_path, _diagnostic_bytes(port))
        except OSError as exc:
            raise ReplayJobError("AUDIT_SINK_FAILURE", "diagnostic fsync failed") from exc
        _verify_diagnostic(audit_path, port)
        result_bytes = canonical_bytes(_semantic_result(spec, result, port, input_sha))
        result_sha = _sha256(result_bytes)
        diagnostics = canonical_bytes({
            "schema_version": "leviathan.replay-diagnostics/1",
            "transaction_authority": "isolated_nondurable_fixture_port",
            "jsonl_authority": "diagnostic_only",
            "status": result.status,
            "audit_events": len(port.events),
        })
        payloads = {
            "input.canonical.json": input_bytes,
            "input.sha256": (input_sha + "\n").encode("ascii"),
            "result.canonical.json": result_bytes,
            "result.sha256": (result_sha + "\n").encode("ascii"),
            "diagnostics.json": diagnostics,
        }
        for name, contents in payloads.items():
            _atomic_bytes(output_dir / name, contents)
        file_hashes = {name: _sha256(contents) for name, contents in payloads.items()}
        file_hashes["risk_audit.jsonl"] = _sha256(audit_path.read_bytes())
        for name, digest in file_hashes.items():
            if _sha256((output_dir / name).read_bytes()) != digest:
                raise ReplayJobError("ARTIFACT_MISMATCH", f"{name} changed before COMPLETE")
        # Revalidate the same terminal evidence at the final publication boundary.
        _require_complete_pipeline_result(result)
        marker = canonical_bytes({
            "schema_version": "leviathan.replay-complete/1",
            "files": file_hashes,
            "input_sha256": input_sha,
            "result_sha256": result_sha,
        })
        _atomic_bytes(complete_path, marker)
        return ReplayArtifacts(
            input_sha, result_sha, output_dir / "input.canonical.json",
            result_path, complete_path,
        )
    except Exception as exc:
        for name in (
            "COMPLETE", "result.canonical.json", "result.sha256",
            "input.canonical.json", "input.sha256",
        ):
            (output_dir / name).unlink(missing_ok=True)
        failure = (
            exc if isinstance(exc, ReplayJobError)
            else ReplayJobError("REPLAY_FAILED", type(exc).__name__)
        )
        _publish_failure(output_dir, failure)
        if failure is exc:
            raise
        raise failure from exc

def _reject_reparse_point(path: Path) -> None:
    """Reject links/reparse points along the replay root and its file entries."""
    candidate = path
    while True:
        try:
            stat_result = candidate.lstat()
        except OSError:
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid") from None
        reparse_flag = getattr(stat_result, "st_file_attributes", 0) & 0x400
        if candidate.is_symlink() or reparse_flag:
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent


def _check_replay_root(root: Path) -> None:
    _reject_reparse_point(root)
    if not root.is_dir():
        raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")
    entries = tuple(root.iterdir())
    # Inspect entries before checking topology so an unexpected junction is
    # rejected as a reparse point, even though it is also an extra path.
    for entry in entries:
        _reject_reparse_point(entry)
    expected_names = _REPLAY_ARTIFACT_NAMES | {"COMPLETE"}
    if {entry.name for entry in entries} != expected_names:
        raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")
    if any(not entry.is_file() for entry in entries):
        raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")


def verify_replay_artifacts(artifacts: ReplayArtifacts) -> VerifiedReplayArtifactsV1:
    """Re-read and verify the complete six-file manifest and COMPLETE marker.

    The function is read-only. Its successful result is the only C-102 artifact
    record that downstream promotion/reporting code should consume.
    """
    try:
        if type(artifacts) is not ReplayArtifacts:
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")
        expected_paths = {
            "input.canonical.json": artifacts.input_path,
            "result.canonical.json": artifacts.result_path,
            "COMPLETE": artifacts.complete_path,
        }
        root = artifacts.complete_path.parent
        if any(path.parent != root or path.name != name for name, path in expected_paths.items()):
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")
        _check_replay_root(root)
        resolved_root = root.resolve(strict=True)

        # The published directory is a closed artifact bundle: six manifest
        # members plus the COMPLETE marker, with no hidden or extra entries.
        complete_bytes = (root / "COMPLETE").read_bytes()
        complete = json.loads(complete_bytes, object_pairs_hook=_unique_pairs)
        if (
            type(complete) is not dict
            or canonical_bytes(complete) != complete_bytes
            or set(complete) != {"schema_version", "files", "input_sha256", "result_sha256"}
            or complete.get("schema_version") != "leviathan.replay-complete/1"
        ):
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")

        manifest_files = complete.get("files")
        if type(manifest_files) is not dict or set(manifest_files) != _REPLAY_ARTIFACT_NAMES:
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")
        if any(
            type(name) is not str
            or type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest, re.ASCII) is None
            for name, digest in manifest_files.items()
        ):
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")

        file_bytes = {name: (root / name).read_bytes() for name in _REPLAY_ARTIFACT_NAMES}
        computed = {name: _sha256(contents) for name, contents in file_bytes.items()}
        if computed != manifest_files:
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")
        input_sha = computed["input.canonical.json"]
        result_sha = computed["result.canonical.json"]
        if (
            complete.get("input_sha256") != input_sha
            or complete.get("result_sha256") != result_sha
            or artifacts.input_sha256 != input_sha
            or artifacts.result_sha256 != result_sha
            or file_bytes["input.sha256"] != (input_sha + "\n").encode("ascii")
            or file_bytes["result.sha256"] != (result_sha + "\n").encode("ascii")
        ):
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")

        spec = _load_spec(root / "input.canonical.json")
        if canonical_bytes(spec) != file_bytes["input.canonical.json"]:
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")
        bars = spec.dataset.bars
        if not bars or any(
            earlier.timestamp >= later.timestamp for earlier, later in pairwise(bars)
        ):
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")
        result_payload = json.loads(
            file_bytes["result.canonical.json"], object_pairs_hook=_unique_pairs
        )
        if (
            type(result_payload) is not dict
            or canonical_bytes(result_payload) != file_bytes["result.canonical.json"]
            or result_payload.get("schema_version") != RESULT_SCHEMA
            or result_payload.get("input_sha256") != input_sha
            or result_payload.get("bars_sha256") != spec.dataset.bars_sha256
            or result_payload.get("verified_lock_sha256") != spec.risk.expected_lock_sha256
        ):
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")

        expected_truth = json.loads(canonical_bytes(spec.truth.result.model_dump(mode="python")))
        expected_truth["setup_id"] = "setup"
        if result_payload.get("truth") != expected_truth:
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")

        diagnostics = json.loads(file_bytes["diagnostics.json"], object_pairs_hook=_unique_pairs)
        if (
            type(diagnostics) is not dict
            or canonical_bytes(diagnostics) != file_bytes["diagnostics.json"]
            or diagnostics.get("schema_version") != "leviathan.replay-diagnostics/1"
            or diagnostics.get("transaction_authority") != "isolated_nondurable_fixture_port"
            or diagnostics.get("jsonl_authority") != "diagnostic_only"
            or diagnostics.get("status") != result_payload.get("status")
            or type(diagnostics.get("audit_events")) is not int
        ):
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")
        audit_bytes = file_bytes["risk_audit.jsonl"]
        try:
            audit_rows = [
                json.loads(line, object_pairs_hook=_unique_pairs)
                for line in audit_bytes.decode("utf-8").splitlines()
            ]
        except (UnicodeError, json.JSONDecodeError):
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid") from None
        if (
            not audit_rows
            or any(
                type(row) is not dict or _diagnostic_line(row) != line
                for row, line in zip(audit_rows, audit_bytes.splitlines(keepends=True), strict=True)
            )
            or diagnostics["audit_events"] != len(audit_rows)
            or result_payload.get("audit_events") != audit_rows
        ):
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid")

        issued = _VERIFIED_REPLAY_ISSUER.issue(
            VerifiedReplayArtifactsV1(
                schema_version="leviathan.replay-verified/1",
                status="COMPLETE",
                input_sha256=input_sha,
                result_sha256=result_sha,
                artifact_root=str(resolved_root),
                strategy_ref=spec.strategy.strategy_ref,
                strategy_id=spec.strategy.genome.strategy_id,
                strategy_version=spec.strategy.strategy_version,
                dataset_id=spec.dataset.dataset_id,
                dataset_version=spec.dataset.dataset_version,
                bars_sha256=spec.dataset.bars_sha256,
                first_bar_ns=_timestamp_ns(bars[0].timestamp),
                last_bar_ns=_timestamp_ns(bars[-1].timestamp),
                truth_provider=spec.truth.truth_provider,
                truth_status=spec.truth.result.truth_status,
                truth_sha256=_sha256(canonical_bytes(spec.truth)),
                verified_lock_sha256=spec.risk.expected_lock_sha256,
                result_status=result_payload["status"],
                artifact_sha256=tuple(sorted(computed.items())),
                provenance="C102_COMPLETE_REHASHED",
            )
        )
        return require_verified_replay_artifacts(issued)
    except ReplayJobError as exc:
        if exc.code == "ARTIFACT_INVALID":
            raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid") from None
        raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid") from None
    except Exception:
        raise ReplayJobError("ARTIFACT_INVALID", "replay artifact set is invalid") from None


def load_verified_replay_result(
    verified: VerifiedReplayArtifactsV1,
) -> ReplayResultArtifactV1:
    """Read and strictly parse the result only after rechecking its issued digest."""
    try:
        evidence = require_verified_replay_artifacts(verified)
        root = Path(evidence.artifact_root)
        _reject_reparse_point(root)
        resolved_root = root.resolve(strict=True)
        if str(resolved_root) != evidence.artifact_root:
            raise ReplayJobError("ARTIFACT_INVALID", "replay result evidence is invalid")
        _check_replay_root(root)
        result_path = root / "result.canonical.json"
        expected = dict(evidence.artifact_sha256).get("result.canonical.json")
        contents = result_path.read_bytes()
        if expected is None or _sha256(contents) != expected or expected != evidence.result_sha256:
            raise ReplayJobError("ARTIFACT_INVALID", "replay result evidence is invalid")
        result = ReplayResultArtifactV1.model_validate_json(contents)
        if canonical_bytes(result.model_dump(mode="json")) != contents:
            raise ReplayJobError("ARTIFACT_INVALID", "replay result evidence is invalid")
        if (
            result.input_sha256 != evidence.input_sha256
            or result.bars_sha256 != evidence.bars_sha256
            or result.verified_lock_sha256 != evidence.verified_lock_sha256
            or result.status != evidence.result_status
        ):
            raise ReplayJobError("ARTIFACT_INVALID", "replay result evidence is invalid")
        return result
    except ReplayJobError:
        raise ReplayJobError("ARTIFACT_INVALID", "replay result evidence is invalid") from None
    except Exception:
        raise ReplayJobError("ARTIFACT_INVALID", "replay result evidence is invalid") from None



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic fixture-only guarded bar replay")
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--risk-lock", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        artifacts = run_replay_job(args.fixture, args.risk_lock, args.output_dir)
    except ReplayJobError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"REPLAY_FAILED: {exc}", file=sys.stderr)
        return 2
    print(f"input_sha256={artifacts.input_sha256} {artifacts.input_path}")
    print(f"result_sha256={artifacts.result_sha256} {artifacts.result_path}")
    print(f"complete={artifacts.complete_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
