"""Pure advisory decision proposal from independently evaluated kernel results."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import InitVar, dataclass, fields, is_dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum, StrEnum
from fractions import Fraction
from typing import Annotated, Any, Literal, NoReturn, SupportsIndex, cast

from pydantic import BaseModel, Field, StringConstraints

from leviathan_core.decision_fusion.models import FeatureAttributionV1, FusionResultV1
from leviathan_core.feature_store.models import FeatureResultV1
from leviathan_core.numeric import (
    NumericError,
    canonical_json,
    canonical_str,
    exact_add,
    exact_mul,
    parse_decimal,
)
from leviathan_core.portfolio.models import (
    ExposureSnapshotV1,
    HardCapsV1,
    SizingResultV1,
    SizingStatus,
)
from leviathan_core.portfolio.overlap import PortfolioCheckV1, PortfolioStatus
from leviathan_core.seal import Issuer, SealedModel, SealError, require, verify
from leviathan_core.truth.verdict.models import TruthVerdictV1, Verdict

PROPOSAL_TAG = "dec002.proposal.v1"
LINK_TAG = "dec002.link.v1"
_PROPOSAL_ISSUER = Issuer(PROPOSAL_TAG)
_LINK_ISSUER = Issuer(LINK_TAG)
_PROPOSAL_CONSTRUCTION = object()
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
ClosedId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128,
                      pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]
NonNegativeNs = Annotated[int, Field(strict=True, ge=0)]
_GOVERNED_MAX_METRIC_AGE_NS = 500_000_000
_STAGES = (
    "BINDINGS", "FUSION", "FEATURE_TRUTH", "PORTFOLIO",
    "SIZING", "GUARDS", "ACTION", "MODE",
)


class DecisionInputError(ValueError):
    """Content-free public validation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DecisionFrozenError(TypeError):
    """Content-free denial of copy or serialization bypasses."""

    def __init__(self) -> None:
        self.code = "FROZEN_DECISION_RECORD"
        super().__init__(self.code)


class _FrozenRecord:
    def __copy__(self) -> NoReturn:
        raise DecisionFrozenError

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        raise DecisionFrozenError

    def __reduce__(self) -> NoReturn:
        raise DecisionFrozenError

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise DecisionFrozenError


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise DecisionInputError(code)


def _guard_new_record(record: object, tag: str) -> None:
    """Reject re-initialization before any generated field assignment can occur."""
    try:
        require(record, tag)
    except SealError as exc:
        if exc.code == "SEAL_NOT_ISSUED":
            return
    raise DecisionInputError("UNISSUED_PROPOSAL")


def _id(value: object) -> str:
    _require(type(value) is str and _ID.fullmatch(value) is not None, "INVALID_ID")
    return cast(str, value)


def _digest(value: object) -> str:
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None, "INVALID_DIGEST")
    return cast(str, value)


def _time(value: object) -> int:
    _require(type(value) is int and value >= 0, "INVALID_TIMESTAMP")
    return cast(int, value)


def _decimal(value: object) -> Decimal:
    _require(type(value) is Decimal, "INVALID_DECIMAL")
    try:
        return parse_decimal(value, field="value")
    except NumericError as exc:
        raise DecisionInputError(exc.code) from None


def _version(value: object) -> None:
    _require(value == "1.0.0" and type(value) is str, "INVALID_VERSION")


def _plain(value: object) -> Any:
    """Canonical tree for input identity and public output, without object IDs."""
    if isinstance(value, Enum):
        return value.value
    if type(value) is Decimal:
        return canonical_str(value)
    if type(value) is datetime:
        _require(value.tzinfo is UTC, "INVALID_TIMESTAMP")
        return value.isoformat(timespec="microseconds")
    if type(value) is DecisionInputLinkV1 and not verify(value, LINK_TAG):
        return {"unverified_link": True}
    if isinstance(value, BaseModel):
        return _plain(value.model_dump(mode="json"))
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        pairs = ((key.value if isinstance(key, Enum) else key, item) for key, item in value.items())
        return {key: _plain(item) for key, item in sorted(pairs)}
    if isinstance(value, (tuple, list)) and type(value) in (tuple, list):
        return [_plain(item) for item in value]
    if value is None or type(value) in (str, int, bool):
        return value
    raise DecisionInputError("INVALID_INPUT_TYPE")


def _hash(value: object) -> str:
    try:
        return hashlib.sha256(canonical_json(_plain(value))).hexdigest()
    except NumericError as exc:
        raise DecisionInputError(exc.code) from None
    except (TypeError, ValueError, UnicodeError):
        raise DecisionInputError("INVALID_CANONICAL_INPUT") from None


def _result_bytes(value: FusionResultV1 | SizingResultV1 | PortfolioCheckV1) -> bytes:
    try:
        return value.canonical_bytes()
    except Exception:
        raise DecisionInputError("INVALID_UPSTREAM_RESULT") from None


def _result_hash(value: FusionResultV1 | SizingResultV1 | PortfolioCheckV1) -> str:
    return hashlib.sha256(_result_bytes(value)).hexdigest()


class DecisionStatus(StrEnum):
    PROPOSED = "PROPOSED"
    NO_INTENT = "NO_INTENT"


class DecisionAction(StrEnum):
    OPEN = "open"
    INCREASE = "increase"
    REDUCE = "reduce"
    CLOSE = "close"
    NONE = "none"


class DecisionReason(StrEnum):
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
    HASH_MISMATCH = "HASH_MISMATCH"
    FEATURE_MISSING = "FEATURE_MISSING"
    FEATURE_ASOF_MISMATCH = "FEATURE_ASOF_MISMATCH"
    TRUTH_REJECTED = "TRUTH_REJECTED"
    TRUTH_ASOF_MISMATCH = "TRUTH_ASOF_MISMATCH"
    FUSION_NO_CANDIDATE = "FUSION_NO_CANDIDATE"
    PORTFOLIO_BLOCKED = "PORTFOLIO_BLOCKED"
    NO_SIZE = "NO_SIZE"
    STALE_METRICS = "STALE_METRICS"
    VOLATILITY_BREACH = "VOLATILITY_BREACH"
    CORRELATION_BREACH = "CORRELATION_BREACH"
    POSITION_BREACH = "POSITION_BREACH"
    CAP_BREACH = "CAP_BREACH"
    COOLDOWN = "COOLDOWN"
    STOP_BREACH = "STOP_BREACH"
    FIFO_UNSUPPORTED = "FIFO_UNSUPPORTED"
    REDUCER_CROSS_ZERO = "REDUCER_CROSS_ZERO"
    LOT_STEP_BREACH = "LOT_STEP_BREACH"
    MIN_NOTIONAL = "MIN_NOTIONAL"
    RISK_OFF = "RISK_OFF"
    MARKET_HALT = "MARKET_HALT"
    MODE_UNAVAILABLE = "MODE_UNAVAILABLE"
    LONG_DISABLED = "LONG_DISABLED"
    SHORT_DISABLED = "SHORT_DISABLED"
    LIVE_FALLBACK_SIM = "LIVE_FALLBACK_SIM"


@dataclass(frozen=True, slots=True)
class DecisionIdentityV1(_FrozenRecord):
    tenant_id: str
    strategy_revision_hash: str
    portfolio_revision_hash: str
    symbol: str
    evaluation_ns: int
    window_id: str
    feature_snapshot_hash: str
    truth_hash: str
    schema_version: Literal["1.0.0"] = "1.0.0"

    def __post_init__(self) -> None:
        for value in (self.tenant_id, self.symbol, self.window_id):
            _id(value)
        for value in (
            self.strategy_revision_hash, self.portfolio_revision_hash,
            self.feature_snapshot_hash, self.truth_hash,
        ):
            _digest(value)
        _time(self.evaluation_ns)
        _version(self.schema_version)

    def canonical_hash(self) -> str:
        self.__post_init__()
        return _hash(self)


class DecisionInputLinkV1(SealedModel):
    source_kind: Literal["FUSION", "SIZING", "PORTFOLIO"]
    tenant_id: ClosedId
    strategy_revision_hash: Digest
    portfolio_revision_hash: Digest
    symbol: ClosedId
    evaluation_ns: NonNegativeNs
    window_id: ClosedId
    feature_snapshot_hash: Digest
    truth_hash: Digest
    identity_hash: Digest
    input_hash: Digest
    result_hash: Digest
    schema_version: Literal["1.0.0"] = "1.0.0"

    def canonical_bytes(self) -> bytes:
        require(self, LINK_TAG)
        return canonical_json(self.model_dump(mode="json"))


def _issue_link_from_verified_sources(
    identity: DecisionIdentityV1,
    fusion: FusionResultV1,
    sizing: SizingResultV1,
    portfolio: PortfolioCheckV1,
) -> tuple[DecisionInputLinkV1, DecisionInputLinkV1, DecisionInputLinkV1]:
    """Trusted adapter hook; callers must authenticate source requests first."""
    _require(type(identity) is DecisionIdentityV1 and type(fusion) is FusionResultV1
             and type(sizing) is SizingResultV1 and type(portfolio) is PortfolioCheckV1,
             "INVALID_INPUT_TYPE")
    identity_hash = identity.canonical_hash()
    _require(fusion.evaluation_ns == identity.evaluation_ns, "CONTEXT_MISMATCH")
    def issue(
        kind: Literal["FUSION", "SIZING", "PORTFOLIO"],
        result: FusionResultV1 | SizingResultV1 | PortfolioCheckV1,
    ) -> DecisionInputLinkV1:
        return _LINK_ISSUER.issue(DecisionInputLinkV1(
            source_kind=kind,
            tenant_id=identity.tenant_id,
            strategy_revision_hash=identity.strategy_revision_hash,
            portfolio_revision_hash=identity.portfolio_revision_hash,
            symbol=identity.symbol,
            evaluation_ns=identity.evaluation_ns,
            window_id=identity.window_id,
            feature_snapshot_hash=identity.feature_snapshot_hash,
            truth_hash=identity.truth_hash,
            identity_hash=identity_hash,
            input_hash=result.input_hash,
            result_hash=_result_hash(result),
        ))

    return issue("FUSION", fusion), issue("SIZING", sizing), issue("PORTFOLIO", portfolio)


@dataclass(frozen=True, slots=True)
class DecisionPolicyV1(_FrozenRecord):
    policy_id: str
    policy_version: str
    max_metric_age_ns: int
    min_volatility: Decimal
    max_volatility: Decimal
    max_correlation: Decimal
    max_position_quantity: Decimal
    hard_caps: HardCapsV1
    live_fallback: Literal["BLOCK", "SIM"]
    long_enabled: bool
    short_enabled: bool
    fifo_netting_supported: bool
    schema_version: Literal["1.0.0"] = "1.0.0"

    def __post_init__(self) -> None:
        _id(self.policy_id)
        _id(self.policy_version)
        _time(self.max_metric_age_ns)
        _require(self.max_metric_age_ns <= _GOVERNED_MAX_METRIC_AGE_NS,
                 "POLICY_OUT_OF_BOUNDS")
        minimum, maximum = _decimal(self.min_volatility), _decimal(self.max_volatility)
        correlation, position = _decimal(self.max_correlation), _decimal(self.max_position_quantity)
        _require(Decimal(0) <= minimum < maximum and maximum > 0, "POLICY_OUT_OF_BOUNDS")
        _require(Decimal(0) <= correlation <= 1 and position > 0, "POLICY_OUT_OF_BOUNDS")
        _require(type(self.hard_caps) is HardCapsV1, "INVALID_POLICY")
        _require(type(self.live_fallback) is str and self.live_fallback in ("BLOCK", "SIM"),
                 "INVALID_POLICY")
        for flag in (self.long_enabled, self.short_enabled, self.fifo_netting_supported):
            _require(type(flag) is bool, "INVALID_BOOLEAN")
        _version(self.schema_version)


@dataclass(frozen=True, slots=True)
class DecisionContextV1(_FrozenRecord):
    identity: DecisionIdentityV1
    fusion_link: DecisionInputLinkV1
    sizing_link: DecisionInputLinkV1
    portfolio_link: DecisionInputLinkV1
    feature: FeatureResultV1
    truth: TruthVerdictV1
    policy: DecisionPolicyV1
    side: Literal["BUY", "SELL"]
    current_quantity: Decimal
    price: Decimal
    contract_multiplier: Decimal
    lot_step: Decimal
    min_notional: Decimal
    rolling_volatility: Decimal | None
    risk_metrics_available_ns: int | None
    cooldown_until_ns: int
    stop_breach: bool
    global_risk_off: bool
    market_halt: bool
    requested_mode: Literal["live", "sim"]
    bridge_healthy: bool
    oms_healthy: bool
    schema_version: Literal["1.0.0"] = "1.0.0"

    def __post_init__(self) -> None:
        _require(type(self.identity) is DecisionIdentityV1, "INVALID_CONTEXT")
        for link in (self.fusion_link, self.sizing_link, self.portfolio_link):
            _require(type(link) is DecisionInputLinkV1, "INVALID_CONTEXT")
        _require(type(self.feature) is FeatureResultV1, "INVALID_CONTEXT")
        _require(type(self.truth) is TruthVerdictV1, "INVALID_CONTEXT")
        _require(type(self.policy) is DecisionPolicyV1, "INVALID_CONTEXT")
        _require(type(self.side) is str and self.side in ("BUY", "SELL"), "INVALID_SIDE")
        for value in (self.current_quantity, self.price, self.contract_multiplier,
                      self.lot_step, self.min_notional):
            _decimal(value)
        _require(self.price > 0 and self.contract_multiplier > 0 and self.lot_step > 0
                 and self.min_notional >= 0, "INVALID_MARKET_INPUT")
        if self.rolling_volatility is not None:
            _decimal(self.rolling_volatility)
        if self.risk_metrics_available_ns is not None:
            _time(self.risk_metrics_available_ns)
        _time(self.cooldown_until_ns)
        for flag in (self.stop_breach, self.global_risk_off, self.market_halt,
                     self.bridge_healthy, self.oms_healthy):
            _require(type(flag) is bool, "INVALID_BOOLEAN")
        _require(type(self.requested_mode) is str and self.requested_mode in ("live", "sim"),
                 "INVALID_MODE")
        _version(self.schema_version)


@dataclass(frozen=True, slots=True)
class DecisionTraceStepV1(_FrozenRecord):
    stage: str
    status: Literal["PASS", "BLOCKED", "SKIPPED"]
    reason_codes: tuple[DecisionReason, ...]
    evidence_hash: str
    schema_version: Literal["1.0.0"] = "1.0.0"

    def __post_init__(self) -> None:
        _require(type(self.stage) is str and self.stage in _STAGES, "INVALID_TRACE")
        _require(type(self.status) is str and self.status in ("PASS", "BLOCKED", "SKIPPED"),
                 "INVALID_TRACE")
        _require(type(self.reason_codes) is tuple and all(type(code) is DecisionReason
                 for code in self.reason_codes), "INVALID_TRACE")
        _require(self.reason_codes == tuple(sorted(set(self.reason_codes))), "INVALID_TRACE")
        _digest(self.evidence_hash)
        _version(self.schema_version)


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class DecisionProposalV1(_FrozenRecord):
    status: DecisionStatus
    action: DecisionAction
    requested_mode: Literal["live", "sim"]
    effective_mode: Literal["live", "sim", "none"]
    qty_delta: Decimal
    target_quantity: Decimal
    projected_exposures: ExposureSnapshotV1 | None
    lot_step: Decimal
    min_notional: Decimal
    notional: Decimal
    lot_multiple: bool
    min_notional_met: bool
    attributions: tuple[FeatureAttributionV1, ...]
    reason_codes: tuple[DecisionReason, ...]
    rule_hits: tuple[str, ...]
    idempotency_key: str
    input_hash: str
    trace: tuple[DecisionTraceStepV1, ...]
    rationale: str
    schema_version: Literal["1.0.0"] = "1.0.0"
    _issuer: InitVar[object | None] = None

    def __init__(self, *, _issuer: object | None = None, **values: object) -> None:
        _guard_new_record(self, PROPOSAL_TAG)
        _require(_issuer is _PROPOSAL_CONSTRUCTION, "UNISSUED_PROPOSAL")
        values.setdefault("schema_version", "1.0.0")
        declared = {field.name for field in fields(type(self))}
        _require(set(values) == declared, "INVALID_PROPOSAL")
        for field in fields(type(self)):
            object.__setattr__(self, field.name, values[field.name])
        self.__post_init__(_issuer)

    def __post_init__(self, _issuer: object | None) -> None:
        _require(_issuer is _PROPOSAL_CONSTRUCTION, "UNISSUED_PROPOSAL")
        _require(not _PROPOSAL_ISSUER.issued_here(self), "ALREADY_ISSUED")
        _require(type(self.status) is DecisionStatus and type(self.action) is DecisionAction,
                 "INVALID_PROPOSAL")
        _require(type(self.requested_mode) is str and self.requested_mode in ("live", "sim"),
                 "INVALID_PROPOSAL")
        _require(
            type(self.effective_mode) is str and self.effective_mode in ("live", "sim", "none"),
            "INVALID_PROPOSAL",
        )
        _require(self.projected_exposures is None or
                 type(self.projected_exposures) is ExposureSnapshotV1, "INVALID_PROPOSAL")
        for value in (self.qty_delta, self.target_quantity, self.lot_step,
                      self.min_notional, self.notional):
            _decimal(value)
        _require(type(self.lot_multiple) is bool and type(self.min_notional_met) is bool,
                 "INVALID_PROPOSAL")
        _require(type(self.attributions) is tuple and all(type(item) is FeatureAttributionV1
                 for item in self.attributions) and len(self.attributions) <= 5, "INVALID_PROPOSAL")
        _require(type(self.reason_codes) is tuple and all(type(code) is DecisionReason
                 for code in self.reason_codes), "INVALID_PROPOSAL")
        _require(self.reason_codes == tuple(sorted(set(self.reason_codes))), "INVALID_PROPOSAL")
        _require(type(self.rule_hits) is tuple and all(type(item) is str and _ID.fullmatch(item)
                 for item in self.rule_hits), "INVALID_PROPOSAL")
        _require(self.rule_hits == tuple(sorted(set(self.rule_hits))), "INVALID_PROPOSAL")
        _digest(self.idempotency_key)
        _digest(self.input_hash)
        _require(type(self.trace) is tuple and tuple(item.stage for item in self.trace) == _STAGES
                 and all(type(item) is DecisionTraceStepV1 for item in self.trace),
                 "INVALID_PROPOSAL")
        _require(type(self.rationale) is str and len(self.rationale) <= 512, "INVALID_PROPOSAL")
        if self.status is DecisionStatus.NO_INTENT:
            _require(self.action is DecisionAction.NONE and self.qty_delta == 0
                     and self.effective_mode == "none" and self.notional == 0,
                     "INVALID_PROPOSAL")
        else:
            _require(self.action is not DecisionAction.NONE and self.qty_delta != 0
                     and self.effective_mode != "none" and self.lot_multiple
                     and self.min_notional_met and self.projected_exposures is not None,
                     "INVALID_PROPOSAL")
        _version(self.schema_version)

    def canonical_bytes(self) -> bytes:
        require(self, PROPOSAL_TAG)
        return canonical_json(_plain(self))


def _truth_ns(value: datetime) -> int:
    _require(type(value) is datetime and value.tzinfo is UTC, "INVALID_TIMESTAMP")
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def _binding_reasons(
    fusion: FusionResultV1, sizing: SizingResultV1,
    portfolio: PortfolioCheckV1, context: DecisionContextV1,
) -> set[DecisionReason]:
    identity_hash = context.identity.canonical_hash()
    pairs = (
        (context.fusion_link, "FUSION", fusion),
        (context.sizing_link, "SIZING", sizing),
        (context.portfolio_link, "PORTFOLIO", portfolio),
    )
    reasons: set[DecisionReason] = set()
    identity = context.identity
    expected_scope = (
        identity.tenant_id, identity.strategy_revision_hash,
        identity.portfolio_revision_hash, identity.symbol,
        identity.evaluation_ns, identity.window_id,
        identity.feature_snapshot_hash, identity.truth_hash,
    )
    for link, kind, result in pairs:
        try:
            require(link, LINK_TAG)
        except SealError:
            reasons.add(DecisionReason.CONTEXT_MISMATCH)
            continue
        linked_scope = (
            link.tenant_id, link.strategy_revision_hash,
            link.portfolio_revision_hash, link.symbol,
            link.evaluation_ns, link.window_id,
            link.feature_snapshot_hash, link.truth_hash,
        )
        if (link.source_kind != kind or link.identity_hash != identity_hash
            or linked_scope != expected_scope):
            reasons.add(DecisionReason.CONTEXT_MISMATCH)
        if link.input_hash != result.input_hash or link.result_hash != _result_hash(result):
            reasons.add(DecisionReason.HASH_MISMATCH)
    if fusion.evaluation_ns != context.identity.evaluation_ns:
        reasons.add(DecisionReason.CONTEXT_MISMATCH)
    return reasons


def _feature_truth_reasons(context: DecisionContextV1) -> set[DecisionReason]:
    identity, feature, truth = context.identity, context.feature, context.truth
    reasons: set[DecisionReason] = set()
    if not feature.found or feature.observation_hash is None:
        reasons.add(DecisionReason.FEATURE_MISSING)
    if (feature.asof_ns != identity.evaluation_ns or feature.instrument_id != identity.symbol
        or feature.observation_hash != identity.feature_snapshot_hash
        or feature.event_time_ns is None or feature.event_time_ns > identity.evaluation_ns
        or feature.availability_ns is None or feature.availability_ns > identity.evaluation_ns):
        reasons.add(DecisionReason.FEATURE_ASOF_MISMATCH)
    if truth.verdict is not Verdict.PASS:
        reasons.add(DecisionReason.TRUTH_REJECTED)
    if (truth.hash_id != identity.truth_hash
        or _truth_ns(truth.evaluation_ts) != identity.evaluation_ns):
        reasons.add(DecisionReason.TRUTH_ASOF_MISMATCH)
    return reasons


def _caps_ok(sizing: SizingResultV1, caps: HardCapsV1) -> bool:
    exposure = sizing.exposures
    if exposure is None:
        return False
    return (
        exposure.symbol_notional <= caps.per_symbol_notional
        and exposure.sector_notional <= caps.per_sector_notional
        and exposure.gross_notional <= caps.gross_notional
        and exposure.net_notional.copy_abs() <= caps.net_notional
        and exposure.leverage <= caps.max_leverage
        and exposure.projected_worst_case_loss <= caps.per_trade_loss
        and exposure.portfolio_heat <= caps.portfolio_heat
    )


def _step(stage: str, reasons: set[DecisionReason], evidence: object) -> DecisionTraceStepV1:
    ordered = tuple(sorted(reasons))
    return DecisionTraceStepV1(
        stage=stage,
        status="BLOCKED" if ordered else "PASS",
        reason_codes=ordered,
        evidence_hash=_hash({"stage": stage, "evidence": evidence}),
    )


def _rule_hit(source: str, code: str) -> str:
    candidate = f"{source}:{code}"
    if _ID.fullmatch(candidate) is not None:
        return candidate
    return f"{source}:{hashlib.sha256(code.encode('utf-8', errors='replace')).hexdigest()}"


def compose(
    fusion: FusionResultV1,
    sizing: SizingResultV1,
    portfolio: PortfolioCheckV1,
    context: DecisionContextV1,
) -> DecisionProposalV1:
    """Compose an advisory proposal; no route permit or OMS command is issued."""
    _require(type(fusion) is FusionResultV1 and type(sizing) is SizingResultV1
             and type(portfolio) is PortfolioCheckV1 and type(context) is DecisionContextV1,
             "INVALID_INPUT_TYPE")
    context.identity.__post_init__()
    context.policy.__post_init__()
    context.__post_init__()
    binding = _binding_reasons(fusion, sizing, portfolio, context)
    fused = ({DecisionReason.FUSION_NO_CANDIDATE}
             if fusion.status != "CAPITAL_CANDIDATE" else set())
    feature_truth = _feature_truth_reasons(context)
    portfolio_reasons = ({DecisionReason.PORTFOLIO_BLOCKED}
                         if portfolio.status is not PortfolioStatus.PASS or portfolio.breaches
                         else set())
    size_reasons = ({DecisionReason.NO_SIZE}
                    if sizing.status is not SizingStatus.SIZE or sizing.proposed_quantity <= 0
                    or sizing.exposures is None else set())
    if not _caps_ok(sizing, context.policy.hard_caps):
        size_reasons.add(DecisionReason.CAP_BREACH)

    guards: set[DecisionReason] = set()
    evaluation_ns = context.identity.evaluation_ns
    available_ns = context.risk_metrics_available_ns
    if (available_ns is None or available_ns > evaluation_ns
        or evaluation_ns - available_ns > context.policy.max_metric_age_ns
        or sizing.as_of_age_ns is None
        or sizing.as_of_age_ns > context.policy.max_metric_age_ns
        or context.rolling_volatility is None):
        guards.add(DecisionReason.STALE_METRICS)
    elif not (
        context.policy.min_volatility <= context.rolling_volatility
        <= context.policy.max_volatility
    ):
        guards.add(DecisionReason.VOLATILITY_BREACH)
    if (portfolio.max_offdiag is not None
        and portfolio.max_offdiag.copy_abs() > context.policy.max_correlation):
        guards.add(DecisionReason.CORRELATION_BREACH)
    if context.global_risk_off:
        guards.add(DecisionReason.RISK_OFF)
    if context.market_halt:
        guards.add(DecisionReason.MARKET_HALT)
    if context.stop_breach:
        guards.add(DecisionReason.STOP_BREACH)
    if context.cooldown_until_ns > evaluation_ns:
        guards.add(DecisionReason.COOLDOWN)

    quantity = _decimal(sizing.proposed_quantity)
    signed = quantity if context.side == "BUY" else exact_mul(quantity, Decimal(-1))
    target = exact_add(context.current_quantity, signed)
    notional = exact_mul(exact_mul(quantity, context.price), context.contract_multiplier)
    projected_symbol_notional = exact_mul(
        exact_mul(target.copy_abs(), context.price), context.contract_multiplier
    )
    lot_multiple = (Fraction(quantity) / Fraction(context.lot_step)).denominator == 1
    min_notional_met = notional >= context.min_notional
    action_reasons: set[DecisionReason] = set()
    if not lot_multiple:
        action_reasons.add(DecisionReason.LOT_STEP_BREACH)
    if not min_notional_met:
        action_reasons.add(DecisionReason.MIN_NOTIONAL)
    if target.copy_abs() > context.policy.max_position_quantity:
        action_reasons.add(DecisionReason.POSITION_BREACH)
    if projected_symbol_notional > context.policy.hard_caps.per_symbol_notional:
        action_reasons.add(DecisionReason.CAP_BREACH)
    if sizing.exposures is not None:
        exposure = sizing.exposures
        if (
            exposure.symbol_notional < projected_symbol_notional
            or exposure.sector_notional < exposure.symbol_notional
            or exposure.gross_notional < exposure.sector_notional
            or exposure.gross_notional < exposure.net_notional.copy_abs()
        ):
            action_reasons.add(DecisionReason.CAP_BREACH)
    if target > 0 and not context.policy.long_enabled:
        action_reasons.add(DecisionReason.LONG_DISABLED)
    if target < 0 and not context.policy.short_enabled:
        action_reasons.add(DecisionReason.SHORT_DISABLED)
    action = DecisionAction.NONE
    current = context.current_quantity
    if quantity > 0:
        if current == 0:
            action = DecisionAction.OPEN
        elif (current > 0 and signed > 0) or (current < 0 and signed < 0):
            action = DecisionAction.INCREASE
        elif signed.copy_abs() < current.copy_abs():
            action = DecisionAction.REDUCE
        elif signed.copy_abs() == current.copy_abs():
            action = DecisionAction.CLOSE
        else:
            action_reasons.add(DecisionReason.REDUCER_CROSS_ZERO)
        if (action in (DecisionAction.REDUCE, DecisionAction.CLOSE)
            and not context.policy.fifo_netting_supported):
            action_reasons.add(DecisionReason.FIFO_UNSUPPORTED)

    mode_reasons: set[DecisionReason] = set()
    fallback = False
    effective_mode: Literal["live", "sim", "none"] = context.requested_mode
    if context.requested_mode == "live" and not (context.bridge_healthy and context.oms_healthy):
        if context.policy.live_fallback == "SIM":
            effective_mode = "sim"
            fallback = True
        else:
            mode_reasons.add(DecisionReason.MODE_UNAVAILABLE)
            effective_mode = "none"

    stage_reasons = (
        binding, fused, feature_truth, portfolio_reasons,
        size_reasons, guards, action_reasons, mode_reasons,
    )
    veto = set().union(*stage_reasons)
    status = DecisionStatus.NO_INTENT if veto else DecisionStatus.PROPOSED
    if veto:
        action = DecisionAction.NONE
        effective_mode = "none"
        signed = Decimal(0)
        target = current
        notional = Decimal(0)
    fallback_reasons = {DecisionReason.LIVE_FALLBACK_SIM} if fallback and not veto else set()
    reason_codes = tuple(sorted(veto | fallback_reasons))
    rule_hits = tuple(sorted({
        *(_rule_hit("LAYER", f"{item.layer}:{item.status}")
          for item in fusion.layer_verdicts),
        *(_rule_hit("SCORE", f"{layer}:{score if score is not None else 'none'}")
          for layer, score in fusion.layer_scores),
        *(_rule_hit("FUSION", code) for code in fusion.reason_codes),
        *(_rule_hit("SIZING", code) for code in sizing.reasons),
        *(_rule_hit("PORTFOLIO", item.code) for item in portfolio.breaches),
        *(_rule_hit("GUARD", code.value) for code in reason_codes),
    }))
    input_hash = _hash({
        "fusion": json.loads(_result_bytes(fusion)),
        "sizing": json.loads(_result_bytes(sizing)),
        "portfolio": json.loads(_result_bytes(portfolio)),
        "context": context,
    })
    idempotency_key = _hash({
        "identity": context.identity, "fusion_key": fusion.idempotency_key,
        "policy_id": context.policy.policy_id, "policy_version": context.policy.policy_version,
    })
    trace = tuple(_step(stage, reasons, {"input_hash": input_hash,
             "reason_codes": tuple(sorted(reasons))})
                  for stage, reasons in zip(_STAGES, stage_reasons, strict=True))
    rationale = ("Advisory proposal for downstream sovereign risk evaluation only."
                 if status is DecisionStatus.PROPOSED else
                 "Decision withheld: " + ", ".join(code.value for code in reason_codes) + ".")
    proposal = DecisionProposalV1(
        status=status, action=action, requested_mode=context.requested_mode,
        effective_mode=effective_mode, qty_delta=signed, target_quantity=target,
        projected_exposures=sizing.exposures if status is DecisionStatus.PROPOSED else None,
        lot_step=context.lot_step, min_notional=context.min_notional, notional=notional,
        lot_multiple=lot_multiple, min_notional_met=min_notional_met,
        attributions=tuple(fusion.attributions[:5]), reason_codes=reason_codes,
        rule_hits=rule_hits, idempotency_key=idempotency_key, input_hash=input_hash,
        trace=trace, rationale=rationale,
        _issuer=_PROPOSAL_CONSTRUCTION,
    )
    return _PROPOSAL_ISSUER.issue(proposal)


__all__ = [
    "DecisionAction", "DecisionContextV1", "DecisionFrozenError", "DecisionIdentityV1",
    "DecisionInputError", "DecisionInputLinkV1", "DecisionPolicyV1", "DecisionProposalV1",
    "DecisionReason", "DecisionStatus", "DecisionTraceStepV1", "compose",
]
