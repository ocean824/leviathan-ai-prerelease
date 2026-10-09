"""RiskSnapshot — Sovereign Risk Engine contract.

Freezes risk conditions at session start so execution cannot improvise
its own thesis (snapshot-security pattern). A RiskSnapshot must exist
and be frozen BEFORE any ExecutionIntent is created.
"""

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from pydantic import Field

from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.enums import RiskAction
from leviathan_core.seal import Issuer, SealError
from leviathan_core.seal import require as _require_sealed


class StreamFreshness(LeviathanModel):
    stream_id: str
    symbol: str
    provider: str
    source_ts: datetime | None
    exchange_ts: datetime | None
    received_at: datetime


class RequiredStream(LeviathanModel):
    stream_id: str
    symbol: str
    provider: str


class KillState(LeviathanModel):
    global_kill: bool = False
    killed_providers: tuple[str, ...] = ()
    kill_expires_at: datetime | None = None


class RiskGateContext(LeviathanModel):
    as_of: datetime
    required: tuple[RequiredStream, ...]
    observed: tuple[StreamFreshness, ...]
    kill: KillState
    max_staleness_ms: int = Field(default=300_000, ge=0)
    max_clock_skew_ms: int = Field(default=2_000, ge=0)


class GateFinding(StrEnum):
    ROUTE_GUARD_UNCONFIGURED = "route_guard_unconfigured"
    LOCK_MISSING = "lock_missing"
    LOCK_HASH_EMPTY = "lock_hash_empty"
    LOCK_TAMPERED = "lock_tampered"
    CONTEXT_MISSING = "freshness_context_missing"
    STREAM_UNKNOWN = "stream_unknown"
    STREAM_STALE = "stream_stale"
    CLOCK_SKEW = "clock_skew_unknown"
    GLOBAL_KILL = "global_kill_active"
    PROVIDER_KILL = "provider_kill_active"
    AUDIT_SINK_FAILURE = "audit_sink_failure"


class RiskSnapshot(LeviathanModel):
    session_id: str
    max_daily_drawdown_pct: Decimal = Field(gt=0)
    max_position_size: Decimal = Field(gt=0)
    allowed_instruments: tuple[str, ...]
    prop_firm_rules: tuple[str, ...] = Field(default=())
    frozen_at: datetime
    risk_lock_sha256: str = Field(
        default="",
        description="SHA-256 of risk_governance.lock.yaml at freeze time; "
        "guardian refuses order routing on mismatch.",
    )


class RiskVerdict(LeviathanModel):
    """TIAMAT's judgement on a proposed trade.

    Every verdict carries a named reason (never an aggregated count) and
    is journaled whether or not a trade results.
    """

    decision_id: str
    action: RiskAction
    reason: str
    adjusted_size: Decimal | None = Field(
        default=None, description="Set when action is reduce_size."
    )
    halts_engaged: tuple[str, ...] = Field(
        default=(), description="Named halt flags active at evaluation time."
    )
    execution_capable: bool = False
    findings: tuple[GateFinding, ...] = ()

    def __init__(self, **data: Any) -> None:
        _reject_issued_reinitialization(self, _RISK_VERDICT_ISSUER)
        super().__init__(**data)


_RISK_VERDICT_ISSUER = Issuer("c101.risk_verdict.v1")


def _reject_issued_reinitialization(value: object, issuer: Issuer) -> None:
    try:
        _require_sealed(value, issuer.tag)
    except SealError as exc:
        if exc.args == ("SEAL_NOT_ISSUED",):
            return
        raise SealError("SEAL_FORBIDDEN_OPERATION") from None
    raise SealError("SEAL_FORBIDDEN_OPERATION")


def _issue_risk_verdict(value: RiskVerdict) -> RiskVerdict:
    """Issue a risk verdict at the C-101 pipeline boundary."""
    if type(value) is not RiskVerdict:
        raise SealError("SEAL_INVALID_MODEL")
    if _RISK_VERDICT_ISSUER.issued_here(value):
        return value
    return _RISK_VERDICT_ISSUER.issue(value)


def require_risk_verdict(value: object) -> RiskVerdict:
    """Require an exact, unmodified RiskVerdict issued by this kernel."""
    if type(value) is not RiskVerdict:
        raise SealError("SEAL_INVALID_MODEL")
    return _require_sealed(value, _RISK_VERDICT_ISSUER.tag)
