"""Typed mirror of risk_governance.lock.yaml (schema leviathan.tiamat.risk.v1).

The YAML is the immutable source of truth; this module only parses it.
Unknown keys are a hard error — a lock file that says more than the
schema understands is a lock file we do not trust.
"""

from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from typing import Any, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Locked(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Rebuild through validation; Pydantic's default copy bypasses validators."""
        payload = self.model_dump(mode="python", round_trip=True)
        if update is not None:
            payload.update(update)
        return type(self).model_validate(payload, by_name=True)

    @classmethod
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> Self:
        raise TypeError("model_construct is disabled for locked risk policy models")


class DrawdownRules(_Locked):
    max_daily_pct: Decimal
    max_weekly_pct: Decimal
    max_trailing_pct: Decimal
    daily_reset_time_utc: str
    on_breach: str


class HeatRules(_Locked):
    max_open_pct: Decimal
    max_per_position_pct: Decimal


class LeverageRules(_Locked):
    max_gross_notional_x: Decimal
    max_net_x: Decimal
    fx_max_x: Decimal


class CorrelationRules(_Locked):
    max_positions_same_sector: int
    correlation_threshold: Decimal
    on_breach: str


class NewsEmbargoRules(_Locked):
    tier_1_events: tuple[str, ...]
    pre_event_minutes: int
    post_event_minutes: int
    on_breach: str


class LossStreakRules(_Locked):
    consecutive_losers: int
    size_cut_pct: Decimal
    duration_hours: int
    recovery_mode: bool


class InstrumentLimit(_Locked):
    max_position_units: Decimal
    max_open_positions_per_symbol: int


class InstrumentLimits(_Locked):
    default: InstrumentLimit
    overrides: dict[str, InstrumentLimit] = Field(default_factory=dict)

    def for_instrument(self, instrument: str) -> InstrumentLimit:
        return self.overrides.get(instrument, self.default)


class KillSwitchRules(_Locked):
    global_halt_file: str
    on_unexpected_pnl_swing_pct: Decimal
    on_consecutive_broker_errors: int
    on_omega_kill_signal: bool


class AuditRules(_Locked):
    master_hash_file: str
    guardian_daemon_path: str
    log_path: str
    verify_before_every_order: bool
    verify_interval_seconds: int


class SelfEvolutionRules(_Locked):
    triton_can_propose_changes: bool
    triton_can_apply_changes: bool
    proposal_log: str

    @field_validator("triton_can_apply_changes")
    @classmethod
    def _forbid_apply_rights(cls, value: bool) -> bool:
        if value:
            raise ValueError("risk policy cannot grant autonomous apply rights")
        return value


class RiskPolicy(_Locked):
    version: int
    schema_id: str = Field(alias="schema")
    operator_handle: str
    account_currency: str
    drawdown: DrawdownRules
    heat: HeatRules
    leverage: LeverageRules
    correlation: CorrelationRules
    news_embargo: NewsEmbargoRules
    loss_streak: LossStreakRules
    instrument_limits: InstrumentLimits
    kill_switches: KillSwitchRules
    audit: AuditRules
    self_evolution: SelfEvolutionRules


def load_risk_policy(lock_path: Path) -> RiskPolicy:
    return load_risk_policy_bytes(lock_path.read_bytes())


def load_risk_policy_bytes(lock_bytes: bytes) -> RiskPolicy:
    """Parse the same immutable byte snapshot that was fingerprinted."""
    raw = yaml.safe_load(lock_bytes.decode("utf-8"))
    policy = RiskPolicy.model_validate(raw)
    if policy.self_evolution.triton_can_apply_changes:
        raise ValueError(
            "lock file grants TRITON apply-rights over risk rules — refusing to load"
        )
    return policy
