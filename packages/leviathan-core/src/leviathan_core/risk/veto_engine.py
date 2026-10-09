"""Sovereign veto engine (TIAMAT).

Implements the risk-veto-policy-matrix evaluator in strict priority
order. The engine does not create trade ideas; it judges whether a
proposed trade may proceed, must shrink, must wait, or must stop.

Every verdict carries a named reason and is written to the audit log
BEFORE it is returned — no verdict is actionable until it exists on
disk.
"""

from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from leviathan_core.risk.audit import (
    RiskAuditError,
    RiskAuditLog,
    RiskAuditRecheckError,
)
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.risk.halt_reasons import HaltReasonV1
from leviathan_core.risk.lock import RiskLockError, verify_risk_lock
from leviathan_core.risk.policy import RiskPolicy
from leviathan_core.risk.route_guard import RouteGuard
from leviathan_core.schemas import (
    AccountState,
    DecisionPacket,
    EconomicEvent,
    GateFinding,
    Permission,
    RiskAction,
    RiskGateContext,
    RiskVerdict,
)

_LOCK_FINDINGS = frozenset(
    (GateFinding.LOCK_MISSING, GateFinding.LOCK_HASH_EMPTY, GateFinding.LOCK_TAMPERED)
)


class VetoEngine:
    def __init__(
        self,
        policy: RiskPolicy,
        halt_authority: HaltAuthority,
        audit_log: RiskAuditLog,
        lock_path: Path | None = None,
        expected_lock_sha256: str = "",
        route_guard: RouteGuard | None = None,
    ) -> None:
        self._policy = policy
        self._halts = halt_authority
        self._audit = audit_log
        self._lock_path = lock_path
        self._expected_sha = expected_lock_sha256
        self._guard = route_guard

    @property
    def route_guard(self) -> RouteGuard | None:
        return self._guard

    @property
    def halt_authority(self) -> HaltAuthority:
        return self._halts

    @property
    def policy_is_bound(self) -> bool:
        return self._guard is not None and self._guard.proves_policy(self._policy)

    def assess_candidate(
        self,
        decision: DecisionPacket,
        account: AccountState,
        instrument: str,
        requested_size: Decimal,
        at: datetime,
        sector: str = "unclassified",
        upcoming_events: tuple[EconomicEvent, ...] = (),
        context: RiskGateContext | None = None,
        execution_input_error: str | None = None,
    ) -> RiskVerdict:
        """Pure candidate evaluation for the SQLite-authoritative route.

        The legacy JSONL audit is diagnostic only; no file write can grant
        execution permission or make an outcome final.
        """
        return self._evaluate(
            decision,
            account,
            instrument,
            requested_size,
            at,
            sector,
            upcoming_events,
            context,
            execution_input_error,
        )

    def guard_verdict(self, decision_id: str, findings: tuple[GateFinding, ...]) -> RiskVerdict:
        return self._guard_verdict(decision_id, findings)

    def assess(
        self,
        decision: DecisionPacket,
        account: AccountState,
        instrument: str,
        requested_size: Decimal,
        at: datetime,
        sector: str = "unclassified",
        upcoming_events: tuple[EconomicEvent, ...] = (),
        context: RiskGateContext | None = None,
        execution_input_error: str | None = None,
    ) -> RiskVerdict:
        verdict = self._evaluate(
            decision,
            account,
            instrument,
            requested_size,
            at,
            sector,
            upcoming_events,
            context,
            execution_input_error,
        )
        actionable = (
            decision.permission is Permission.APPROVE
            and verdict.action in (RiskAction.ALLOW, RiskAction.REDUCE_SIZE)
            and verdict.execution_capable
        )
        try:
            self._audit.record(
                verdict,
                context={
                    "instrument": instrument,
                    "requested_size": str(requested_size),
                    "daily_pnl_pct": str(account.daily_pnl_pct),
                    "consecutive_losses": account.consecutive_losses,
                },
                final=not actionable,
            )
        except RiskAuditError:
            return self._audit_failure(verdict.decision_id)
        return verdict

    def finalize_route(
        self,
        assessment: RiskVerdict,
        findings: tuple[GateFinding, ...],
        authorization_check: Callable[[], tuple[GateFinding, ...]] | None = None,
    ) -> RiskVerdict:
        """Record the final route check before an intent can be constructed."""
        if assessment.execution_capable and not self.policy_is_bound:
            findings = (*findings, GateFinding.LOCK_TAMPERED)
        if self._halts.halted and GateFinding.GLOBAL_KILL not in findings:
            findings = (*findings, GateFinding.GLOBAL_KILL)
        final = self._guard_verdict(assessment.decision_id, findings) if findings else assessment

        def check_before_commit() -> tuple[GateFinding, ...]:
            latest = authorization_check() if authorization_check is not None else ()
            if not self.policy_is_bound and GateFinding.LOCK_TAMPERED not in latest:
                latest = (*latest, GateFinding.LOCK_TAMPERED)
            if self._halts.halted and GateFinding.GLOBAL_KILL not in latest:
                latest = (*latest, GateFinding.GLOBAL_KILL)
            return latest

        try:
            self._audit.record(
                final,
                phase="route_recheck",
                seq=2,
                final=True,
                authorization_check=(
                    check_before_commit
                    if final.action in (RiskAction.ALLOW, RiskAction.REDUCE_SIZE)
                    else None
                ),
            )
        except RiskAuditRecheckError as changed:
            final = self._guard_verdict(assessment.decision_id, changed.findings)
            try:
                self._audit.record(final, phase="route_recheck", seq=2, final=True)
            except RiskAuditError:
                return self._audit_failure(assessment.decision_id)
        except RiskAuditError:
            return self._audit_failure(assessment.decision_id)
        return final

    def reconcile_route(
        self,
        assessment: RiskVerdict,
        authorization_check: Callable[[], tuple[GateFinding, ...]],
    ) -> RiskVerdict | None:
        """Close a change observed after final audit commit but before intent."""
        try:
            findings = authorization_check()
        except Exception:
            failed = self._audit_failure(assessment.decision_id)
            try:
                self._audit.reconcile_final(failed)
            except RiskAuditError:
                with suppress(RiskAuditError):
                    self._audit.quarantine()
            return failed
        if not self.policy_is_bound and GateFinding.LOCK_TAMPERED not in findings:
            findings = (*findings, GateFinding.LOCK_TAMPERED)
        if self._halts.halted and GateFinding.GLOBAL_KILL not in findings:
            findings = (*findings, GateFinding.GLOBAL_KILL)
        if not findings:
            return None
        final = self._guard_verdict(assessment.decision_id, findings)
        try:
            self._audit.reconcile_final(final)
        except RiskAuditError:
            with suppress(RiskAuditError):
                self._audit.quarantine()
            return self._audit_failure(assessment.decision_id)
        return final

    def _audit_failure(self, decision_id: str) -> RiskVerdict:
        self._halts.engage(HaltReasonV1.AUDIT_SINK_FAILURE)
        return RiskVerdict(
            decision_id=decision_id,
            action=RiskAction.HALT_ALL_TRADING,
            reason=GateFinding.AUDIT_SINK_FAILURE.value,
            halts_engaged=self._halts.active,
            findings=(GateFinding.AUDIT_SINK_FAILURE,),
        )

    def _guard_verdict(self, decision_id: str, findings: tuple[GateFinding, ...]) -> RiskVerdict:
        if any(finding in _LOCK_FINDINGS for finding in findings):
            self._halts.engage(HaltReasonV1.TIAMAT_HASH_MISMATCH)
        halt = (
            any(finding in _LOCK_FINDINGS for finding in findings)
            or GateFinding.GLOBAL_KILL in findings
        )
        return RiskVerdict(
            decision_id=decision_id,
            action=RiskAction.HALT_ALL_TRADING if halt else RiskAction.REJECT,
            reason=",".join(finding.value for finding in findings),
            halts_engaged=self._halts.active,
            findings=findings,
        )

    def _evaluate(
        self,
        decision: DecisionPacket,
        account: AccountState,
        instrument: str,
        requested_size: Decimal,
        at: datetime,
        sector: str,
        events: tuple[EconomicEvent, ...],
        context: RiskGateContext | None,
        execution_input_error: str | None,
    ) -> RiskVerdict:
        p = self._policy

        def verdict(
            action: RiskAction, reason: str, adjusted: Decimal | None = None
        ) -> RiskVerdict:
            return RiskVerdict(
                decision_id=decision.decision_id,
                action=action,
                reason=reason,
                adjusted_size=adjusted,
                halts_engaged=self._halts.active,
                execution_capable=(
                    self._guard is not None
                    and self.policy_is_bound
                    and action in (RiskAction.ALLOW, RiskAction.REDUCE_SIZE)
                ),
            )

        # 0. A configured route guard proves lock, context, kill and freshness.
        if self._guard is not None:
            findings = list(self._guard.check(context))
            if (
                not any(finding in _LOCK_FINDINGS for finding in findings)
                and not self.policy_is_bound
            ):
                findings.append(GateFinding.LOCK_TAMPERED)
            if (
                context is not None
                and not any(item.symbol == instrument for item in context.required)
                and GateFinding.STREAM_UNKNOWN not in findings
            ):
                findings.append(GateFinding.STREAM_UNKNOWN)
            if findings:
                return self._guard_verdict(decision.decision_id, tuple(findings))
        elif self._lock_path is not None:
            try:
                verify_risk_lock(self._lock_path, self._expected_sha)
            except (RiskLockError, OSError) as exc:
                self._halts.engage(HaltReasonV1.TIAMAT_HASH_MISMATCH)
                return verdict(RiskAction.HALT_ALL_TRADING, f"lock_verification_failed: {exc}")

        # 0b. Existing halt state wins over everything downstream.
        if self._halts.halted:
            return verdict(
                RiskAction.HALT_ALL_TRADING, f"halt_active: {','.join(self._halts.active)}"
            )

        # Preflight before a non-final actionable assessment is written.
        if execution_input_error is not None:
            return verdict(RiskAction.REJECT, execution_input_error)

        # 1. Daily / weekly / trailing drawdown → global halt (critical).
        if -account.daily_pnl_pct >= p.drawdown.max_daily_pct:
            self._halts.engage(HaltReasonV1.DAILY_DRAWDOWN_BREACH)
            return verdict(RiskAction.HALT_ALL_TRADING, "daily_drawdown_breach")
        if -account.weekly_pnl_pct >= p.drawdown.max_weekly_pct:
            self._halts.engage(HaltReasonV1.WEEKLY_DRAWDOWN_BREACH)
            return verdict(RiskAction.HALT_ALL_TRADING, "weekly_drawdown_breach")
        if account.trailing_dd_pct >= p.drawdown.max_trailing_pct:
            self._halts.engage(HaltReasonV1.TRAILING_DRAWDOWN_BREACH)
            return verdict(RiskAction.HALT_ALL_TRADING, "trailing_drawdown_breach")

        # 2. News embargo window → wait (high).
        window_pre = timedelta(minutes=p.news_embargo.pre_event_minutes)
        window_post = timedelta(minutes=p.news_embargo.post_event_minutes)
        for event in events:
            if event.tier == 1 and -window_post <= (event.scheduled_at - at) <= window_pre:
                return verdict(RiskAction.WAIT, f"news_embargo:{event.name}")

        # 3. Instrument limits → reject (high).
        limits = p.instrument_limits.for_instrument(instrument)
        if account.open_count(instrument) >= limits.max_open_positions_per_symbol:
            return verdict(RiskAction.REJECT, f"max_open_positions_reached:{instrument}")

        # 4. Portfolio heat → reject new risk (high).
        if account.open_heat_pct >= p.heat.max_open_pct:
            return verdict(RiskAction.REJECT, "portfolio_heat_cap")

        # 5. Correlated exposure → throttle (medium).
        if account.positions_in_sector(sector) >= p.correlation.max_positions_same_sector:
            return verdict(RiskAction.REJECT, f"correlated_exposure_cap:{sector}")

        # 6. Loss streak → reduce size 50% (high, not a hard veto).
        size = requested_size
        streak_cut = account.consecutive_losses >= p.loss_streak.consecutive_losers
        if streak_cut:
            size = size * (Decimal(100) - p.loss_streak.size_cut_pct) / Decimal(100)

        # 7. Per-instrument unit cap → resize or reject (medium).
        if size > limits.max_position_units:
            size = limits.max_position_units
        if size <= 0:
            return verdict(RiskAction.REJECT, "size_reduced_to_zero")

        if size != requested_size:
            reason = "loss_streak_throttle" if streak_cut else "instrument_unit_cap"
            return verdict(RiskAction.REDUCE_SIZE, reason, adjusted=size)

        return verdict(RiskAction.ALLOW, "within_all_sovereign_limits")
