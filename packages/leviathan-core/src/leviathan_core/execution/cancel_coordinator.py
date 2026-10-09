"""Fake-first cancel and flatten policy execution.

The coordinator does not create an OMS order or dispatch a flatten. All side
effects are expressed through injected ports so tests can verify the durable
write-ahead and broker-evidence ordering.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Protocol

from leviathan_core.execution.broker_port_v1 import (
    BrokerOutcomeUnknown,
    BrokerRejected,
)
from leviathan_core.execution.cancel_policy import (
    CancelBrokerEvidenceV1,
    CancelExecutionV1,
    CancelPolicyCode,
    CancelPolicyError,
    CancelPolicyV1,
    CancelRequestV1,
    CancelResultV1,
    FlattenDecisionV1,
    FlattenPolicyV1,
    FlattenRequestV1,
    MassCancelRequestV1,
    MassCancelResultV1,
    PositionSnapshotV1,
    issue_cancel_result,
    issue_flatten_decision,
    issue_mass_cancel_result,
    require_cancel_broker_evidence,
    require_cancel_execution,
    require_cancel_policy,
    require_cancel_request,
    require_flatten_policy,
    require_flatten_request,
    require_mass_cancel_request,
    require_position_snapshot,
)


class CancelCoordinatorError(RuntimeError):
    """Stable, content-free coordinator failure."""

    def __init__(self, code: str) -> None:
        if code not in {"CANCEL_JOURNAL_UNAVAILABLE", "CANCEL_OUTCOME_UNKNOWN"}:
            raise ValueError("INVALID_CANCEL_COORDINATOR_ERROR")
        self.code = code
        super().__init__(code)


class CancelBrokerPort(Protocol):
    """Broker boundary used by the coordinator and fake transports."""

    async def cancel(self, request: CancelRequestV1) -> CancelBrokerEvidenceV1: ...

    async def reconcile(self, request: CancelRequestV1) -> CancelBrokerEvidenceV1: ...


class ChildDispatchPort(Protocol):
    """Stops local child dispatch before the broker cancel is attempted."""

    async def stop_children(self, request: CancelRequestV1) -> None: ...


class CancelJournalPort(Protocol):
    """Durable append-only cancellation journal; methods commit before return."""

    async def begin_cancel(self, request: CancelRequestV1) -> bool:
        """Durably claim the idempotency key; false means it already exists."""
        ...

    async def mark_cancel_sent(self, request: CancelRequestV1) -> None: ...

    async def record_state(
        self, request: CancelRequestV1, state: str, reason_code: str
    ) -> None: ...

    async def record_execution(
        self, request: CancelRequestV1, execution: CancelExecutionV1
    ) -> None: ...

    async def record_discrepancy(self, request: CancelRequestV1, code: str) -> None: ...

    async def alert_operator(self, request: CancelRequestV1, code: str) -> None: ...


class CoordinatorClockPort(Protocol):
    """Trusted UTC clock read at the start of each coordinator decision."""

    def now(self) -> datetime: ...


class CancelCoordinator:
    """Applies explicitly injected policy to cancel and flatten requests."""

    def __init__(
        self,
        *,
        cancel_policy: CancelPolicyV1,
        flatten_policy: FlattenPolicyV1 | None,
        broker: CancelBrokerPort,
        child_dispatch: ChildDispatchPort,
        journal: CancelJournalPort,
        clock: CoordinatorClockPort,
    ) -> None:
        self._cancel_policy = require_cancel_policy(cancel_policy)
        self._flatten_policy = (
            None if flatten_policy is None else require_flatten_policy(flatten_policy)
        )
        self._broker = broker
        self._child_dispatch = child_dispatch
        self._journal = journal
        if not callable(getattr(clock, "now", None)):
            raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST)
        self._clock = clock

    async def cancel(self, request: CancelRequestV1, *, halt_active: bool) -> CancelResultV1:
        """Stop children, issue at most one cancel, then reconcile uncertainty."""

        policy = self._cancel_policy
        request = require_cancel_request(request)
        self._read_clock_ns()
        if type(halt_active) is not bool:
            raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST)
        self._authorize_cancel(policy, request)

        # The durable claim precedes all effects. Existing claims only reconcile;
        # they never send a second cancel, including after a process restart.
        try:
            new_claim = await self._journal.begin_cancel(request)
        except Exception:
            raise CancelCoordinatorError("CANCEL_JOURNAL_UNAVAILABLE") from None
        if type(new_claim) is not bool:
            raise CancelCoordinatorError("CANCEL_JOURNAL_UNAVAILABLE")

        child_stopped = False
        try:
            await self._child_dispatch.stop_children(request)
            child_stopped = True
        except Exception:
            await self._record_state(
                request, "CANCEL_REQUESTED_UNCONFIRMED", "CHILD_DISPATCH_STOP_FAILED"
            )
            return await self._reconcile_result(
                request,
                child_dispatch_stopped=False,
                cancel_sent=False,
                reason_code=CancelPolicyCode.CHILD_DISPATCH_STOP_FAILED.value,
            )
        discrepancy_codes: tuple[str, ...] = ()
        if new_claim:
            try:
                await self._journal.mark_cancel_sent(request)
            except Exception:
                # The broker call is forbidden without a durable sent marker.
                await self._record_state(
                    request, "UNKNOWN_CANCEL", CancelPolicyCode.CANCEL_OUTCOME_UNKNOWN.value
                )
                return await self._reconcile_result(
                    request,
                    child_dispatch_stopped=child_stopped,
                    cancel_sent=False,
                    reason_code=CancelPolicyCode.CANCEL_OUTCOME_UNKNOWN.value,
                )
            try:
                evidence = await asyncio.wait_for(
                    self._broker.cancel(request), timeout=policy.cancel_timeout_ms / 1000
                )
                evidence = require_cancel_broker_evidence(evidence)
                self._validate_evidence(request, evidence, source="CANCEL_ACK")
                if evidence.cancel_confirmed and evidence.status == "CANCELED":
                    return await self._finish_from_evidence(
                        request,
                        evidence,
                        child_dispatch_stopped=child_stopped,
                        cancel_sent=True,
                        reconciled=False,
                    )
                await self._record_state(
                    request,
                    "CANCEL_REQUESTED_UNCONFIRMED",
                    "CANCEL_REQUESTED_UNCONFIRMED",
                )
            except BrokerRejected as error:
                rejection_code = error.code
                await self._record_state(request, "REJECTED", rejection_code)
                return self._result(
                    request,
                    lifecycle_state="REJECTED",
                    oms_state=None,
                    reason_code=rejection_code,
                    child_stopped=child_stopped,
                    cancel_sent=True,
                    reconciled=False,
                )
            except (BrokerOutcomeUnknown, TimeoutError):
                await self._record_state(
                    request,
                    "CANCEL_REQUESTED_UNCONFIRMED",
                    "CANCEL_REQUESTED_UNCONFIRMED",
                )
            except CancelPolicyError:
                await self._record_state(
                    request,
                    "UNKNOWN_CANCEL",
                    CancelPolicyCode.BROKER_EVIDENCE_MISMATCH.value,
                )
                await self._record_discrepancy(
                    request, CancelPolicyCode.BROKER_EVIDENCE_MISMATCH.value
                )
                discrepancy_codes = (CancelPolicyCode.BROKER_EVIDENCE_MISMATCH.value,)
            except Exception:
                # An untyped transport exception has an ambiguous outcome.
                await self._record_state(
                    request,
                    "UNKNOWN_CANCEL",
                    CancelPolicyCode.CANCEL_OUTCOME_UNKNOWN.value,
                )

        return await self._reconcile_result(
            request,
            child_dispatch_stopped=child_stopped,
            cancel_sent=new_claim,
            reason_code="CANCEL_REQUESTED_UNCONFIRMED",
            prior_discrepancy_codes=discrepancy_codes,
        )

    async def mass_cancel(
        self, request: MassCancelRequestV1, *, halt_active: bool
    ) -> MassCancelResultV1:
        """Apply a bounded, ordered mass cancel with an explicit resume cursor."""

        request = require_mass_cancel_request(request)
        self._read_clock_ns()
        if type(halt_active) is not bool:
            raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST)
        effective_halt = halt_active or request.halt_active
        if effective_halt and not self._cancel_policy.halt_requests_mass_cancel:
            raise CancelPolicyError(CancelPolicyCode.HALT_MASS_CANCEL_DENIED)
        self._authorize_operator_and_scope(
            self._cancel_policy,
            request.account_id,
            request.venue,
            request.environment,
            request.operator_id,
            request.scope,
        )
        if request.scope not in self._cancel_policy.allowed_scopes:
            raise CancelPolicyError(CancelPolicyCode.SCOPE_NOT_ALLOWED)
        if request.start_index >= len(request.requests):
            raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST)
        end = min(
            len(request.requests),
            request.start_index + self._cancel_policy.maximum_mass_cancel_orders,
        )
        results: list[CancelResultV1] = []
        for item in request.requests[request.start_index:end]:
            results.append(await self.cancel(item, halt_active=effective_halt))
        next_index = end if end < len(request.requests) else None
        return issue_mass_cancel_result(
            MassCancelResultV1(
                request_idempotency_key=request.idempotency_key,
                results=tuple(results),
                start_index=request.start_index,
                next_index=next_index,
                complete=next_index is None,
            )
        )

    def evaluate_flatten(
        self,
        request: FlattenRequestV1,
        position: PositionSnapshotV1,
        *,
        halt_active: bool,
    ) -> FlattenDecisionV1:
        """Return eligibility for later OMS review; never creates or sends an order."""

        request = require_flatten_request(request)
        position = require_position_snapshot(position)
        trusted_now_ns = self._read_clock_ns()
        if type(halt_active) is not bool:
            raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST)
        policy = self._flatten_policy
        if policy is None:
            return self._flatten_denial(CancelPolicyCode.FLATTEN_POLICY_REQUIRED.value)
        if halt_active or request.halt_active:
            return self._flatten_denial(CancelPolicyCode.HALT_FLATTEN_DENIED.value)
        if not request.human_confirmed:
            return self._flatten_denial(CancelPolicyCode.FLATTEN_NOT_ALLOWED.value)
        # ``now_ns`` remains on the request for wire compatibility, but it is
        # caller-controlled and cannot establish snapshot freshness. Use only
        # the coordinator's injected, trusted clock for authorization.
        age_ns = trusted_now_ns - position.observed_at_ns
        if age_ns < 0 or age_ns > policy.maximum_position_age_ns:
            return self._flatten_denial(CancelPolicyCode.POSITION_STALE.value)
        if (
            (request.account_id, request.venue, request.environment)
            != (policy.account_id, policy.venue, policy.environment)
            or (position.account_id, position.venue, position.environment)
            != (policy.account_id, policy.venue, policy.environment)
            or request.instrument_id != position.instrument_id
            or request.strategy_id != position.strategy_id
            or position.position_source != policy.position_source
            or request.operator_id not in policy.operator_ids
            or request.instrument_id not in policy.instrument_ids
            or request.strategy_id not in policy.strategy_ids
            or request.side not in policy.allowed_sides
            or request.session_state not in policy.allowed_session_states
        ):
            return self._flatten_denial(CancelPolicyCode.FLATTEN_NOT_ALLOWED.value)
        if (
            request.quantity > policy.maximum_quantity
            or request.slippage_bps > policy.maximum_slippage_bps
        ):
            return self._flatten_denial(CancelPolicyCode.FLATTEN_NOT_ALLOWED.value)
        if position.net_quantity == 0 or request.quantity > abs(position.net_quantity):
            return self._flatten_denial(CancelPolicyCode.FLATTEN_NOT_ALLOWED.value)
        reducing_side = "SELL" if position.net_quantity > 0 else "BUY"
        if request.side != reducing_side:
            return self._flatten_denial(CancelPolicyCode.FLATTEN_NOT_ALLOWED.value)
        return issue_flatten_decision(
            FlattenDecisionV1(
                policy_id=policy.policy_id,
                approved_for_oms_review=True,
                denial_code=None,
                dispatch_permitted=False,
                requires_fresh_risk_halt_oms_checks=True,
            )
        )

    def _authorize_cancel(self, policy: CancelPolicyV1, request: CancelRequestV1) -> None:
        self._authorize_operator_and_scope(
            policy,
            request.account_id,
            request.venue,
            request.environment,
            request.operator_id,
            request.scope,
        )
        if request.scope not in policy.allowed_scopes:
            raise CancelPolicyError(CancelPolicyCode.SCOPE_NOT_ALLOWED)
        if request.instrument_id not in policy.instrument_ids:
            raise CancelPolicyError(CancelPolicyCode.SCOPE_NOT_ALLOWED)
        if request.strategy_id not in policy.strategy_ids:
            raise CancelPolicyError(CancelPolicyCode.SCOPE_NOT_ALLOWED)
        if request.protective_leg and policy.protective_leg_action == "PRESERVE":
            raise CancelPolicyError(CancelPolicyCode.SCOPE_NOT_ALLOWED)
        if request.trigger == "HALT" and not policy.halt_requests_mass_cancel:
            raise CancelPolicyError(CancelPolicyCode.HALT_MASS_CANCEL_DENIED)

    @staticmethod
    def _authorize_operator_and_scope(
        policy: CancelPolicyV1,
        account_id: str,
        venue: str,
        environment: str,
        operator_id: str,
        scope: str,
    ) -> None:
        if (
            account_id != policy.account_id
            or venue != policy.venue
            or environment != policy.environment
        ):
            raise CancelPolicyError(CancelPolicyCode.SCOPE_NOT_ALLOWED)
        if operator_id not in policy.allowed_operator_ids:
            raise CancelPolicyError(CancelPolicyCode.OPERATOR_NOT_ALLOWED)
        if scope not in policy.allowed_scopes:
            raise CancelPolicyError(CancelPolicyCode.SCOPE_NOT_ALLOWED)

    async def _reconcile_result(
        self,
        request: CancelRequestV1,
        *,
        child_dispatch_stopped: bool,
        cancel_sent: bool,
        reason_code: str,
        prior_discrepancy_codes: tuple[str, ...] = (),
    ) -> CancelResultV1:
        try:
            evidence = require_cancel_broker_evidence(await self._broker.reconcile(request))
            self._validate_evidence(request, evidence, source="RECONCILIATION")
            if evidence.cancel_confirmed and evidence.status == "CANCELED":
                return await self._finish_from_evidence(
                    request,
                    evidence,
                    child_dispatch_stopped=child_dispatch_stopped,
                    cancel_sent=cancel_sent,
                    reconciled=True,
                    prior_discrepancy_codes=prior_discrepancy_codes,
                )
            fill_ids = await self._record_executions(request, evidence.executions)
            discrepancy_codes, alert_codes = await self._post_gtd_fill_evidence(
                request,
                evidence.executions,
                prior_discrepancy_codes=prior_discrepancy_codes,
            )
            await self._record_state(
                request,
                "CANCEL_REQUESTED_UNCONFIRMED",
                CancelPolicyCode.CANCEL_OUTCOME_UNKNOWN.value,
            )
            return self._result(
                request,
                lifecycle_state="CANCEL_REQUESTED_UNCONFIRMED",
                oms_state="UNKNOWN_CANCEL",
                reason_code=reason_code,
                child_stopped=child_dispatch_stopped,
                cancel_sent=cancel_sent,
                reconciled=True,
                discrepancy_codes=discrepancy_codes,
                alert_codes=alert_codes,
                fill_execution_ids=fill_ids,
            )
        except CancelPolicyError:
            code = CancelPolicyCode.BROKER_EVIDENCE_MISMATCH.value
            await self._record_discrepancy(request, code)
            await self._record_state(request, "UNKNOWN_CANCEL", code)
            return self._result(
                request,
                lifecycle_state="CANCEL_REQUESTED_UNCONFIRMED",
                oms_state="UNKNOWN_CANCEL",
                reason_code=code,
                child_stopped=child_dispatch_stopped,
                cancel_sent=cancel_sent,
                reconciled=True,
                discrepancy_codes=tuple(dict.fromkeys((*prior_discrepancy_codes, code))),
            )
        except Exception:
            await self._record_state(
                request, "UNKNOWN_CANCEL", CancelPolicyCode.CANCEL_OUTCOME_UNKNOWN.value
            )
            return self._result(
                request,
                lifecycle_state="CANCEL_REQUESTED_UNCONFIRMED",
                oms_state="UNKNOWN_CANCEL",
                reason_code=CancelPolicyCode.CANCEL_OUTCOME_UNKNOWN.value,
                child_stopped=child_dispatch_stopped,
                cancel_sent=cancel_sent,
                reconciled=False,
                discrepancy_codes=prior_discrepancy_codes,
            )

    async def _finish_from_evidence(
        self,
        request: CancelRequestV1,
        evidence: CancelBrokerEvidenceV1,
        *,
        child_dispatch_stopped: bool,
        cancel_sent: bool,
        reconciled: bool,
        prior_discrepancy_codes: tuple[str, ...] = (),
    ) -> CancelResultV1:
        fill_ids = await self._record_executions(request, evidence.executions)
        discrepancy_codes, alert_codes = await self._post_gtd_fill_evidence(
            request,
            evidence.executions,
            prior_discrepancy_codes=prior_discrepancy_codes,
        )
        await self._record_state(request, "CANCELED", "BROKER_CANCEL_CONFIRMED")
        return self._result(
            request,
            lifecycle_state="CANCELED",
            oms_state="CANCELED",
            reason_code="BROKER_CANCEL_CONFIRMED",
            child_stopped=child_dispatch_stopped,
            cancel_sent=cancel_sent,
            reconciled=reconciled,
            discrepancy_codes=discrepancy_codes,
            alert_codes=alert_codes,
            fill_execution_ids=fill_ids,
        )

    async def _post_gtd_fill_evidence(
        self,
        request: CancelRequestV1,
        executions: tuple[CancelExecutionV1, ...],
        *,
        prior_discrepancy_codes: tuple[str, ...] = (),
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        discrepancy_codes = prior_discrepancy_codes
        alert_codes: tuple[str, ...] = ()
        if request.gtd_expiry_ns is not None and any(
            _execution_time_ns(item) > request.gtd_expiry_ns for item in executions
        ):
            await self._record_discrepancy(request, "POST_GTD_FILL")
            try:
                await self._journal.alert_operator(request, "POST_GTD_FILL")
            except Exception:
                raise CancelCoordinatorError("CANCEL_JOURNAL_UNAVAILABLE") from None
            discrepancy_codes = tuple(dict.fromkeys((*discrepancy_codes, "POST_GTD_FILL")))
            alert_codes = ("POST_GTD_FILL",)
        return discrepancy_codes, alert_codes

    async def _record_executions(
        self, request: CancelRequestV1, executions: tuple[CancelExecutionV1, ...]
    ) -> tuple[str, ...]:
        ids: list[str] = []
        for execution in executions:
            try:
                execution = require_cancel_execution(execution)
            except Exception:
                raise CancelPolicyError(CancelPolicyCode.BROKER_EVIDENCE_MISMATCH) from None
            if (
                execution.client_order_id not in {None, request.client_order_id}
                or execution.venue_order_id != request.venue_order_id
                or execution.instrument_id != request.instrument_id
                or execution.side != request.side
            ):
                raise CancelPolicyError(CancelPolicyCode.BROKER_EVIDENCE_MISMATCH)
            await self._journal.record_execution(request, execution)
            ids.append(execution.execution_id)
        return tuple(ids)

    def _validate_evidence(
        self,
        request: CancelRequestV1,
        evidence: CancelBrokerEvidenceV1,
        *,
        source: str,
    ) -> None:
        if (
            evidence.source != source
            or evidence.order_id != request.order_id
            or evidence.client_order_id != request.client_order_id
            or evidence.venue_order_id != request.venue_order_id
            or evidence.account_id != request.account_id
            or evidence.venue != request.venue
            or evidence.environment != request.environment
            or evidence.instrument_id != request.instrument_id
            or evidence.side != request.side
        ):
            raise CancelPolicyError(CancelPolicyCode.BROKER_EVIDENCE_MISMATCH)

    async def _record_state(self, request: CancelRequestV1, state: str, code: str) -> None:
        try:
            await self._journal.record_state(request, state, code)
        except Exception:
            raise CancelCoordinatorError("CANCEL_JOURNAL_UNAVAILABLE") from None

    async def _record_discrepancy(self, request: CancelRequestV1, code: str) -> None:
        try:
            await self._journal.record_discrepancy(request, code)
        except Exception:
            raise CancelCoordinatorError("CANCEL_JOURNAL_UNAVAILABLE") from None

    def _read_clock_ns(self) -> int:
        try:
            value = self._clock.now()
        except Exception:
            raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST) from None
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST)
        timestamp_ns = _datetime_time_ns(value)
        if timestamp_ns < 0:
            raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST)
        return timestamp_ns

    @staticmethod
    def _result(
        request: CancelRequestV1,
        *,
        lifecycle_state: str,
        oms_state: str | None,
        reason_code: str,
        child_stopped: bool,
        cancel_sent: bool,
        reconciled: bool,
        discrepancy_codes: tuple[str, ...] = (),
        alert_codes: tuple[str, ...] = (),
        fill_execution_ids: tuple[str, ...] = (),
    ) -> CancelResultV1:
        return issue_cancel_result(
            CancelResultV1(
                order_id=request.order_id,
                idempotency_key=request.idempotency_key,
                lifecycle_state=lifecycle_state,  # type: ignore[arg-type]
                oms_state=oms_state,  # type: ignore[arg-type]
                reason_code=reason_code,
                child_dispatch_stopped=child_stopped,
                cancel_sent=cancel_sent,
                reconciled=reconciled,
                discrepancy_codes=discrepancy_codes,
                operator_alert_codes=alert_codes,
                fill_execution_ids=fill_execution_ids,
            )
        )

    @staticmethod
    def _flatten_denial(code: str) -> FlattenDecisionV1:
        return issue_flatten_decision(
            FlattenDecisionV1(
                policy_id=None,
                approved_for_oms_review=False,
                denial_code=code,
                dispatch_permitted=False,
                requires_fresh_risk_halt_oms_checks=False,
            )
        )


def _execution_time_ns(execution: CancelExecutionV1) -> int:
    executed_at = execution.executed_at.astimezone(UTC)
    delta = executed_at - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def _datetime_time_ns(value: datetime) -> int:
    delta = value.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


__all__ = [
    "CancelBrokerPort",
    "CancelCoordinator",
    "CancelCoordinatorError",
    "CancelJournalPort",
    "ChildDispatchPort",
    "CoordinatorClockPort",
]
