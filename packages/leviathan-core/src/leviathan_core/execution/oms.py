"""Durable fake-only order gateway; no funded transport can be injected."""

from __future__ import annotations

import asyncio
import hashlib
import threading
import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal, NoReturn, Protocol, SupportsIndex, cast
from weakref import WeakKeyDictionary, WeakSet

from leviathan_core.execution.broker_port import FakeBrokerPort, FakeDispatchPermit
from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerOutcomeUnknown,
    BrokerPortError,
    BrokerPortV1,
    BrokerRejected,
    BrokerRejectionCode,
    CancelResultV1,
    ExecutionV1,
    SubmitResultV1,
    VenueDispatchCapabilityV1,
    VenueIdentityV1,
)
from leviathan_core.execution.broker_reconciliation import (
    BrokerAccountView,
    BrokerExecution,
    BrokerLookup,
    BrokerMatch,
    BrokerReconciliationPort,
    BrokerReconciliationStatus,
    FakeBrokerReconciliation,
    broker_evidence_digest,
)
from leviathan_core.execution.order_models import (
    BrokerObservation,
    ClientIdKey,
    DispatchGuard,
    Fill,
    FillCorrection,
    OMSConflict,
    OMSDiscrepancy,
    OMSLedgerCorruption,
    OMSStaleBrokerView,
    OMSValidationError,
    OperatorAuthorizationKey,
    OperatorGuardConfirmation,
    OperatorGuardReview,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
)
from leviathan_core.execution.venue_conflict_resolution import (
    VenueConflictResolutionCode,
    VenueConflictResolutionError,
    VenueConflictResolutionRequest,
    VenueConflictResolutionResult,
    VenueConflictReview,
    issue_venue_conflict_resolution_result,
    issue_venue_conflict_review,
    require_venue_conflict_resolution_request,
)
from leviathan_core.numeric import NumericError, canonical_json, exact_sum
from leviathan_core.seal import require
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

_ISSUER = object()
_ISSUING: ContextVar[object | None] = ContextVar("oms_actor_issuing", default=None)
_ISSUED_GATEWAYS: WeakSet[OrderGateway] = WeakSet()
_ISSUED_ACTORS: WeakSet[OrderGatewayActor] = WeakSet()
_GATEWAY_TASKS: WeakKeyDictionary[OrderGateway, asyncio.Task[Any]] = WeakKeyDictionary()

ActivityOrderRow = tuple[int, OrderSnapshot, datetime]
ActivityFillRow = tuple[int, str, Fill]
ActivityCorrectionRow = tuple[int, str, FillCorrection]
ActivityLedgerSnapshot = tuple[
    int,
    tuple[ActivityOrderRow, ...],
    tuple[ActivityFillRow, ...],
    tuple[ActivityCorrectionRow, ...],
]


@dataclass(frozen=True, slots=True)
class VerifiedSubmitSnapshot:
    """Immutable order and execution evidence derived from one ledger audit."""

    environment: str
    account_id: str
    account_inventory: tuple[OrderSnapshot, ...]
    account_identity_inventory: tuple[OrderSnapshot, ...]
    account_execution_evidence: tuple[tuple[str, Fill], ...]
    account_fill_corrections: tuple[tuple[str, FillCorrection], ...]

    def __post_init__(self) -> None:
        if (
            type(self.environment) is not str
            or self.environment not in {"paper", "demo"}
            or type(self.account_id) is not str
            or not self.account_id
            or type(self.account_inventory) is not tuple
            or type(self.account_identity_inventory) is not tuple
            or type(self.account_execution_evidence) is not tuple
            or type(self.account_fill_corrections) is not tuple
            or any(type(order) is not OrderSnapshot for order in self.account_inventory)
            or any(type(order) is not OrderSnapshot for order in self.account_identity_inventory)
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not Fill
                for item in self.account_execution_evidence
            )
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not FillCorrection
                for item in self.account_fill_corrections
            )
            or any(
                order.request.environment != self.environment
                or order.request.account_id != self.account_id
                for order in self.account_inventory
            )
            or any(
                order.request.account_id != self.account_id
                for order in self.account_identity_inventory
            )
            or any(
                fill.account_id != self.account_id for _, fill in self.account_execution_evidence
            )
            or any(
                correction.account_id != self.account_id
                for _, correction in self.account_fill_corrections
            )
        ):
            raise OMSValidationError("INVALID_VERIFIED_SUBMIT_SNAPSHOT")


@dataclass(frozen=True, slots=True)
class ActivityOrderItem:
    ledger_sequence: int
    snapshot: OrderSnapshot
    created_at: datetime


@dataclass(frozen=True, slots=True)
class ActivityFillItem:
    ledger_sequence: int
    order_id: str
    instrument_id: str
    side: Literal["BUY", "SELL"]
    fill: Fill


@dataclass(frozen=True, slots=True)
class ActivityCorrectionItem:
    ledger_sequence: int
    order_id: str
    instrument_id: str
    side: Literal["BUY", "SELL"]
    correction: FillCorrection


ActivityItem = ActivityOrderItem | ActivityFillItem | ActivityCorrectionItem
ActivityNetGroup = tuple[str, str, Decimal]


@dataclass(frozen=True, slots=True)
class ActivityLedgerPage:
    high_water_sequence: int
    items: tuple[ActivityItem, ...]
    has_more: bool
    net_filled_units: tuple[ActivityNetGroup, ...]


class DispatchGateCode(StrEnum):
    ALLOW = "ALLOW"
    DENY_HALT = "DENY_HALT"
    DENY_KILL = "DENY_KILL"
    DENY_SCOPE = "DENY_SCOPE"
    DENY_UNAVAILABLE = "DENY_UNAVAILABLE"


class DispatchGate(Protocol):
    def check(
        self, action: Literal["SUBMIT", "CANCEL"], scope: OrderSnapshot
    ) -> DispatchGateCode: ...


class _DefaultDispatchGate:
    def __init__(self, *, test_factory: bool) -> None:
        self._test_factory = test_factory

    def check(self, action: Literal["SUBMIT", "CANCEL"], scope: OrderSnapshot) -> DispatchGateCode:
        if self._test_factory and scope.request.environment in {"paper", "demo"}:
            return DispatchGateCode.ALLOW
        return DispatchGateCode.DENY_SCOPE


class OrderLedgerPort(Protocol):
    dispatch_mutex: asyncio.Lock
    active_dispatch: set[str]

    async def create(self, request: OrderRequest) -> OrderSnapshot: ...
    async def get(self, order_id: str) -> OrderSnapshot | None: ...
    async def reject_risk(self, order_id: str, code: str) -> OrderSnapshot: ...
    async def mark_submitting(
        self, order_id: str, evidence: PaperDispatchEvidence
    ) -> OrderSnapshot: ...
    async def arm_dispatch_guard(
        self, order_id: str, *, action: str, broker_revision: int
    ) -> OrderSnapshot: ...
    async def complete_guarded_submit(
        self,
        order_id: str,
        state: OrderState,
        venue_order_id: str | None = None,
        *,
        conflict: bool = False,
        cancel_confirmed: bool = False,
        rejection_code: BrokerRejectionCode | None = None,
        cancel_gate_denied: bool = False,
    ) -> OrderSnapshot: ...
    async def complete_guarded_cancel(
        self,
        order_id: str,
        state: OrderState,
        *,
        verified_clean: bool,
        conflict: bool = False,
    ) -> OrderSnapshot: ...
    async def complete_guarded_gate_denial(
        self, order_id: str, *, action: str, reason: str
    ) -> OrderSnapshot: ...
    async def account_guard(self, environment: str, account_id: str) -> DispatchGuard | None: ...
    async def assert_dispatch_fence(self, order_id: str, fence_epoch: int) -> DispatchGuard: ...
    async def operator_guard_context(
        self, environment: str, account_id: str
    ) -> tuple[DispatchGuard, str, OrderSnapshot, tuple[bytes, ...]]: ...
    async def operator_release_guard(
        self,
        order_id: str,
        confirmation: OperatorGuardConfirmation,
        lookup: BrokerLookup,
        view: BrokerAccountView,
    ) -> OrderSnapshot: ...
    async def arm_compensating_cancel(self, order_id: str) -> OrderSnapshot: ...
    async def mark_submit_result(
        self, order_id: str, state: OrderState, venue_order_id: str | None = None
    ) -> OrderSnapshot: ...
    async def mark_cancel_pending(self, order_id: str) -> OrderSnapshot: ...
    async def mark_cancel_result(self, order_id: str, state: OrderState) -> OrderSnapshot: ...
    async def record_fill(self, order_id: str, fill: Fill) -> OrderSnapshot: ...
    async def record_fill_correction(
        self, order_id: str, correction: FillCorrection
    ) -> OrderSnapshot: ...
    async def record_observation(
        self, order_id: str, observation: BrokerObservation
    ) -> OrderSnapshot: ...
    async def record_reconcile_pending(self, order_id: str, code: str) -> OrderSnapshot: ...
    async def mark_venue_mismatch(self, order_id: str, action: str) -> OrderSnapshot: ...
    async def mark_venue_account_conflict(
        self,
        order_id: str,
        *,
        binding_venue: str | None = None,
        binding_environment: str | None = None,
        observations: tuple[tuple[str, str, str], ...] = (),
        affected_order_ids: tuple[str, ...] = (),
    ) -> OrderSnapshot: ...
    async def venue_conflict_context(self, environment: str, account_id: str) -> dict[str, Any]: ...
    async def find_venue_conflict_resolution(
        self, request: VenueConflictResolutionRequest
    ) -> dict[str, Any] | None: ...
    async def append_venue_conflict_resolution(
        self,
        request: VenueConflictResolutionRequest,
        *,
        broker_revision: int,
        broker_evidence_digest: str,
        observed_at_ns: int,
    ) -> dict[str, Any]: ...
    async def clear_venue_conflict_quarantine(
        self,
        request: VenueConflictResolutionRequest,
        *,
        resolution_id: str,
        broker_revision: int,
        broker_evidence_digest: str,
        restored_states: dict[str, OrderState],
    ) -> dict[str, Any]: ...
    async def is_exact_venue_conflict_resolved(
        self,
        *,
        environment: str,
        account_id: str,
        binding_venue: str,
        binding_environment: str,
        observation_ids: tuple[str, ...],
        affected_order_ids: tuple[str, ...],
        identity_digest: str,
    ) -> bool: ...
    async def mark_broker_intent_found(
        self, order_id: str, match: BrokerMatch
    ) -> OrderSnapshot: ...
    async def mark_broker_account_unmatched(self, order_id: str) -> OrderSnapshot: ...
    async def mark_submit_stale(self, order_id: str) -> OrderSnapshot: ...
    async def mark_pre_dispatch_stale_conflict(self, order_id: str) -> OrderSnapshot: ...
    async def mark_post_dispatch_conflict(
        self, order_id: str, *, cancel_confirmed: bool
    ) -> OrderSnapshot: ...
    async def account_inventory(
        self, environment: str, account_id: str
    ) -> tuple[OrderSnapshot, ...]: ...
    async def account_identity_inventory(self, account_id: str) -> tuple[OrderSnapshot, ...]: ...
    async def account_execution_evidence(
        self, environment: str, account_id: str
    ) -> tuple[tuple[str, Fill], ...]: ...
    async def verified_submit_snapshot(
        self, environment: str, account_id: str
    ) -> VerifiedSubmitSnapshot: ...
    async def account_activity_snapshot(
        self, environment: str, account_id: str, high_water_sequence: int | None = None
    ) -> ActivityLedgerSnapshot: ...
    async def account_activity_page(
        self,
        environment: str,
        account_id: str,
        *,
        after_sequence: int,
        high_water_sequence: int | None,
        limit: int,
    ) -> ActivityLedgerPage: ...
    async def begin_activity_read_snapshot(self, environment: str, account_id: str) -> object: ...
    async def activity_page_from_snapshot(
        self,
        snapshot: object,
        *,
        after_sequence: int,
        high_water_sequence: int | None,
        limit: int,
    ) -> ActivityLedgerPage: ...
    async def activity_snapshot_from_snapshot(
        self, snapshot: object, high_water_sequence: int | None
    ) -> ActivityLedgerSnapshot: ...
    async def close_activity_read_snapshot(self, snapshot: object) -> None: ...
    async def recover_uncertain(self) -> list[OrderSnapshot]: ...


class OrderGateway:
    """Stateful orchestration around a durable ledger and exact fake transport."""

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise OMSValidationError("OMS_ACTOR_REQUIRED")

    def __init__(
        self,
        ledger: OrderLedgerPort,
        broker: BrokerPortV1,
        reconciliation: BrokerReconciliationPort | None = None,
        client_id_key: ClientIdKey | None = None,
        operator_key: OperatorAuthorizationKey | None = None,
        dispatch_gate: DispatchGate | None = None,
    ) -> None:
        if _ISSUING.get() is not _ISSUER or self in _ISSUED_GATEWAYS:
            raise OMSValidationError("OMS_ACTOR_REQUIRED")
        if not isinstance(broker, BrokerPortV1):
            raise OMSValidationError("BROKER_PORT_V1_REQUIRED")
        if (
            type(broker.capability) is not VenueDispatchCapabilityV1
            or type(broker.venue) is not VenueIdentityV1
        ):
            raise OMSValidationError("BROKER_PORT_V1_REQUIRED")
        broker.capability.assert_sealed()
        broker.venue.assert_sealed()
        if (
            reconciliation is None
            or not callable(getattr(reconciliation, "find_by_client_order_id", None))
            or not callable(getattr(reconciliation, "account_view", None))
        ):
            raise OMSValidationError("BROKER_RECONCILIATION_REQUIRED")
        if isinstance(broker, FakeBrokerPort) and broker.reconciliation is not reconciliation:
            raise OMSValidationError("FAKE_RECONCILIATION_REQUIRED")
        if type(client_id_key) is not ClientIdKey:
            raise OMSValidationError("CLIENT_ID_KEY_REQUIRED")
        if dispatch_gate is None or not callable(getattr(dispatch_gate, "check", None)):
            raise OMSValidationError("DISPATCH_GATE_REQUIRED")
        self._ledger = ledger
        self._broker = broker
        self._reconciliation = reconciliation
        self._client_id_key = client_id_key
        self._operator_key = operator_key
        self._dispatch_gate = dispatch_gate
        self._dispatch_mutex = ledger.dispatch_mutex
        self._active_dispatch = ledger.active_dispatch
        _ISSUED_GATEWAYS.add(self)

    @property
    def venue(self) -> VenueIdentityV1:
        identity = self._broker.venue
        identity.assert_sealed()
        return identity

    @property
    def dispatch_gate(self) -> DispatchGate:
        """The exact final-seam gate installed for this gateway."""
        return self._dispatch_gate

    def _gate_code(
        self, action: Literal["SUBMIT", "CANCEL"], order: OrderSnapshot
    ) -> DispatchGateCode:
        try:
            decision = self._dispatch_gate.check(action, order)
        except Exception:
            return DispatchGateCode.DENY_UNAVAILABLE
        if type(decision) is not DispatchGateCode:
            return DispatchGateCode.DENY_UNAVAILABLE
        if action == "CANCEL" and decision in {
            DispatchGateCode.DENY_HALT,
            DispatchGateCode.DENY_KILL,
        }:
            return DispatchGateCode.ALLOW
        return decision

    async def _broker_account_view(
        self,
        account_id: str,
        *,
        identity_inventory: tuple[OrderSnapshot, ...] | None = None,
    ) -> tuple[BrokerAccountView, AccountViewV1] | AccountViewV1:
        """Return a consistent pair or an isolated venue-conflict image."""
        # Stage the independent reference first, but do not inspect or consume
        # it if the sealed port image proves an account-identity conflict.
        reference = await self._reconciliation.account_view(account_id, None)
        try:
            image = self._broker.read_account_view(account_id)
        except BrokerOutcomeUnknown:
            # If the port cannot supply an image, retain the independently
            # typed reconciliation failure instead of flattening AMBIGUOUS or
            # UNAVAILABLE into a generic read failure.
            if type(reference) is BrokerAccountView:
                if reference.status is BrokerReconciliationStatus.UNAVAILABLE:
                    raise OMSValidationError("BROKER_RECONCILIATION_UNAVAILABLE") from None
                if reference.status is BrokerReconciliationStatus.AMBIGUOUS:
                    raise OMSValidationError("BROKER_RECONCILIATION_AMBIGUOUS") from None
            raise
        if type(image) is not AccountViewV1:
            raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
        image.assert_sealed()
        if image.account_id != account_id:
            raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
        if identity_inventory is None:
            identity_inventory = await self._ledger.account_identity_inventory(account_id)
        if identity_inventory:
            binding = (
                identity_inventory[0].request.venue,
                identity_inventory[0].request.environment,
            )
            if any(
                (observation.venue, observation.environment) != binding
                for observation in image.open_orders
            ):
                return image
        if any(
            observation.venue != self._broker.venue.venue.value
            or observation.environment != self._broker.venue.environment.value.lower()
            for observation in image.open_orders
        ):
            return image
        if type(reference) is not BrokerAccountView:
            raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
        if reference.status is BrokerReconciliationStatus.UNAVAILABLE:
            raise OMSValidationError("BROKER_RECONCILIATION_UNAVAILABLE")
        if reference.status is BrokerReconciliationStatus.AMBIGUOUS:
            raise OMSValidationError("BROKER_RECONCILIATION_AMBIGUOUS")
        if image.executions_since > datetime(1970, 1, 1, tzinfo=UTC):
            raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
        amounts: dict[str, list[Decimal]] = {}
        executions: list[BrokerExecution] = []
        for execution in image.executions:
            execution.assert_sealed()
            client_id = execution.client_order_id
            if client_id is None:
                raise OMSValidationError("BROKER_ACCOUNT_ACTIVITY_UNMATCHED")
            amounts.setdefault(client_id, []).append(execution.quantity)
            executions.append(
                BrokerExecution(account_id, client_id, execution.execution_id, execution.quantity)
            )
        orders: list[BrokerMatch] = []
        for observation in image.open_orders:
            if observation.account_id != account_id:
                raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
            orders.append(
                BrokerMatch(
                    account_id,
                    observation.client_order_id,
                    observation.venue_order_id,
                    observation.status,
                    exact_sum(amounts.get(observation.client_order_id, ())),
                )
            )
        converted = BrokerAccountView(
            BrokerReconciliationStatus.FOUND
            if orders or executions
            else BrokerReconciliationStatus.NOT_FOUND,
            image.broker_revision,
            tuple(sorted(orders, key=lambda item: item.client_order_id)),
            tuple(sorted(executions, key=lambda item: (item.client_order_id, item.execution_id))),
        )
        if converted != reference:
            raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
        return converted, image

    def _require_actor_task(self) -> None:
        if self not in _ISSUED_GATEWAYS or _GATEWAY_TASKS.get(self) is not asyncio.current_task():
            raise OMSValidationError("OMS_ACTOR_REQUIRED")

    def __copy__(self) -> None:
        raise OMSValidationError("OMS_ACTOR_REQUIRED")

    def __deepcopy__(self, _memo: object) -> None:
        raise OMSValidationError("OMS_ACTOR_REQUIRED")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise OMSValidationError("OMS_ACTOR_REQUIRED")

    async def _account_venue_conflict(
        self,
        inventory: tuple[OrderSnapshot, ...],
        image: AccountViewV1 | None = None,
    ) -> bool:
        """Quarantine any departure from this account's first durable identity."""
        if not inventory:
            raise OMSValidationError("OMS_LEDGER_CORRUPT")
        first = inventory[0]
        binding = (first.request.venue, first.request.environment)
        different_orders = tuple(
            item for item in inventory if (item.request.venue, item.request.environment) != binding
        )
        different_observations = (
            ()
            if image is None
            else tuple(
                item for item in image.open_orders if (item.venue, item.environment) != binding
            )
        )
        port_binding = (
            self._broker.venue.venue.value,
            self._broker.venue.environment.value.lower(),
        )
        observation_ids = tuple(sorted({item.observation_id for item in different_observations}))
        observed_order_ids = {
            item.order_id
            for observation in different_observations
            for item in inventory
            if (
                item.request.client_order_id == observation.client_order_id
                or (
                    item.venue_order_id is not None
                    and item.venue_order_id == observation.venue_order_id
                )
            )
        }
        affected_order_ids = tuple(
            sorted(
                {
                    first.order_id,
                    *(item.order_id for item in different_orders),
                    *observed_order_ids,
                }
            )
        )
        if observation_ids:
            identity_digest = hashlib.sha256(
                canonical_json(
                    {
                        "environment": first.request.environment,
                        "account_id": first.request.account_id,
                        "binding_venue": binding[0],
                        "binding_environment": binding[1],
                        "observations": [
                            [item.observation_id, item.venue, item.environment]
                            for item in sorted(
                                different_observations, key=lambda value: value.observation_id
                            )
                        ],
                        "affected_order_ids": list(affected_order_ids),
                    }
                )
            ).hexdigest()
            if await self._ledger.is_exact_venue_conflict_resolved(
                environment=first.request.environment,
                account_id=first.request.account_id,
                binding_venue=binding[0],
                binding_environment=binding[1],
                observation_ids=observation_ids,
                affected_order_ids=affected_order_ids,
                identity_digest=identity_digest,
            ):
                return False
        if not (
            different_orders
            or different_observations
            or port_binding != binding
            or self._broker.venue.account_id != first.request.account_id
            or any("VENUE_ACCOUNT_CONFLICT" in item.discrepancies for item in inventory)
        ):
            return False
        await self._ledger.mark_venue_account_conflict(
            first.order_id,
            binding_venue=binding[0] if observation_ids else None,
            binding_environment=binding[1] if observation_ids else None,
            observations=tuple(
                sorted(
                    (item.observation_id, item.venue, item.environment)
                    for item in different_observations
                )
            ),
            affected_order_ids=affected_order_ids if observation_ids else (),
        )
        conflicted_ids = {first.order_id}
        for item in different_orders:
            if item.order_id not in conflicted_ids:
                await self._ledger.mark_venue_account_conflict(item.order_id)
                conflicted_ids.add(item.order_id)
        for observation in different_observations:
            observed_order = next(
                (
                    item
                    for item in inventory
                    if (
                        item.request.client_order_id == observation.client_order_id
                        or (
                            item.venue_order_id is not None
                            and item.venue_order_id == observation.venue_order_id
                        )
                    )
                ),
                None,
            )
            if observed_order is not None and observed_order.order_id not in conflicted_ids:
                await self._ledger.mark_venue_account_conflict(observed_order.order_id)
                conflicted_ids.add(observed_order.order_id)
        return True

    def _account_view_matches(
        self,
        view: BrokerAccountView,
        inventory: tuple[OrderSnapshot, ...],
        port_image: AccountViewV1 | None = None,
    ) -> bool:
        local: dict[str, OrderSnapshot] = {}
        for snapshot in inventory:
            request = snapshot.request
            if (
                request.venue != self._broker.venue.venue.value
                or request.environment != self._broker.venue.environment.value.lower()
                or request.account_id != self._broker.venue.account_id
            ):
                return False
            expected = self._client_id_key.derive(
                request.account_id, request.intent_idempotency_key, request.attempt
            )
            if request.client_order_id != expected or expected in local:
                return False
            local[expected] = snapshot
        broker_orders: set[str] = set()
        for match in view.orders:
            local_snapshot = local.get(match.client_order_id)
            if (
                local_snapshot is None
                or match.account_id != local_snapshot.request.account_id
                or local_snapshot.state != match.state
                or local_snapshot.venue_order_id != match.venue_order_id
                or local_snapshot.filled_quantity != match.filled_quantity
                or match.client_order_id in broker_orders
            ):
                return False
            broker_orders.add(match.client_order_id)
        broker_executions: dict[str, list[Decimal]] = {}
        for execution in view.executions:
            local_snapshot = local.get(execution.client_order_id)
            if local_snapshot is None or execution.account_id != local_snapshot.request.account_id:
                return False
            broker_executions.setdefault(execution.client_order_id, []).append(execution.quantity)
        for client_id, snapshot in local.items():
            if (
                snapshot.state
                in {
                    OrderState.SUBMITTING,
                    OrderState.WORKING,
                    OrderState.PARTIALLY_FILLED,
                    OrderState.CANCEL_PENDING,
                    OrderState.CANCEL_REQUESTED_UNCONFIRMED,
                    OrderState.UNKNOWN_SUBMIT,
                    OrderState.UNKNOWN_CANCEL,
                }
                and client_id not in broker_orders
            ):
                return False
            try:
                broker_filled = exact_sum(broker_executions.get(client_id, []))
            except NumericError:
                return False
            if broker_filled != snapshot.filled_quantity:
                return False
        if port_image is not None:
            if any(
                observation.venue != self._broker.venue.venue.value
                or observation.environment != self._broker.venue.environment.value.lower()
                for observation in port_image.open_orders
            ):
                return False
            expected_positions: dict[str, list[Decimal]] = {}
            for snapshot in inventory:
                if snapshot.filled_quantity == 0:
                    continue
                signed = (
                    snapshot.filled_quantity
                    if snapshot.request.side == "BUY"
                    else -snapshot.filled_quantity
                )
                expected_positions.setdefault(snapshot.request.instrument_id, []).append(signed)
            try:
                positions = tuple(
                    (instrument, exact_sum(values))
                    for instrument, values in sorted(expected_positions.items())
                )
            except NumericError:
                return False
            if positions != port_image.positions:
                return False
        return True

    async def _execution_evidence_conflict(
        self,
        inventory: tuple[OrderSnapshot, ...],
        image: AccountViewV1,
        *,
        persisted: tuple[tuple[str, Fill], ...] | None = None,
    ) -> str | None:
        """Find the order whose authenticated fill differs from broker evidence."""
        if not inventory:
            return None
        environment = inventory[0].request.environment
        account_id = inventory[0].request.account_id
        if persisted is None:
            persisted = await self._ledger.account_execution_evidence(environment, account_id)
        orders = {order.order_id: order for order in inventory}
        broker = {execution.execution_id: execution for execution in image.executions}
        for order_id, fill in persisted:
            order = orders[order_id]
            execution: ExecutionV1 | None = broker.get(fill.execution_id)
            if (
                execution is None
                or fill.venue != self._broker.venue.venue.value
                or order.request.venue != self._broker.venue.venue.value
                or image.account_id != fill.account_id
                or execution.client_order_id != order.request.client_order_id
                or execution.venue_order_id != order.venue_order_id
                or execution.instrument_id != order.request.instrument_id
                or execution.side != order.request.side
                or execution.quantity != fill.quantity
                or execution.price != fill.price
                or execution.executed_at != fill.occurred_at
            ):
                return order_id
        return None

    async def _post_dispatch_consistent(
        self,
        marked: OrderSnapshot,
        state: OrderState,
        venue_order_id: str | None,
        verified: VerifiedSubmitSnapshot,
    ) -> bool:
        """Check the broker again before recording a result or returning it."""
        request = marked.request
        client_order_id = request.client_order_id
        if client_order_id is None:
            return False
        try:
            lookup = await self._reconciliation.find_by_client_order_id(
                request.account_id, client_order_id
            )
            if state == OrderState.UNKNOWN_SUBMIT:
                view = await self._reconciliation.account_view(request.account_id, None)
                image = None
            else:
                account_result = await self._broker_account_view(
                    request.account_id,
                    identity_inventory=verified.account_identity_inventory,
                )
                if isinstance(account_result, AccountViewV1):
                    await self._account_venue_conflict(
                        verified.account_identity_inventory, account_result
                    )
                    return False
                view, image = account_result
            inventory = verified.account_inventory
            if (
                lookup.status != BrokerReconciliationStatus.FOUND
                or lookup.match is None
                or lookup.match.account_id != request.account_id
                or lookup.match.client_order_id != client_order_id
                or lookup.match.state != state
                or lookup.match.venue_order_id != venue_order_id
                or lookup.match.filled_quantity != 0
                or lookup.broker_revision != view.broker_revision
                or view.status
                in {
                    BrokerReconciliationStatus.UNAVAILABLE,
                    BrokerReconciliationStatus.AMBIGUOUS,
                }
            ):
                return False
            for prior_attempt in range(1, request.attempt):
                prior_id = self._client_id_key.derive(
                    request.account_id, request.intent_idempotency_key, prior_attempt
                )
                prior = await self._reconciliation.find_by_client_order_id(
                    request.account_id, prior_id
                )
                if (
                    prior.broker_revision != view.broker_revision
                    or prior.status != BrokerReconciliationStatus.FOUND
                    or prior.match is None
                    or prior.match.account_id != request.account_id
                    or prior.match.client_order_id != prior_id
                    or prior.match.state
                    not in {OrderState.CANCELED, OrderState.REJECTED, OrderState.EXPIRED}
                    or prior.match.filled_quantity != 0
                ):
                    return False
            expected = replace(marked, state=state, venue_order_id=venue_order_id)
            compared = tuple(
                expected if item.order_id == marked.order_id else item for item in inventory
            )
            if not self._account_view_matches(view, compared, image):
                return False
            if state == OrderState.UNKNOWN_SUBMIT:
                final_view = await self._reconciliation.account_view(request.account_id, None)
                final_image = None
            else:
                final_result = await self._broker_account_view(
                    request.account_id,
                    identity_inventory=verified.account_identity_inventory,
                )
                if isinstance(final_result, AccountViewV1):
                    await self._account_venue_conflict(
                        verified.account_identity_inventory, final_result
                    )
                    return False
                final_view, final_image = final_result
            return (
                final_view.broker_revision == view.broker_revision
                and final_view == view
                and final_image == image
            )
        except Exception:
            return False

    async def create(self, request: OrderRequest) -> OrderSnapshot:
        self._require_actor_task()
        if not isinstance(request, OrderRequest):
            raise OMSValidationError("INVALID_ORDER_REQUEST")
        expected = self._client_id_key.derive(
            request.account_id, request.intent_idempotency_key, request.attempt
        )
        if request.client_order_id is not None and request.client_order_id != expected:
            raise OMSValidationError("CLIENT_ID_NOT_DERIVED")
        return await self._ledger.create(replace(request, client_order_id=expected))

    async def get(self, order_id: str) -> OrderSnapshot | None:
        self._require_actor_task()
        return await self._ledger.get(order_id)

    async def operator_guard_review(self, environment: str, account_id: str) -> OperatorGuardReview:
        """Present signed local journal beside an unabridged fake broker image."""
        self._require_actor_task()
        guard, guard_id, snapshot, journal = await self._ledger.operator_guard_context(
            environment, account_id
        )
        lookup = await self._reconciliation.find_by_client_order_id(
            account_id, guard.client_order_id
        )
        view = await self._reconciliation.account_view(account_id, None)
        if type(lookup) is not BrokerLookup or type(view) is not BrokerAccountView:
            raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
        return OperatorGuardReview(
            guard,
            guard_id,
            snapshot,
            journal,
            lookup,
            view,
            broker_evidence_digest(lookup, view),
        )

    async def operator_release_guard(
        self,
        environment: str,
        account_id: str,
        confirmation: OperatorGuardConfirmation,
    ) -> OrderSnapshot:
        self._require_actor_task()
        async with self._dispatch_mutex:
            guard = await self._ledger.account_guard(environment, account_id)
            if guard is not None and guard.order_id in self._active_dispatch:
                raise OMSValidationError("OPERATOR_RELEASE_REFUSED_ACTIVE_DISPATCH")
            return await self._operator_release_guard_locked(environment, account_id, confirmation)

    async def _operator_release_guard_locked(
        self,
        environment: str,
        account_id: str,
        confirmation: OperatorGuardConfirmation,
    ) -> OrderSnapshot:
        """Only an exact signed operator decision may clear a leftover guard."""
        if (
            type(confirmation) is not OperatorGuardConfirmation
            or type(self._operator_key) is not OperatorAuthorizationKey
            or not self._operator_key.verify(confirmation)
        ):
            raise OMSValidationError("OPERATOR_CONFIRMATION_MISMATCH")
        review = await self.operator_guard_review(environment, account_id)
        if (
            confirmation.guard_id != review.guard_id
            or confirmation.broker_evidence_digest != review.broker_evidence_digest
        ):
            raise OMSValidationError("OPERATOR_CONFIRMATION_MISMATCH")
        lookup = review.broker_lookup
        view = review.broker_view
        if (
            lookup.broker_revision != view.broker_revision
            or lookup.status
            not in {BrokerReconciliationStatus.FOUND, BrokerReconciliationStatus.NOT_FOUND}
            or view.status
            not in {BrokerReconciliationStatus.FOUND, BrokerReconciliationStatus.NOT_FOUND}
        ):
            raise OMSValidationError("ACCOUNT_RECONCILE_REQUIRED")
        match = lookup.match
        if match is None and review.guard.action != "SUBMIT":
            raise OMSValidationError("ACCOUNT_RECONCILE_REQUIRED")
        if match is not None and (
            match.account_id != account_id
            or match.client_order_id != review.guard.client_order_id
            or match.filled_quantity != 0
            or match.state
            not in {
                OrderState.WORKING,
                OrderState.REJECTED,
                OrderState.CANCELED,
                OrderState.EXPIRED,
            }
            or (review.guard.action == "CANCEL" and match.state != OrderState.CANCELED)
        ):
            raise OMSValidationError("ACCOUNT_RECONCILE_REQUIRED")
        inventory = await self._ledger.account_inventory(environment, account_id)
        expected = replace(
            review.snapshot,
            state=OrderState.CREATED if match is None else match.state,
            venue_order_id=None if match is None else match.venue_order_id,
        )
        compared = tuple(
            expected if item.order_id == review.guard.order_id else item for item in inventory
        )
        if not self._account_view_matches(view, compared):
            raise OMSValidationError("ACCOUNT_RECONCILE_REQUIRED")
        final_view = await self._reconciliation.account_view(account_id, None)
        if final_view != view:
            raise OMSValidationError("OPERATOR_CONFIRMATION_MISMATCH")
        return await self._ledger.operator_release_guard(
            review.guard.order_id, confirmation, lookup, view
        )

    async def review_venue_conflict(self, environment: str, account_id: str) -> VenueConflictReview:
        self._require_actor_task()
        context = await self._ledger.venue_conflict_context(environment, account_id)
        return issue_venue_conflict_review(
            environment=context["environment"],
            account_id=context["account_id"],
            conflict_id=context["conflict_id"],
            ledger_revision=context["ledger_revision"],
            affected_order_ids=context["affected_order_ids"],
            binding_venue=context["binding_venue"],
            binding_environment=context["binding_environment"],
            observation_ids=context["observation_ids"],
            identity_digest=context["identity_digest"],
        )

    def _require_resolution_principal(
        self, request: VenueConflictResolutionRequest, now_ns: int
    ) -> VerifiedPrincipalV1:
        checked = require_venue_conflict_resolution_request(request)
        principal = checked.principal
        try:
            require(principal, "sec003.verified_principal.v1")
        except Exception:
            raise VenueConflictResolutionError(
                VenueConflictResolutionCode.OPERATOR_REQUIRED
            ) from None
        if (
            checked.human_confirmed is not True
            or principal.role != "operator"
            or "oms:venue-conflict:resolve" not in principal.scopes
        ):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.OPERATOR_REQUIRED)
        if (
            principal.env != checked.environment
            or type(principal.expires_at_ns) is not int
            or type(principal.issued_at_ns) is not int
            or type(principal.verified_at_ns) is not int
            or now_ns < principal.issued_at_ns - 60_000_000_000
            or now_ns < principal.verified_at_ns
            or now_ns > principal.expires_at_ns
            or (principal.venue is not None and principal.venue != self._broker.venue.venue.value)
        ):
            code = (
                VenueConflictResolutionCode.CONFIRMATION_REQUIRED
                if checked.human_confirmed is not True
                else VenueConflictResolutionCode.OPERATOR_REQUIRED
            )
            raise VenueConflictResolutionError(code)
        return principal

    async def _clean_resolution_evidence(
        self, request: VenueConflictResolutionRequest, context: dict[str, Any]
    ) -> tuple[int, str, int, dict[str, OrderState]]:
        """Read and exactly reconcile a fresh complete sealed account image."""
        identity_inventory = await self._ledger.account_identity_inventory(request.account_id)
        if not identity_inventory:
            raise VenueConflictResolutionError(VenueConflictResolutionCode.CONFLICT_NOT_FOUND)
        binding = (
            identity_inventory[0].request.venue,
            identity_inventory[0].request.environment,
        )
        if (
            request.environment != binding[1]
            or binding != (context["binding_venue"], context["binding_environment"])
            or any(
                (item.request.venue, item.request.environment) != binding
                for item in identity_inventory
            )
            or (
                self._broker.venue.venue.value,
                self._broker.venue.environment.value.lower(),
            )
            != binding
            or self._broker.venue.account_id != request.account_id
        ):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH)
        if context["guard"] is not None:
            raise VenueConflictResolutionError(VenueConflictResolutionCode.UNRESOLVED_EVIDENCE)
        inventory = await self._ledger.account_inventory(request.environment, request.account_id)
        if any(
            item.discrepancies
            and any(code != "VENUE_ACCOUNT_CONFLICT" for code in item.discrepancies)
            for item in inventory
        ):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.UNRESOLVED_EVIDENCE)
        started = time.monotonic_ns()
        try:
            account_result = await self._broker_account_view(request.account_id)
        except Exception:
            raise VenueConflictResolutionError(
                VenueConflictResolutionCode.BROKER_EVIDENCE_UNAVAILABLE
            ) from None
        observed_at_ns = time.time_ns()
        if time.monotonic_ns() - started > 300_000_000_000:
            raise VenueConflictResolutionError(
                VenueConflictResolutionCode.BROKER_EVIDENCE_UNAVAILABLE
            )
        if isinstance(account_result, AccountViewV1):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH)
        view, image = account_result
        try:
            image.assert_sealed()
        except BrokerPortError:
            raise VenueConflictResolutionError(
                VenueConflictResolutionCode.BROKER_EVIDENCE_INCOMPLETE
            ) from None
        if (
            type(image) is not AccountViewV1
            or image.account_id != request.account_id
            or self._broker.venue.account_id != request.account_id
            or any(
                (observation.venue, observation.environment) != binding
                or observation.account_id != request.account_id
                for observation in image.open_orders
            )
        ):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH)
        local_by_client = {item.request.client_order_id: item for item in inventory}
        if len(local_by_client) != len(inventory):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.UNRESOLVED_EVIDENCE)
        observed_by_client = {item.client_order_id: item for item in image.open_orders}
        if len(observed_by_client) != len(image.open_orders):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH)
        if any(client_id not in local_by_client for client_id in observed_by_client):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.UNRESOLVED_EVIDENCE)
        persisted = await self._ledger.account_execution_evidence(
            request.environment, request.account_id
        )
        local_fills = {fill.execution_id: (order_id, fill) for order_id, fill in persisted}
        broker_fills = {execution.execution_id: execution for execution in image.executions}
        if len(local_fills) != len(persisted) or set(local_fills) != set(broker_fills):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH)
        for execution_id, execution in broker_fills.items():
            order_id, fill = local_fills[execution_id]
            local = next((item for item in inventory if item.order_id == order_id), None)
            if local is None or (
                execution.client_order_id != local.request.client_order_id
                or execution.venue_order_id != local.venue_order_id
                or execution.instrument_id != local.request.instrument_id
                or execution.side != local.request.side
                or execution.quantity != fill.quantity
                or execution.price != fill.price
                or execution.executed_at != fill.occurred_at
            ):
                raise VenueConflictResolutionError(
                    VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH
                )
        executions_by_client: dict[str, list[Decimal]] = {}
        for execution in image.executions:
            if (
                execution.client_order_id is None
                or execution.client_order_id not in local_by_client
            ):
                raise VenueConflictResolutionError(VenueConflictResolutionCode.UNRESOLVED_EVIDENCE)
            executions_by_client.setdefault(execution.client_order_id, []).append(
                execution.quantity
            )
        expected_positions: dict[str, list[Decimal]] = {}
        for item in inventory:
            client_id = item.request.client_order_id
            if client_id is None:
                raise OMSLedgerCorruption()
            if exact_sum(executions_by_client.get(client_id, ())) != item.filled_quantity:
                raise VenueConflictResolutionError(
                    VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH
                )
            if item.filled_quantity:
                signed = (
                    item.filled_quantity if item.request.side == "BUY" else -item.filled_quantity
                )
                expected_positions.setdefault(item.request.instrument_id, []).append(signed)
        expected_position_image = tuple(
            (instrument, exact_sum(values))
            for instrument, values in sorted(expected_positions.items())
            if exact_sum(values) != 0
        )
        if expected_position_image != image.positions:
            raise VenueConflictResolutionError(VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH)
        matches = {item.client_order_id: item for item in view.orders}
        if len(matches) != len(view.orders):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH)
        restored_states: dict[str, OrderState] = {}
        for item in inventory:
            client_id = item.request.client_order_id
            if client_id is None:
                raise OMSLedgerCorruption()
            match = matches.get(client_id)
            observation = observed_by_client.get(client_id)
            if item.order_id in context["affected_order_ids"]:
                if item.state in {
                    OrderState.REJECTED,
                    OrderState.CANCELED,
                    OrderState.EXPIRED,
                    OrderState.FILLED,
                    OrderState.REJECTED_HALTED,
                    OrderState.RISK_REJECTED,
                }:
                    if observation is not None or match is not None:
                        raise VenueConflictResolutionError(
                            VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH
                        )
                    restored_states[item.order_id] = item.state
                elif item.state is OrderState.RECONCILE_REQUIRED:
                    if observation is not None:
                        target = observation.status
                    elif item.filled_quantity == item.request.quantity:
                        target = OrderState.FILLED
                    else:
                        raise VenueConflictResolutionError(
                            VenueConflictResolutionCode.UNRESOLVED_EVIDENCE
                        )
                    restored_states[item.order_id] = target
                else:
                    raise VenueConflictResolutionError(
                        VenueConflictResolutionCode.UNRESOLVED_EVIDENCE
                    )
            elif item.state in {
                OrderState.SUBMITTING,
                OrderState.DISPATCH_IN_FLIGHT,
                OrderState.CANCEL_PENDING,
                OrderState.CANCEL_REQUESTED_UNCONFIRMED,
                OrderState.UNKNOWN_SUBMIT,
                OrderState.UNKNOWN_CANCEL,
                OrderState.RECONCILE_REQUIRED,
            }:
                raise VenueConflictResolutionError(VenueConflictResolutionCode.UNRESOLVED_EVIDENCE)
            if match is not None and (
                match.account_id != request.account_id
                or match.venue_order_id != item.venue_order_id
                or match.filled_quantity != item.filled_quantity
                or observation is None
                or observation.status != match.state
            ):
                raise VenueConflictResolutionError(
                    VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH
                )
            if item.state in {OrderState.WORKING, OrderState.PARTIALLY_FILLED} and match is None:
                raise VenueConflictResolutionError(VenueConflictResolutionCode.UNRESOLVED_EVIDENCE)
            if (
                item.state
                in {
                    OrderState.CREATED,
                    OrderState.REJECTED,
                    OrderState.CANCELED,
                    OrderState.EXPIRED,
                    OrderState.FILLED,
                    OrderState.RISK_REJECTED,
                    OrderState.REJECTED_HALTED,
                }
                and match is not None
            ):
                raise VenueConflictResolutionError(
                    VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH
                )
        evidence_digest = hashlib.sha256(canonical_json(image.seal_payload())).hexdigest()
        return image.broker_revision, evidence_digest, observed_at_ns, restored_states

    async def resolve_venue_conflict(
        self, request: VenueConflictResolutionRequest
    ) -> VenueConflictResolutionResult:
        self._require_actor_task()
        checked = require_venue_conflict_resolution_request(request)
        now_ns = time.time_ns()
        self._require_resolution_principal(checked, now_ns)
        prior = await self._ledger.find_venue_conflict_resolution(checked)
        try:
            context = await self._ledger.venue_conflict_context(
                checked.environment, checked.account_id
            )
        except VenueConflictResolutionError as exc:
            if (
                prior is not None
                and exc.code == VenueConflictResolutionCode.CONFLICT_NOT_FOUND.value
            ):
                return issue_venue_conflict_resolution_result(
                    resolution_id=prior["resolution_id"],
                    environment=prior["environment"],
                    account_id=prior["account_id"],
                    conflict_id=prior["conflict_id"],
                    operator_principal_id=prior["operator_principal_id"],
                    broker_revision=prior["broker_revision"],
                    broker_evidence_digest=prior["broker_evidence_digest"],
                    prior_ledger_revision=prior["prior_ledger_revision"],
                    resolved_ledger_revision=prior["resolved_ledger_revision"],
                    affected_order_ids=prior["affected_order_ids"],
                    resolved_at_ns=prior["resolved_at_ns"],
                )
            raise
        if (
            context["conflict_id"] != checked.conflict_id
            or (prior is None and context["ledger_revision"] != checked.expected_ledger_revision)
            or (
                prior is not None
                and context["ledger_revision"] != checked.expected_ledger_revision + 1
            )
        ):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.STALE_REVISION)
        (
            broker_revision,
            evidence_digest,
            observed_at_ns,
            restored_states,
        ) = await self._clean_resolution_evidence(checked, context)
        if prior is not None and (
            prior["broker_revision"] != broker_revision
            or prior["broker_evidence_digest"] != evidence_digest
        ):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH)
        recorded = await self._ledger.append_venue_conflict_resolution(
            checked,
            broker_revision=broker_revision,
            broker_evidence_digest=evidence_digest,
            observed_at_ns=observed_at_ns,
        )
        cleared = await self._ledger.clear_venue_conflict_quarantine(
            checked,
            resolution_id=recorded["resolution_id"],
            broker_revision=broker_revision,
            broker_evidence_digest=evidence_digest,
            restored_states=restored_states,
        )
        return issue_venue_conflict_resolution_result(
            resolution_id=cleared["resolution_id"],
            environment=cleared["environment"],
            account_id=cleared["account_id"],
            conflict_id=cleared["conflict_id"],
            operator_principal_id=cleared["operator_principal_id"],
            broker_revision=cleared["broker_revision"],
            broker_evidence_digest=cleared["broker_evidence_digest"],
            prior_ledger_revision=cleared["prior_ledger_revision"],
            resolved_ledger_revision=cleared["resolved_ledger_revision"],
            affected_order_ids=cleared["affected_order_ids"],
            resolved_at_ns=cleared["resolved_at_ns"],
        )

    async def submit(self, order_id: str, evidence: PaperDispatchEvidence) -> OrderSnapshot:
        self._require_actor_task()
        async with self._dispatch_mutex:
            if order_id in self._active_dispatch:
                raise OMSConflict("DISPATCH_ALREADY_ACTIVE")
            self._active_dispatch.add(order_id)
        try:
            return await self._submit_bounded(order_id, evidence, remaining=3, stale_seen=False)
        finally:
            async with self._dispatch_mutex:
                self._active_dispatch.discard(order_id)

    async def _submit_bounded(
        self,
        order_id: str,
        evidence: PaperDispatchEvidence,
        *,
        remaining: int,
        stale_seen: bool,
    ) -> OrderSnapshot:
        order = await self._ledger.get(order_id)
        if order is None:
            raise OMSConflict("ORDER_NOT_FOUND")
        expected = self._client_id_key.derive(
            order.request.account_id,
            order.request.intent_idempotency_key,
            order.request.attempt,
        )
        if order.request.client_order_id != expected:
            raise OMSValidationError("CLIENT_ID_NOT_DERIVED")
        if (
            self._broker.venue.account_id != order.request.account_id
            or self._broker.venue.environment.value.lower() != order.request.environment
            or self._broker.venue.venue.value != order.request.venue
        ):
            return await self._ledger.mark_venue_mismatch(order_id, "SUBMIT")
        if order.discrepancies:
            raise OMSValidationError("ACCOUNT_RECONCILE_REQUIRED")
        if order.state != OrderState.CREATED or order.submit_attempted:
            raise OMSConflict("SUBMIT_ALREADY_ATTEMPTED")
        if (
            await self._ledger.account_guard(order.request.environment, order.request.account_id)
            is not None
        ):
            raise OMSValidationError("ACCOUNT_RECONCILE_REQUIRED")
        if not isinstance(evidence, PaperDispatchEvidence):
            denied = "DISPATCH_EVIDENCE_REQUIRED"
        else:
            denied = evidence.denial_code(order.request, order_id)
        if denied is not None:
            await self._ledger.reject_risk(order_id, denied)
            raise OMSValidationError(denied)
        verified = await self._ledger.verified_submit_snapshot(
            order.request.environment, order.request.account_id
        )
        if (
            type(verified) is not VerifiedSubmitSnapshot
            or verified.environment != order.request.environment
            or verified.account_id != order.request.account_id
        ):
            raise OMSLedgerCorruption()
        inventory = verified.account_inventory
        others = tuple(item for item in inventory if item.order_id != order_id)
        if any(item.discrepancies for item in others):
            await self._ledger.reject_risk(order_id, "ACCOUNT_RECONCILE_REQUIRED")
            raise OMSValidationError("ACCOUNT_RECONCILE_REQUIRED")
        identity_inventory = verified.account_identity_inventory
        if await self._account_venue_conflict(identity_inventory):
            raise OMSValidationError("VENUE_ACCOUNT_CONFLICT")
        try:
            lookup = await self._reconciliation.find_by_client_order_id(
                order.request.account_id, expected
            )
            if not isinstance(lookup, BrokerLookup):
                raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
            if lookup.status == BrokerReconciliationStatus.FOUND:
                if (
                    lookup.match is None
                    or lookup.match.account_id != order.request.account_id
                    or lookup.match.client_order_id != expected
                ):
                    raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
                await self._ledger.mark_broker_intent_found(order_id, lookup.match)
                if stale_seen:
                    raise OMSStaleBrokerView()
                raise OMSConflict("DUPLICATE_INTENT")
            if lookup.status == BrokerReconciliationStatus.UNAVAILABLE:
                raise OMSValidationError("BROKER_RECONCILIATION_UNAVAILABLE")
            if lookup.status == BrokerReconciliationStatus.AMBIGUOUS:
                raise OMSValidationError("BROKER_RECONCILIATION_AMBIGUOUS")
            account_result = await self._broker_account_view(
                order.request.account_id, identity_inventory=identity_inventory
            )
            if isinstance(account_result, AccountViewV1):
                await self._account_venue_conflict(identity_inventory, account_result)
                raise OMSValidationError("VENUE_ACCOUNT_CONFLICT")
            view, port_image = account_result
        except OMSValidationError as exc:
            if exc.code == "BROKER_ACCOUNT_ACTIVITY_UNMATCHED":
                await self._ledger.mark_broker_account_unmatched(order_id)
            raise
        except (OMSConflict, OMSStaleBrokerView):
            raise
        except BrokerOutcomeUnknown:
            if stale_seen:
                await self._ledger.mark_pre_dispatch_stale_conflict(order_id)
                raise OMSStaleBrokerView() from None
            reference = await self._reconciliation.account_view(order.request.account_id, None)
            local_ids = {item.request.client_order_id for item in inventory}
            if (
                type(reference) is BrokerAccountView
                and reference.status == BrokerReconciliationStatus.FOUND
                and (
                    any(item.client_order_id not in local_ids for item in reference.orders)
                    or any(item.client_order_id not in local_ids for item in reference.executions)
                )
            ):
                await self._ledger.mark_broker_account_unmatched(order_id)
                raise OMSValidationError("BROKER_ACCOUNT_ACTIVITY_UNMATCHED") from None
            raise OMSValidationError("BROKER_RECONCILIATION_UNAVAILABLE") from None
        except Exception:
            raise OMSValidationError("BROKER_RECONCILIATION_UNAVAILABLE") from None
        if not isinstance(view, BrokerAccountView):
            raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
        if (
            lookup.status != BrokerReconciliationStatus.NOT_FOUND
            or lookup.revision != view.revision
        ):
            raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
        if await self._account_venue_conflict(identity_inventory, port_image):
            raise OMSValidationError("VENUE_ACCOUNT_CONFLICT")
        for prior_attempt in range(1, order.request.attempt):
            prior_id = self._client_id_key.derive(
                order.request.account_id,
                order.request.intent_idempotency_key,
                prior_attempt,
            )
            try:
                prior = await self._reconciliation.find_by_client_order_id(
                    order.request.account_id, prior_id
                )
            except Exception:
                raise OMSValidationError("PRIOR_ATTEMPT_UNRESOLVED") from None
            if (
                not isinstance(prior, BrokerLookup)
                or prior.revision != view.revision
                or prior.status != BrokerReconciliationStatus.FOUND
                or prior.match is None
                or prior.match.account_id != order.request.account_id
                or prior.match.client_order_id != prior_id
                or prior.match.state
                not in {OrderState.CANCELED, OrderState.REJECTED, OrderState.EXPIRED}
                or prior.match.filled_quantity != 0
            ):
                if stale_seen:
                    await self._ledger.mark_pre_dispatch_stale_conflict(order_id)
                    raise OMSStaleBrokerView()
                raise OMSValidationError("PRIOR_ATTEMPT_UNRESOLVED")
            if not self._broker.capability.atomic_revision_dispatch:
                settle_window = self._broker.capability.settle_window
                if (
                    settle_window is None
                    or prior.match.terminal_since is None
                    or datetime.now(UTC) - prior.match.terminal_since < settle_window
                ):
                    if stale_seen:
                        await self._ledger.mark_pre_dispatch_stale_conflict(order_id)
                        raise OMSStaleBrokerView()
                    raise OMSValidationError("PRIOR_ATTEMPT_UNRESOLVED")
        if any(
            item.state
            in {
                OrderState.SUBMITTING,
                OrderState.CANCEL_PENDING,
                OrderState.CANCEL_REQUESTED_UNCONFIRMED,
                OrderState.UNKNOWN_SUBMIT,
                OrderState.UNKNOWN_CANCEL,
                OrderState.RECONCILE_REQUIRED,
            }
            for item in others
        ):
            await self._ledger.reject_risk(order_id, "ACCOUNT_RECONCILIATION_REQUIRED")
            raise OMSValidationError("ACCOUNT_RECONCILIATION_REQUIRED")
        conflict_order_id = await self._execution_evidence_conflict(
            inventory, port_image, persisted=verified.account_execution_evidence
        )
        if conflict_order_id is not None:
            await self._ledger.record_reconcile_pending(
                conflict_order_id, "BROKER_EXECUTION_CONFLICT"
            )
            raise OMSValidationError("BROKER_EXECUTION_CONFLICT")
        if not self._account_view_matches(view, inventory, port_image):
            if stale_seen:
                await self._ledger.mark_pre_dispatch_stale_conflict(order_id)
                raise OMSStaleBrokerView()
            await self._ledger.mark_broker_account_unmatched(order_id)
            raise OMSValidationError("BROKER_ACCOUNT_ACTIVITY_UNMATCHED")
        # This commit is the only local dispatch claim. Any failure before it
        # returns means no call; any crash after it means UNKNOWN, never retry.
        await self._ledger.mark_submitting(order_id, evidence)
        marked = await self._ledger.arm_dispatch_guard(
            order_id, action="SUBMIT", broker_revision=view.broker_revision
        )
        guard = await self._ledger.account_guard(
            order.request.environment, order.request.account_id
        )
        if guard is None or guard.order_id != order_id:
            raise OMSConflict("STALE_DISPATCH_FENCE")
        permit = FakeDispatchPermit(marked.order_id, marked.request.digest, view.broker_revision)
        rejection_code: BrokerRejectionCode | None = None
        gate_denied: DispatchGateCode | None = None
        halt_generation_advanced = False
        try:
            async with self._dispatch_mutex:
                await self._ledger.assert_dispatch_fence(order_id, guard.fence_epoch)
                acquire_fence = cast(
                    Callable[[], int] | None,
                    getattr(self._dispatch_gate, "acquire_submit_fence", None),
                )
                generation_current = cast(
                    Callable[[int], bool] | None,
                    getattr(self._dispatch_gate, "submit_generation_current", None),
                )
                release_fence = cast(
                    Callable[[], None] | None,
                    getattr(self._dispatch_gate, "release_submit_fence", None),
                )
                fence_held = False
                fence_generation: int | None = None
                transport_issued = False
                if acquire_fence is not None:
                    if generation_current is None or release_fence is None:
                        gate_denied = DispatchGateCode.DENY_UNAVAILABLE
                    else:
                        try:
                            fence_generation = acquire_fence()
                            fence_held = True
                        except Exception:
                            gate_denied = DispatchGateCode.DENY_UNAVAILABLE
                try:
                    if gate_denied is None:
                        gate_denied = self._gate_code("SUBMIT", marked)
                        if gate_denied is DispatchGateCode.ALLOW and fence_held:
                            if fence_generation is None or generation_current is None:
                                gate_denied = DispatchGateCode.DENY_UNAVAILABLE
                            else:
                                try:
                                    generation_matches = generation_current(fence_generation)
                                except Exception:
                                    gate_denied = DispatchGateCode.DENY_UNAVAILABLE
                                else:
                                    if not generation_matches:
                                        gate_denied = DispatchGateCode.DENY_HALT
                        if gate_denied is DispatchGateCode.ALLOW:
                            # No await is permitted from this final gate check
                            # through the synchronous transport issue.
                            transport_issued = True
                            result = self._broker.submit(
                                marked.request, permit, view.broker_revision
                            )
                            permit.assert_consumed()
                finally:
                    if fence_held:
                        if transport_issued:
                            if fence_generation is None or generation_current is None:
                                halt_generation_advanced = True
                            else:
                                try:
                                    halt_generation_advanced = not generation_current(
                                        fence_generation
                                    )
                                except Exception:
                                    halt_generation_advanced = True
                        if release_fence is not None:
                            release_fence()
                if gate_denied is DispatchGateCode.ALLOW:
                    gate_denied = None
            if gate_denied is not None:
                return await self._ledger.complete_guarded_gate_denial(
                    order_id, action="SUBMIT", reason=gate_denied.value
                )
        except OMSStaleBrokerView:
            await self._ledger.mark_submit_stale(order_id)
            if remaining <= 1:
                raise
            return await self._submit_bounded(
                order_id, evidence, remaining=remaining - 1, stale_seen=True
            )
        except OMSConflict as exc:
            if exc.code == "STALE_DISPATCH_FENCE":
                raise
            if exc.code == "DUPLICATE_INTENT":
                await self._ledger.mark_submit_stale(order_id)
                match = await self._reconciliation.find_by_client_order_id(
                    order.request.account_id, expected
                )
                if match.status == BrokerReconciliationStatus.FOUND and match.match is not None:
                    await self._ledger.mark_broker_intent_found(order_id, match.match)
                raise
            return await self._ledger.complete_guarded_submit(order_id, OrderState.UNKNOWN_SUBMIT)
        except BrokerRejected as exc:
            result = None
            rejected = True
            rejection_code = BrokerRejectionCode(str(exc))
        except BrokerOutcomeUnknown:
            result = None
            rejected = False
        except Exception:
            result = None
            rejected = False
        else:
            rejected = False
        if not rejected:
            rejection_code = None
        if result is not None and type(result) is not SubmitResultV1:
            result = None
        if result is not None:
            result.assert_sealed()
            rejection_code = result.rejection_code
        state = (
            OrderState.REJECTED
            if rejected
            else result.state
            if result is not None
            else OrderState.UNKNOWN_SUBMIT
        )
        venue_order_id = result.venue_order_id if result is not None else None
        if halt_generation_advanced or not await self._post_dispatch_consistent(
            marked, state, venue_order_id, verified
        ):
            # A failed completion must still retain evidence that a cancel may
            # have escaped. This append-only marker commits before the port call.
            await self._ledger.arm_compensating_cancel(order_id)
            confirmed = False
            cancel_gate_denied = False
            try:
                async with self._dispatch_mutex:
                    await self._ledger.assert_dispatch_fence(order_id, guard.fence_epoch)
                    if self._gate_code("CANCEL", marked) is DispatchGateCode.ALLOW:
                        canceled = self._broker.cancel(
                            replace(marked, venue_order_id=venue_order_id)
                        )
                        if type(canceled) is CancelResultV1:
                            canceled.assert_sealed()
                            confirmed = canceled.confirmed
                    else:
                        cancel_gate_denied = True
            except Exception:
                pass
            if cancel_gate_denied:
                await self._ledger.complete_guarded_submit(
                    order_id,
                    state,
                    venue_order_id,
                    conflict=True,
                    cancel_confirmed=confirmed,
                    rejection_code=rejection_code,
                    cancel_gate_denied=True,
                )
            else:
                await self._ledger.complete_guarded_submit(
                    order_id,
                    state,
                    venue_order_id,
                    conflict=True,
                    cancel_confirmed=confirmed,
                    rejection_code=rejection_code,
                )
            raise OMSDiscrepancy("POST_DISPATCH_CONFLICT")
        return await self._ledger.complete_guarded_submit(
            order_id,
            state,
            venue_order_id,
            rejection_code=rejection_code,
        )

    async def cancel(self, order_id: str) -> OrderSnapshot:
        self._require_actor_task()
        async with self._dispatch_mutex:
            if order_id in self._active_dispatch:
                raise OMSConflict("DISPATCH_ALREADY_ACTIVE")
            self._active_dispatch.add(order_id)
        try:
            return await self._cancel_active(order_id)
        finally:
            async with self._dispatch_mutex:
                self._active_dispatch.discard(order_id)

    async def _cancel_active(self, order_id: str) -> OrderSnapshot:
        order = await self._ledger.get(order_id)
        if order is None:
            raise OMSConflict("ORDER_NOT_FOUND")
        if (
            self._broker.venue.account_id != order.request.account_id
            or self._broker.venue.environment.value.lower() != order.request.environment
            or self._broker.venue.venue.value != order.request.venue
        ):
            return await self._ledger.mark_venue_mismatch(order_id, "CANCEL")
        if order.cancel_attempted:
            return order  # same local intent; never send a second cancel blindly
        if (
            await self._ledger.account_guard(order.request.environment, order.request.account_id)
            is not None
        ):
            raise OMSValidationError("ACCOUNT_RECONCILE_REQUIRED")
        identity_inventory = await self._ledger.account_identity_inventory(order.request.account_id)
        try:
            account_result = await self._broker_account_view(order.request.account_id)
            if isinstance(account_result, AccountViewV1):
                await self._account_venue_conflict(identity_inventory, account_result)
                updated = await self._ledger.get(order_id)
                if updated is None:
                    raise OMSConflict("ORDER_NOT_FOUND")
                return updated
            view, image = account_result
        except OMSValidationError:
            raise OMSValidationError("BROKER_RECONCILIATION_UNAVAILABLE") from None
        except Exception:
            raise OMSValidationError("BROKER_RECONCILIATION_UNAVAILABLE") from None
        if any(
            (observation.venue, observation.environment)
            != (order.request.venue, order.request.environment)
            for observation in image.open_orders
        ):
            return await self._ledger.mark_venue_account_conflict(order_id)
        if view.status != BrokerReconciliationStatus.FOUND:
            raise OMSValidationError("BROKER_RECONCILIATION_UNAVAILABLE")
        await self._ledger.mark_cancel_pending(order_id)
        marked = await self._ledger.arm_dispatch_guard(
            order_id, action="CANCEL", broker_revision=view.broker_revision
        )
        guard = await self._ledger.account_guard(
            order.request.environment, order.request.account_id
        )
        if guard is None or guard.order_id != order_id:
            raise OMSConflict("STALE_DISPATCH_FENCE")
        try:
            async with self._dispatch_mutex:
                await self._ledger.assert_dispatch_fence(order_id, guard.fence_epoch)
                gate_code = self._gate_code("CANCEL", marked)
                if gate_code is not DispatchGateCode.ALLOW:
                    return await self._ledger.complete_guarded_gate_denial(
                        order_id, action="CANCEL", reason=gate_code.value
                    )
                result = self._broker.cancel(marked)
        except OMSConflict as exc:
            if exc.code == "STALE_DISPATCH_FENCE":
                raise
            return await self._ledger.complete_guarded_cancel(
                order_id, OrderState.UNKNOWN_CANCEL, verified_clean=False
            )
        except Exception:
            return await self._ledger.complete_guarded_cancel(
                order_id, OrderState.UNKNOWN_CANCEL, verified_clean=False
            )
        if type(result) is not CancelResultV1:
            return await self._ledger.complete_guarded_cancel(
                order_id, OrderState.UNKNOWN_CANCEL, verified_clean=False
            )
        result.assert_sealed()
        state = OrderState.CANCELED if result.confirmed else OrderState.CANCEL_REQUESTED_UNCONFIRMED
        verified = False
        if result.confirmed:
            try:
                lookup = await self._reconciliation.find_by_client_order_id(
                    order.request.account_id, order.request.client_order_id or ""
                )
                after_result = await self._broker_account_view(order.request.account_id)
                if isinstance(after_result, AccountViewV1):
                    identity_inventory = await self._ledger.account_identity_inventory(
                        order.request.account_id
                    )
                    await self._account_venue_conflict(identity_inventory, after_result)
                    raise OMSValidationError("VENUE_ACCOUNT_CONFLICT")
                after, after_image = after_result
                inventory = await self._ledger.account_inventory(
                    order.request.environment, order.request.account_id
                )
                expected = replace(marked, state=OrderState.CANCELED)
                compared = tuple(
                    expected if item.order_id == order_id else item for item in inventory
                )
                verified = (
                    lookup.status == BrokerReconciliationStatus.FOUND
                    and lookup.match is not None
                    and lookup.match.state == OrderState.CANCELED
                    and lookup.match.client_order_id == order.request.client_order_id
                    and lookup.broker_revision == after.broker_revision
                    and after.status
                    in {
                        BrokerReconciliationStatus.FOUND,
                        BrokerReconciliationStatus.NOT_FOUND,
                    }
                    and self._account_view_matches(after, compared, after_image)
                )
                if verified:
                    latest_result = await self._broker_account_view(order.request.account_id)
                    if isinstance(latest_result, AccountViewV1):
                        identity_inventory = await self._ledger.account_identity_inventory(
                            order.request.account_id
                        )
                        await self._account_venue_conflict(identity_inventory, latest_result)
                        raise OMSValidationError("VENUE_ACCOUNT_CONFLICT")
                    latest, latest_image = latest_result
                    verified = latest == after and latest_image == after_image
            except Exception:
                verified = False
        return await self._ledger.complete_guarded_cancel(
            order_id,
            state,
            verified_clean=verified,
            conflict=result.confirmed and not verified,
        )

    async def record_fill(self, order_id: str, fill: Fill) -> OrderSnapshot:
        self._require_actor_task()
        snapshot = await self._ledger.record_fill(order_id, fill)
        client_order_id = snapshot.request.client_order_id
        if client_order_id is None:
            raise OMSValidationError("CLIENT_ID_NOT_DERIVED")
        if isinstance(self._reconciliation, FakeBrokerReconciliation):
            self._reconciliation.record_execution(
                snapshot.request.account_id,
                client_order_id,
                fill.execution_id,
                fill.quantity,
            )
        if isinstance(self._broker, FakeBrokerPort):
            self._broker.record_local_fill(snapshot, fill)
        return snapshot

    async def record_fill_correction(
        self, order_id: str, correction: FillCorrection
    ) -> OrderSnapshot:
        self._require_actor_task()
        return await self._ledger.record_fill_correction(order_id, correction)

    async def reconcile(self, order_id: str) -> OrderSnapshot:
        self._require_actor_task()
        order = await self._ledger.get(order_id)
        if order is None:
            raise OMSConflict("ORDER_NOT_FOUND")
        identity_inventory = await self._ledger.account_identity_inventory(order.request.account_id)
        if await self._account_venue_conflict(identity_inventory):
            updated = await self._ledger.get(order_id)
            if updated is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            return updated
        try:
            account_result = await self._broker_account_view(order.request.account_id)
            if isinstance(account_result, AccountViewV1):
                await self._account_venue_conflict(identity_inventory, account_result)
                updated = await self._ledger.get(order_id)
                if updated is None:
                    raise OMSConflict("ORDER_NOT_FOUND")
                return updated
            _view, image = account_result
            if await self._account_venue_conflict(identity_inventory, image):
                updated = await self._ledger.get(order_id)
                if updated is None:
                    raise OMSConflict("ORDER_NOT_FOUND")
                return updated
        except BrokerOutcomeUnknown:
            image = None  # Incomplete evidence cannot create a fill.
        except OMSValidationError as exc:
            if exc.code == "VENUE_ACCOUNT_CONFLICT":
                await self._ledger.mark_venue_account_conflict(identity_inventory[0].order_id)
                updated = await self._ledger.get(order_id)
                if updated is None:
                    raise OMSConflict("ORDER_NOT_FOUND") from None
                return updated
            if exc.code in {
                "BROKER_RECONCILIATION_UNAVAILABLE",
                "BROKER_RECONCILIATION_AMBIGUOUS",
            }:
                return await self._ledger.record_reconcile_pending(
                    order_id, "BROKER_READ_UNAVAILABLE"
                )
            # UNKNOWN_SUBMIT has no representable V1 open-order observation.
            # A separate broker lookup still handles it, but only if the
            # independent account authority has no executions to import.
            if order.state == OrderState.UNKNOWN_SUBMIT and exc.code == "BROKER_VIEW_INCONSISTENT":
                reference = await self._reconciliation.account_view(order.request.account_id, None)
                if (
                    reference.status == BrokerReconciliationStatus.FOUND
                    and not reference.executions
                    and all(item.state == OrderState.UNKNOWN_SUBMIT for item in reference.orders)
                ):
                    image = None
                else:
                    return await self._ledger.record_reconcile_pending(
                        order_id, "BROKER_EXECUTION_CONFLICT"
                    )
            else:
                return await self._ledger.record_reconcile_pending(
                    order_id, "BROKER_EXECUTION_CONFLICT"
                )
        except BrokerPortError:
            return await self._ledger.record_reconcile_pending(
                order_id, "BROKER_EXECUTION_CONFLICT"
            )
        except Exception:
            return await self._ledger.record_reconcile_pending(order_id, "BROKER_READ_UNAVAILABLE")
        try:
            if image is not None:
                inventory = await self._ledger.account_inventory(
                    order.request.environment, order.request.account_id
                )
                known = {item.request.client_order_id: item for item in inventory}
                for execution in image.executions:
                    execution.assert_sealed()
                    linked = known.get(execution.client_order_id)
                    if (
                        linked is None
                        or execution.instrument_id != linked.request.instrument_id
                        or execution.side != linked.request.side
                        or (
                            linked.venue_order_id is not None
                            and execution.venue_order_id != linked.venue_order_id
                        )
                    ):
                        raise OMSValidationError("BROKER_EXECUTION_CONFLICT")
                    if linked.order_id == order_id:
                        await self._ledger.record_fill(
                            order_id,
                            Fill(
                                order.request.venue,
                                order.request.account_id,
                                execution.execution_id,
                                execution.quantity,
                                execution.price,
                                execution.executed_at,
                            ),
                        )
        except (OMSConflict, OMSValidationError):
            return await self._ledger.record_reconcile_pending(
                order_id, "BROKER_EXECUTION_CONFLICT"
            )
        order = await self._ledger.get(order_id) or order
        try:
            observation = self._broker.read_order(order)
        except Exception:
            return await self._ledger.record_reconcile_pending(order_id, "BROKER_READ_UNAVAILABLE")
        if observation is None:
            return await self._ledger.record_reconcile_pending(order_id, "BROKER_EVIDENCE_ABSENT")
        return await self._ledger.record_observation(order_id, observation)

    async def recover_uncertain(self) -> list[OrderSnapshot]:
        self._require_actor_task()
        return await self._ledger.recover_uncertain()


@dataclass(frozen=True, slots=True)
class _Create:
    request: OrderRequest

    async def run(self, gateway: OrderGateway, _ledger: OrderLedgerPort) -> OrderSnapshot:
        return await gateway.create(self.request)


@dataclass(frozen=True, slots=True)
class _Get:
    order_id: str

    async def run(self, gateway: OrderGateway, _ledger: OrderLedgerPort) -> OrderSnapshot | None:
        return await gateway.get(self.order_id)


@dataclass(frozen=True, slots=True)
class _Submit:
    order_id: str
    evidence: PaperDispatchEvidence

    async def run(self, gateway: OrderGateway, _ledger: OrderLedgerPort) -> OrderSnapshot:
        return await gateway.submit(self.order_id, self.evidence)


@dataclass(frozen=True, slots=True)
class _Cancel:
    order_id: str

    async def run(self, gateway: OrderGateway, _ledger: OrderLedgerPort) -> OrderSnapshot:
        return await gateway.cancel(self.order_id)


@dataclass(frozen=True, slots=True)
class _Fill:
    order_id: str
    fill: Fill

    async def run(self, gateway: OrderGateway, _ledger: OrderLedgerPort) -> OrderSnapshot:
        return await gateway.record_fill(self.order_id, self.fill)


@dataclass(frozen=True, slots=True)
class _Correction:
    order_id: str
    correction: FillCorrection

    async def run(self, gateway: OrderGateway, _ledger: OrderLedgerPort) -> OrderSnapshot:
        return await gateway.record_fill_correction(self.order_id, self.correction)


@dataclass(frozen=True, slots=True)
class _Reconcile:
    order_id: str

    async def run(self, gateway: OrderGateway, _ledger: OrderLedgerPort) -> OrderSnapshot:
        return await gateway.reconcile(self.order_id)


@dataclass(frozen=True, slots=True)
class _Recover:
    async def run(self, gateway: OrderGateway, _ledger: OrderLedgerPort) -> list[OrderSnapshot]:
        return await gateway.recover_uncertain()


@dataclass(frozen=True, slots=True)
class _ActivityReadSnapshotCapture:
    environment: str
    account_id: str

    async def run(self, _gateway: OrderGateway, ledger: OrderLedgerPort) -> object:
        return await ledger.begin_activity_read_snapshot(self.environment, self.account_id)


@dataclass(frozen=True, slots=True)
class _Guard:
    environment: str
    account_id: str

    async def run(self, _gateway: OrderGateway, ledger: OrderLedgerPort) -> DispatchGuard | None:
        return await ledger.account_guard(self.environment, self.account_id)


@dataclass(frozen=True, slots=True)
class _Fence:
    order_id: str
    epoch: int

    async def run(self, _gateway: OrderGateway, ledger: OrderLedgerPort) -> DispatchGuard:
        return await ledger.assert_dispatch_fence(self.order_id, self.epoch)


@dataclass(frozen=True, slots=True)
class _Review:
    environment: str
    account_id: str

    async def run(self, gateway: OrderGateway, _ledger: OrderLedgerPort) -> OperatorGuardReview:
        return await gateway.operator_guard_review(self.environment, self.account_id)


@dataclass(frozen=True, slots=True)
class _Release:
    environment: str
    account_id: str
    confirmation: OperatorGuardConfirmation

    async def run(self, gateway: OrderGateway, _ledger: OrderLedgerPort) -> OrderSnapshot:
        return await gateway.operator_release_guard(
            self.environment, self.account_id, self.confirmation
        )


@dataclass(frozen=True, slots=True)
class _ReviewVenueConflict:
    environment: str
    account_id: str

    async def run(self, gateway: OrderGateway, _ledger: OrderLedgerPort) -> VenueConflictReview:
        return await gateway.review_venue_conflict(self.environment, self.account_id)


@dataclass(frozen=True, slots=True)
class _ResolveVenueConflict:
    request: VenueConflictResolutionRequest

    async def run(
        self, gateway: OrderGateway, _ledger: OrderLedgerPort
    ) -> VenueConflictResolutionResult:
        return await gateway.resolve_venue_conflict(self.request)


@dataclass(frozen=True, slots=True)
class _Close:
    pass


_ActorCommand = (
    _Create
    | _Get
    | _Submit
    | _Cancel
    | _Fill
    | _Correction
    | _Reconcile
    | _Recover
    | _ActivityReadSnapshotCapture
    | _Guard
    | _Fence
    | _Review
    | _Release
    | _ReviewVenueConflict
    | _ResolveVenueConflict
    | _Close
)
_COMMAND_TYPES = frozenset(
    {
        _Create,
        _Get,
        _Submit,
        _Cancel,
        _Fill,
        _Correction,
        _Reconcile,
        _Recover,
        _ActivityReadSnapshotCapture,
        _Guard,
        _Fence,
        _Review,
        _Release,
        _ReviewVenueConflict,
        _ResolveVenueConflict,
        _Close,
    }
)


class OrderGatewayActor:
    """The only command owner of a dispatch-capable OMS gateway."""

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise OMSValidationError("OMS_ACTOR_REQUIRED")

    def __init__(
        self,
        gateway: OrderGateway,
        ledger: OrderLedgerPort,
        on_close: Callable[[], None],
    ) -> None:
        if _ISSUING.get() is not _ISSUER or self in _ISSUED_ACTORS:
            raise OMSValidationError("OMS_ACTOR_REQUIRED")
        self._gateway = gateway
        self._ledger = ledger
        self._on_close = on_close
        self._loop = asyncio.get_running_loop()
        self._queue: asyncio.Queue[tuple[_ActorCommand, asyncio.Future[Any]]] = asyncio.Queue()
        self._closed = False
        self._closing = False
        self._activity_read_accounts: set[str] = set()
        self._activity_read_lock = threading.Lock()
        self._worker = self._loop.create_task(self._run(), name="oms-gateway-actor")
        _ISSUED_ACTORS.add(self)
        _GATEWAY_TASKS[gateway] = self._worker

    @property
    def venue(self) -> VenueIdentityV1:
        """Sealed venue identity for startup activation checks."""
        return self._gateway.venue

    @property
    def dispatch_gate(self) -> DispatchGate:
        """Expose the gateway's installed gate for startup identity checks."""
        return self._gateway.dispatch_gate

    async def _run(self) -> None:
        while True:
            command, result = await self._queue.get()
            try:
                if isinstance(command, _Close):
                    self._on_close()
                    self._closed = True
                    _GATEWAY_TASKS.pop(self._gateway, None)
                    result.set_result(None)
                    return
                value = await command.run(self._gateway, self._ledger)
            except Exception as exc:
                if isinstance(command, _Close):
                    self._closing = False
                result.set_exception(exc)
            else:
                result.set_result(value)
            finally:
                self._queue.task_done()

    async def _enqueue(self, command: _ActorCommand) -> Any:
        if self not in _ISSUED_ACTORS or type(command) not in _COMMAND_TYPES:
            raise OMSValidationError("OMS_ACTOR_REQUIRED")
        if self._closed or (self._closing and type(command) is not _Close):
            raise OMSConflict("OMS_ACTOR_CLOSED")
        if type(command) is _Close:
            if self._closing:
                raise OMSConflict("OMS_ACTOR_CLOSED")
            self._closing = True
        result: asyncio.Future[Any] = self._loop.create_future()
        await self._queue.put((command, result))
        return await asyncio.shield(result)

    async def _call(self, command: _ActorCommand) -> Any:
        if (
            self._loop.is_closed()
            or not self._loop.is_running()
            or (self._worker.done() and not self._closed)
        ):
            raise OMSConflict("OMS_ACTOR_CLOSED")
        if asyncio.get_running_loop() is self._loop:
            return await self._enqueue(command)
        enqueue = self._enqueue(command)
        try:
            pending = asyncio.run_coroutine_threadsafe(enqueue, self._loop)
        except RuntimeError:
            enqueue.close()
            raise OMSConflict("OMS_ACTOR_CLOSED") from None
        return await asyncio.wrap_future(pending)

    async def create(self, request: OrderRequest) -> OrderSnapshot:
        return cast(OrderSnapshot, await self._call(_Create(request)))

    async def get(self, order_id: str) -> OrderSnapshot | None:
        return cast(OrderSnapshot | None, await self._call(_Get(order_id)))

    async def submit(self, order_id: str, evidence: PaperDispatchEvidence) -> OrderSnapshot:
        return cast(OrderSnapshot, await self._call(_Submit(order_id, evidence)))

    async def cancel(self, order_id: str) -> OrderSnapshot:
        return cast(OrderSnapshot, await self._call(_Cancel(order_id)))

    async def record_fill(self, order_id: str, fill: Fill) -> OrderSnapshot:
        return cast(OrderSnapshot, await self._call(_Fill(order_id, fill)))

    async def record_fill_correction(
        self, order_id: str, correction: FillCorrection
    ) -> OrderSnapshot:
        return cast(OrderSnapshot, await self._call(_Correction(order_id, correction)))

    async def reconcile(self, order_id: str) -> OrderSnapshot:
        return cast(OrderSnapshot, await self._call(_Reconcile(order_id)))

    async def recover_uncertain(self) -> list[OrderSnapshot]:
        return cast(list[OrderSnapshot], await self._call(_Recover()))

    async def read_activity(
        self,
        environment: str,
        account_id: str,
        high_water_sequence: int | None = None,
    ) -> ActivityLedgerSnapshot:
        return cast(
            ActivityLedgerSnapshot,
            await self._read_activity_outside_actor(
                environment,
                account_id,
                lambda token: self._ledger.activity_snapshot_from_snapshot(
                    token, high_water_sequence
                ),
            ),
        )

    async def _read_activity_outside_actor(
        self,
        environment: str,
        account_id: str,
        reader: Callable[[object], Any],
    ) -> Any:
        if type(account_id) is not str or not account_id:
            raise OMSValidationError("INVALID_ACTIVITY_QUERY")
        with self._activity_read_lock:
            if account_id in self._activity_read_accounts:
                raise OMSConflict("ACTIVITY_READ_BUSY")
            self._activity_read_accounts.add(account_id)
        snapshot: object | None = None
        try:
            snapshot = await self._call(_ActivityReadSnapshotCapture(environment, account_id))
            try:
                async with asyncio.timeout(30):
                    return await reader(snapshot)
            except TimeoutError:
                raise OMSConflict("ACTIVITY_SNAPSHOT_TIMEOUT") from None
        finally:
            try:
                if snapshot is not None:
                    close_task = asyncio.create_task(
                        self._ledger.close_activity_read_snapshot(snapshot)
                    )
                    try:
                        await asyncio.shield(close_task)
                    except asyncio.CancelledError:
                        await close_task
                        raise
            finally:
                with self._activity_read_lock:
                    self._activity_read_accounts.discard(account_id)

    async def read_activity_page(
        self,
        environment: str,
        account_id: str,
        *,
        after_sequence: int = 0,
        high_water_sequence: int | None = None,
        limit: int = 100,
    ) -> ActivityLedgerPage:
        return cast(
            ActivityLedgerPage,
            await self._read_activity_outside_actor(
                environment,
                account_id,
                lambda token: self._ledger.activity_page_from_snapshot(
                    token,
                    after_sequence=after_sequence,
                    high_water_sequence=high_water_sequence,
                    limit=limit,
                ),
            ),
        )

    async def account_guard(self, environment: str, account_id: str) -> DispatchGuard | None:
        return cast(DispatchGuard | None, await self._call(_Guard(environment, account_id)))

    async def assert_dispatch_fence(self, order_id: str, epoch: int) -> DispatchGuard:
        return cast(DispatchGuard, await self._call(_Fence(order_id, epoch)))

    async def operator_guard_review(self, environment: str, account_id: str) -> OperatorGuardReview:
        return cast(OperatorGuardReview, await self._call(_Review(environment, account_id)))

    async def operator_release_guard(
        self,
        environment: str,
        account_id: str,
        confirmation: OperatorGuardConfirmation,
    ) -> OrderSnapshot:
        return cast(
            OrderSnapshot,
            await self._call(_Release(environment, account_id, confirmation)),
        )

    async def review_venue_conflict(self, environment: str, account_id: str) -> VenueConflictReview:
        return cast(
            VenueConflictReview,
            await self._call(_ReviewVenueConflict(environment, account_id)),
        )

    async def resolve_venue_conflict(
        self, request: VenueConflictResolutionRequest
    ) -> VenueConflictResolutionResult:
        return cast(
            VenueConflictResolutionResult,
            await self._call(_ResolveVenueConflict(request)),
        )

    async def close(self) -> None:
        await self._call(_Close())
        if asyncio.get_running_loop() is self._loop:
            await self._worker

    def __copy__(self) -> None:
        raise OMSValidationError("OMS_ACTOR_REQUIRED")

    def __deepcopy__(self, _memo: object) -> None:
        raise OMSValidationError("OMS_ACTOR_REQUIRED")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise OMSValidationError("OMS_ACTOR_REQUIRED")


def _issue_order_gateway_actor(
    ledger: OrderLedgerPort,
    broker: BrokerPortV1,
    reconciliation: BrokerReconciliationPort,
    client_id_key: ClientIdKey,
    operator_key: OperatorAuthorizationKey | None,
    dispatch_gate: DispatchGate,
    on_close: Callable[[], None],
) -> OrderGatewayActor:
    """Called only by the store's single-owner factory after it claims the ledger."""
    token = _ISSUING.set(_ISSUER)
    try:
        gateway = OrderGateway(
            ledger,
            broker,
            reconciliation,
            client_id_key,
            operator_key,
            dispatch_gate,
        )
        return OrderGatewayActor(gateway, ledger, on_close)
    finally:
        _ISSUING.reset(token)
