"""Synthetic broker port for OMS-CORE-001.

There is deliberately no live adapter or socket/credential code in this module.
Future adapters need a separate dispatch permit and review before wiring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from hashlib import sha256
from typing import Any, NoReturn, SupportsIndex

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerOutcomeUnknown,
    BrokerPortError,
    BrokerRejected,
    BrokerRejectionCode,
    BrokerUnknownCode,
    BrokerVenue,
    CancelResultV1,
    DispatchPermitV1,
    EquityEvidenceKindV1,
    ExecutionV1,
    SubmitResultV1,
    VenueDispatchCapabilityV1,
    VenueIdentityV1,
    _issue_account_view,
    _issue_cancel_result,
    _issue_equity_evidence,
    _issue_execution,
    _issue_submit_result,
    _issue_venue_capability,
    _issue_venue_identity,
)
from leviathan_core.execution.broker_reconciliation import (
    BrokerReconciliationStatus,
    FakeBrokerReconciliation,
)
from leviathan_core.execution.order_models import (
    BrokerObservation,
    Fill,
    OMSConflict,
    OMSValidationError,
    OrderRequest,
    OrderSnapshot,
    OrderState,
)
from leviathan_core.numeric import exact_sum


class _FrozenFakeValue:
    def __copy__(self) -> NoReturn:
        raise TypeError("fake broker values cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        raise TypeError("fake broker values cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("fake broker values cannot be pickled")


@dataclass(frozen=True, slots=True)
class FakeSubmitResult(_FrozenFakeValue):
    venue_order_id: str | None
    state: OrderState = OrderState.WORKING

    def __post_init__(self) -> None:
        if not isinstance(self.state, OrderState) or self.state not in {
            OrderState.WORKING,
            OrderState.REJECTED,
        }:
            raise OMSValidationError("INVALID_FAKE_SUBMIT_RESULT")
        if self.state == OrderState.WORKING and not self.venue_order_id:
            raise OMSValidationError("INVALID_FAKE_SUBMIT_RESULT")
        if self.venue_order_id is not None and (
            not isinstance(self.venue_order_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", self.venue_order_id) is None
        ):
            raise OMSValidationError("INVALID_FAKE_SUBMIT_RESULT")


@dataclass(frozen=True, slots=True)
class FakeCancelResult(_FrozenFakeValue):
    confirmed: bool

    def __post_init__(self) -> None:
        if type(self.confirmed) is not bool:
            raise OMSValidationError("INVALID_FAKE_CANCEL_RESULT")


VenueDispatchCapability = VenueDispatchCapabilityV1


def make_venue_dispatch_capability(
    atomic_revision_dispatch: bool, settle_window: timedelta | None = None
) -> VenueDispatchCapabilityV1:
    """Issue the one ADR-0008 capability type for fake venue fixtures."""
    return _issue_venue_capability(atomic_revision_dispatch, settle_window)


ATOMIC_FAKE_CAPABILITY = make_venue_dispatch_capability(True)


class FakeDispatchPermit:
    """Single-use local token minted after the durable submit marker commits."""

    def __init__(self, order_id: str, request_digest: str, expected_revision: int) -> None:
        if type(expected_revision) is not int or expected_revision < 0:
            raise OMSValidationError("INVALID_BROKER_REVISION")
        self.order_id = order_id
        self.request_digest = request_digest
        self.expected_revision = expected_revision
        self._spent = False

    def consume(self, order_id: str, request_digest: str, expected_revision: int) -> None:
        if (
            self._spent
            or type(expected_revision) is not int
            or self.order_id != order_id
            or self.request_digest != request_digest
            or self.expected_revision != expected_revision
        ):
            raise OMSConflict("FAKE_PERMIT_INVALID")
        self._spent = True

    def assert_consumed(self) -> None:
        if not self._spent:
            raise OMSConflict("DISPATCH_PERMIT_NOT_CONSUMED")

    def __copy__(self) -> NoReturn:
        raise TypeError("fake permits cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        raise TypeError("fake permits cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("fake permits cannot be pickled")


class FakeBrokerPort:
    """Explicitly scripted transport with no network, implicit success or retry."""

    def __init__(
        self,
        reconciliation: FakeBrokerReconciliation,
        capability: VenueDispatchCapabilityV1 = ATOMIC_FAKE_CAPABILITY,
        *,
        account_id: str = "UNBOUND",
        environment: str = "paper",
        venue: BrokerVenue = BrokerVenue.ALPACA,
    ) -> None:
        if type(reconciliation) is not FakeBrokerReconciliation:
            raise OMSValidationError("FAKE_RECONCILIATION_REQUIRED")
        if type(capability) is not VenueDispatchCapabilityV1:
            raise OMSValidationError("INVALID_VENUE_CAPABILITY")
        capability.assert_sealed()
        if environment not in {"paper", "demo"} or type(environment) is not str:
            raise OMSValidationError("NON_LIVE_SCOPE_REQUIRED")
        if type(venue) is not BrokerVenue:
            raise OMSValidationError("BROKER_VENUE_MISMATCH")
        self.reconciliation = reconciliation
        self.capability = capability
        self.venue: VenueIdentityV1 = _issue_venue_identity(
            venue,
            BrokerEnvironment.PAPER if environment == "paper" else BrokerEnvironment.DEMO,
            account_id,
        )
        self._submits: list[FakeSubmitResult | SubmitResultV1 | Exception] = []
        self._cancels: list[FakeCancelResult | CancelResultV1 | Exception] = []
        self._observations: list[BrokerObservation | None | Exception] = []
        self._account_views: list[AccountViewV1 | Exception] = []
        self._requests: dict[str, OrderRequest] = {}
        self._venue_order_ids: dict[str, str] = {}
        self._execution_details: dict[str, ExecutionV1] = {}
        self.submit_calls = 0
        self.cancel_calls = 0
        self.read_calls = 0
        self.account_view_calls = 0

    def queue_submit(self, outcome: FakeSubmitResult | SubmitResultV1 | Exception) -> None:
        if type(outcome) not in {FakeSubmitResult, SubmitResultV1} and not isinstance(
            outcome, Exception
        ):
            raise OMSValidationError("INVALID_FAKE_SCRIPT")
        if type(outcome) is SubmitResultV1:
            outcome.assert_sealed()
        self._submits.append(outcome)

    def queue_cancel(self, outcome: FakeCancelResult | CancelResultV1 | Exception) -> None:
        if type(outcome) not in {FakeCancelResult, CancelResultV1} and not isinstance(
            outcome, Exception
        ):
            raise OMSValidationError("INVALID_FAKE_SCRIPT")
        if type(outcome) is CancelResultV1:
            outcome.assert_sealed()
        self._cancels.append(outcome)

    def queue_observation(self, outcome: BrokerObservation | None | Exception) -> None:
        if outcome is not None and not isinstance(outcome, (BrokerObservation, Exception)):
            raise OMSValidationError("INVALID_FAKE_SCRIPT")
        self._observations.append(outcome)

    def queue_account_view(self, outcome: AccountViewV1 | Exception) -> None:
        """Script a stale complete image or a failed/incomplete broker read."""
        if type(outcome) is AccountViewV1:
            outcome.assert_sealed()
        elif not isinstance(outcome, Exception):
            raise OMSValidationError("INVALID_FAKE_SCRIPT")
        self._account_views.append(outcome)

    def submit(
        self, request: OrderRequest, permit: DispatchPermitV1, expected_revision: int
    ) -> SubmitResultV1:
        if not isinstance(request, OrderRequest):
            raise OMSValidationError("INVALID_ORDER_REQUEST")
        if not isinstance(permit, FakeDispatchPermit):
            raise OMSConflict("FAKE_PERMIT_REQUIRED")
        permit.consume(permit.order_id, request.digest, expected_revision)
        if request.client_order_id is None:
            raise OMSValidationError("CLIENT_ID_NOT_DERIVED")
        if (
            request.account_id != self.venue.account_id
            or request.environment.upper() != self.venue.environment.value
            or request.venue != self.venue.venue.value
        ):
            raise BrokerRejected(BrokerRejectionCode.ACCOUNT_MISMATCH)
        if self.capability.atomic_revision_dispatch:
            self.reconciliation.record_dispatch_if_revision(
                request.account_id, request.client_order_id, expected_revision
            )
        else:
            self.reconciliation.record_dispatch(request.account_id, request.client_order_id)
        self._requests[request.client_order_id] = request
        self.submit_calls += 1
        if not self._submits:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        outcome = self._submits.pop(0)
        if type(outcome) is BrokerRejected:
            self.reconciliation.record_outcome(
                request.account_id, request.client_order_id, OrderState.REJECTED, None
            )
            raise outcome
        if isinstance(outcome, Exception):
            raise outcome
        if isinstance(outcome, FakeSubmitResult):
            if outcome.state is OrderState.REJECTED:
                issued = _issue_submit_result(
                    None, OrderState.REJECTED, BrokerRejectionCode.VENUE_REJECTED
                )
            else:
                issued = _issue_submit_result(outcome.venue_order_id, outcome.state)
        else:
            issued = outcome
        issued.assert_sealed()
        self.reconciliation.record_outcome(
            request.account_id, request.client_order_id, issued.state, issued.venue_order_id
        )
        if issued.venue_order_id is not None:
            self._venue_order_ids[request.client_order_id] = issued.venue_order_id
        return issued

    def cancel(self, order: OrderSnapshot) -> CancelResultV1:
        if (
            order.request.account_id != self.venue.account_id
            or order.request.environment.upper() != self.venue.environment.value
            or order.request.venue != self.venue.venue.value
        ):
            raise BrokerRejected(BrokerRejectionCode.ACCOUNT_MISMATCH)
        self.cancel_calls += 1
        if not self._cancels:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        outcome = self._cancels.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        issued = (
            _issue_cancel_result(outcome.confirmed)
            if isinstance(outcome, FakeCancelResult)
            else outcome
        )
        issued.assert_sealed()
        if issued.confirmed:
            client_order_id = order.request.client_order_id
            if client_order_id is None:
                raise OMSValidationError("CLIENT_ID_NOT_DERIVED")
            self.reconciliation.record_outcome(
                order.request.account_id,
                client_order_id,
                OrderState.CANCELED,
                order.venue_order_id,
            )
        return issued

    def read_order(self, order: OrderSnapshot) -> BrokerObservation | None:
        self.read_calls += 1
        if not self._observations:
            raise TimeoutError("fake read unscripted")
        outcome = self._observations.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def record_execution(
        self,
        client_order_id: str,
        execution_id: str,
        quantity: Decimal,
        price: Decimal,
        executed_at: datetime,
    ) -> None:
        """Script one exact broker fill in memory independent of SQLite."""
        request = self._requests.get(client_order_id)
        venue_order_id = self._venue_order_ids.get(client_order_id)
        if request is None or venue_order_id is None:
            raise OMSConflict("BROKER_DISPATCH_NOT_FOUND")
        execution = _issue_execution(
            execution_id,
            venue_order_id,
            client_order_id,
            request.instrument_id,
            request.side,
            quantity,
            price,
            executed_at,
        )
        prior = self._execution_details.get(execution_id)
        if prior is not None:
            prior.assert_sealed()
            if prior.seal_payload() != execution.seal_payload():
                raise OMSConflict("BROKER_EXECUTION_CONFLICT")
            return
        self.reconciliation.record_execution(
            request.account_id, client_order_id, execution_id, quantity
        )
        self.reconciliation.record_execution_detail(request.account_id, execution)
        self._execution_details[execution_id] = execution

    def record_local_fill(self, order: OrderSnapshot, fill: Fill) -> None:
        """Retain exact detail for the legacy fake's explicit OMS fill path."""
        client_id = order.request.client_order_id
        if client_id is None:
            raise OMSConflict("BROKER_DISPATCH_NOT_FOUND")
        detail = _issue_execution(
            fill.execution_id,
            order.venue_order_id or self._venue_order_ids.get(client_id, client_id),
            client_id,
            order.request.instrument_id, order.request.side,
            fill.quantity, fill.price, fill.occurred_at,
        )
        self._execution_details[fill.execution_id] = detail
        self.reconciliation.record_execution_detail(order.request.account_id, detail)

    def read_account_view(self, account_id: str) -> AccountViewV1:
        """Return a complete sealed account image from independent fake memory."""
        self.account_view_calls += 1
        if account_id != self.venue.account_id:
            raise BrokerRejected(BrokerRejectionCode.ACCOUNT_MISMATCH)
        if self._account_views:
            scripted = self._account_views.pop(0)
            if isinstance(scripted, Exception):
                raise scripted
            scripted.assert_sealed()
            return scripted
        snapshot = self.reconciliation.snapshot_account(account_id)
        if snapshot.status not in {
            BrokerReconciliationStatus.FOUND,
            BrokerReconciliationStatus.NOT_FOUND,
        }:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        base_time = datetime(1970, 1, 1, tzinfo=UTC)
        observations_list: list[BrokerObservation] = []
        for match in snapshot.orders:
            if match.state not in {OrderState.WORKING, OrderState.PARTIALLY_FILLED}:
                # The v1 account image cannot invent a known working state for
                # an unknown submit. The separate lookup remains authoritative.
                continue
            request = self._requests.get(match.client_order_id)
            observations_list.append(
                BrokerObservation(
                    observation_id="view-"
                    + sha256((match.client_order_id + str(snapshot.revision)).encode()).hexdigest()[
                        :24
                    ],
                    environment=self.venue.environment.value.lower(),
                    account_id=account_id,
                    venue=request.venue if request is not None else self.venue.venue.value,
                    client_order_id=match.client_order_id,
                    status=match.state,
                    observed_at=base_time,
                    venue_order_id=match.venue_order_id,
                    broker_sequence=snapshot.revision,
                )
            )
        observations = tuple(observations_list)
        executions: list[ExecutionV1] = []
        for item in snapshot.executions:
            detail = self._execution_details.get(item.execution_id)
            if detail is None:
                detail = self.reconciliation.snapshot_execution_detail(
                    account_id, item.client_order_id, item.execution_id
                )
            if detail is None:
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
            detail.assert_sealed()
            if detail.quantity != item.quantity:
                raise BrokerPortError("INVALID_ACCOUNT_VIEW")
            executions.append(detail)
        executions.sort(key=lambda item: item.execution_id)
        quantities: dict[str, list[Decimal]] = {}
        for execution in executions:
            signed = execution.quantity if execution.side == "BUY" else -execution.quantity
            quantities.setdefault(execution.instrument_id, []).append(signed)
        positions = tuple(
            (instrument, exact_sum(values)) for instrument, values in sorted(quantities.items())
        )
        equity = _issue_equity_evidence(
            "USD",
            Decimal("100000"),
            EquityEvidenceKindV1.TOTAL_EQUITY,
            0,
            "fake-broker-v1",
        )
        return _issue_account_view(
            account_id,
            observations,
            positions,
            snapshot.revision,
            tuple(executions),
            base_time,
            complete=True,
            equity=equity,
        )
