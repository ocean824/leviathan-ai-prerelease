"""Typed broker-side evidence, with fake memory independent of the OMS database."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from threading import RLock
from typing import Any, NoReturn, Protocol, SupportsIndex

from leviathan_core.execution.broker_port_v1 import ExecutionV1
from leviathan_core.execution.order_models import (
    OMSConflict,
    OMSStaleBrokerView,
    OMSValidationError,
    OrderState,
)
from leviathan_core.numeric import NumericError, canonical_json, exact_sum, parse_decimal

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)


def _identity(value: object) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise OMSValidationError("INVALID_BROKER_RECONCILIATION")
    return value


def _quantity(value: object, *, positive: bool) -> Decimal:
    if not isinstance(value, Decimal):
        raise OMSValidationError("INVALID_BROKER_RECONCILIATION")
    try:
        quantity = parse_decimal(value, field="quantity", min_value=Decimal(0))
    except NumericError:
        raise OMSValidationError("INVALID_BROKER_RECONCILIATION") from None
    if positive and quantity == 0:
        raise OMSValidationError("INVALID_BROKER_RECONCILIATION")
    return quantity


class _FrozenBrokerValue:
    def __copy__(self) -> NoReturn:
        raise TypeError("broker evidence cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        raise TypeError("broker evidence cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("broker evidence cannot be pickled")


class BrokerReconciliationStatus(StrEnum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    UNAVAILABLE = "UNAVAILABLE"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class BrokerMatch(_FrozenBrokerValue):
    account_id: str
    client_order_id: str
    venue_order_id: str | None
    state: OrderState
    filled_quantity: Decimal
    terminal_since: datetime | None = None

    def __post_init__(self) -> None:
        _identity(self.account_id)
        _identity(self.client_order_id)
        if self.venue_order_id is not None:
            _identity(self.venue_order_id)
        if not isinstance(self.state, OrderState):
            raise OMSValidationError("INVALID_BROKER_RECONCILIATION")
        object.__setattr__(
            self, "filled_quantity", _quantity(self.filled_quantity, positive=False)
        )
        terminal = self.state in {
            OrderState.CANCELED, OrderState.REJECTED, OrderState.EXPIRED
        }
        if terminal != (self.terminal_since is not None):
            raise OMSValidationError("INVALID_BROKER_RECONCILIATION")
        if self.terminal_since is not None:
            if not isinstance(self.terminal_since, datetime) or self.terminal_since.tzinfo is None:
                raise OMSValidationError("INVALID_BROKER_RECONCILIATION")
            object.__setattr__(self, "terminal_since", self.terminal_since.astimezone(UTC))


@dataclass(frozen=True, slots=True)
class BrokerExecution(_FrozenBrokerValue):
    account_id: str
    client_order_id: str
    execution_id: str
    quantity: Decimal

    def __post_init__(self) -> None:
        _identity(self.account_id)
        _identity(self.client_order_id)
        _identity(self.execution_id)
        object.__setattr__(self, "quantity", _quantity(self.quantity, positive=True))


@dataclass(frozen=True, slots=True)
class BrokerLookup(_FrozenBrokerValue):
    status: BrokerReconciliationStatus
    revision: int
    match: BrokerMatch | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.status, BrokerReconciliationStatus)
            or type(self.revision) is not int or self.revision < 0
            or (self.status == BrokerReconciliationStatus.FOUND) != (self.match is not None)
            or (self.match is not None and not isinstance(self.match, BrokerMatch))
        ):
            raise OMSValidationError("INVALID_BROKER_RECONCILIATION")

    @property
    def broker_revision(self) -> int:
        return self.revision


@dataclass(frozen=True, slots=True)
class BrokerAccountView(_FrozenBrokerValue):
    status: BrokerReconciliationStatus
    revision: int
    orders: tuple[BrokerMatch, ...] = ()
    executions: tuple[BrokerExecution, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.status, BrokerReconciliationStatus)
            or type(self.revision) is not int or self.revision < 0
            or type(self.orders) is not tuple
            or type(self.executions) is not tuple
            or any(not isinstance(item, BrokerMatch) for item in self.orders)
            or any(not isinstance(item, BrokerExecution) for item in self.executions)
            or (self.status == BrokerReconciliationStatus.FOUND)
            != bool(self.orders or self.executions)
        ):
            raise OMSValidationError("INVALID_BROKER_RECONCILIATION")

    @property
    def broker_revision(self) -> int:
        return self.revision


class BrokerReconciliationPort(Protocol):
    async def find_by_client_order_id(
        self, account: str, client_order_id: str
    ) -> BrokerLookup: ...

    async def account_view(
        self, account: str, since: datetime | None
    ) -> BrokerAccountView: ...


def broker_evidence_digest(lookup: BrokerLookup, view: BrokerAccountView) -> str:
    """Digest the complete, typed broker lookup and account image."""
    if type(lookup) is not BrokerLookup or type(view) is not BrokerAccountView:
        raise OMSValidationError("INVALID_BROKER_RECONCILIATION")

    def match_payload(match: BrokerMatch) -> dict[str, Any]:
        return {
            "account_id": match.account_id,
            "client_order_id": match.client_order_id,
            "venue_order_id": match.venue_order_id,
            "state": match.state.value,
            "filled_quantity": match.filled_quantity,
            "terminal_since": (
                None if match.terminal_since is None else match.terminal_since.isoformat()
            ),
        }

    payload = {
        "lookup": {
            "status": lookup.status.value,
            "revision": lookup.revision,
            "match": None if lookup.match is None else match_payload(lookup.match),
        },
        "account_view": {
            "status": view.status.value,
            "revision": view.revision,
            "orders": [match_payload(item) for item in view.orders],
            "executions": [{
                "account_id": item.account_id,
                "client_order_id": item.client_order_id,
                "execution_id": item.execution_id,
                "quantity": item.quantity,
            } for item in view.executions],
        },
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


class FakeBrokerReconciliation:
    """Broker memory lives on this object across local SQLite restore or erasure."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._records: dict[tuple[str, str], BrokerMatch] = {}
        self._executions: dict[tuple[str, str, str], BrokerExecution] = {}
        self._execution_details: dict[tuple[str, str, str], ExecutionV1] = {}
        self._lookup_scripts: list[BrokerReconciliationStatus] = []
        self._view_scripts: list[BrokerReconciliationStatus] = []
        self._revision = 0
        self.find_calls = 0
        self.view_calls = 0

    def queue_lookup(self, status: BrokerReconciliationStatus) -> None:
        if type(status) is not BrokerReconciliationStatus or status not in {
            BrokerReconciliationStatus.UNAVAILABLE, BrokerReconciliationStatus.AMBIGUOUS
        }:
            raise OMSValidationError("INVALID_FAKE_SCRIPT")
        with self._lock:
            self._lookup_scripts.append(status)

    def queue_account_view(self, status: BrokerReconciliationStatus) -> None:
        if type(status) is not BrokerReconciliationStatus or status not in {
            BrokerReconciliationStatus.UNAVAILABLE, BrokerReconciliationStatus.AMBIGUOUS
        }:
            raise OMSValidationError("INVALID_FAKE_SCRIPT")
        with self._lock:
            self._view_scripts.append(status)

    async def find_by_client_order_id(
        self, account: str, client_order_id: str
    ) -> BrokerLookup:
        _identity(account)
        _identity(client_order_id)
        with self._lock:
            self.find_calls += 1
            if self._lookup_scripts:
                return BrokerLookup(self._lookup_scripts.pop(0), self._revision)
            match = self._records.get((account, client_order_id))
            return BrokerLookup(
                BrokerReconciliationStatus.FOUND
                if match else BrokerReconciliationStatus.NOT_FOUND,
                self._revision,
                match,
            )

    async def account_view(
        self, account: str, since: datetime | None
    ) -> BrokerAccountView:
        return self.snapshot_account(account, since)

    def snapshot_account(
        self, account: str, since: datetime | None = None
    ) -> BrokerAccountView:
        """The same broker image for the synchronous BrokerPortV1 fake."""
        _identity(account)
        if since is not None and (not isinstance(since, datetime) or since.tzinfo is None):
            raise OMSValidationError("INVALID_BROKER_RECONCILIATION")
        if since is not None:
            since.astimezone(UTC)
        with self._lock:
            self.view_calls += 1
            if self._view_scripts:
                return BrokerAccountView(self._view_scripts.pop(0), self._revision)
            orders = tuple(
                match for (item_account, _), match in sorted(self._records.items())
                if item_account == account and match.state not in {
                    OrderState.REJECTED, OrderState.CANCELED, OrderState.EXPIRED,
                    OrderState.FILLED,
                }
            )
            executions = tuple(
                execution
                for (item_account, _, _), execution in sorted(self._executions.items())
                if item_account == account
            )
            return BrokerAccountView(
                BrokerReconciliationStatus.FOUND if orders or executions
                else BrokerReconciliationStatus.NOT_FOUND,
                self._revision,
                orders,
                executions,
            )

    def snapshot_match(self, account: str, client_order_id: str) -> BrokerMatch | None:
        """Return durable fake broker identity even after an order leaves the open view."""
        with self._lock:
            return self._records.get((_identity(account), _identity(client_order_id)))

    def snapshot_execution_detail(
        self, account: str, client_order_id: str, execution_id: str,
    ) -> ExecutionV1 | None:
        with self._lock:
            return self._execution_details.get((
                _identity(account), _identity(client_order_id), _identity(execution_id)
            ))

    def record_execution_detail(self, account: str, execution: ExecutionV1) -> None:
        if type(execution) is not ExecutionV1 or execution.client_order_id is None:
            raise OMSValidationError("INVALID_BROKER_RECONCILIATION")
        execution.assert_sealed()
        key = (_identity(account), execution.client_order_id, execution.execution_id)
        with self._lock:
            if key not in self._executions or self._executions[key].quantity != execution.quantity:
                raise OMSConflict("BROKER_EXECUTION_CONFLICT")
            prior = self._execution_details.get(key)
            if prior is not None and prior.seal_payload() != execution.seal_payload():
                raise OMSConflict("BROKER_EXECUTION_CONFLICT")
            if prior is None:
                self._revision += 1
            self._execution_details[key] = execution

    def record_dispatch(self, account: str, client_order_id: str) -> None:
        _identity(account)
        _identity(client_order_id)
        with self._lock:
            identity = (account, client_order_id)
            if identity in self._records:
                raise OMSConflict("DUPLICATE_INTENT")
            self._records[identity] = BrokerMatch(
                account, client_order_id, None, OrderState.UNKNOWN_SUBMIT, Decimal(0)
            )
            self._revision += 1

    def record_dispatch_if_revision(
        self, account: str, client_order_id: str, expected_revision: int
    ) -> None:
        """One synchronous compare-and-record step for the atomic fake venue."""
        if type(expected_revision) is not int or expected_revision < 0:
            raise OMSValidationError("INVALID_BROKER_REVISION")
        with self._lock:
            if self._revision != expected_revision:
                raise OMSStaleBrokerView()
            self.record_dispatch(account, client_order_id)

    def record_outcome(
        self, account: str, client_order_id: str, state: OrderState,
        venue_order_id: str | None,
        *, observed_at: datetime | None = None,
    ) -> None:
        identity = (_identity(account), _identity(client_order_id))
        if observed_at is not None and (
            not isinstance(observed_at, datetime) or observed_at.tzinfo is None
        ):
            raise OMSValidationError("INVALID_BROKER_RECONCILIATION")
        with self._lock:
            if identity not in self._records:
                raise OMSConflict("BROKER_DISPATCH_NOT_FOUND")
            prior = self._records[identity]
            terminal = state in {OrderState.CANCELED, OrderState.REJECTED, OrderState.EXPIRED}
            terminal_since = (
                (observed_at or (
                    prior.terminal_since if prior.state == state else None
                ) or datetime.now(UTC)).astimezone(UTC)
                if terminal else None
            )
            self._records[identity] = BrokerMatch(
                account, client_order_id, venue_order_id, state,
                prior.filled_quantity, terminal_since,
            )
            self._revision += 1

    def record_execution(
        self, account: str, client_order_id: str, execution_id: str, quantity: Decimal
    ) -> None:
        item = BrokerExecution(account, client_order_id, execution_id, quantity)
        with self._lock:
            key = (account, client_order_id, execution_id)
            existing = self._executions.get(key)
            if existing is not None:
                if existing != item:
                    raise OMSConflict("BROKER_EXECUTION_CONFLICT")
                return
            match = self._records.get((account, client_order_id))
            if match is not None:
                try:
                    filled = exact_sum((match.filled_quantity, item.quantity))
                except NumericError:
                    raise OMSValidationError("INVALID_BROKER_RECONCILIATION") from None
                self._records[(account, client_order_id)] = BrokerMatch(
                    account, client_order_id, match.venue_order_id,
                    OrderState.PARTIALLY_FILLED if match.state in {
                        OrderState.UNKNOWN_SUBMIT, OrderState.WORKING,
                        OrderState.PARTIALLY_FILLED
                    } else match.state,
                    filled,
                    match.terminal_since,
                )
            self._executions[key] = item
            self._revision += 1
