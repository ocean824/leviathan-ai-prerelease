# ruff: noqa: N802 - TWS callback and request method names are the native API surface.
"""Fake-only IBKR TWS paper adapter and callback evidence collector.

The transport deliberately has no socket, SDK or credential implementation.
TWS callbacks are evidence; a returned method call is never an acknowledgement.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from threading import RLock
from typing import Any, NoReturn, Protocol, SupportsIndex

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
    ExecutionV1,
    SubmitResultV1,
    VenueDispatchCapabilityV1,
    VenueIdentityV1,
    _issue_account_view,
    _issue_cancel_result,
    _issue_execution,
    _issue_submit_result,
    _issue_venue_capability,
    _issue_venue_identity,
)
from leviathan_core.execution.brokers.ibkr_mapping import (
    IBKRAdapterError,
    IBKRContractBindingV1,
    IBKRNativeContractV1,
    IBKRNativeOrderV1,
    map_order_request,
)
from leviathan_core.execution.order_models import (
    BrokerObservation,
    OrderRequest,
    OrderSnapshot,
    OrderState,
)
from leviathan_core.numeric import NumericError, parse_decimal, parse_int

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_REF = re.compile(r"LI1[A-Z2-7]{32}\Z", re.ASCII)
_MAX_ORDER_ID = 2_147_483_647
_OPEN_STATUSES = frozenset({"ApiPending", "PendingSubmit", "PreSubmitted", "Submitted"})
_CANCEL_STATUSES = frozenset({"PendingCancel", "ApiCancelled", "Cancelled"})
_OTHER_STATUSES = frozenset({"Filled", "Inactive"})
_ALL_STATUSES = _OPEN_STATUSES | _CANCEL_STATUSES | _OTHER_STATUSES


def _native_ref(value: object) -> str:
    if (
        type(value) is not str
        or len(value) > 128
        or any(ord(char) < 32 or ord(char) > 126 for char in value)
    ):
        raise IBKRAdapterError("INVALID_CALLBACK")
    return value


def _id(value: object) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise IBKRAdapterError("INVALID_CALLBACK")
    return value


def _positive_int(value: object, *, minimum: int = 1) -> int:
    try:
        return parse_int(value, field="native_id", min_value=minimum, max_value=_MAX_ORDER_ID)
    except NumericError:
        raise IBKRAdapterError("INVALID_CALLBACK") from None


def _nonnegative_long(value: object) -> int:
    try:
        return parse_int(value, field="perm_id", min_value=0, max_value=2**63 - 1)
    except NumericError:
        raise IBKRAdapterError("INVALID_CALLBACK") from None


def _nonnegative_decimal(value: object) -> Decimal:
    if type(value) is not Decimal:
        raise IBKRAdapterError("INVALID_CALLBACK")
    try:
        result = parse_decimal(value, field="native_quantity")
    except NumericError:
        raise IBKRAdapterError("INVALID_CALLBACK") from None
    if result < 0:
        raise IBKRAdapterError("INVALID_CALLBACK")
    return result


def _signed_decimal(value: object) -> Decimal:
    if type(value) is not Decimal:
        raise IBKRAdapterError("INVALID_CALLBACK")
    try:
        return parse_decimal(value, field="native_quantity")
    except NumericError:
        raise IBKRAdapterError("INVALID_CALLBACK") from None


class _FrozenCallback:
    def __copy__(self) -> NoReturn:
        raise TypeError("IBKR callback values cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        raise TypeError("IBKR callback values cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("IBKR callback values cannot be pickled")


@dataclass(frozen=True, slots=True)
class IBKRPaperSessionV1(_FrozenCallback):
    """Explicit expected or observed identity; a fake is not provider proof."""

    account_id: str
    client_id: int
    session_id: str
    master_client_id: int
    mode: str = "PAPER"
    executions_since: datetime | None = None

    def __post_init__(self) -> None:
        _id(self.account_id)
        _id(self.session_id)
        _positive_int(self.client_id, minimum=0)
        _positive_int(self.master_client_id, minimum=0)
        if type(self.mode) is not str or self.mode != "PAPER":
            raise IBKRAdapterError("PAPER_SESSION_REQUIRED")
        if self.executions_since is not None:
            if (
                type(self.executions_since) is not datetime
                or self.executions_since.tzinfo is None
                or self.executions_since.utcoffset() is None
                or self.executions_since.microsecond != 0
            ):
                raise IBKRAdapterError("INVALID_EXECUTION_WINDOW")
            object.__setattr__(self, "executions_since", self.executions_since.astimezone(UTC))


@dataclass(frozen=True, slots=True)
class IBKROpenOrderV1(_FrozenCallback):
    account_id: str
    client_id: int
    order_id: int
    perm_id: int
    order_ref: str
    con_id: int
    status: str
    total_quantity: Decimal

    def __post_init__(self) -> None:
        _id(self.account_id)
        _positive_int(self.client_id, minimum=0)
        _positive_int(self.order_id, minimum=0)
        _nonnegative_long(self.perm_id)
        _positive_int(self.con_id)
        _native_ref(self.order_ref)
        if type(self.status) is not str or self.status not in _ALL_STATUSES:
            raise IBKRAdapterError("INVALID_CALLBACK")
        value = _nonnegative_decimal(self.total_quantity)
        if value <= 0:
            raise IBKRAdapterError("INVALID_CALLBACK")
        object.__setattr__(self, "total_quantity", value)


@dataclass(frozen=True, slots=True)
class IBKROrderStatusV1(_FrozenCallback):
    client_id: int
    order_id: int
    perm_id: int
    status: str
    filled: Decimal
    remaining: Decimal

    def __post_init__(self) -> None:
        _positive_int(self.client_id, minimum=0)
        _positive_int(self.order_id, minimum=0)
        _nonnegative_long(self.perm_id)
        if type(self.status) is not str or self.status not in _ALL_STATUSES:
            raise IBKRAdapterError("INVALID_CALLBACK")
        object.__setattr__(self, "filled", _nonnegative_decimal(self.filled))
        object.__setattr__(self, "remaining", _nonnegative_decimal(self.remaining))


@dataclass(frozen=True, slots=True)
class IBKRExecDetailsV1(_FrozenCallback):
    account_id: str
    client_id: int
    order_id: int
    perm_id: int
    order_ref: str
    con_id: int
    execution_id: str
    quantity: Decimal
    price: Decimal
    side: str | None = None
    executed_at: datetime | None = None

    def __post_init__(self) -> None:
        _id(self.account_id)
        _positive_int(self.client_id, minimum=0)
        _positive_int(self.order_id, minimum=0)
        _nonnegative_long(self.perm_id)
        _positive_int(self.con_id)
        _id(self.execution_id)
        _native_ref(self.order_ref)
        for name in ("quantity", "price"):
            value = _nonnegative_decimal(getattr(self, name))
            if value <= 0:
                raise IBKRAdapterError("INVALID_CALLBACK")
            object.__setattr__(self, name, value)
        if self.side is not None and (
            type(self.side) is not str or self.side not in {"BOT", "SLD"}
        ):
            raise IBKRAdapterError("INVALID_CALLBACK")
        if self.executed_at is not None:
            if (
                type(self.executed_at) is not datetime
                or self.executed_at.tzinfo is None
                or self.executed_at.utcoffset() is None
            ):
                raise IBKRAdapterError("INVALID_CALLBACK")
            object.__setattr__(self, "executed_at", self.executed_at.astimezone(UTC))


@dataclass(frozen=True, slots=True)
class IBKRErrorV1(_FrozenCallback):
    request_id: int
    code: int

    def __post_init__(self) -> None:
        try:
            parse_int(self.request_id, field="request_id", min_value=-1, max_value=_MAX_ORDER_ID)
        except NumericError:
            raise IBKRAdapterError("INVALID_CALLBACK") from None
        _positive_int(self.code, minimum=0)


@dataclass(frozen=True, slots=True)
class IBKRCompletedOrderV1(_FrozenCallback):
    account_id: str
    client_id: int
    order_id: int
    perm_id: int
    order_ref: str
    con_id: int
    status: str

    def __post_init__(self) -> None:
        _id(self.account_id)
        _positive_int(self.client_id, minimum=0)
        _positive_int(self.order_id, minimum=0)
        _nonnegative_long(self.perm_id)
        _positive_int(self.con_id)
        _native_ref(self.order_ref)
        if type(self.status) is not str or self.status not in {"Cancelled", "Filled", "Inactive"}:
            raise IBKRAdapterError("INVALID_CALLBACK")


@dataclass(frozen=True, slots=True)
class IBKRPositionV1(_FrozenCallback):
    account_id: str
    con_id: int
    quantity: Decimal

    def __post_init__(self) -> None:
        _id(self.account_id)
        _positive_int(self.con_id)
        object.__setattr__(self, "quantity", _signed_decimal(self.quantity))


@dataclass(frozen=True, slots=True)
class IBKROpenOrderEndV1(_FrozenCallback):
    pass


@dataclass(frozen=True, slots=True)
class IBKRExecDetailsEndV1(_FrozenCallback):
    request_id: int

    def __post_init__(self) -> None:
        _positive_int(self.request_id)


@dataclass(frozen=True, slots=True)
class IBKRCompletedOrdersEndV1(_FrozenCallback):
    pass


@dataclass(frozen=True, slots=True)
class IBKRPositionEndV1(_FrozenCallback):
    pass


TwsCallback = (
    IBKROpenOrderV1
    | IBKROrderStatusV1
    | IBKRExecDetailsV1
    | IBKRErrorV1
    | IBKRCompletedOrderV1
    | IBKRPositionV1
    | IBKROpenOrderEndV1
    | IBKRExecDetailsEndV1
    | IBKRCompletedOrdersEndV1
    | IBKRPositionEndV1
)
_CALLBACK_TYPES = (
    IBKROpenOrderV1,
    IBKROrderStatusV1,
    IBKRExecDetailsV1,
    IBKRErrorV1,
    IBKRCompletedOrderV1,
    IBKRPositionV1,
    IBKROpenOrderEndV1,
    IBKRExecDetailsEndV1,
    IBKRCompletedOrdersEndV1,
    IBKRPositionEndV1,
)


class TwsCallbackSink(Protocol):
    def openOrder(self, event: IBKROpenOrderV1) -> None: ...
    def orderStatus(self, event: IBKROrderStatusV1) -> None: ...
    def execDetails(self, event: IBKRExecDetailsV1) -> None: ...
    def error(self, event: IBKRErrorV1) -> None: ...
    def completedOrder(self, event: IBKRCompletedOrderV1) -> None: ...
    def position(self, event: IBKRPositionV1) -> None: ...
    def openOrderEnd(self) -> None: ...
    def execDetailsEnd(self, request_id: int) -> None: ...
    def completedOrdersEnd(self) -> None: ...
    def positionEnd(self) -> None: ...


class TwsTransport(Protocol):
    """Narrow TWS-shaped seam; no implementation here can open a connection."""

    def observed_session(self) -> IBKRPaperSessionV1: ...
    def bind_callbacks(self, sink: TwsCallbackSink) -> None: ...
    def placeOrder(
        self, order_id: int, contract: IBKRNativeContractV1, order: IBKRNativeOrderV1
    ) -> None: ...
    def cancelOrder(self, order_id: int) -> None: ...
    def reqOpenOrders(self) -> None: ...
    def reqAllOpenOrders(self) -> None: ...
    def reqCompletedOrders(self, api_only: bool) -> None: ...
    def reqPositions(self) -> None: ...
    def reqExecutions(
        self, request_id: int, account_id: str, client_id: int | None, since: datetime
    ) -> None: ...


class FakeTwsTransport:
    """Scripted in-memory transport; the only accepted adapter transport type."""

    def __init__(self, session: IBKRPaperSessionV1) -> None:
        if type(session) is not IBKRPaperSessionV1:
            raise IBKRAdapterError("PAPER_SESSION_REQUIRED")
        self._session = session
        self._sink: TwsCallbackSink | None = None
        self._place: list[tuple[tuple[TwsCallback, ...], Exception | None]] = []
        self._cancel: list[tuple[tuple[TwsCallback, ...], Exception | None]] = []
        self._open: list[tuple[tuple[TwsCallback, ...], Exception | None]] = []
        self._all_open: list[tuple[tuple[TwsCallback, ...], Exception | None]] = []
        self._completed: list[tuple[tuple[TwsCallback, ...], Exception | None]] = []
        self._positions: list[tuple[tuple[TwsCallback, ...], Exception | None]] = []
        self._executions: list[tuple[tuple[TwsCallback, ...], Exception | None]] = []
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def observed_session(self) -> IBKRPaperSessionV1:
        return self._session

    def bind_callbacks(self, sink: TwsCallbackSink) -> None:
        if self._sink is not None:
            raise IBKRAdapterError("TRANSPORT_ALREADY_BOUND")
        self._sink = sink

    @staticmethod
    def _script(
        queue: list[tuple[tuple[TwsCallback, ...], Exception | None]],
        events: tuple[TwsCallback, ...],
        failure: Exception | None,
    ) -> None:
        if type(events) is not tuple or any(type(item) not in _CALLBACK_TYPES for item in events):
            raise IBKRAdapterError("INVALID_FAKE_SCRIPT")
        if failure is not None and not isinstance(failure, Exception):
            raise IBKRAdapterError("INVALID_FAKE_SCRIPT")
        queue.append((events, failure))

    def queue_place(
        self, events: tuple[TwsCallback, ...] = (), failure: Exception | None = None
    ) -> None:
        self._script(self._place, events, failure)

    def queue_cancel(
        self, events: tuple[TwsCallback, ...] = (), failure: Exception | None = None
    ) -> None:
        self._script(self._cancel, events, failure)

    def queue_open_orders(
        self, events: tuple[TwsCallback, ...] = (), failure: Exception | None = None
    ) -> None:
        self._script(self._open, events, failure)

    def queue_executions(
        self, events: tuple[TwsCallback, ...] = (), failure: Exception | None = None
    ) -> None:
        self._script(self._executions, events, failure)

    def queue_all_open_orders(
        self, events: tuple[TwsCallback, ...] = (), failure: Exception | None = None
    ) -> None:
        self._script(self._all_open, events, failure)

    def queue_completed_orders(
        self, events: tuple[TwsCallback, ...] = (), failure: Exception | None = None
    ) -> None:
        self._script(self._completed, events, failure)

    def queue_positions(
        self, events: tuple[TwsCallback, ...] = (), failure: Exception | None = None
    ) -> None:
        self._script(self._positions, events, failure)

    def _run(self, queue: list[tuple[tuple[TwsCallback, ...], Exception | None]]) -> None:
        if self._sink is None:
            raise IBKRAdapterError("TRANSPORT_UNBOUND")
        if not queue:
            raise TimeoutError("fake TWS response absent")
        events, failure = queue.pop(0)
        for event in events:
            if type(event) is IBKROpenOrderV1:
                self._sink.openOrder(event)
            elif type(event) is IBKROrderStatusV1:
                self._sink.orderStatus(event)
            elif type(event) is IBKRExecDetailsV1:
                self._sink.execDetails(event)
            elif type(event) is IBKRErrorV1:
                self._sink.error(event)
            elif type(event) is IBKRCompletedOrderV1:
                self._sink.completedOrder(event)
            elif type(event) is IBKRPositionV1:
                self._sink.position(event)
            elif type(event) is IBKROpenOrderEndV1:
                self._sink.openOrderEnd()
            elif type(event) is IBKRExecDetailsEndV1:
                self._sink.execDetailsEnd(event.request_id)
            elif type(event) is IBKRCompletedOrdersEndV1:
                self._sink.completedOrdersEnd()
            elif type(event) is IBKRPositionEndV1:
                self._sink.positionEnd()
        if failure is not None:
            raise failure

    def placeOrder(
        self, order_id: int, contract: IBKRNativeContractV1, order: IBKRNativeOrderV1
    ) -> None:
        self.calls.append(("placeOrder", (order_id, contract, order)))
        self._run(self._place)

    def cancelOrder(self, order_id: int) -> None:
        self.calls.append(("cancelOrder", (order_id,)))
        self._run(self._cancel)

    def reqOpenOrders(self) -> None:
        self.calls.append(("reqOpenOrders", ()))
        self._run(self._open)

    def reqAllOpenOrders(self) -> None:
        self.calls.append(("reqAllOpenOrders", ()))
        self._run(self._all_open)

    def reqCompletedOrders(self, api_only: bool) -> None:
        if type(api_only) is not bool or api_only:
            raise IBKRAdapterError("FULL_ACCOUNT_VIEW_REQUIRED")
        self.calls.append(("reqCompletedOrders", (api_only,)))
        self._run(self._completed)

    def reqPositions(self) -> None:
        self.calls.append(("reqPositions", ()))
        self._run(self._positions)

    def reqExecutions(
        self, request_id: int, account_id: str, client_id: int | None, since: datetime
    ) -> None:
        if (
            account_id != self._session.account_id
            or client_id is not None
            or since != self._session.executions_since
        ):
            raise IBKRAdapterError("INVALID_EXECUTION_FILTER")
        self.calls.append(("reqExecutions", (request_id, account_id, client_id, since)))
        self._run(self._executions)


@dataclass(frozen=True, slots=True)
class _AccountEvidence:
    open_orders: tuple[IBKROpenOrderV1, ...]
    completed_orders: tuple[IBKRCompletedOrderV1, ...]
    positions: tuple[IBKRPositionV1, ...]
    executions: tuple[IBKRExecDetailsV1, ...]
    executions_since: datetime
    sequence: int
    callback_sequence: int


class IBKRTwsPaperAdapter:
    """Callback-aware paper adapter; only the exact in-memory fake can be bound."""

    def __init__(
        self,
        transport: FakeTwsTransport,
        expected_session: IBKRPaperSessionV1,
        bindings: tuple[IBKRContractBindingV1, ...],
    ) -> None:
        if (
            type(transport) is not FakeTwsTransport
            or type(expected_session) is not IBKRPaperSessionV1
        ):
            raise IBKRAdapterError("FAKE_PAPER_TRANSPORT_REQUIRED")
        if transport.observed_session() != expected_session:
            raise IBKRAdapterError("PAPER_SESSION_MISMATCH")
        if expected_session.client_id not in {0, expected_session.master_client_id}:
            raise IBKRAdapterError("MASTER_CLIENT_REQUIRED")
        if type(bindings) is not tuple or any(
            type(item) is not IBKRContractBindingV1 for item in bindings
        ):
            raise IBKRAdapterError("INVALID_CONTRACT_BINDING")
        lookup = {item.native_contract_id: item for item in bindings}
        if len(lookup) != len(bindings) or len({item.con_id for item in bindings}) != len(bindings):
            raise IBKRAdapterError("DUPLICATE_CONTRACT_BINDING")
        self._transport = transport
        self._dispatch_mutex = RLock()
        self._callback_arrival_mutex = RLock()
        self._callback_arrivals = 0
        self._callback_processed = 0
        self._session = expected_session
        self._bindings = lookup
        self._next_order_id: int | None = None
        self._highest_seen_order_id = 0
        self._sequence = 0
        self._callback_sequence = 0
        self._callback_history: deque[tuple[int, TwsCallback]] = deque(maxlen=4096)
        self._last_view_callback_sequence: int | None = None
        self._last_view_revision: int | None = None
        self._collecting_account = False
        self._snapshot_cross_component = False
        self._discrepancies: list[str] = []
        self._next_request_id = 1
        self._connected = True
        self._blocked = False
        self._hard_block = False
        self._active_component: str | None = None
        self._component_finished = False
        self._component_events: list[TwsCallback] = []
        self._open_orders: dict[tuple[int, int], IBKROpenOrderV1] = {}
        self._completed_orders: dict[tuple[int, int], IBKRCompletedOrderV1] = {}
        self._statuses: dict[tuple[int, int], IBKROrderStatusV1] = {}
        self._terminal_statuses: dict[tuple[int, int], str] = {}
        self._executions: dict[tuple[str, str], IBKRExecDetailsV1] = {}
        self._order_refs: dict[str, tuple[int, int, int]] = {}
        self._errors: dict[int, int] = {}
        self._attempted_refs: set[str] = set()
        self._cancel_attempted_refs: set[str] = set()
        self._client_ids_by_ref: dict[str, str] = {}
        self._last_account_evidence: _AccountEvidence | None = None
        self._capability = _issue_venue_capability(False, timedelta(minutes=1))
        self._venue = _issue_venue_identity(
            BrokerVenue.IBKR_TWS, BrokerEnvironment.PAPER, expected_session.account_id
        )
        transport.bind_callbacks(self)

    @property
    def capability(self) -> VenueDispatchCapabilityV1:
        self._capability.assert_sealed()
        return self._capability

    @property
    def venue(self) -> VenueIdentityV1:
        self._venue.assert_sealed()
        return self._venue

    @property
    def paper_session(self) -> IBKRPaperSessionV1:
        return self._session

    @property
    def blocked(self) -> bool:
        return self._blocked

    @property
    def callback_sequence(self) -> int:
        return self._callback_sequence

    @property
    def discrepancies(self) -> tuple[str, ...]:
        return tuple(self._discrepancies)

    @property
    def next_order_id(self) -> int | None:
        return self._next_order_id

    def disconnect(self) -> None:
        """The fake's loss of session requires a new bound adapter and reconciliation."""
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                self._connected = False
                self._blocked = True
            finally:
                self._callback_processed += 1

    def _note_callback_arrival(self) -> None:
        with self._callback_arrival_mutex:
            self._callback_arrivals += 1

    def _fault(self, code: str) -> NoReturn:
        self._blocked = True
        self._hard_block = True
        if code not in self._discrepancies:
            self._discrepancies.append(code)
        raise IBKRAdapterError(code)

    def _require_session(self, *, for_read: bool = False) -> None:
        if not self._connected or self._hard_block or (self._blocked and not for_read):
            raise IBKRAdapterError("SESSION_RECONCILIATION_REQUIRED")
        if self._transport.observed_session() != self._session:
            self._fault("PAPER_SESSION_MISMATCH")

    def nextValidId(self, order_id: int) -> None:
        """A per-clientId high-water floor; exhaustion never wraps to a reused ID."""
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                _positive_int(order_id)
                if order_id <= self._highest_seen_order_id:
                    order_id = self._highest_seen_order_id + 1
                self._next_order_id = order_id if order_id <= _MAX_ORDER_ID else None
            finally:
                self._callback_processed += 1

    def _track_ref(self, order_ref: str, client_id: int, order_id: int, perm_id: int) -> None:
        if _REF.fullmatch(order_ref) is None:
            return
        key = (client_id, order_id, perm_id)
        previous = self._order_refs.get(order_ref)
        if previous is not None and (
            previous[:2] != key[:2]
            or (previous[2] != 0 and perm_id != 0 and previous[2] != perm_id)
        ):
            self._fault("ORDER_REF_CONFLICT")
        self._order_refs[order_ref] = key if perm_id != 0 or previous is None else previous

    def _track_native_id(self, client_id: int, order_id: int) -> None:
        if client_id == self._session.client_id:
            self._highest_seen_order_id = max(self._highest_seen_order_id, order_id)
            if self._next_order_id is not None and self._next_order_id <= order_id:
                self._next_order_id = order_id + 1 if order_id < _MAX_ORDER_ID else None

    def _capture(self, event: TwsCallback) -> None:
        self._callback_sequence += 1
        self._callback_history.append((self._callback_sequence, event))
        if isinstance(event, (IBKROpenOrderV1, IBKROrderStatusV1, IBKRCompletedOrderV1)):
            key = (event.client_id, event.order_id)
            terminal = self._terminal_statuses.get(key)
            if terminal is not None and event.status != terminal:
                self._fault("ORDER_STATUS_CONFLICT")
            if event.status in {"Cancelled", "Filled", "Inactive"}:
                self._terminal_statuses[key] = event.status
        expected_component = {
            IBKROpenOrderV1: "all_open",
            IBKRCompletedOrderV1: "completed",
            IBKRPositionV1: "positions",
            IBKRExecDetailsV1: "executions",
        }.get(type(event))
        if self._collecting_account and self._active_component != expected_component:
            self._snapshot_cross_component = True
        if self._active_component is not None:
            self._component_events.append(event)

    def openOrder(self, event: IBKROpenOrderV1) -> None:
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                self._open_order(event)
            finally:
                self._callback_processed += 1

    def _open_order(self, event: IBKROpenOrderV1) -> None:
        if type(event) is not IBKROpenOrderV1:
            self._fault("INVALID_CALLBACK")
        self._capture(event)
        if event.account_id != self._session.account_id:
            self._fault("ACCOUNT_MISMATCH")
        key = (event.client_id, event.order_id)
        previous = self._open_orders.get(key)
        if previous is not None and (
            (previous.perm_id != 0 and event.perm_id != 0 and previous.perm_id != event.perm_id)
            or previous.order_ref != event.order_ref
            or previous.con_id != event.con_id
            or previous.total_quantity != event.total_quantity
        ):
            self._fault("OPEN_ORDER_CONFLICT")
        self._track_ref(event.order_ref, event.client_id, event.order_id, event.perm_id)
        self._track_native_id(event.client_id, event.order_id)
        self._open_orders[key] = event

    def orderStatus(self, event: IBKROrderStatusV1) -> None:
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                self._order_status(event)
            finally:
                self._callback_processed += 1

    def _order_status(self, event: IBKROrderStatusV1) -> None:
        if type(event) is not IBKROrderStatusV1:
            self._fault("INVALID_CALLBACK")
        self._capture(event)
        key = (event.client_id, event.order_id)
        previous = self._statuses.get(key)
        if previous is not None and (
            (previous.perm_id != 0 and event.perm_id != 0 and previous.perm_id != event.perm_id)
            or event.filled < previous.filled
            or (previous.status in {"Cancelled", "Filled", "Inactive"} and event != previous)
        ):
            self._fault("ORDER_STATUS_CONFLICT")
        self._track_native_id(event.client_id, event.order_id)
        self._statuses[key] = event

    def execDetails(self, event: IBKRExecDetailsV1) -> None:
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                self._exec_details(event)
            finally:
                self._callback_processed += 1

    def _exec_details(self, event: IBKRExecDetailsV1) -> None:
        if type(event) is not IBKRExecDetailsV1:
            self._fault("INVALID_CALLBACK")
        self._capture(event)
        if event.account_id != self._session.account_id:
            self._fault("ACCOUNT_MISMATCH")
        key = (event.account_id, event.execution_id)
        previous = self._executions.get(key)
        if previous is not None and previous != event:
            self._fault("EXECUTION_CONFLICT")
        self._track_ref(event.order_ref, event.client_id, event.order_id, event.perm_id)
        self._track_native_id(event.client_id, event.order_id)
        self._executions[key] = event

    def completedOrder(self, event: IBKRCompletedOrderV1) -> None:
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                self._completed_order(event)
            finally:
                self._callback_processed += 1

    def _completed_order(self, event: IBKRCompletedOrderV1) -> None:
        if type(event) is not IBKRCompletedOrderV1:
            self._fault("INVALID_CALLBACK")
        self._capture(event)
        if event.account_id != self._session.account_id:
            self._fault("ACCOUNT_MISMATCH")
        key = (event.client_id, event.order_id)
        previous = self._completed_orders.get(key)
        if previous is not None and previous != event:
            self._fault("COMPLETED_ORDER_CONFLICT")
        self._track_ref(event.order_ref, event.client_id, event.order_id, event.perm_id)
        self._track_native_id(event.client_id, event.order_id)
        self._completed_orders[key] = event

    def position(self, event: IBKRPositionV1) -> None:
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                self._position(event)
            finally:
                self._callback_processed += 1

    def _position(self, event: IBKRPositionV1) -> None:
        if type(event) is not IBKRPositionV1:
            self._fault("INVALID_CALLBACK")
        self._capture(event)
        if event.account_id != self._session.account_id:
            self._fault("ACCOUNT_MISMATCH")

    def error(self, event: IBKRErrorV1) -> None:
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                self._error(event)
            finally:
                self._callback_processed += 1

    def _error(self, event: IBKRErrorV1) -> None:
        if type(event) is not IBKRErrorV1:
            self._fault("INVALID_CALLBACK")
        self._capture(event)
        previous = self._errors.get(event.request_id)
        if previous is not None and previous != event.code:
            self._fault("BROKER_ERROR_CONFLICT")
        self._errors[event.request_id] = event.code

    def openOrderEnd(self) -> None:
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                if self._active_component in {"open", "all_open"}:
                    self._component_finished = True
            finally:
                self._callback_processed += 1

    def completedOrdersEnd(self) -> None:
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                if self._active_component == "completed":
                    self._component_finished = True
            finally:
                self._callback_processed += 1

    def positionEnd(self) -> None:
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                if self._active_component == "positions":
                    self._component_finished = True
            finally:
                self._callback_processed += 1

    def execDetailsEnd(self, request_id: int) -> None:
        self._note_callback_arrival()
        with self._dispatch_mutex:
            try:
                _positive_int(request_id)
                if (
                    self._active_component == "executions"
                    and request_id == self._next_request_id - 1
                ):
                    self._component_finished = True
            finally:
                self._callback_processed += 1

    def _run_component(self, component: str, call: Callable[[], None]) -> tuple[TwsCallback, ...]:
        self._require_session(for_read=True)
        self._active_component = component
        self._component_finished = False
        self._component_events = []
        try:
            call()
        except Exception:
            self._active_component = None
            self._blocked = True
            raise IBKRAdapterError("BROKER_OUTCOME_UNKNOWN") from None
        result = tuple(self._component_events)
        complete = self._component_finished
        self._active_component = None
        if (
            not complete
            or self._snapshot_cross_component
            or any(type(event) is IBKRErrorV1 for event in result)
        ):
            self._blocked = True
            raise IBKRAdapterError("BROKER_OUTCOME_UNKNOWN")
        return result

    def _collect_account_evidence(self) -> _AccountEvidence:
        if self._session.client_id not in {0, self._session.master_client_id}:
            self._fault("MASTER_CLIENT_REQUIRED")
        since = self._session.executions_since
        if since is None:
            raise IBKRAdapterError("EXECUTION_WINDOW_REQUIRED")
        self._collecting_account = True
        self._snapshot_cross_component = False
        try:
            open_events = self._run_component("all_open", self._transport.reqAllOpenOrders)
            completed_events = self._run_component(
                "completed", lambda: self._transport.reqCompletedOrders(False)
            )
            position_events = self._run_component("positions", self._transport.reqPositions)
            request_id = self._next_request_id
            self._next_request_id += 1
            execution_events = self._run_component(
                "executions",
                lambda: self._transport.reqExecutions(
                    request_id, self._session.account_id, None, since
                ),
            )
            if self._snapshot_cross_component:
                raise IBKRAdapterError("CROSS_COMPONENT_CALLBACK")
            collection_callback_sequence = self._callback_sequence
        finally:
            self._collecting_account = False
        self._sequence += 1
        evidence = _AccountEvidence(
            open_orders=tuple(item for item in open_events if type(item) is IBKROpenOrderV1),
            completed_orders=tuple(
                item for item in completed_events if type(item) is IBKRCompletedOrderV1
            ),
            positions=tuple(item for item in position_events if type(item) is IBKRPositionV1),
            executions=tuple(item for item in execution_events if type(item) is IBKRExecDetailsV1),
            executions_since=since,
            sequence=self._sequence,
            callback_sequence=collection_callback_sequence,
        )
        self._last_account_evidence = evidence
        return evidence

    def _observation(
        self,
        event: IBKROpenOrderV1 | IBKRCompletedOrderV1,
        status: OrderState,
        *,
        client_order_id: str | None = None,
        sequence: int,
    ) -> BrokerObservation:
        native_id = (event.client_id, event.order_id, event.perm_id)
        reference = client_order_id or self._client_ids_by_ref.get(event.order_ref)
        if reference is None:
            reference = f"native:{native_id[0]}:{native_id[1]}:{native_id[2]}"
        return BrokerObservation(
            observation_id=f"ibkr.{sequence}.{native_id[0]}.{native_id[1]}.{native_id[2]}",
            environment="paper",
            account_id=self._session.account_id,
            venue="IBKR_TWS",
            client_order_id=reference,
            status=status,
            observed_at=datetime.now(UTC),
            venue_order_id=str(event.perm_id),
            broker_sequence=sequence,
        )

    def _open_state(self, event: IBKROpenOrderV1) -> OrderState:
        if event.perm_id == 0 or event.status not in (_OPEN_STATUSES | {"PendingCancel"}):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        status = self._statuses.get((event.client_id, event.order_id))
        if status is not None and status.perm_id not in {0, event.perm_id}:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        if status is not None and status.status in {"Cancelled", "Filled", "Inactive"}:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        return (
            OrderState.PARTIALLY_FILLED
            if status is not None and status.filled > 0 and status.remaining > 0
            else OrderState.WORKING
        )

    def read_account_view(self, account_id: str) -> AccountViewV1:
        if type(account_id) is not str or account_id != self._session.account_id:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        try:
            evidence = self._collect_account_evidence()
            sealing_callback_sequence = evidence.callback_sequence
            if self._callback_sequence != sealing_callback_sequence:
                raise IBKRAdapterError("STALE_ACCOUNT_VIEW")
            unique_open = {
                (item.client_id, item.order_id, item.perm_id): item for item in evidence.open_orders
            }
            open_orders = tuple(
                self._observation(item, self._open_state(item), sequence=evidence.sequence)
                for _, item in sorted(unique_open.items())
            )
            by_con_id = {item.con_id: item.instrument_id for item in self._bindings.values()}
            positions: dict[str, Decimal] = {}
            for position_event in evidence.positions:
                instrument_id = by_con_id.get(position_event.con_id)
                if instrument_id is None or instrument_id in positions:
                    raise IBKRAdapterError("UNKNOWN_POSITION_MAPPING")
                positions[instrument_id] = position_event.quantity
            native_executions: dict[str, IBKRExecDetailsV1] = {}
            issued_executions: dict[str, ExecutionV1] = {}
            for execution_event in evidence.executions:
                prior = native_executions.get(execution_event.execution_id)
                if prior is not None and prior != execution_event:
                    raise IBKRAdapterError("EXECUTION_CONFLICT")
                side = execution_event.side
                executed_at = execution_event.executed_at
                if (
                    execution_event.perm_id == 0
                    or side is None
                    or executed_at is None
                    or executed_at < evidence.executions_since
                    or execution_event.con_id not in by_con_id
                ):
                    raise IBKRAdapterError("INCOMPLETE_EXECUTION")
                native_executions[execution_event.execution_id] = execution_event
                issued_executions[execution_event.execution_id] = _issue_execution(
                    execution_event.execution_id,
                    str(execution_event.perm_id),
                    self._client_ids_by_ref.get(execution_event.order_ref),
                    by_con_id[execution_event.con_id],
                    "BUY" if side == "BOT" else "SELL",
                    execution_event.quantity,
                    execution_event.price,
                    executed_at,
                )
            executions = tuple(item for _, item in sorted(issued_executions.items()))
            result = _issue_account_view(
                account_id,
                open_orders,
                tuple(sorted(positions.items())),
                evidence.sequence,
                executions,
                evidence.executions_since,
                complete=True,
            )
            result.assert_sealed()
            if self._callback_sequence != sealing_callback_sequence:
                raise IBKRAdapterError("STALE_ACCOUNT_VIEW")
            with self._callback_arrival_mutex:
                if (
                    self._callback_sequence != sealing_callback_sequence
                    or self._callback_arrivals != self._callback_processed
                ):
                    raise IBKRAdapterError("STALE_ACCOUNT_VIEW")
                self._last_view_callback_sequence = sealing_callback_sequence
                self._last_view_revision = evidence.sequence
            self._blocked = False
            return result
        except (IBKRAdapterError, BrokerPortError, ValueError):
            self._blocked = True
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW) from None

    def _find_order_evidence(
        self, order: OrderSnapshot, evidence: _AccountEvidence
    ) -> tuple[IBKROpenOrderV1 | IBKRCompletedOrderV1, OrderState]:
        binding = self._bindings[order.request.native_contract_id]
        reference = map_order_request(order.request, binding)[1].order_ref
        matching_open = [item for item in evidence.open_orders if item.order_ref == reference]
        matching_completed = [
            item for item in evidence.completed_orders if item.order_ref == reference
        ]
        if not matching_open and not matching_completed and order.venue_order_id is not None:
            matching_open = [
                item for item in evidence.open_orders if str(item.perm_id) == order.venue_order_id
            ]
            matching_completed = [
                item
                for item in evidence.completed_orders
                if str(item.perm_id) == order.venue_order_id
            ]
        if (
            len(
                {
                    (item.client_id, item.order_id, item.perm_id)
                    for item in matching_open + matching_completed
                }
            )
            != 1
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        if matching_open:
            item = matching_open[-1]
            if item.con_id != binding.con_id or (
                order.venue_order_id is not None and str(item.perm_id) != order.venue_order_id
            ):
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
            return item, self._open_state(item)
        completed_item = matching_completed[-1]
        if (
            completed_item.perm_id == 0
            or completed_item.con_id != binding.con_id
            or (
                order.venue_order_id is not None
                and str(completed_item.perm_id) != order.venue_order_id
            )
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        if completed_item.status == "Inactive":
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        return (
            completed_item,
            OrderState.FILLED if completed_item.status == "Filled" else OrderState.CANCELED,
        )

    def read_order(self, order: OrderSnapshot) -> BrokerObservation | None:
        if (
            type(order) is not OrderSnapshot
            or order.request.account_id != self._session.account_id
            or order.request.environment != "paper"
            or order.request.venue != "IBKR_TWS"
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        try:
            evidence = self._collect_account_evidence()
            item, status = self._find_order_evidence(order, evidence)
            return self._observation(
                item,
                status,
                client_order_id=order.request.client_order_id,
                sequence=evidence.sequence,
            )
        except (IBKRAdapterError, KeyError, ValueError):
            self._blocked = True
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER) from None

    def submit(
        self, request: OrderRequest, permit: DispatchPermitV1, expected_revision: int
    ) -> SubmitResultV1:
        with self._dispatch_mutex:
            return self._submit_locked(request, permit, expected_revision)

    def _submit_locked(
        self, request: OrderRequest, permit: DispatchPermitV1, expected_revision: int
    ) -> SubmitResultV1:
        if type(request) is not OrderRequest:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        if request.account_id != self._session.account_id:
            raise BrokerRejected(BrokerRejectionCode.ACCOUNT_MISMATCH)
        if request.environment != "paper" or request.venue != "IBKR_TWS":
            raise BrokerRejected(BrokerRejectionCode.ENVIRONMENT_MISMATCH)
        try:
            parse_int(
                expected_revision, field="expected_revision", min_value=0, max_value=2**63 - 1
            )
        except NumericError:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER) from None
        try:
            self._require_session()
        except IBKRAdapterError:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
        evidence = self._last_account_evidence
        view_callback_sequence = self._callback_sequence
        with self._callback_arrival_mutex:
            view_arrival_sequence = self._callback_arrivals
            pending_callback = self._callback_arrivals != self._callback_processed
        if (
            evidence is None
            or expected_revision != evidence.sequence
            or expected_revision != self._last_view_revision
            or self._last_view_callback_sequence != view_callback_sequence
            or pending_callback
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        binding = self._bindings.get(request.native_contract_id)
        if binding is None:
            raise BrokerRejected(BrokerRejectionCode.UNSUPPORTED_INSTRUMENT)
        if request.client_order_id is None:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        try:
            contract, native_order = map_order_request(request, binding)
        except IBKRAdapterError:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER) from None
        if (
            native_order.order_ref in self._attempted_refs
            or native_order.order_ref in self._order_refs
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        if not callable(getattr(permit, "consume", None)) or not isinstance(
            getattr(permit, "order_id", None), str
        ):
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        # Callback handlers use the same reentrant mutex. A callback invoked by
        # consume can run, but its sequence change aborts before placeOrder.
        permit.consume(permit.order_id, request.digest, expected_revision)
        order_id = self._next_order_id
        if order_id is None:
            self._blocked = True
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        known_order_ids = [
            native_order_id
            for client_id, native_order_id in (
                *self._open_orders,
                *self._completed_orders,
                *self._statuses,
            )
            if client_id == self._session.client_id
        ]
        order_id = max(order_id, self._highest_seen_order_id + 1, *(i + 1 for i in known_order_ids))
        if order_id > _MAX_ORDER_ID:
            self._next_order_id = None
            self._blocked = True
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        self._highest_seen_order_id = order_id
        self._next_order_id = order_id + 1 if order_id < _MAX_ORDER_ID else None
        with self._callback_arrival_mutex:
            if (
                self._callback_sequence != view_callback_sequence
                or self._callback_arrivals != view_arrival_sequence
                or self._callback_arrivals != self._callback_processed
                or self._blocked
            ):
                self._blocked = True
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
            self._attempted_refs.add(native_order.order_ref)
            self._client_ids_by_ref[native_order.order_ref] = request.client_order_id
            try:
                self._transport.placeOrder(order_id, contract, native_order)
            except Exception:
                self._blocked = True
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
        native_error = self._errors.get(order_id)
        matches = [
            item
            for item in self._open_orders.values()
            if item.client_id == self._session.client_id
            and item.order_id == order_id
            and item.order_ref == native_order.order_ref
            and item.account_id == self._session.account_id
            and item.con_id == contract.con_id
            and item.perm_id > 0
            and item.status in _OPEN_STATUSES
        ]
        if native_error == 201 and not matches:
            result = _issue_submit_result(
                None, OrderState.REJECTED, BrokerRejectionCode.VENUE_REJECTED
            )
            result.assert_sealed()
            return result
        if native_error is not None or len(matches) != 1:
            self._blocked = True
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        result = _issue_submit_result(str(matches[0].perm_id), OrderState.WORKING)
        result.assert_sealed()
        return result

    def cancel(self, order: OrderSnapshot) -> CancelResultV1:
        if type(order) is not OrderSnapshot or order.request.account_id != self._session.account_id:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        try:
            self._require_session()
        except IBKRAdapterError:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL) from None
        try:
            binding = self._bindings[order.request.native_contract_id]
            reference = map_order_request(order.request, binding)[1].order_ref
        except (IBKRAdapterError, KeyError):
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER) from None
        if reference in self._cancel_attempted_refs:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        native = self._order_refs.get(reference)
        if native is None or native[0] != self._session.client_id or native[1] <= 0:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        tracked_open = self._open_orders.get((native[0], native[1]))
        if (
            native[2] <= 0
            or order.venue_order_id != str(native[2])
            or tracked_open is None
            or tracked_open.account_id != self._session.account_id
            or tracked_open.con_id != binding.con_id
            or tracked_open.perm_id != native[2]
        ):
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        self._cancel_attempted_refs.add(reference)
        self._active_component = "cancel"
        self._component_events = []
        try:
            self._transport.cancelOrder(native[1])
        except Exception:
            self._blocked = True
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL) from None
        finally:
            self._active_component = None
        callbacks = tuple(self._component_events)
        if native[1] in self._errors or any(type(event) is IBKRErrorV1 for event in callbacks):
            self._blocked = True
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        matching = tuple(
            event
            for event in callbacks
            if (
                isinstance(event, (IBKROrderStatusV1, IBKRCompletedOrderV1))
                and event.client_id == native[0]
                and event.order_id == native[1]
                and event.perm_id in {0, native[2]}
            )
        )
        terminal_seen = False
        contradictory = False
        for event in matching:
            if terminal_seen and event.status != "Cancelled":
                contradictory = True
            if event.status == "Cancelled":
                terminal_seen = True
        if contradictory:
            self._blocked = True
            self._hard_block = True
            if "CANCEL_CALLBACK_CONFLICT" not in self._discrepancies:
                self._discrepancies.append("CANCEL_CALLBACK_CONFLICT")
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        if not matching or any(event.status in {"Filled", "Inactive"} for event in matching):
            self._blocked = True
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        confirmed = any(event.status == "Cancelled" for event in matching)
        result = _issue_cancel_result(confirmed)
        result.assert_sealed()
        return result
