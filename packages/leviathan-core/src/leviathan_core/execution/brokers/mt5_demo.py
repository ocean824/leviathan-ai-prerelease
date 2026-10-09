"""Fake-only FOREX.com/MT5 demo session and broker adapter.

This module does not import MetaTrader5, open a socket, resolve a credential,
or submit to a real terminal. A later, separately reviewed activation adapter
must replace the exact-type fake transport gate.
"""

from __future__ import annotations

import hashlib
import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from threading import RLock
from typing import Literal

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerOutcomeUnknown,
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
from leviathan_core.execution.brokers.mt5_mapping import (
    MT5AdapterError,
    MT5CorrelationV1,
    MT5SymbolSpecV1,
    _decimal,
    _FrozenRecord,
    _identity,
    encode_correlation,
    minimum_stop_distance,
    to_native_price,
    to_native_volume,
)
from leviathan_core.execution.order_models import (
    BrokerObservation,
    OrderRequest,
    OrderSnapshot,
    OrderState,
)
from leviathan_core.numeric import (
    NumericError,
    canonical_json,
    exact_add,
    exact_sub,
    parse_decimal,
    parse_int,
)

_CREDENTIAL_REF = re.compile(
    r"vault://leviathan-ai/development/forexcom/[A-Z][A-Z0-9_]{0,63}\Z",
    re.ASCII,
)
_SESSION_PROTOCOL = "FAKE_MT5_EA"
_PROTOCOL_VERSION = "1"
_MAX_SKEW_MS = 250


def _ns(value: object, *, code: str = "INVALID_SESSION_BINDING") -> int:
    try:
        return parse_int(value, field="time_ns", min_value=0, max_value=(1 << 63) - 1)
    except NumericError:
        raise MT5AdapterError(code) from None


def _bool(value: object, code: str) -> bool:
    if type(value) is not bool:
        raise MT5AdapterError(code)
    return value


@dataclass(slots=True)
class MT5SessionBindingV1(_FrozenRecord):
    """Nonsecret operator-reviewed identity and freshness policy for fake DEMO."""

    project_id: str
    environment: str
    provider: str
    mode: str
    server: str
    account_id: str
    terminal_agent_id: str
    protocol: str
    protocol_version: str
    mapping_revision: str
    broker_timezone: str
    calendar_id: str
    trade_allowed: bool
    max_heartbeat_age_ns: int
    max_quote_age_ns: int
    credential_ref: str | None = None

    def __post_init__(self) -> None:
        if (
            self.project_id != "leviathan-ai"
            or self.environment != "development"
            or self.provider != "FOREX.com"
            or self.mode != "DEMO"
            or self.protocol != _SESSION_PROTOCOL
            or self.protocol_version != _PROTOCOL_VERSION
            or self.trade_allowed is not True
        ):
            raise MT5AdapterError("INVALID_SESSION_BINDING")
        for name in (
            "server",
            "account_id",
            "terminal_agent_id",
            "mapping_revision",
            "broker_timezone",
            "calendar_id",
        ):
            _identity(getattr(self, name))
        if self.credential_ref is not None and (
            type(self.credential_ref) is not str
            or _CREDENTIAL_REF.fullmatch(self.credential_ref) is None
        ):
            raise MT5AdapterError("INVALID_SESSION_BINDING")
        try:
            parse_int(
                self.max_heartbeat_age_ns,
                field="max_heartbeat_age_ns",
                min_value=1,
                max_value=30_000_000_000,
            )
            parse_int(
                self.max_quote_age_ns,
                field="max_quote_age_ns",
                min_value=1,
                max_value=5_000_000_000,
            )
        except NumericError:
            raise MT5AdapterError("INVALID_SESSION_BINDING") from None
        self._freeze()


@dataclass(slots=True)
class MT5QuoteV1(_FrozenRecord):
    native_symbol: str
    bid: Decimal
    ask: Decimal
    observed_ns: int

    def __post_init__(self) -> None:
        _identity(self.native_symbol, symbol=True)
        object.__setattr__(self, "bid", _decimal(self.bid, "INVALID_PRICE"))
        object.__setattr__(self, "ask", _decimal(self.ask, "INVALID_PRICE"))
        if self.bid > self.ask:
            raise MT5AdapterError("INVALID_PRICE")
        _ns(self.observed_ns)
        self._freeze()


@dataclass(slots=True)
class MT5TerminalSnapshotV1(_FrozenRecord):
    server: str
    account_id: str
    mode: str
    terminal_agent_id: str
    protocol: str
    protocol_version: str
    mapping_revision: str
    broker_timezone: str
    calendar_id: str
    connected: bool
    trade_allowed: bool
    heartbeat_at_ns: int | None
    broker_clock_skew_ms: int | None
    session_open: bool | None
    news_blackout: bool | None
    margin_confirmed: bool | None
    calendar_ambiguous: bool | None
    quote: MT5QuoteV1 | None
    broker_revision: int

    def __post_init__(self) -> None:
        for name in (
            "server",
            "account_id",
            "terminal_agent_id",
            "mapping_revision",
            "broker_timezone",
            "calendar_id",
        ):
            _identity(getattr(self, name))
        if type(self.mode) is not str or self.mode not in {"DEMO", "LIVE"}:
            raise MT5AdapterError("INVALID_SESSION_BINDING")
        if self.protocol != _SESSION_PROTOCOL or self.protocol_version != _PROTOCOL_VERSION:
            raise MT5AdapterError("INVALID_SESSION_BINDING")
        for name in ("connected", "trade_allowed"):
            _bool(getattr(self, name), "INVALID_SESSION_BINDING")
        for name in ("session_open", "news_blackout", "margin_confirmed", "calendar_ambiguous"):
            value = getattr(self, name)
            if value is not None:
                _bool(value, "INVALID_SESSION_BINDING")
        if self.heartbeat_at_ns is not None:
            _ns(self.heartbeat_at_ns)
        if self.broker_clock_skew_ms is not None:
            try:
                parse_int(
                    self.broker_clock_skew_ms,
                    field="broker_clock_skew_ms",
                    min_value=-1_000_000,
                    max_value=1_000_000,
                )
            except NumericError:
                raise MT5AdapterError("INVALID_SESSION_BINDING") from None
        if self.quote is not None and type(self.quote) is not MT5QuoteV1:
            raise MT5AdapterError("INVALID_SESSION_BINDING")
        _ns(self.broker_revision)
        self._freeze()


@dataclass(slots=True)
class MT5NativeSubmitV1(_FrozenRecord):
    server: str
    account_id: str
    native_symbol: str
    side: str
    volume_lots: Decimal
    order_type: str
    time_in_force: str
    price: Decimal | None
    expires_at_ns: int | None
    comment: str
    magic: int
    expected_revision: int

    def __post_init__(self) -> None:
        _identity(self.server)
        _identity(self.account_id)
        _identity(self.native_symbol, symbol=True)
        if (
            type(self.side) is not str
            or self.side not in {"BUY", "SELL"}
            or type(self.order_type) is not str
            or self.order_type not in {"MARKET", "LIMIT"}
        ):
            raise MT5AdapterError("UNSUPPORTED_ORDER")
        if type(self.time_in_force) is not str or self.time_in_force not in {"DAY", "GTC", "GTD"}:
            raise MT5AdapterError("UNSUPPORTED_TIF")
        object.__setattr__(self, "volume_lots", _decimal(self.volume_lots, "INVALID_LOT"))
        if self.price is not None:
            object.__setattr__(self, "price", _decimal(self.price, "INVALID_PRICE"))
        if (self.order_type == "LIMIT") != (self.price is not None):
            raise MT5AdapterError("INVALID_PRICE")
        if (self.time_in_force == "GTD") != (self.expires_at_ns is not None):
            raise MT5AdapterError("UNSUPPORTED_TIF")
        if self.expires_at_ns is not None:
            _ns(self.expires_at_ns)
        MT5CorrelationV1(self.comment, self.magic)
        _ns(self.expected_revision)
        self._freeze()


@dataclass(slots=True)
class MT5NativeSubmitAckV1(_FrozenRecord):
    state: Literal["ACCEPTED", "REJECTED"]
    native_order_id: str | None

    def __post_init__(self) -> None:
        if type(self.state) is not str or self.state not in {"ACCEPTED", "REJECTED"}:
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        if self.state == "ACCEPTED":
            _identity(self.native_order_id)
        elif self.native_order_id is not None:
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        self._freeze()


@dataclass(slots=True)
class MT5NativeCancelAckV1(_FrozenRecord):
    confirmed: bool

    def __post_init__(self) -> None:
        _bool(self.confirmed, "NATIVE_EVENT_INVALID")
        self._freeze()


@dataclass(slots=True)
class MT5NativeEventV1(_FrozenRecord):
    """Fake EA observation; quantity is exact instrument units, not MT5 lots.

    Order/deal/position identities are disjoint even if ticket strings coincide.
    A later real transport must normalize reported lots with the reviewed map.
    """

    kind: Literal["ORDER", "DEAL", "POSITION"]
    native_id: str
    version: int
    server: str
    account_id: str
    comment: str
    magic: int
    related_order_id: str | None
    related_position_id: str | None
    quantity: Decimal
    price: Decimal | None
    occurred_at_ns: int
    state: str
    instrument_id: str | None = None
    side: str | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in {"ORDER", "DEAL", "POSITION"}:
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        for name in ("native_id", "server", "account_id", "state"):
            _identity(getattr(self, name))
        for name in ("related_order_id", "related_position_id"):
            value = getattr(self, name)
            if value is not None:
                _identity(value)
        MT5CorrelationV1(self.comment, self.magic)
        try:
            parse_int(self.version, field="version", min_value=0, max_value=(1 << 63) - 1)
        except NumericError:
            raise MT5AdapterError("NATIVE_EVENT_INVALID") from None
        object.__setattr__(
            self,
            "quantity",
            _decimal(self.quantity, "NATIVE_EVENT_INVALID", positive=False),
        )
        if self.price is not None:
            object.__setattr__(self, "price", _decimal(self.price, "NATIVE_EVENT_INVALID"))
        _ns(self.occurred_at_ns, code="NATIVE_EVENT_INVALID")
        if self.instrument_id is not None:
            _identity(self.instrument_id)
        if self.side is not None and (
            type(self.side) is not str or self.side not in {"BUY", "SELL"}
        ):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        if self.kind == "DEAL" and (
            self.related_order_id is None
            or self.instrument_id is None
            or self.side is None
            or self.quantity <= 0
            or self.price is None
            or self.occurred_at_ns % 1_000 != 0
        ):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        self._freeze()


@dataclass(slots=True)
class MT5NativeAccountViewV1(_FrozenRecord):
    """Exact-account fake snapshot; positions are exact instrument units."""

    server: str
    account_id: str
    mode: str
    open_orders: tuple[BrokerObservation, ...]
    deals: tuple[MT5NativeEventV1, ...]
    positions: tuple[tuple[str, Decimal], ...]
    broker_revision: int
    observed_ns: int
    orders_complete: bool
    deals_complete: bool
    positions_complete: bool
    executions_since: datetime

    def __post_init__(self) -> None:
        _identity(self.server)
        _identity(self.account_id)
        if type(self.mode) is not str or self.mode not in {"DEMO", "LIVE"}:
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        if type(self.open_orders) is not tuple or any(
            type(item) is not BrokerObservation
            or item.account_id != self.account_id
            or item.environment != "demo"
            or item.venue != "MT5"
            or type(item.status) is not OrderState
            or item.status not in {OrderState.WORKING, OrderState.PARTIALLY_FILLED}
            for item in self.open_orders
        ):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        if type(self.deals) is not tuple or any(
            type(item) is not MT5NativeEventV1
            or item.kind != "DEAL"
            or item.account_id != self.account_id
            or item.server != self.server
            for item in self.deals
        ):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        if len({item.native_id for item in self.deals}) != len(self.deals):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        if type(self.positions) is not tuple:
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        checked_positions: list[tuple[str, Decimal]] = []
        for pair in self.positions:
            if type(pair) is not tuple or len(pair) != 2:
                raise MT5AdapterError("NATIVE_EVENT_INVALID")
            instrument_id, quantity = pair
            _identity(instrument_id)
            try:
                checked_positions.append(
                    (instrument_id, parse_decimal(quantity, field="position_quantity"))
                )
            except NumericError:
                raise MT5AdapterError("NATIVE_EVENT_INVALID") from None
        names = [item[0] for item in checked_positions]
        if names != sorted(set(names)):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        object.__setattr__(self, "positions", tuple(checked_positions))
        _ns(self.broker_revision, code="NATIVE_EVENT_INVALID")
        _ns(self.observed_ns, code="NATIVE_EVENT_INVALID")
        for name in ("orders_complete", "deals_complete", "positions_complete"):
            _bool(getattr(self, name), "NATIVE_EVENT_INVALID")
        since = self.executions_since
        if type(since) is not datetime or since.tzinfo is None:
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        try:
            since = since.astimezone(UTC)
            since_ns = _datetime_ns(since)
        except Exception:
            raise MT5AdapterError("NATIVE_EVENT_INVALID") from None
        if since_ns > self.observed_ns or any(
            item.occurred_at_ns < since_ns or item.occurred_at_ns > self.observed_ns
            for item in self.deals
        ):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        object.__setattr__(self, "executions_since", since)
        self._freeze()


@dataclass(slots=True)
class MT5CallbackDecisionV1(_FrozenRecord):
    applied: bool
    late_gtd: bool
    operator_alert_code: str | None

    def __post_init__(self) -> None:
        _bool(self.applied, "NATIVE_EVENT_INVALID")
        _bool(self.late_gtd, "NATIVE_EVENT_INVALID")
        if self.operator_alert_code is not None and (
            type(self.operator_alert_code) is not str
            or self.operator_alert_code not in {"LATE_GTD", "RECONCILE_REQUIRED"}
        ):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        self._freeze()

    @property
    def discrepancy_code(self) -> str | None:
        return "LATE_GTD" if self.late_gtd else None


class FakeMT5Transport:
    """Scripted in-memory terminal; construction/restart never sends orders."""

    def __init__(self, snapshot: MT5TerminalSnapshotV1) -> None:
        if type(snapshot) is not MT5TerminalSnapshotV1:
            raise MT5AdapterError("INVALID_SESSION_BINDING")
        self._snapshot = snapshot
        self._submits: deque[MT5NativeSubmitAckV1 | Exception] = deque()
        self._cancels: deque[MT5NativeCancelAckV1 | Exception] = deque()
        self._reads: deque[BrokerObservation | None | Exception] = deque()
        self._views: deque[MT5NativeAccountViewV1 | Exception] = deque()
        self.submit_calls: list[MT5NativeSubmitV1] = []
        self.cancel_calls: list[str] = []
        self.read_calls = 0
        self.view_calls = 0
        self.snapshot_calls = 0

    def restart(self, snapshot: MT5TerminalSnapshotV1) -> None:
        if type(snapshot) is not MT5TerminalSnapshotV1:
            raise MT5AdapterError("INVALID_SESSION_BINDING")
        self._snapshot = snapshot

    def read_snapshot(self) -> MT5TerminalSnapshotV1:
        self.snapshot_calls += 1
        return self._snapshot

    def queue_submit(self, outcome: MT5NativeSubmitAckV1 | Exception) -> None:
        if not isinstance(outcome, (MT5NativeSubmitAckV1, Exception)):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        self._submits.append(outcome)

    def queue_cancel(self, outcome: MT5NativeCancelAckV1 | Exception) -> None:
        if not isinstance(outcome, (MT5NativeCancelAckV1, Exception)):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        self._cancels.append(outcome)

    def queue_read(self, outcome: BrokerObservation | None | Exception) -> None:
        if outcome is not None and not isinstance(outcome, (BrokerObservation, Exception)):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        self._reads.append(outcome)

    def queue_account_view(self, outcome: MT5NativeAccountViewV1 | Exception) -> None:
        if not isinstance(outcome, (MT5NativeAccountViewV1, Exception)):
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        self._views.append(outcome)

    def submit_native(self, request: MT5NativeSubmitV1) -> MT5NativeSubmitAckV1:
        self.submit_calls.append(request)
        if not self._submits:
            raise TimeoutError("FAKE_MT5_UNSCRIPTED")
        outcome = self._submits.popleft()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def cancel_native(self, native_order_id: str) -> MT5NativeCancelAckV1:
        self.cancel_calls.append(native_order_id)
        if not self._cancels:
            raise TimeoutError("FAKE_MT5_UNSCRIPTED")
        outcome = self._cancels.popleft()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def read_native_order(
        self, account_id: str, comment: str, magic: int
    ) -> BrokerObservation | None:
        self.read_calls += 1
        if not self._reads:
            raise TimeoutError("FAKE_MT5_UNSCRIPTED")
        outcome = self._reads.popleft()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def read_native_account_view(self, account_id: str) -> MT5NativeAccountViewV1:
        self.view_calls += 1
        if not self._views:
            raise TimeoutError("FAKE_MT5_UNSCRIPTED")
        outcome = self._views.popleft()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@dataclass(frozen=True, slots=True)
class _OMSEvidenceEntry:
    account_id: str
    client_order_id: str
    oms_order_id: str
    intent_idempotency_key: str
    attempt: int
    instrument_id: str
    side: str
    quantity: Decimal
    attempted_at_ns: int
    expires_at_ns: int | None = None
    native_order_id: str | None = None


class FakeMT5OMSEvidence:
    """Fake durable OMS attempt memory shared across adapter instances.

    This object is independent of an adapter's local caches. A real bridge
    must obtain the equivalent ticket mapping from durable OMS evidence.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._entries: dict[tuple[str, str], _OMSEvidenceEntry] = {}
        self._cancel_attempts: dict[tuple[str, str], str] = {}

    def lookup(self, account_id: str, client_order_id: str) -> _OMSEvidenceEntry | None:
        _identity(account_id)
        _identity(client_order_id)
        with self._lock:
            return self._entries.get((account_id, client_order_id))

    def owner_of_native(self, account_id: str, native_order_id: str) -> _OMSEvidenceEntry | None:
        _identity(account_id)
        _identity(native_order_id)
        with self._lock:
            matches = tuple(
                entry
                for entry in self._entries.values()
                if entry.account_id == account_id and entry.native_order_id == native_order_id
            )
        if len(matches) > 1:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        return matches[0] if matches else None

    def owner_of_correlation(
        self, account_id: str, comment: str, magic: int
    ) -> _OMSEvidenceEntry | None:
        """Recover an exact pair from reserved OMS clients after restart."""
        _identity(account_id)
        observed = MT5CorrelationV1(comment, magic)
        with self._lock:
            candidates = tuple(
                (entry, encode_correlation(account_id, entry.client_order_id))
                for entry in self._entries.values()
                if entry.account_id == account_id
            )
        exact = tuple(entry for entry, pair in candidates if pair == observed)
        partial = any(
            (pair.comment == comment or pair.magic == magic) and pair != observed
            for _, pair in candidates
        )
        if len(exact) > 1 or partial:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        return exact[0] if exact else None

    def reserve(self, request: OrderRequest, oms_order_id: str, attempted_at_ns: int) -> None:
        if type(request) is not OrderRequest or type(request.client_order_id) is not str:
            raise MT5AdapterError("INVALID_IDENTITY")
        _identity(oms_order_id)
        attempted = _ns(attempted_at_ns)
        expiry = (
            _datetime_ns(request.expires_at)
            if request.time_in_force == "GTD" and request.expires_at is not None
            else None
        )
        key = (request.account_id, request.client_order_id)
        with self._lock:
            if key in self._entries or any(
                entry.account_id == request.account_id
                and entry.intent_idempotency_key == request.intent_idempotency_key
                and entry.attempt == request.attempt
                for entry in self._entries.values()
            ):
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
            self._entries[key] = _OMSEvidenceEntry(
                request.account_id,
                request.client_order_id,
                oms_order_id,
                request.intent_idempotency_key,
                request.attempt,
                request.instrument_id,
                request.side,
                request.quantity,
                attempted,
                expiry,
            )

    def bind_native(self, account_id: str, client_order_id: str, native_order_id: str) -> None:
        _identity(account_id)
        _identity(client_order_id)
        _identity(native_order_id)
        key = (account_id, client_order_id)
        with self._lock:
            entry = self._entries.get(key)
            if (
                entry is None
                or (entry.native_order_id is not None and entry.native_order_id != native_order_id)
                or any(
                    other.account_id == account_id
                    and other.client_order_id != client_order_id
                    and other.native_order_id == native_order_id
                    for other in self._entries.values()
                )
            ):
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
            self._entries[key] = replace(entry, native_order_id=native_order_id)

    def reserve_cancel(self, order: OrderSnapshot) -> None:
        """Remember one cancel before fake transport, including across restarts."""
        if type(order) is not OrderSnapshot or order.venue_order_id is None:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        request = order.request
        if type(request.client_order_id) is not str:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        key = (request.account_id, order.order_id)
        with self._lock:
            entry = self._entries.get((request.account_id, request.client_order_id))
            if (
                key in self._cancel_attempts
                or any(
                    account == request.account_id and ticket == order.venue_order_id
                    for (account, _), ticket in self._cancel_attempts.items()
                )
                or (
                    entry is not None
                    and (
                        entry.oms_order_id != order.order_id
                        or entry.native_order_id != order.venue_order_id
                    )
                )
            ):
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
            self._cancel_attempts[key] = order.venue_order_id


def _binding_digest(binding: MT5SessionBindingV1) -> str:
    payload = {field.name: getattr(binding, field.name) for field in fields(binding)}
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _symbol_digest(spec: MT5SymbolSpecV1) -> str:
    payload = {field.name: getattr(spec, field.name) for field in fields(spec)}
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _datetime_ns(value: datetime) -> int:
    if type(value) is not datetime or value.tzinfo is None:
        raise MT5AdapterError("UNSUPPORTED_TIF")
    try:
        delta = value.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    except Exception:
        raise MT5AdapterError("UNSUPPORTED_TIF") from None
    result = ((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1_000
    return _ns(result, code="UNSUPPORTED_TIF")


def _event_datetime(event: MT5NativeEventV1) -> datetime:
    """Convert a validated microsecond-aligned native timestamp exactly."""
    return datetime.fromtimestamp(event.occurred_at_ns // 1_000_000_000, UTC).replace(
        microsecond=(event.occurred_at_ns // 1_000) % 1_000_000
    )


def _issue_deal_execution(deal: MT5NativeEventV1, client_order_id: str | None) -> ExecutionV1:
    """Issue a port execution only from a complete, checked DEAL record."""
    if (
        deal.kind != "DEAL"
        or deal.related_order_id is None
        or deal.instrument_id is None
        or deal.side is None
        or deal.price is None
    ):
        raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
    return _issue_execution(
        deal.native_id,
        deal.related_order_id,
        client_order_id,
        deal.instrument_id,
        deal.side,
        deal.quantity,
        deal.price,
        _event_datetime(deal),
    )


def _validate_terminal(
    binding: MT5SessionBindingV1,
    snapshot: MT5TerminalSnapshotV1,
    *,
    now_ns: int,
    native_symbol: str,
) -> MT5QuoteV1:
    """Fail closed on any unverified DEMO session, clock or market gate."""
    if type(binding) is not MT5SessionBindingV1 or type(snapshot) is not MT5TerminalSnapshotV1:
        raise MT5AdapterError("INVALID_SESSION_BINDING")
    now = _ns(now_ns)
    if (
        snapshot.server != binding.server
        or snapshot.account_id != binding.account_id
        or snapshot.mode != "DEMO"
        or snapshot.terminal_agent_id != binding.terminal_agent_id
        or snapshot.protocol != binding.protocol
        or snapshot.protocol_version != binding.protocol_version
        or snapshot.mapping_revision != binding.mapping_revision
        or snapshot.broker_timezone != binding.broker_timezone
        or snapshot.calendar_id != binding.calendar_id
    ):
        raise MT5AdapterError("SESSION_MISMATCH")
    if not snapshot.connected or not snapshot.trade_allowed or not binding.trade_allowed:
        raise MT5AdapterError("SESSION_UNAVAILABLE")
    at = snapshot.heartbeat_at_ns
    if at is None or at > now or now - at > binding.max_heartbeat_age_ns:
        raise MT5AdapterError("SESSION_UNAVAILABLE")
    skew = snapshot.broker_clock_skew_ms
    if skew is None or abs(skew) >= _MAX_SKEW_MS:
        raise MT5AdapterError("CLOCK_SKEW_DENIED")
    if snapshot.calendar_ambiguous is not False or snapshot.session_open is not True:
        raise MT5AdapterError("SESSION_CLOSED")
    if snapshot.news_blackout is not False:
        raise MT5AdapterError("NEWS_BLACKOUT")
    if snapshot.margin_confirmed is not True:
        raise MT5AdapterError("MARGIN_UNCONFIRMED")
    quote = snapshot.quote
    if (
        quote is None
        or quote.native_symbol != native_symbol
        or quote.observed_ns > now
        or now - quote.observed_ns > binding.max_quote_age_ns
    ):
        raise MT5AdapterError("QUOTE_STALE")
    return quote


def build_native_submit(
    request: OrderRequest,
    binding: MT5SessionBindingV1,
    snapshot: MT5TerminalSnapshotV1,
    spec: MT5SymbolSpecV1,
    *,
    now_ns: int,
    expected_revision: int,
) -> MT5NativeSubmitV1:
    """Translate a validated OMS request; this pure helper performs no I/O."""
    if (
        type(request) is not OrderRequest
        or type(binding) is not MT5SessionBindingV1
        or type(snapshot) is not MT5TerminalSnapshotV1
        or type(spec) is not MT5SymbolSpecV1
    ):
        raise MT5AdapterError("UNSUPPORTED_ORDER")
    try:
        binding = replace(binding)
        spec = replace(spec)
        snapshot = replace(
            snapshot,
            quote=replace(snapshot.quote) if snapshot.quote is not None else None,
        )
    except Exception:
        raise MT5AdapterError("INVALID_SESSION_BINDING") from None
    if (
        request.project_id != "leviathan-ai"
        or request.environment != "demo"
        or request.account_id != binding.account_id
        or request.venue != "MT5"
        or type(request.client_order_id) is not str
    ):
        raise MT5AdapterError("SESSION_MISMATCH")
    if (
        request.instrument_id != spec.instrument_id
        or request.native_contract_id != spec.native_contract_id
    ):
        raise MT5AdapterError("UNSUPPORTED_SYMBOL")
    if spec.revision != binding.mapping_revision:
        raise MT5AdapterError("MAPPING_REVISION_MISMATCH")
    if request.order_type not in {"MARKET", "LIMIT"}:
        raise MT5AdapterError("UNSUPPORTED_ORDER")
    if request.time_in_force not in {"DAY", "GTC", "GTD"}:
        raise MT5AdapterError("UNSUPPORTED_TIF")
    _ns(expected_revision)
    quote = _validate_terminal(binding, snapshot, now_ns=now_ns, native_symbol=spec.native_symbol)
    to_native_price(quote.bid, spec)
    to_native_price(quote.ask, spec)
    volume_lots = to_native_volume(request.quantity, spec)
    if request.order_type == "LIMIT":
        if request.limit_price is None:
            raise MT5AdapterError("INVALID_PRICE")
        price = to_native_price(request.limit_price, spec)
        try:
            minimum = minimum_stop_distance(spec)
            if request.side == "BUY":
                allowed_price = exact_sub(quote.ask, minimum)
                valid = price <= allowed_price
            else:
                allowed_price = exact_add(quote.bid, minimum)
                valid = price >= allowed_price
        except NumericError:
            raise MT5AdapterError("STOP_DISTANCE_DENIED") from None
        if not valid:
            raise MT5AdapterError("STOP_DISTANCE_DENIED")
    else:
        price = None
    expiry = _datetime_ns(request.expires_at) if request.expires_at is not None else None
    if expiry is not None and expiry <= now_ns:
        raise MT5AdapterError("UNSUPPORTED_TIF")
    correlation = encode_correlation(request.account_id, request.client_order_id)
    return MT5NativeSubmitV1(
        server=binding.server,
        account_id=binding.account_id,
        native_symbol=spec.native_symbol,
        side=request.side,
        volume_lots=volume_lots,
        order_type=request.order_type,
        time_in_force=request.time_in_force,
        price=price,
        expires_at_ns=expiry,
        comment=correlation.comment,
        magic=correlation.magic,
        expected_revision=expected_revision,
    )


class MT5DemoBrokerPortV1:
    """ADR-0008 port bound permanently to one fake FOREX.com DEMO account."""

    def __init__(
        self,
        *,
        binding: MT5SessionBindingV1,
        symbols: tuple[MT5SymbolSpecV1, ...],
        transport: FakeMT5Transport,
        oms_evidence: FakeMT5OMSEvidence,
        clock_ns: Callable[[], int],
        settle_window_ms: int,
    ) -> None:
        if (
            type(binding) is not MT5SessionBindingV1
            or type(symbols) is not tuple
            or not symbols
            or any(type(spec) is not MT5SymbolSpecV1 for spec in symbols)
            or type(transport) is not FakeMT5Transport
            or type(oms_evidence) is not FakeMT5OMSEvidence
            or not callable(clock_ns)
        ):
            raise MT5AdapterError("INVALID_SESSION_BINDING")
        try:
            parse_int(settle_window_ms, field="settle_window_ms", min_value=1, max_value=30_000)
        except NumericError:
            raise MT5AdapterError("INVALID_SESSION_BINDING") from None
        if len({spec.instrument_id for spec in symbols}) != len(symbols) or any(
            spec.revision != binding.mapping_revision for spec in symbols
        ):
            raise MT5AdapterError("INVALID_SYMBOL_MAPPING")
        self._binding = replace(binding)
        self._binding_hash = _binding_digest(self._binding)
        self._symbols = {spec.instrument_id: replace(spec) for spec in symbols}
        self._symbol_hashes = {
            instrument_id: _symbol_digest(spec) for instrument_id, spec in self._symbols.items()
        }
        self._transport = transport
        self._oms_evidence = oms_evidence
        self._clock_ns = clock_ns
        self._capability = _issue_venue_capability(False, timedelta(milliseconds=settle_window_ms))
        self._venue = _issue_venue_identity(
            BrokerVenue.MT5, BrokerEnvironment.DEMO, self._binding.account_id
        )
        self._submitted_clients: set[str] = set()
        self._submitted_at_ns: dict[str, int] = {}
        self._cancel_attempts: set[str] = set()
        self._correlations: dict[tuple[str, int], str] = {}
        self._events: dict[tuple[str, str], tuple[MT5NativeEventV1, str]] = {}
        self._gtd_expiry: dict[tuple[str, int], int] = {}
        self._late_gtd_alerts: set[tuple[str, str]] = set()

    @property
    def capability(self) -> VenueDispatchCapabilityV1:
        self._capability.assert_sealed()
        return self._capability

    @property
    def venue(self) -> VenueIdentityV1:
        self._venue.assert_sealed()
        return self._venue

    @property
    def late_gtd_alert_count(self) -> int:
        return len(self._late_gtd_alerts)

    @property
    def deal_events(self) -> tuple[MT5NativeEventV1, ...]:
        result: list[MT5NativeEventV1] = []
        for key, (event, digest) in sorted(self._events.items()):
            if key[0] != "DEAL":
                continue
            try:
                payload = {field.name: getattr(event, field.name) for field in fields(event)}
                current_digest = hashlib.sha256(canonical_json(payload)).hexdigest()
                copy = replace(event)
            except Exception:
                raise MT5AdapterError("NATIVE_EVENT_CONFLICT") from None
            if current_digest != digest:
                raise MT5AdapterError("NATIVE_EVENT_CONFLICT")
            result.append(copy)
        return tuple(result)

    def _now(self) -> int:
        return _ns(self._clock_ns())

    def _validate_binding(self) -> None:
        try:
            binding = replace(self._binding)
            digest = _binding_digest(binding)
        except Exception:
            raise MT5AdapterError("INVALID_SESSION_BINDING") from None
        if digest != self._binding_hash:
            raise MT5AdapterError("INVALID_SESSION_BINDING")
        try:
            symbols_intact = self._symbols.keys() == self._symbol_hashes.keys() and all(
                _symbol_digest(replace(spec)) == self._symbol_hashes[instrument_id]
                for instrument_id, spec in self._symbols.items()
            )
        except Exception:
            raise MT5AdapterError("INVALID_SYMBOL_MAPPING") from None
        if not symbols_intact:
            raise MT5AdapterError("INVALID_SYMBOL_MAPPING")
        if self.venue.account_id != self._binding.account_id:
            raise MT5AdapterError("SESSION_MISMATCH")

    def _read_identity(self) -> MT5TerminalSnapshotV1:
        self._validate_binding()
        try:
            snapshot = self._transport.read_snapshot()
        except Exception:
            raise MT5AdapterError("SESSION_UNAVAILABLE") from None
        if type(snapshot) is not MT5TerminalSnapshotV1:
            raise MT5AdapterError("SESSION_MISMATCH")
        try:
            snapshot = replace(
                snapshot,
                quote=replace(snapshot.quote) if snapshot.quote is not None else None,
            )
        except Exception:
            raise MT5AdapterError("SESSION_MISMATCH") from None
        binding = self._binding
        if (
            snapshot.server != binding.server
            or snapshot.account_id != binding.account_id
            or snapshot.mode != "DEMO"
            or snapshot.terminal_agent_id != binding.terminal_agent_id
            or snapshot.protocol != binding.protocol
            or snapshot.protocol_version != binding.protocol_version
            or snapshot.mapping_revision != binding.mapping_revision
        ):
            raise MT5AdapterError("SESSION_MISMATCH")
        return snapshot

    def _read_native_view(self, account_id: str) -> MT5NativeAccountViewV1:
        if account_id != self.venue.account_id:
            raise BrokerRejected(BrokerRejectionCode.ACCOUNT_MISMATCH)
        self._read_identity()
        try:
            view = self._transport.read_native_account_view(account_id)
        except Exception:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW) from None
        if type(view) is not MT5NativeAccountViewV1:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        try:
            view = replace(
                view,
                open_orders=tuple(replace(item) for item in view.open_orders),
                deals=tuple(replace(item) for item in view.deals),
            )
        except Exception:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW) from None
        native_order_ids = [item.venue_order_id for item in view.open_orders]
        client_order_ids = [item.client_order_id for item in view.open_orders]
        if len(set(native_order_ids)) != len(native_order_ids) or len(set(client_order_ids)) != len(
            client_order_ids
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        now = self._now()
        if (
            view.server != self._binding.server
            or view.account_id != account_id
            or view.mode != "DEMO"
            or not view.orders_complete
            or not view.deals_complete
            or not view.positions_complete
            or view.observed_ns > now
            or now - view.observed_ns > self._binding.max_heartbeat_age_ns
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        return view

    def _client_for_deal(self, deal: MT5NativeEventV1) -> str | None:
        pair = (deal.comment, deal.magic)
        local_owner = self._correlations.get(pair)
        pair_claim = self._oms_evidence.owner_of_correlation(
            deal.account_id, deal.comment, deal.magic
        )
        pair_owner = pair_claim.client_order_id if pair_claim is not None else None
        if local_owner is not None and local_owner != pair_owner:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        if deal.related_order_id is not None:
            linked = self._oms_evidence.owner_of_native(deal.account_id, deal.related_order_id)
            if linked is not None:
                if (
                    linked.instrument_id != deal.instrument_id
                    or linked.side != deal.side
                    or (pair_owner is not None and pair_owner != linked.client_order_id)
                ):
                    raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
                return linked.client_order_id
        if pair_owner is not None:
            claim = pair_claim
            if (
                claim is None
                or claim.instrument_id != deal.instrument_id
                or claim.side != deal.side
                or (
                    claim.native_order_id is not None
                    and claim.native_order_id != deal.related_order_id
                )
            ):
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
            return pair_owner
        if any(
            (comment == deal.comment or magic == deal.magic) and (comment, magic) != pair
            for comment, magic in self._correlations
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        return None

    def _consistent_view_deals(
        self, view: MT5NativeAccountViewV1
    ) -> tuple[tuple[MT5NativeEventV1, str | None], ...]:
        """Resolve every account-wide native identity before trusting a view."""
        for item in view.open_orders:
            if item.venue_order_id is not None:
                linked = self._oms_evidence.owner_of_native(view.account_id, item.venue_order_id)
                if linked is not None and linked.client_order_id != item.client_order_id:
                    raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        return tuple(
            (deal, self._client_for_deal(deal))
            for deal in sorted(view.deals, key=lambda item: item.native_id)
        )

    def read_account_view(self, account_id: str) -> AccountViewV1:
        """Read a complete exact-account fake snapshot; never infer completeness."""
        view = self._read_native_view(account_id)
        deal_owners = self._consistent_view_deals(view)
        executions = tuple(
            _issue_deal_execution(deal, client_order_id) for deal, client_order_id in deal_owners
        )
        result = _issue_account_view(
            view.account_id,
            view.open_orders,
            view.positions,
            view.broker_revision,
            executions,
            view.executions_since,
            complete=True,
        )
        result.assert_sealed()
        return result

    def read_order(self, order: OrderSnapshot) -> BrokerObservation | None:
        if type(order) is not OrderSnapshot:
            raise MT5AdapterError("INVALID_IDENTITY")
        request = order.request
        if type(request.client_order_id) is not str:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        if request.account_id != self.venue.account_id or request.venue != "MT5":
            raise BrokerRejected(BrokerRejectionCode.ACCOUNT_MISMATCH)
        evidence = self._oms_evidence.lookup(request.account_id, request.client_order_id)
        if evidence is not None and (
            evidence.oms_order_id != order.order_id
            or evidence.instrument_id != request.instrument_id
            or evidence.side != request.side
            or evidence.quantity != request.quantity
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        self._read_identity()
        correlation = encode_correlation(request.account_id, request.client_order_id)
        try:
            observation = self._transport.read_native_order(
                request.account_id, correlation.comment, correlation.magic
            )
        except Exception:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER) from None
        if observation is not None:
            native_owner = (
                self._oms_evidence.owner_of_native(request.account_id, observation.venue_order_id)
                if type(observation) is BrokerObservation and observation.venue_order_id is not None
                else None
            )
            if (
                type(observation) is not BrokerObservation
                or observation.account_id != request.account_id
                or observation.client_order_id != request.client_order_id
                or observation.environment != "demo"
                or observation.venue != "MT5"
                or (
                    order.venue_order_id is not None
                    and observation.venue_order_id != order.venue_order_id
                )
                or (
                    evidence is not None
                    and evidence.native_order_id is not None
                    and observation.venue_order_id != evidence.native_order_id
                )
                or (
                    native_owner is not None
                    and native_owner.client_order_id != request.client_order_id
                )
            ):
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
            return observation
        try:
            view = self._read_native_view(request.account_id)
            self._consistent_view_deals(view)
        except BrokerOutcomeUnknown:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER) from None
        attempted_at = (
            evidence.attempted_at_ns
            if evidence is not None
            else self._submitted_at_ns.get(request.client_order_id)
        )
        if (
            attempted_at is None
            or _datetime_ns(view.executions_since) > attempted_at
            or view.observed_ns <= attempted_at
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        known_ids = {
            native_id
            for native_id in (
                order.venue_order_id,
                evidence.native_order_id if evidence is not None else None,
            )
            if native_id is not None
        }
        if len(known_ids) > 1:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        if any(item.venue_order_id in known_ids for item in view.open_orders) or any(
            deal.related_order_id in known_ids for deal in view.deals
        ):
            # A rewritten comment, magic or client label cannot erase native evidence.
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        if any(item.client_order_id == request.client_order_id for item in view.open_orders):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        if any(
            item.venue_order_id is None
            or self._oms_evidence.owner_of_native(request.account_id, item.venue_order_id) is None
            for item in view.open_orders
        ):
            # The fake open-order view has no symbol or volume, so an unowned
            # ticket prevents a proof of absence for this request.
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        if any(
            item.comment == correlation.comment or item.magic == correlation.magic
            for item in view.deals
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        if any(
            deal.instrument_id == request.instrument_id
            and deal.side == request.side
            and deal.quantity <= request.quantity
            and _datetime_ns(view.executions_since) <= deal.occurred_at_ns <= self._now()
            for deal in view.deals
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        return None

    def submit(
        self,
        request: OrderRequest,
        permit: DispatchPermitV1,
        expected_revision: int,
    ) -> SubmitResultV1:
        """Consume one OMS permit, reconcile, then send at most one fake request."""
        if type(request) is not OrderRequest:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        if type(request.client_order_id) is not str:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        if request.account_id != self.venue.account_id:
            raise BrokerRejected(BrokerRejectionCode.ACCOUNT_MISMATCH)
        if request.environment != "demo" or request.venue != "MT5":
            raise BrokerRejected(BrokerRejectionCode.ENVIRONMENT_MISMATCH)
        if request.order_type not in {"MARKET", "LIMIT"}:
            raise BrokerRejected(BrokerRejectionCode.UNSUPPORTED_ORDER_CLASS)
        spec = self._symbols.get(request.instrument_id)
        if spec is None or spec.native_contract_id != request.native_contract_id:
            raise BrokerRejected(BrokerRejectionCode.UNSUPPORTED_INSTRUMENT)
        self._validate_binding()
        revision = _ns(expected_revision, code="BROKER_REVISION_MISMATCH")
        if request.client_order_id in self._submitted_clients:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        if self._oms_evidence.lookup(request.account_id, request.client_order_id) is not None:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        try:
            order_id = permit.order_id
        except Exception:
            raise MT5AdapterError("PERMIT_REQUIRED") from None
        if type(order_id) is not str or not callable(getattr(permit, "consume", None)):
            raise MT5AdapterError("PERMIT_REQUIRED")
        try:
            permit.consume(permit.order_id, request.digest, revision)
        except Exception:
            raise MT5AdapterError("PERMIT_REQUIRED") from None
        # The permit is now spent; any later uncertainty blocks blind retry.
        self._submitted_clients.add(request.client_order_id)
        snapshot = self._read_identity()
        try:
            view = self._read_native_view(request.account_id)
        except BrokerOutcomeUnknown:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
        if snapshot.broker_revision != revision or view.broker_revision != revision:
            raise MT5AdapterError("BROKER_REVISION_MISMATCH")
        try:
            self._consistent_view_deals(view)
        except BrokerOutcomeUnknown:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
        native = build_native_submit(
            request, self._binding, snapshot, spec, now_ns=self._now(), expected_revision=revision
        )
        pair = (native.comment, native.magic)
        owner = self._correlations.get(pair)
        if owner is not None and owner != request.client_order_id:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        if any(
            (comment == native.comment or magic == native.magic)
            and client_id != request.client_order_id
            for (comment, magic), client_id in self._correlations.items()
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        if any(item.client_order_id == request.client_order_id for item in view.open_orders):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        if any(item.comment == native.comment or item.magic == native.magic for item in view.deals):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        # Open observations carry no symbol/side/volume; an unowned ticket is
        # therefore ambiguous. Deals do carry exact instrument units.
        if any(
            item.venue_order_id is None
            or self._oms_evidence.owner_of_native(request.account_id, item.venue_order_id) is None
            for item in view.open_orders
        ) or any(
            deal.instrument_id == request.instrument_id
            and deal.side == request.side
            and deal.quantity <= request.quantity
            and _datetime_ns(view.executions_since) <= deal.occurred_at_ns <= self._now()
            for deal in view.deals
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        attempted_at_ns = self._now()
        self._oms_evidence.reserve(request, permit.order_id, attempted_at_ns)
        self._submitted_at_ns[request.client_order_id] = attempted_at_ns
        self._correlations[pair] = request.client_order_id
        if native.expires_at_ns is not None:
            self._gtd_expiry[pair] = native.expires_at_ns
        try:
            ack = self._transport.submit_native(native)
        except Exception:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
        if type(ack) is not MT5NativeSubmitAckV1:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        if ack.state == "REJECTED":
            result = _issue_submit_result(
                None, OrderState.REJECTED, BrokerRejectionCode.VENUE_REJECTED
            )
        else:
            assert ack.native_order_id is not None
            self._oms_evidence.bind_native(
                request.account_id, request.client_order_id, ack.native_order_id
            )
            result = _issue_submit_result(ack.native_order_id, OrderState.WORKING)
        result.assert_sealed()
        return result

    def cancel(self, order: OrderSnapshot) -> CancelResultV1:
        """Send one bounded cancel; unknown acknowledgment stays unconfirmed."""
        if type(order) is not OrderSnapshot:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        if order.request.account_id != self.venue.account_id or order.request.venue != "MT5":
            raise BrokerRejected(BrokerRejectionCode.ACCOUNT_MISMATCH)
        if order.venue_order_id is None or order.order_id in self._cancel_attempts:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        try:
            self._read_identity()
        except Exception:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL) from None
        try:
            view = self._read_native_view(order.request.account_id)
            self._consistent_view_deals(view)
        except BrokerOutcomeUnknown:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL) from None
        self._oms_evidence.reserve_cancel(order)
        self._cancel_attempts.add(order.order_id)
        try:
            ack = self._transport.cancel_native(order.venue_order_id)
        except Exception:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL) from None
        if type(ack) is not MT5NativeCancelAckV1:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        result = _issue_cancel_result(ack.confirmed)
        result.assert_sealed()
        return result

    def ingest_callback(self, event: MT5NativeEventV1) -> MT5CallbackDecisionV1:
        """Retain each native ID/version without treating a deal as an order or a flat position."""
        if type(event) is not MT5NativeEventV1:
            raise MT5AdapterError("NATIVE_EVENT_INVALID")
        try:
            event = replace(event)
        except Exception:
            raise MT5AdapterError("NATIVE_EVENT_INVALID") from None
        self._validate_binding()
        if event.server != self._binding.server or event.account_id != self.venue.account_id:
            raise MT5AdapterError("SESSION_MISMATCH")
        pair = (event.comment, event.magic)
        conflict = False
        if event.kind == "DEAL":
            try:
                owner = self._client_for_deal(event)
            except BrokerOutcomeUnknown:
                owner = None
                conflict = True
            claim = (
                self._oms_evidence.lookup(event.account_id, owner) if owner is not None else None
            )
            expiry = claim.expires_at_ns if claim is not None else None
        else:
            owner = self._correlations.get(pair)
            expiry = self._gtd_expiry.get(pair)
        payload = {field.name: getattr(event, field.name) for field in fields(event)}
        digest = hashlib.sha256(canonical_json(payload)).hexdigest()
        key = (event.kind, event.native_id)
        prior = self._events.get(key)
        if prior is not None:
            if event.version < prior[0].version:
                return MT5CallbackDecisionV1(False, False, None)
            if event.version == prior[0].version:
                if digest != prior[1]:
                    raise MT5AdapterError("NATIVE_EVENT_CONFLICT")
                return MT5CallbackDecisionV1(False, False, None)
        self._events[key] = (event, digest)
        if conflict or owner is None:
            return MT5CallbackDecisionV1(True, False, "RECONCILE_REQUIRED")
        late = event.kind == "DEAL" and expiry is not None and event.occurred_at_ns > expiry
        if late:
            self._late_gtd_alerts.add(key)
        return MT5CallbackDecisionV1(True, late, "LATE_GTD" if late else None)
