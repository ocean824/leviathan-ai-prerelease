"""Offline Alpaca paper adapter and explicitly recorded fake transport.

No network or credential implementation belongs in this module.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from hashlib import sha256
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
from leviathan_core.execution.brokers.alpaca_mapping import (
    AlpacaAssetMapV1,
    AlpacaMappingError,
    AlpacaOrderPayloadV1,
    AlpacaOrderSpecV1,
    map_alpaca_order,
)
from leviathan_core.execution.order_models import (
    BrokerObservation,
    Fill,
    FillCorrection,
    OrderRequest,
    OrderSnapshot,
    OrderState,
)
from leviathan_core.numeric import (
    NumericError,
    canonical_json,
    canonical_str,
    exact_sub,
    parse_decimal,
    parse_int,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_CREDENTIAL_REF = re.compile(
    r"vault://leviathan-ai/development/alpaca/[A-Z][A-Z0-9_]{0,63}\Z", re.ASCII
)


class AlpacaPaperError(ValueError):
    """A typed, content-free adapter denial."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AlpacaBaseUrlIdentity(StrEnum):
    PAPER = "ALPACA_PAPER"


class RecordedHttpError(RuntimeError):
    """A fake REST failure whose untrusted body is deliberately discarded."""

    __slots__ = ("reason_code", "status_code")

    def __init__(
        self, status_code: int, reason_code: str | None = None, response_body: object = None
    ) -> None:
        del response_body
        if type(status_code) is not int or not 400 <= status_code <= 599:
            raise AlpacaPaperError("INVALID_RECORDED_FAILURE")
        if reason_code is not None and (
            type(reason_code) is not str or reason_code != "DUPLICATE_CLIENT_ORDER_ID"
        ):
            raise AlpacaPaperError("INVALID_RECORDED_FAILURE")
        self.status_code = status_code
        self.reason_code = reason_code
        super().__init__("RECORDED_HTTP_FAILURE")


class _NoCopy:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise TypeError("ALPACA_COPY_DISABLED")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("ALPACA_COPY_DISABLED")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ALPACA_SERIALIZATION_DISABLED")


def _id(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise AlpacaPaperError(code)
    return value


def _time(value: object, code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AlpacaPaperError(code)
    return value.astimezone(UTC)


def _quantity(value: object, code: str) -> Decimal:
    try:
        result = parse_decimal(value, field="value")
    except NumericError:
        raise AlpacaPaperError(code) from None
    if result < 0:
        raise AlpacaPaperError(code)
    return result


@dataclass(frozen=True, slots=True)
class AlpacaSessionBindingV1(_NoCopy):
    account_id: str
    mapping_revision: str
    calendar_revision: str
    environment: BrokerEnvironment = BrokerEnvironment.PAPER
    base_url_identity: AlpacaBaseUrlIdentity = AlpacaBaseUrlIdentity.PAPER
    api_version: str = "v2"
    credential_ref: str | None = None

    def __post_init__(self) -> None:
        _id(self.account_id, "INVALID_SESSION_BINDING")
        _id(self.mapping_revision, "INVALID_SESSION_BINDING")
        _id(self.calendar_revision, "INVALID_SESSION_BINDING")
        if (
            type(self.environment) is not BrokerEnvironment
            or self.environment is not BrokerEnvironment.PAPER
            or type(self.base_url_identity) is not AlpacaBaseUrlIdentity
            or self.base_url_identity is not AlpacaBaseUrlIdentity.PAPER
            or self.api_version != "v2"
        ):
            raise AlpacaPaperError("PAPER_SESSION_REQUIRED")
        if self.credential_ref is not None and (
            not isinstance(self.credential_ref, str)
            or _CREDENTIAL_REF.fullmatch(self.credential_ref) is None
        ):
            raise AlpacaPaperError("INVALID_CREDENTIAL_REFERENCE")


@dataclass(frozen=True, slots=True)
class AlpacaOrderRecordV1(_NoCopy):
    venue_order_id: str
    client_order_id: str
    account_id: str
    state: str
    observed_at: datetime
    filled_quantity: Decimal = Decimal(0)
    broker_sequence: int | None = None
    asset_id: str | None = None
    side: str | None = None
    quantity: Decimal | None = None

    def __post_init__(self) -> None:
        for value in (self.venue_order_id, self.client_order_id, self.account_id):
            _id(value, "INVALID_ORDER_RECORD")
        if type(self.state) is not str or self.state not in {
            "new",
            "accepted",
            "partially_filled",
            "filled",
            "canceled",
            "rejected",
            "expired",
        }:
            raise AlpacaPaperError("INVALID_ORDER_RECORD")
        object.__setattr__(self, "observed_at", _time(self.observed_at, "INVALID_ORDER_RECORD"))
        object.__setattr__(
            self,
            "filled_quantity",
            _quantity(self.filled_quantity, "INVALID_ORDER_RECORD"),
        )
        if self.broker_sequence is not None and (
            type(self.broker_sequence) is not int or self.broker_sequence < 0
        ):
            raise AlpacaPaperError("INVALID_ORDER_RECORD")
        details = (self.asset_id, self.side, self.quantity)
        if any(value is not None for value in details):
            if any(value is None for value in details):
                raise AlpacaPaperError("INVALID_ORDER_RECORD")
            _id(self.asset_id, "INVALID_ORDER_RECORD")
            if type(self.side) is not str or self.side not in {"BUY", "SELL"}:
                raise AlpacaPaperError("INVALID_ORDER_RECORD")
            quantity = _quantity(self.quantity, "INVALID_ORDER_RECORD")
            if quantity <= 0 or self.filled_quantity > quantity:
                raise AlpacaPaperError("INVALID_ORDER_RECORD")
            object.__setattr__(self, "quantity", quantity)


@dataclass(frozen=True, slots=True)
class AlpacaPositionRecordV1(_NoCopy):
    asset_id: str
    quantity: Decimal

    def __post_init__(self) -> None:
        _id(self.asset_id, "INVALID_POSITION_RECORD")
        try:
            quantity = parse_decimal(self.quantity, field="value")
        except NumericError:
            raise AlpacaPaperError("INVALID_POSITION_RECORD") from None
        object.__setattr__(self, "quantity", quantity)


@dataclass(frozen=True, slots=True)
class AlpacaExecutionRecordV1(_NoCopy):
    execution_id: str
    venue_order_id: str
    client_order_id: str | None
    account_id: str
    asset_id: str
    side: str
    quantity: Decimal
    price: Decimal
    executed_at: datetime

    def __post_init__(self) -> None:
        for value in (
            self.execution_id,
            self.venue_order_id,
            self.account_id,
            self.asset_id,
        ):
            _id(value, "INVALID_EXECUTION_RECORD")
        if self.client_order_id is not None:
            _id(self.client_order_id, "INVALID_EXECUTION_RECORD")
        if type(self.side) is not str or self.side not in {"BUY", "SELL"}:
            raise AlpacaPaperError("INVALID_EXECUTION_RECORD")
        for name in ("quantity", "price"):
            parsed = _quantity(getattr(self, name), "INVALID_EXECUTION_RECORD")
            if parsed <= 0:
                raise AlpacaPaperError("INVALID_EXECUTION_RECORD")
            object.__setattr__(self, name, parsed)
        object.__setattr__(self, "executed_at", _time(self.executed_at, "INVALID_EXECUTION_RECORD"))


@dataclass(frozen=True, slots=True)
class AlpacaAccountRecordV1(_NoCopy):
    account_id: str
    broker_revision: int
    open_orders: tuple[AlpacaOrderRecordV1, ...]
    positions: tuple[AlpacaPositionRecordV1, ...]
    observed_at: datetime
    venue_time_ns: int | None
    executions_since: datetime
    executions: tuple[AlpacaExecutionRecordV1, ...] = ()
    executions_complete: bool = True

    def __post_init__(self) -> None:
        _id(self.account_id, "INVALID_ACCOUNT_RECORD")
        if type(self.broker_revision) is not int or self.broker_revision < 0:
            raise AlpacaPaperError("INVALID_ACCOUNT_RECORD")
        if not isinstance(self.open_orders, tuple) or any(
            not isinstance(order, AlpacaOrderRecordV1) or order.account_id != self.account_id
            for order in self.open_orders
        ):
            raise AlpacaPaperError("INVALID_ACCOUNT_RECORD")
        if not isinstance(self.positions, tuple) or any(
            not isinstance(position, AlpacaPositionRecordV1) for position in self.positions
        ):
            raise AlpacaPaperError("INVALID_ACCOUNT_RECORD")
        if not isinstance(self.executions, tuple) or any(
            not isinstance(execution, AlpacaExecutionRecordV1)
            or execution.account_id != self.account_id
            for execution in self.executions
        ):
            raise AlpacaPaperError("INVALID_ACCOUNT_RECORD")
        if type(self.executions_complete) is not bool:
            raise AlpacaPaperError("INVALID_ACCOUNT_RECORD")
        if self.venue_time_ns is not None and (
            type(self.venue_time_ns) is not int or self.venue_time_ns < 0
        ):
            raise AlpacaPaperError("INVALID_ACCOUNT_RECORD")
        observed_at = _time(self.observed_at, "INVALID_ACCOUNT_RECORD")
        since = _time(self.executions_since, "INVALID_ACCOUNT_RECORD")
        if (
            since > observed_at
            or any(
                not since <= execution.executed_at <= observed_at for execution in self.executions
            )
            or any(order.observed_at > observed_at for order in self.open_orders)
        ):
            raise AlpacaPaperError("INVALID_ACCOUNT_RECORD")
        object.__setattr__(self, "observed_at", observed_at)
        object.__setattr__(self, "executions_since", since)


@dataclass(frozen=True, slots=True)
class AlpacaTradeUpdateV1(_NoCopy):
    venue_order_id: str
    client_order_id: str
    account_id: str
    event_type: str
    event_time: datetime
    event_sequence: int | None = None
    execution_id: str | None = None
    quantity: Decimal | None = None
    price: Decimal | None = None
    correction_id: str | None = None
    revision: int | None = None

    def __post_init__(self) -> None:
        for value in (self.venue_order_id, self.client_order_id, self.account_id):
            _id(value, "INVALID_TRADE_UPDATE")
        if type(self.event_type) is not str or self.event_type not in {
            "new",
            "partial_fill",
            "fill",
            "canceled",
            "rejected",
            "correction",
        }:
            raise AlpacaPaperError("INVALID_TRADE_UPDATE")
        if self.event_sequence is not None and (
            type(self.event_sequence) is not int or self.event_sequence < 0
        ):
            raise AlpacaPaperError("INVALID_TRADE_UPDATE")
        if self.execution_id is not None:
            _id(self.execution_id, "INVALID_TRADE_UPDATE")
        if self.correction_id is not None:
            _id(self.correction_id, "INVALID_TRADE_UPDATE")
        if self.revision is not None and (type(self.revision) is not int or self.revision < 1):
            raise AlpacaPaperError("INVALID_TRADE_UPDATE")
        if self.event_type in {"partial_fill", "fill", "correction"} and (
            self.execution_id is None or self.quantity is None
        ):
            raise AlpacaPaperError("INVALID_TRADE_UPDATE")
        if self.event_type in {"partial_fill", "fill"} and self.price is None:
            raise AlpacaPaperError("INVALID_TRADE_UPDATE")
        if self.event_type == "correction" and (
            self.correction_id is None or self.revision is None
        ):
            raise AlpacaPaperError("INVALID_TRADE_UPDATE")
        if self.event_type != "correction" and (
            self.correction_id is not None or self.revision is not None
        ):
            raise AlpacaPaperError("INVALID_TRADE_UPDATE")
        if self.event_type in {"new", "canceled", "rejected"} and (
            self.execution_id is not None or self.quantity is not None or self.price is not None
        ):
            raise AlpacaPaperError("INVALID_TRADE_UPDATE")
        for name in ("quantity", "price"):
            value = getattr(self, name)
            if value is not None:
                parsed = _quantity(value, "INVALID_TRADE_UPDATE")
                if name == "price" and parsed <= 0:
                    raise AlpacaPaperError("INVALID_TRADE_UPDATE")
                object.__setattr__(self, name, parsed)
        if self.event_type in {"partial_fill", "fill"} and self.quantity == 0:
            raise AlpacaPaperError("INVALID_TRADE_UPDATE")
        if (
            self.event_type == "correction"
            and self.quantity is not None
            and ((self.quantity > 0) != (self.price is not None))
        ):
            raise AlpacaPaperError("INVALID_TRADE_UPDATE")
        object.__setattr__(self, "event_time", _time(self.event_time, "INVALID_TRADE_UPDATE"))


class AlpacaTransport(Protocol):
    """Internal REST and stream seam; no HTTP library is part of v0.1."""

    def post_order(self, payload: AlpacaOrderPayloadV1) -> AlpacaOrderRecordV1: ...

    def delete_order(self, venue_order_id: str) -> bool: ...

    def get_order_by_client_id(self, client_order_id: str) -> AlpacaOrderRecordV1 | None: ...

    def get_order_by_venue_id(self, venue_order_id: str) -> AlpacaOrderRecordV1 | None: ...

    def get_account_view(self, account_id: str) -> AlpacaAccountRecordV1: ...

    def poll_trade_updates(self) -> tuple[AlpacaTradeUpdateV1, ...]: ...


class RecordedAlpacaTransport(_NoCopy):
    """One-shot scripted exchanges. Missing scripts fail uncertain, never succeed."""

    def __init__(self) -> None:
        self._posts: list[AlpacaOrderRecordV1 | Exception] = []
        self._deletes: list[bool | Exception] = []
        self._reads_client: list[AlpacaOrderRecordV1 | None | Exception] = []
        self._reads_venue: list[AlpacaOrderRecordV1 | None | Exception] = []
        self._accounts: list[AlpacaAccountRecordV1 | Exception] = []
        self._updates: list[tuple[AlpacaTradeUpdateV1, ...] | Exception] = []
        self.post_payloads: list[AlpacaOrderPayloadV1] = []
        self.delete_ids: list[str] = []
        self.client_lookup_ids: list[str] = []
        self.venue_lookup_ids: list[str] = []
        self.account_lookup_ids: list[str] = []
        self.update_polls = 0

    def queue_post(self, outcome: AlpacaOrderRecordV1 | Exception) -> None:
        self._posts.append(outcome)

    def queue_delete(self, outcome: bool | Exception) -> None:
        if type(outcome) is not bool and not isinstance(outcome, Exception):
            raise AlpacaPaperError("INVALID_FAKE_SCRIPT")
        self._deletes.append(outcome)

    def queue_client_read(self, outcome: AlpacaOrderRecordV1 | None | Exception) -> None:
        self._reads_client.append(outcome)

    def queue_venue_read(self, outcome: AlpacaOrderRecordV1 | None | Exception) -> None:
        self._reads_venue.append(outcome)

    def queue_account(self, outcome: AlpacaAccountRecordV1 | Exception) -> None:
        self._accounts.append(outcome)

    def queue_updates(self, outcome: tuple[AlpacaTradeUpdateV1, ...] | Exception) -> None:
        if not isinstance(outcome, (tuple, Exception)) or (
            isinstance(outcome, tuple)
            and any(not isinstance(item, AlpacaTradeUpdateV1) for item in outcome)
        ):
            raise AlpacaPaperError("INVALID_FAKE_SCRIPT")
        self._updates.append(outcome)

    @staticmethod
    def _take(script: list[Any], code: str) -> Any:
        if not script:
            raise TimeoutError(code)
        outcome = script.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def post_order(self, payload: AlpacaOrderPayloadV1) -> AlpacaOrderRecordV1:
        if not isinstance(payload, AlpacaOrderPayloadV1):
            raise AlpacaPaperError("INVALID_FAKE_REQUEST")
        self.post_payloads.append(payload)
        result = self._take(self._posts, "UNSCRIPTED_POST")
        if not isinstance(result, AlpacaOrderRecordV1):
            raise AlpacaPaperError("INVALID_FAKE_SCRIPT")
        return result

    def delete_order(self, venue_order_id: str) -> bool:
        self.delete_ids.append(_id(venue_order_id, "INVALID_FAKE_REQUEST"))
        result = self._take(self._deletes, "UNSCRIPTED_DELETE")
        if type(result) is not bool:
            raise AlpacaPaperError("INVALID_FAKE_SCRIPT")
        return result

    def get_order_by_client_id(self, client_order_id: str) -> AlpacaOrderRecordV1 | None:
        self.client_lookup_ids.append(_id(client_order_id, "INVALID_FAKE_REQUEST"))
        result = self._take(self._reads_client, "UNSCRIPTED_CLIENT_READ")
        if result is not None and not isinstance(result, AlpacaOrderRecordV1):
            raise AlpacaPaperError("INVALID_FAKE_SCRIPT")
        return result

    def get_order_by_venue_id(self, venue_order_id: str) -> AlpacaOrderRecordV1 | None:
        self.venue_lookup_ids.append(_id(venue_order_id, "INVALID_FAKE_REQUEST"))
        result = self._take(self._reads_venue, "UNSCRIPTED_VENUE_READ")
        if result is not None and not isinstance(result, AlpacaOrderRecordV1):
            raise AlpacaPaperError("INVALID_FAKE_SCRIPT")
        return result

    def get_account_view(self, account_id: str) -> AlpacaAccountRecordV1:
        self.account_lookup_ids.append(_id(account_id, "INVALID_FAKE_REQUEST"))
        result = self._take(self._accounts, "UNSCRIPTED_ACCOUNT_READ")
        if not isinstance(result, AlpacaAccountRecordV1):
            raise AlpacaPaperError("INVALID_FAKE_SCRIPT")
        return result

    def poll_trade_updates(self) -> tuple[AlpacaTradeUpdateV1, ...]:
        self.update_polls += 1
        result = self._take(self._updates, "UNSCRIPTED_UPDATES")
        if not isinstance(result, tuple) or any(
            not isinstance(item, AlpacaTradeUpdateV1) for item in result
        ):
            raise AlpacaPaperError("INVALID_FAKE_SCRIPT")
        return result


@dataclass(frozen=True, slots=True)
class _SellAttempt:
    account_id: str
    client_order_id: str
    oms_order_id: str
    intent_idempotency_key: str
    attempt: int
    instrument_id: str
    native_contract_id: str
    quantity: Decimal
    broker_revision: int
    observed_at: datetime
    reflected: bool = False


def _account_evidence_digest(record: AlpacaAccountRecordV1) -> bytes:
    return sha256(
        canonical_json(
            [
                record.account_id,
                record.broker_revision,
                record.observed_at.isoformat(),
                record.venue_time_ns,
                record.executions_since.isoformat(),
                record.executions_complete,
                [
                    [
                        item.venue_order_id,
                        item.client_order_id,
                        item.account_id,
                        item.state,
                        item.observed_at.isoformat(),
                        item.filled_quantity,
                        item.broker_sequence,
                        item.asset_id,
                        item.side,
                        item.quantity,
                    ]
                    for item in sorted(record.open_orders, key=lambda item: item.venue_order_id)
                ],
                [
                    [item.asset_id, item.quantity]
                    for item in sorted(record.positions, key=lambda item: item.asset_id)
                ],
                [
                    [
                        item.execution_id,
                        item.venue_order_id,
                        item.client_order_id,
                        item.account_id,
                        item.asset_id,
                        item.side,
                        item.quantity,
                        item.price,
                        item.executed_at.isoformat(),
                    ]
                    for item in sorted(record.executions, key=lambda item: item.execution_id)
                ],
            ]
        )
    ).digest()


class FakeAlpacaOMSEvidence(_NoCopy):
    """Fake durable SELL attempt memory shared across adapter instances."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._attempts: dict[tuple[str, str], _SellAttempt] = {}
        self._latest_views: dict[str, tuple[int, bytes]] = {}

    def _check_view(self, record: AlpacaAccountRecordV1, unknown_code: BrokerUnknownCode) -> None:
        if record.executions_complete is not True:
            raise BrokerOutcomeUnknown(unknown_code)
        try:
            digest = _account_evidence_digest(record)
        except Exception:
            raise BrokerOutcomeUnknown(unknown_code) from None
        prior = self._latest_views.get(record.account_id)
        if prior is not None and (
            record.broker_revision < prior[0]
            or (record.broker_revision == prior[0] and digest != prior[1])
        ):
            raise BrokerOutcomeUnknown(unknown_code)
        if prior is None or record.broker_revision > prior[0]:
            self._latest_views[record.account_id] = (record.broker_revision, digest)

    def observe_account_view(self, record: AlpacaAccountRecordV1) -> None:
        with self._lock:
            self._check_view(record, BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)

    def reserve_sell(
        self,
        request: OrderRequest,
        oms_order_id: str,
        quantity: Decimal,
        available: Decimal,
        record: AlpacaAccountRecordV1,
    ) -> None:
        client_id = request.client_order_id
        if type(client_id) is not str:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        key = (request.account_id, client_id)
        with self._lock:
            if record.account_id != request.account_id:
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
            self._check_view(record, BrokerUnknownCode.UNKNOWN_SUBMIT)
            if key in self._attempts:
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
            for prior_key, prior in tuple(self._attempts.items()):
                if prior.account_id != request.account_id or prior.reflected:
                    continue
                prior_orders = tuple(
                    item
                    for item in record.open_orders
                    if item.client_order_id == prior.client_order_id
                )
                prior_executions = tuple(
                    item
                    for item in record.executions
                    if item.client_order_id == prior.client_order_id
                )
                if any(
                    item.asset_id != prior.native_contract_id
                    or item.side != "SELL"
                    or item.quantity != prior.quantity
                    for item in prior_orders
                ) or any(
                    item.asset_id != prior.native_contract_id
                    or item.side != "SELL"
                    or item.quantity > prior.quantity
                    for item in prior_executions
                ):
                    continue
                if record.broker_revision > prior.broker_revision and (
                    prior_orders or record.executions_since <= prior.observed_at
                ):
                    self._attempts[prior_key] = replace(prior, reflected=True)
            try:
                for prior in self._attempts.values():
                    if (
                        prior.account_id == request.account_id
                        and prior.instrument_id == request.instrument_id
                        and not prior.reflected
                    ):
                        available = exact_sub(available, prior.quantity)
            except NumericError:
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
            if quantity > available:
                raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
            self._attempts[key] = _SellAttempt(
                request.account_id,
                client_id,
                oms_order_id,
                request.intent_idempotency_key,
                request.attempt,
                request.instrument_id,
                request.native_contract_id,
                quantity,
                record.broker_revision,
                record.observed_at,
            )


_ORDER_STATES: dict[str, OrderState] = {
    "new": OrderState.WORKING,
    "accepted": OrderState.WORKING,
    "partially_filled": OrderState.PARTIALLY_FILLED,
    "filled": OrderState.FILLED,
    "canceled": OrderState.CANCELED,
    "rejected": OrderState.REJECTED,
    "expired": OrderState.EXPIRED,
}
_EVENT_STATES: dict[str, OrderState] = {
    "new": OrderState.WORKING,
    "partial_fill": OrderState.PARTIALLY_FILLED,
    "fill": OrderState.FILLED,
    "canceled": OrderState.CANCELED,
    "rejected": OrderState.REJECTED,
}


def _observation_id(value: object) -> str:
    return sha256(canonical_json(value)).hexdigest()


def _configuration_digest(binding: AlpacaSessionBindingV1, assets: AlpacaAssetMapV1) -> bytes:
    return sha256(
        canonical_json(
            {
                "account_id": binding.account_id,
                "environment": binding.environment.value,
                "base_url_identity": binding.base_url_identity.value,
                "api_version": binding.api_version,
                "mapping_revision": binding.mapping_revision,
                "calendar_revision": binding.calendar_revision,
                "credential_ref": binding.credential_ref,
                "assets": [
                    [
                        asset.instrument_id,
                        asset.asset_id,
                        asset.symbol,
                        asset.tick_size,
                        asset.lot_size,
                        asset.round_quantity_toward_zero,
                        asset.asset_class,
                    ]
                    for asset in assets.assets
                ],
            }
        )
    ).digest()


class AlpacaPaperBrokerPortV1(_NoCopy):
    """Bound Alpaca PAPER implementation of the sealed BrokerPortV1 seam."""

    def __init__(
        self,
        binding: AlpacaSessionBindingV1,
        assets: AlpacaAssetMapV1,
        transport: AlpacaTransport,
        *,
        oms_evidence: FakeAlpacaOMSEvidence,
        clock_ns: Callable[[], int],
        settle_window: timedelta = timedelta(seconds=2),
    ) -> None:
        if not isinstance(binding, AlpacaSessionBindingV1):
            raise AlpacaPaperError("INVALID_SESSION_BINDING")
        if not isinstance(assets, AlpacaAssetMapV1) or assets.revision != binding.mapping_revision:
            raise AlpacaPaperError("MAPPING_REVISION_MISMATCH")
        if type(transport) is not RecordedAlpacaTransport:
            raise AlpacaPaperError("RECORDED_TRANSPORT_REQUIRED")
        if type(oms_evidence) is not FakeAlpacaOMSEvidence:
            raise AlpacaPaperError("OMS_EVIDENCE_REQUIRED")
        if not callable(clock_ns):
            raise AlpacaPaperError("INVALID_CLOCK")
        self._binding = binding
        self._assets = assets
        self._transport = transport
        self._oms_evidence = oms_evidence
        self._clock_ns = clock_ns
        self._configuration_digest = _configuration_digest(binding, assets)
        self._capability = _issue_venue_capability(False, settle_window)
        self._venue = _issue_venue_identity(
            BrokerVenue.ALPACA, BrokerEnvironment.PAPER, binding.account_id
        )
        self._last_account: AlpacaAccountRecordV1 | None = None
        self._attempted_client_ids: set[str] = set()
        self._seen_updates: dict[tuple[str, str, int | str], bytes] = {}
        self._discrepancies: list[str] = []

    @property
    def discrepancies(self) -> tuple[str, ...]:
        return tuple(self._discrepancies)

    @property
    def capability(self) -> VenueDispatchCapabilityV1:
        self._capability.assert_sealed()
        return self._capability

    @property
    def venue(self) -> VenueIdentityV1:
        self._venue.assert_sealed()
        return self._venue

    def _assert_configuration(self) -> None:
        try:
            current = _configuration_digest(self._binding, self._assets)
        except Exception:
            raise AlpacaPaperError("CONFIG_TAMPERED") from None
        if not hmac.compare_digest(self._configuration_digest, current):
            raise AlpacaPaperError("CONFIG_TAMPERED")

    @staticmethod
    def _raise_transport(
        exc: Exception, unknown_code: BrokerUnknownCode, *, read_only: bool = False
    ) -> NoReturn:
        if isinstance(exc, RecordedHttpError):
            if exc.status_code == 429:
                if read_only:
                    raise BrokerRejected(BrokerRejectionCode.RATE_LIMITED) from None
                raise BrokerOutcomeUnknown(unknown_code) from None
            if 400 <= exc.status_code < 500:
                raise BrokerRejected(BrokerRejectionCode.VENUE_REJECTED) from None
        raise BrokerOutcomeUnknown(unknown_code) from None

    def _account_record(self, account_id: str) -> AlpacaAccountRecordV1:
        try:
            record = self._transport.get_account_view(account_id)
        except Exception as exc:
            self._raise_transport(exc, BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW, read_only=True)
        if record.account_id != account_id:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        if (
            record.executions_complete is not True
            or record.executions_since > record.observed_at
            or any(execution.account_id != account_id for execution in record.executions)
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        prior = self._last_account
        if prior is not None and (
            record.broker_revision < prior.broker_revision
            or (record.broker_revision == prior.broker_revision and record != prior)
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        self._last_account = record
        return record

    def _observation(self, record: AlpacaOrderRecordV1) -> BrokerObservation:
        return BrokerObservation(
            observation_id=_observation_id(
                [
                    record.account_id,
                    record.venue_order_id,
                    record.client_order_id,
                    record.state,
                    record.observed_at.isoformat(),
                    record.broker_sequence,
                ]
            ),
            environment="paper",
            account_id=record.account_id,
            venue="ALPACA",
            client_order_id=record.client_order_id,
            status=_ORDER_STATES[record.state],
            observed_at=record.observed_at,
            venue_order_id=record.venue_order_id,
            broker_sequence=record.broker_sequence,
        )

    def read_account_view(self, account_id: str) -> AccountViewV1:
        self._assert_configuration()
        if account_id != self._binding.account_id:
            raise BrokerRejected(BrokerRejectionCode.ACCOUNT_MISMATCH)
        record = self._account_record(account_id)
        if len({item.venue_order_id for item in record.open_orders}) != len(
            record.open_orders
        ) or len({item.client_order_id for item in record.open_orders}) != len(record.open_orders):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        open_orders = tuple(self._observation(item) for item in record.open_orders)
        if any(
            item.status not in {OrderState.WORKING, OrderState.PARTIALLY_FILLED}
            for item in open_orders
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        asset_ids = {asset.asset_id: asset.instrument_id for asset in self._assets.assets}
        if any(position.asset_id not in asset_ids for position in record.positions):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        if any(execution.asset_id not in asset_ids for execution in record.executions):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        positions = tuple(
            sorted(
                (
                    (asset_ids[position.asset_id], position.quantity)
                    for position in record.positions
                ),
                key=lambda item: item[0],
            )
        )
        if len({instrument for instrument, _ in positions}) != len(positions):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        try:
            executions: tuple[ExecutionV1, ...] = tuple(
                _issue_execution(
                    execution.execution_id,
                    execution.venue_order_id,
                    execution.client_order_id,
                    asset_ids[execution.asset_id],
                    execution.side,
                    execution.quantity,
                    execution.price,
                    execution.executed_at,
                )
                for execution in sorted(record.executions, key=lambda item: item.execution_id)
            )
            view = _issue_account_view(
                account_id,
                open_orders,
                positions,
                record.broker_revision,
                executions,
                record.executions_since,
                complete=True,
            )
            self._oms_evidence.observe_account_view(record)
            return view
        except BrokerPortError:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW) from None

    def read_order(self, order: OrderSnapshot) -> BrokerObservation | None:
        self._assert_configuration()
        self._check_order_scope(order)
        client_id = order.request.client_order_id
        if type(client_id) is not str:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        try:
            record = self._transport.get_order_by_client_id(client_id)
        except Exception as exc:
            self._raise_transport(exc, BrokerUnknownCode.UNKNOWN_READ_ORDER, read_only=True)
        if record is None and order.venue_order_id is not None:
            try:
                record = self._transport.get_order_by_venue_id(order.venue_order_id)
            except Exception as exc:
                self._raise_transport(exc, BrokerUnknownCode.UNKNOWN_READ_ORDER, read_only=True)
        if record is None:
            return None
        if (
            record.account_id != self._binding.account_id
            or record.client_order_id != client_id
            or (order.venue_order_id is not None and record.venue_order_id != order.venue_order_id)
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_READ_ORDER)
        return self._observation(record)

    def cancel(self, order: OrderSnapshot) -> CancelResultV1:
        self._assert_configuration()
        self._check_order_scope(order)
        client_id = order.request.client_order_id
        if type(client_id) is not str:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        try:
            view = self.read_account_view(order.request.account_id)
        except (BrokerOutcomeUnknown, BrokerRejected):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL) from None
        if order.venue_order_id is not None and any(
            item.venue_order_id == order.venue_order_id and item.client_order_id != client_id
            for item in view.open_orders
        ):
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        matches = tuple(item for item in view.open_orders if item.client_order_id == client_id)
        if len(matches) != 1 or matches[0].venue_order_id is None:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        venue_order_id = matches[0].venue_order_id
        if order.venue_order_id is not None and order.venue_order_id != venue_order_id:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        try:
            confirmed = self._transport.delete_order(venue_order_id)
        except Exception as exc:
            self._raise_transport(exc, BrokerUnknownCode.UNKNOWN_CANCEL)
        return _issue_cancel_result(confirmed)

    def _check_order_scope(self, order: OrderSnapshot) -> None:
        if not isinstance(order, OrderSnapshot):
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        if order.request.account_id != self._binding.account_id:
            raise BrokerRejected(BrokerRejectionCode.ACCOUNT_MISMATCH)
        if order.request.environment != "paper" or order.request.venue != "ALPACA":
            raise BrokerRejected(BrokerRejectionCode.ENVIRONMENT_MISMATCH)

    def _check_clock_skew(self, record: AlpacaAccountRecordV1) -> None:
        try:
            now = self._clock_ns()
        except Exception:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
        if (
            type(now) is not int
            or now < 0
            or type(record.venue_time_ns) is not int
            or record.venue_time_ns < 0
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        if abs(now - record.venue_time_ns) >= 250_000_000:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)

    def _check_sell_capacity(
        self,
        request: OrderRequest,
        payload: AlpacaOrderPayloadV1,
        view: AccountViewV1,
        record: AlpacaAccountRecordV1,
    ) -> Decimal:
        if record.broker_revision != view.broker_revision:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        asset_ids = {asset.asset_id for asset in self._assets.assets}
        if any(
            item.asset_id is None
            or item.side is None
            or item.quantity is None
            or item.asset_id not in asset_ids
            for item in record.open_orders
        ):
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        available = dict(view.positions).get(request.instrument_id, Decimal(0))
        try:
            for item in record.open_orders:
                if item.asset_id == request.native_contract_id and item.side == "SELL":
                    assert item.quantity is not None
                    available = exact_sub(available, exact_sub(item.quantity, item.filled_quantity))
        except NumericError:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
        if payload.quantity > available:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        return available

    def submit(
        self, request: OrderRequest, permit: DispatchPermitV1, expected_revision: int
    ) -> SubmitResultV1:
        """Consume the OMS permit, reconcile, then make at most one fake POST."""
        self._assert_configuration()
        if not isinstance(request, OrderRequest):
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        try:
            parse_int(expected_revision, field="broker_revision", min_value=0, max_value=2**63 - 1)
        except NumericError:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER) from None
        if request.environment != "paper":
            return _issue_submit_result(
                None, OrderState.REJECTED, BrokerRejectionCode.ENVIRONMENT_MISMATCH
            )
        if request.account_id != self._binding.account_id:
            return _issue_submit_result(
                None, OrderState.REJECTED, BrokerRejectionCode.ACCOUNT_MISMATCH
            )
        if request.venue != "ALPACA":
            return _issue_submit_result(
                None, OrderState.REJECTED, BrokerRejectionCode.INVALID_ORDER
            )
        client_id = request.client_order_id
        if type(client_id) is not str:
            return _issue_submit_result(
                None, OrderState.REJECTED, BrokerRejectionCode.INVALID_ORDER
            )
        try:
            spec = AlpacaOrderSpecV1(
                instrument_id=request.instrument_id,
                native_contract_id=request.native_contract_id,
                side=request.side,
                quantity=request.quantity,
                order_type=request.order_type,
                time_in_force=request.time_in_force,
                client_order_id=client_id,
                limit_price=request.limit_price,
            )
            payload = map_alpaca_order(spec, self._assets)
        except AlpacaMappingError as exc:
            if exc.code == "UNSUPPORTED_ORDER_CLASS":
                code = BrokerRejectionCode.UNSUPPORTED_ORDER_CLASS
            elif exc.code in {"UNSUPPORTED_INSTRUMENT", "FRACTIONAL_UNSUPPORTED"}:
                code = BrokerRejectionCode.UNSUPPORTED_INSTRUMENT
            else:
                code = BrokerRejectionCode.INVALID_ORDER
            return _issue_submit_result(None, OrderState.REJECTED, code)
        try:
            order_id = permit.order_id
            _id(order_id, "INVALID_PERMIT")
            permit.consume(order_id, request.digest, expected_revision)
        except Exception:
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER) from None
        try:
            view = self.read_account_view(request.account_id)
        except BrokerOutcomeUnknown:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
        except BrokerRejected as exc:
            if exc.code == BrokerRejectionCode.RATE_LIMITED.value:
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
            raise
        view.assert_sealed()
        if view.broker_revision != expected_revision:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        record = self._last_account
        if record is None:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        self._check_clock_skew(record)
        if any(item.client_order_id == client_id for item in view.open_orders) or any(
            item.client_order_id == client_id for item in view.executions
        ):
            return _issue_submit_result(
                None, OrderState.REJECTED, BrokerRejectionCode.DUPLICATE_CLIENT_ORDER_ID
            )
        sell_available: Decimal | None = None
        if request.side == "SELL":
            sell_available = self._check_sell_capacity(request, payload, view, record)
        try:
            prior = self._transport.get_order_by_client_id(client_id)
        except Exception as exc:
            self._raise_transport(exc, BrokerUnknownCode.UNKNOWN_SUBMIT)
        if prior is not None:
            if prior.account_id != request.account_id or prior.client_order_id != client_id:
                raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
            return _issue_submit_result(
                None, OrderState.REJECTED, BrokerRejectionCode.DUPLICATE_CLIENT_ORDER_ID
            )
        if client_id in self._attempted_client_ids:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        if sell_available is not None:
            self._oms_evidence.reserve_sell(
                request, order_id, payload.quantity, sell_available, record
            )
        self._attempted_client_ids.add(client_id)
        try:
            submitted = self._transport.post_order(payload)
        except RecordedHttpError as exc:
            if (
                400 <= exc.status_code < 500
                and exc.status_code != 429
                and exc.reason_code == "DUPLICATE_CLIENT_ORDER_ID"
            ):
                try:
                    existing = self._transport.get_order_by_client_id(client_id)
                except Exception:
                    raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
                if (
                    existing is None
                    or existing.account_id != request.account_id
                    or existing.client_order_id != client_id
                ):
                    raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
                return _issue_submit_result(
                    None, OrderState.REJECTED, BrokerRejectionCode.DUPLICATE_CLIENT_ORDER_ID
                )
            if 400 <= exc.status_code < 500 and exc.status_code != 429:
                return _issue_submit_result(
                    None, OrderState.REJECTED, BrokerRejectionCode.VENUE_REJECTED
                )
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
        except Exception:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT) from None
        if (
            submitted.account_id != request.account_id
            or submitted.client_order_id != payload.client_order_id
            or submitted.state not in {"new", "accepted"}
            or (
                submitted.asset_id is not None
                and (
                    submitted.asset_id != request.native_contract_id
                    or submitted.side != request.side
                    or submitted.quantity != payload.quantity
                )
            )
        ):
            self._discrepancies.append("CONFLICT")
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        return _issue_submit_result(submitted.venue_order_id, OrderState.WORKING)

    def poll_trade_updates(self) -> tuple[BrokerObservation | Fill | FillCorrection, ...]:
        """Deduplicate recorded stream updates across reconnect/replay."""
        self._assert_configuration()
        try:
            updates = self._transport.poll_trade_updates()
        except Exception as exc:
            self._raise_transport(exc, BrokerUnknownCode.UNKNOWN_READ_ORDER, read_only=True)
        output: list[BrokerObservation | Fill | FillCorrection] = []
        for update in updates:
            if update.account_id != self._binding.account_id:
                raise AlpacaPaperError("TRADE_UPDATE_ACCOUNT_MISMATCH")
            cursor: int | str = (
                update.event_sequence
                if update.event_sequence is not None
                else update.event_time.isoformat()
            )
            key = (update.venue_order_id, update.event_type, cursor)
            digest = sha256(
                canonical_json(
                    [
                        update.venue_order_id,
                        update.client_order_id,
                        update.account_id,
                        update.event_type,
                        update.event_time.isoformat(),
                        update.event_sequence,
                        update.execution_id,
                        canonical_str(update.quantity) if update.quantity is not None else None,
                        canonical_str(update.price) if update.price is not None else None,
                        update.correction_id,
                        update.revision,
                    ]
                )
            ).digest()
            prior = self._seen_updates.get(key)
            if prior is not None:
                if prior != digest:
                    raise AlpacaPaperError("TRADE_UPDATE_DISCREPANCY")
                continue
            if update.event_type in {"partial_fill", "fill"}:
                assert update.execution_id is not None
                assert update.quantity is not None
                assert update.price is not None
                output.append(
                    Fill(
                        venue="ALPACA",
                        account_id=update.account_id,
                        execution_id=update.execution_id,
                        quantity=update.quantity,
                        price=update.price,
                        occurred_at=update.event_time,
                    )
                )
            elif update.event_type == "correction":
                assert update.execution_id is not None
                assert update.correction_id is not None
                assert update.revision is not None
                assert update.quantity is not None
                output.append(
                    FillCorrection(
                        venue="ALPACA",
                        account_id=update.account_id,
                        execution_id=update.execution_id,
                        correction_id=update.correction_id,
                        revision=update.revision,
                        revised_quantity=update.quantity,
                        revised_price=update.price,
                        occurred_at=update.event_time,
                    )
                )
            else:
                output.append(
                    BrokerObservation(
                        observation_id=_observation_id(
                            [update.venue_order_id, update.event_type, cursor]
                        ),
                        environment="paper",
                        account_id=update.account_id,
                        venue="ALPACA",
                        client_order_id=update.client_order_id,
                        status=_EVENT_STATES[update.event_type],
                        observed_at=update.event_time,
                        venue_order_id=update.venue_order_id,
                        broker_sequence=update.event_sequence,
                    )
                )
            self._seen_updates[key] = digest
        return tuple(output)
