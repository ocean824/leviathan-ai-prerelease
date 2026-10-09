"""Validated order inputs for the deterministic, simulation-only fill kernel."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from decimal import Decimal
from itertools import pairwise
from typing import Literal, NoReturn, SupportsIndex

from leviathan_core.numeric import NumericError, parse_decimal
from leviathan_core.seal import Issuer, SealError, require

from .events import SessionWindowV1

OrderSide = Literal["BUY", "SELL"]
OrderType = Literal["MARKET", "LIMIT", "STOP", "STOP_LIMIT"]
TimeInForce = Literal["DAY", "GTC", "IOC", "FOK"]

_MAX_UTC_NS = 253_402_300_799_999_999_999
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_CURRENCY = re.compile(r"[A-Z]{3}\Z", re.ASCII)
_REQUEST_ISSUER = Issuer("bt003.fill_request.v1")


class FillKernelError(ValueError):
    """Base for content-free fill-kernel errors."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        if type(code) is not str or not code.isascii() or not code.isupper():
            code = "FILL_ERROR"
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code


class FillValidationError(FillKernelError):
    pass


class OrderRejectedError(FillKernelError):
    pass


class FillPolicyError(FillKernelError):
    pass


class FillCapacityError(FillKernelError):
    pass


def _text(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _decimal(value: object, *, positive: bool = False, nonnegative: bool = False) -> Decimal:
    if type(value) is not Decimal:
        raise FillValidationError("INVALID_DECIMAL") from None
    parsed: Decimal
    try:
        parsed = parse_decimal(value, field="value")
    except NumericError as exc:
        code = exc.code
        raise FillValidationError(code) from None
    if (positive and parsed <= 0) or (nonnegative and parsed < 0):
        raise FillValidationError("OUT_OF_RANGE") from None
    return parsed


def _ns(value: object, *, allow_zero: bool = True) -> int:
    if (
        type(value) is not int or value < (0 if allow_zero else 1)
        or value > _MAX_UTC_NS
    ):
        raise FillValidationError("INVALID_UTC_NS") from None
    return value


class _FrozenInput:
    """Input records cannot be cloned or restored around validation."""

    def __copy__(self) -> NoReturn:
        raise FillValidationError("COPY_FORBIDDEN") from None

    def __deepcopy__(self, memo: object) -> NoReturn:
        del memo
        raise FillValidationError("COPY_FORBIDDEN") from None

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise FillValidationError("PICKLE_FORBIDDEN") from None

    def __setstate__(self, state: object) -> NoReturn:
        del state
        raise FillValidationError("RESTORE_FORBIDDEN") from None


@dataclass(frozen=True, slots=True)
class FillRequestV1(_FrozenInput):
    """One explicit order intent and the calendar window in which it may fill."""

    request_id: str
    instrument: str
    venue: str
    side: OrderSide
    order_type: OrderType
    time_in_force: TimeInForce
    quantity: Decimal
    submit_ns: int
    submit_sequence: int
    currency: str
    calendar_id: str
    calendar_version: str
    session: SessionWindowV1
    sessions: tuple[SessionWindowV1, ...]
    limit_price: Decimal | None = None
    stop_price: Decimal | None = None
    expires_ns: int | None = None
    cancel_ns: int | None = None
    cancel_sequence: int | None = None

    def __post_init__(self) -> None:
        try:
            require(self, _REQUEST_ISSUER.tag)
        except SealError as exc:
            if exc.code != "SEAL_NOT_ISSUED":
                raise FillValidationError("REQUEST_REINIT") from None
        else:
            raise FillValidationError("REQUEST_REINIT") from None
        if any(not _text(value) for value in (
            self.request_id, self.instrument, self.venue,
            self.calendar_id, self.calendar_version,
        )):
            raise FillValidationError("INVALID_IDENTIFIER") from None
        if type(self.side) is not str or self.side not in ("BUY", "SELL"):
            raise FillValidationError("INVALID_SIDE") from None
        if type(self.order_type) is not str or self.order_type not in (
            "MARKET", "LIMIT", "STOP", "STOP_LIMIT"
        ):
            raise FillValidationError("INVALID_ORDER_TYPE") from None
        if type(self.time_in_force) is not str or self.time_in_force not in (
            "DAY", "GTC", "IOC", "FOK"
        ):
            raise FillValidationError("INVALID_TIME_IN_FORCE") from None
        if type(self.session) is not SessionWindowV1:
            raise FillValidationError("INVALID_SESSION") from None
        if type(self.sessions) is not tuple or any(
            type(item) is not SessionWindowV1 for item in self.sessions
        ):
            raise FillValidationError("INVALID_SESSIONS") from None
        if type(self.currency) is not str or _CURRENCY.fullmatch(self.currency) is None:
            raise FillValidationError("INVALID_CURRENCY") from None
        quantity = _decimal(self.quantity, positive=True)
        submit_ns = _ns(self.submit_ns)
        if type(self.submit_sequence) is not int or self.submit_sequence < 0:
            raise FillValidationError("INVALID_SEQUENCE") from None
        if self.venue != self.session.venue or not (
            self.session.open_ns <= submit_ns < self.session.close_ns
        ):
            raise FillValidationError("INVALID_SESSION") from None
        pinned_sessions = self.sessions
        if (
            not pinned_sessions
            or
            any(item.venue != self.venue for item in pinned_sessions)
            or tuple(sorted(pinned_sessions, key=lambda item: item.open_ns)) != pinned_sessions
            or any(
                left.close_ns > right.open_ns
                for left, right in pairwise(pinned_sessions)
            )
            or not any(
                item.venue == self.session.venue
                and item.session_date == self.session.session_date
                and item.open_ns == self.session.open_ns
                and item.close_ns == self.session.close_ns
                for item in pinned_sessions
            )
        ):
            raise FillValidationError("INVALID_SESSIONS") from None
        if self.limit_price is not None:
            _decimal(self.limit_price, positive=True)
        if self.stop_price is not None:
            _decimal(self.stop_price, positive=True)
        if (
            self.order_type == "MARKET"
            and (self.limit_price is not None or self.stop_price is not None)
        ) or (
            self.order_type == "LIMIT" and (self.limit_price is None or self.stop_price is not None)
        ) or (
            self.order_type == "STOP" and (self.stop_price is None or self.limit_price is not None)
        ) or (
            self.order_type == "STOP_LIMIT" and (
                self.stop_price is None or self.limit_price is None
            )
        ):
            raise FillValidationError("INVALID_ORDER_PRICES") from None
        if self.expires_ns is not None:
            expires_ns = _ns(self.expires_ns, allow_zero=False)
            if self.time_in_force != "GTC" or expires_ns <= submit_ns:
                raise FillValidationError("INVALID_EXPIRY") from None
        if (self.cancel_ns is None) != (self.cancel_sequence is None):
            raise FillValidationError("INVALID_CANCEL_ORDER") from None
        if self.cancel_ns is not None:
            cancel_ns = _ns(self.cancel_ns)
            if (
                type(self.cancel_sequence) is not int or self.cancel_sequence < 0
                or cancel_ns < submit_ns
            ):
                raise FillValidationError("INVALID_CANCEL_ORDER") from None
        if quantity is not self.quantity:
            object.__setattr__(self, "quantity", quantity)
        object.__setattr__(self, "session", replace(self.session))
        object.__setattr__(self, "sessions", tuple(replace(item) for item in pinned_sessions))
        _REQUEST_ISSUER.issue(self)
