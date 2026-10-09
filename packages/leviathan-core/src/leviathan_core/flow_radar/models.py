from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import ROUND_HALF_EVEN, Context, Decimal, Inexact
from enum import StrEnum
from hashlib import sha256
from json import dumps
from re import fullmatch
from typing import Final, NoReturn, SupportsIndex


class FlowError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code


class FlowValue:
    def __copy__(self) -> NoReturn:
        raise FlowError("COPY_FORBIDDEN")

    def __deepcopy__(self, memo: dict[int, bool]) -> NoReturn:
        raise FlowError("COPY_FORBIDDEN")

    def __reduce__(self) -> NoReturn:
        raise FlowError("PICKLE_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex, /) -> NoReturn:
        raise FlowError("PICKLE_FORBIDDEN")


class Entitlement(StrEnum):
    ENTITLED = "ENTITLED"
    UNVERIFIED = "UNVERIFIED"
    SYNTHETIC = "SYNTHETIC"


class OptionSide(StrEnum):
    CALL = "CALL"
    PUT = "PUT"


class TradeSide(StrEnum):
    BUY = "BUY"
    SELL = "SELL"


class PrintFlag(StrEnum):
    SWEEP = "SWEEP"
    BLOCK = "BLOCK"
    MULTI_LEG = "MULTI_LEG"
    OFF_MARKET = "OFF_MARKET"


DECIMAL_PRECISION: Final = 34
MAX_ADJUSTED_EXPONENT: Final = 38


def kernel_context() -> Context:
    context = Context(prec=DECIMAL_PRECISION, rounding=ROUND_HALF_EVEN, Emin=-999999, Emax=999999)
    context.traps[Inexact] = True
    return context


def checked_decimal(
    value: Decimal, *, positive: bool = False, nonnegative: bool = False
) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise FlowError("INVALID_DECIMAL")
    digits = list(value.as_tuple().digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
    if len(digits) > DECIMAL_PRECISION:
        raise FlowError("PRECISION_EXCEEDED")
    if value != 0 and abs(value.adjusted()) > MAX_ADJUSTED_EXPONENT:
        raise FlowError("MAGNITUDE_EXCEEDED")
    if positive and value <= 0:
        raise FlowError("INVALID_DECIMAL_RANGE")
    if nonnegative and value < 0:
        raise FlowError("INVALID_DECIMAL_RANGE")
    return value


def canonical_decimal(value: Decimal) -> str:
    checked_decimal(value)
    if value == 0:
        return "0"
    rendered = format(value, "f")
    if "." in rendered:
        return rendered.rstrip("0").rstrip(".")
    return rendered


def required_text(value: str) -> None:
    if (
        not isinstance(value, str)
        or fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", value) is None
    ):
        raise FlowError("INVALID_TEXT")


def _ns(value: int) -> None:
    if type(value) is not int or value < 0:
        raise FlowError("INVALID_UTC_NS")


@dataclass(frozen=True, slots=True)
class TradingSession(FlowValue):
    trading_day: date
    open_ns: int
    close_ns: int

    def __post_init__(self) -> None:
        if type(self.trading_day) is not date:
            raise FlowError("INVALID_TRADING_DAY")
        _ns(self.open_ns)
        _ns(self.close_ns)
        if self.open_ns >= self.close_ns:
            raise FlowError("INVALID_SESSION")


@dataclass(frozen=True, slots=True)
class SessionCalendar(FlowValue):
    sessions: tuple[TradingSession, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.sessions, tuple) or not self.sessions:
            raise FlowError("INVALID_CALENDAR")
        prior: TradingSession | None = None
        for session in self.sessions:
            if not isinstance(session, TradingSession):
                raise FlowError("INVALID_CALENDAR")
            if prior is not None and (
                session.open_ns < prior.close_ns or session.trading_day <= prior.trading_day
            ):
                raise FlowError("INVALID_CALENDAR")
            prior = session

    def session_for(self, event_ns: int) -> TradingSession | None:
        _ns(event_ns)
        return next((s for s in self.sessions if s.open_ns <= event_ns < s.close_ns), None)

    def day_index(self, trading_day: date) -> int | None:
        return next((i for i, s in enumerate(self.sessions) if s.trading_day == trading_day), None)


@dataclass(frozen=True, slots=True)
class SourceStamp(FlowValue):
    provider: str
    dataset: str
    session: str
    venue: str
    native_record_key: str
    event_ns: int
    available_ns: int
    entitlement: Entitlement
    ingest_ns: int | None = None
    request_id: str | None = None
    correction_of: str | None = None
    schema_version: str = "1"

    def __post_init__(self) -> None:
        for value in (
            self.provider,
            self.dataset,
            self.session,
            self.venue,
            self.native_record_key,
        ):
            required_text(value)
        if self.schema_version != "1":
            raise FlowError("UNSUPPORTED_SCHEMA")
        if not isinstance(self.entitlement, Entitlement):
            raise FlowError("INVALID_ENTITLEMENT")
        _ns(self.event_ns)
        _ns(self.available_ns)
        if self.ingest_ns is not None:
            _ns(self.ingest_ns)
        if self.request_id is not None:
            required_text(self.request_id)
        if self.correction_of is not None:
            required_text(self.correction_of)

    @property
    def source_key(self) -> str:
        payload = dict(
            provider=self.provider,
            dataset=self.dataset,
            session=self.session,
            venue=self.venue,
            native_record_key=self.native_record_key,
        )
        return sha256(dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class OptionPrint(FlowValue):
    stamp: SourceStamp
    ticker: str
    expiry: date
    strike: Decimal
    cp: OptionSide
    trade_side: TradeSide
    size: Decimal
    price: Decimal
    multiplier: Decimal
    flags: tuple[PrintFlag, ...] = ()
    common_order_id: str | None = None
    aggression_score: Decimal | None = None
    original_strike: Decimal | None = None
    original_size: Decimal | None = None
    adjustment_version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.stamp, SourceStamp) or type(self.expiry) is not date:
            raise FlowError("INVALID_PRINT")
        required_text(self.ticker)
        if not isinstance(self.cp, OptionSide) or not isinstance(self.trade_side, TradeSide):
            raise FlowError("INVALID_SIDE")
        for value in (self.strike, self.size, self.price, self.multiplier):
            checked_decimal(value, positive=True)
        if not isinstance(self.flags, tuple) or any(
            not isinstance(f, PrintFlag) for f in self.flags
        ):
            raise FlowError("INVALID_FLAGS")
        if len(set(self.flags)) != len(self.flags):
            raise FlowError("INVALID_FLAGS")
        if self.common_order_id is not None:
            required_text(self.common_order_id)
        if self.aggression_score is not None:
            checked_decimal(self.aggression_score, nonnegative=True)
            if self.aggression_score > 1:
                raise FlowError("INVALID_AGGRESSION_SCORE")
        if (self.adjustment_version is None) != (
            self.original_strike is None and self.original_size is None
        ):
            raise FlowError("INCOMPLETE_ADJUSTMENT")
        if self.adjustment_version is not None:
            required_text(self.adjustment_version)
        if self.original_strike is not None:
            checked_decimal(self.original_strike, positive=True)
        if self.original_size is not None:
            checked_decimal(self.original_size, positive=True)

    @property
    def record_id(self) -> str:
        payload = dict(
            source_key=self.stamp.source_key,
            event_ns=self.stamp.event_ns,
            entitlement=self.stamp.entitlement.value,
            ticker=self.ticker,
            expiry=self.expiry.isoformat(),
            strike=canonical_decimal(self.strike),
            cp=self.cp.value,
            trade_side=self.trade_side.value,
            size=canonical_decimal(self.size),
            price=canonical_decimal(self.price),
            multiplier=canonical_decimal(self.multiplier),
            flags=sorted(flag.value for flag in self.flags),
            common_order_id=self.common_order_id,
            aggression_score=None
            if self.aggression_score is None
            else canonical_decimal(self.aggression_score),
            original_strike=None
            if self.original_strike is None
            else canonical_decimal(self.original_strike),
            original_size=None
            if self.original_size is None
            else canonical_decimal(self.original_size),
            adjustment_version=self.adjustment_version,
            correction_of=self.stamp.correction_of,
        )
        return sha256(dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class Quote(FlowValue):
    stamp: SourceStamp
    ticker: str
    expiry: date
    strike: Decimal
    cp: OptionSide
    bid: Decimal
    ask: Decimal

    def __post_init__(self) -> None:
        if (
            not isinstance(self.stamp, SourceStamp)
            or type(self.expiry) is not date
            or not isinstance(self.cp, OptionSide)
        ):
            raise FlowError("INVALID_QUOTE")
        required_text(self.ticker)
        checked_decimal(self.strike, positive=True)
        checked_decimal(self.bid, nonnegative=True)
        checked_decimal(self.ask, positive=True)
        if self.bid > self.ask:
            raise FlowError("CROSSED_QUOTE")


@dataclass(frozen=True, slots=True)
class OpenInterest(FlowValue):
    stamp: SourceStamp
    ticker: str
    expiry: date
    strike: Decimal
    cp: OptionSide
    contracts: Decimal
    as_of_day: date

    def __post_init__(self) -> None:
        if (
            not isinstance(self.stamp, SourceStamp)
            or type(self.expiry) is not date
            or not isinstance(self.cp, OptionSide)
            or type(self.as_of_day) is not date
        ):
            raise FlowError("INVALID_OPEN_INTEREST")
        required_text(self.ticker)
        checked_decimal(self.strike, positive=True)
        checked_decimal(self.contracts, nonnegative=True)


@dataclass(frozen=True, slots=True)
class UnderlyingMid(FlowValue):
    stamp: SourceStamp
    ticker: str
    mid: Decimal

    def __post_init__(self) -> None:
        if not isinstance(self.stamp, SourceStamp):
            raise FlowError("INVALID_UNDERLYING")
        required_text(self.ticker)
        checked_decimal(self.mid, positive=True)
