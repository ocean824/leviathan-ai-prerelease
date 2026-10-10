"""Exact, offline mapping of US equity orders to Alpaca paper wire fields."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import NoReturn, SupportsIndex

from leviathan_core.execution.broker_port_v1 import BrokerEnvironment, BrokerVenue
from leviathan_core.execution.instrument_binding_v1 import (
    AssetClassV1,
    RollPolicyV1,
    VenueInstrumentBindingV1,
)
from leviathan_core.numeric import NumericError, Ratio, canonical_str, exact_mul, parse_decimal

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_SYMBOL = re.compile(r"[A-Z][A-Z0-9.]{0,15}\Z", re.ASCII)


class AlpacaMappingError(ValueError):
    """An input-free, closed reason for refusing an Alpaca paper order."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


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
        raise AlpacaMappingError(code)
    return value


def _positive_decimal(value: object, code: str) -> Decimal:
    try:
        parsed = parse_decimal(value, field="value")
    except NumericError:
        raise AlpacaMappingError(code) from None
    if parsed <= 0:
        raise AlpacaMappingError(code)
    return parsed


def _multiple(value: Decimal, quantum: Decimal) -> bool:
    try:
        return Ratio.of(value, quantum).denominator == 1
    except NumericError:
        raise AlpacaMappingError("INVALID_ASSET_MAPPING") from None


@dataclass(frozen=True, slots=True)
class AlpacaAssetV1(_NoCopy):
    instrument_id: str
    asset_id: str
    symbol: str
    tick_size: Decimal
    lot_size: Decimal
    round_quantity_toward_zero: bool = False
    asset_class: str = "us_equity"

    def __post_init__(self) -> None:
        _id(self.instrument_id, "INVALID_ASSET_MAPPING")
        _id(self.asset_id, "INVALID_ASSET_MAPPING")
        if not isinstance(self.symbol, str) or _SYMBOL.fullmatch(self.symbol) is None:
            raise AlpacaMappingError("INVALID_ASSET_MAPPING")
        if type(self.asset_class) is not str or self.asset_class != "us_equity":
            raise AlpacaMappingError("UNSUPPORTED_INSTRUMENT")
        if type(self.round_quantity_toward_zero) is not bool:
            raise AlpacaMappingError("INVALID_ASSET_MAPPING")
        tick = _positive_decimal(self.tick_size, "INVALID_ASSET_MAPPING")
        lot = _positive_decimal(self.lot_size, "INVALID_ASSET_MAPPING")
        if not _multiple(lot, Decimal(1)):
            raise AlpacaMappingError("FRACTIONAL_UNSUPPORTED")
        object.__setattr__(self, "tick_size", tick)
        object.__setattr__(self, "lot_size", lot)


@dataclass(frozen=True, slots=True)
class AlpacaAssetMapV1(_NoCopy):
    revision: str
    assets: tuple[AlpacaAssetV1, ...]

    def __post_init__(self) -> None:
        _id(self.revision, "INVALID_ASSET_MAPPING")
        if (
            not isinstance(self.assets, tuple)
            or not self.assets
            or any(not isinstance(asset, AlpacaAssetV1) for asset in self.assets)
        ):
            raise AlpacaMappingError("INVALID_ASSET_MAPPING")
        if (
            len({asset.instrument_id for asset in self.assets}) != len(self.assets)
            or len({asset.asset_id for asset in self.assets}) != len(self.assets)
            or len({asset.symbol for asset in self.assets}) != len(self.assets)
        ):
            raise AlpacaMappingError("DUPLICATE_ASSET_MAPPING")

    def resolve(self, instrument_id: str, native_contract_id: str) -> AlpacaAssetV1:
        _id(instrument_id, "UNMAPPED_ASSET")
        _id(native_contract_id, "UNMAPPED_ASSET")
        for asset in self.assets:
            if asset.instrument_id == instrument_id:
                if asset.asset_id != native_contract_id:
                    raise AlpacaMappingError("ASSET_ID_MISMATCH")
                return asset
        raise AlpacaMappingError("UNMAPPED_ASSET")


def to_venue_instrument_binding(
    asset: AlpacaAssetV1,
    *,
    revision: str,
    currency: str,
    session_calendar_ref: str,
    environment: BrokerEnvironment = BrokerEnvironment.PAPER,
    expiry: date | None = None,
    listed_at: date | None = None,
    last_trade: date | None = None,
    roll_policy: RollPolicyV1 = RollPolicyV1.NONE,
) -> VenueInstrumentBindingV1:
    """Adapt an Alpaca asset using caller-supplied account currency/calendar."""
    if type(asset) is not AlpacaAssetV1:
        raise AlpacaMappingError("INVALID_ASSET_MAPPING")
    try:
        return VenueInstrumentBindingV1(
            instrument_id=asset.instrument_id,
            venue=BrokerVenue.ALPACA,
            environment=environment,
            venue_symbol=asset.symbol,
            native_contract_id=asset.asset_id,
            asset_class=AssetClassV1.EQUITY,
            tick_size=asset.tick_size,
            lot_size=asset.lot_size,
            currency=currency,
            session_calendar_ref=session_calendar_ref,
            revision=revision,
            expiry=expiry,
            listed_at=listed_at,
            last_trade=last_trade,
            roll_policy=roll_policy,
        )
    except ValueError:
        raise AlpacaMappingError("INVALID_ASSET_MAPPING") from None


@dataclass(frozen=True, slots=True)
class AlpacaOrderSpecV1(_NoCopy):
    instrument_id: str
    native_contract_id: str
    side: str
    quantity: Decimal
    order_type: str
    time_in_force: str
    client_order_id: str
    limit_price: Decimal | None = None
    order_class: str = "simple"
    instrument_kind: str = "US_EQUITY"
    extended_hours: bool = False
    notional: Decimal | None = None

    def __post_init__(self) -> None:
        _id(self.instrument_id, "INVALID_INSTRUMENT_ID")
        _id(self.native_contract_id, "INVALID_ASSET_ID")
        _id(self.client_order_id, "INVALID_CLIENT_ORDER_ID")
        if type(self.order_class) is not str or self.order_class != "simple":
            raise AlpacaMappingError("UNSUPPORTED_ORDER_CLASS")
        if type(self.instrument_kind) is not str or self.instrument_kind != "US_EQUITY":
            raise AlpacaMappingError("UNSUPPORTED_INSTRUMENT")
        if type(self.extended_hours) is not bool or self.extended_hours:
            raise AlpacaMappingError("UNSUPPORTED_EXTENDED_HOURS")
        if self.notional is not None:
            raise AlpacaMappingError("UNSUPPORTED_NOTIONAL")
        if type(self.side) is not str or self.side not in {"BUY", "SELL"}:
            raise AlpacaMappingError("UNSUPPORTED_SIDE")
        if type(self.order_type) is not str or self.order_type not in {"MARKET", "LIMIT"}:
            raise AlpacaMappingError("UNSUPPORTED_ORDER_TYPE")
        if type(self.time_in_force) is not str or self.time_in_force not in {"DAY", "GTC"}:
            raise AlpacaMappingError("UNSUPPORTED_TIF")
        object.__setattr__(self, "quantity", _positive_decimal(self.quantity, "INVALID_QUANTITY"))
        if (self.order_type == "LIMIT") != (self.limit_price is not None):
            raise AlpacaMappingError("INVALID_LIMIT_PRICE")
        if self.limit_price is not None:
            object.__setattr__(
                self, "limit_price", _positive_decimal(self.limit_price, "INVALID_LIMIT_PRICE")
            )


@dataclass(frozen=True, slots=True)
class AlpacaOrderPayloadV1(_NoCopy):
    symbol: str
    quantity: Decimal
    side: str
    order_type: str
    time_in_force: str
    client_order_id: str
    limit_price: Decimal | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.symbol, str) or _SYMBOL.fullmatch(self.symbol) is None:
            raise AlpacaMappingError("INVALID_PAYLOAD")
        _id(self.client_order_id, "INVALID_PAYLOAD")
        if (
            type(self.side) is not str
            or self.side not in {"buy", "sell"}
            or type(self.order_type) is not str
            or self.order_type not in {"market", "limit"}
            or type(self.time_in_force) is not str
            or self.time_in_force not in {"day", "gtc"}
        ):
            raise AlpacaMappingError("INVALID_PAYLOAD")
        object.__setattr__(self, "quantity", _positive_decimal(self.quantity, "INVALID_PAYLOAD"))
        if (self.order_type == "limit") != (self.limit_price is not None):
            raise AlpacaMappingError("INVALID_PAYLOAD")
        if self.limit_price is not None:
            object.__setattr__(
                self, "limit_price", _positive_decimal(self.limit_price, "INVALID_PAYLOAD")
            )

    def to_wire(self) -> dict[str, str | bool]:
        """Return a fresh exact body with only the simple native order class."""
        body: dict[str, str | bool] = {
            "symbol": self.symbol,
            "qty": canonical_str(self.quantity),
            "side": self.side,
            "type": self.order_type,
            "time_in_force": self.time_in_force,
            "client_order_id": self.client_order_id,
            "order_class": "simple",
            "extended_hours": False,
        }
        if self.limit_price is not None:
            body["limit_price"] = canonical_str(self.limit_price)
        return body


def map_alpaca_order(spec: AlpacaOrderSpecV1, assets: AlpacaAssetMapV1) -> AlpacaOrderPayloadV1:
    """Validate injected tick/lot metadata and translate without price rounding."""
    if not isinstance(spec, AlpacaOrderSpecV1) or not isinstance(assets, AlpacaAssetMapV1):
        raise AlpacaMappingError("INVALID_MAPPING_INPUT")
    asset = assets.resolve(spec.instrument_id, spec.native_contract_id)
    quantity = spec.quantity
    lots = Ratio.of(quantity, asset.lot_size)
    if lots.denominator != 1:
        if not asset.round_quantity_toward_zero:
            raise AlpacaMappingError("LOT_VIOLATION")
        try:
            quantity = exact_mul(lots.numerator // lots.denominator, asset.lot_size)
        except NumericError:
            raise AlpacaMappingError("LOT_VIOLATION") from None
        if quantity <= 0:
            raise AlpacaMappingError("LOT_VIOLATION")
    if spec.limit_price is not None and not _multiple(spec.limit_price, asset.tick_size):
        raise AlpacaMappingError("TICK_VIOLATION")
    return AlpacaOrderPayloadV1(
        symbol=asset.symbol,
        quantity=quantity,
        side=spec.side.lower(),
        order_type=spec.order_type.lower(),
        time_in_force=spec.time_in_force.lower(),
        client_order_id=spec.client_order_id,
        limit_price=spec.limit_price,
    )
