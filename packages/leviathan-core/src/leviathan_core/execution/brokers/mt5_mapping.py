"""Exact, fake-first FOREX.com/MT5 symbol and client-correlation mapping.

The MT5 comment is limited to 29 ASCII characters here: ``LV1`` followed by
26 RFC 4648 base32 characters encoding 128 SHA-256 bits. ``magic`` carries
the following 64 bits. For n distinct account/client IDs, ideal SHA-256
birthday collision bounds are n(n-1)/2**129 for comments alone and
n(n-1)/2**193 for the (comment, magic) pair. Broker-side comment rewriting
still requires account-wide order/deal reconciliation before every dispatch.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, NoReturn, SupportsIndex

from leviathan_core.numeric import (
    NumericError,
    Ratio,
    canonical_json,
    exact_add,
    exact_mul,
    exact_sub,
    parse_decimal,
    parse_int,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_SYMBOL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_CODES = frozenset(
    {
        "INVALID_IDENTITY",
        "INVALID_SYMBOL_MAPPING",
        "MAPPING_REVISION_MISMATCH",
        "UNSUPPORTED_SYMBOL",
        "INVALID_LOT",
        "LOT_OUT_OF_BOUNDS",
        "LOT_STEP_MISMATCH",
        "INVALID_PRICE",
        "PRICE_TICK_MISMATCH",
        "STOP_DISTANCE_DENIED",
        "FROZEN_RECORD",
        "INVALID_CORRELATION",
        "INVALID_SESSION_BINDING",
        "SESSION_MISMATCH",
        "SESSION_UNAVAILABLE",
        "CLOCK_SKEW_DENIED",
        "QUOTE_STALE",
        "SESSION_CLOSED",
        "NEWS_BLACKOUT",
        "MARGIN_UNCONFIRMED",
        "DUPLICATE_CLIENT_ID",
        "BROKER_REVISION_MISMATCH",
        "UNSUPPORTED_ORDER",
        "UNSUPPORTED_TIF",
        "PERMIT_REQUIRED",
        "TRANSPORT_UNCERTAIN",
        "NATIVE_EVENT_CONFLICT",
        "NATIVE_EVENT_INVALID",
        "ACCOUNT_RECONCILE_REQUIRED",
    }
)


class MT5AdapterError(RuntimeError):
    """Closed, non-echoing MT5 denial code."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        safe_code = code if code in _CODES else "INVALID_SESSION_BINDING"
        self.code = safe_code
        super().__init__(safe_code)

    def errors(self) -> list[dict[str, str]]:
        return [{"code": self.code}]

    def json(self) -> str:
        return json.dumps(self.errors(), sort_keys=True, separators=(",", ":"))


class _FrozenRecord:
    """Runtime freeze with errors that never include a caller's attribute name."""

    __slots__ = ("_locked",)

    def _freeze(self) -> None:
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_locked", False):
            raise MT5AdapterError("FROZEN_RECORD")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> NoReturn:
        raise MT5AdapterError("FROZEN_RECORD")

    def __copy__(self) -> NoReturn:
        raise TypeError("MT5 records cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        raise TypeError("MT5 records cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("MT5 records cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("MT5 records cannot be serialized")


def _identity(value: object, *, symbol: bool = False) -> str:
    grammar = _SYMBOL if symbol else _ID
    if type(value) is not str or grammar.fullmatch(value) is None:
        raise MT5AdapterError("INVALID_IDENTITY")
    return value


def _decimal(value: object, code: str, *, positive: bool = True) -> Decimal:
    try:
        result = parse_decimal(value, field="value")
    except NumericError:
        raise MT5AdapterError(code) from None
    if (positive and result <= 0) or (not positive and result < 0):
        raise MT5AdapterError(code)
    return result


@dataclass(slots=True)
class MT5SymbolSpecV1(_FrozenRecord):
    """Operator-reviewed exact symbol, contract, volume and point mapping."""

    instrument_id: str
    native_contract_id: str
    native_symbol: str
    revision: str
    contract_size: Decimal
    lot_min: Decimal
    lot_max: Decimal
    lot_step: Decimal
    point: Decimal
    tick_size: Decimal
    digits: int
    stops_level_points: int

    def __post_init__(self) -> None:
        for name in ("instrument_id", "native_contract_id", "revision"):
            _identity(getattr(self, name))
        _identity(self.native_symbol, symbol=True)
        for name in ("contract_size", "lot_min", "lot_max", "lot_step", "point", "tick_size"):
            object.__setattr__(
                self, name, _decimal(getattr(self, name), "INVALID_SYMBOL_MAPPING")
            )
        try:
            digits = parse_int(self.digits, field="digits", min_value=0, max_value=18)
            stops = parse_int(
                self.stops_level_points,
                field="stops_level_points",
                min_value=0,
                max_value=1_000_000,
            )
            point_ratio = Ratio.from_decimals(self.tick_size, self.point)
        except NumericError:
            raise MT5AdapterError("INVALID_SYMBOL_MAPPING") from None
        if self.lot_max < self.lot_min or point_ratio.denominator != 1:
            raise MT5AdapterError("INVALID_SYMBOL_MAPPING")
        object.__setattr__(self, "digits", digits)
        object.__setattr__(self, "stops_level_points", stops)
        self._freeze()


@dataclass(slots=True)
class MT5CorrelationV1(_FrozenRecord):
    comment: str
    magic: int

    def __post_init__(self) -> None:
        if (
            type(self.comment) is not str
            or re.fullmatch(r"LV1[A-Z2-7]{26}", self.comment, re.ASCII) is None
            or type(self.magic) is not int
            or not 0 <= self.magic < 1 << 64
        ):
            raise MT5AdapterError("INVALID_CORRELATION")
        self._freeze()


def encode_correlation(account_id: str, client_order_id: str) -> MT5CorrelationV1:
    """Bind an ADR-0005 client ID to MT5 comment+magic without exposing it."""
    _identity(account_id)
    _identity(client_order_id)
    digest = hashlib.sha256(
        canonical_json(
            {
                "account_id": account_id,
                "client_order_id": client_order_id,
                "venue": "MT5",
                "v": 1,
            }
        )
    ).digest()
    comment = "LV1" + base64.b32encode(digest[:16]).decode("ascii").rstrip("=")
    return MT5CorrelationV1(comment=comment, magic=int.from_bytes(digest[16:24], "big"))


def to_native_volume(quantity: Decimal, spec: MT5SymbolSpecV1) -> Decimal:
    """Convert units to lots exactly; an off-grid quantity is denied, never rounded."""
    if type(spec) is not MT5SymbolSpecV1:
        raise MT5AdapterError("INVALID_SYMBOL_MAPPING")
    requested = _decimal(quantity, "INVALID_LOT")
    try:
        minimum_units = exact_mul(spec.contract_size, spec.lot_min)
        maximum_units = exact_mul(spec.contract_size, spec.lot_max)
        step_units = exact_mul(spec.contract_size, spec.lot_step)
        if requested < minimum_units or requested > maximum_units:
            raise MT5AdapterError("LOT_OUT_OF_BOUNDS")
        delta = exact_sub(requested, minimum_units)
        units = Ratio.from_decimals(delta, step_units)
        if units.denominator != 1:
            raise MT5AdapterError("LOT_STEP_MISMATCH")
        lots = exact_add(spec.lot_min, exact_mul(spec.lot_step, units.numerator))
    except NumericError:
        raise MT5AdapterError("INVALID_LOT") from None
    if lots > spec.lot_max:
        raise MT5AdapterError("LOT_OUT_OF_BOUNDS")
    return lots


def to_native_price(price: Decimal, spec: MT5SymbolSpecV1) -> Decimal:
    """Require an exact MT5 tick; no silent price movement is allowed."""
    if type(spec) is not MT5SymbolSpecV1:
        raise MT5AdapterError("INVALID_SYMBOL_MAPPING")
    requested = _decimal(price, "INVALID_PRICE")
    try:
        ratio = Ratio.from_decimals(requested, spec.tick_size)
    except NumericError:
        raise MT5AdapterError("INVALID_PRICE") from None
    if ratio.denominator != 1:
        raise MT5AdapterError("PRICE_TICK_MISMATCH")
    return requested


def minimum_stop_distance(spec: MT5SymbolSpecV1) -> Decimal:
    if type(spec) is not MT5SymbolSpecV1:
        raise MT5AdapterError("INVALID_SYMBOL_MAPPING")
    try:
        return exact_mul(spec.point, spec.stops_level_points)
    except NumericError:
        raise MT5AdapterError("INVALID_SYMBOL_MAPPING") from None
