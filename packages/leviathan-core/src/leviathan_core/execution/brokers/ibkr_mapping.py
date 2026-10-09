"""Pure, bounded mapping from an OMS order to IBKR TWS paper order fields.

There is no SDK import or session authority in this module. ``orderRef`` uses
``LI1`` followed by base32 of the first 160 bits of SHA-256 over canonical JSON
of ``{account_id, client_order_id}``. The 35-character alias is deterministic;
the OMS client ID is never truncated or logged. A broker-side orderRef match is
evidence for the expected ID only within the exact account, never a proof of
session identity or an authorization to resubmit.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC
from decimal import Decimal
from typing import Any, NoReturn, SupportsIndex

from leviathan_core.execution.order_models import OrderRequest
from leviathan_core.numeric import NumericError, canonical_json, parse_decimal, parse_int

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_SYMBOL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z", re.ASCII)
_EXCHANGE = re.compile(r"[A-Z][A-Z0-9.]{0,19}\Z", re.ASCII)
_CURRENCY = re.compile(r"[A-Z]{3}\Z", re.ASCII)
_MAX_ORDER_ID = 2_147_483_647


class IBKRAdapterError(ValueError):
    """Closed, input-free denial code for native mapping or callback evidence."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _FrozenNative:
    def __copy__(self) -> NoReturn:
        raise TypeError("IBKR native values cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        raise TypeError("IBKR native values cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("IBKR native values cannot be pickled")


def _identifier(value: object, code: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise IBKRAdapterError(code)
    return value


def _positive_decimal(value: object, code: str) -> Decimal:
    if type(value) is not Decimal:
        raise IBKRAdapterError(code)
    try:
        parsed = parse_decimal(value, field="value")
    except NumericError:
        raise IBKRAdapterError(code) from None
    if parsed <= 0:
        raise IBKRAdapterError(code)
    return parsed


@dataclass(frozen=True, slots=True)
class IBKRContractBindingV1(_FrozenNative):
    """Exact, revisioned mapping supplied by a separately governed registry."""

    instrument_id: str
    native_contract_id: str
    con_id: int
    symbol: str
    sec_type: str
    exchange: str
    currency: str
    revision: str

    def __post_init__(self) -> None:
        _identifier(self.instrument_id, "INVALID_CONTRACT_BINDING")
        _identifier(self.native_contract_id, "INVALID_CONTRACT_BINDING")
        _identifier(self.revision, "INVALID_CONTRACT_BINDING")
        try:
            parse_int(self.con_id, field="con_id", min_value=1, max_value=_MAX_ORDER_ID)
        except NumericError:
            raise IBKRAdapterError("INVALID_CONTRACT_BINDING") from None
        if (
            type(self.symbol) is not str
            or _SYMBOL.fullmatch(self.symbol) is None
            or type(self.sec_type) is not str
            or self.sec_type not in {"STK", "CASH", "FUT", "OPT"}
            or type(self.exchange) is not str
            or _EXCHANGE.fullmatch(self.exchange) is None
            or type(self.currency) is not str
            or _CURRENCY.fullmatch(self.currency) is None
        ):
            raise IBKRAdapterError("INVALID_CONTRACT_BINDING")


@dataclass(frozen=True, slots=True)
class IBKRNativeContractV1(_FrozenNative):
    con_id: int
    symbol: str
    sec_type: str
    exchange: str
    currency: str

    def __post_init__(self) -> None:
        IBKRContractBindingV1(
            instrument_id="validation",
            native_contract_id="validation",
            con_id=self.con_id,
            symbol=self.symbol,
            sec_type=self.sec_type,
            exchange=self.exchange,
            currency=self.currency,
            revision="validation",
        )


@dataclass(frozen=True, slots=True)
class IBKRNativeOrderV1(_FrozenNative):
    account: str
    action: str
    total_quantity: Decimal
    order_type: str
    tif: str
    order_ref: str
    lmt_price: Decimal | None = None
    good_till_date: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.account, "INVALID_NATIVE_ORDER")
        if (
            type(self.action) is not str
            or self.action not in {"BUY", "SELL"}
            or type(self.order_type) is not str
            or self.order_type not in {"MKT", "LMT"}
            or type(self.tif) is not str
            or self.tif not in {"DAY", "GTC", "GTD"}
            or type(self.order_ref) is not str
            or re.fullmatch(r"LI1[A-Z2-7]{32}", self.order_ref, re.ASCII) is None
        ):
            raise IBKRAdapterError("INVALID_NATIVE_ORDER")
        object.__setattr__(
            self, "total_quantity", _positive_decimal(self.total_quantity, "INVALID_NATIVE_ORDER")
        )
        if (self.order_type == "LMT") != (self.lmt_price is not None):
            raise IBKRAdapterError("INVALID_NATIVE_ORDER")
        if self.lmt_price is not None:
            object.__setattr__(
                self, "lmt_price", _positive_decimal(self.lmt_price, "INVALID_NATIVE_ORDER")
            )
        if self.tif == "GTD":
            if (
                type(self.good_till_date) is not str
                or re.fullmatch(r"[0-9]{8} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC", self.good_till_date)
                is None
            ):
                raise IBKRAdapterError("INVALID_NATIVE_ORDER")
        elif self.good_till_date is not None:
            raise IBKRAdapterError("INVALID_NATIVE_ORDER")


def encode_order_ref(account_id: str, client_order_id: str) -> str:
    """Return the stable, account-scoped LI1 orderRef alias (35 ASCII chars)."""
    _identifier(account_id, "INVALID_CLIENT_IDENTITY")
    _identifier(client_order_id, "INVALID_CLIENT_IDENTITY")
    digest = hashlib.sha256(
        canonical_json({"account_id": account_id, "client_order_id": client_order_id})
    ).digest()[:20]
    return "LI1" + base64.b32encode(digest).decode("ascii").rstrip("=")


def map_order_request(
    request: OrderRequest, binding: IBKRContractBindingV1
) -> tuple[IBKRNativeContractV1, IBKRNativeOrderV1]:
    """Map only an exact paper IBKR order and exact instrument binding."""
    if type(request) is not OrderRequest or type(binding) is not IBKRContractBindingV1:
        raise IBKRAdapterError("INVALID_ORDER_MAPPING")
    if request.client_order_id is None:
        raise IBKRAdapterError("MISSING_CLIENT_ORDER_ID")
    if (
        request.environment != "paper"
        or request.venue != "IBKR_TWS"
        or request.instrument_id != binding.instrument_id
        or request.native_contract_id != binding.native_contract_id
    ):
        raise IBKRAdapterError("ORDER_MAPPING_MISMATCH")
    if request.time_in_force == "GTD":
        expiry = request.expires_at
        if expiry is None or expiry.microsecond != 0:
            raise IBKRAdapterError("UNREPRESENTABLE_GTD")
        good_till_date = expiry.astimezone(UTC).strftime("%Y%m%d %H:%M:%S UTC")
    else:
        good_till_date = None
    return (
        IBKRNativeContractV1(
            con_id=binding.con_id,
            symbol=binding.symbol,
            sec_type=binding.sec_type,
            exchange=binding.exchange,
            currency=binding.currency,
        ),
        IBKRNativeOrderV1(
            account=request.account_id,
            action=request.side,
            total_quantity=request.quantity,
            order_type="MKT" if request.order_type == "MARKET" else "LMT",
            tif=request.time_in_force,
            order_ref=encode_order_ref(request.account_id, request.client_order_id),
            lmt_price=request.limit_price,
            good_till_date=good_till_date,
        ),
    )
