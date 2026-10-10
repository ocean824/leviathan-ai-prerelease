"""Frozen, fake-only OMS inputs and public order views.

These types do not turn a C-101 paper intent into a broker order.  An OMS
request has its own explicit account, contract and caller identity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from base64 import b32encode
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal, Inexact, InvalidOperation, localcontext
from enum import StrEnum
from typing import TYPE_CHECKING, Any, NoReturn, SupportsIndex

from leviathan_core.numeric import canonical_json

if TYPE_CHECKING:
    from leviathan_core.execution.broker_reconciliation import (
        BrokerAccountView,
        BrokerLookup,
    )

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_STORED_DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:E[+-]?[0-9]+)?\Z", re.ASCII)


class OMSError(RuntimeError):
    """An OMS denial with a stable, input-free audit code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class OMSValidationError(OMSError):
    """Invalid request, evidence or broker observation."""


class OMSConflict(OMSError):  # noqa: N818 - frozen public contract name
    """A durable idempotency or lifecycle conflict."""


class OMSStaleBrokerView(OMSConflict):
    """The broker revision advanced; the port placed no order."""

    def __init__(self) -> None:
        super().__init__("STALE_BROKER_VIEW")


class OMSDiscrepancy(OMSConflict):
    """Contradictory broker evidence was retained and quarantined."""


class OMSLedgerCorruption(OMSValidationError):  # noqa: N818 - stable public contract name
    """Stored OMS evidence failed typed validation or replay invariants."""

    def __init__(self) -> None:
        super().__init__("OMS_LEDGER_CORRUPT")


class OrderState(StrEnum):
    CREATED = "CREATED"
    RISK_PENDING = "RISK_PENDING"
    RISK_REJECTED = "RISK_REJECTED"
    READY = "READY"
    SUBMITTING = "SUBMITTING"
    DISPATCH_IN_FLIGHT = "DISPATCH_IN_FLIGHT"
    WORKING = "WORKING"
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    FILLED = "FILLED"
    REJECTED = "REJECTED"
    REJECTED_HALTED = "REJECTED_HALTED"
    EXPIRED = "EXPIRED"
    CANCEL_PENDING = "CANCEL_PENDING"
    CANCEL_REQUESTED_UNCONFIRMED = "CANCEL_REQUESTED_UNCONFIRMED"
    CANCELED = "CANCELED"
    UNKNOWN_SUBMIT = "UNKNOWN_SUBMIT"
    UNKNOWN_CANCEL = "UNKNOWN_CANCEL"
    RECONCILE_REQUIRED = "RECONCILE_REQUIRED"


class _FrozenInput:
    def __copy__(self) -> NoReturn:
        raise TypeError("OMS inputs cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        raise TypeError("OMS inputs cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("OMS inputs cannot be pickled")


class OrderTypeV1(StrEnum):
    """Order classes represented by the cross-venue capability contract.

    This enum describes a venue's declared support; it does not expand the
    order types accepted by the current OMS request or any broker adapter.
    Bracket/OCO behavior is handled by ``execution.brackets``.
    """

    MARKET = "MARKET"
    LIMIT = "LIMIT"
    STOP = "STOP"
    STOP_LIMIT = "STOP_LIMIT"


class TimeInForceV1(StrEnum):
    DAY = "DAY"
    GTC = "GTC"
    GTD = "GTD"
    IOC = "IOC"
    FOK = "FOK"


class PredictionOutcomeV1(StrEnum):
    YES = "YES"
    NO = "NO"


class PredictionPriceUnitV1(StrEnum):
    CENTS = "CENTS"
    PROBABILITY = "PROBABILITY"


@dataclass(frozen=True, slots=True)
class PredictionPriceV1(_FrozenInput):
    """Explicitly unit-tagged price; cents are 0..100, probability 0..1."""

    value: Decimal
    unit: PredictionPriceUnitV1

    def __post_init__(self) -> None:
        if type(self.value) is not Decimal or type(self.unit) is not PredictionPriceUnitV1:
            raise OMSValidationError("INVALID_PREDICTION_PRICE")
        value = _decimal(self.value, positive=False, code="INVALID_PREDICTION_PRICE")
        upper = Decimal(100) if self.unit is PredictionPriceUnitV1.CENTS else Decimal(1)
        if value < 0 or value > upper:
            raise OMSValidationError("INVALID_PREDICTION_PRICE")
        object.__setattr__(self, "value", value)


@dataclass(frozen=True, slots=True)
class PredictionOrderTermsV1(_FrozenInput):
    outcome: PredictionOutcomeV1
    price: PredictionPriceV1

    def __post_init__(self) -> None:
        if (
            type(self.outcome) is not PredictionOutcomeV1
            or type(self.price) is not PredictionPriceV1
        ):
            raise OMSValidationError("INVALID_PREDICTION_ORDER")


class LedgerIntegrityKey(_FrozenInput):
    """Injected signing port; material is never serialized or represented."""

    __slots__ = ("_material",)

    def __init__(self, material: bytes) -> None:
        if type(material) is not bytes or len(material) < 32:
            raise OMSLedgerCorruption()
        self._material = material

    def sign(self, payload: bytes) -> str:
        if type(payload) is not bytes:
            raise OMSLedgerCorruption()
        return hmac.new(self._material, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return type(signature) is str and hmac.compare_digest(self.sign(payload), signature)

    def __repr__(self) -> str:
        return "LedgerIntegrityKey(<redacted>)"


class ClientIdKey(_FrozenInput):
    """Keyed, venue-agnostic broker identity for one explicit intent attempt."""

    __slots__ = ("_material",)
    _material: bytes

    def __init__(self, material: bytes) -> None:
        if type(material) is not bytes or len(material) < 32:
            raise OMSValidationError("INVALID_CLIENT_ID_KEY")
        object.__setattr__(self, "_material", material)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise TypeError("client id key is frozen")

    def derive(self, account: str, intent_idempotency_key: str, attempt: int) -> str:
        _identifier(account, "INVALID_INTENT_IDENTITY")
        _identifier(intent_idempotency_key, "INVALID_INTENT_IDENTITY")
        if type(attempt) is not int:
            raise OMSValidationError("INVALID_ATTEMPT")
        if not 1 <= attempt <= 16:
            raise OMSValidationError("POLICY_OUT_OF_BOUNDS")
        payload = canonical_json(
            {
                "account": account,
                "intent_idempotency_key": intent_idempotency_key,
                "attempt": attempt,
            }
        )
        digest = hmac.new(self._material, payload, hashlib.sha256).digest()
        return "oms_" + b32encode(digest).decode("ascii").rstrip("=").lower()

    def __repr__(self) -> str:
        return "ClientIdKey(<redacted>)"


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise OMSValidationError(code)
    return value


def _decimal(value: object, *, positive: bool, code: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, Decimal) or not value.is_finite():
        raise OMSValidationError(code)
    coefficient = value.as_tuple().digits
    significant = len(coefficient)
    while significant > 1 and coefficient[significant - 1] == 0:
        significant -= 1
    if significant > 34:
        raise OMSValidationError("PRECISION_EXCEEDED")
    if abs(value.adjusted()) > 38 or (positive and value <= 0):
        raise OMSValidationError(code)
    try:
        with localcontext() as context:
            context.prec = 34
            context.rounding = ROUND_HALF_EVEN
            context.traps[InvalidOperation] = True
            context.traps[Inexact] = True
            canonical = value.normalize(context)
    except (InvalidOperation, OverflowError, Inexact):
        raise OMSValidationError(code) from None
    return Decimal(0) if canonical.is_zero() else canonical


def parse_oms_decimal(
    value: object, *, positive: bool = False, code: str = "INVALID_STORED_DECIMAL"
) -> Decimal:
    """Read compact stored Decimal text without expanding an unchecked exponent."""
    if not isinstance(code, str) or code not in {
        "INVALID_STORED_DECIMAL",
        "INVALID_STORED_REQUEST",
        "INVALID_STORED_FILL",
        "INVALID_STORED_CORRECTION",
    }:
        raise OMSValidationError("INVALID_DECIMAL_ERROR_CODE")
    if not isinstance(value, str) or len(value) > 128 or _STORED_DECIMAL.fullmatch(value) is None:
        raise OMSValidationError(code)
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        raise OMSValidationError(code) from None
    return _decimal(parsed, positive=positive, code=code)


def _utc(value: object, code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise OMSValidationError(code)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class OrderRequest(_FrozenInput):
    project_id: str
    environment: str
    account_id: str
    venue: str
    instrument_id: str
    native_contract_id: str
    side: str
    quantity: Decimal
    order_type: str
    time_in_force: str
    client_order_id: str | None
    intent_idempotency_key: str
    attempt: int
    strategy_id: str
    risk_policy_digest: str
    actor_id: str
    capability: str
    limit_price: Decimal | None = None
    expires_at: datetime | None = None
    root_order_id: str | None = None
    parent_order_id: str | None = None
    _live_activation: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self._live_activation) is not bool:
            raise OMSValidationError("NON_LIVE_SCOPE_REQUIRED")
        if (
            self.project_id != "leviathan-ai"
            or not isinstance(self.environment, str)
            or self.environment not in {"paper", "demo", "live"}
            or (self.environment == "live" and not self._live_activation)
            or (self._live_activation and self.environment != "live")
        ):
            raise OMSValidationError("NON_LIVE_SCOPE_REQUIRED")
        for name in (
            "account_id",
            "venue",
            "instrument_id",
            "native_contract_id",
            "intent_idempotency_key",
            "strategy_id",
            "actor_id",
            "capability",
        ):
            _identifier(getattr(self, name), "INVALID_ORDER_IDENTITY")
        if self.client_order_id is not None:
            _identifier(self.client_order_id, "INVALID_ORDER_IDENTITY")
        if type(self.attempt) is not int:
            raise OMSValidationError("INVALID_ATTEMPT")
        if not 1 <= self.attempt <= 16:
            raise OMSValidationError("POLICY_OUT_OF_BOUNDS")
        for name in ("root_order_id", "parent_order_id"):
            value = getattr(self, name)
            if value is not None:
                _identifier(value, "INVALID_ORDER_LINK")
        if (
            not isinstance(self.side, str)
            or self.side not in {"BUY", "SELL"}
            or not isinstance(self.order_type, str)
            or self.order_type not in {"MARKET", "LIMIT"}
        ):
            raise OMSValidationError("UNSUPPORTED_ORDER")
        if not isinstance(self.time_in_force, str) or self.time_in_force not in {
            "DAY",
            "GTC",
            "GTD",
        }:
            raise OMSValidationError("UNSUPPORTED_TIF")
        if not isinstance(self.risk_policy_digest, str) or not _DIGEST.fullmatch(
            self.risk_policy_digest
        ):
            raise OMSValidationError("INVALID_POLICY_DIGEST")
        object.__setattr__(
            self, "quantity", _decimal(self.quantity, positive=True, code="INVALID_QUANTITY")
        )
        if (self.order_type == "LIMIT") != (self.limit_price is not None):
            raise OMSValidationError("INVALID_LIMIT_PRICE")
        if self.limit_price is not None:
            object.__setattr__(
                self,
                "limit_price",
                _decimal(self.limit_price, positive=True, code="INVALID_LIMIT_PRICE"),
            )
        if (self.time_in_force == "GTD") != (self.expires_at is not None):
            raise OMSValidationError("INVALID_EXPIRY")
        if self.expires_at is not None:
            object.__setattr__(self, "expires_at", _utc(self.expires_at, "INVALID_EXPIRY"))

    def payload(self) -> dict[str, str | None]:
        result: dict[str, str | None] = {}
        for field_info in fields(self):
            if field_info.name == "_live_activation":
                continue
            value = getattr(self, field_info.name)
            result[field_info.name] = (
                value.isoformat()
                if isinstance(value, datetime)
                else str(value)
                if isinstance(value, Decimal)
                else value
            )
        return result

    @classmethod
    def from_payload(cls, payload: dict[str, str | None]) -> OrderRequest:
        try:
            data: dict[str, Any] = dict(payload)
            for key in ("quantity", "limit_price"):
                if data.get(key) is not None:
                    data[key] = parse_oms_decimal(
                        data[key], positive=True, code="INVALID_STORED_REQUEST"
                    )
            if data.get("expires_at") is not None:
                data["expires_at"] = datetime.fromisoformat(str(data["expires_at"]))
            return cls(**data)
        except (InvalidOperation, TypeError, ValueError):
            raise OMSValidationError("INVALID_STORED_REQUEST") from None

    @classmethod
    def _from_live_activation(cls, **values: Any) -> OrderRequest:
        """Construct LIVE only after the trusted API activation predicate passed.

        Wire and persisted payloads always use ``from_payload`` and cannot set
        the internal construction capability.
        """
        if values.get("environment") != "live" or "_live_activation" in values:
            raise OMSValidationError("NON_LIVE_SCOPE_REQUIRED")
        paper_values = {**values, "environment": "paper"}
        request = cls(**paper_values)
        object.__setattr__(request, "environment", "live")
        object.__setattr__(request, "_live_activation", True)
        request.__post_init__()
        return request

    @property
    def digest(self) -> str:
        encoded = json.dumps(self.payload(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class PaperDispatchEvidence(_FrozenInput):
    """Synthetic proof for the fake port; it cannot certify live trading."""

    order_id: str
    request_digest: str
    account_id: str
    venue: str
    strategy_id: str
    policy_digest: str
    account_session_verified: bool
    entitled: bool
    feed_fresh: bool
    risk_approved: bool
    halt_clear: bool
    allowlisted: bool

    def __post_init__(self) -> None:
        for value in (self.order_id, self.account_id, self.venue, self.strategy_id):
            _identifier(value, "INVALID_DISPATCH_EVIDENCE")
        for value in (self.request_digest, self.policy_digest):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise OMSValidationError("INVALID_DISPATCH_EVIDENCE")
        for name in (
            "account_session_verified",
            "entitled",
            "feed_fresh",
            "risk_approved",
            "halt_clear",
            "allowlisted",
        ):
            if type(getattr(self, name)) is not bool:
                raise OMSValidationError("INVALID_DISPATCH_EVIDENCE")

    def denial_code(self, request: OrderRequest, order_id: str) -> str | None:
        if (
            self.order_id != order_id
            or self.request_digest != request.digest
            or self.account_id != request.account_id
            or self.venue != request.venue
            or self.strategy_id != request.strategy_id
            or self.policy_digest != request.risk_policy_digest
        ):
            return "DISPATCH_SCOPE_MISMATCH"
        for name, code in (
            ("account_session_verified", "ACCOUNT_UNVERIFIED"),
            ("entitled", "ENTITLEMENT_UNVERIFIED"),
            ("feed_fresh", "FEED_STALE"),
            ("risk_approved", "RISK_NOT_APPROVED"),
            ("halt_clear", "HALT_ACTIVE"),
            ("allowlisted", "ACTIVATION_NOT_ALLOWED"),
        ):
            if not getattr(self, name):
                return code
        return None

    def payload(self) -> dict[str, str | bool]:
        return {field.name: getattr(self, field.name) for field in fields(self)}


@dataclass(frozen=True, slots=True)
class Fill(_FrozenInput):
    venue: str
    account_id: str
    execution_id: str
    quantity: Decimal
    price: Decimal
    occurred_at: datetime
    commission: Decimal = Decimal(0)

    def __post_init__(self) -> None:
        for value in (self.venue, self.account_id, self.execution_id):
            _identifier(value, "INVALID_FILL_IDENTITY")
        object.__setattr__(
            self, "quantity", _decimal(self.quantity, positive=True, code="INVALID_FILL_QUANTITY")
        )
        object.__setattr__(
            self, "price", _decimal(self.price, positive=True, code="INVALID_FILL_PRICE")
        )
        object.__setattr__(
            self, "commission", _decimal(self.commission, positive=False, code="INVALID_COMMISSION")
        )
        if self.commission < 0:
            raise OMSValidationError("INVALID_COMMISSION")
        object.__setattr__(self, "occurred_at", _utc(self.occurred_at, "INVALID_FILL_TIME"))

    def payload(self) -> dict[str, str]:
        return {
            "venue": self.venue,
            "account_id": self.account_id,
            "execution_id": self.execution_id,
            "quantity": str(self.quantity),
            "price": str(self.price),
            "commission": str(self.commission),
            "occurred_at": self.occurred_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class FillCorrection(_FrozenInput):
    """A broker's versioned revision or bust; revision 1 follows the original fill."""

    venue: str
    account_id: str
    execution_id: str
    correction_id: str
    revision: int
    revised_quantity: Decimal
    revised_price: Decimal | None
    occurred_at: datetime
    revised_commission: Decimal = Decimal(0)

    def __post_init__(self) -> None:
        for value in (self.venue, self.account_id, self.execution_id, self.correction_id):
            _identifier(value, "INVALID_FILL_CORRECTION")
        if type(self.revision) is not int or self.revision < 1:
            raise OMSValidationError("INVALID_FILL_CORRECTION")
        quantity = _decimal(self.revised_quantity, positive=False, code="INVALID_FILL_CORRECTION")
        if quantity < 0:
            raise OMSValidationError("INVALID_FILL_CORRECTION")
        object.__setattr__(self, "revised_quantity", quantity)
        if (quantity > 0) != (self.revised_price is not None):
            raise OMSValidationError("INVALID_FILL_CORRECTION")
        if self.revised_price is not None:
            object.__setattr__(
                self,
                "revised_price",
                _decimal(self.revised_price, positive=True, code="INVALID_FILL_CORRECTION"),
            )
        commission = _decimal(
            self.revised_commission, positive=False, code="INVALID_FILL_CORRECTION"
        )
        if commission < 0:
            raise OMSValidationError("INVALID_FILL_CORRECTION")
        object.__setattr__(self, "revised_commission", commission)
        object.__setattr__(self, "occurred_at", _utc(self.occurred_at, "INVALID_FILL_CORRECTION"))

    def payload(self) -> dict[str, str | int | None]:
        return {
            "venue": self.venue,
            "account_id": self.account_id,
            "execution_id": self.execution_id,
            "correction_id": self.correction_id,
            "revision": self.revision,
            "revised_quantity": str(self.revised_quantity),
            "revised_price": str(self.revised_price) if self.revised_price is not None else None,
            "revised_commission": str(self.revised_commission),
            "occurred_at": self.occurred_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class BrokerObservation(_FrozenInput):
    observation_id: str
    environment: str
    account_id: str
    venue: str
    client_order_id: str
    status: OrderState
    observed_at: datetime
    venue_order_id: str | None = None
    broker_sequence: int | None = None

    def __post_init__(self) -> None:
        for value in (self.observation_id, self.account_id, self.venue, self.client_order_id):
            _identifier(value, "INVALID_OBSERVATION")
        if (
            not isinstance(self.environment, str)
            or self.environment not in {"paper", "demo"}
            or not isinstance(self.status, OrderState)
            or self.status
            not in {
                OrderState.WORKING,
                OrderState.PARTIALLY_FILLED,
                OrderState.FILLED,
                OrderState.CANCELED,
                OrderState.REJECTED,
                OrderState.EXPIRED,
            }
        ):
            raise OMSValidationError("INVALID_OBSERVATION")
        if self.venue_order_id is not None:
            _identifier(self.venue_order_id, "INVALID_OBSERVATION")
        if self.broker_sequence is not None and (
            type(self.broker_sequence) is not int or self.broker_sequence < 0
        ):
            raise OMSValidationError("INVALID_OBSERVATION")
        object.__setattr__(self, "observed_at", _utc(self.observed_at, "INVALID_OBSERVATION"))

    def payload(self) -> dict[str, str | int | None]:
        return {
            "observation_id": self.observation_id,
            "environment": self.environment,
            "account_id": self.account_id,
            "venue": self.venue,
            "client_order_id": self.client_order_id,
            "status": self.status.value,
            "observed_at": self.observed_at.isoformat(),
            "venue_order_id": self.venue_order_id,
            "broker_sequence": self.broker_sequence,
        }


@dataclass(frozen=True, slots=True)
class OrderSnapshot(_FrozenInput):
    order_id: str
    request: OrderRequest
    state: OrderState
    version: int
    venue_order_id: str | None
    filled_quantity: Decimal
    discrepancies: tuple[str, ...]
    submit_attempted: bool
    cancel_attempted: bool

    def __post_init__(self) -> None:
        _identifier(self.order_id, "INVALID_ORDER_SNAPSHOT")
        if (
            not isinstance(self.request, OrderRequest)
            or not isinstance(self.state, OrderState)
            or type(self.version) is not int
            or self.version < 0
            or not isinstance(self.filled_quantity, Decimal)
            or not isinstance(self.discrepancies, tuple)
            or any(not isinstance(value, str) for value in self.discrepancies)
            or type(self.submit_attempted) is not bool
            or type(self.cancel_attempted) is not bool
        ):
            raise OMSValidationError("INVALID_ORDER_SNAPSHOT")


@dataclass(frozen=True, slots=True)
class DispatchGuard(_FrozenInput):
    """Authenticated account hold around one possible broker side effect."""

    environment: str
    account_id: str
    order_id: str
    action: str
    client_order_id: str
    attempt: int
    broker_revision: int
    fence_epoch: int

    def __post_init__(self) -> None:
        for value in (self.environment, self.account_id, self.order_id, self.client_order_id):
            _identifier(value, "INVALID_DISPATCH_GUARD")
        if (
            type(self.action) is not str
            or self.action not in {"SUBMIT", "CANCEL"}
            or type(self.attempt) is not int
            or not 1 <= self.attempt <= 16
            or type(self.broker_revision) is not int
            or self.broker_revision < 0
            or type(self.fence_epoch) is not int
            or self.fence_epoch < 1
        ):
            raise OMSValidationError("INVALID_DISPATCH_GUARD")


@dataclass(frozen=True, slots=True)
class OperatorGuardConfirmation(_FrozenInput):
    """A signed, single-image operator decision; the signature is never audited."""

    operator_id: str
    guard_id: str
    broker_evidence_digest: str
    signature: str

    def __post_init__(self) -> None:
        _identifier(self.operator_id, "INVALID_OPERATOR_CONFIRMATION")
        if any(
            type(value) is not str or _DIGEST.fullmatch(value) is None
            for value in (self.guard_id, self.broker_evidence_digest, self.signature)
        ):
            raise OMSValidationError("INVALID_OPERATOR_CONFIRMATION")

    def __repr__(self) -> str:
        return "OperatorGuardConfirmation(<redacted>)"


class OperatorAuthorizationKey(_FrozenInput):
    """Injected operator authorization port; tests provide synthetic material."""

    __slots__ = ("_material",)

    def __init__(self, material: bytes) -> None:
        if type(material) is not bytes or len(material) < 32:
            raise OMSValidationError("OPERATOR_KEY_REQUIRED")
        self._material = material

    @staticmethod
    def _payload(operator_id: str, guard_id: str, digest: str) -> bytes:
        return canonical_json(
            {
                "operator_id": operator_id,
                "guard_id": guard_id,
                "broker_evidence_digest": digest,
                "decision": "RELEASE_GUARD",
            }
        )

    def confirm(
        self, operator_id: str, guard_id: str, broker_evidence_digest: str
    ) -> OperatorGuardConfirmation:
        _identifier(operator_id, "INVALID_OPERATOR_CONFIRMATION")
        if any(
            type(value) is not str or _DIGEST.fullmatch(value) is None
            for value in (guard_id, broker_evidence_digest)
        ):
            raise OMSValidationError("INVALID_OPERATOR_CONFIRMATION")
        signature = hmac.new(
            self._material,
            self._payload(operator_id, guard_id, broker_evidence_digest),
            hashlib.sha256,
        ).hexdigest()
        return OperatorGuardConfirmation(operator_id, guard_id, broker_evidence_digest, signature)

    def verify(self, confirmation: OperatorGuardConfirmation) -> bool:
        if type(confirmation) is not OperatorGuardConfirmation:
            return False
        expected = self.confirm(
            confirmation.operator_id,
            confirmation.guard_id,
            confirmation.broker_evidence_digest,
        )
        return hmac.compare_digest(expected.signature, confirmation.signature)

    def __repr__(self) -> str:
        return "OperatorAuthorizationKey(<redacted>)"


@dataclass(frozen=True, slots=True)
class OperatorGuardReview(_FrozenInput):
    """Authenticated local effect journal beside a complete broker image."""

    guard: DispatchGuard
    guard_id: str
    snapshot: OrderSnapshot
    effect_journal: tuple[bytes, ...]
    broker_lookup: BrokerLookup
    broker_view: BrokerAccountView
    broker_evidence_digest: str

    def __post_init__(self) -> None:
        from leviathan_core.execution.broker_reconciliation import (
            BrokerAccountView,
            BrokerLookup,
        )

        if (
            type(self.guard) is not DispatchGuard
            or type(self.snapshot) is not OrderSnapshot
            or type(self.guard_id) is not str
            or _DIGEST.fullmatch(self.guard_id) is None
            or type(self.broker_evidence_digest) is not str
            or _DIGEST.fullmatch(self.broker_evidence_digest) is None
            or type(self.effect_journal) is not tuple
            or any(type(item) is not bytes for item in self.effect_journal)
            or type(self.broker_lookup) is not BrokerLookup
            or type(self.broker_view) is not BrokerAccountView
        ):
            raise OMSValidationError("INVALID_OPERATOR_GUARD_REVIEW")
