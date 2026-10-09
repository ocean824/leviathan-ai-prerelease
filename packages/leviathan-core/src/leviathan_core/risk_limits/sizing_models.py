"""Immutable, source-linked inputs for the offline Kelly and heat kernel."""

from __future__ import annotations

import hashlib
import hmac
import re
import weakref
from contextvars import ContextVar
from dataclasses import InitVar, dataclass
from decimal import Decimal
from enum import StrEnum
from typing import NoReturn, SupportsIndex

from leviathan_core.numeric import NumericError, canonical_json, parse_decimal, parse_int
from leviathan_core.risk_limits.models import ProjectedOrderV1, RiskStateV1

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z", re.ASCII)
_NS_MAX = 2**63 - 1
_ISSUER = object()
_ISSUING: ContextVar[bool] = ContextVar("risk004_issuing", default=False)
_ISSUED: dict[int, tuple[weakref.ReferenceType[SizingDecisionV1], bytes]] = {}


class SizingEvidenceError(ValueError):
    """Content-free validation error with a stable machine code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ValidationStatus(StrEnum):
    VALIDATED = "VALIDATED"
    UNVALIDATED = "UNVALIDATED"
    REJECTED = "REJECTED"


def _status(value: object) -> ValidationStatus:
    if type(value) is ValidationStatus:
        return value
    if type(value) is str:
        try:
            return ValidationStatus(value)
        except ValueError:
            pass
    raise SizingEvidenceError("INVALID_VALIDATION_STATUS")


def _id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _required_id(value: object) -> None:
    if not _id(value):
        raise SizingEvidenceError("INVALID_IDENTIFIER")


def _ns(value: object) -> None:
    try:
        parse_int(value, field="timestamp", min_value=0, max_value=_NS_MAX)
    except NumericError:
        raise SizingEvidenceError("INVALID_TIMESTAMP") from None


def _amount(
    value: object, *, minimum: Decimal | None = None, maximum: Decimal | None = None
) -> None:
    if type(value) is not Decimal:
        raise SizingEvidenceError("INVALID_DECIMAL")
    try:
        parse_decimal(value, field="value", min_value=minimum, max_value=maximum)
    except NumericError as error:
        raise SizingEvidenceError(error.code) from None


class _FrozenRecord:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise TypeError("sizing evidence cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("sizing evidence cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("sizing evidence cannot be serialized")

    def __setstate__(self, _state: object) -> NoReturn:
        raise TypeError("sizing evidence cannot be restored")


@dataclass(frozen=True, slots=True)
class EquitySnapshotV1(_FrozenRecord):
    account_id: str
    state_event_id: str
    broker_source_id: str
    equity: Decimal
    buying_power: Decimal
    event_ns: int
    received_ns: int

    def __post_init__(self) -> None:
        for value in (self.account_id, self.state_event_id, self.broker_source_id):
            _required_id(value)
        _amount(self.equity, minimum=Decimal(0))
        _amount(self.buying_power, minimum=Decimal(0))
        if self.equity == 0:
            raise SizingEvidenceError("EQUITY_INVALID")
        _ns(self.event_ns)
        _ns(self.received_ns)
        if self.event_ns > self.received_ns:
            raise SizingEvidenceError("INVALID_TIMESTAMP")


@dataclass(frozen=True, slots=True)
class PayoffEstimateV1(_FrozenRecord):
    strategy_id: str
    win_probability: Decimal
    win_payoff: Decimal
    loss_payoff: Decimal
    sample_count: int
    uncertainty_fraction: Decimal
    source_id: str
    revision: str
    event_ns: int
    received_ns: int
    validation_status: str

    def __post_init__(self) -> None:
        for value in (self.strategy_id, self.source_id, self.revision):
            _required_id(value)
        _amount(self.win_probability, minimum=Decimal(0), maximum=Decimal(1))
        _amount(self.win_payoff, minimum=Decimal(0))
        _amount(self.loss_payoff, minimum=Decimal(0))
        _amount(self.uncertainty_fraction, minimum=Decimal(0), maximum=Decimal(1))
        try:
            parse_int(self.sample_count, field="sample_count", min_value=0, max_value=_NS_MAX)
        except NumericError:
            raise SizingEvidenceError("INVALID_SAMPLE_COUNT") from None
        _ns(self.event_ns)
        _ns(self.received_ns)
        if self.event_ns > self.received_ns:
            raise SizingEvidenceError("INVALID_TIMESTAMP")
        object.__setattr__(self, "validation_status", _status(self.validation_status))


@dataclass(frozen=True, slots=True)
class CorrelationClusterV1(_FrozenRecord):
    instrument_id: str
    cluster_id: str
    source_id: str
    revision: str
    event_ns: int
    received_ns: int
    validation_status: str

    def __post_init__(self) -> None:
        for value in (self.instrument_id, self.cluster_id, self.source_id, self.revision):
            _required_id(value)
        _ns(self.event_ns)
        _ns(self.received_ns)
        if self.event_ns > self.received_ns:
            raise SizingEvidenceError("INVALID_TIMESTAMP")
        object.__setattr__(self, "validation_status", _status(self.validation_status))


@dataclass(frozen=True, slots=True)
class StopLossV1(_FrozenRecord):
    """Adverse loss per unit in instrument currency; absent evidence uses full notional."""

    instrument_id: str
    request_id: str | None
    attempt_id: str | None
    loss_per_unit: Decimal
    source_id: str
    revision: str
    event_ns: int
    received_ns: int
    validation_status: str

    def __post_init__(self) -> None:
        for value in (self.instrument_id, self.source_id, self.revision):
            _required_id(value)
        if (self.request_id is None) != (self.attempt_id is None):
            raise SizingEvidenceError("STOP_SELECTOR_INVALID")
        if self.request_id is not None:
            _required_id(self.request_id)
            _required_id(self.attempt_id)
        _amount(self.loss_per_unit, minimum=Decimal(0))
        if self.loss_per_unit == 0:
            raise SizingEvidenceError("STOP_LOSS_INVALID")
        _ns(self.event_ns)
        _ns(self.received_ns)
        if self.event_ns > self.received_ns:
            raise SizingEvidenceError("INVALID_TIMESTAMP")
        object.__setattr__(self, "validation_status", _status(self.validation_status))


@dataclass(frozen=True, slots=True)
class SizingPolicyV1(_FrozenRecord):
    revision: str
    account_id: str
    strategy_id: str
    effective_from_ns: int
    effective_until_ns: int
    kelly_fraction_cap: Decimal
    portfolio_heat_fraction_cap: Decimal
    cluster_heat_fraction_cap: Decimal
    lot_step: Decimal

    def __post_init__(self) -> None:
        for value in (self.revision, self.account_id, self.strategy_id):
            _required_id(value)
        _ns(self.effective_from_ns)
        _ns(self.effective_until_ns)
        if self.effective_from_ns >= self.effective_until_ns:
            raise SizingEvidenceError("POLICY_INTERVAL_INVALID")
        _amount(self.kelly_fraction_cap, minimum=Decimal(0), maximum=Decimal(1))
        _amount(self.portfolio_heat_fraction_cap, minimum=Decimal(0))
        _amount(self.cluster_heat_fraction_cap, minimum=Decimal(0))
        _amount(self.lot_step, minimum=Decimal(0))
        if self.lot_step == 0:
            raise SizingEvidenceError("POLICY_OUT_OF_BOUNDS")


@dataclass(frozen=True, slots=True)
class SizingEvidenceV1(_FrozenRecord):
    order: ProjectedOrderV1
    state: RiskStateV1
    equity: EquitySnapshotV1
    payoff: PayoffEstimateV1 | None
    correlations: tuple[CorrelationClusterV1, ...] | None
    policy: SizingPolicyV1 | None
    stops: tuple[StopLossV1, ...] | None = None

    def __post_init__(self) -> None:
        if (
            type(self.order) is not ProjectedOrderV1
            or type(self.state) is not RiskStateV1
            or type(self.equity) is not EquitySnapshotV1
            or (self.payoff is not None and type(self.payoff) is not PayoffEstimateV1)
            or (self.policy is not None and type(self.policy) is not SizingPolicyV1)
            or (
                self.correlations is not None
                and (
                    type(self.correlations) is not tuple
                    or any(type(item) is not CorrelationClusterV1 for item in self.correlations)
                )
            )
            or (
                self.stops is not None
                and (
                    type(self.stops) is not tuple
                    or any(type(item) is not StopLossV1 for item in self.stops)
                )
            )
        ):
            raise SizingEvidenceError("EVIDENCE_INVALID")


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class SizingDecisionV1(_FrozenRecord):
    status: str
    max_quantity: Decimal
    reason_codes: tuple[str, ...]
    input_revision: str | None
    policy_revision: str | None
    evidence_digest: str
    as_of_ns: int
    _issuer: InitVar[object] = None

    def __init__(
        self,
        status: str,
        max_quantity: Decimal,
        reason_codes: tuple[str, ...],
        input_revision: str | None,
        policy_revision: str | None,
        evidence_digest: str,
        as_of_ns: int,
        _issuer: object = None,
    ) -> None:
        entry = _ISSUED.get(id(self))
        if (
            _issuer is not _ISSUER
            or not _ISSUING.get()
            or (entry is not None and entry[0]() is self)
        ):
            raise SizingEvidenceError("UNISSUED_DECISION")
        for name, value in (
            ("status", status),
            ("max_quantity", max_quantity),
            ("reason_codes", reason_codes),
            ("input_revision", input_revision),
            ("policy_revision", policy_revision),
            ("evidence_digest", evidence_digest),
            ("as_of_ns", as_of_ns),
        ):
            object.__setattr__(self, name, value)
        self.__post_init__(_issuer)

    def __post_init__(self, _issuer: object) -> None:
        entry = _ISSUED.get(id(self))
        if (
            _issuer is not _ISSUER
            or not _ISSUING.get()
            or (entry is not None and entry[0]() is self)
        ):
            raise SizingEvidenceError("UNISSUED_DECISION")
        if (
            type(self.status) is not str
            or self.status not in ("SIZE", "DENY")
            or type(self.reason_codes) is not tuple
            or not self.reason_codes
        ):
            raise SizingEvidenceError("DECISION_INVALID")
        if any(not _id(code) for code in self.reason_codes):
            raise SizingEvidenceError("DECISION_INVALID")
        _amount(self.max_quantity, minimum=Decimal(0))
        if self.status == "DENY" and self.max_quantity != 0:
            raise SizingEvidenceError("DECISION_INVALID")
        if self.status == "SIZE" and self.max_quantity == 0:
            raise SizingEvidenceError("DECISION_INVALID")
        if self.input_revision is not None:
            _required_id(self.input_revision)
        if self.policy_revision is not None:
            _required_id(self.policy_revision)
        if (
            type(self.evidence_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.evidence_digest, re.ASCII) is None
        ):
            raise SizingEvidenceError("DECISION_INVALID")
        _ns(self.as_of_ns)
        identity = id(self)

        def forget(reference: weakref.ReferenceType[SizingDecisionV1]) -> None:
            entry = _ISSUED.get(identity)
            if entry is not None and entry[0] is reference:
                _ISSUED.pop(identity, None)

        _ISSUED[identity] = (weakref.ref(self, forget), _decision_fingerprint(self))


def _decision_fingerprint(value: SizingDecisionV1) -> bytes:
    document = {
        "status": value.status,
        "max_quantity": value.max_quantity,
        "reason_codes": value.reason_codes,
        "input_revision": value.input_revision,
        "policy_revision": value.policy_revision,
        "evidence_digest": value.evidence_digest,
        "as_of_ns": value.as_of_ns,
    }
    return hashlib.sha256(canonical_json(document)).digest()


def _mint_decision(
    status: str,
    max_quantity: Decimal,
    reason_codes: tuple[str, ...],
    input_revision: str | None,
    policy_revision: str | None,
    evidence_digest: str,
    as_of_ns: int,
) -> SizingDecisionV1:
    token = _ISSUING.set(True)
    try:
        return SizingDecisionV1(
            status,
            max_quantity,
            reason_codes,
            input_revision,
            policy_revision,
            evidence_digest,
            as_of_ns,
            _issuer=_ISSUER,
        )
    finally:
        _ISSUING.reset(token)


def _issued_decision(value: object) -> bool:
    if type(value) is not SizingDecisionV1:
        return False
    entry = _ISSUED.get(id(value))
    if entry is None or entry[0]() is not value:
        return False
    try:
        return hmac.compare_digest(entry[1], _decision_fingerprint(value))
    except (NumericError, TypeError, ValueError):
        return False
