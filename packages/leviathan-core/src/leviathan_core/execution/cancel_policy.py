"""Explicit, injected policy records for fake-first cancel and flatten flows.

This module defines policy and evidence only.  It does not connect to a broker,
create an OMS order, or grant a dispatch permit.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Literal, TypeVar

from pydantic import model_validator

from leviathan_core.numeric import NumericError, parse_decimal
from leviathan_core.seal import Issuer, SealedModel, require

_ISSUER = Issuer("leviathan.execution.cancel_policy.v1")
_TAG = _ISSUER.tag
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}\Z", re.ASCII)
_MAX_NS = 2**63 - 1
_PolicyModel = TypeVar("_PolicyModel", bound=SealedModel)


class CancelPolicyCode(StrEnum):
    INVALID_POLICY = "INVALID_POLICY"
    INVALID_REQUEST = "INVALID_REQUEST"
    POLICY_REQUIRED = "CANCEL_POLICY_REQUIRED"
    FLATTEN_POLICY_REQUIRED = "FLATTEN_POLICY_REQUIRED"
    OPERATOR_NOT_ALLOWED = "OPERATOR_NOT_ALLOWED"
    SCOPE_NOT_ALLOWED = "CANCEL_SCOPE_NOT_ALLOWED"
    HALT_MASS_CANCEL_DENIED = "HALT_MASS_CANCEL_DENIED"
    HALT_FLATTEN_DENIED = "HALT_FLATTEN_DENIED"
    FLATTEN_NOT_ALLOWED = "FLATTEN_NOT_ALLOWED"
    POSITION_STALE = "POSITION_STALE"
    BROKER_EVIDENCE_MISMATCH = "BROKER_EVIDENCE_MISMATCH"
    CANCEL_OUTCOME_UNKNOWN = "UNKNOWN_CANCEL"
    CHILD_DISPATCH_STOP_FAILED = "CHILD_DISPATCH_STOP_FAILED"


class CancelPolicyError(RuntimeError):
    """Stable content-free policy error."""

    def __init__(self, code: CancelPolicyCode) -> None:
        if type(code) is not CancelPolicyCode:
            raise ValueError("INVALID_CANCEL_POLICY_ERROR")
        self.code = code.value
        super().__init__(self.code)


class CancelPolicyV1(SealedModel):
    """Operator-supplied cancel limits; every value is explicit and scoped."""

    policy_id: str
    revision: str
    account_id: str
    venue: str
    environment: Literal["paper", "demo", "live"]
    allowed_operator_ids: tuple[str, ...]
    instrument_ids: tuple[str, ...]
    strategy_ids: tuple[str, ...]
    allowed_scopes: tuple[Literal["ORDER", "INSTRUMENT", "STRATEGY", "ACCOUNT"], ...]
    halt_requests_mass_cancel: bool
    cancel_timeout_ms: int
    maximum_mass_cancel_orders: int
    protective_leg_action: Literal["PRESERVE", "CANCEL"]
    lost_connection_action: Literal["RECONCILE_AND_HOLD"]

    @model_validator(mode="after")
    def _validate_policy(self) -> CancelPolicyV1:
        if (
            not _valid_identifier(self.policy_id)
            or not _valid_identifier(self.revision)
            or not _valid_identifier(self.account_id)
            or not _valid_identifier(self.venue)
            or self.environment not in {"paper", "demo", "live"}
            or not _identifiers(self.allowed_operator_ids, allow_empty=True)
            or not _identifiers(self.instrument_ids, allow_empty=True)
            or not _identifiers(self.strategy_ids, allow_empty=True)
            or type(self.allowed_scopes) is not tuple
            or not self.allowed_scopes
            or len(set(self.allowed_scopes)) != len(self.allowed_scopes)
            or any(item not in {"ORDER", "INSTRUMENT", "STRATEGY", "ACCOUNT"}
                   for item in self.allowed_scopes)
            or type(self.halt_requests_mass_cancel) is not bool
            or type(self.cancel_timeout_ms) is not int
            or not 1 <= self.cancel_timeout_ms <= 300_000
            or type(self.maximum_mass_cancel_orders) is not int
            or not 1 <= self.maximum_mass_cancel_orders <= 10_000
            or self.protective_leg_action not in {"PRESERVE", "CANCEL"}
            or self.lost_connection_action != "RECONCILE_AND_HOLD"
        ):
            raise ValueError("INVALID_POLICY")
        return self


class FlattenPolicyV1(SealedModel):
    """Explicit user-supplied flatten envelope; no policy values are defaulted."""

    policy_id: str
    revision: str
    account_id: str
    venue: str
    environment: Literal["paper", "demo", "live"]
    operator_ids: tuple[str, ...]
    instrument_ids: tuple[str, ...]
    strategy_ids: tuple[str, ...]
    allowed_sides: tuple[Literal["BUY", "SELL"], ...]
    allowed_session_states: tuple[str, ...]
    position_source: str
    maximum_position_age_ns: int
    maximum_quantity: Decimal
    maximum_slippage_bps: Decimal

    @model_validator(mode="after")
    def _validate_policy(self) -> FlattenPolicyV1:
        try:
            quantity = parse_decimal(self.maximum_quantity, field="maximum_quantity")
            slippage = parse_decimal(self.maximum_slippage_bps, field="maximum_slippage_bps")
        except NumericError:
            raise ValueError("INVALID_POLICY") from None
        if (
            not _valid_identifier(self.policy_id)
            or not _valid_identifier(self.revision)
            or not _valid_identifier(self.account_id)
            or not _valid_identifier(self.venue)
            or self.environment not in {"paper", "demo", "live"}
            or not _identifiers(self.operator_ids)
            or not _identifiers(self.instrument_ids)
            or not _identifiers(self.strategy_ids)
            or type(self.allowed_sides) is not tuple
            or not self.allowed_sides
            or len(set(self.allowed_sides)) != len(self.allowed_sides)
            or any(side not in {"BUY", "SELL"} for side in self.allowed_sides)
            or not _identifiers(self.allowed_session_states)
            or not _valid_identifier(self.position_source)
            or type(self.maximum_position_age_ns) is not int
            or not 0 <= self.maximum_position_age_ns <= _MAX_NS
            or quantity <= 0
            or slippage < 0
        ):
            raise ValueError("INVALID_POLICY")
        object.__setattr__(self, "maximum_quantity", quantity)
        object.__setattr__(self, "maximum_slippage_bps", slippage)
        return self


class CancelRequestV1(SealedModel):
    """One exact order cancel request with caller-provided idempotency identity."""

    order_id: str
    client_order_id: str
    venue_order_id: str
    account_id: str
    venue: str
    environment: Literal["paper", "demo", "live"]
    instrument_id: str
    strategy_id: str
    side: Literal["BUY", "SELL"]
    operator_id: str
    idempotency_key: str
    scope: Literal["ORDER", "INSTRUMENT", "STRATEGY", "ACCOUNT"]
    trigger: Literal["OPERATOR", "HALT", "CHILD_TIMEOUT"]
    protective_leg: bool
    gtd_expiry_ns: int | None

    @model_validator(mode="after")
    def _validate_request(self) -> CancelRequestV1:
        if (
            not all(_valid_identifier(value) for value in (
                self.order_id, self.client_order_id, self.venue_order_id,
                self.account_id, self.venue, self.instrument_id,
                self.strategy_id, self.operator_id, self.idempotency_key,
            ))
            or self.environment not in {"paper", "demo", "live"}
            or self.scope not in {"ORDER", "INSTRUMENT", "STRATEGY", "ACCOUNT"}
            or self.trigger not in {"OPERATOR", "HALT", "CHILD_TIMEOUT"}
            or self.side not in {"BUY", "SELL"}
            or type(self.protective_leg) is not bool
            or (self.gtd_expiry_ns is not None and not _valid_ns(self.gtd_expiry_ns))
        ):
            raise ValueError("INVALID_REQUEST")
        return self


class MassCancelRequestV1(SealedModel):
    """Bounded account-scoped mass cancel; cursor permits explicit resumption."""

    account_id: str
    venue: str
    environment: Literal["paper", "demo", "live"]
    operator_id: str
    idempotency_key: str
    scope: Literal["INSTRUMENT", "STRATEGY", "ACCOUNT"]
    requests: tuple[CancelRequestV1, ...]
    start_index: int
    halt_active: bool

    @model_validator(mode="after")
    def _validate_request(self) -> MassCancelRequestV1:
        if (
            not all(_valid_identifier(value) for value in (
                self.account_id, self.venue, self.operator_id, self.idempotency_key,
            ))
            or self.environment not in {"paper", "demo", "live"}
            or self.scope not in {"INSTRUMENT", "STRATEGY", "ACCOUNT"}
            or type(self.requests) is not tuple
            or not self.requests
            or any(type(item) is not CancelRequestV1 for item in self.requests)
            or type(self.start_index) is not int
            or not 0 <= self.start_index < len(self.requests)
            or type(self.halt_active) is not bool
        ):
            raise ValueError("INVALID_REQUEST")
        if any(
            item.account_id != self.account_id
            or item.venue != self.venue
            or item.environment != self.environment
            or item.operator_id != self.operator_id
            for item in self.requests
        ):
            raise ValueError("INVALID_REQUEST")
        return self


class PositionSnapshotV1(SealedModel):
    """Fresh signed position evidence; this is not a dispatch authorization."""

    account_id: str
    venue: str
    environment: Literal["paper", "demo", "live"]
    instrument_id: str
    strategy_id: str
    position_source: str
    position_revision: str
    net_quantity: Decimal
    observed_at_ns: int

    @model_validator(mode="after")
    def _validate_position(self) -> PositionSnapshotV1:
        try:
            quantity = parse_decimal(self.net_quantity, field="net_quantity")
        except NumericError:
            raise ValueError("INVALID_POSITION") from None
        if (
            not all(_valid_identifier(value) for value in (
                self.account_id, self.venue, self.instrument_id,
                self.strategy_id, self.position_source, self.position_revision,
            ))
            or self.environment not in {"paper", "demo", "live"}
            or not _valid_ns(self.observed_at_ns)
        ):
            raise ValueError("INVALID_POSITION")
        object.__setattr__(self, "net_quantity", quantity)
        return self


class FlattenRequestV1(SealedModel):
    """Policy-only flatten request; a later OMS slot must create the guarded order."""

    account_id: str
    venue: str
    environment: Literal["paper", "demo", "live"]
    instrument_id: str
    strategy_id: str
    operator_id: str
    idempotency_key: str
    side: Literal["BUY", "SELL"]
    quantity: Decimal
    slippage_bps: Decimal
    session_state: str
    human_confirmed: bool
    halt_active: bool
    now_ns: int

    @model_validator(mode="after")
    def _validate_request(self) -> FlattenRequestV1:
        try:
            quantity = parse_decimal(self.quantity, field="quantity")
            slippage = parse_decimal(self.slippage_bps, field="slippage_bps")
        except NumericError:
            raise ValueError("INVALID_REQUEST") from None
        if (
            not all(_valid_identifier(value) for value in (
                self.account_id, self.venue, self.instrument_id, self.strategy_id,
                self.operator_id, self.idempotency_key, self.session_state,
            ))
            or self.environment not in {"paper", "demo", "live"}
            or self.side not in {"BUY", "SELL"}
            or quantity <= 0
            or slippage < 0
            or type(self.human_confirmed) is not bool
            or type(self.halt_active) is not bool
            or not _valid_ns(self.now_ns)
        ):
            raise ValueError("INVALID_REQUEST")
        object.__setattr__(self, "quantity", quantity)
        object.__setattr__(self, "slippage_bps", slippage)
        return self


class CancelBrokerEvidenceV1(SealedModel):
    """Exact broker evidence returned by a cancel attempt or reconciliation read."""

    source: Literal["CANCEL_ACK", "RECONCILIATION"]
    order_id: str
    client_order_id: str
    venue_order_id: str
    account_id: str
    venue: str
    environment: Literal["paper", "demo", "live"]
    instrument_id: str
    side: Literal["BUY", "SELL"]
    status: Literal["CANCELED", "WORKING", "PARTIALLY_FILLED", "REJECTED", "UNKNOWN_CANCEL"]
    cancel_confirmed: bool
    executions: tuple[CancelExecutionV1, ...]
    observed_at_ns: int

    @model_validator(mode="after")
    def _validate_evidence(self) -> CancelBrokerEvidenceV1:
        if (
            not all(_valid_identifier(value) for value in (
                self.order_id, self.client_order_id, self.venue_order_id,
                self.account_id, self.venue, self.instrument_id,
            ))
            or self.environment not in {"paper", "demo", "live"}
            or self.side not in {"BUY", "SELL"}
            or self.status not in {
                "CANCELED", "WORKING", "PARTIALLY_FILLED", "REJECTED", "UNKNOWN_CANCEL"
            }
            or type(self.cancel_confirmed) is not bool
            or (self.cancel_confirmed and self.status != "CANCELED")
            or type(self.executions) is not tuple
            or any(type(item) is not CancelExecutionV1 for item in self.executions)
            or not _valid_ns(self.observed_at_ns)
        ):
            raise ValueError("INVALID_BROKER_EVIDENCE")
        return self


class CancelExecutionV1(SealedModel):
    """Complete immutable execution evidence carried by a cancel reconciliation."""

    execution_id: str
    venue_order_id: str
    client_order_id: str | None
    instrument_id: str
    side: Literal["BUY", "SELL"]
    quantity: Decimal
    price: Decimal
    executed_at: datetime

    @model_validator(mode="after")
    def _validate_execution(self) -> CancelExecutionV1:
        try:
            quantity = parse_decimal(self.quantity, field="quantity")
            price = parse_decimal(self.price, field="price")
        except NumericError:
            raise ValueError("INVALID_EXECUTION") from None
        if (
            not _valid_identifier(self.execution_id)
            or not _valid_identifier(self.venue_order_id)
            or (self.client_order_id is not None and not _valid_identifier(self.client_order_id))
            or not _valid_identifier(self.instrument_id)
            or self.side not in {"BUY", "SELL"}
            or quantity <= 0
            or price <= 0
            or type(self.executed_at) is not datetime
            or self.executed_at.tzinfo is None
        ):
            raise ValueError("INVALID_EXECUTION")
        try:
            if self.executed_at.utcoffset() is None:
                raise ValueError("INVALID_EXECUTION")
            executed_at = self.executed_at.astimezone(UTC)
        except Exception:
            raise ValueError("INVALID_EXECUTION") from None
        object.__setattr__(self, "quantity", quantity)
        object.__setattr__(self, "price", price)
        object.__setattr__(self, "executed_at", executed_at)
        return self


CancelBrokerEvidenceV1.model_rebuild()


class CancelJournalRecordV1(SealedModel):
    """Durable cancel journal view; an in-flight entry is never resent blindly."""

    order_id: str
    idempotency_key: str
    state: Literal[
        "CANCEL_IN_FLIGHT", "CANCEL_REQUESTED_UNCONFIRMED", "UNKNOWN_CANCEL",
        "CANCELED", "REJECTED",
    ]
    reason_code: str
    cancel_sent: bool

    @model_validator(mode="after")
    def _validate_record(self) -> CancelJournalRecordV1:
        if (
            not _valid_identifier(self.order_id)
            or not _valid_identifier(self.idempotency_key)
            or self.state not in {
                "CANCEL_IN_FLIGHT", "CANCEL_REQUESTED_UNCONFIRMED", "UNKNOWN_CANCEL",
                "CANCELED", "REJECTED",
            }
            or not _valid_identifier(self.reason_code)
            or type(self.cancel_sent) is not bool
        ):
            raise ValueError("INVALID_CANCEL_JOURNAL")
        return self


class CancelResultV1(SealedModel):
    order_id: str
    idempotency_key: str
    lifecycle_state: Literal["CANCELED", "REJECTED", "CANCEL_REQUESTED_UNCONFIRMED"]
    oms_state: Literal["CANCELED", "UNKNOWN_CANCEL"] | None
    reason_code: str
    child_dispatch_stopped: bool
    cancel_sent: bool
    reconciled: bool
    discrepancy_codes: tuple[str, ...]
    operator_alert_codes: tuple[str, ...]
    fill_execution_ids: tuple[str, ...]

    @model_validator(mode="after")
    def _validate_result(self) -> CancelResultV1:
        if (
            not _valid_identifier(self.order_id)
            or not _valid_identifier(self.idempotency_key)
            or self.lifecycle_state not in {
                "CANCELED", "REJECTED", "CANCEL_REQUESTED_UNCONFIRMED"
            }
            or (
                self.lifecycle_state == "CANCELED"
                and self.oms_state != "CANCELED"
            )
            or (
                self.lifecycle_state == "CANCEL_REQUESTED_UNCONFIRMED"
                and self.oms_state != "UNKNOWN_CANCEL"
            )
            or (self.lifecycle_state == "REJECTED" and self.oms_state is not None)
            or not _valid_identifier(self.reason_code)
            or type(self.child_dispatch_stopped) is not bool
            or type(self.cancel_sent) is not bool
            or type(self.reconciled) is not bool
            or not _identifiers(self.discrepancy_codes, allow_empty=True)
            or not _identifiers(self.operator_alert_codes, allow_empty=True)
            or not _identifiers(self.fill_execution_ids, allow_empty=True)
        ):
            raise ValueError("INVALID_CANCEL_RESULT")
        return self


class MassCancelResultV1(SealedModel):
    request_idempotency_key: str
    results: tuple[CancelResultV1, ...]
    start_index: int
    next_index: int | None
    complete: bool

    @model_validator(mode="after")
    def _validate_result(self) -> MassCancelResultV1:
        if (
            not _valid_identifier(self.request_idempotency_key)
            or type(self.results) is not tuple
            or any(type(item) is not CancelResultV1 for item in self.results)
            or type(self.start_index) is not int
            or self.start_index < 0
            or (self.next_index is not None and type(self.next_index) is not int)
            or (self.next_index is not None and self.next_index <= self.start_index)
            or type(self.complete) is not bool
            or self.complete != (self.next_index is None)
        ):
            raise ValueError("INVALID_MASS_CANCEL_RESULT")
        return self


class FlattenDecisionV1(SealedModel):
    """Eligibility result only; approval never supplies OMS or broker authority."""

    policy_id: str | None
    approved_for_oms_review: bool
    denial_code: str | None
    dispatch_permitted: bool
    requires_fresh_risk_halt_oms_checks: bool

    @model_validator(mode="after")
    def _validate_decision(self) -> FlattenDecisionV1:
        if (
            (self.policy_id is not None and not _valid_identifier(self.policy_id))
            or type(self.approved_for_oms_review) is not bool
            or (self.denial_code is not None and not _valid_identifier(self.denial_code))
            or type(self.dispatch_permitted) is not bool
            or self.dispatch_permitted
            or type(self.requires_fresh_risk_halt_oms_checks) is not bool
            or self.requires_fresh_risk_halt_oms_checks != self.approved_for_oms_review
            or self.approved_for_oms_review != (self.denial_code is None)
        ):
            raise ValueError("INVALID_FLATTEN_DECISION")
        return self


def _valid_identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _identifiers(values: object, *, allow_empty: bool = False) -> bool:
    return (
        type(values) is tuple
        and (allow_empty or bool(values))
        and all(_valid_identifier(value) for value in values)
        and len(set(values)) == len(values)
    )


def _valid_ns(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_NS


def issue_cancel_policy(value: CancelPolicyV1) -> CancelPolicyV1:
    return _issue(value, CancelPolicyV1)


def issue_flatten_policy(value: FlattenPolicyV1) -> FlattenPolicyV1:
    return _issue(value, FlattenPolicyV1)


def issue_cancel_request(value: CancelRequestV1) -> CancelRequestV1:
    return _issue(value, CancelRequestV1)


def issue_mass_cancel_request(value: MassCancelRequestV1) -> MassCancelRequestV1:
    return _issue(value, MassCancelRequestV1)


def issue_position_snapshot(value: PositionSnapshotV1) -> PositionSnapshotV1:
    return _issue(value, PositionSnapshotV1)


def issue_flatten_request(value: FlattenRequestV1) -> FlattenRequestV1:
    return _issue(value, FlattenRequestV1)


def issue_cancel_broker_evidence(value: CancelBrokerEvidenceV1) -> CancelBrokerEvidenceV1:
    return _issue(value, CancelBrokerEvidenceV1)


def issue_cancel_execution(value: CancelExecutionV1) -> CancelExecutionV1:
    return _issue(value, CancelExecutionV1)


def issue_cancel_journal_record(value: CancelJournalRecordV1) -> CancelJournalRecordV1:
    return _issue(value, CancelJournalRecordV1)


def issue_cancel_result(value: CancelResultV1) -> CancelResultV1:
    return _issue(value, CancelResultV1)


def issue_mass_cancel_result(value: MassCancelResultV1) -> MassCancelResultV1:
    return _issue(value, MassCancelResultV1)


def issue_flatten_decision(value: FlattenDecisionV1) -> FlattenDecisionV1:
    return _issue(value, FlattenDecisionV1)


def require_cancel_policy(value: object) -> CancelPolicyV1:
    return _require(value, CancelPolicyV1)


def require_flatten_policy(value: object) -> FlattenPolicyV1:
    return _require(value, FlattenPolicyV1)


def require_cancel_request(value: object) -> CancelRequestV1:
    return _require(value, CancelRequestV1)


def require_mass_cancel_request(value: object) -> MassCancelRequestV1:
    return _require(value, MassCancelRequestV1)


def require_position_snapshot(value: object) -> PositionSnapshotV1:
    return _require(value, PositionSnapshotV1)


def require_flatten_request(value: object) -> FlattenRequestV1:
    return _require(value, FlattenRequestV1)


def require_cancel_broker_evidence(value: object) -> CancelBrokerEvidenceV1:
    return _require(value, CancelBrokerEvidenceV1)


def require_cancel_execution(value: object) -> CancelExecutionV1:
    return _require(value, CancelExecutionV1)


def require_cancel_journal_record(value: object) -> CancelJournalRecordV1:
    return _require(value, CancelJournalRecordV1)


def require_cancel_result(value: object) -> CancelResultV1:
    return _require(value, CancelResultV1)


def require_mass_cancel_result(value: object) -> MassCancelResultV1:
    return _require(value, MassCancelResultV1)


def require_flatten_decision(value: object) -> FlattenDecisionV1:
    return _require(value, FlattenDecisionV1)


def _issue(value: _PolicyModel, expected_type: type[_PolicyModel]) -> _PolicyModel:
    if type(value) is not expected_type:
        raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST)
    try:
        return _ISSUER.issue(value)
    except Exception:
        raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST) from None


def _require(value: object, expected_type: type[_PolicyModel]) -> _PolicyModel:
    if type(value) is not expected_type:
        raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST)
    try:
        return require(value, _TAG)
    except Exception:
        raise CancelPolicyError(CancelPolicyCode.INVALID_REQUEST) from None


__all__ = [
    "CancelBrokerEvidenceV1",
    "CancelExecutionV1",
    "CancelJournalRecordV1",
    "CancelPolicyCode",
    "CancelPolicyError",
    "CancelPolicyV1",
    "CancelRequestV1",
    "CancelResultV1",
    "FlattenDecisionV1",
    "FlattenPolicyV1",
    "FlattenRequestV1",
    "MassCancelRequestV1",
    "MassCancelResultV1",
    "PositionSnapshotV1",
    "issue_cancel_broker_evidence",
    "issue_cancel_execution",
    "issue_cancel_journal_record",
    "issue_cancel_policy",
    "issue_cancel_request",
    "issue_cancel_result",
    "issue_flatten_decision",
    "issue_flatten_policy",
    "issue_flatten_request",
    "issue_mass_cancel_request",
    "issue_mass_cancel_result",
    "issue_position_snapshot",
    "require_cancel_broker_evidence",
    "require_cancel_execution",
    "require_cancel_journal_record",
    "require_cancel_policy",
    "require_cancel_request",
    "require_cancel_result",
    "require_flatten_decision",
    "require_flatten_policy",
    "require_flatten_request",
    "require_mass_cancel_request",
    "require_mass_cancel_result",
    "require_position_snapshot",
]
