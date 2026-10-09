"""Exact-account, read-only OMS reconciliation for the bounded paper path.

The broker adapter supplies a *complete* AccountViewV1. This module never
submits, cancels, infers a terminal cancel from absence, or promotes local
observation time into a broker timestamp. A ledger writer must append the
result and its compensating events in one transaction before using it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Literal, Protocol

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerOutcomeUnknown,
    BrokerPortV1,
    BrokerVenue,
    VenueIdentityV1,
)
from leviathan_core.execution.order_models import (
    Fill,
    FillCorrection,
    OrderSnapshot,
    OrderState,
)
from leviathan_core.numeric import NumericError, canonical_json, exact_sum, parse_decimal, parse_int
from leviathan_core.seal import Issuer, SealedModel, digest, require

_TAG = "execution.reconciliation"
_ISSUER = Issuer(_TAG)
_SESSION_START_ANCHOR_TAG = "execution.reconciliation.session_start_anchor.v1"
_SESSION_START_ANCHOR_ISSUER = Issuer(_SESSION_START_ANCHOR_TAG)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
# A caller may tighten this limit, never extend an account observation past it.
MAX_OBSERVATION_AGE_NS = 300_000_000_000
_PAPER_NONBLOCKING_EVIDENCE_CODES = frozenset(
    {
        "BALANCE_MISMATCH",
        "BALANCES_UNVERIFIED",
        "BROKER_TIME_UNVERIFIED",
        "SESSION_CHANGED",
        "SESSION_UNVERIFIED",
        "STALE",
    }
)
_IDENTITY_DISCREPANCY_CODES = frozenset(
    {
        "ACCOUNT_SCOPE_MISMATCH",
        "BROKER_ORDER_SCOPE_MISMATCH",
        "DUPLICATE_BROKER_ORDER_ID",
        "EXECUTION_IDENTITY_CONFLICT",
        "LOCAL_EXECUTION_VENUE_MISMATCH",
        "LOCAL_ORDER_VENUE_MISMATCH",
        "LOCAL_VENUE_MISMATCH",
        "ORDER_IDENTITY_COLLISION",
    }
)


class ReconcileError(RuntimeError):
    """Closed, content-free reconciliation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ReconcileStatus(StrEnum):
    MATCHED = "MATCHED"
    BROKER_ONLY = "BROKER_ONLY"
    LOCAL_ONLY = "LOCAL_ONLY"
    CONFLICT = "CONFLICT"
    UNKNOWN = "UNKNOWN"


class VerificationStatus(StrEnum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"


class VerifiedSessionStartAnchorV1(SealedModel):
    """Explicitly verified first-session evidence scoped to one venue account."""

    environment: BrokerEnvironment
    account_id: str
    venue: BrokerVenue
    session_id: str
    verified: Literal[True]


def _validate_session_start_anchor(anchor: object | None) -> None:
    if anchor is None:
        return
    if type(anchor) is not VerifiedSessionStartAnchorV1:
        raise ReconcileError("INVALID_SESSION_START_ANCHOR")
    require(anchor, _SESSION_START_ANCHOR_TAG)
    if (
        type(anchor.environment) is not BrokerEnvironment
        or type(anchor.venue) is not BrokerVenue
        or anchor.verified is not True
    ):
        raise ReconcileError("INVALID_SESSION_START_ANCHOR")
    try:
        _id(anchor.account_id)
        _id(anchor.session_id)
    except ReconcileError:
        raise ReconcileError("INVALID_SESSION_START_ANCHOR") from None


class ObservationSource(StrEnum):
    LOCAL_OBSERVED_AT = "LOCAL_OBSERVED_AT"


class ReconcileEntityV1(SealedModel):
    kind: str
    entity_id: str
    status: ReconcileStatus
    code: str
    order_id: str | None = None


class CompensatingEventV1(SealedModel):
    """Append-only proposal; applying it is the ledger port's transaction."""

    event_id: str
    kind: str
    execution_id: str
    order_id: str
    prior_quantity: Decimal
    revised_quantity: Decimal
    prior_price: Decimal
    revised_price: Decimal | None
    prior_executed_at: datetime | None
    revised_executed_at: datetime | None
    broker_revision: int


class OrderUpdateV1(SealedModel):
    order_id: str
    observed_state: OrderState
    venue_order_id: str
    code: str


class BrokerOrderV1(SealedModel):
    observation_id: str
    environment: str
    account_id: str
    venue: str
    client_order_id: str
    venue_order_id: str | None
    state: OrderState
    broker_sequence: int | None


class BrokerExecutionV1(SealedModel):
    execution_id: str
    venue_order_id: str
    client_order_id: str | None
    instrument_id: str
    side: str
    quantity: Decimal
    price: Decimal
    executed_at: datetime


class PositionV1(SealedModel):
    instrument_id: str
    quantity: Decimal


class BrokerBalanceV1(SealedModel):
    currency: str
    amount: Decimal


class BrokerSnapshotV1(SealedModel):
    venue: BrokerVenue
    environment: BrokerEnvironment
    venue_account_id: str
    account_id: str
    open_orders: tuple[BrokerOrderV1, ...]
    executions: tuple[BrokerExecutionV1, ...]
    positions: tuple[PositionV1, ...]
    broker_revision: int
    executions_since: datetime
    observed_at_ns: int
    observation_source: ObservationSource
    balances_status: VerificationStatus
    session_status: VerificationStatus
    balances: tuple[BrokerBalanceV1, ...] | None
    broker_observed_at: datetime | None
    session_id: str | None


class ReconcileResultV1(SealedModel):
    venue: BrokerVenue
    environment: BrokerEnvironment
    account_id: str
    observed_venue: BrokerVenue | None
    observed_environment: BrokerEnvironment | None
    observed_account_id: str | None
    account_status: ReconcileStatus
    entities: tuple[ReconcileEntityV1, ...]
    divergence_codes: tuple[str, ...]
    compensating_events: tuple[CompensatingEventV1, ...]
    order_updates: tuple[OrderUpdateV1, ...]
    submission_blocked: bool
    operator_alert: bool
    broker_revision: int | None
    ledger_revision: int
    snapshot_digest: str | None
    observed_at_ns: int
    observation_source: ObservationSource
    balances_status: VerificationStatus
    session_status: VerificationStatus
    broker_observed_at: datetime | None
    session_id: str | None


class OperatorResolutionV1(SealedModel):
    """An evidenced human decision; recording it cannot unblock by itself."""

    result_digest: str
    actor_id: str
    reason: str
    evidence_digest: str
    observed_at_ns: int


def _id(value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ReconcileError("INVALID_LEDGER_EVIDENCE")
    return value


def _revision(value: object) -> int:
    try:
        return parse_int(value, field="revision", min_value=0, max_value=2**63 - 1)
    except NumericError:
        raise ReconcileError("INVALID_LEDGER_EVIDENCE") from None


def _ns(value: object) -> int:
    try:
        return parse_int(value, field="observed_at_ns", min_value=0, max_value=2**63 - 1)
    except NumericError:
        raise ReconcileError("INVALID_OBSERVATION_TIME") from None


@dataclass(frozen=True, slots=True)
class RecordedExecutionV1:
    order_id: str
    fill: Fill
    corrections: tuple[FillCorrection, ...] = ()

    def __post_init__(self) -> None:
        _validate_recorded_execution(self)


def _validate_recorded_execution(item: RecordedExecutionV1) -> None:
    if type(item) is not RecordedExecutionV1 or type(item.fill) is not Fill:
        raise ReconcileError("INVALID_LEDGER_EVIDENCE")
    _id(item.order_id)
    if type(item.corrections) is not tuple:
        raise ReconcileError("INVALID_LEDGER_EVIDENCE")
    for index, correction in enumerate(item.corrections, 1):
        if (
            type(correction) is not FillCorrection
            or correction.execution_id != item.fill.execution_id
            or correction.account_id != item.fill.account_id
            or correction.venue != item.fill.venue
            or correction.revision != index
        ):
            raise ReconcileError("INVALID_LEDGER_EVIDENCE")
    if len({correction.correction_id for correction in item.corrections}) != len(item.corrections):
        raise ReconcileError("INVALID_LEDGER_EVIDENCE")


@dataclass(frozen=True, slots=True)
class LocalLedgerEvidenceV1:
    environment: BrokerEnvironment
    account_id: str
    orders: tuple[OrderSnapshot, ...]
    executions: tuple[RecordedExecutionV1, ...]
    positions: tuple[tuple[str, Decimal], ...]
    ledger_revision: int
    venue: BrokerVenue
    previous_broker_revision: int | None = None
    complete: bool = True
    balances: tuple[tuple[str, Decimal], ...] | None = None
    previous_session_id: str | None = None
    previous_session_verified: bool = False

    def __post_init__(self) -> None:
        _validate_ledger(self)


def _validate_ledger(ledger: LocalLedgerEvidenceV1) -> None:
    if type(ledger) is not LocalLedgerEvidenceV1:
        raise ReconcileError("INVALID_LEDGER_EVIDENCE")
    if (
        type(ledger.environment) is not BrokerEnvironment
        or type(ledger.complete) is not bool
        or type(ledger.previous_session_verified) is not bool
    ):
        raise ReconcileError("INVALID_LEDGER_EVIDENCE")
    if type(ledger.venue) is not BrokerVenue:
        raise ReconcileError("INVALID_LEDGER_EVIDENCE")
    _id(ledger.account_id)
    _revision(ledger.ledger_revision)
    if ledger.previous_broker_revision is not None:
        _revision(ledger.previous_broker_revision)
    if ledger.previous_session_id is not None:
        _id(ledger.previous_session_id)
    if ledger.previous_session_verified and ledger.previous_session_id is None:
        raise ReconcileError("INVALID_LEDGER_EVIDENCE")
    if type(ledger.orders) is not tuple or type(ledger.executions) is not tuple:
        raise ReconcileError("INVALID_LEDGER_EVIDENCE")
    order_ids: set[str] = set()
    client_ids: set[str] = set()
    native_ids: set[str] = set()
    for order in ledger.orders:
        if type(order) is not OrderSnapshot or order.order_id in order_ids:
            raise ReconcileError("INVALID_LEDGER_EVIDENCE")
        if (
            order.request.account_id != ledger.account_id
            or order.request.environment.upper() != ledger.environment.value
        ):
            raise ReconcileError("INVALID_LEDGER_EVIDENCE")
        order_ids.add(order.order_id)
        client_id = order.request.client_order_id
        if client_id is not None:
            if client_id in client_ids:
                raise ReconcileError("INVALID_LEDGER_EVIDENCE")
            client_ids.add(client_id)
        if order.venue_order_id is not None:
            if order.venue_order_id in native_ids:
                raise ReconcileError("INVALID_LEDGER_EVIDENCE")
            native_ids.add(order.venue_order_id)
    execution_ids: set[str] = set()
    for execution in ledger.executions:
        _validate_recorded_execution(execution)
        if (
            execution.order_id not in order_ids
            or execution.fill.account_id != ledger.account_id
            or execution.fill.execution_id in execution_ids
        ):
            raise ReconcileError("INVALID_LEDGER_EVIDENCE")
        execution_ids.add(execution.fill.execution_id)
    if type(ledger.positions) is not tuple:
        raise ReconcileError("INVALID_LEDGER_EVIDENCE")
    position_ids: list[str] = []
    for position in ledger.positions:
        if type(position) is not tuple or len(position) != 2:
            raise ReconcileError("INVALID_LEDGER_EVIDENCE")
        instrument_id, quantity = position
        position_ids.append(_id(instrument_id))
        if type(quantity) is not Decimal:
            raise ReconcileError("INVALID_LEDGER_EVIDENCE")
        try:
            parse_decimal(quantity, field="position_quantity")
        except NumericError:
            raise ReconcileError("INVALID_LEDGER_EVIDENCE") from None
    if position_ids != sorted(set(position_ids)):
        raise ReconcileError("INVALID_LEDGER_EVIDENCE")
    if ledger.balances is not None:
        if type(ledger.balances) is not tuple:
            raise ReconcileError("INVALID_LEDGER_EVIDENCE")
        currencies: list[str] = []
        for balance in ledger.balances:
            if type(balance) is not tuple or len(balance) != 2:
                raise ReconcileError("INVALID_LEDGER_EVIDENCE")
            currency, amount = balance
            if type(currency) is not str or re.fullmatch(r"[A-Z]{3}", currency) is None:
                raise ReconcileError("INVALID_LEDGER_EVIDENCE")
            currencies.append(currency)
            if type(amount) is not Decimal:
                raise ReconcileError("INVALID_LEDGER_EVIDENCE")
            try:
                parse_decimal(amount, field="ledger_balance")
            except NumericError:
                raise ReconcileError("INVALID_LEDGER_EVIDENCE") from None
        if currencies != sorted(set(currencies)):
            raise ReconcileError("INVALID_LEDGER_EVIDENCE")


def _lineage_code(ledger: LocalLedgerEvidenceV1) -> str | None:
    """Check local links before declaring broker lineage unavailable."""
    orders = {item.order_id: item for item in ledger.orders}
    linked = False
    for order in ledger.orders:
        request = order.request
        parent_id = request.parent_order_id
        root_id = request.root_order_id
        if parent_id is None and root_id is None:
            continue
        linked = True
        if (parent_id is not None and parent_id not in orders) or (
            root_id is not None and root_id not in orders
        ):
            return "LOCAL_LINEAGE_INVALID"
        if parent_id == order.order_id or (root_id == order.order_id and parent_id is not None):
            return "LOCAL_LINEAGE_INVALID"
        if root_id is not None and orders[root_id].request.parent_order_id is not None:
            return "LOCAL_LINEAGE_INVALID"
        seen = {order.order_id}
        ancestor_id = parent_id
        reached_root = root_id is None
        while ancestor_id is not None:
            if ancestor_id in seen or ancestor_id not in orders:
                return "LOCAL_LINEAGE_INVALID"
            seen.add(ancestor_id)
            if ancestor_id == root_id:
                reached_root = True
            ancestor_id = orders[ancestor_id].request.parent_order_id
        if not reached_root:
            return "LOCAL_LINEAGE_INVALID"
    return "BROKER_LINEAGE_UNVERIFIED" if linked else None


def build_broker_snapshot(
    view: AccountViewV1, venue: VenueIdentityV1, *, observed_at_ns: int
) -> BrokerSnapshotV1:
    """Project an issued complete view; never infer missing provider fields."""
    if type(view) is not AccountViewV1 or type(venue) is not VenueIdentityV1:
        raise ReconcileError("INVALID_BROKER_VIEW")
    view.assert_sealed()
    venue.assert_sealed()
    observed_at_ns = _ns(observed_at_ns)
    return _ISSUER.issue(
        BrokerSnapshotV1(
            venue=venue.venue,
            environment=venue.environment,
            venue_account_id=venue.account_id,
            account_id=view.account_id,
            open_orders=tuple(
                BrokerOrderV1(
                    observation_id=item.observation_id,
                    environment=item.environment,
                    account_id=item.account_id,
                    venue=item.venue,
                    client_order_id=item.client_order_id,
                    venue_order_id=item.venue_order_id,
                    state=item.status,
                    broker_sequence=item.broker_sequence,
                )
                for item in view.open_orders
            ),
            executions=tuple(
                BrokerExecutionV1(
                    execution_id=item.execution_id,
                    venue_order_id=item.venue_order_id,
                    client_order_id=item.client_order_id,
                    instrument_id=item.instrument_id,
                    side=item.side,
                    quantity=item.quantity,
                    price=item.price,
                    executed_at=item.executed_at,
                )
                for item in view.executions
            ),
            positions=tuple(
                PositionV1(instrument_id=name, quantity=quantity)
                for name, quantity in view.positions
            ),
            broker_revision=view.broker_revision,
            executions_since=view.executions_since,
            observed_at_ns=observed_at_ns,
            observation_source=ObservationSource.LOCAL_OBSERVED_AT,
            balances_status=VerificationStatus.UNVERIFIED,
            session_status=VerificationStatus.UNVERIFIED,
            balances=(
                None
                if view.balances is None
                else tuple(
                    BrokerBalanceV1(currency=item.currency, amount=item.amount)
                    for item in view.balances
                )
            ),
            broker_observed_at=view.broker_observed_at,
            session_id=view.session_id,
        )
    )


def _datetime_ns(value: datetime) -> int:
    if type(value) is not datetime or value.tzinfo is None:
        raise ReconcileError("INVALID_BROKER_TIME")
    try:
        if value.utcoffset() is None:
            raise ReconcileError("INVALID_BROKER_TIME")
        delta = value.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    except Exception:
        raise ReconcileError("INVALID_BROKER_TIME") from None
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def _balances_match(snapshot: BrokerSnapshotV1, ledger: LocalLedgerEvidenceV1) -> bool:
    if not ledger.complete or not snapshot.balances or not ledger.balances:
        return False
    broker_balances = {item.currency: item.amount for item in snapshot.balances}
    ledger_balances = dict(ledger.balances)
    return broker_balances.keys() == ledger_balances.keys() and all(
        broker_balances[currency] == ledger_balances[currency] for currency in broker_balances
    )


def _verification_identity_matches(
    snapshot: BrokerSnapshotV1,
    ledger: LocalLedgerEvidenceV1,
    expected_venue: VenueIdentityV1,
) -> bool:
    return (
        snapshot.venue is expected_venue.venue
        and snapshot.environment is expected_venue.environment
        and snapshot.venue_account_id == expected_venue.account_id
        and snapshot.account_id == expected_venue.account_id
        and ledger.venue is expected_venue.venue
        and ledger.environment is expected_venue.environment
        and ledger.account_id == expected_venue.account_id
        and all(
            order.request.account_id == expected_venue.account_id
            and order.request.environment.upper() == expected_venue.environment.value
            and order.request.venue == expected_venue.venue.value
            for order in ledger.orders
        )
        and all(
            execution.fill.account_id == expected_venue.account_id
            and execution.fill.venue == expected_venue.venue.value
            for execution in ledger.executions
        )
    )


def _record(
    entities: list[ReconcileEntityV1],
    codes: set[str],
    kind: str,
    entity_id: str,
    status: ReconcileStatus,
    code: str,
    order_id: str | None = None,
) -> None:
    entities.append(
        ReconcileEntityV1(
            kind=kind, entity_id=entity_id, status=status, code=code, order_id=order_id
        )
    )
    if status is not ReconcileStatus.MATCHED:
        codes.add(code)


def _effective(execution: RecordedExecutionV1) -> tuple[Decimal, Decimal | None]:
    if not execution.corrections:
        return execution.fill.quantity, execution.fill.price
    last = execution.corrections[-1]
    return last.revised_quantity, last.revised_price


def _compensating_event(
    kind: str,
    execution_id: str,
    order_id: str,
    prior_quantity: Decimal,
    revised_quantity: Decimal,
    prior_price: Decimal,
    revised_price: Decimal | None,
    prior_executed_at: datetime | None,
    revised_executed_at: datetime | None,
    broker_revision: int,
) -> CompensatingEventV1:
    payload = [
        kind,
        execution_id,
        order_id,
        prior_quantity,
        revised_quantity,
        prior_price,
        revised_price,
        prior_executed_at.isoformat() if prior_executed_at is not None else None,
        revised_executed_at.isoformat() if revised_executed_at is not None else None,
        broker_revision,
    ]
    event_id = hashlib.sha256(canonical_json(payload)).hexdigest()
    return CompensatingEventV1(
        event_id=event_id,
        kind=kind,
        execution_id=execution_id,
        order_id=order_id,
        prior_quantity=prior_quantity,
        revised_quantity=revised_quantity,
        prior_price=prior_price,
        revised_price=revised_price,
        prior_executed_at=prior_executed_at,
        revised_executed_at=revised_executed_at,
        broker_revision=broker_revision,
    )


def _unknown_result(
    snapshot: BrokerSnapshotV1,
    ledger: LocalLedgerEvidenceV1,
    expected_venue: VenueIdentityV1,
    codes: set[str],
    entities: list[ReconcileEntityV1],
    session_start_anchor: VerifiedSessionStartAnchorV1 | None = None,
) -> ReconcileResultV1:
    return _result(
        snapshot,
        ledger,
        expected_venue,
        entities,
        codes,
        [],
        [],
        session_start_anchor,
    )


def _session_is_verified(
    snapshot: BrokerSnapshotV1,
    ledger: LocalLedgerEvidenceV1,
    expected_venue: VenueIdentityV1,
    anchor: VerifiedSessionStartAnchorV1 | None,
    *,
    identity_matches: bool,
    provider_time_fresh: bool,
    codes: set[str],
) -> bool:
    if (
        snapshot.session_id is None
        or not identity_matches
        or not provider_time_fresh
        or codes & (_IDENTITY_DISCREPANCY_CODES | {"SESSION_CHANGED", "STALE"})
    ):
        return False
    ledger_anchor_matches = (
        ledger.previous_session_verified
        and ledger.previous_session_id is not None
        and snapshot.session_id == ledger.previous_session_id
    )
    injected_anchor_matches = (
        anchor is not None
        and anchor.verified is True
        and anchor.environment is expected_venue.environment
        and anchor.account_id == expected_venue.account_id
        and anchor.venue is expected_venue.venue
        and anchor.session_id == snapshot.session_id
    )
    return ledger_anchor_matches or injected_anchor_matches


def _result(
    snapshot: BrokerSnapshotV1,
    ledger: LocalLedgerEvidenceV1,
    expected_venue: VenueIdentityV1,
    entities: list[ReconcileEntityV1],
    codes: set[str],
    compensating_events: list[CompensatingEventV1],
    order_updates: list[OrderUpdateV1],
    session_start_anchor: VerifiedSessionStartAnchorV1 | None = None,
) -> ReconcileResultV1:
    balances_match = _balances_match(snapshot, ledger)
    provider_time_fresh = snapshot.broker_observed_at is not None and "STALE" not in codes
    session_matches = (
        snapshot.session_id is not None
        and ledger.previous_session_id is not None
        and snapshot.session_id == ledger.previous_session_id
    )
    identity_matches = _verification_identity_matches(
        snapshot, ledger, expected_venue
    ) and not bool(codes & _IDENTITY_DISCREPANCY_CODES)
    session_verified = _session_is_verified(
        snapshot,
        ledger,
        expected_venue,
        session_start_anchor,
        identity_matches=identity_matches,
        provider_time_fresh=provider_time_fresh,
        codes=codes,
    )
    balances_verified = (
        identity_matches and balances_match and provider_time_fresh and session_matches
    )
    balances_status = (
        VerificationStatus.VERIFIED if balances_verified else VerificationStatus.UNVERIFIED
    )
    # New account evidence is advisory for PAPER/DEMO. LIVE requires a complete,
    # exact balance match with fresh provider time and a stable identified session.
    if expected_venue.environment is BrokerEnvironment.LIVE:
        if not balances_match:
            code = (
                "BALANCE_MISMATCH"
                if snapshot.balances is not None and ledger.balances is not None
                else "BALANCES_UNVERIFIED"
            )
            codes.add(code)
        if snapshot.broker_observed_at is None:
            codes.add("BROKER_TIME_UNVERIFIED")
        if not session_matches and not session_verified:
            if snapshot.session_id is not None and ledger.previous_session_id is not None:
                if snapshot.session_id != ledger.previous_session_id:
                    codes.add("SESSION_CHANGED")
                else:
                    codes.add("SESSION_UNVERIFIED")
            else:
                codes.add("SESSION_UNVERIFIED")
        if not provider_time_fresh and snapshot.broker_observed_at is not None:
            codes.add("STALE")
    status = ReconcileStatus.MATCHED
    if any(entity.status is ReconcileStatus.UNKNOWN for entity in entities):
        status = ReconcileStatus.UNKNOWN
    elif any(entity.status is ReconcileStatus.CONFLICT for entity in entities) or (
        entities and any(entity.status is not ReconcileStatus.MATCHED for entity in entities)
    ):
        status = ReconcileStatus.CONFLICT
    elif codes:
        status = ReconcileStatus.UNKNOWN
    return _ISSUER.issue(
        ReconcileResultV1(
            venue=expected_venue.venue,
            environment=expected_venue.environment,
            account_id=expected_venue.account_id,
            observed_venue=snapshot.venue,
            observed_environment=snapshot.environment,
            observed_account_id=snapshot.account_id,
            account_status=status,
            entities=tuple(
                sorted(entities, key=lambda item: (item.kind, item.entity_id, item.code))
            ),
            divergence_codes=tuple(sorted(codes)),
            compensating_events=tuple(
                sorted(compensating_events, key=lambda item: (item.execution_id, item.kind))
            ),
            order_updates=tuple(sorted(order_updates, key=lambda item: item.order_id)),
            submission_blocked=(
                not (
                    balances_status is VerificationStatus.VERIFIED
                    and session_verified
                    and not codes
                )
                if expected_venue.environment is BrokerEnvironment.LIVE
                else bool(codes - _PAPER_NONBLOCKING_EVIDENCE_CODES)
            ),
            operator_alert=bool(codes),
            broker_revision=snapshot.broker_revision,
            ledger_revision=ledger.ledger_revision,
            snapshot_digest=digest(snapshot),
            observed_at_ns=snapshot.observed_at_ns,
            observation_source=ObservationSource.LOCAL_OBSERVED_AT,
            balances_status=balances_status,
            session_status=(
                VerificationStatus.VERIFIED if session_verified else VerificationStatus.UNVERIFIED
            ),
            broker_observed_at=snapshot.broker_observed_at,
            session_id=snapshot.session_id,
        )
    )


def _unavailable_result(
    venue: VenueIdentityV1,
    ledger: LocalLedgerEvidenceV1,
    observed_at_ns: int,
    code: str,
    observed_identity: VenueIdentityV1 | None = None,
) -> ReconcileResultV1:
    """A source-linked UNKNOWN with no invented broker image or revision."""
    codes = {code}
    if venue.environment is BrokerEnvironment.LIVE:
        codes.update({"BALANCES_UNVERIFIED", "SESSION_UNVERIFIED"})
    return _ISSUER.issue(
        ReconcileResultV1(
            venue=venue.venue,
            environment=venue.environment,
            account_id=venue.account_id,
            observed_venue=observed_identity.venue if observed_identity is not None else None,
            observed_environment=(
                observed_identity.environment if observed_identity is not None else None
            ),
            observed_account_id=(
                observed_identity.account_id if observed_identity is not None else None
            ),
            account_status=ReconcileStatus.UNKNOWN,
            entities=(
                ReconcileEntityV1(
                    kind="ACCOUNT",
                    entity_id=venue.account_id,
                    status=ReconcileStatus.UNKNOWN,
                    code=code,
                ),
            ),
            divergence_codes=tuple(sorted(codes)),
            compensating_events=(),
            order_updates=(),
            submission_blocked=True,
            operator_alert=True,
            broker_revision=None,
            ledger_revision=ledger.ledger_revision,
            snapshot_digest=None,
            observed_at_ns=observed_at_ns,
            observation_source=ObservationSource.LOCAL_OBSERVED_AT,
            balances_status=VerificationStatus.UNVERIFIED,
            session_status=VerificationStatus.UNVERIFIED,
            broker_observed_at=None,
            session_id=None,
        )
    )


def record_operator_resolution(
    result: ReconcileResultV1,
    *,
    actor_id: str,
    reason: str,
    evidence_digest: str,
) -> OperatorResolutionV1:
    """Issue an audit record to append; a later complete cycle decides status."""
    require(result, _TAG)
    _id(actor_id)
    _id(reason)
    if (
        type(evidence_digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", evidence_digest, re.ASCII) is None
    ):
        raise ReconcileError("INVALID_RESOLUTION_EVIDENCE")
    return _ISSUER.issue(
        OperatorResolutionV1(
            result_digest=digest(result),
            actor_id=actor_id,
            reason=reason,
            evidence_digest=evidence_digest,
            observed_at_ns=result.observed_at_ns,
        )
    )


def reconcile_account(
    snapshot: BrokerSnapshotV1,
    ledger: LocalLedgerEvidenceV1,
    expected_venue: VenueIdentityV1,
    *,
    now_ns: int,
    max_age_ns: int,
    session_start_anchor: VerifiedSessionStartAnchorV1 | None = None,
) -> ReconcileResultV1:
    """Compare exact identifiers and lineage; all uncertainty fails closed."""
    require(snapshot, _TAG)
    _validate_ledger(ledger)
    if type(expected_venue) is not VenueIdentityV1:
        raise ReconcileError("INVALID_EXPECTED_VENUE")
    expected_venue.assert_sealed()
    _validate_session_start_anchor(session_start_anchor)
    now_ns = _ns(now_ns)
    max_age_ns = min(_ns(max_age_ns), MAX_OBSERVATION_AGE_NS)
    entities: list[ReconcileEntityV1] = []
    codes: set[str] = set()
    events: list[CompensatingEventV1] = []
    updates: list[OrderUpdateV1] = []
    identity_bad = (
        snapshot.venue is not expected_venue.venue
        or snapshot.environment is not expected_venue.environment
        or snapshot.venue_account_id != expected_venue.account_id
        or snapshot.account_id != expected_venue.account_id
        or ledger.environment is not expected_venue.environment
        or ledger.account_id != expected_venue.account_id
    )
    if identity_bad:
        _record(
            entities,
            codes,
            "ACCOUNT",
            expected_venue.account_id,
            ReconcileStatus.UNKNOWN,
            "ACCOUNT_SCOPE_MISMATCH",
        )
    if ledger.venue is not expected_venue.venue:
        _record(
            entities,
            codes,
            "ACCOUNT",
            expected_venue.account_id,
            ReconcileStatus.UNKNOWN,
            "LOCAL_VENUE_MISMATCH",
        )
    if any(order.request.venue != expected_venue.venue.value for order in ledger.orders):
        _record(
            entities,
            codes,
            "ACCOUNT",
            expected_venue.account_id,
            ReconcileStatus.UNKNOWN,
            "LOCAL_ORDER_VENUE_MISMATCH",
        )
    local_orders = {order.order_id: order for order in ledger.orders}
    for ledger_execution in ledger.executions:
        ledger_owner = local_orders[ledger_execution.order_id]
        if ledger_execution.fill.venue != expected_venue.venue.value or (
            ledger_execution.fill.venue != ledger_owner.request.venue
        ):
            _record(
                entities,
                codes,
                "EXECUTION",
                ledger_execution.fill.execution_id,
                ReconcileStatus.UNKNOWN,
                "LOCAL_EXECUTION_VENUE_MISMATCH",
                ledger_execution.order_id,
            )
        if (
            not ledger_owner.submit_attempted
            or ledger_owner.state
            in {
                OrderState.CREATED,
                OrderState.RISK_PENDING,
                OrderState.RISK_REJECTED,
                OrderState.READY,
            }
            or (
                ledger_owner.venue_order_id is None and ledger_owner.request.client_order_id is None
            )
        ):
            _record(
                entities,
                codes,
                "EXECUTION",
                ledger_execution.fill.execution_id,
                ReconcileStatus.CONFLICT,
                "LOCAL_EXECUTION_OWNER_UNVERIFIED",
                ledger_execution.order_id,
            )
    lineage_code = _lineage_code(ledger)
    if lineage_code is not None:
        _record(
            entities,
            codes,
            "ACCOUNT",
            expected_venue.account_id,
            ReconcileStatus.UNKNOWN,
            lineage_code,
        )
    if not ledger.complete:
        _record(
            entities,
            codes,
            "ACCOUNT",
            expected_venue.account_id,
            ReconcileStatus.UNKNOWN,
            "LOCAL_LEDGER_INCOMPLETE",
        )
    if now_ns < snapshot.observed_at_ns or now_ns - snapshot.observed_at_ns > max_age_ns:
        _record(
            entities,
            codes,
            "ACCOUNT",
            expected_venue.account_id,
            ReconcileStatus.UNKNOWN,
            "STALE_LOCAL_OBSERVATION",
        )
    if snapshot.broker_observed_at is not None:
        provider_observed_ns = _datetime_ns(snapshot.broker_observed_at)
        if now_ns < provider_observed_ns or now_ns - provider_observed_ns > max_age_ns:
            codes.add("STALE")
    if (
        snapshot.session_id is not None
        and ledger.previous_session_id is not None
        and snapshot.session_id != ledger.previous_session_id
    ):
        codes.add("SESSION_CHANGED")
    previous = ledger.previous_broker_revision
    if previous is not None and snapshot.broker_revision < previous:
        _record(
            entities,
            codes,
            "ACCOUNT",
            expected_venue.account_id,
            ReconcileStatus.UNKNOWN,
            "BROKER_REVISION_REGRESSED",
        )
    if previous is not None and snapshot.broker_revision > previous + 1:
        _record(
            entities,
            codes,
            "ACCOUNT",
            expected_venue.account_id,
            ReconcileStatus.UNKNOWN,
            "BROKER_REVISION_GAP",
        )
    if any(
        order.environment.upper() != snapshot.environment.value
        or order.account_id != snapshot.account_id
        or order.venue != snapshot.venue.value
        for order in snapshot.open_orders
    ):
        _record(
            entities,
            codes,
            "ACCOUNT",
            expected_venue.account_id,
            ReconcileStatus.UNKNOWN,
            "BROKER_ORDER_SCOPE_MISMATCH",
        )
    if codes:
        return _unknown_result(
            snapshot, ledger, expected_venue, codes, entities, session_start_anchor
        )

    local_by_client = {
        item.request.client_order_id: item
        for item in ledger.orders
        if item.request.client_order_id is not None
    }
    local_by_native = {
        item.venue_order_id: item for item in ledger.orders if item.venue_order_id is not None
    }
    broker_by_client: dict[str, BrokerOrderV1] = {}
    broker_by_native: dict[str, BrokerOrderV1] = {}
    for order in snapshot.open_orders:
        if order.client_order_id in broker_by_client or (
            order.venue_order_id is not None and order.venue_order_id in broker_by_native
        ):
            _record(
                entities,
                codes,
                "ORDER",
                order.client_order_id,
                ReconcileStatus.CONFLICT,
                "DUPLICATE_BROKER_ORDER_ID",
            )
        broker_by_client[order.client_order_id] = order
        if order.venue_order_id is not None:
            broker_by_native[order.venue_order_id] = order
    if "DUPLICATE_BROKER_ORDER_ID" in codes:
        return _result(
            snapshot,
            ledger,
            expected_venue,
            entities,
            codes,
            events,
            updates,
            session_start_anchor,
        )

    matched_order_ids: set[str] = set()
    for broker_order in snapshot.open_orders:
        by_client = local_by_client.get(broker_order.client_order_id)
        by_native = (
            local_by_native.get(broker_order.venue_order_id)
            if broker_order.venue_order_id is not None
            else None
        )
        if by_client is not None and by_native is not None and by_client is not by_native:
            _record(
                entities,
                codes,
                "ORDER",
                broker_order.client_order_id,
                ReconcileStatus.CONFLICT,
                "ORDER_IDENTITY_COLLISION",
            )
            continue
        local = by_client or by_native
        if local is None:
            _record(
                entities,
                codes,
                "ORDER",
                broker_order.client_order_id,
                ReconcileStatus.BROKER_ONLY,
                "BROKER_ONLY_ORDER",
            )
            continue
        if (
            (
                local.request.client_order_id is not None
                and local.request.client_order_id != broker_order.client_order_id
            )
            or (
                local.venue_order_id is not None
                and local.venue_order_id != broker_order.venue_order_id
            )
            or local.request.venue != snapshot.venue.value
        ):
            _record(
                entities,
                codes,
                "ORDER",
                local.order_id,
                ReconcileStatus.CONFLICT,
                "ORDER_IDENTITY_COLLISION",
                local.order_id,
            )
            continue
        matched_order_ids.add(local.order_id)
        if broker_order.venue_order_id is None:
            _record(
                entities,
                codes,
                "ORDER",
                local.order_id,
                ReconcileStatus.UNKNOWN,
                "NATIVE_ORDER_ID_UNVERIFIED",
                local.order_id,
            )
            continue
        if local.state in {
            OrderState.UNKNOWN_SUBMIT,
            OrderState.SUBMITTING,
            OrderState.DISPATCH_IN_FLIGHT,
        }:
            if broker_order.state is OrderState.PARTIALLY_FILLED:
                _record(
                    entities,
                    codes,
                    "ORDER",
                    local.order_id,
                    ReconcileStatus.UNKNOWN,
                    "PARTIAL_FILL_UNVERIFIED",
                    local.order_id,
                )
            else:
                updates.append(
                    OrderUpdateV1(
                        order_id=local.order_id,
                        observed_state=broker_order.state,
                        venue_order_id=broker_order.venue_order_id,
                        code="SUBMIT_FOUND_OPEN",
                    )
                )
                _record(
                    entities,
                    codes,
                    "ORDER",
                    local.order_id,
                    ReconcileStatus.MATCHED,
                    "SUBMIT_FOUND_OPEN",
                    local.order_id,
                )
        elif local.state is OrderState.CANCEL_REQUESTED_UNCONFIRMED:
            _record(
                entities,
                codes,
                "ORDER",
                local.order_id,
                ReconcileStatus.UNKNOWN,
                "CANCEL_OUTCOME_UNKNOWN",
                local.order_id,
            )
        elif local.state in {OrderState.WORKING, OrderState.PARTIALLY_FILLED}:
            local_fills = tuple(
                item for item in ledger.executions if item.order_id == local.order_id
            )
            broker_fills = tuple(
                item
                for item in snapshot.executions
                if item.venue_order_id == broker_order.venue_order_id
                and item.client_order_id == broker_order.client_order_id
            )
            if broker_order.state is not local.state:
                order_status = ReconcileStatus.CONFLICT
                order_code = "PARTIAL_FILL_STATUS_MISMATCH"
            elif local.state is OrderState.WORKING:
                order_status = (
                    ReconcileStatus.MATCHED
                    if local.filled_quantity == 0 and not local_fills and not broker_fills
                    else ReconcileStatus.CONFLICT
                )
                order_code = (
                    "OPEN_ORDER_MATCHED"
                    if order_status is ReconcileStatus.MATCHED
                    else "ORDER_FILL_STATUS_MISMATCH"
                )
            else:
                recorded_ids = {item.fill.execution_id for item in local_fills}
                broker_ids = {item.execution_id for item in broker_fills}
                sums_match = (
                    bool(local_fills)
                    and bool(broker_fills)
                    and recorded_ids == broker_ids
                    and exact_sum(_effective(item)[0] for item in local_fills)
                    == local.filled_quantity
                    and exact_sum(item.quantity for item in broker_fills) == local.filled_quantity
                    and 0 < local.filled_quantity < local.request.quantity
                )
                order_status = ReconcileStatus.MATCHED if sums_match else ReconcileStatus.UNKNOWN
                order_code = "OPEN_ORDER_MATCHED" if sums_match else "PARTIAL_FILL_UNVERIFIED"
            _record(
                entities,
                codes,
                "ORDER",
                local.order_id,
                order_status,
                order_code,
                local.order_id,
            )
        else:
            _record(
                entities,
                codes,
                "ORDER",
                local.order_id,
                ReconcileStatus.CONFLICT,
                "OPEN_ORDER_STATE_CONFLICT",
                local.order_id,
            )
    for local in ledger.orders:
        if local.order_id in matched_order_ids:
            continue
        if (
            local.state
            in {
                OrderState.CREATED,
                OrderState.RISK_PENDING,
                OrderState.RISK_REJECTED,
                OrderState.READY,
            }
            and not local.submit_attempted
        ):
            _record(
                entities,
                codes,
                "ORDER",
                local.order_id,
                ReconcileStatus.MATCHED,
                "NOT_DISPATCHED",
                local.order_id,
            )
        elif local.state is OrderState.FILLED:
            fills = tuple(
                execution
                for execution in snapshot.executions
                if (
                    local.venue_order_id is not None
                    and execution.venue_order_id == local.venue_order_id
                )
                or (
                    local.request.client_order_id is not None
                    and execution.client_order_id == local.request.client_order_id
                )
            )
            recorded_ids = {
                item.fill.execution_id
                for item in ledger.executions
                if item.order_id == local.order_id
            }
            fully_observed = (
                bool(fills)
                and exact_sum(execution.quantity for execution in fills) == local.request.quantity
                and local.filled_quantity == local.request.quantity
                and all(execution.execution_id in recorded_ids for execution in fills)
            )
            order_status = (
                ReconcileStatus.MATCHED
                if fully_observed
                else ReconcileStatus.CONFLICT
                if fills
                else ReconcileStatus.UNKNOWN
            )
            order_code = (
                "FILLED_EXECUTIONS_MATCHED"
                if fully_observed
                else "TERMINAL_FILL_CONFLICT"
                if fills
                else "TERMINAL_UNVERIFIED"
            )
            _record(
                entities,
                codes,
                "ORDER",
                local.order_id,
                order_status,
                order_code,
                local.order_id,
            )
        elif local.state is OrderState.UNKNOWN_SUBMIT:
            fills = tuple(
                execution
                for execution in snapshot.executions
                if (
                    local.venue_order_id is not None
                    and execution.venue_order_id == local.venue_order_id
                )
                or (
                    local.request.client_order_id is not None
                    and execution.client_order_id == local.request.client_order_id
                )
            )
            if fills and exact_sum(item.quantity for item in fills) == local.request.quantity:
                native_ids = {item.venue_order_id for item in fills}
                if len(native_ids) == 1:
                    updates.append(
                        OrderUpdateV1(
                            order_id=local.order_id,
                            observed_state=OrderState.FILLED,
                            venue_order_id=next(iter(native_ids)),
                            code="SUBMIT_FOUND_FILLED",
                        )
                    )
            _record(
                entities,
                codes,
                "ORDER",
                local.order_id,
                ReconcileStatus.UNKNOWN,
                "SUBMIT_OUTCOME_PENDING_LEDGER",
                local.order_id,
            )
        else:
            _record(
                entities,
                codes,
                "ORDER",
                local.order_id,
                ReconcileStatus.LOCAL_ONLY
                if local.state in {OrderState.WORKING, OrderState.PARTIALLY_FILLED}
                else ReconcileStatus.UNKNOWN,
                "LOCAL_ORDER_NOT_OPEN",
                local.order_id,
            )

    local_exec = {item.fill.execution_id: item for item in ledger.executions}
    broker_exec = {item.execution_id: item for item in snapshot.executions}
    order_by_id = {item.order_id: item for item in ledger.orders}
    for execution in snapshot.executions:
        recorded = local_exec.get(execution.execution_id)
        if recorded is None:
            native_owner = local_by_native.get(execution.venue_order_id)
            client_owner = (
                local_by_client.get(execution.client_order_id)
                if execution.client_order_id is not None
                else None
            )
            if (
                native_owner is not None
                and client_owner is not None
                and (native_owner is not client_owner)
            ):
                _record(
                    entities,
                    codes,
                    "EXECUTION",
                    execution.execution_id,
                    ReconcileStatus.CONFLICT,
                    "EXECUTION_IDENTITY_CONFLICT",
                )
                continue
            owner = native_owner or client_owner
            if owner is not None and (
                not owner.submit_attempted
                or owner.state
                in {
                    OrderState.CREATED,
                    OrderState.RISK_PENDING,
                    OrderState.RISK_REJECTED,
                    OrderState.READY,
                }
            ):
                _record(
                    entities,
                    codes,
                    "EXECUTION",
                    execution.execution_id,
                    ReconcileStatus.CONFLICT,
                    "EXECUTION_OWNER_UNVERIFIED",
                    owner.order_id,
                )
                continue
            if owner is not None and (
                owner.request.instrument_id != execution.instrument_id
                or owner.request.side != execution.side
                or (
                    owner.venue_order_id is not None
                    and owner.venue_order_id != execution.venue_order_id
                )
                or (
                    owner.request.client_order_id is not None
                    and owner.request.client_order_id != execution.client_order_id
                )
            ):
                _record(
                    entities,
                    codes,
                    "EXECUTION",
                    execution.execution_id,
                    ReconcileStatus.CONFLICT,
                    "EXECUTION_IDENTITY_CONFLICT",
                    owner.order_id,
                )
                continue
            order_id = owner.order_id if owner is not None else None
            _record(
                entities,
                codes,
                "EXECUTION",
                execution.execution_id,
                ReconcileStatus.BROKER_ONLY,
                "BROKER_ONLY_EXECUTION",
                order_id,
            )
            if owner is not None:
                events.append(
                    _compensating_event(
                        "NEW_FILL",
                        execution.execution_id,
                        owner.order_id,
                        Decimal(0),
                        execution.quantity,
                        execution.price,
                        execution.price,
                        None,
                        execution.executed_at,
                        snapshot.broker_revision,
                    )
                )
            if (
                owner is not None
                and owner.request.expires_at is not None
                and (execution.executed_at > owner.request.expires_at)
            ):
                _record(
                    entities,
                    codes,
                    "EXECUTION",
                    execution.execution_id,
                    ReconcileStatus.CONFLICT,
                    "POST_GTD_FILL",
                    owner.order_id,
                )
            continue
        owner = order_by_id[recorded.order_id]
        quantity, price = _effective(recorded)
        native_match = (
            owner.venue_order_id is not None and owner.venue_order_id == execution.venue_order_id
        )
        client_match = (
            owner.request.client_order_id is not None
            and owner.request.client_order_id == execution.client_order_id
        )
        identity_match = (
            (native_match or client_match)
            and recorded.fill.venue == snapshot.venue.value
            and owner.request.venue == snapshot.venue.value
            and execution.instrument_id == owner.request.instrument_id
            and execution.side == owner.request.side
            and (owner.venue_order_id is None or owner.venue_order_id == execution.venue_order_id)
            and (
                owner.request.client_order_id is None
                or owner.request.client_order_id == execution.client_order_id
            )
        )
        if not identity_match:
            _record(
                entities,
                codes,
                "EXECUTION",
                execution.execution_id,
                ReconcileStatus.CONFLICT,
                "EXECUTION_IDENTITY_CONFLICT",
                recorded.order_id,
            )
        elif (
            quantity != execution.quantity
            or price != execution.price
            or recorded.fill.occurred_at != execution.executed_at
        ):
            events.append(
                _compensating_event(
                    "CORRECTION",
                    execution.execution_id,
                    recorded.order_id,
                    quantity,
                    execution.quantity,
                    price or recorded.fill.price,
                    execution.price,
                    recorded.fill.occurred_at,
                    execution.executed_at,
                    snapshot.broker_revision,
                )
            )
            _record(
                entities,
                codes,
                "EXECUTION",
                execution.execution_id,
                ReconcileStatus.CONFLICT,
                "EXECUTION_CORRECTION",
                recorded.order_id,
            )
        else:
            _record(
                entities,
                codes,
                "EXECUTION",
                execution.execution_id,
                ReconcileStatus.MATCHED,
                "EXECUTION_MATCHED",
                recorded.order_id,
            )
        if (
            owner.request.expires_at is not None
            and execution.executed_at > owner.request.expires_at
        ):
            _record(
                entities,
                codes,
                "EXECUTION",
                execution.execution_id,
                ReconcileStatus.CONFLICT,
                "POST_GTD_FILL",
                recorded.order_id,
            )
    for recorded in ledger.executions:
        if recorded.fill.execution_id in broker_exec:
            continue
        if recorded.fill.occurred_at < snapshot.executions_since:
            _record(
                entities,
                codes,
                "EXECUTION",
                recorded.fill.execution_id,
                ReconcileStatus.UNKNOWN,
                "EXECUTION_OUTSIDE_WINDOW",
                recorded.order_id,
            )
            continue
        quantity, price = _effective(recorded)
        if quantity == 0:
            _record(
                entities,
                codes,
                "EXECUTION",
                recorded.fill.execution_id,
                ReconcileStatus.MATCHED,
                "BUST_ALREADY_RECORDED",
                recorded.order_id,
            )
            continue
        events.append(
            _compensating_event(
                "BUST",
                recorded.fill.execution_id,
                recorded.order_id,
                quantity,
                Decimal(0),
                price or recorded.fill.price,
                None,
                recorded.fill.occurred_at,
                None,
                snapshot.broker_revision,
            )
        )
        _record(
            entities,
            codes,
            "EXECUTION",
            recorded.fill.execution_id,
            ReconcileStatus.CONFLICT,
            "EXECUTION_BUST",
            recorded.order_id,
        )

    local_positions = dict(ledger.positions)
    broker_positions = {item.instrument_id: item.quantity for item in snapshot.positions}
    for instrument_id in sorted(local_positions.keys() | broker_positions.keys()):
        left = local_positions.get(instrument_id, Decimal(0))
        right = broker_positions.get(instrument_id, Decimal(0))
        if left == right:
            _record(
                entities,
                codes,
                "POSITION",
                instrument_id,
                ReconcileStatus.MATCHED,
                "POSITION_MATCHED",
            )
        else:
            _record(
                entities,
                codes,
                "POSITION",
                instrument_id,
                ReconcileStatus.CONFLICT,
                "POSITION_MISMATCH",
            )
    return _result(
        snapshot,
        ledger,
        expected_venue,
        entities,
        codes,
        events,
        updates,
        session_start_anchor,
    )


class ReconcilePortV1(Protocol):
    """Read exact OMS evidence and append one observation transactionally."""

    async def account_evidence(
        self, environment: BrokerEnvironment, account_id: str
    ) -> LocalLedgerEvidenceV1: ...

    async def append_reconciliation(
        self, result: ReconcileResultV1, *, expected_ledger_revision: int
    ) -> None: ...

    async def append_operator_resolution(self, resolution: OperatorResolutionV1) -> None: ...


async def append_operator_resolution(
    ledger_port: ReconcilePortV1,
    result: ReconcileResultV1,
    *,
    actor_id: str,
    reason: str,
    evidence_digest: str,
) -> OperatorResolutionV1:
    """Persist an evidenced human decision without changing account status."""
    resolution = record_operator_resolution(
        result, actor_id=actor_id, reason=reason, evidence_digest=evidence_digest
    )
    try:
        await ledger_port.append_operator_resolution(resolution)
    except Exception:
        raise ReconcileError("RESOLUTION_NOT_COMMITTED") from None
    require(resolution, _TAG)
    return resolution


async def reconcile_once(
    broker: BrokerPortV1,
    ledger_port: ReconcilePortV1,
    expected_venue: VenueIdentityV1,
    *,
    observed_at_ns: int,
    now_ns: int,
    max_age_ns: int,
    session_start_anchor: VerifiedSessionStartAnchorV1 | None = None,
) -> ReconcileResultV1:
    """One read-only broker cycle, then one mandatory transactional OMS append."""
    if type(expected_venue) is not VenueIdentityV1:
        raise ReconcileError("INVALID_EXPECTED_VENUE")
    expected_venue.assert_sealed()
    _validate_session_start_anchor(session_start_anchor)
    try:
        observed_at_ns = _ns(observed_at_ns)
        actual_venue = broker.venue
        actual_venue.assert_sealed()
        ledger = await ledger_port.account_evidence(
            expected_venue.environment, expected_venue.account_id
        )
        _validate_ledger(ledger)
        if actual_venue != expected_venue:
            result = _unavailable_result(
                expected_venue,
                ledger,
                observed_at_ns,
                "ACCOUNT_SCOPE_MISMATCH",
                observed_identity=actual_venue,
            )
        else:
            try:
                view = broker.read_account_view(expected_venue.account_id)
            except BrokerOutcomeUnknown:
                result = _unavailable_result(
                    expected_venue,
                    ledger,
                    observed_at_ns,
                    "BROKER_ACCOUNT_VIEW_UNKNOWN",
                    observed_identity=actual_venue,
                )
            else:
                snapshot = build_broker_snapshot(view, actual_venue, observed_at_ns=observed_at_ns)
                result = reconcile_account(
                    snapshot,
                    ledger,
                    expected_venue,
                    now_ns=now_ns,
                    max_age_ns=max_age_ns,
                    session_start_anchor=session_start_anchor,
                )
        await ledger_port.append_reconciliation(
            result, expected_ledger_revision=ledger.ledger_revision
        )
        require(result, _TAG)
        return result
    except Exception:
        raise ReconcileError("RECONCILIATION_NOT_COMMITTED") from None


__all__ = [
    "BrokerSnapshotV1",
    "CompensatingEventV1",
    "LocalLedgerEvidenceV1",
    "ObservationSource",
    "OperatorResolutionV1",
    "OrderUpdateV1",
    "ReconcileEntityV1",
    "ReconcileError",
    "ReconcilePortV1",
    "ReconcileResultV1",
    "ReconcileStatus",
    "RecordedExecutionV1",
    "VerificationStatus",
    "VerifiedSessionStartAnchorV1",
    "append_operator_resolution",
    "build_broker_snapshot",
    "reconcile_account",
    "reconcile_once",
    "record_operator_resolution",
]
