"""SQLite-authoritative OMS ledger with append-only events and executions.

Every outbound marker is committed before the caller touches the fake port.
A crash at any point after that marker is uncertain and must be reconciled.
"""

from __future__ import annotations

import asyncio
import hashlib
import heapq
import logging
import os
import re
import threading
import time
from collections.abc import Coroutine, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal, Inexact, localcontext
from pathlib import Path
from typing import Any, Literal, NoReturn, SupportsIndex, cast
from uuid import uuid4
from weakref import WeakKeyDictionary, WeakSet

from sqlalchemy import (
    Column,
    CursorResult,
    Integer,
    String,
    Table,
    and_,
    func,
    insert,
    select,
    text,
    update,
)
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from leviathan_core.execution.broker_port_v1 import BrokerPortV1, BrokerRejectionCode
from leviathan_core.execution.broker_reconciliation import (
    BrokerAccountView,
    BrokerLookup,
    BrokerMatch,
    BrokerReconciliationPort,
    BrokerReconciliationStatus,
    broker_evidence_digest,
)
from leviathan_core.execution.oms import (
    ActivityCorrectionItem,
    ActivityFillItem,
    ActivityLedgerPage,
    ActivityLedgerSnapshot,
    ActivityOrderItem,
    DispatchGate,
    OrderGatewayActor,
    VerifiedSubmitSnapshot,
    _DefaultDispatchGate,
    _issue_order_gateway_actor,
)
from leviathan_core.execution.order_models import (
    BrokerObservation,
    ClientIdKey,
    DispatchGuard,
    Fill,
    FillCorrection,
    LedgerIntegrityKey,
    OMSConflict,
    OMSDiscrepancy,
    OMSLedgerCorruption,
    OMSValidationError,
    OperatorAuthorizationKey,
    OperatorGuardConfirmation,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
    parse_oms_decimal,
)
from leviathan_core.execution.venue_conflict_resolution import (
    VenueConflictResolutionCode,
    VenueConflictResolutionError,
    VenueConflictResolutionRequest,
    require_venue_conflict_resolution_request,
)
from leviathan_core.numeric import canonical_json, exact_sum
from leviathan_store.oms_operator_resolution import OmsOperatorResolutionRow
from leviathan_store.tables import (
    OmsEventRow,
    OmsFillCorrectionRow,
    OmsFillRow,
    OmsLedgerHeadRow,
    OmsObservationRow,
    OmsOrderRow,
    SchemaMigrationRow,
    StoreBase,
)

_LOGGER = logging.getLogger(__name__)
_CHECKPOINT_INTERVAL = 256
_CHECKPOINT_TABLE = Table(
    "oms_ledger_checkpoints",
    StoreBase.metadata,
    Column("environment", String, primary_key=True),
    Column("account_id", String, primary_key=True),
    Column("sequence", Integer, primary_key=True),
    Column("chain_head", String, nullable=False),
    Column("signature", String, nullable=False),
)

_DENIAL_CODES = {
    "DISPATCH_EVIDENCE_REQUIRED",
    "DISPATCH_SCOPE_MISMATCH",
    "ACCOUNT_UNVERIFIED",
    "ENTITLEMENT_UNVERIFIED",
    "FEED_STALE",
    "RISK_NOT_APPROVED",
    "HALT_ACTIVE",
    "ACTIVATION_NOT_ALLOWED",
    "ACCOUNT_RECONCILIATION_REQUIRED",
    "ACCOUNT_RECONCILE_REQUIRED",
}
_DISCREPANCY_CODES = {
    "OVERFILL",
    "FILL_AFTER_GTD",
    "FILL_AFTER_TERMINAL",
    "CANCEL_STATUS_UNCONFIRMED",
    "FILL_CORRECTION",
    "MISSING_EXECUTIONS",
    "BROKER_STATE_DIVERGENCE",
    "REJECT_AFTER_FILL",
    "BROKER_SCOPE_MISMATCH",
    "POST_DISPATCH_CONFLICT",
    "GATE_DENIED_CANCEL",
    "BROKER_EXECUTION_CONFLICT",
    "VENUE_MISMATCH",
    "VENUE_ACCOUNT_CONFLICT",
    "VENUE_ACCOUNT_CONFLICT_RESOLVED",
}
_EVENT_CODES = _DENIAL_CODES | {
    "ORDER_CREATED",
    "RISK_CHECK_STARTED",
    "FAKE_RISK_READY",
    "OUTBOUND_SUBMIT_COMMITTED",
    "BROKER_SUBMIT_RESULT",
    "SUBMIT_UNKNOWN",
    "REJECT_AFTER_FILL",
    "OUTBOUND_CANCEL_COMMITTED",
    "BROKER_CANCEL_CONFIRMED",
    "CANCEL_UNCONFIRMED",
    "BROKER_FILL",
    "FILL_AFTER_TERMINAL",
    "BROKER_FILL_CORRECTION",
    "BROKER_SCOPE_MISMATCH",
    "STALE_BROKER_OBSERVATION",
    "BROKER_STATE_DIVERGENCE",
    "MISSING_EXECUTIONS",
    "BROKER_RECONCILIATION",
    "BROKER_READ_UNAVAILABLE",
    "BROKER_EVIDENCE_ABSENT",
    "BROKER_INTENT_FOUND",
    "BROKER_ACCOUNT_ACTIVITY_UNMATCHED",
    "BROKER_DISPATCH_NOT_PLACED",
    "STALE_BROKER_VIEW",
    "POST_DISPATCH_CONFLICT",
    "DISPATCH_GUARD_SET",
    "DISPATCH_GATE_DENIED",
    "BROKER_EXECUTION_CONFLICT",
    "VENUE_MISMATCH",
    "VENUE_ACCOUNT_CONFLICT",
    "VENUE_ACCOUNT_CONFLICT_RESOLVED",
    "BROKER_GUARD_ADOPTED",  # historical signed events remain readable
    "CANCEL_IN_FLIGHT",
    "OPERATOR_GUARD_RELEASED",
    "RECOVERED_UNCERTAIN",
}
_TERMINAL_STATES = {
    OrderState.RISK_REJECTED,
    OrderState.REJECTED,
    OrderState.REJECTED_HALTED,
    OrderState.CANCELED,
    OrderState.EXPIRED,
    OrderState.FILLED,
}


class _ExclusiveLedgerLock:
    """One owner lease, with an OS byte-range lock for file-backed SQLite."""

    def __init__(self, database: str | None) -> None:
        self._closed = False
        self.mutex = asyncio.Lock()
        self.active_dispatch: set[str] = set()
        self.armed_here: dict[str, int] = {}
        self.issued_here: set[tuple[str, int]] = set()
        self._file = None
        if database is None:
            return
        path = Path(database).resolve()
        self._file = open(path.with_name(path.name + ".oms.lock"), "a+b")  # noqa: SIM115
        try:
            self._file.seek(0)
            if not self._file.read(1):
                self._file.seek(0)
                self._file.write(b"\0")
                self._file.flush()
            self._file.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import importlib

                fcntl = importlib.import_module("fcntl")
                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._file.close()
            raise OMSConflict("OMS_LEDGER_LOCKED") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._file is None:
            return
        try:
            self._file.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import importlib

                fcntl = importlib.import_module("fcntl")
                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        finally:
            self._file.close()

    @property
    def closed(self) -> bool:
        return self._closed


_ENGINE_LOCKS: WeakKeyDictionary[AsyncEngine, _ExclusiveLedgerLock] = WeakKeyDictionary()
_ACTOR_TASKS: WeakKeyDictionary[OrderLedger, asyncio.Task[Any]] = WeakKeyDictionary()
_ISSUED_LEDGERS: WeakSet[OrderLedger] = WeakSet()
_OWNER_CLAIM_LOCK = threading.RLock()
_ACTIVITY_SNAPSHOT_ISSUER = object()
_ACTIVITY_GIL_YIELD_ROWS = 1


class _ActivityReadWorker:
    """Own one pinned read connection and its asyncio loop on a worker thread."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name="oms-activity-reader",
            daemon=True,
        )
        self.engine: AsyncEngine | None = None
        self.session: AsyncSession | None = None
        self.thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.ready.set()
        self.loop.run_forever()
        pending = asyncio.all_tasks(self.loop)
        for task in pending:
            task.cancel()
        if pending:
            self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        self.loop.close()

    async def run(self, operation: Coroutine[Any, Any, Any]) -> Any:
        try:
            ready = await asyncio.to_thread(self.ready.wait, 5)
        except BaseException:
            operation.close()
            self.loop.call_soon_threadsafe(self.loop.stop)
            raise
        if not ready:
            self.loop.call_soon_threadsafe(self.loop.stop)
            await asyncio.to_thread(self.thread.join, 5)
            operation.close()
            raise OMSConflict("ACTIVITY_READ_UNAVAILABLE") from None
        future = asyncio.run_coroutine_threadsafe(operation, self.loop)
        return await asyncio.wrap_future(future)

    async def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        await asyncio.to_thread(self.thread.join, 5)
        if self.thread.is_alive():
            raise OMSConflict("ACTIVITY_SNAPSHOT_TIMEOUT") from None


@dataclass(slots=True, eq=False)
class _ActivityReadSnapshot:
    owner: object
    session: AsyncSession | None
    environment: str
    account_id: str
    high_water_sequence: int
    expires_at: float
    worker: _ActivityReadWorker | None

    def __init__(
        self,
        issuer: object,
        owner: object,
        session: AsyncSession | None,
        environment: str,
        account_id: str,
        high_water_sequence: int,
        worker: _ActivityReadWorker | None = None,
    ) -> None:
        if issuer is not _ACTIVITY_SNAPSHOT_ISSUER:
            raise OMSValidationError("INVALID_ACTIVITY_SNAPSHOT")
        self.owner = owner
        self.session = session
        self.environment = environment
        self.account_id = account_id
        self.high_water_sequence = high_water_sequence
        self.expires_at = time.monotonic() + 30.0
        self.worker = worker


class OrderLedger:
    """The single durable order/fill ledger for the bounded OMS core."""

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise OMSValidationError("OMS_LEDGER_SEALED")

    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        key: LedgerIntegrityKey | None = None,
        operator_key: OperatorAuthorizationKey | None = None,
    ) -> None:
        if not isinstance(sessions, async_sessionmaker):
            raise OMSValidationError("OMS_SQLITE_REQUIRED")
        engine = sessions.kw.get("bind")
        if not isinstance(engine, AsyncEngine) or engine.url.get_backend_name() != "sqlite":
            raise OMSValidationError("OMS_SQLITE_REQUIRED")
        with _OWNER_CLAIM_LOCK:
            if self in _ISSUED_LEDGERS:
                raise OMSConflict("OMS_LEDGER_LOCKED")
            existing = _ENGINE_LOCKS.get(engine)
            if existing is not None and not existing.closed:
                raise OMSConflict("OMS_LEDGER_LOCKED")
            database = engine.url.database
            lock = _ExclusiveLedgerLock(None if database in (None, "", ":memory:") else database)
            self._sessions = sessions
            self._key = key
            self._operator_key = operator_key
            self._engine = engine
            self._activity_snapshot_owner = object()
            self._activity_snapshots: dict[int, _ActivityReadSnapshot] = {}
            self._activity_wal_ready = False
            self._activity_wal_lock = asyncio.Lock()
            _ENGINE_LOCKS[engine] = lock

            def release_on_dispose(_sync_engine: object) -> None:
                with _OWNER_CLAIM_LOCK:
                    if _ENGINE_LOCKS.get(engine) is not lock:
                        return
                    # A live actor or side effect retains the owner lease.
                    if lock.active_dispatch or self in _ACTOR_TASKS:
                        return
                    lock.close()
                    _ENGINE_LOCKS.pop(engine, None)

            sqlalchemy_event.listen(engine.sync_engine, "engine_disposed", release_on_dispose)
            self._writer_lock = lock
            self.dispatch_mutex = lock.mutex
            self.active_dispatch = lock.active_dispatch
            self._armed_here = lock.armed_here
            self._issued_here = lock.issued_here
            _ISSUED_LEDGERS.add(self)

    def close(self) -> None:
        """Release ownership after the actor has stopped, or for a store-only test."""
        with _OWNER_CLAIM_LOCK:
            if self in _ACTOR_TASKS or self.active_dispatch:
                raise OMSConflict("OMS_LEDGER_BUSY")
            self._writer_lock.close()
            if _ENGINE_LOCKS.get(self._engine) is self._writer_lock:
                _ENGINE_LOCKS.pop(self._engine, None)

    def _require_actor_task(self) -> None:
        with _OWNER_CLAIM_LOCK:
            owner = _ACTOR_TASKS.get(self)
        if owner is not asyncio.current_task():
            raise OMSValidationError("OMS_ACTOR_REQUIRED")

    def _require_actor_when_bound(self) -> None:
        with _OWNER_CLAIM_LOCK:
            owner = _ACTOR_TASKS.get(self)
        if owner is not None and owner is not asyncio.current_task():
            raise OMSValidationError("OMS_ACTOR_REQUIRED")

    def __copy__(self) -> NoReturn:
        raise OMSConflict("OMS_LEDGER_LOCKED")

    def __deepcopy__(self, _memo: object) -> NoReturn:
        raise OMSConflict("OMS_LEDGER_LOCKED")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise OMSConflict("OMS_LEDGER_LOCKED")

    def _integrity_key(self) -> LedgerIntegrityKey:
        if self._writer_lock is not None and self._writer_lock.closed:
            raise OMSConflict("OMS_LEDGER_CLOSED")
        if not isinstance(self._key, LedgerIntegrityKey):
            raise OMSLedgerCorruption()
        return self._key

    @staticmethod
    def _canonical_value(value: Any) -> Any:
        if isinstance(value, datetime):
            return OrderLedger._stored_time(value).isoformat()
        if isinstance(value, dict):
            return {key: OrderLedger._canonical_value(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [OrderLedger._canonical_value(item) for item in value]
        return value

    @classmethod
    def _row_payload(cls, row: Any, *, exclude: frozenset[str]) -> bytes:
        data = {
            column.name: cls._canonical_value(getattr(row, column.name))
            for column in row.__table__.columns
            if column.name not in exclude
        }
        return canonical_json({"table": row.__tablename__, "row": data})

    @staticmethod
    def _validate_operator_resolution_row(row: OmsOperatorResolutionRow) -> None:
        digest_pattern = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
        identifier_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z", re.ASCII)
        if (
            type(row.resolution_id) is not str
            or digest_pattern.fullmatch(row.resolution_id) is None
            or type(row.environment) is not str
            or row.environment not in {"paper", "demo", "live"}
            or type(row.account_id) is not str
            or identifier_pattern.fullmatch(row.account_id) is None
            or type(row.conflict_id) is not str
            or digest_pattern.fullmatch(row.conflict_id) is None
            or type(row.binding_venue) is not str
            or identifier_pattern.fullmatch(row.binding_venue) is None
            or type(row.binding_environment) is not str
            or row.binding_environment not in {"paper", "demo", "live"}
            or type(row.observation_ids) is not list
            or not row.observation_ids
            or any(
                type(item) is not str or identifier_pattern.fullmatch(item) is None
                for item in row.observation_ids
            )
            or row.observation_ids != sorted(set(row.observation_ids))
            or type(row.identity_digest) is not str
            or digest_pattern.fullmatch(row.identity_digest) is None
            or type(row.idempotency_digest) is not str
            or digest_pattern.fullmatch(row.idempotency_digest) is None
            or type(row.operator_principal_id) is not str
            or identifier_pattern.fullmatch(row.operator_principal_id) is None
            or type(row.reason_code) is not str
            or row.reason_code
            not in {
                "BINDING_VERIFIED",
                "BROKER_STATE_RECONCILED",
                "OPERATOR_CORRECTION_CONFIRMED",
            }
            or type(row.broker_revision) is not int
            or not 0 <= row.broker_revision <= 2**63 - 1
            or type(row.broker_evidence_digest) is not str
            or digest_pattern.fullmatch(row.broker_evidence_digest) is None
            or type(row.prior_ledger_revision) is not int
            or row.prior_ledger_revision < 0
            or type(row.resolved_at_ns) is not int
            or row.resolved_at_ns < 0
            or type(row.affected_order_ids) is not list
            or not row.affected_order_ids
            or any(
                type(order_id) is not str or identifier_pattern.fullmatch(order_id) is None
                for order_id in row.affected_order_ids
            )
            or row.affected_order_ids != sorted(set(row.affected_order_ids))
            or not isinstance(row.recorded_at, datetime)
        ):
            raise OMSLedgerCorruption()

    async def _ensure_operator_resolution_schema(self) -> None:
        """Apply only the additive OMS-OPS table before its first actor use."""
        async with self._engine.begin() as connection:
            table = cast(Table, OmsOperatorResolutionRow.__table__)
            await connection.run_sync(table.create, checkfirst=True)
            migration = await connection.scalar(
                select(SchemaMigrationRow.version).where(SchemaMigrationRow.version == 4)
            )
            if migration is None:
                await connection.execute(
                    insert(SchemaMigrationRow).values(
                        version=4,
                        name="oms_ops_001_venue_conflict_resolution",
                        applied_at=datetime.now(UTC),
                    )
                )

    async def _active_venue_conflict(
        self, session: AsyncSession, environment: str, account_id: str
    ) -> tuple[str, tuple[str, ...], str, str, tuple[str, ...], str] | None:
        orders, children = await self._account_rows(session, environment, account_id)
        snapshots = {row.order_id: await self._snapshot(session, row) for row in orders}
        affected = tuple(
            sorted(
                order_id
                for order_id, snapshot in snapshots.items()
                if "VENUE_ACCOUNT_CONFLICT" in snapshot.discrepancies
            )
        )
        if not affected:
            return None
        events = [
            child
            for child in children
            if isinstance(child, OmsEventRow)
            and child.order_id in affected
            and child.code == "VENUE_ACCOUNT_CONFLICT"
        ]
        latest: dict[str, OmsEventRow] = {}
        for event in events:
            if event.order_id not in latest or event.sequence > latest[event.order_id].sequence:
                latest[event.order_id] = event
        if set(latest) != set(affected):
            raise OMSLedgerCorruption()
        captured = [
            latest[order_id].evidence
            for order_id in affected
            if set(latest[order_id].evidence) > {"discrepancies"}
        ]
        if len(captured) != 1:
            raise VenueConflictResolutionError(
                VenueConflictResolutionCode.LEGACY_CONFLICT_UNWAIVABLE
            )
        identity = captured[0]
        required = {
            "discrepancies",
            "binding_venue",
            "binding_environment",
            "observations",
            "affected_order_ids",
            "identity_digest",
        }
        if (
            set(identity) != required
            or identity.get("affected_order_ids") != list(affected)
            or type(identity.get("binding_venue")) is not str
            or type(identity.get("binding_environment")) is not str
            or type(identity.get("observations")) is not list
            or not identity["observations"]
            or any(
                not isinstance(item, dict)
                or set(item) != {"observation_id", "venue", "environment"}
                or any(
                    type(item.get(field)) is not str
                    for field in ("observation_id", "venue", "environment")
                )
                for item in identity["observations"]
            )
        ):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.CONFLICT_NOT_FOUND)
        observations = tuple(
            sorted(
                (item["observation_id"], item["venue"], item["environment"])
                for item in identity["observations"]
            )
        )
        if len({item[0] for item in observations}) != len(observations):
            raise OMSLedgerCorruption()
        identity_payload = {
            "environment": environment,
            "account_id": account_id,
            "binding_venue": identity["binding_venue"],
            "binding_environment": identity["binding_environment"],
            "observations": [list(item) for item in observations],
            "affected_order_ids": list(affected),
        }
        identity_digest = hashlib.sha256(canonical_json(identity_payload)).hexdigest()
        if identity.get("identity_digest") != identity_digest:
            raise OMSLedgerCorruption()
        material = {
            "environment": environment,
            "account_id": account_id,
            "binding_venue": identity["binding_venue"],
            "binding_environment": identity["binding_environment"],
            "observation_ids": [item[0] for item in observations],
            "identity_digest": identity_digest,
            "orders": [
                [
                    order_id,
                    latest[order_id].sequence,
                    latest[order_id].state,
                    latest[order_id].evidence,
                ]
                for order_id in affected
            ],
        }
        conflict_id = hashlib.sha256(canonical_json(material)).hexdigest()
        return (
            conflict_id,
            affected,
            identity["binding_venue"],
            identity["binding_environment"],
            tuple(item[0] for item in observations),
            identity_digest,
        )

    @staticmethod
    def _resolution_row_values(row: OmsOperatorResolutionRow) -> dict[str, Any]:
        OrderLedger._validate_operator_resolution_row(row)
        return {
            "resolution_id": row.resolution_id,
            "environment": row.environment,
            "account_id": row.account_id,
            "conflict_id": row.conflict_id,
            "binding_venue": row.binding_venue,
            "binding_environment": row.binding_environment,
            "observation_ids": tuple(row.observation_ids),
            "identity_digest": row.identity_digest,
            "operator_principal_id": row.operator_principal_id,
            "broker_revision": row.broker_revision,
            "broker_evidence_digest": row.broker_evidence_digest,
            "prior_ledger_revision": row.prior_ledger_revision,
            "resolved_ledger_revision": (
                row.prior_ledger_revision + 1 + len(row.affected_order_ids)
            ),
            "affected_order_ids": tuple(row.affected_order_ids),
            "resolved_at_ns": row.resolved_at_ns,
        }

    async def _account_rows(
        self, session: AsyncSession, environment: str, account_id: str
    ) -> tuple[list[OmsOrderRow], list[Any]]:
        orders = list(
            (
                await session.scalars(
                    select(OmsOrderRow)
                    .where(
                        OmsOrderRow.environment == environment, OmsOrderRow.account_id == account_id
                    )
                    .order_by(OmsOrderRow.order_id)
                )
            ).all()
        )
        children: list[Any] = []
        for row_type in (
            OmsFillRow,
            OmsFillCorrectionRow,
            OmsObservationRow,
            OmsEventRow,
        ):
            children.extend(
                (
                    await session.scalars(
                        select(row_type)
                        .join(OmsOrderRow, row_type.order_id == OmsOrderRow.order_id)
                        .where(
                            OmsOrderRow.environment == environment,
                            OmsOrderRow.account_id == account_id,
                        )
                    )
                ).all()
            )
        children.extend(
            (
                await session.scalars(
                    select(OmsOperatorResolutionRow).where(
                        OmsOperatorResolutionRow.environment == environment,
                        OmsOperatorResolutionRow.account_id == account_id,
                    )
                )
            ).all()
        )
        return orders, children

    @staticmethod
    def _cache_digest(orders: Sequence[OmsOrderRow]) -> str:
        return hashlib.sha256(
            canonical_json([[row.order_id, row.chain] for row in orders])
        ).hexdigest()

    def _head_payload(self, head: OmsLedgerHeadRow) -> bytes:
        # Legacy unguarded heads retain their exact ADR-0004 signed bytes.
        guard_fields = frozenset(
            {
                "guard_order_id",
                "guard_action",
                "guard_client_order_id",
                "guard_attempt",
                "guard_revision",
            }
        )
        excluded = frozenset({"anchor"}) | (
            guard_fields if head.guard_order_id is None else frozenset()
        )
        if head.fence_epoch is None:
            excluded |= frozenset({"fence_epoch"})
        return self._row_payload(head, exclude=excluded)

    @staticmethod
    def _checkpoint_payload(
        environment: str, account_id: str, sequence: int, chain_head: str
    ) -> bytes:
        return canonical_json(
            {
                "domain": "OMS_LEDGER_CHECKPOINT_V1",
                "environment": environment,
                "account_id": account_id,
                "sequence": sequence,
                "chain_head": chain_head,
            }
        )

    async def _checkpoint_rows(
        self,
        session: AsyncSession,
        environment: str,
        account_id: str,
        *,
        latest_only: bool = False,
    ) -> list[dict[str, Any]]:
        statement = select(_CHECKPOINT_TABLE).where(
            _CHECKPOINT_TABLE.c.environment == environment,
            _CHECKPOINT_TABLE.c.account_id == account_id,
        )
        if latest_only:
            statement = statement.order_by(_CHECKPOINT_TABLE.c.sequence.desc()).limit(1)
        else:
            statement = statement.order_by(_CHECKPOINT_TABLE.c.sequence)
        try:
            result = await session.execute(statement)
        except OperationalError as exc:
            # A legacy schema without the additive checkpoint table is read as
            # an account with no checkpoints. Reads never repair or mutate DDL.
            if "no such table" in str(exc).lower() and "oms_ledger_checkpoints" in str(exc).lower():
                return []
            raise
        return [dict(row) for row in result.mappings().all()]

    def _validate_checkpoint(
        self,
        row: dict[str, Any],
        environment: str,
        account_id: str,
        *,
        maximum_sequence: int,
    ) -> tuple[int, str]:
        sequence = row.get("sequence")
        chain_head = row.get("chain_head")
        signature = row.get("signature")
        if (
            row.get("environment") != environment
            or row.get("account_id") != account_id
            or type(sequence) is not int
            or sequence < 1
            or sequence > maximum_sequence
            or type(chain_head) is not str
            or re.fullmatch(r"[0-9a-f]{64}", chain_head, re.ASCII) is None
            or type(signature) is not str
            or re.fullmatch(r"[0-9a-f]{64}", signature, re.ASCII) is None
        ):
            raise OMSLedgerCorruption()
        payload = self._checkpoint_payload(environment, account_id, sequence, chain_head)
        if not self._integrity_key().verify(payload, signature):
            raise OMSLedgerCorruption()
        return sequence, chain_head

    @staticmethod
    def _guard_from_head(head: OmsLedgerHeadRow) -> DispatchGuard | None:
        fields = (
            head.guard_order_id,
            head.guard_action,
            head.guard_client_order_id,
            head.guard_attempt,
            head.guard_revision,
        )
        if fields == (None, None, None, None, None):
            return None
        try:
            if (
                not isinstance(head.guard_order_id, str)
                or not isinstance(head.guard_action, str)
                or not isinstance(head.guard_client_order_id, str)
                or type(head.guard_attempt) is not int
                or type(head.guard_revision) is not int
                or type(head.fence_epoch) is not int
            ):
                raise OMSLedgerCorruption()
            return DispatchGuard(
                head.environment,
                head.account_id,
                head.guard_order_id,
                head.guard_action,
                head.guard_client_order_id,
                head.guard_attempt,
                head.guard_revision,
                head.fence_epoch,
            )
        except (OMSValidationError, TypeError):
            raise OMSLedgerCorruption() from None

    async def _verify_account(
        self, session: AsyncSession, environment: str, account_id: str
    ) -> None:
        key = self._integrity_key()
        try:
            head = await session.get(OmsLedgerHeadRow, (environment, account_id))
            orders, children = await self._account_rows(session, environment, account_id)
            checkpoint_rows = await self._checkpoint_rows(session, environment, account_id)
            if head is None:
                if orders or children or checkpoint_rows:
                    raise OMSLedgerCorruption()
                return
            if not orders or type(head.sequence_count) is not int or head.sequence_count < 1:
                raise OMSLedgerCorruption()
            if head.fence_epoch is not None and (
                type(head.fence_epoch) is not int or head.fence_epoch < 1
            ):
                raise OMSLedgerCorruption()
            if not key.verify(self._head_payload(head), head.anchor):
                raise OMSLedgerCorruption()
            guard = self._guard_from_head(head)
            if guard is not None:
                guarded = next((row for row in orders if row.order_id == guard.order_id), None)
                if guarded is None or guarded.client_order_id != guard.client_order_id:
                    raise OMSLedgerCorruption()
            if head.order_count != len(orders):
                raise OMSLedgerCorruption()
            chain = "0" * 64
            if len(children) != head.sequence_count:
                raise OMSLedgerCorruption()
            checkpoint_heads: dict[int, str] = {}
            for checkpoint in checkpoint_rows:
                sequence, checkpoint_head = self._validate_checkpoint(
                    checkpoint,
                    environment,
                    account_id,
                    maximum_sequence=head.sequence_count,
                )
                if sequence in checkpoint_heads:
                    raise OMSLedgerCorruption()
                checkpoint_heads[sequence] = checkpoint_head
            children.sort(
                key=lambda row: row.ledger_sequence if type(row.ledger_sequence) is int else -1
            )
            for number, child in enumerate(children, start=1):
                if child.ledger_sequence != number or type(child.chain) is not str:
                    raise OMSLedgerCorruption()
                if isinstance(child, OmsOperatorResolutionRow):
                    self._validate_operator_resolution_row(child)
                payload = bytes.fromhex(chain) + self._row_payload(
                    child, exclude=frozenset({"chain"})
                )
                if not key.verify(payload, child.chain):
                    raise OMSLedgerCorruption()
                chain = child.chain
                if number in checkpoint_heads and checkpoint_heads[number] != chain:
                    raise OMSLedgerCorruption()
            if head.head_chain != chain:
                raise OMSLedgerCorruption()
            resolution_ids = {
                child.resolution_id: child
                for child in children
                if isinstance(child, OmsOperatorResolutionRow)
            }
            event_rows = [child for child in children if isinstance(child, OmsEventRow)]
            for event in event_rows:
                if event.code == "VENUE_ACCOUNT_CONFLICT_RESOLVED":
                    evidence = event.evidence
                    resolution_id = (
                        evidence.get("resolution_id")
                        if isinstance(evidence, dict) and type(evidence.get("resolution_id")) is str
                        else None
                    )
                    resolution = (
                        resolution_ids.get(resolution_id) if resolution_id is not None else None
                    )
                    if (
                        not isinstance(evidence, dict)
                        or type(evidence.get("resolution_id")) is not str
                        or resolution is None
                        or event.order_id not in resolution.affected_order_ids
                        or evidence.get("conflict_id") != resolution.conflict_id
                        or evidence.get("identity_digest") != resolution.identity_digest
                        or evidence.get("broker_revision") != resolution.broker_revision
                        or evidence.get("broker_evidence_digest")
                        != resolution.broker_evidence_digest
                        or evidence.get("prior_ledger_revision") != resolution.prior_ledger_revision
                        or evidence.get("resolved_state") != event.state
                    ):
                        raise OMSLedgerCorruption()
            for row in orders:
                payload = bytes.fromhex(chain) + self._row_payload(
                    row, exclude=frozenset({"chain"})
                )
                if type(row.chain) is not str or not key.verify(payload, row.chain):
                    raise OMSLedgerCorruption()
            if head.order_cache_digest != self._cache_digest(orders):
                raise OMSLedgerCorruption()
            if guard is not None:
                guard_events = [
                    child
                    for child in children
                    if isinstance(child, OmsEventRow)
                    and child.order_id == guard.order_id
                    and child.code == "DISPATCH_GUARD_SET"
                ]
                if not guard_events:
                    raise OMSLedgerCorruption()
                last_guard = max(guard_events, key=lambda item: item.sequence)
                if last_guard.evidence != {
                    "action": guard.action,
                    "client_order_id": guard.client_order_id,
                    "attempt": guard.attempt,
                    "broker_revision": guard.broker_revision,
                    "fence_epoch": guard.fence_epoch,
                }:
                    raise OMSLedgerCorruption()
        except OMSLedgerCorruption:
            raise
        except Exception:
            raise OMSLedgerCorruption() from None

    async def _verify_activity_account_streaming(
        self,
        session: AsyncSession,
        environment: str,
        account_id: str,
        *,
        full_replay: bool = False,
    ) -> int:
        """Authenticate an activity read with memory bounded by fixed-size streams.

        Normal reads start at the latest signed checkpoint and authenticate only
        the bounded suffix, but they still authenticate every order row and
        compute the complete order-cache digest. Thus child-row HMAC work is
        bounded; total normal-read work remains O(order_count + suffix_rows).
        The scheduled full verifier requests ``full_replay`` and checks the
        checkpoint sequence/head against the complete chain.
        """
        key = self._integrity_key()
        try:
            head = await session.get(OmsLedgerHeadRow, (environment, account_id))
            checkpoints = await self._checkpoint_rows(
                session,
                environment,
                account_id,
                latest_only=not full_replay,
            )
            if head is None:
                if checkpoints:
                    raise OMSLedgerCorruption()
                starting_sequence = 0
                starting_chain = "0" * 64
            else:
                if (
                    type(head.sequence_count) is not int
                    or head.sequence_count < 1
                    or type(head.head_chain) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", head.head_chain, re.ASCII) is None
                    or not key.verify(self._head_payload(head), head.anchor)
                ):
                    raise OMSLedgerCorruption()
                verified_checkpoints: list[tuple[int, str]] = []
                prior_sequence = 0
                for checkpoint in checkpoints:
                    verified = self._validate_checkpoint(
                        checkpoint,
                        environment,
                        account_id,
                        maximum_sequence=head.sequence_count,
                    )
                    if verified[0] <= prior_sequence:
                        raise OMSLedgerCorruption()
                    prior_sequence = verified[0]
                    verified_checkpoints.append(verified)
                if full_replay:
                    starting_sequence = 0
                    starting_chain = "0" * 64
                elif verified_checkpoints:
                    starting_sequence, starting_chain = verified_checkpoints[-1]
                    if head.sequence_count - starting_sequence > _CHECKPOINT_INTERVAL:
                        raise OMSLedgerCorruption()
                else:
                    starting_sequence = 0
                    starting_chain = "0" * 64
            checkpoint_heads = dict(verified_checkpoints if checkpoints else [])
            order_chain_prefix = bytes.fromhex(head.head_chain) if head is not None else bytes(32)
            orders_result = await session.stream_scalars(
                select(OmsOrderRow)
                .where(
                    OmsOrderRow.environment == environment,
                    OmsOrderRow.account_id == account_id,
                )
                .order_by(OmsOrderRow.order_id)
                .execution_options(yield_per=100)
            )
            digest = hashlib.sha256()
            digest.update(b"[")
            order_count = 0
            guard_order_found = False
            async for row in orders_result:
                if (
                    type(row.order_id) is not str
                    or type(row.chain) is not str
                    or not key.verify(
                        order_chain_prefix + self._row_payload(row, exclude=frozenset({"chain"})),
                        row.chain,
                    )
                ):
                    raise OMSLedgerCorruption()
                if order_count:
                    digest.update(b",")
                digest.update(canonical_json([row.order_id, row.chain]))
                order_count += 1
                if head is not None and row.order_id == head.guard_order_id:
                    if row.client_order_id != head.guard_client_order_id:
                        raise OMSLedgerCorruption()
                    guard_order_found = True
                if order_count % _ACTIVITY_GIL_YIELD_ROWS == 0:
                    time.sleep(0)
            await orders_result.close()
            digest.update(b"]")
            if head is None:
                if order_count:
                    raise OMSLedgerCorruption()
                empty_check_types: tuple[Any, ...] = (
                    OmsEventRow,
                    OmsFillRow,
                    OmsFillCorrectionRow,
                    OmsObservationRow,
                    OmsOperatorResolutionRow,
                )
                for row_type in empty_check_types:
                    exists_statement: Any
                    if row_type is OmsOperatorResolutionRow:
                        exists_statement = select(row_type).where(
                            row_type.environment == environment,
                            row_type.account_id == account_id,
                        )
                    else:
                        exists_statement = (
                            select(row_type)
                            .join(OmsOrderRow, row_type.order_id == OmsOrderRow.order_id)
                            .where(
                                OmsOrderRow.environment == environment,
                                OmsOrderRow.account_id == account_id,
                            )
                        )
                    exists = await session.scalar(exists_statement.limit(1))
                    if exists is not None:
                        raise OMSLedgerCorruption()
                return 0
            if (
                order_count < 1
                or type(head.sequence_count) is not int
                or head.sequence_count < 1
                or type(head.order_count) is not int
                or head.order_count != order_count
                or head.order_cache_digest != digest.hexdigest()
                or (head.guard_order_id is not None and not guard_order_found)
                or (
                    head.fence_epoch is not None
                    and (type(head.fence_epoch) is not int or head.fence_epoch < 1)
                )
                or not key.verify(self._head_payload(head), head.anchor)
            ):
                raise OMSLedgerCorruption()
            self._guard_from_head(head)

            # The signed head counts every append-only child row in this
            # account chain. Comparing durable per-table counts catches a
            # missing prefix row even when the latest checkpoint is at the
            # head and the suffix is empty.
            child_counts: list[int] = []
            count_row_types: tuple[Any, ...] = (
                OmsEventRow,
                OmsFillRow,
                OmsFillCorrectionRow,
                OmsObservationRow,
                OmsOperatorResolutionRow,
            )
            for row_type in count_row_types:
                if row_type is OmsOperatorResolutionRow:
                    count_statement = (
                        select(func.count())
                        .select_from(row_type)
                        .where(
                            row_type.environment == environment,
                            row_type.account_id == account_id,
                        )
                    )
                else:
                    count_statement = (
                        select(func.count())
                        .select_from(row_type)
                        .join(OmsOrderRow, row_type.order_id == OmsOrderRow.order_id)
                        .where(
                            OmsOrderRow.environment == environment,
                            OmsOrderRow.account_id == account_id,
                        )
                    )
                count_value = await session.scalar(count_statement)
                if type(count_value) is not int or count_value < 0:
                    raise OMSLedgerCorruption()
                child_counts.append(count_value)
            if sum(child_counts) != head.sequence_count:
                raise OMSLedgerCorruption()

            row_types: tuple[Any, ...] = (
                OmsEventRow,
                OmsFillRow,
                OmsFillCorrectionRow,
                OmsObservationRow,
                OmsOperatorResolutionRow,
            )
            streams = []
            iterators = []
            heap: list[tuple[int, int, Any]] = []
            for index, row_type in enumerate(row_types):
                child_statement: Any
                if row_type is OmsOperatorResolutionRow:
                    child_statement = select(row_type).where(
                        row_type.environment == environment,
                        row_type.account_id == account_id,
                        row_type.ledger_sequence > starting_sequence,
                    )
                else:
                    child_statement = (
                        select(row_type)
                        .join(OmsOrderRow, row_type.order_id == OmsOrderRow.order_id)
                        .where(
                            OmsOrderRow.environment == environment,
                            OmsOrderRow.account_id == account_id,
                            row_type.ledger_sequence > starting_sequence,
                        )
                    )
                result = await session.stream_scalars(
                    child_statement.order_by(row_type.ledger_sequence).execution_options(
                        yield_per=100
                    )
                )
                streams.append(result)
                iterator = result.__aiter__()
                iterators.append(iterator)
                try:
                    first = await iterator.__anext__()
                except StopAsyncIteration:
                    continue
                if type(first.ledger_sequence) is not int:
                    raise OMSLedgerCorruption()
                heapq.heappush(heap, (first.ledger_sequence, index, first))

            chain = starting_chain
            sequence = starting_sequence
            suffix_rows = 0
            while heap:
                row_sequence, index, child = heapq.heappop(heap)
                sequence += 1
                if row_sequence != sequence or type(child.chain) is not str:
                    raise OMSLedgerCorruption()
                if isinstance(child, OmsOperatorResolutionRow):
                    self._validate_operator_resolution_row(child)
                payload = bytes.fromhex(chain) + self._row_payload(
                    child, exclude=frozenset({"chain"})
                )
                if not key.verify(payload, child.chain):
                    raise OMSLedgerCorruption()
                chain = child.chain
                suffix_rows += 1
                if (
                    full_replay
                    and sequence in checkpoint_heads
                    and checkpoint_heads[sequence] != chain
                ):
                    raise OMSLedgerCorruption()
                try:
                    following = await iterators[index].__anext__()
                except StopAsyncIteration:
                    continue
                if type(following.ledger_sequence) is not int:
                    raise OMSLedgerCorruption()
                heapq.heappush(heap, (following.ledger_sequence, index, following))
                if sequence % _ACTIVITY_GIL_YIELD_ROWS == 0:
                    time.sleep(0)
            for result in streams:
                await result.close()
            if sequence != (head.sequence_count if head is not None else 0) or (
                head is not None and chain != head.head_chain
            ):
                raise OMSLedgerCorruption()
            if full_replay and set(checkpoint_heads) - set(
                range(1, (head.sequence_count if head is not None else 0) + 1)
            ):
                raise OMSLedgerCorruption()

            if head.guard_order_id is not None:
                guard_events = await session.scalars(
                    select(OmsEventRow)
                    .where(
                        OmsEventRow.order_id == head.guard_order_id,
                        OmsEventRow.code == "DISPATCH_GUARD_SET",
                    )
                    .order_by(OmsEventRow.sequence.desc())
                    .limit(1)
                )
                event = guard_events.first()
                guard = self._guard_from_head(head)
                if (
                    event is None
                    or guard is None
                    or event.evidence
                    != {
                        "action": guard.action,
                        "client_order_id": guard.client_order_id,
                        "attempt": guard.attempt,
                        "broker_revision": guard.broker_revision,
                        "fence_epoch": guard.fence_epoch,
                    }
                ):
                    raise OMSLedgerCorruption()

            # Resolution linkage is checked with a streaming join, avoiding a
            # history-sized resolution/event dictionary.
            resolution_stmt = (
                select(OmsEventRow, OmsOperatorResolutionRow)
                .join(OmsOrderRow, OmsOrderRow.order_id == OmsEventRow.order_id)
                .outerjoin(
                    OmsOperatorResolutionRow,
                    OmsEventRow.evidence["resolution_id"].as_string()
                    == OmsOperatorResolutionRow.resolution_id,
                )
                .where(
                    OmsOrderRow.environment == environment,
                    OmsOrderRow.account_id == account_id,
                    OmsEventRow.code == "VENUE_ACCOUNT_CONFLICT_RESOLVED",
                )
                .execution_options(yield_per=100)
            )
            resolutions = await session.stream(resolution_stmt)
            async for event, resolution in resolutions:
                evidence = event.evidence
                if (
                    not isinstance(evidence, dict)
                    or resolution is None
                    or event.order_id not in resolution.affected_order_ids
                    or evidence.get("conflict_id") != resolution.conflict_id
                    or evidence.get("identity_digest") != resolution.identity_digest
                    or evidence.get("broker_revision") != resolution.broker_revision
                    or evidence.get("broker_evidence_digest") != resolution.broker_evidence_digest
                    or evidence.get("prior_ledger_revision") != resolution.prior_ledger_revision
                    or evidence.get("resolved_state") != event.state
                ):
                    raise OMSLedgerCorruption()
            await resolutions.close()
            _LOGGER.info(
                "OMS_LEDGER_INTEGRITY_VERIFIED suffix_rows=%d orders_verified=%d",
                suffix_rows,
                order_count,
            )
            return suffix_rows
        except OMSLedgerCorruption:
            raise
        except Exception:
            raise OMSLedgerCorruption() from None

    async def _seal_account(self, session: AsyncSession, environment: str, account_id: str) -> None:
        key = self._integrity_key()
        await session.flush()
        head = await session.get(OmsLedgerHeadRow, (environment, account_id))
        orders, children = await self._account_rows(session, environment, account_id)
        if not orders:
            raise OMSLedgerCorruption()
        new_children = [row for row in children if row.ledger_sequence is None]
        if not new_children:
            raise OMSLedgerCorruption()
        rank = {
            OmsFillRow: 0,
            OmsFillCorrectionRow: 1,
            OmsObservationRow: 2,
            OmsEventRow: 3,
            OmsOperatorResolutionRow: 4,
        }
        new_children.sort(
            key=lambda row: (
                rank[type(row)],
                row.resolution_id if isinstance(row, OmsOperatorResolutionRow) else row.id,
            )
        )
        count = head.sequence_count if head is not None else 0
        chain = head.head_chain if head is not None else "0" * 64
        for child in new_children:
            count += 1
            child.ledger_sequence = count
            child.chain = key.sign(
                bytes.fromhex(chain) + self._row_payload(child, exclude=frozenset({"chain"}))
            )
            chain = child.chain
        for row in orders:
            row.chain = key.sign(
                bytes.fromhex(chain) + self._row_payload(row, exclude=frozenset({"chain"}))
            )
        now = datetime.now(UTC)
        if head is None:
            head = OmsLedgerHeadRow(environment=environment, account_id=account_id)
            session.add(head)
        head.sequence_count = count
        head.head_chain = chain
        head.order_cache_digest = self._cache_digest(orders)
        head.order_count = len(orders)
        head.updated_at = now
        head.anchor = key.sign(self._head_payload(head))
        await session.flush()
        latest_checkpoint = await session.execute(
            select(_CHECKPOINT_TABLE.c.sequence)
            .where(
                _CHECKPOINT_TABLE.c.environment == environment,
                _CHECKPOINT_TABLE.c.account_id == account_id,
            )
            .order_by(_CHECKPOINT_TABLE.c.sequence.desc())
            .limit(1)
        )
        checkpoint_sequence = latest_checkpoint.scalar_one_or_none() or 0
        if count - checkpoint_sequence >= _CHECKPOINT_INTERVAL:
            await session.execute(
                insert(_CHECKPOINT_TABLE).values(
                    environment=environment,
                    account_id=account_id,
                    sequence=count,
                    chain_head=chain,
                    signature=key.sign(
                        self._checkpoint_payload(environment, account_id, count, chain)
                    ),
                )
            )
            await session.flush()
        # The live write and authoritative read pass through one replay
        # verifier; event and snapshot caches cannot diverge at commit.
        for row in orders:
            await self._snapshot_checked(session, row)

    @staticmethod
    def _stored_time(value: object) -> datetime:
        if not isinstance(value, datetime):
            raise OMSLedgerCorruption()
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @staticmethod
    def _stored_discrepancies(value: object) -> tuple[str, ...]:
        if (
            not isinstance(value, list)
            or any(type(item) is not str or item not in _DISCREPANCY_CODES for item in value)
            or len(value) != len(set(value))
        ):
            raise OMSLedgerCorruption()
        return tuple(value)

    @staticmethod
    def _checked_observation(row: OmsObservationRow) -> BrokerObservation:
        try:
            payload = row.evidence
            if not isinstance(payload, dict) or set(payload) != {
                "observation_id",
                "environment",
                "account_id",
                "venue",
                "client_order_id",
                "status",
                "observed_at",
                "venue_order_id",
                "broker_sequence",
            }:
                raise OMSLedgerCorruption()
            checked = BrokerObservation(
                observation_id=payload["observation_id"],
                environment=payload["environment"],
                account_id=payload["account_id"],
                venue=payload["venue"],
                client_order_id=payload["client_order_id"],
                status=OrderState(payload["status"]),
                observed_at=datetime.fromisoformat(payload["observed_at"]),
                venue_order_id=payload["venue_order_id"],
                broker_sequence=payload["broker_sequence"],
            )
            if (
                type(row.id) is not int
                or row.id < 1
                or checked.observation_id != row.observation_id
                or checked.account_id != row.account_id
                or checked.venue != row.venue
            ):
                raise OMSLedgerCorruption()
            OrderLedger._stored_time(row.recorded_at)
            return checked
        except (KeyError, TypeError, ValueError, OMSValidationError):
            raise OMSLedgerCorruption() from None

    @staticmethod
    def _observation_key(row: OmsObservationRow) -> tuple[datetime, int]:
        """Validate durable broker evidence before using it to order callbacks."""
        checked = OrderLedger._checked_observation(row)
        sequence = checked.broker_sequence if checked.broker_sequence is not None else -1
        return checked.observed_at, sequence

    @staticmethod
    def _reduce_observation(
        observed: BrokerObservation,
        current_state: OrderState,
        filled: Decimal,
        order_quantity: Decimal,
        discrepancies: Sequence[str],
        latest: tuple[datetime, int] | None,
        venue_order_id: str | None,
    ) -> tuple[OrderState, str, list[str], str | None]:
        """Pure broker-evidence reducer shared by live writes and replay."""
        codes = list(discrepancies)
        incoming = (
            observed.observed_at,
            observed.broker_sequence if observed.broker_sequence is not None else -1,
        )
        if latest is not None and incoming < latest:
            return current_state, "STALE_BROKER_OBSERVATION", codes, venue_order_id
        target = observed.status
        conflict: str | None = None
        if target == OrderState.REJECTED and filled > 0:
            conflict = "REJECT_AFTER_FILL"
        elif (
            current_state == OrderState.FILLED
            and target == OrderState.FILLED
            and filled != order_quantity
        ):
            conflict = "MISSING_EXECUTIONS"
        elif (
            (current_state in _TERMINAL_STATES and target != current_state)
            or (latest is not None and incoming == latest and target != current_state)
            or (current_state == OrderState.PARTIALLY_FILLED and target == OrderState.WORKING)
        ):
            conflict = "BROKER_STATE_DIVERGENCE"
        if conflict is not None:
            if conflict not in codes:
                codes.append(conflict)
            return current_state, conflict, codes, observed.venue_order_id or venue_order_id
        if target == OrderState.FILLED and filled != order_quantity:
            target = OrderState.RECONCILE_REQUIRED
            if "MISSING_EXECUTIONS" not in codes:
                codes.append("MISSING_EXECUTIONS")
        if target == OrderState.PARTIALLY_FILLED and filled == 0:
            target = OrderState.RECONCILE_REQUIRED
            if "MISSING_EXECUTIONS" not in codes:
                codes.append("MISSING_EXECUTIONS")
        if current_state in {
            OrderState.UNKNOWN_CANCEL,
            OrderState.CANCEL_REQUESTED_UNCONFIRMED,
        } and target in {OrderState.WORKING, OrderState.PARTIALLY_FILLED}:
            target = OrderState.CANCEL_REQUESTED_UNCONFIRMED
        if "CANCEL_STATUS_UNCONFIRMED" in codes and target in {
            OrderState.WORKING,
            OrderState.PARTIALLY_FILLED,
        }:
            target = OrderState.RECONCILE_REQUIRED
        return target, "BROKER_RECONCILIATION", codes, observed.venue_order_id or venue_order_id

    async def _snapshot(self, session: AsyncSession, row: OmsOrderRow) -> OrderSnapshot:
        try:
            await self._verify_activity_account_streaming(session, row.environment, row.account_id)
            return await self._snapshot_checked(session, row)
        except OMSLedgerCorruption:
            raise
        except Exception:
            # The read boundary must never expose malformed durable evidence as a snapshot.
            raise OMSLedgerCorruption() from None

    async def verify_account_integrity(self, environment: str, account_id: str) -> int:
        """Verify a signed checkpoint and its bounded suffix; return suffix rows checked."""
        try:
            async with self._sessions() as session:
                return await self._verify_activity_account_streaming(
                    session, environment, account_id
                )
        except OMSLedgerCorruption:
            raise
        except Exception:
            raise OMSLedgerCorruption() from None

    async def verify_account_integrity_full(self, environment: str, account_id: str) -> int:
        """Scheduled full-chain verifier; emit a fixed alert code on any failure."""
        try:
            async with self._sessions() as session:
                return await self._verify_activity_account_streaming(
                    session, environment, account_id, full_replay=True
                )
        except Exception:
            _LOGGER.error("OMS_LEDGER_FULL_VERIFY_FAILED")
            raise OMSLedgerCorruption() from None

    async def _snapshot_checked(self, session: AsyncSession, row: OmsOrderRow) -> OrderSnapshot:
        events = (
            await session.scalars(
                select(OmsEventRow)
                .where(OmsEventRow.order_id == row.order_id)
                .order_by(OmsEventRow.sequence)
            )
        ).all()
        fills = (
            await session.scalars(select(OmsFillRow).where(OmsFillRow.order_id == row.order_id))
        ).all()
        corrections = (
            await session.scalars(
                select(OmsFillCorrectionRow)
                .where(OmsFillCorrectionRow.order_id == row.order_id)
                .order_by(OmsFillCorrectionRow.revision)
            )
        ).all()
        observations = (
            await session.scalars(
                select(OmsObservationRow).where(OmsObservationRow.order_id == row.order_id)
            )
        ).all()
        if (
            type(row.version) is not int
            or row.version < 0
            or type(row.submit_attempted) is not bool
            or type(row.cancel_attempted) is not bool
            or not isinstance(row.request, dict)
            or not isinstance(row.request_digest, str)
        ):
            raise OMSLedgerCorruption()
        created_at = self._stored_time(row.created_at)
        updated_at = self._stored_time(row.updated_at)
        if updated_at < created_at:
            raise OMSLedgerCorruption()
        quantities: dict[str, Decimal] = {}
        checked_fills: dict[str, Fill] = {}
        for fill in fills:
            try:
                checked = Fill(
                    venue=fill.venue,
                    account_id=fill.account_id,
                    execution_id=fill.execution_id,
                    quantity=parse_oms_decimal(
                        fill.quantity, positive=True, code="INVALID_STORED_FILL"
                    ),
                    price=parse_oms_decimal(fill.price, positive=True, code="INVALID_STORED_FILL"),
                    commission=parse_oms_decimal(fill.commission, code="INVALID_STORED_FILL"),
                    occurred_at=fill.occurred_at.replace(tzinfo=UTC),
                )
                if (
                    type(fill.id) is not int
                    or fill.id < 1
                    or fill.order_id != row.order_id
                    or checked.account_id != row.account_id
                    or checked.venue != row.venue
                    or checked.execution_id in checked_fills
                ):
                    raise OMSValidationError("INVALID_STORED_FILL")
            except (OMSValidationError, TypeError, ValueError):
                raise OMSValidationError("INVALID_STORED_FILL") from None
            quantities[checked.execution_id] = checked.quantity
            checked_fills[checked.execution_id] = checked
        checked_corrections: dict[str, FillCorrection] = {}
        last_revision: dict[str, int] = {}
        for correction in corrections:
            try:
                checked_correction = FillCorrection(
                    venue=correction.venue,
                    account_id=correction.account_id,
                    execution_id=correction.execution_id,
                    correction_id=correction.correction_id,
                    revision=correction.revision,
                    revised_quantity=parse_oms_decimal(
                        correction.revised_quantity, code="INVALID_STORED_CORRECTION"
                    ),
                    revised_price=(
                        parse_oms_decimal(
                            correction.revised_price,
                            positive=True,
                            code="INVALID_STORED_CORRECTION",
                        )
                        if correction.revised_price is not None
                        else None
                    ),
                    revised_commission=parse_oms_decimal(
                        correction.revised_commission, code="INVALID_STORED_CORRECTION"
                    ),
                    occurred_at=correction.occurred_at.replace(tzinfo=UTC),
                )
                if (
                    type(correction.id) is not int
                    or correction.id < 1
                    or correction.order_id != row.order_id
                    or checked_correction.account_id != row.account_id
                    or checked_correction.venue != row.venue
                    or checked_correction.execution_id not in quantities
                    or checked_correction.correction_id in checked_corrections
                    or checked_correction.revision
                    != last_revision.get(checked_correction.execution_id, 0) + 1
                ):
                    raise OMSValidationError("INVALID_STORED_CORRECTION")
            except (OMSValidationError, TypeError, ValueError):
                raise OMSValidationError("INVALID_STORED_CORRECTION") from None
            quantities[checked_correction.execution_id] = checked_correction.revised_quantity
            checked_corrections[checked_correction.correction_id] = checked_correction
            last_revision[checked_correction.execution_id] = checked_correction.revision
        try:
            with localcontext() as context:
                context.prec = 34
                context.rounding = ROUND_HALF_EVEN
                context.traps[Inexact] = True
                filled = sum(quantities.values(), Decimal(0))
        except Inexact:
            raise OMSValidationError("PRECISION_EXCEEDED") from None
        request = OrderRequest.from_payload(row.request)
        if (
            request.payload() != row.request
            or request.digest != row.request_digest
            or request.environment != row.environment
            or request.account_id != row.account_id
            or request.venue != row.venue
            or request.client_order_id != row.client_order_id
            or request.root_order_id != row.root_order_id
            or request.parent_order_id != row.parent_order_id
        ):
            raise OMSLedgerCorruption()
        self._validate_replay(
            row, request, events, checked_fills, checked_corrections, observations, filled
        )
        return OrderSnapshot(
            order_id=row.order_id,
            request=request,
            state=OrderState(row.state),
            version=row.version,
            venue_order_id=row.venue_order_id,
            filled_quantity=filled,
            discrepancies=tuple(row.discrepancies),
            submit_attempted=row.submit_attempted,
            cancel_attempted=row.cancel_attempted,
        )

    def _validate_replay(
        self,
        row: OmsOrderRow,
        request: OrderRequest,
        events: Sequence[OmsEventRow],
        fills: dict[str, Fill],
        corrections: dict[str, FillCorrection],
        observations: Sequence[OmsObservationRow],
        filled: Decimal,
    ) -> None:
        if not events or len(events) != row.version + 1:
            raise OMSLedgerCorruption()
        checked_observations: dict[str, BrokerObservation] = {}
        for persisted in observations:
            observation = self._checked_observation(persisted)
            if (
                persisted.order_id != row.order_id
                or observation.environment != request.environment
                or observation.account_id != request.account_id
                or observation.venue != request.venue
                or observation.client_order_id != request.client_order_id
                or observation.observation_id in checked_observations
            ):
                raise OMSLedgerCorruption()
            checked_observations[observation.observation_id] = observation
        seen_fills: set[str] = set()
        seen_corrections: set[str] = set()
        seen_observations: set[str] = set()
        effective: dict[str, Decimal] = {}
        discrepancies: tuple[str, ...] = ()
        previous_state: OrderState | None = None
        previous_time: datetime | None = None
        submit_attempted = False
        cancel_attempted = False
        replay_venue_id: str | None = None
        active_guard_id: str | None = None
        latest_fence_epoch = 0
        latest_observation_key: tuple[datetime, int] | None = None
        for sequence, event in enumerate(events):
            if (
                type(event.id) is not int
                or event.id < 1
                or event.order_id != row.order_id
                or type(event.sequence) is not int
                or event.sequence != sequence
                or type(event.code) is not str
                or event.code not in _EVENT_CODES
                or type(event.state) is not str
                or not isinstance(event.evidence, dict)
            ):
                raise OMSLedgerCorruption()
            state = OrderState(event.state)
            recorded_at = self._stored_time(event.recorded_at)
            if (
                recorded_at < self._stored_time(row.created_at)
                or recorded_at > self._stored_time(row.updated_at)
                or (previous_time is not None and recorded_at < previous_time)
                or (previous_state in _TERMINAL_STATES and state != previous_state)
            ):
                raise OMSLedgerCorruption()
            evidence = event.evidence
            code = event.code
            if sequence == 0:
                if (
                    code != "ORDER_CREATED"
                    or state != OrderState.CREATED
                    or evidence != {"request_digest": request.digest}
                ):
                    raise OMSLedgerCorruption()
            elif code == "BROKER_INTENT_FOUND":
                if (
                    previous_state != OrderState.CREATED
                    or state != OrderState.RECONCILE_REQUIRED
                    or set(evidence)
                    != {"account_id", "client_order_id", "broker_state", "venue_order_id"}
                    or evidence["account_id"] != request.account_id
                    or evidence["client_order_id"] != request.client_order_id
                    or evidence["broker_state"] not in {value.value for value in OrderState}
                    or (
                        evidence["venue_order_id"] is not None
                        and (
                            type(evidence["venue_order_id"]) is not str
                            or re.fullmatch(
                                r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}",
                                evidence["venue_order_id"],
                            )
                            is None
                        )
                    )
                ):
                    raise OMSLedgerCorruption()
            elif code == "BROKER_ACCOUNT_ACTIVITY_UNMATCHED":
                if (
                    previous_state != OrderState.CREATED
                    or state != OrderState.RECONCILE_REQUIRED
                    or evidence
                ):
                    raise OMSLedgerCorruption()
            elif code == "BROKER_DISPATCH_NOT_PLACED":
                if (
                    previous_state
                    not in {
                        OrderState.SUBMITTING,
                        OrderState.DISPATCH_IN_FLIGHT,
                        OrderState.RECONCILE_REQUIRED,
                        OrderState.UNKNOWN_SUBMIT,
                    }
                    or state != OrderState.CREATED
                    or evidence
                ):
                    raise OMSLedgerCorruption()
                submit_attempted = False
            elif code == "BROKER_GUARD_ADOPTED":
                if (
                    previous_state
                    not in {
                        OrderState.DISPATCH_IN_FLIGHT,
                        OrderState.RECONCILE_REQUIRED,
                        OrderState.UNKNOWN_SUBMIT,
                        OrderState.UNKNOWN_CANCEL,
                        OrderState.CANCEL_REQUESTED_UNCONFIRMED,
                    }
                    or state
                    not in {
                        OrderState.WORKING,
                        OrderState.REJECTED,
                        OrderState.CANCELED,
                        OrderState.EXPIRED,
                    }
                    or set(evidence) != {"venue_order_id"}
                ):
                    raise OMSLedgerCorruption()
                replay_venue_id = evidence["venue_order_id"]
                if replay_venue_id is not None and (
                    type(replay_venue_id) is not str
                    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", replay_venue_id) is None
                ):
                    raise OMSLedgerCorruption()
            elif code == "DISPATCH_GUARD_SET":
                if (
                    state != OrderState.DISPATCH_IN_FLIGHT
                    or set(evidence)
                    not in (
                        {"action", "client_order_id", "attempt", "broker_revision"},
                        {
                            "action",
                            "client_order_id",
                            "attempt",
                            "broker_revision",
                            "fence_epoch",
                        },
                    )
                    or evidence["action"] not in {"SUBMIT", "CANCEL"}
                    or previous_state
                    != (
                        OrderState.SUBMITTING
                        if evidence["action"] == "SUBMIT"
                        else OrderState.CANCEL_PENDING
                    )
                    or evidence["client_order_id"] != request.client_order_id
                    or type(evidence["attempt"]) is not int
                    or evidence["attempt"] != request.attempt
                    or type(evidence["broker_revision"]) is not int
                    or evidence["broker_revision"] < 0
                ):
                    raise OMSLedgerCorruption()
                if "fence_epoch" in evidence:
                    if (
                        type(evidence["fence_epoch"]) is not int
                        or evidence["fence_epoch"] <= latest_fence_epoch
                    ):
                        raise OMSLedgerCorruption()
                    latest_fence_epoch = evidence["fence_epoch"]
                active_guard_id = event.chain
            elif code == "CANCEL_IN_FLIGHT":
                if (
                    previous_state != OrderState.DISPATCH_IN_FLIGHT
                    or state != previous_state
                    or set(evidence) != {"guard_id"}
                    or type(evidence["guard_id"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", evidence["guard_id"]) is None
                    or evidence["guard_id"] != active_guard_id
                    or cancel_attempted
                ):
                    raise OMSLedgerCorruption()
                cancel_attempted = True
            elif code == "DISPATCH_GATE_DENIED":
                if (
                    previous_state != OrderState.DISPATCH_IN_FLIGHT
                    or set(evidence) != {"action", "reason", "discrepancies"}
                    or evidence["action"] not in {"SUBMIT", "CANCEL"}
                    or evidence["reason"]
                    not in {"DENY_HALT", "DENY_KILL", "DENY_SCOPE", "DENY_UNAVAILABLE"}
                    or evidence["discrepancies"]
                    != (
                        list(discrepancies)
                        if evidence["action"] == "SUBMIT"
                        else [*discrepancies, "GATE_DENIED_CANCEL"]
                    )
                    or state
                    != (
                        OrderState.REJECTED_HALTED
                        if evidence["action"] == "SUBMIT"
                        else OrderState.RECONCILE_REQUIRED
                    )
                    or active_guard_id is None
                ):
                    raise OMSLedgerCorruption()
                active_guard_id = None
                if evidence["action"] == "SUBMIT":
                    submit_attempted = False
                else:
                    cancel_attempted = False
            elif code == "BROKER_EXECUTION_CONFLICT":
                if (
                    set(evidence) != {"discrepancies"}
                    or evidence["discrepancies"] != [*discrepancies, "BROKER_EXECUTION_CONFLICT"]
                    or state
                    != (
                        previous_state
                        if previous_state in _TERMINAL_STATES
                        else OrderState.RECONCILE_REQUIRED
                    )
                ):
                    raise OMSLedgerCorruption()
            elif code == "VENUE_MISMATCH":
                if previous_state == OrderState.CREATED and not evidence:
                    if state != OrderState.REJECTED:
                        raise OMSLedgerCorruption()
                elif (
                    previous_state is None
                    or state
                    != (
                        previous_state
                        if previous_state in _TERMINAL_STATES
                        else OrderState.RECONCILE_REQUIRED
                    )
                    or evidence != {"discrepancies": [*discrepancies, "VENUE_MISMATCH"]}
                ):
                    raise OMSLedgerCorruption()
            elif code == "VENUE_ACCOUNT_CONFLICT":
                expected_discrepancies = (
                    list(discrepancies)
                    if "VENUE_ACCOUNT_CONFLICT" in discrepancies
                    else [*discrepancies, "VENUE_ACCOUNT_CONFLICT"]
                )
                base_evidence = {"discrepancies": expected_discrepancies}
                if (
                    previous_state is None
                    or state
                    != (
                        previous_state
                        if previous_state in _TERMINAL_STATES
                        else OrderState.RECONCILE_REQUIRED
                    )
                    or evidence.get("discrepancies") != base_evidence["discrepancies"]
                ):
                    raise OMSLedgerCorruption()
                if set(evidence) == {"discrepancies"}:
                    # Legacy conflicts remain valid audit history but cannot be
                    # operator-waived because their originating image is unknown.
                    pass
                elif set(evidence) == {
                    "discrepancies",
                    "binding_venue",
                    "binding_environment",
                    "observations",
                    "affected_order_ids",
                    "identity_digest",
                }:
                    observations = evidence["observations"]
                    affected_ids = evidence["affected_order_ids"]
                    if (
                        type(evidence["binding_venue"]) is not str
                        or not evidence["binding_venue"]
                        or evidence["binding_environment"] not in {"paper", "demo", "live"}
                        or type(observations) is not list
                        or not observations
                        or any(
                            not isinstance(item, dict)
                            or set(item) != {"observation_id", "venue", "environment"}
                            or any(
                                type(item.get(name)) is not str or not item[name]
                                for name in ("observation_id", "venue", "environment")
                            )
                            or item["environment"] not in {"paper", "demo", "live"}
                            for item in observations
                        )
                        or [item["observation_id"] for item in observations]
                        != sorted(set(item["observation_id"] for item in observations))
                        or type(affected_ids) is not list
                        or row.order_id not in affected_ids
                        or affected_ids != sorted(set(affected_ids))
                        or any(type(item) is not str for item in affected_ids)
                        or type(evidence["identity_digest"]) is not str
                        or re.fullmatch(r"[0-9a-f]{64}", evidence["identity_digest"]) is None
                    ):
                        raise OMSLedgerCorruption()
                    identity_payload = {
                        "environment": request.environment,
                        "account_id": request.account_id,
                        "binding_venue": evidence["binding_venue"],
                        "binding_environment": evidence["binding_environment"],
                        "observations": [
                            [item["observation_id"], item["venue"], item["environment"]]
                            for item in observations
                        ],
                        "affected_order_ids": affected_ids,
                    }
                    if (
                        hashlib.sha256(canonical_json(identity_payload)).hexdigest()
                        != evidence["identity_digest"]
                    ):
                        raise OMSLedgerCorruption()
                else:
                    raise OMSLedgerCorruption()
                discrepancies = tuple(base_evidence["discrepancies"])
            elif code == "VENUE_ACCOUNT_CONFLICT_RESOLVED":
                if (
                    "VENUE_ACCOUNT_CONFLICT" not in discrepancies
                    or set(evidence)
                    != {
                        "resolution_id",
                        "conflict_id",
                        "broker_revision",
                        "broker_evidence_digest",
                        "prior_ledger_revision",
                        "identity_digest",
                        "discrepancies",
                        "resolved_state",
                    }
                    or type(evidence["resolution_id"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", evidence["resolution_id"]) is None
                    or type(evidence["conflict_id"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", evidence["conflict_id"]) is None
                    or type(evidence["identity_digest"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", evidence["identity_digest"]) is None
                    or type(evidence["broker_revision"]) is not int
                    or evidence["broker_revision"] < 0
                    or type(evidence["broker_evidence_digest"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", evidence["broker_evidence_digest"]) is None
                    or type(evidence["prior_ledger_revision"]) is not int
                    or evidence["prior_ledger_revision"] < 0
                    or evidence["discrepancies"]
                    != [code for code in discrepancies if code != "VENUE_ACCOUNT_CONFLICT"]
                    or state != (previous_state if previous_state in _TERMINAL_STATES else state)
                    or (
                        previous_state not in _TERMINAL_STATES
                        and (
                            previous_state != OrderState.RECONCILE_REQUIRED
                            or state
                            not in {
                                OrderState.CREATED,
                                OrderState.WORKING,
                                OrderState.PARTIALLY_FILLED,
                                OrderState.FILLED,
                            }
                        )
                    )
                    or evidence["resolved_state"] != state.value
                ):
                    raise OMSLedgerCorruption()
                discrepancies = tuple(evidence["discrepancies"])
            elif code == "OPERATOR_GUARD_RELEASED":
                if (
                    previous_state
                    not in {
                        OrderState.DISPATCH_IN_FLIGHT,
                        OrderState.RECONCILE_REQUIRED,
                        OrderState.UNKNOWN_SUBMIT,
                        OrderState.UNKNOWN_CANCEL,
                        OrderState.CANCEL_REQUESTED_UNCONFIRMED,
                        OrderState.WORKING,
                        OrderState.REJECTED,
                        OrderState.CANCELED,
                    }
                    or set(evidence)
                    != {
                        "guard_id",
                        "broker_evidence_digest",
                        "operator_id",
                        "venue_order_id",
                        "not_placed",
                    }
                    or any(
                        type(evidence[name]) is not str
                        or re.fullmatch(r"[0-9a-f]{64}", evidence[name]) is None
                        for name in ("guard_id", "broker_evidence_digest")
                    )
                    or type(evidence["operator_id"]) is not str
                    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", evidence["operator_id"])
                    is None
                    or type(evidence["not_placed"]) is not bool
                    or evidence["guard_id"] != active_guard_id
                ):
                    raise OMSLedgerCorruption()
                active_guard_id = None
                if evidence["not_placed"]:
                    if state != OrderState.CREATED or evidence["venue_order_id"] is not None:
                        raise OMSLedgerCorruption()
                    submit_attempted = False
                    cancel_attempted = False
                    replay_venue_id = None
                else:
                    if state not in {
                        OrderState.WORKING,
                        OrderState.REJECTED,
                        OrderState.CANCELED,
                        OrderState.EXPIRED,
                    }:
                        raise OMSLedgerCorruption()
                    venue_id = evidence["venue_order_id"]
                    if venue_id is not None and (
                        type(venue_id) is not str
                        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", venue_id) is None
                    ):
                        raise OMSLedgerCorruption()
                    replay_venue_id = venue_id
            elif code == "STALE_BROKER_VIEW":
                if (
                    previous_state != OrderState.CREATED
                    or state != OrderState.RECONCILE_REQUIRED
                    or evidence
                ):
                    raise OMSLedgerCorruption()
            elif code == "POST_DISPATCH_CONFLICT":
                if (
                    previous_state
                    not in {
                        OrderState.WORKING,
                        OrderState.REJECTED,
                        OrderState.UNKNOWN_SUBMIT,
                        OrderState.CANCELED,
                        OrderState.UNKNOWN_CANCEL,
                        OrderState.CANCEL_REQUESTED_UNCONFIRMED,
                    }
                    or state
                    != (
                        previous_state
                        if previous_state in {OrderState.REJECTED, OrderState.CANCELED}
                        else OrderState.RECONCILE_REQUIRED
                    )
                    or set(evidence) != {"cancel_requested", "cancel_confirmed", "discrepancies"}
                    or type(evidence["cancel_requested"]) is not bool
                    or evidence["cancel_requested"] is not True
                    or type(evidence["cancel_confirmed"]) is not bool
                ):
                    raise OMSLedgerCorruption()
                cancel_attempted = True
            elif code in _DENIAL_CODES:
                if (
                    state != OrderState.RISK_REJECTED
                    or previous_state != OrderState.RISK_PENDING
                    or evidence
                ):
                    raise OMSLedgerCorruption()
            elif code == "RISK_CHECK_STARTED":
                if (
                    state != OrderState.RISK_PENDING
                    or previous_state != OrderState.CREATED
                    or evidence
                ):
                    raise OMSLedgerCorruption()
            elif code == "FAKE_RISK_READY":
                checked_evidence = PaperDispatchEvidence(**evidence)
                if (
                    state != OrderState.READY
                    or previous_state != OrderState.RISK_PENDING
                    or checked_evidence.payload() != evidence
                    or checked_evidence.denial_code(request, row.order_id) is not None
                ):
                    raise OMSLedgerCorruption()
            elif code == "OUTBOUND_SUBMIT_COMMITTED":
                if (
                    state != OrderState.SUBMITTING
                    or previous_state != OrderState.READY
                    or evidence != {"request_digest": request.digest}
                ):
                    raise OMSLedgerCorruption()
                submit_attempted = True
            elif code in {"BROKER_SUBMIT_RESULT", "SUBMIT_UNKNOWN"}:
                if previous_state not in {
                    OrderState.SUBMITTING,
                    OrderState.DISPATCH_IN_FLIGHT,
                } or set(evidence) not in (
                    {"venue_order_id"},
                    {"venue_order_id", "rejection_code"},
                ):
                    raise OMSLedgerCorruption()
                if "rejection_code" in evidence and (
                    code != "BROKER_SUBMIT_RESULT"
                    or state != OrderState.REJECTED
                    or evidence["rejection_code"]
                    not in {item.value for item in BrokerRejectionCode}
                ):
                    raise OMSLedgerCorruption()
                venue_id = evidence["venue_order_id"]
                if venue_id is not None:
                    if (
                        type(venue_id) is not str
                        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", venue_id) is None
                    ):
                        raise OMSLedgerCorruption()
                    replay_venue_id = venue_id
                if (code == "SUBMIT_UNKNOWN") != (state == OrderState.UNKNOWN_SUBMIT):
                    raise OMSLedgerCorruption()
                if code == "BROKER_SUBMIT_RESULT" and state not in {
                    OrderState.WORKING,
                    OrderState.REJECTED,
                }:
                    raise OMSLedgerCorruption()
            elif code == "OUTBOUND_CANCEL_COMMITTED":
                if (
                    previous_state not in {OrderState.WORKING, OrderState.PARTIALLY_FILLED}
                    or state != OrderState.CANCEL_PENDING
                    or evidence
                ):
                    raise OMSLedgerCorruption()
                cancel_attempted = True
            elif code in {"BROKER_CANCEL_CONFIRMED", "CANCEL_UNCONFIRMED"}:
                if (
                    previous_state not in {OrderState.CANCEL_PENDING, OrderState.DISPATCH_IN_FLIGHT}
                    or evidence
                ):
                    raise OMSLedgerCorruption()
                if code == "BROKER_CANCEL_CONFIRMED" and state != OrderState.CANCELED:
                    raise OMSLedgerCorruption()
                if code == "CANCEL_UNCONFIRMED" and state not in {
                    OrderState.CANCEL_REQUESTED_UNCONFIRMED,
                    OrderState.UNKNOWN_CANCEL,
                }:
                    raise OMSLedgerCorruption()
            elif code in {"BROKER_FILL", "FILL_AFTER_TERMINAL"}:
                if set(evidence) != {"execution_id", "discrepancies", "overfill_excess"}:
                    raise OMSLedgerCorruption()
                execution_id = evidence["execution_id"]
                if (
                    type(execution_id) is not str
                    or execution_id not in fills
                    or execution_id in seen_fills
                ):
                    raise OMSLedgerCorruption()
                seen_fills.add(execution_id)
                effective[execution_id] = fills[execution_id].quantity
                if not submit_attempted:
                    raise OMSLedgerCorruption()
                if code == "FILL_AFTER_TERMINAL":
                    if previous_state not in _TERMINAL_STATES or state != previous_state:
                        raise OMSLedgerCorruption()
                elif state not in {
                    OrderState.PARTIALLY_FILLED,
                    OrderState.FILLED,
                    OrderState.RECONCILE_REQUIRED,
                }:
                    raise OMSLedgerCorruption()
            elif code == "BROKER_FILL_CORRECTION":
                if set(evidence) != {
                    "execution_id",
                    "correction_id",
                    "revision",
                    "discrepancies",
                    "overfill_excess",
                }:
                    raise OMSLedgerCorruption()
                correction_id = evidence["correction_id"]
                if (
                    type(correction_id) is not str
                    or correction_id not in corrections
                    or correction_id in seen_corrections
                ):
                    raise OMSLedgerCorruption()
                correction = corrections[correction_id]
                if (
                    evidence["execution_id"] != correction.execution_id
                    or type(evidence["revision"]) is not int
                    or evidence["revision"] != correction.revision
                    or correction.execution_id not in effective
                ):
                    raise OMSLedgerCorruption()
                seen_corrections.add(correction_id)
                effective[correction.execution_id] = correction.revised_quantity
                if previous_state in _TERMINAL_STATES:
                    if state != previous_state:
                        raise OMSLedgerCorruption()
                elif state != OrderState.RECONCILE_REQUIRED:
                    raise OMSLedgerCorruption()
            elif code in {
                "BROKER_RECONCILIATION",
                "STALE_BROKER_OBSERVATION",
                "BROKER_STATE_DIVERGENCE",
                "MISSING_EXECUTIONS",
            } or (code == "REJECT_AFTER_FILL" and "observation_id" in evidence):
                if set(evidence) != {"observation_id", "discrepancies"}:
                    raise OMSLedgerCorruption()
                observation_id = evidence["observation_id"]
                if (
                    type(observation_id) is not str
                    or observation_id not in checked_observations
                    or observation_id in seen_observations
                ):
                    raise OMSLedgerCorruption()
                seen_observations.add(observation_id)
                observed = checked_observations[observation_id]
                if previous_state is None:
                    raise OMSLedgerCorruption()
                with localcontext() as context:
                    context.prec = 34
                    context.traps[Inexact] = True
                    observed_filled = sum(effective.values(), Decimal(0))
                expected_state, expected_code, expected_discrepancies, _ = self._reduce_observation(
                    observed,
                    previous_state,
                    observed_filled,
                    request.quantity,
                    discrepancies,
                    latest_observation_key,
                    replay_venue_id,
                )
                if (
                    state != expected_state
                    or code != expected_code
                    or evidence["discrepancies"] != expected_discrepancies
                ):
                    raise OMSLedgerCorruption()
                observed_key = (
                    observed.observed_at,
                    observed.broker_sequence if observed.broker_sequence is not None else -1,
                )
                if code == "STALE_BROKER_OBSERVATION":
                    if latest_observation_key is None or observed_key >= latest_observation_key:
                        raise OMSLedgerCorruption()
                elif latest_observation_key is not None and observed_key < latest_observation_key:
                    raise OMSLedgerCorruption()
                if latest_observation_key is None or observed_key > latest_observation_key:
                    latest_observation_key = observed_key
                if observed.venue_order_id is not None and code != "STALE_BROKER_OBSERVATION":
                    if replay_venue_id is not None and replay_venue_id != observed.venue_order_id:
                        raise OMSLedgerCorruption()
                    replay_venue_id = observed.venue_order_id
                if code != "BROKER_RECONCILIATION" and state != previous_state:
                    raise OMSLedgerCorruption()
            elif code in {"REJECT_AFTER_FILL", "BROKER_SCOPE_MISMATCH"}:
                if set(evidence) != {"discrepancies"} or state != previous_state:
                    raise OMSLedgerCorruption()
            elif code == "RECOVERED_UNCERTAIN":
                if (
                    evidence
                    or (
                        previous_state == OrderState.SUBMITTING
                        and state != OrderState.UNKNOWN_SUBMIT
                    )
                    or (
                        previous_state == OrderState.CANCEL_PENDING
                        and state != OrderState.UNKNOWN_CANCEL
                    )
                    or (
                        previous_state == OrderState.DISPATCH_IN_FLIGHT
                        and state != OrderState.RECONCILE_REQUIRED
                    )
                    or previous_state
                    not in {
                        OrderState.SUBMITTING,
                        OrderState.CANCEL_PENDING,
                        OrderState.DISPATCH_IN_FLIGHT,
                    }
                ):
                    raise OMSLedgerCorruption()
            else:
                if evidence or state != previous_state:
                    raise OMSLedgerCorruption()
            if "discrepancies" in evidence:
                current = self._stored_discrepancies(evidence["discrepancies"])
                if current[: len(discrepancies)] != discrepancies:
                    raise OMSLedgerCorruption()
                discrepancies = current
            if code in {"BROKER_FILL", "FILL_AFTER_TERMINAL", "BROKER_FILL_CORRECTION"}:
                with localcontext() as context:
                    context.prec = 34
                    context.traps[Inexact] = True
                    running_total = sum(effective.values(), Decimal(0))
                excess = evidence["overfill_excess"]
                if running_total > request.quantity:
                    with localcontext() as context:
                        context.prec = 160
                        context.traps[Inexact] = True
                        exact_excess = running_total - request.quantity
                    if (
                        "OVERFILL" not in discrepancies
                        or parse_oms_decimal(excess, positive=True) != exact_excess
                    ):
                        raise OMSLedgerCorruption()
                elif excess is not None:
                    raise OMSLedgerCorruption()
            previous_state = state
            previous_time = recorded_at
        if (
            seen_fills != set(fills)
            or seen_corrections != set(corrections)
            or seen_observations != set(checked_observations)
            or previous_state is None
            or previous_state.value != row.state
            or discrepancies != self._stored_discrepancies(row.discrepancies)
            or submit_attempted != row.submit_attempted
            or cancel_attempted != row.cancel_attempted
            or row.venue_order_id != replay_venue_id
        ):
            raise OMSLedgerCorruption()
        with localcontext() as context:
            context.prec = 34
            context.traps[Inexact] = True
            replay_total = sum(effective.values(), Decimal(0))
        if replay_total != filled:
            raise OMSLedgerCorruption()
        if filled > request.quantity and "OVERFILL" not in discrepancies:
            raise OMSLedgerCorruption()
        if previous_state == OrderState.FILLED and filled != request.quantity and not corrections:
            raise OMSLedgerCorruption()

    async def get(self, order_id: str) -> OrderSnapshot | None:
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            return None if row is None else await self._snapshot(session, row)

    async def _audit_all_oms_rows(self, session: AsyncSession) -> None:
        """Fail closed on every persisted OMS row before any new dispatch marker."""
        try:
            orders = (await session.scalars(select(OmsOrderRow))).all()
            known_order_ids = {row.order_id for row in orders}
            for persisted in orders:
                await self._snapshot(session, persisted)
            heads = (await session.scalars(select(OmsLedgerHeadRow))).all()
            for head in heads:
                await self._verify_account(session, head.environment, head.account_id)
            for row_type in (OmsEventRow, OmsFillRow, OmsFillCorrectionRow, OmsObservationRow):
                children = (await session.scalars(select(row_type))).all()
                if any(
                    getattr(child, "order_id", None) not in known_order_ids for child in children
                ):
                    raise OMSLedgerCorruption()
        except OMSLedgerCorruption:
            raise
        except Exception:
            raise OMSLedgerCorruption() from None

    async def create(self, request: OrderRequest) -> OrderSnapshot:
        """Reserve caller idempotency and canonical request before any dispatch."""
        self._require_actor_when_bound()
        if not isinstance(request, OrderRequest):
            raise OMSValidationError("INVALID_ORDER_REQUEST")
        if request.client_order_id is None:
            raise OMSValidationError("CLIENT_ID_NOT_DERIVED")
        self._integrity_key()
        async with self._sessions() as session:
            await self._verify_account(session, request.environment, request.account_id)
            existing = await session.scalar(
                select(OmsOrderRow).where(
                    OmsOrderRow.environment == request.environment,
                    OmsOrderRow.account_id == request.account_id,
                    OmsOrderRow.client_order_id == request.client_order_id,
                )
            )
            if existing is not None:
                if (
                    existing.request_digest != request.digest
                    or existing.request != request.payload()
                ):
                    raise OMSConflict("IDEMPOTENCY_CONFLICT")
                return await self._snapshot(session, existing)
            for link in (request.parent_order_id, request.root_order_id):
                if link is None:
                    continue
                linked = await session.get(OmsOrderRow, link)
                if linked is None or (
                    linked.environment != request.environment
                    or linked.account_id != request.account_id
                    or linked.venue != request.venue
                ):
                    raise OMSValidationError("ORDER_LINK_SCOPE_MISMATCH")
            if request.parent_order_id is not None:
                parent = await session.get(OmsOrderRow, request.parent_order_id)
                if parent is None or request.root_order_id != (
                    parent.root_order_id or parent.order_id
                ):
                    raise OMSValidationError("ORDER_LINK_SCOPE_MISMATCH")
            now = datetime.now(UTC)
            row = OmsOrderRow(
                order_id=uuid4().hex,
                environment=request.environment,
                account_id=request.account_id,
                venue=request.venue,
                client_order_id=request.client_order_id,
                venue_order_id=None,
                root_order_id=request.root_order_id,
                parent_order_id=request.parent_order_id,
                request_digest=request.digest,
                request=request.payload(),
                state=OrderState.CREATED.value,
                version=0,
                submit_attempted=False,
                cancel_attempted=False,
                discrepancies=[],
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.add(
                OmsEventRow(
                    order_id=row.order_id,
                    sequence=0,
                    state=OrderState.CREATED.value,
                    code="ORDER_CREATED",
                    evidence={"request_digest": request.digest},
                    recorded_at=now,
                )
            )
            try:
                await self._seal_account(session, request.environment, request.account_id)
                await session.commit()
            except IntegrityError:
                await session.rollback()
                existing = await session.scalar(
                    select(OmsOrderRow).where(
                        OmsOrderRow.environment == request.environment,
                        OmsOrderRow.account_id == request.account_id,
                        OmsOrderRow.client_order_id == request.client_order_id,
                    )
                )
                if (
                    existing is None
                    or existing.request_digest != request.digest
                    or existing.request != request.payload()
                ):
                    raise OMSConflict("IDEMPOTENCY_CONFLICT") from None
                return await self._snapshot(session, existing)
            return await self._snapshot(session, row)

    async def _advance(
        self,
        session: AsyncSession,
        row: OmsOrderRow,
        steps: list[tuple[OrderState, str, dict[str, Any]]],
        *,
        values: dict[str, Any] | None = None,
        guard_change: tuple[str, DispatchGuard | None] | None = None,
        bump_fence: bool = False,
    ) -> None:
        with session.no_autoflush:
            await self._verify_account(session, row.environment, row.account_id)
        version = row.version
        now = datetime.now(UTC)
        states = [state.value for state, _, _ in steps]
        changed = await session.execute(
            update(OmsOrderRow)
            .where(OmsOrderRow.order_id == row.order_id)
            .where(OmsOrderRow.version == version, OmsOrderRow.state == row.state)
            .values(
                state=states[-1],
                version=version + len(steps),
                updated_at=now,
                **(values or {}),
            )
        )
        if not isinstance(changed, CursorResult) or changed.rowcount != 1:
            raise OMSConflict("ORDER_STATE_CHANGED")
        for number, (state, code, evidence) in enumerate(steps, start=1):
            session.add(
                OmsEventRow(
                    order_id=row.order_id,
                    sequence=version + number,
                    state=state.value,
                    code=code,
                    evidence=evidence,
                    recorded_at=now,
                )
            )
        if guard_change is not None:
            action, guard = guard_change
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            if head is None:
                raise OMSLedgerCorruption()
            existing_guard = self._guard_from_head(head)
            if action == "SET" and guard is not None and existing_guard is None:
                if guard.fence_epoch != (head.fence_epoch or 0) + 1 or bump_fence:
                    raise OMSConflict("STALE_DISPATCH_FENCE")
                head.guard_order_id = guard.order_id
                head.guard_action = guard.action
                head.guard_client_order_id = guard.client_order_id
                head.guard_attempt = guard.attempt
                head.guard_revision = guard.broker_revision
                head.fence_epoch = guard.fence_epoch
            elif action == "CLEAR" and guard is None and existing_guard is not None:
                if existing_guard.order_id != row.order_id:
                    raise OMSConflict("ACCOUNT_RECONCILE_REQUIRED")
                head.guard_order_id = None
                head.guard_action = None
                head.guard_client_order_id = None
                head.guard_attempt = None
                head.guard_revision = None
                if bump_fence:
                    head.fence_epoch = existing_guard.fence_epoch + 1
            else:
                raise OMSConflict("ACCOUNT_RECONCILE_REQUIRED")
        elif bump_fence:
            raise OMSConflict("STALE_DISPATCH_FENCE")
        await self._seal_account(session, row.environment, row.account_id)
        await session.commit()
        await session.refresh(row)

    async def account_guard(self, environment: str, account_id: str) -> DispatchGuard | None:
        async with self._sessions() as session:
            await self._verify_account(session, environment, account_id)
            head = await session.get(OmsLedgerHeadRow, (environment, account_id))
            return None if head is None else self._guard_from_head(head)

    async def assert_dispatch_fence(self, order_id: str, fence_epoch: int) -> DispatchGuard:
        """The final durable check immediately before a broker side effect."""
        if type(order_id) is not str or type(fence_epoch) is not int or fence_epoch < 1:
            raise OMSValidationError("INVALID_DISPATCH_FENCE")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("STALE_DISPATCH_FENCE")
            await self._verify_account(session, row.environment, row.account_id)
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            guard = None if head is None else self._guard_from_head(head)
            if (
                guard is None
                or guard.order_id != order_id
                or guard.fence_epoch != fence_epoch
                or row.state != OrderState.DISPATCH_IN_FLIGHT.value
                or self._armed_here.get(order_id) != fence_epoch
            ):
                raise OMSConflict("STALE_DISPATCH_FENCE")
            return guard

    async def operator_guard_context(
        self, environment: str, account_id: str
    ) -> tuple[DispatchGuard, str, OrderSnapshot, tuple[bytes, ...]]:
        """Return authenticated guard identity and immutable effect journal."""
        async with self._sessions() as session:
            await self._verify_account(session, environment, account_id)
            head = await session.get(OmsLedgerHeadRow, (environment, account_id))
            guard = None if head is None else self._guard_from_head(head)
            if guard is None:
                raise OMSConflict("DISPATCH_GUARD_REQUIRED")
            row = await session.get(OmsOrderRow, guard.order_id)
            if row is None:
                raise OMSLedgerCorruption()
            snapshot = await self._snapshot_checked(session, row)
            events = list(
                (
                    await session.scalars(
                        select(OmsEventRow)
                        .where(OmsEventRow.order_id == guard.order_id)
                        .order_by(OmsEventRow.sequence)
                    )
                ).all()
            )
            armed = [event for event in events if event.code == "DISPATCH_GUARD_SET"]
            if not armed or type(armed[-1].chain) is not str:
                raise OMSLedgerCorruption()
            guard_id = armed[-1].chain
            journal = tuple(
                canonical_json(
                    {
                        "sequence": event.sequence,
                        "state": event.state,
                        "code": event.code,
                        "evidence": event.evidence,
                        "chain": event.chain,
                    }
                )
                for event in events
            )
            return guard, guard_id, snapshot, journal

    async def arm_compensating_cancel(self, order_id: str) -> OrderSnapshot:
        """Persist possible cancel effect before the fake port is touched."""
        self._require_actor_task()
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            current = await self._snapshot(session, row)
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            guard = None if head is None else self._guard_from_head(head)
            if (
                guard is None
                or guard.action != "SUBMIT"
                or guard.order_id != order_id
                or current.state != OrderState.DISPATCH_IN_FLIGHT
                or current.cancel_attempted
            ):
                raise OMSConflict("DISPATCH_GUARD_REQUIRED")
            armed = (
                await session.scalars(
                    select(OmsEventRow)
                    .where(
                        OmsEventRow.order_id == order_id,
                        OmsEventRow.code == "DISPATCH_GUARD_SET",
                    )
                    .order_by(OmsEventRow.sequence.desc())
                )
            ).first()
            if armed is None or type(armed.chain) is not str:
                raise OMSLedgerCorruption()
            await self._advance(
                session,
                row,
                [
                    (
                        OrderState.DISPATCH_IN_FLIGHT,
                        "CANCEL_IN_FLIGHT",
                        {
                            "guard_id": armed.chain,
                        },
                    )
                ],
                values={"cancel_attempted": True},
            )
            return await self._snapshot(session, row)

    async def arm_dispatch_guard(
        self, order_id: str, *, action: str, broker_revision: int
    ) -> OrderSnapshot:
        """Commit account guard and worst-case state before a broker effect."""
        self._require_actor_task()
        if action not in {"SUBMIT", "CANCEL"} or type(broker_revision) is not int:
            raise OMSValidationError("INVALID_DISPATCH_GUARD")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            current = await self._snapshot(session, row)
            expected_state = (
                OrderState.SUBMITTING if action == "SUBMIT" else OrderState.CANCEL_PENDING
            )
            if current.state != expected_state:
                raise OMSConflict("DISPATCH_MARKER_REQUIRED")
            client_order_id = current.request.client_order_id
            if client_order_id is None:
                raise OMSValidationError("CLIENT_ID_NOT_DERIVED")
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            if head is None:
                raise OMSLedgerCorruption()
            next_epoch = (head.fence_epoch or 0) + 1
            guard = DispatchGuard(
                current.request.environment,
                current.request.account_id,
                order_id,
                action,
                client_order_id,
                current.request.attempt,
                broker_revision,
                next_epoch,
            )
            await self._advance(
                session,
                row,
                [
                    (
                        OrderState.DISPATCH_IN_FLIGHT,
                        "DISPATCH_GUARD_SET",
                        {
                            "action": action,
                            "client_order_id": client_order_id,
                            "attempt": current.request.attempt,
                            "broker_revision": broker_revision,
                            "fence_epoch": next_epoch,
                        },
                    )
                ],
                guard_change=("SET", guard),
            )
            self._armed_here[order_id] = next_epoch
            self._issued_here.add((order_id, next_epoch))
            return await self._snapshot(session, row)

    async def complete_guarded_gate_denial(
        self,
        order_id: str,
        *,
        action: str,
        reason: str,
    ) -> OrderSnapshot:
        """Commit a final-seam denial and clear its guard without an effect."""
        self._require_actor_task()
        if action not in {"SUBMIT", "CANCEL"} or reason not in {
            "DENY_HALT",
            "DENY_KILL",
            "DENY_SCOPE",
            "DENY_UNAVAILABLE",
        }:
            raise OMSValidationError("INVALID_DISPATCH_GATE_RESULT")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None or row.state != OrderState.DISPATCH_IN_FLIGHT.value:
                raise OMSConflict("DISPATCH_GUARD_REQUIRED")
            await self._snapshot(session, row)
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            guard = None if head is None else self._guard_from_head(head)
            if guard is None or guard.order_id != order_id or guard.action != action:
                raise OMSConflict("DISPATCH_GUARD_REQUIRED")
            if self._armed_here.get(order_id) != guard.fence_epoch:
                raise OMSConflict("STALE_DISPATCH_FENCE")
            self._armed_here.pop(order_id, None)
            discrepancies = list(row.discrepancies)
            if action == "CANCEL":
                if "GATE_DENIED_CANCEL" not in discrepancies:
                    discrepancies.append("GATE_DENIED_CANCEL")
                state = OrderState.RECONCILE_REQUIRED
                values: dict[str, Any] = {
                    "discrepancies": discrepancies,
                    "cancel_attempted": False,
                }
            else:
                state = OrderState.REJECTED_HALTED
                values = {"submit_attempted": False}
            await self._advance(
                session,
                row,
                [
                    (
                        state,
                        "DISPATCH_GATE_DENIED",
                        {
                            "action": action,
                            "reason": reason,
                            "discrepancies": discrepancies,
                        },
                    )
                ],
                values=values,
                guard_change=("CLEAR", None),
            )
            return await self._snapshot(session, row)

    async def complete_guarded_submit(
        self,
        order_id: str,
        state: OrderState,
        venue_order_id: str | None = None,
        *,
        conflict: bool = False,
        cancel_confirmed: bool = False,
        rejection_code: BrokerRejectionCode | None = None,
        cancel_gate_denied: bool = False,
    ) -> OrderSnapshot:
        """Record result, conflict and guard clearance in one SQLite commit."""
        self._require_actor_task()
        if (
            state not in {OrderState.WORKING, OrderState.REJECTED, OrderState.UNKNOWN_SUBMIT}
            or any(
                type(value) is not bool
                for value in (conflict, cancel_confirmed, cancel_gate_denied)
            )
            or (cancel_gate_denied and not conflict)
        ):
            raise OMSValidationError("INVALID_SUBMIT_RESULT")
        if state == OrderState.WORKING and not venue_order_id:
            raise OMSValidationError("VENUE_ORDER_ID_REQUIRED")
        if rejection_code is not None and (
            type(rejection_code) is not BrokerRejectionCode or state != OrderState.REJECTED
        ):
            raise OMSValidationError("INVALID_SUBMIT_RESULT")
        if venue_order_id is not None and (
            type(venue_order_id) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", venue_order_id) is None
        ):
            raise OMSValidationError("INVALID_SUBMIT_RESULT")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None or row.state != OrderState.DISPATCH_IN_FLIGHT.value:
                raise OMSConflict("DISPATCH_GUARD_REQUIRED")
            current = await self._snapshot(session, row)
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            guard = None if head is None else self._guard_from_head(head)
            if guard is None or guard.order_id != order_id or guard.action != "SUBMIT":
                raise OMSConflict("DISPATCH_GUARD_REQUIRED")
            if (
                not conflict
                and state != OrderState.UNKNOWN_SUBMIT
                and (
                    self._armed_here.get(order_id) != guard.fence_epoch or current.cancel_attempted
                )
            ):
                raise OMSConflict("STALE_DISPATCH_FENCE")
            self._armed_here.pop(order_id, None)
            code = (
                "SUBMIT_UNKNOWN" if state == OrderState.UNKNOWN_SUBMIT else "BROKER_SUBMIT_RESULT"
            )
            steps: list[tuple[OrderState, str, dict[str, Any]]] = [
                (
                    state,
                    code,
                    {
                        "venue_order_id": venue_order_id,
                        **(
                            {"rejection_code": rejection_code.value}
                            if rejection_code is not None
                            else {}
                        ),
                    },
                )
            ]
            values: dict[str, Any] = {"venue_order_id": venue_order_id}
            if conflict:
                discrepancies = list(row.discrepancies)
                if "POST_DISPATCH_CONFLICT" not in discrepancies:
                    discrepancies.append("POST_DISPATCH_CONFLICT")
                if cancel_gate_denied and "GATE_DENIED_CANCEL" not in discrepancies:
                    discrepancies.append("GATE_DENIED_CANCEL")
                final = (
                    OrderState.REJECTED
                    if state == OrderState.REJECTED
                    else OrderState.RECONCILE_REQUIRED
                )
                steps.append(
                    (
                        final,
                        "POST_DISPATCH_CONFLICT",
                        {
                            "cancel_requested": True,
                            "cancel_confirmed": cancel_confirmed,
                            "discrepancies": discrepancies,
                        },
                    )
                )
                values.update(discrepancies=discrepancies, cancel_attempted=True)
            release = not conflict and state != OrderState.UNKNOWN_SUBMIT
            try:
                await self._advance(
                    session,
                    row,
                    steps,
                    values=values,
                    guard_change=("CLEAR", None) if release else None,
                )
            except IntegrityError:
                raise OMSConflict("VENUE_ORDER_ID_CONFLICT") from None
            return await self._snapshot(session, row)

    async def complete_guarded_cancel(
        self,
        order_id: str,
        state: OrderState,
        *,
        verified_clean: bool,
        conflict: bool = False,
    ) -> OrderSnapshot:
        self._require_actor_task()
        if (
            state
            not in {
                OrderState.CANCELED,
                OrderState.CANCEL_REQUESTED_UNCONFIRMED,
                OrderState.UNKNOWN_CANCEL,
            }
            or type(verified_clean) is not bool
            or type(conflict) is not bool
        ):
            raise OMSValidationError("INVALID_CANCEL_RESULT")
        if verified_clean and (state != OrderState.CANCELED or conflict):
            raise OMSValidationError("INVALID_CANCEL_RESULT")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None or row.state != OrderState.DISPATCH_IN_FLIGHT.value:
                raise OMSConflict("DISPATCH_GUARD_REQUIRED")
            await self._snapshot(session, row)
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            guard = None if head is None else self._guard_from_head(head)
            if guard is None or guard.order_id != order_id or guard.action != "CANCEL":
                raise OMSConflict("DISPATCH_GUARD_REQUIRED")
            if verified_clean and self._armed_here.get(order_id) != guard.fence_epoch:
                raise OMSConflict("STALE_DISPATCH_FENCE")
            self._armed_here.pop(order_id, None)
            steps: list[tuple[OrderState, str, dict[str, Any]]] = [
                (
                    state,
                    "BROKER_CANCEL_CONFIRMED"
                    if state == OrderState.CANCELED
                    else "CANCEL_UNCONFIRMED",
                    {},
                )
            ]
            values: dict[str, Any] = {}
            if conflict:
                discrepancies = list(row.discrepancies)
                if "POST_DISPATCH_CONFLICT" not in discrepancies:
                    discrepancies.append("POST_DISPATCH_CONFLICT")
                final = (
                    OrderState.CANCELED
                    if state == OrderState.CANCELED
                    else OrderState.RECONCILE_REQUIRED
                )
                steps.append(
                    (
                        final,
                        "POST_DISPATCH_CONFLICT",
                        {
                            "cancel_requested": True,
                            "cancel_confirmed": state == OrderState.CANCELED,
                            "discrepancies": discrepancies,
                        },
                    )
                )
                values["discrepancies"] = discrepancies
            await self._advance(
                session,
                row,
                steps,
                values=values,
                guard_change=("CLEAR", None) if verified_clean else None,
            )
            return await self._snapshot(session, row)

    async def operator_release_guard(
        self,
        order_id: str,
        confirmation: OperatorGuardConfirmation,
        lookup: BrokerLookup,
        view: BrokerAccountView,
    ) -> OrderSnapshot:
        """Audit an authenticated operator decision and release in one commit."""
        self._require_actor_task()
        if (
            type(confirmation) is not OperatorGuardConfirmation
            or not isinstance(self._operator_key, OperatorAuthorizationKey)
            or not self._operator_key.verify(confirmation)
        ):
            raise OMSValidationError("OPERATOR_CONFIRMATION_MISMATCH")
        if type(lookup) is not BrokerLookup or type(view) is not BrokerAccountView:
            raise OMSValidationError("INVALID_BROKER_RECONCILIATION")
        if (
            lookup.status
            not in {BrokerReconciliationStatus.FOUND, BrokerReconciliationStatus.NOT_FOUND}
            or view.status
            not in {BrokerReconciliationStatus.FOUND, BrokerReconciliationStatus.NOT_FOUND}
            or lookup.revision != view.revision
            or broker_evidence_digest(lookup, view) != confirmation.broker_evidence_digest
        ):
            raise OMSValidationError("OPERATOR_CONFIRMATION_MISMATCH")
        match = lookup.match
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            current = await self._snapshot(session, row)
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            guard = None if head is None else self._guard_from_head(head)
            if guard is None or guard.order_id != order_id:
                raise OMSConflict("DISPATCH_GUARD_REQUIRED")
            if (order_id, guard.fence_epoch) in self._issued_here:
                raise OMSValidationError("OPERATOR_RELEASE_REFUSED_ACTIVE_DISPATCH")
            armed = (
                await session.scalars(
                    select(OmsEventRow)
                    .where(
                        OmsEventRow.order_id == order_id,
                        OmsEventRow.code == "DISPATCH_GUARD_SET",
                    )
                    .order_by(OmsEventRow.sequence.desc())
                )
            ).first()
            if armed is None or confirmation.guard_id != armed.chain:
                raise OMSValidationError("OPERATOR_CONFIRMATION_MISMATCH")
            if match is None:
                if guard.action != "SUBMIT" or current.discrepancies:
                    raise OMSConflict("ACCOUNT_RECONCILE_REQUIRED")
                state = OrderState.CREATED
                venue_order_id = None
                values: dict[str, Any] = {
                    "submit_attempted": False,
                    "cancel_attempted": False,
                    "venue_order_id": None,
                }
            else:
                if (
                    match.account_id != guard.account_id
                    or match.client_order_id != guard.client_order_id
                    or match.filled_quantity != 0
                    or match.state
                    not in {
                        OrderState.WORKING,
                        OrderState.REJECTED,
                        OrderState.CANCELED,
                        OrderState.EXPIRED,
                    }
                    or (guard.action == "CANCEL" and match.state != OrderState.CANCELED)
                ):
                    raise OMSConflict("ACCOUNT_RECONCILE_REQUIRED")
                state = match.state
                venue_order_id = match.venue_order_id
                values = {"venue_order_id": venue_order_id}
            await self._advance(
                session,
                row,
                [
                    (
                        state,
                        "OPERATOR_GUARD_RELEASED",
                        {
                            "guard_id": confirmation.guard_id,
                            "broker_evidence_digest": confirmation.broker_evidence_digest,
                            "operator_id": confirmation.operator_id,
                            "venue_order_id": venue_order_id,
                            "not_placed": match is None,
                        },
                    )
                ],
                values=values,
                guard_change=("CLEAR", None),
                bump_fence=True,
            )
            return await self._snapshot(session, row)

    async def reject_risk(self, order_id: str, code: str) -> OrderSnapshot:
        self._require_actor_when_bound()
        if not isinstance(code, str) or code not in {
            "DISPATCH_EVIDENCE_REQUIRED",
            "DISPATCH_SCOPE_MISMATCH",
            "ACCOUNT_UNVERIFIED",
            "ENTITLEMENT_UNVERIFIED",
            "FEED_STALE",
            "RISK_NOT_APPROVED",
            "HALT_ACTIVE",
            "ACTIVATION_NOT_ALLOWED",
            "ACCOUNT_RECONCILIATION_REQUIRED",
            "ACCOUNT_RECONCILE_REQUIRED",
        }:
            raise OMSValidationError("INVALID_RISK_DENIAL_CODE")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            if row.state != OrderState.CREATED.value:
                raise OMSConflict("ORDER_NOT_NEW")
            await self._advance(
                session,
                row,
                [
                    (OrderState.RISK_PENDING, "RISK_CHECK_STARTED", {}),
                    (OrderState.RISK_REJECTED, code, {}),
                ],
            )
            return await self._snapshot(session, row)

    async def mark_broker_intent_found(self, order_id: str, match: BrokerMatch) -> OrderSnapshot:
        """Quarantine a locally new order whose intent already exists at the broker."""
        self._require_actor_when_bound()
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            current = await self._snapshot(session, row)
            if current.state != OrderState.CREATED or current.submit_attempted:
                raise OMSConflict("SUBMIT_ALREADY_ATTEMPTED")
            if (
                not isinstance(match, BrokerMatch)
                or match.account_id != current.request.account_id
                or match.client_order_id != current.request.client_order_id
            ):
                raise OMSValidationError("BROKER_VIEW_INCONSISTENT")
            await self._advance(
                session,
                row,
                [
                    (
                        OrderState.RECONCILE_REQUIRED,
                        "BROKER_INTENT_FOUND",
                        {
                            "account_id": match.account_id,
                            "client_order_id": match.client_order_id,
                            "broker_state": match.state.value,
                            "venue_order_id": match.venue_order_id,
                        },
                    )
                ],
            )
            return await self._snapshot(session, row)

    async def mark_broker_account_unmatched(self, order_id: str) -> OrderSnapshot:
        """Durably quarantine an account whose broker view is not locally known."""
        self._require_actor_when_bound()
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            current = await self._snapshot(session, row)
            if current.state != OrderState.CREATED or current.submit_attempted:
                raise OMSConflict("SUBMIT_ALREADY_ATTEMPTED")
            await self._advance(
                session,
                row,
                [(OrderState.RECONCILE_REQUIRED, "BROKER_ACCOUNT_ACTIVITY_UNMATCHED", {})],
            )
            return await self._snapshot(session, row)

    async def mark_venue_mismatch(self, order_id: str, action: str) -> OrderSnapshot:
        """Persist a closed submit denial or an unresolved cancel scope conflict."""
        self._require_actor_task()
        if action not in {"SUBMIT", "CANCEL", "RECONCILE"}:
            raise OMSValidationError("INVALID_VENUE_ACTION")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            current = await self._snapshot(session, row)
            if action == "SUBMIT":
                if current.state != OrderState.CREATED or current.submit_attempted:
                    raise OMSConflict("SUBMIT_ALREADY_ATTEMPTED")
                target = OrderState.REJECTED
                evidence: dict[str, Any] = {}
                values: dict[str, Any] = {}
            else:
                if action == "CANCEL" and current.state not in {
                    OrderState.WORKING,
                    OrderState.PARTIALLY_FILLED,
                }:
                    raise OMSConflict("CANCEL_NOT_ALLOWED")
                if "VENUE_MISMATCH" in current.discrepancies:
                    return current
                target = (
                    current.state
                    if current.state in _TERMINAL_STATES
                    else OrderState.RECONCILE_REQUIRED
                )
                discrepancies = [*current.discrepancies, "VENUE_MISMATCH"]
                evidence = {"discrepancies": discrepancies}
                values = {"discrepancies": discrepancies}
            await self._advance(
                session,
                row,
                [(target, "VENUE_MISMATCH", evidence)],
                values=values,
            )
            return await self._snapshot(session, row)

    async def mark_venue_account_conflict(
        self,
        order_id: str,
        *,
        binding_venue: str | None = None,
        binding_environment: str | None = None,
        observations: tuple[tuple[str, str, str], ...] = (),
        affected_order_ids: tuple[str, ...] = (),
    ) -> OrderSnapshot:
        """Quarantine a binding conflict and capture exact new-image identity."""
        self._require_actor_task()
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            current = await self._snapshot(session, row)
            already_quarantined = "VENUE_ACCOUNT_CONFLICT" in current.discrepancies
            discrepancies = (
                list(current.discrepancies)
                if already_quarantined
                else [*current.discrepancies, "VENUE_ACCOUNT_CONFLICT"]
            )
            target = (
                current.state
                if current.state in _TERMINAL_STATES
                else OrderState.RECONCILE_REQUIRED
            )
            evidence: dict[str, Any] = {"discrepancies": discrepancies}
            precise_identity = (
                type(binding_venue) is str
                and type(binding_environment) is str
                and type(observations) is tuple
                and observations
                and type(affected_order_ids) is tuple
                and order_id in affected_order_ids
            )
            if precise_identity:
                cleaned: list[dict[str, str]] = []
                for item in observations:
                    if (
                        type(item) is not tuple
                        or len(item) != 3
                        or any(type(value) is not str for value in item)
                    ):
                        raise OMSValidationError("INVALID_VENUE_CONFLICT_IDENTITY")
                    observation_id, venue, environment = item
                    if (
                        not observation_id
                        or not venue
                        or environment not in {"paper", "demo", "live"}
                    ):
                        raise OMSValidationError("INVALID_VENUE_CONFLICT_IDENTITY")
                    cleaned.append(
                        {
                            "observation_id": observation_id,
                            "venue": venue,
                            "environment": environment,
                        }
                    )
                cleaned.sort(key=lambda value: value["observation_id"])
                ids = tuple(value["observation_id"] for value in cleaned)
                affected = tuple(sorted(set(affected_order_ids)))
                if len(ids) != len(set(ids)) or affected != affected_order_ids:
                    raise OMSValidationError("INVALID_VENUE_CONFLICT_IDENTITY")
                identity_payload = {
                    "environment": row.environment,
                    "account_id": row.account_id,
                    "binding_venue": binding_venue,
                    "binding_environment": binding_environment,
                    "observations": [
                        [value["observation_id"], value["venue"], value["environment"]]
                        for value in cleaned
                    ],
                    "affected_order_ids": list(affected),
                }
                evidence.update(
                    {
                        "binding_venue": binding_venue,
                        "binding_environment": binding_environment,
                        "observations": cleaned,
                        "affected_order_ids": list(affected),
                        "identity_digest": hashlib.sha256(
                            canonical_json(identity_payload)
                        ).hexdigest(),
                    }
                )
                if already_quarantined:
                    previous_conflict = await session.scalar(
                        select(OmsEventRow)
                        .where(
                            OmsEventRow.order_id == order_id,
                            OmsEventRow.code == "VENUE_ACCOUNT_CONFLICT",
                        )
                        .order_by(OmsEventRow.sequence.desc())
                        .limit(1)
                    )
                    if (
                        previous_conflict is not None
                        and previous_conflict.evidence.get("identity_digest")
                        == evidence["identity_digest"]
                    ):
                        return current
            elif already_quarantined:
                return current
            await self._advance(
                session,
                row,
                [(target, "VENUE_ACCOUNT_CONFLICT", evidence)],
                values={"discrepancies": discrepancies},
            )
            return await self._snapshot(session, row)

    async def venue_conflict_context(self, environment: str, account_id: str) -> dict[str, Any]:
        """Return exact active conflict identity and authenticated account revision."""
        self._require_actor_task()
        await self._ensure_operator_resolution_schema()
        async with self._sessions() as session:
            await self._verify_account(session, environment, account_id)
            head = await session.get(OmsLedgerHeadRow, (environment, account_id))
            conflict = await self._active_venue_conflict(session, environment, account_id)
            if head is None or conflict is None:
                raise VenueConflictResolutionError(VenueConflictResolutionCode.CONFLICT_NOT_FOUND)
            return {
                "environment": environment,
                "account_id": account_id,
                "conflict_id": conflict[0],
                "ledger_revision": head.sequence_count,
                "affected_order_ids": conflict[1],
                "binding_venue": conflict[2],
                "binding_environment": conflict[3],
                "observation_ids": conflict[4],
                "identity_digest": conflict[5],
                "guard": self._guard_from_head(head),
                "inventory": await self._identity_scoped_inventory(
                    session, environment, account_id
                ),
            }

    @staticmethod
    def _idempotency_digest(request: VenueConflictResolutionRequest) -> str:
        return hashlib.sha256(
            canonical_json(
                {
                    "environment": request.environment,
                    "account_id": request.account_id,
                    "conflict_id": request.conflict_id,
                    "idempotency_key": request.idempotency_key,
                }
            )
        ).hexdigest()

    async def find_venue_conflict_resolution(
        self, request: VenueConflictResolutionRequest
    ) -> dict[str, Any] | None:
        """Read a prior decision for a same-key retry; never releases a newer conflict."""
        self._require_actor_task()
        checked = require_venue_conflict_resolution_request(request)
        await self._ensure_operator_resolution_schema()
        async with self._sessions() as session:
            await self._verify_account(session, checked.environment, checked.account_id)
            row = await session.scalar(
                select(OmsOperatorResolutionRow).where(
                    OmsOperatorResolutionRow.environment == checked.environment,
                    OmsOperatorResolutionRow.account_id == checked.account_id,
                    OmsOperatorResolutionRow.idempotency_digest
                    == self._idempotency_digest(checked),
                )
            )
            if row is None:
                return None
            self._validate_operator_resolution_row(row)
            if (
                row.conflict_id != checked.conflict_id
                or row.operator_principal_id != checked.principal.subject_id
                or row.reason_code != checked.reason_code
                or row.prior_ledger_revision != checked.expected_ledger_revision
            ):
                raise VenueConflictResolutionError(
                    VenueConflictResolutionCode.RESOLUTION_ALREADY_USED
                )
            return self._resolution_row_values(row)

    async def append_venue_conflict_resolution(
        self,
        request: VenueConflictResolutionRequest,
        *,
        broker_revision: int,
        broker_evidence_digest: str,
        observed_at_ns: int,
    ) -> dict[str, Any]:
        """Durably append the decision before any quarantine-clear write."""
        self._require_actor_task()
        checked = require_venue_conflict_resolution_request(request)
        await self._ensure_operator_resolution_schema()
        if (
            type(broker_revision) is not int
            or not 0 <= broker_revision <= 2**63 - 1
            or type(broker_evidence_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", broker_evidence_digest) is None
            or type(observed_at_ns) is not int
            or observed_at_ns < 0
            or checked.human_confirmed is not True
        ):
            raise VenueConflictResolutionError(VenueConflictResolutionCode.INVALID_REQUEST)
        idem = self._idempotency_digest(checked)
        resolution_id = hashlib.sha256(
            canonical_json(
                {
                    "environment": checked.environment,
                    "account_id": checked.account_id,
                    "conflict_id": checked.conflict_id,
                    "idempotency_digest": idem,
                }
            )
        ).hexdigest()
        async with self._sessions() as session:
            await self._verify_account(session, checked.environment, checked.account_id)
            existing = await session.get(OmsOperatorResolutionRow, resolution_id)
            if existing is not None:
                self._validate_operator_resolution_row(existing)
                if (
                    existing.idempotency_digest != idem
                    or existing.operator_principal_id != checked.principal.subject_id
                    or existing.reason_code != checked.reason_code
                    or existing.prior_ledger_revision != checked.expected_ledger_revision
                    or existing.broker_evidence_digest != broker_evidence_digest
                    or existing.broker_revision != broker_revision
                ):
                    raise VenueConflictResolutionError(
                        VenueConflictResolutionCode.RESOLUTION_ALREADY_USED
                    )
                return self._resolution_row_values(existing)
            head = await session.get(OmsLedgerHeadRow, (checked.environment, checked.account_id))
            current = await self._active_venue_conflict(
                session, checked.environment, checked.account_id
            )
            if head is None or current is None:
                raise VenueConflictResolutionError(VenueConflictResolutionCode.CONFLICT_NOT_FOUND)
            if (
                head.sequence_count != checked.expected_ledger_revision
                or current[0] != checked.conflict_id
            ):
                raise VenueConflictResolutionError(VenueConflictResolutionCode.STALE_REVISION)
            if self._guard_from_head(head) is not None:
                raise VenueConflictResolutionError(VenueConflictResolutionCode.UNRESOLVED_EVIDENCE)
            snapshots = await self._identity_scoped_inventory(
                session, checked.environment, checked.account_id
            )
            if any(
                snapshot.order_id in current[1]
                and any(code != "VENUE_ACCOUNT_CONFLICT" for code in snapshot.discrepancies)
                for snapshot in snapshots
            ):
                raise VenueConflictResolutionError(VenueConflictResolutionCode.UNRESOLVED_EVIDENCE)
            row = OmsOperatorResolutionRow(
                resolution_id=resolution_id,
                environment=checked.environment,
                account_id=checked.account_id,
                conflict_id=checked.conflict_id,
                binding_venue=current[2],
                binding_environment=current[3],
                observation_ids=list(current[4]),
                identity_digest=current[5],
                idempotency_digest=idem,
                operator_principal_id=checked.principal.subject_id,
                reason_code=checked.reason_code,
                broker_revision=broker_revision,
                broker_evidence_digest=broker_evidence_digest,
                prior_ledger_revision=checked.expected_ledger_revision,
                resolved_at_ns=observed_at_ns,
                affected_order_ids=list(current[1]),
                ledger_sequence=None,
                chain=None,
                recorded_at=datetime.now(UTC),
            )
            self._validate_operator_resolution_row(row)
            session.add(row)
            await self._seal_account(session, checked.environment, checked.account_id)
            await session.commit()
            return self._resolution_row_values(row)

    async def clear_venue_conflict_quarantine(
        self,
        request: VenueConflictResolutionRequest,
        *,
        resolution_id: str,
        broker_revision: int,
        broker_evidence_digest: str,
        restored_states: dict[str, OrderState],
    ) -> dict[str, Any]:
        """Clear only the recorded conflict after its append-only decision committed."""
        self._require_actor_task()
        checked = require_venue_conflict_resolution_request(request)
        await self._ensure_operator_resolution_schema()
        async with self._sessions() as session:
            await self._verify_account(session, checked.environment, checked.account_id)
            row = await session.get(OmsOperatorResolutionRow, resolution_id)
            head = await session.get(OmsLedgerHeadRow, (checked.environment, checked.account_id))
            current = await self._active_venue_conflict(
                session, checked.environment, checked.account_id
            )
            if row is None or head is None:
                raise VenueConflictResolutionError(VenueConflictResolutionCode.CONFLICT_NOT_FOUND)
            if current is None:
                raise VenueConflictResolutionError(VenueConflictResolutionCode.STALE_CONFLICT)
            self._validate_operator_resolution_row(row)
            if (
                row.conflict_id != checked.conflict_id
                or row.binding_venue != current[2]
                or row.binding_environment != current[3]
                or tuple(row.observation_ids) != current[4]
                or row.identity_digest != current[5]
                or row.operator_principal_id != checked.principal.subject_id
                or row.prior_ledger_revision != checked.expected_ledger_revision
                or row.broker_revision != broker_revision
                or row.broker_evidence_digest != broker_evidence_digest
                or current[0] != checked.conflict_id
                or tuple(row.affected_order_ids) != current[1]
            ):
                raise VenueConflictResolutionError(VenueConflictResolutionCode.STALE_CONFLICT)
            if head.sequence_count != checked.expected_ledger_revision + 1:
                raise VenueConflictResolutionError(VenueConflictResolutionCode.STALE_REVISION)
            if self._guard_from_head(head) is not None:
                raise VenueConflictResolutionError(VenueConflictResolutionCode.UNRESOLVED_EVIDENCE)
            if type(restored_states) is not dict or set(restored_states) != set(current[1]):
                raise VenueConflictResolutionError(
                    VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH
                )
            snapshots: dict[str, OrderSnapshot] = {}
            rows: dict[str, OmsOrderRow] = {}
            for order_id in current[1]:
                order_row = await session.get(OmsOrderRow, order_id)
                if order_row is None:
                    raise OMSLedgerCorruption()
                snapshot = await self._snapshot(session, order_row)
                if "VENUE_ACCOUNT_CONFLICT" not in snapshot.discrepancies or any(
                    code != "VENUE_ACCOUNT_CONFLICT" for code in snapshot.discrepancies
                ):
                    raise VenueConflictResolutionError(
                        VenueConflictResolutionCode.UNRESOLVED_EVIDENCE
                    )
                target = restored_states[order_id]
                if type(target) is not OrderState:
                    raise VenueConflictResolutionError(
                        VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH
                    )
                if snapshot.state in _TERMINAL_STATES:
                    if target is not snapshot.state:
                        raise VenueConflictResolutionError(
                            VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH
                        )
                elif snapshot.state is not OrderState.RECONCILE_REQUIRED or target not in {
                    OrderState.CREATED,
                    OrderState.WORKING,
                    OrderState.PARTIALLY_FILLED,
                    OrderState.FILLED,
                }:
                    raise VenueConflictResolutionError(
                        VenueConflictResolutionCode.BROKER_EVIDENCE_MISMATCH
                    )
                snapshots[order_id] = snapshot
                rows[order_id] = order_row
            now = datetime.now(UTC)
            for order_id in current[1]:
                snapshot = snapshots[order_id]
                order_row = rows[order_id]
                target = restored_states[order_id]
                discrepancies = [
                    code for code in snapshot.discrepancies if code != "VENUE_ACCOUNT_CONFLICT"
                ]
                changed = await session.execute(
                    update(OmsOrderRow)
                    .where(
                        OmsOrderRow.order_id == order_id,
                        OmsOrderRow.version == order_row.version,
                        OmsOrderRow.state == order_row.state,
                    )
                    .values(
                        state=target.value,
                        version=order_row.version + 1,
                        updated_at=now,
                        discrepancies=discrepancies,
                    )
                )
                if not isinstance(changed, CursorResult) or changed.rowcount != 1:
                    raise VenueConflictResolutionError(VenueConflictResolutionCode.STALE_REVISION)
                session.add(
                    OmsEventRow(
                        order_id=order_id,
                        sequence=order_row.version,
                        state=target.value,
                        code="VENUE_ACCOUNT_CONFLICT_RESOLVED",
                        evidence={
                            "resolution_id": resolution_id,
                            "conflict_id": checked.conflict_id,
                            "broker_revision": broker_revision,
                            "broker_evidence_digest": broker_evidence_digest,
                            "prior_ledger_revision": checked.expected_ledger_revision,
                            "identity_digest": row.identity_digest,
                            "discrepancies": discrepancies,
                            "resolved_state": target.value,
                        },
                        recorded_at=now,
                    )
                )
            await self._seal_account(session, checked.environment, checked.account_id)
            await session.commit()
            refreshed = await session.get(
                OmsLedgerHeadRow, (checked.environment, checked.account_id)
            )
            if refreshed is None:
                raise OMSLedgerCorruption()
            values = self._resolution_row_values(row)
            values["resolved_ledger_revision"] = refreshed.sequence_count
            return values

    async def _identity_scoped_inventory(
        self, session: AsyncSession, environment: str, account_id: str
    ) -> tuple[OrderSnapshot, ...]:
        rows = (
            await session.scalars(
                select(OmsOrderRow)
                .where(
                    OmsOrderRow.environment == environment,
                    OmsOrderRow.account_id == account_id,
                )
                .order_by(OmsOrderRow.order_id)
            )
        ).all()
        return tuple([await self._snapshot(session, row) for row in rows])

    async def is_exact_venue_conflict_resolved(
        self,
        *,
        environment: str,
        account_id: str,
        binding_venue: str,
        binding_environment: str,
        observation_ids: tuple[str, ...],
        affected_order_ids: tuple[str, ...],
        identity_digest: str,
    ) -> bool:
        """Fail-closed read-side waiver for one exact cleared conflict image."""
        self._require_actor_task()
        try:
            await self._ensure_operator_resolution_schema()
            async with self._sessions() as session:
                await self._verify_account(session, environment, account_id)
                rows = (
                    await session.scalars(
                        select(OmsOperatorResolutionRow).where(
                            OmsOperatorResolutionRow.environment == environment,
                            OmsOperatorResolutionRow.account_id == account_id,
                            OmsOperatorResolutionRow.identity_digest == identity_digest,
                        )
                    )
                ).all()
                if len(rows) != 1:
                    return False
                row = rows[0]
                self._validate_operator_resolution_row(row)
                if (
                    row.binding_venue != binding_venue
                    or row.binding_environment != binding_environment
                    or tuple(row.observation_ids) != observation_ids
                    or tuple(row.affected_order_ids) != affected_order_ids
                ):
                    return False
                orders = {
                    snapshot.order_id: snapshot
                    for snapshot in await self._identity_scoped_inventory(
                        session, environment, account_id
                    )
                }
                if any(
                    order_id not in orders
                    or "VENUE_ACCOUNT_CONFLICT" in orders[order_id].discrepancies
                    for order_id in affected_order_ids
                ):
                    return False
                event_rows = (
                    await session.scalars(
                        select(OmsEventRow).where(
                            OmsEventRow.order_id.in_(affected_order_ids),
                            OmsEventRow.code == "VENUE_ACCOUNT_CONFLICT_RESOLVED",
                        )
                    )
                ).all()
                covered = {
                    event.order_id
                    for event in event_rows
                    if event.evidence.get("resolution_id") == row.resolution_id
                    and event.evidence.get("identity_digest") == identity_digest
                }
                return covered == set(affected_order_ids)
        except Exception:
            return False

    async def mark_submit_stale(self, order_id: str) -> OrderSnapshot:
        """Record the port's authenticated no-placement response and release the claim."""
        self._require_actor_task()
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            current = await self._snapshot(session, row)
            if (
                current.state not in {OrderState.SUBMITTING, OrderState.DISPATCH_IN_FLIGHT}
                or not current.submit_attempted
            ):
                raise OMSConflict("SUBMIT_MARKER_REQUIRED")
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            guard = None if head is None else self._guard_from_head(head)
            if guard is not None and (guard.order_id != order_id or guard.action != "SUBMIT"):
                raise OMSConflict("ACCOUNT_RECONCILE_REQUIRED")
            if guard is not None and (
                self._armed_here.get(order_id) != guard.fence_epoch or current.cancel_attempted
            ):
                raise OMSConflict("STALE_DISPATCH_FENCE")
            self._armed_here.pop(order_id, None)
            await self._advance(
                session,
                row,
                [(OrderState.CREATED, "BROKER_DISPATCH_NOT_PLACED", {})],
                values={"submit_attempted": False},
                guard_change=("CLEAR", None) if guard is not None else None,
            )
            return await self._snapshot(session, row)

    async def mark_pre_dispatch_stale_conflict(self, order_id: str) -> OrderSnapshot:
        """Quarantine changed broker evidence discovered after a stale refusal."""
        self._require_actor_when_bound()
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            current = await self._snapshot(session, row)
            if current.state != OrderState.CREATED or current.submit_attempted:
                raise OMSConflict("ORDER_NOT_NEW")
            await self._advance(
                session,
                row,
                [(OrderState.RECONCILE_REQUIRED, "STALE_BROKER_VIEW", {})],
            )
            return await self._snapshot(session, row)

    async def mark_post_dispatch_conflict(
        self, order_id: str, *, cancel_confirmed: bool
    ) -> OrderSnapshot:
        """Persist cancellation request and discrepancy after a late broker conflict."""
        self._require_actor_when_bound()
        if type(cancel_confirmed) is not bool:
            raise OMSValidationError("INVALID_CANCEL_RESULT")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            current = await self._snapshot(session, row)
            if current.state not in {
                OrderState.WORKING,
                OrderState.REJECTED,
                OrderState.UNKNOWN_SUBMIT,
            }:
                raise OMSConflict("SUBMIT_RESULT_REQUIRED")
            discrepancies = list(current.discrepancies)
            if "POST_DISPATCH_CONFLICT" not in discrepancies:
                discrepancies.append("POST_DISPATCH_CONFLICT")
            state = (
                OrderState.REJECTED
                if current.state == OrderState.REJECTED
                else OrderState.RECONCILE_REQUIRED
            )
            await self._advance(
                session,
                row,
                [
                    (
                        state,
                        "POST_DISPATCH_CONFLICT",
                        {
                            "cancel_requested": True,
                            "cancel_confirmed": cancel_confirmed,
                            "discrepancies": discrepancies,
                        },
                    )
                ],
                values={"discrepancies": discrepancies, "cancel_attempted": True},
            )
            return await self._snapshot(session, row)

    async def account_inventory(
        self, environment: str, account_id: str
    ) -> tuple[OrderSnapshot, ...]:
        """Return authenticated account orders for broker-view comparison."""
        self._integrity_key()
        async with self._sessions() as session:
            await self._audit_all_oms_rows(session)
            rows = (
                await session.scalars(
                    select(OmsOrderRow).where(
                        OmsOrderRow.environment == environment,
                        OmsOrderRow.account_id == account_id,
                    )
                )
            ).all()
            return tuple([await self._snapshot(session, row) for row in rows])

    async def verified_submit_snapshot(
        self, environment: str, account_id: str
    ) -> VerifiedSubmitSnapshot:
        """Return all pre-submit evidence from one global authenticated audit."""
        if (
            type(environment) is not str
            or environment not in {"paper", "demo"}
            or type(account_id) is not str
            or not account_id
        ):
            raise OMSValidationError("INVALID_VERIFIED_SUBMIT_SNAPSHOT")
        self._integrity_key()
        async with self._sessions() as session:
            await self._audit_all_oms_rows(session)
            scoped_rows = (
                await session.scalars(
                    select(OmsOrderRow).where(
                        OmsOrderRow.environment == environment,
                        OmsOrderRow.account_id == account_id,
                    )
                )
            ).all()
            identity_rows = (
                await session.scalars(
                    select(OmsOrderRow)
                    .join(OmsEventRow, OmsEventRow.order_id == OmsOrderRow.order_id)
                    .where(
                        OmsOrderRow.account_id == account_id,
                        OmsEventRow.sequence == 0,
                    )
                    .order_by(OmsEventRow.id)
                )
            ).all()
            scoped_inventory = tuple(
                [await self._snapshot_checked(session, row) for row in scoped_rows]
            )
            identity_inventory = tuple(
                [await self._snapshot_checked(session, row) for row in identity_rows]
            )

            fill_rows = (
                await session.scalars(
                    select(OmsFillRow)
                    .join(OmsOrderRow, OmsOrderRow.order_id == OmsFillRow.order_id)
                    .where(
                        OmsOrderRow.environment == environment,
                        OmsOrderRow.account_id == account_id,
                    )
                    .order_by(OmsFillRow.id)
                )
            ).all()
            fills = tuple(
                (
                    row.order_id,
                    Fill(
                        row.venue,
                        row.account_id,
                        row.execution_id,
                        parse_oms_decimal(row.quantity, positive=True, code="INVALID_STORED_FILL"),
                        parse_oms_decimal(row.price, positive=True, code="INVALID_STORED_FILL"),
                        self._stored_time(row.occurred_at),
                        parse_oms_decimal(row.commission, code="INVALID_STORED_FILL"),
                    ),
                )
                for row in fill_rows
            )
            correction_rows = (
                await session.scalars(
                    select(OmsFillCorrectionRow)
                    .join(OmsOrderRow, OmsOrderRow.order_id == OmsFillCorrectionRow.order_id)
                    .where(
                        OmsOrderRow.environment == environment,
                        OmsOrderRow.account_id == account_id,
                    )
                    .order_by(OmsFillCorrectionRow.id)
                )
            ).all()
            corrections = tuple(
                (
                    row.order_id,
                    FillCorrection(
                        row.venue,
                        row.account_id,
                        row.execution_id,
                        row.correction_id,
                        row.revision,
                        parse_oms_decimal(row.revised_quantity, code="INVALID_STORED_CORRECTION"),
                        (
                            parse_oms_decimal(
                                row.revised_price,
                                positive=True,
                                code="INVALID_STORED_CORRECTION",
                            )
                            if row.revised_price is not None
                            else None
                        ),
                        self._stored_time(row.occurred_at),
                        parse_oms_decimal(row.revised_commission, code="INVALID_STORED_CORRECTION"),
                    ),
                )
                for row in correction_rows
            )
            return VerifiedSubmitSnapshot(
                environment=environment,
                account_id=account_id,
                account_inventory=scoped_inventory,
                account_identity_inventory=identity_inventory,
                account_execution_evidence=fills,
                account_fill_corrections=corrections,
            )

    async def account_identity_inventory(self, account_id: str) -> tuple[OrderSnapshot, ...]:
        """Return all account orders in durable creation order across venues and envs."""
        self._integrity_key()
        async with self._sessions() as session:
            await self._audit_all_oms_rows(session)
            rows = (
                await session.scalars(
                    select(OmsOrderRow)
                    .join(OmsEventRow, OmsEventRow.order_id == OmsOrderRow.order_id)
                    .where(
                        OmsOrderRow.account_id == account_id,
                        OmsEventRow.sequence == 0,
                    )
                    .order_by(OmsEventRow.id)
                )
            ).all()
            return tuple([await self._snapshot(session, row) for row in rows])

    async def account_execution_evidence(
        self,
        environment: str,
        account_id: str,
    ) -> tuple[tuple[str, Fill], ...]:
        """Return every original fill after authenticated replay of OMS rows."""
        self._integrity_key()
        async with self._sessions() as session:
            await self._audit_all_oms_rows(session)
            rows = (
                await session.scalars(
                    select(OmsFillRow)
                    .join(OmsOrderRow, OmsFillRow.order_id == OmsOrderRow.order_id)
                    .where(
                        OmsOrderRow.environment == environment,
                        OmsOrderRow.account_id == account_id,
                    )
                    .order_by(OmsFillRow.id)
                )
            ).all()
            return tuple(
                (
                    row.order_id,
                    Fill(
                        row.venue,
                        row.account_id,
                        row.execution_id,
                        parse_oms_decimal(row.quantity, positive=True, code="INVALID_STORED_FILL"),
                        parse_oms_decimal(row.price, positive=True, code="INVALID_STORED_FILL"),
                        self._stored_time(row.occurred_at),
                        parse_oms_decimal(row.commission, code="INVALID_STORED_FILL"),
                    ),
                )
                for row in rows
            )

    async def _activity_net_filled_units(
        self,
        session: AsyncSession,
        environment: str,
        account_id: str,
        high_water_sequence: int,
    ) -> tuple[tuple[str, str, Decimal], ...]:
        corrections = (
            select(
                OmsFillCorrectionRow.order_id.label("order_id"),
                OmsFillCorrectionRow.execution_id.label("execution_id"),
                OmsFillCorrectionRow.revised_quantity.label("revised_quantity"),
                func.row_number()
                .over(
                    partition_by=(
                        OmsFillCorrectionRow.order_id,
                        OmsFillCorrectionRow.execution_id,
                    ),
                    order_by=OmsFillCorrectionRow.revision.desc(),
                )
                .label("revision_rank"),
            )
            .join(OmsOrderRow, OmsOrderRow.order_id == OmsFillCorrectionRow.order_id)
            .where(
                OmsOrderRow.environment == environment,
                OmsOrderRow.account_id == account_id,
                OmsFillCorrectionRow.ledger_sequence <= high_water_sequence,
            )
            .subquery()
        )
        statement = (
            select(
                OmsOrderRow.venue,
                OmsOrderRow.request,
                OmsOrderRow.request_digest,
                OmsFillRow.quantity,
                corrections.c.revised_quantity,
            )
            .select_from(OmsOrderRow)
            .outerjoin(
                OmsFillRow,
                and_(
                    OmsFillRow.order_id == OmsOrderRow.order_id,
                    OmsFillRow.ledger_sequence <= high_water_sequence,
                ),
            )
            .outerjoin(
                corrections,
                and_(
                    corrections.c.order_id == OmsFillRow.order_id,
                    corrections.c.execution_id == OmsFillRow.execution_id,
                    corrections.c.revision_rank == 1,
                ),
            )
            .where(
                OmsOrderRow.environment == environment,
                OmsOrderRow.account_id == account_id,
            )
            .order_by(OmsOrderRow.order_id, OmsFillRow.execution_id)
            .execution_options(yield_per=100)
        )
        result = await session.stream(statement)
        groups: dict[tuple[str, str], Decimal] = {}
        async for raw in result:
            venue, payload, digest, fill_quantity, revised_quantity = raw
            try:
                request = OrderRequest.from_payload(payload)
                if request.digest != digest or request.venue != venue:
                    raise OMSLedgerCorruption()
                key = (venue, request.instrument_id)
                quantity = (
                    Decimal(0)
                    if fill_quantity is None
                    else (
                        parse_oms_decimal(revised_quantity, code="INVALID_STORED_CORRECTION")
                        if revised_quantity is not None
                        else parse_oms_decimal(
                            fill_quantity,
                            positive=True,
                            code="INVALID_STORED_FILL",
                        )
                    )
                )
                signed = quantity if request.side == "BUY" else -quantity
                groups[key] = exact_sum((groups.get(key, Decimal(0)), signed))
                if len(groups) > 100:
                    raise OMSValidationError("ACTIVITY_TOO_LARGE")
            except OMSValidationError:
                raise
            except Exception:
                raise OMSLedgerCorruption() from None
        return tuple(
            (venue, instrument, groups[(venue, instrument)]) for venue, instrument in sorted(groups)
        )

    async def _activity_order_snapshot(
        self,
        session: AsyncSession,
        row: OmsOrderRow,
        high_water_sequence: int,
        current_high_water: int,
    ) -> OrderSnapshot:
        if (
            type(row.version) is not int
            or row.version < 0
            or type(row.submit_attempted) is not bool
            or type(row.cancel_attempted) is not bool
            or type(row.request) is not dict
            or type(row.request_digest) is not str
        ):
            raise OMSLedgerCorruption()
        created_at = self._stored_time(row.created_at)
        updated_at = self._stored_time(row.updated_at)
        if updated_at < created_at:
            raise OMSLedgerCorruption()
        request = OrderRequest.from_payload(row.request)
        if (
            request.payload() != row.request
            or request.digest != row.request_digest
            or request.environment != row.environment
            or request.account_id != row.account_id
            or request.venue != row.venue
            or request.client_order_id != row.client_order_id
            or request.root_order_id != row.root_order_id
            or request.parent_order_id != row.parent_order_id
        ):
            raise OMSLedgerCorruption()

        event_result = await session.stream_scalars(
            select(OmsEventRow)
            .where(
                OmsEventRow.order_id == row.order_id,
                OmsEventRow.ledger_sequence <= high_water_sequence,
            )
            .order_by(OmsEventRow.sequence)
            .execution_options(yield_per=100)
        )
        event_count = 0
        latest_state: OrderState | None = None
        latest_sequence = -1
        discrepancies: tuple[str, ...] = ()
        previous_time: datetime | None = None
        async for event in event_result:
            if (
                type(event.id) is not int
                or event.id < 1
                or event.order_id != row.order_id
                or type(event.sequence) is not int
                or event.sequence != event_count
                or type(event.code) is not str
                or event.code not in _EVENT_CODES
                or type(event.state) is not str
                or type(event.evidence) is not dict
            ):
                raise OMSLedgerCorruption()
            state = OrderState(event.state)
            event_time = self._stored_time(event.recorded_at)
            if (
                event_time < created_at
                or event_time > updated_at
                or (previous_time is not None and event_time < previous_time)
                or (latest_state in _TERMINAL_STATES and state != latest_state)
            ):
                raise OMSLedgerCorruption()
            if event_count == 0 and (
                event.code != "ORDER_CREATED"
                or state != OrderState.CREATED
                or event.evidence != {"request_digest": request.digest}
            ):
                raise OMSLedgerCorruption()
            if "discrepancies" in event.evidence:
                discrepancies = self._stored_discrepancies(event.evidence["discrepancies"])
            event_count += 1
            latest_state = state
            latest_sequence = event.sequence
            previous_time = event_time
            if event_count % 100 == 0:
                await asyncio.sleep(0)
        await event_result.close()
        if event_count == 0 or latest_state is None or latest_sequence != event_count - 1:
            raise OMSLedgerCorruption()

        correction_stats = (
            select(
                OmsFillCorrectionRow.execution_id.label("execution_id"),
                func.count().label("revision_count"),
                func.min(OmsFillCorrectionRow.revision).label("min_revision"),
                func.max(OmsFillCorrectionRow.revision).label("max_revision"),
            )
            .where(
                OmsFillCorrectionRow.order_id == row.order_id,
                OmsFillCorrectionRow.ledger_sequence <= high_water_sequence,
            )
            .group_by(OmsFillCorrectionRow.execution_id)
            .subquery()
        )
        revision_result = await session.stream(
            select(
                correction_stats.c.execution_id,
                correction_stats.c.revision_count,
                correction_stats.c.min_revision,
                correction_stats.c.max_revision,
                OmsFillRow.id,
            )
            .select_from(
                correction_stats.outerjoin(
                    OmsFillRow,
                    and_(
                        OmsFillRow.order_id == row.order_id,
                        OmsFillRow.execution_id == correction_stats.c.execution_id,
                        OmsFillRow.ledger_sequence <= high_water_sequence,
                    ),
                )
            )
            .execution_options(yield_per=100)
        )
        async for _execution_id, count, minimum, maximum, fill_id in revision_result:
            if (
                fill_id is None
                or type(count) is not int
                or type(minimum) is not int
                or type(maximum) is not int
                or minimum != 1
                or count != maximum
            ):
                raise OMSLedgerCorruption()
        await revision_result.close()

        correction_result = await session.stream_scalars(
            select(OmsFillCorrectionRow)
            .where(
                OmsFillCorrectionRow.order_id == row.order_id,
                OmsFillCorrectionRow.ledger_sequence <= high_water_sequence,
            )
            .order_by(OmsFillCorrectionRow.ledger_sequence)
            .execution_options(yield_per=100)
        )
        async for correction in correction_result:
            FillCorrection(
                venue=correction.venue,
                account_id=correction.account_id,
                execution_id=correction.execution_id,
                correction_id=correction.correction_id,
                revision=correction.revision,
                revised_quantity=parse_oms_decimal(
                    correction.revised_quantity, code="INVALID_STORED_CORRECTION"
                ),
                revised_price=(
                    parse_oms_decimal(
                        correction.revised_price,
                        positive=True,
                        code="INVALID_STORED_CORRECTION",
                    )
                    if correction.revised_price is not None
                    else None
                ),
                revised_commission=parse_oms_decimal(
                    correction.revised_commission, code="INVALID_STORED_CORRECTION"
                ),
                occurred_at=self._stored_time(correction.occurred_at),
            )
            if (
                type(correction.id) is not int
                or correction.id < 1
                or correction.order_id != row.order_id
                or correction.venue != row.venue
                or correction.account_id != row.account_id
            ):
                raise OMSLedgerCorruption()
        await correction_result.close()

        latest_corrections = (
            select(
                OmsFillCorrectionRow.order_id.label("order_id"),
                OmsFillCorrectionRow.execution_id.label("execution_id"),
                OmsFillCorrectionRow.revised_quantity.label("revised_quantity"),
                func.row_number()
                .over(
                    partition_by=OmsFillCorrectionRow.execution_id,
                    order_by=OmsFillCorrectionRow.revision.desc(),
                )
                .label("revision_rank"),
            )
            .where(
                OmsFillCorrectionRow.order_id == row.order_id,
                OmsFillCorrectionRow.ledger_sequence <= high_water_sequence,
            )
            .subquery()
        )
        fill_result = await session.stream(
            select(OmsFillRow, latest_corrections.c.revised_quantity)
            .outerjoin(
                latest_corrections,
                and_(
                    latest_corrections.c.order_id == OmsFillRow.order_id,
                    latest_corrections.c.execution_id == OmsFillRow.execution_id,
                    latest_corrections.c.revision_rank == 1,
                ),
            )
            .where(
                OmsFillRow.order_id == row.order_id,
                OmsFillRow.ledger_sequence <= high_water_sequence,
            )
            .order_by(OmsFillRow.execution_id)
            .execution_options(yield_per=100)
        )
        filled = Decimal(0)
        async for fill, revised_quantity in fill_result:
            checked_fill = Fill(
                venue=fill.venue,
                account_id=fill.account_id,
                execution_id=fill.execution_id,
                quantity=parse_oms_decimal(
                    fill.quantity, positive=True, code="INVALID_STORED_FILL"
                ),
                price=parse_oms_decimal(fill.price, positive=True, code="INVALID_STORED_FILL"),
                commission=parse_oms_decimal(fill.commission, code="INVALID_STORED_FILL"),
                occurred_at=self._stored_time(fill.occurred_at),
            )
            if (
                type(fill.id) is not int
                or fill.id < 1
                or fill.order_id != row.order_id
                or checked_fill.venue != row.venue
                or checked_fill.account_id != row.account_id
            ):
                raise OMSLedgerCorruption()
            effective_quantity = (
                parse_oms_decimal(revised_quantity, code="INVALID_STORED_CORRECTION")
                if revised_quantity is not None
                else checked_fill.quantity
            )
            filled = exact_sum((filled, effective_quantity))
        await fill_result.close()
        if (filled > request.quantity and "OVERFILL" not in discrepancies) or (
            filled <= request.quantity and "OVERFILL" in discrepancies
        ):
            raise OMSLedgerCorruption()

        observation_result = await session.stream_scalars(
            select(OmsObservationRow)
            .where(
                OmsObservationRow.order_id == row.order_id,
                OmsObservationRow.ledger_sequence <= high_water_sequence,
            )
            .order_by(OmsObservationRow.ledger_sequence)
            .execution_options(yield_per=100)
        )
        async for observation_row in observation_result:
            observed = self._checked_observation(observation_row)
            if (
                observation_row.order_id != row.order_id
                or observed.environment != request.environment
                or observed.account_id != request.account_id
                or observed.venue != request.venue
                or observed.client_order_id != request.client_order_id
            ):
                raise OMSLedgerCorruption()
        await observation_result.close()

        if high_water_sequence == current_high_water and (
            latest_state != OrderState(row.state)
            or latest_sequence != row.version
            or discrepancies != self._stored_discrepancies(row.discrepancies)
        ):
            raise OMSLedgerCorruption()
        try:
            return OrderSnapshot(
                order_id=row.order_id,
                request=request,
                state=latest_state,
                version=latest_sequence,
                venue_order_id=row.venue_order_id,
                filled_quantity=filled,
                discrepancies=discrepancies,
                submit_attempted=row.submit_attempted,
                cancel_attempted=row.cancel_attempted,
            )
        except Exception:
            raise OMSLedgerCorruption() from None

    async def _ensure_activity_wal(self) -> None:
        database = self._engine.url.database
        is_memory = (
            database in (None, "", ":memory:") or self._engine.url.query.get("mode") == "memory"
        )
        if is_memory:
            # In-memory SQLite is limited to sequential test fixtures; the actor's
            # single-read gate still applies, while file-backed operation requires WAL.
            return
        if self._activity_wal_ready:
            return
        async with self._activity_wal_lock:
            if self._activity_wal_ready:
                return
            try:
                async with self._engine.connect() as connection:
                    autocommit = await connection.execution_options(isolation_level="AUTOCOMMIT")
                    result = await autocommit.exec_driver_sql("PRAGMA journal_mode=WAL")
                    mode = result.scalar_one_or_none()
                if type(mode) is not str or mode.lower() != "wal":
                    raise OMSConflict("ACTIVITY_WAL_REQUIRED")
            except OMSConflict:
                raise
            except Exception:
                raise OMSConflict("ACTIVITY_WAL_REQUIRED") from None
            self._activity_wal_ready = True

    async def begin_activity_read_snapshot(self, environment: str, account_id: str) -> object:
        self._integrity_key()
        if (
            type(environment) is not str
            or environment not in {"paper", "demo"}
            or type(account_id) is not str
            or not account_id
        ):
            raise OMSValidationError("INVALID_ACTIVITY_QUERY")
        await self._ensure_activity_wal()
        is_memory = (
            self._engine.url.database in (None, "", ":memory:")
            or self._engine.url.query.get("mode") == "memory"
        )
        if not is_memory:
            worker = _ActivityReadWorker()
            try:
                high_water = await worker.run(
                    self._open_activity_worker_snapshot(worker, environment, account_id)
                )
                snapshot = _ActivityReadSnapshot(
                    _ACTIVITY_SNAPSHOT_ISSUER,
                    self._activity_snapshot_owner,
                    worker.session,
                    environment,
                    account_id,
                    high_water,
                    worker,
                )
                self._activity_snapshots[id(snapshot)] = snapshot
                return snapshot
            except BaseException:
                with suppress(Exception):
                    await worker.run(self._close_activity_worker_snapshot(worker))
                await worker.stop()
                raise
        session = self._sessions()
        query_only_enabled = False
        try:
            await session.begin()
            await session.execute(text("PRAGMA query_only=ON"))
            query_only_enabled = True
            # sqlite3's legacy transaction mode does not issue a database-level
            # BEGIN for SELECTs. Explicitly begin so the first head read pins a
            # WAL snapshot that survives while verification runs outside actor.
            connection = await session.connection()
            await connection.exec_driver_sql("BEGIN")
            mode = await session.scalar(text("PRAGMA journal_mode"))
            if not is_memory and (type(mode) is not str or mode.lower() != "wal"):
                raise OMSConflict("ACTIVITY_WAL_REQUIRED")
            # This first read pins SQLite's transaction snapshot before returning
            # control to the caller and before any expensive verification begins.
            head = await session.get(OmsLedgerHeadRow, (environment, account_id))
            if head is None:
                high_water = 0
            else:
                if (
                    type(head.sequence_count) is not int
                    or head.sequence_count < 0
                    or head.sequence_count > (1 << 53) - 1
                    or not self._integrity_key().verify(self._head_payload(head), head.anchor)
                ):
                    raise OMSLedgerCorruption()
                self._guard_from_head(head)
                high_water = head.sequence_count
            snapshot = _ActivityReadSnapshot(
                _ACTIVITY_SNAPSHOT_ISSUER,
                self._activity_snapshot_owner,
                session,
                environment,
                account_id,
                high_water,
            )
            self._activity_snapshots[id(snapshot)] = snapshot
            return snapshot
        except BaseException:
            try:
                if session.in_transaction():
                    await session.rollback()
                if query_only_enabled:
                    await session.execute(text("PRAGMA query_only=OFF"))
            finally:
                await session.close()
            raise

    async def _open_activity_worker_snapshot(
        self,
        worker: _ActivityReadWorker,
        environment: str,
        account_id: str,
    ) -> int:
        """Open and pin a file-backed read transaction on its owning thread."""
        engine = create_async_engine(self._engine.url, pool_size=1, max_overflow=0)
        worker.engine = engine
        session = async_sessionmaker(engine, expire_on_commit=False)()
        worker.session = session
        try:
            await session.begin()
            await session.execute(text("PRAGMA query_only=ON"))
            connection = await session.connection()
            await connection.exec_driver_sql("BEGIN")
            mode = await session.scalar(text("PRAGMA journal_mode"))
            if type(mode) is not str or mode.lower() != "wal":
                raise OMSConflict("ACTIVITY_WAL_REQUIRED")
            # This read pins the SQLite WAL snapshot before actor ownership is
            # released. All later page/replay work stays on this worker loop.
            head = await session.get(OmsLedgerHeadRow, (environment, account_id))
            if head is None:
                return 0
            if (
                type(head.sequence_count) is not int
                or head.sequence_count < 0
                or head.sequence_count > (1 << 53) - 1
                or not self._integrity_key().verify(self._head_payload(head), head.anchor)
            ):
                raise OMSLedgerCorruption()
            self._guard_from_head(head)
            return head.sequence_count
        except BaseException:
            await self._close_activity_worker_snapshot(worker)
            raise

    async def _close_activity_worker_snapshot(self, worker: _ActivityReadWorker) -> None:
        session = worker.session
        engine = worker.engine
        try:
            if session is not None:
                if session.in_transaction():
                    await session.rollback()
                with suppress(Exception):
                    await session.execute(text("PRAGMA query_only=OFF"))
                await session.close()
        finally:
            worker.session = None
            if engine is not None:
                await engine.dispose()
                worker.engine = None

    def _require_activity_snapshot(self, snapshot: object) -> _ActivityReadSnapshot:
        if (
            type(snapshot) is not _ActivityReadSnapshot
            or snapshot.owner is not self._activity_snapshot_owner
            or self._activity_snapshots.get(id(snapshot)) is not snapshot
        ):
            raise OMSValidationError("INVALID_ACTIVITY_SNAPSHOT")
        if time.monotonic() >= snapshot.expires_at:
            raise OMSConflict("ACTIVITY_SNAPSHOT_TIMEOUT")
        return snapshot

    async def activity_page_from_snapshot(
        self,
        snapshot: object,
        *,
        after_sequence: int,
        high_water_sequence: int | None,
        limit: int,
    ) -> ActivityLedgerPage:
        token = self._require_activity_snapshot(snapshot)
        if token.worker is not None:
            if token.session is None:
                raise OMSConflict("ACTIVITY_SNAPSHOT_TIMEOUT") from None
            return cast(
                ActivityLedgerPage,
                await token.worker.run(
                    self._account_activity_page_in_session(
                        token.session,
                        token.environment,
                        token.account_id,
                        after_sequence=after_sequence,
                        high_water_sequence=high_water_sequence,
                        limit=limit,
                    )
                ),
            )
        if token.session is None:
            raise OMSConflict("ACTIVITY_SNAPSHOT_TIMEOUT") from None
        return await self._account_activity_page_in_session(
            token.session,
            token.environment,
            token.account_id,
            after_sequence=after_sequence,
            high_water_sequence=high_water_sequence,
            limit=limit,
        )

    async def close_activity_read_snapshot(self, snapshot: object) -> None:
        if (
            type(snapshot) is not _ActivityReadSnapshot
            or snapshot.owner is not self._activity_snapshot_owner
            or self._activity_snapshots.get(id(snapshot)) is not snapshot
        ):
            raise OMSValidationError("INVALID_ACTIVITY_SNAPSHOT")
        token = snapshot
        self._activity_snapshots.pop(id(token), None)
        if token.worker is not None:
            worker = token.worker
            try:
                await worker.run(self._close_activity_worker_snapshot(worker))
            finally:
                await worker.stop()
            return
        if token.session is None:
            return
        try:
            if token.session.in_transaction():
                await token.session.rollback()
            await token.session.execute(text("PRAGMA query_only=OFF"))
        finally:
            await token.session.close()

    async def account_activity_page(
        self,
        environment: str,
        account_id: str,
        *,
        after_sequence: int,
        high_water_sequence: int | None,
        limit: int,
    ) -> ActivityLedgerPage:
        snapshot = await self.begin_activity_read_snapshot(environment, account_id)
        try:
            return await self.activity_page_from_snapshot(
                snapshot,
                after_sequence=after_sequence,
                high_water_sequence=high_water_sequence,
                limit=limit,
            )
        finally:
            await self.close_activity_read_snapshot(snapshot)

    async def _account_activity_page_in_session(
        self,
        session: AsyncSession,
        environment: str,
        account_id: str,
        *,
        after_sequence: int,
        high_water_sequence: int | None,
        limit: int,
    ) -> ActivityLedgerPage:
        self._integrity_key()
        if (
            type(environment) is not str
            or environment not in {"paper", "demo"}
            or type(account_id) is not str
            or not account_id
            or type(after_sequence) is not int
            or after_sequence < 0
            or after_sequence > (1 << 53) - 1
            or type(limit) is not int
            or not 1 <= limit <= 100
            or (
                high_water_sequence is not None
                and (
                    type(high_water_sequence) is not int
                    or high_water_sequence < 0
                    or high_water_sequence > (1 << 53) - 1
                )
            )
        ):
            raise OMSValidationError("INVALID_ACTIVITY_QUERY")
        await self._verify_activity_account_streaming(session, environment, account_id)
        head = await session.get(OmsLedgerHeadRow, (environment, account_id))
        current_high_water = head.sequence_count if head is not None else 0
        captured = current_high_water if high_water_sequence is None else high_water_sequence
        if captured > current_high_water or captured > (1 << 53) - 1:
            raise OMSLedgerCorruption()

        order_rows = (
            await session.execute(
                select(OmsEventRow, OmsOrderRow)
                .join(OmsOrderRow, OmsOrderRow.order_id == OmsEventRow.order_id)
                .where(
                    OmsOrderRow.environment == environment,
                    OmsOrderRow.account_id == account_id,
                    OmsEventRow.sequence == 0,
                    OmsEventRow.code == "ORDER_CREATED",
                    OmsEventRow.ledger_sequence > after_sequence,
                    OmsEventRow.ledger_sequence <= captured,
                )
                .order_by(OmsEventRow.ledger_sequence)
                .limit(limit + 1)
            )
        ).all()
        fill_rows = (
            await session.execute(
                select(OmsFillRow, OmsOrderRow)
                .join(OmsOrderRow, OmsOrderRow.order_id == OmsFillRow.order_id)
                .where(
                    OmsOrderRow.environment == environment,
                    OmsOrderRow.account_id == account_id,
                    OmsFillRow.ledger_sequence > after_sequence,
                    OmsFillRow.ledger_sequence <= captured,
                )
                .order_by(OmsFillRow.ledger_sequence)
                .limit(limit + 1)
            )
        ).all()
        correction_rows = (
            await session.execute(
                select(OmsFillCorrectionRow, OmsOrderRow)
                .join(
                    OmsOrderRow,
                    OmsOrderRow.order_id == OmsFillCorrectionRow.order_id,
                )
                .where(
                    OmsOrderRow.environment == environment,
                    OmsOrderRow.account_id == account_id,
                    OmsFillCorrectionRow.ledger_sequence > after_sequence,
                    OmsFillCorrectionRow.ledger_sequence <= captured,
                )
                .order_by(OmsFillCorrectionRow.ledger_sequence)
                .limit(limit + 1)
            )
        ).all()

        candidates: list[tuple[int, str, Any, OmsOrderRow]] = []
        candidates.extend(
            (event.ledger_sequence, "ORDER", event, order)
            for event, order in order_rows
            if type(event.ledger_sequence) is int
        )
        candidates.extend(
            (fill.ledger_sequence, "FILL", fill, order)
            for fill, order in fill_rows
            if type(fill.ledger_sequence) is int
        )
        candidates.extend(
            (correction.ledger_sequence, "FILL_CORRECTION", correction, order)
            for correction, order in correction_rows
            if type(correction.ledger_sequence) is int
        )
        candidates.sort(key=lambda item: item[0])
        has_more = len(candidates) > limit
        selected = candidates[: limit + 1]
        items: list[Any] = []
        snapshot_by_order: dict[str, OrderSnapshot] = {}
        for sequence, kind, row, order in selected:
            request = OrderRequest.from_payload(order.request)
            if request.digest != order.request_digest:
                raise OMSLedgerCorruption()
            if order.order_id not in snapshot_by_order:
                snapshot_by_order[order.order_id] = await self._activity_order_snapshot(
                    session, order, captured, current_high_water
                )
            if kind == "ORDER":
                items.append(
                    ActivityOrderItem(
                        sequence,
                        snapshot_by_order[order.order_id],
                        self._stored_time(order.created_at),
                    )
                )
            elif kind == "FILL":
                fill = Fill(
                    venue=row.venue,
                    account_id=row.account_id,
                    execution_id=row.execution_id,
                    quantity=parse_oms_decimal(
                        row.quantity, positive=True, code="INVALID_STORED_FILL"
                    ),
                    price=parse_oms_decimal(row.price, positive=True, code="INVALID_STORED_FILL"),
                    commission=parse_oms_decimal(row.commission, code="INVALID_STORED_FILL"),
                    occurred_at=self._stored_time(row.occurred_at),
                )
                items.append(
                    ActivityFillItem(
                        sequence,
                        order.order_id,
                        request.instrument_id,
                        cast(Literal["BUY", "SELL"], request.side),
                        fill,
                    )
                )
            else:
                correction = FillCorrection(
                    venue=row.venue,
                    account_id=row.account_id,
                    execution_id=row.execution_id,
                    correction_id=row.correction_id,
                    revision=row.revision,
                    revised_quantity=parse_oms_decimal(
                        row.revised_quantity, code="INVALID_STORED_CORRECTION"
                    ),
                    revised_price=(
                        parse_oms_decimal(
                            row.revised_price,
                            positive=True,
                            code="INVALID_STORED_CORRECTION",
                        )
                        if row.revised_price is not None
                        else None
                    ),
                    revised_commission=parse_oms_decimal(
                        row.revised_commission, code="INVALID_STORED_CORRECTION"
                    ),
                    occurred_at=self._stored_time(row.occurred_at),
                )
                items.append(
                    ActivityCorrectionItem(
                        sequence,
                        order.order_id,
                        request.instrument_id,
                        cast(Literal["BUY", "SELL"], request.side),
                        correction,
                    )
                )
        summary = await self._activity_net_filled_units(session, environment, account_id, captured)
        return ActivityLedgerPage(captured, tuple(items), has_more, summary)

    async def activity_snapshot_from_snapshot(
        self, snapshot: object, high_water_sequence: int | None
    ) -> ActivityLedgerSnapshot:
        token = self._require_activity_snapshot(snapshot)
        if token.worker is not None:
            if token.session is None:
                raise OMSConflict("ACTIVITY_SNAPSHOT_TIMEOUT") from None
            return cast(
                ActivityLedgerSnapshot,
                await token.worker.run(
                    self._account_activity_snapshot_in_session(
                        token.session,
                        token.environment,
                        token.account_id,
                        high_water_sequence,
                    )
                ),
            )
        if token.session is None:
            raise OMSConflict("ACTIVITY_SNAPSHOT_TIMEOUT") from None
        return await self._account_activity_snapshot_in_session(
            token.session,
            token.environment,
            token.account_id,
            high_water_sequence,
        )

    async def account_activity_snapshot(
        self,
        environment: str,
        account_id: str,
        high_water_sequence: int | None = None,
    ) -> ActivityLedgerSnapshot:
        snapshot = await self.begin_activity_read_snapshot(environment, account_id)
        try:
            return await self.activity_snapshot_from_snapshot(snapshot, high_water_sequence)
        finally:
            await self.close_activity_read_snapshot(snapshot)

    async def _account_activity_snapshot_in_session(
        self,
        session: AsyncSession,
        environment: str,
        account_id: str,
        high_water_sequence: int | None = None,
    ) -> ActivityLedgerSnapshot:
        self._integrity_key()
        if (
            type(environment) is not str
            or environment not in {"paper", "demo"}
            or type(account_id) is not str
            or not account_id
            or (
                high_water_sequence is not None
                and (type(high_water_sequence) is not int or high_water_sequence < 0)
            )
        ):
            raise OMSLedgerCorruption()

        orders, children = await self._account_rows(session, environment, account_id)
        await self._verify_account(session, environment, account_id)
        head = await session.get(OmsLedgerHeadRow, (environment, account_id))
        current_high_water = head.sequence_count if head is not None else 0
        captured = current_high_water if high_water_sequence is None else high_water_sequence
        if captured > current_high_water:
            raise OMSLedgerCorruption()
        if not orders:
            if children or captured != 0:
                raise OMSLedgerCorruption()
            return (0, (), (), ())

        events = [item for item in children if isinstance(item, OmsEventRow)]
        fills = [item for item in children if isinstance(item, OmsFillRow)]
        corrections = [item for item in children if isinstance(item, OmsFillCorrectionRow)]
        event_by_order: dict[str, list[OmsEventRow]] = {}
        for event in events:
            event_by_order.setdefault(event.order_id, []).append(event)
        fill_by_order: dict[str, list[OmsFillRow]] = {}
        for fill in fills:
            fill_by_order.setdefault(fill.order_id, []).append(fill)
        correction_by_order: dict[str, list[OmsFillCorrectionRow]] = {}
        for correction in corrections:
            correction_by_order.setdefault(correction.order_id, []).append(correction)

        order_entries: list[tuple[int, OrderSnapshot, datetime]] = []
        fill_entries: list[tuple[int, str, Fill]] = []
        correction_entries: list[tuple[int, str, FillCorrection]] = []
        for row in orders:
            # Full current replay validates every order before historical state is
            # projected, so malformed future rows cannot hide behind an old cursor.
            current = await self._snapshot_checked(session, row)
            order_events = sorted(
                event_by_order.get(row.order_id, []), key=lambda item: item.sequence
            )
            visible_events = [
                event
                for event in order_events
                if type(event.ledger_sequence) is int and event.ledger_sequence <= captured
            ]
            if not visible_events:
                continue
            first = visible_events[0]
            if first.sequence != 0 or first.code != "ORDER_CREATED":
                raise OMSLedgerCorruption()
            if type(first.ledger_sequence) is not int:
                raise OMSLedgerCorruption()

            discrepancies: tuple[str, ...] = ()
            for event in visible_events:
                evidence = event.evidence
                if "discrepancies" in evidence:
                    discrepancies = self._stored_discrepancies(evidence["discrepancies"])
            visible_fills: dict[str, tuple[int, Fill]] = {}
            for fill_row in fill_by_order.get(row.order_id, []):
                if type(fill_row.ledger_sequence) is not int or fill_row.ledger_sequence > captured:
                    continue
                checked_fill = Fill(
                    venue=fill_row.venue,
                    account_id=fill_row.account_id,
                    execution_id=fill_row.execution_id,
                    quantity=parse_oms_decimal(
                        fill_row.quantity, positive=True, code="INVALID_STORED_FILL"
                    ),
                    price=parse_oms_decimal(
                        fill_row.price, positive=True, code="INVALID_STORED_FILL"
                    ),
                    commission=parse_oms_decimal(fill_row.commission, code="INVALID_STORED_FILL"),
                    occurred_at=self._stored_time(fill_row.occurred_at),
                )
                visible_fills[checked_fill.execution_id] = (
                    fill_row.ledger_sequence,
                    checked_fill,
                )
                fill_entries.append((fill_row.ledger_sequence, row.order_id, checked_fill))

            latest_correction: dict[str, FillCorrection] = {}
            for correction_row in sorted(
                correction_by_order.get(row.order_id, []),
                key=lambda item: item.revision,
            ):
                if (
                    type(correction_row.ledger_sequence) is not int
                    or correction_row.ledger_sequence > captured
                ):
                    continue
                checked_correction = FillCorrection(
                    venue=correction_row.venue,
                    account_id=correction_row.account_id,
                    execution_id=correction_row.execution_id,
                    correction_id=correction_row.correction_id,
                    revision=correction_row.revision,
                    revised_quantity=parse_oms_decimal(
                        correction_row.revised_quantity,
                        code="INVALID_STORED_CORRECTION",
                    ),
                    revised_price=(
                        parse_oms_decimal(
                            correction_row.revised_price,
                            positive=True,
                            code="INVALID_STORED_CORRECTION",
                        )
                        if correction_row.revised_price is not None
                        else None
                    ),
                    revised_commission=parse_oms_decimal(
                        correction_row.revised_commission,
                        code="INVALID_STORED_CORRECTION",
                    ),
                    occurred_at=self._stored_time(correction_row.occurred_at),
                )
                latest_correction[checked_correction.execution_id] = checked_correction
                correction_entries.append(
                    (
                        correction_row.ledger_sequence,
                        row.order_id,
                        checked_correction,
                    )
                )

            filled = exact_sum(
                latest_correction[execution_id].revised_quantity
                if execution_id in latest_correction
                else fill.quantity
                for execution_id, (_sequence, fill) in visible_fills.items()
            )
            last_event = visible_events[-1]
            historic = OrderSnapshot(
                order_id=current.order_id,
                request=current.request,
                state=OrderState(last_event.state),
                version=last_event.sequence,
                venue_order_id=current.venue_order_id,
                filled_quantity=filled,
                discrepancies=discrepancies,
                submit_attempted=current.submit_attempted,
                cancel_attempted=current.cancel_attempted,
            )
            order_entries.append(
                (first.ledger_sequence, historic, self._stored_time(row.created_at))
            )

        return (
            captured,
            tuple(sorted(order_entries, key=lambda item: item[0])),
            tuple(sorted(fill_entries, key=lambda item: item[0])),
            tuple(sorted(correction_entries, key=lambda item: item[0])),
        )

    async def mark_submitting(
        self, order_id: str, evidence: PaperDispatchEvidence
    ) -> OrderSnapshot:
        self._require_actor_when_bound()
        if not isinstance(evidence, PaperDispatchEvidence):
            raise OMSValidationError("DISPATCH_EVIDENCE_REQUIRED")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            current = await self._snapshot(session, row)
            if current.state != OrderState.CREATED or current.submit_attempted:
                raise OMSConflict("SUBMIT_ALREADY_ATTEMPTED")
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            if head is not None and self._guard_from_head(head) is not None:
                raise OMSConflict("ACCOUNT_RECONCILE_REQUIRED")
            await self._audit_all_oms_rows(session)
            request = current.request
            denial = evidence.denial_code(request, order_id)
            if denial is not None:
                await self._advance(
                    session,
                    row,
                    [
                        (OrderState.RISK_PENDING, "RISK_CHECK_STARTED", {}),
                        (OrderState.RISK_REJECTED, denial, {}),
                    ],
                )
                raise OMSValidationError(denial)
            account_orders = (
                await session.scalars(
                    select(OmsOrderRow).where(
                        OmsOrderRow.environment == row.environment,
                        OmsOrderRow.account_id == row.account_id,
                        OmsOrderRow.order_id != order_id,
                    )
                )
            ).all()
            unresolved_states = {
                OrderState.SUBMITTING.value,
                OrderState.DISPATCH_IN_FLIGHT.value,
                OrderState.CANCEL_PENDING.value,
                OrderState.CANCEL_REQUESTED_UNCONFIRMED.value,
                OrderState.UNKNOWN_SUBMIT.value,
                OrderState.UNKNOWN_CANCEL.value,
                OrderState.RECONCILE_REQUIRED.value,
            }
            account_corrupt = False
            for candidate in account_orders:
                try:
                    await self._snapshot(session, candidate)
                except (OMSConflict, OMSValidationError):
                    account_corrupt = True
                    break
            if account_corrupt:
                await self._advance(
                    session,
                    row,
                    [
                        (OrderState.RISK_PENDING, "RISK_CHECK_STARTED", {}),
                        (OrderState.RISK_REJECTED, "ACCOUNT_RECONCILE_REQUIRED", {}),
                    ],
                )
                raise OMSValidationError("ACCOUNT_RECONCILE_REQUIRED")
            if any(candidate.discrepancies for candidate in account_orders):
                await self._advance(
                    session,
                    row,
                    [
                        (OrderState.RISK_PENDING, "RISK_CHECK_STARTED", {}),
                        (OrderState.RISK_REJECTED, "ACCOUNT_RECONCILE_REQUIRED", {}),
                    ],
                )
                raise OMSValidationError("ACCOUNT_RECONCILE_REQUIRED")
            if any(candidate.state in unresolved_states for candidate in account_orders):
                await self._advance(
                    session,
                    row,
                    [
                        (OrderState.RISK_PENDING, "RISK_CHECK_STARTED", {}),
                        (OrderState.RISK_REJECTED, "ACCOUNT_RECONCILIATION_REQUIRED", {}),
                    ],
                )
                raise OMSValidationError("ACCOUNT_RECONCILIATION_REQUIRED")
            await self._advance(
                session,
                row,
                [
                    (OrderState.RISK_PENDING, "RISK_CHECK_STARTED", {}),
                    (OrderState.READY, "FAKE_RISK_READY", evidence.payload()),
                    (
                        OrderState.SUBMITTING,
                        "OUTBOUND_SUBMIT_COMMITTED",
                        {
                            "request_digest": row.request_digest,
                        },
                    ),
                ],
                values={"submit_attempted": True},
            )
            return await self._snapshot(session, row)

    async def mark_submit_result(
        self, order_id: str, state: OrderState, venue_order_id: str | None = None
    ) -> OrderSnapshot:
        self._require_actor_when_bound()
        if not isinstance(state, OrderState) or state not in {
            OrderState.WORKING,
            OrderState.REJECTED,
            OrderState.UNKNOWN_SUBMIT,
        }:
            raise OMSValidationError("INVALID_SUBMIT_RESULT")
        if venue_order_id is not None and (
            not isinstance(venue_order_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", venue_order_id) is None
        ):
            raise OMSValidationError("INVALID_SUBMIT_RESULT")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("SUBMIT_MARKER_REQUIRED")
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            if head is not None and self._guard_from_head(head) is not None:
                raise OMSConflict("DISPATCH_GUARD_REQUIRED")
            if state == OrderState.REJECTED and row.submit_attempted:
                current = await self._snapshot(session, row)
                if current.filled_quantity > 0:
                    discrepancies = list(row.discrepancies)
                    if "REJECT_AFTER_FILL" not in discrepancies:
                        discrepancies.append("REJECT_AFTER_FILL")
                    await self._advance(
                        session,
                        row,
                        [
                            (
                                current.state,
                                "REJECT_AFTER_FILL",
                                {"discrepancies": discrepancies},
                            )
                        ],
                        values={"discrepancies": discrepancies},
                    )
                    raise OMSDiscrepancy("REJECT_AFTER_FILL")
            if row.state != OrderState.SUBMITTING.value:
                raise OMSConflict("SUBMIT_MARKER_REQUIRED")
            if state == OrderState.WORKING and not venue_order_id:
                raise OMSValidationError("VENUE_ORDER_ID_REQUIRED")
            try:
                await self._advance(
                    session,
                    row,
                    [
                        (
                            state,
                            "SUBMIT_UNKNOWN"
                            if state == OrderState.UNKNOWN_SUBMIT
                            else "BROKER_SUBMIT_RESULT",
                            {
                                "venue_order_id": venue_order_id,
                            },
                        )
                    ],
                    values={"venue_order_id": venue_order_id},
                )
            except IntegrityError:
                raise OMSConflict("VENUE_ORDER_ID_CONFLICT") from None
            return await self._snapshot(session, row)

    async def mark_cancel_pending(self, order_id: str) -> OrderSnapshot:
        self._require_actor_when_bound()
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            if row.discrepancies:
                raise OMSConflict("ACCOUNT_RECONCILE_REQUIRED")
            if row.cancel_attempted or row.state not in {
                OrderState.WORKING.value,
                OrderState.PARTIALLY_FILLED.value,
            }:
                raise OMSConflict("CANCEL_NOT_ALLOWED")
            await self._advance(
                session,
                row,
                [(OrderState.CANCEL_PENDING, "OUTBOUND_CANCEL_COMMITTED", {})],
                values={"cancel_attempted": True},
            )
            return await self._snapshot(session, row)

    async def mark_cancel_result(self, order_id: str, state: OrderState) -> OrderSnapshot:
        self._require_actor_when_bound()
        if not isinstance(state, OrderState) or state not in {
            OrderState.CANCELED,
            OrderState.CANCEL_REQUESTED_UNCONFIRMED,
            OrderState.UNKNOWN_CANCEL,
        }:
            raise OMSValidationError("INVALID_CANCEL_RESULT")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None or row.state != OrderState.CANCEL_PENDING.value:
                raise OMSConflict("CANCEL_MARKER_REQUIRED")
            head = await session.get(OmsLedgerHeadRow, (row.environment, row.account_id))
            if head is not None and self._guard_from_head(head) is not None:
                raise OMSConflict("DISPATCH_GUARD_REQUIRED")
            await self._advance(
                session,
                row,
                [
                    (
                        state,
                        "BROKER_CANCEL_CONFIRMED"
                        if state == OrderState.CANCELED
                        else "CANCEL_UNCONFIRMED",
                        {},
                    )
                ],
            )
            return await self._snapshot(session, row)

    async def record_fill(self, order_id: str, fill: Fill) -> OrderSnapshot:
        self._require_actor_when_bound()
        if not isinstance(fill, Fill):
            raise OMSValidationError("INVALID_FILL")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            if fill.venue != row.venue or fill.account_id != row.account_id:
                raise OMSValidationError("FILL_SCOPE_MISMATCH")
            if not row.submit_attempted:
                raise OMSConflict("SUBMIT_MARKER_REQUIRED")
            prior = await session.scalar(
                select(OmsFillRow).where(
                    OmsFillRow.venue == fill.venue,
                    OmsFillRow.account_id == fill.account_id,
                    OmsFillRow.execution_id == fill.execution_id,
                )
            )
            if prior is not None:
                if (
                    prior.order_id != order_id
                    or {
                        "venue": prior.venue,
                        "account_id": prior.account_id,
                        "execution_id": prior.execution_id,
                        "quantity": prior.quantity,
                        "price": prior.price,
                        "commission": prior.commission,
                        "occurred_at": prior.occurred_at.replace(tzinfo=UTC).isoformat(),
                    }
                    != fill.payload()
                ):
                    raise OMSConflict("EXECUTION_ID_CONFLICT")
                return await self._snapshot(session, row)
            request = OrderRequest.from_payload(row.request)
            before = await self._snapshot(session, row)
            try:
                with localcontext() as context:
                    context.prec = 34
                    context.rounding = ROUND_HALF_EVEN
                    context.traps[Inexact] = True
                    total = before.filled_quantity + fill.quantity
            except Inexact:
                raise OMSValidationError("PRECISION_EXCEEDED") from None
            discrepancies = list(row.discrepancies)
            if total > request.quantity and "OVERFILL" not in discrepancies:
                discrepancies.append("OVERFILL")
            with localcontext() as context:
                context.prec = 160
                context.traps[Inexact] = True
                overfill_excess = (
                    str(total - request.quantity) if total > request.quantity else None
                )
            if (
                request.expires_at is not None
                and fill.occurred_at > request.expires_at
                and "FILL_AFTER_GTD" not in discrepancies
            ):
                discrepancies.append("FILL_AFTER_GTD")
            terminal = row.state in {
                OrderState.REJECTED.value,
                OrderState.CANCELED.value,
                OrderState.EXPIRED.value,
                OrderState.FILLED.value,
            }
            if terminal and "FILL_AFTER_TERMINAL" not in discrepancies:
                discrepancies.append("FILL_AFTER_TERMINAL")
            cancel_unconfirmed = row.state in {
                OrderState.CANCEL_PENDING.value,
                OrderState.CANCEL_REQUESTED_UNCONFIRMED.value,
                OrderState.UNKNOWN_CANCEL.value,
            }
            if cancel_unconfirmed and "CANCEL_STATUS_UNCONFIRMED" not in discrepancies:
                discrepancies.append("CANCEL_STATUS_UNCONFIRMED")
            next_state = (
                OrderState(row.state)
                if terminal
                else OrderState.RECONCILE_REQUIRED
                if total > request.quantity or (cancel_unconfirmed and total < request.quantity)
                else OrderState.FILLED
                if total == request.quantity
                else OrderState.PARTIALLY_FILLED
            )
            session.add(
                OmsFillRow(
                    order_id=order_id,
                    venue=fill.venue,
                    account_id=fill.account_id,
                    execution_id=fill.execution_id,
                    quantity=str(fill.quantity),
                    price=str(fill.price),
                    commission=str(fill.commission),
                    occurred_at=fill.occurred_at,
                )
            )
            try:
                await self._advance(
                    session,
                    row,
                    [
                        (
                            next_state,
                            "FILL_AFTER_TERMINAL" if terminal else "BROKER_FILL",
                            {
                                "execution_id": fill.execution_id,
                                "discrepancies": discrepancies,
                                "overfill_excess": overfill_excess,
                            },
                        )
                    ],
                    values={"discrepancies": discrepancies},
                )
            except IntegrityError:
                raise OMSConflict("EXECUTION_ID_CONFLICT") from None
            snapshot = await self._snapshot(session, row)
            if terminal:
                raise OMSDiscrepancy("FILL_AFTER_TERMINAL")
            return snapshot

    async def record_fill_correction(
        self, order_id: str, correction: FillCorrection
    ) -> OrderSnapshot:
        self._require_actor_when_bound()
        if not isinstance(correction, FillCorrection):
            raise OMSValidationError("INVALID_FILL_CORRECTION")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            if correction.venue != row.venue or correction.account_id != row.account_id:
                raise OMSValidationError("FILL_SCOPE_MISMATCH")
            original = await session.scalar(
                select(OmsFillRow).where(
                    OmsFillRow.venue == correction.venue,
                    OmsFillRow.account_id == correction.account_id,
                    OmsFillRow.execution_id == correction.execution_id,
                )
            )
            if original is None or original.order_id != order_id:
                raise OMSConflict("ORIGINAL_EXECUTION_REQUIRED")
            prior = (
                await session.scalars(
                    select(OmsFillCorrectionRow)
                    .where(
                        OmsFillCorrectionRow.venue == correction.venue,
                        OmsFillCorrectionRow.account_id == correction.account_id,
                        OmsFillCorrectionRow.execution_id == correction.execution_id,
                    )
                    .order_by(OmsFillCorrectionRow.revision.desc())
                )
            ).first()
            if prior is not None and correction.revision <= prior.revision:
                existing_revision = await session.scalar(
                    select(OmsFillCorrectionRow).where(
                        OmsFillCorrectionRow.venue == correction.venue,
                        OmsFillCorrectionRow.account_id == correction.account_id,
                        OmsFillCorrectionRow.execution_id == correction.execution_id,
                        OmsFillCorrectionRow.revision == correction.revision,
                    )
                )
                if existing_revision is not None:
                    existing_payload: dict[str, str | int | None] = {
                        "venue": existing_revision.venue,
                        "account_id": existing_revision.account_id,
                        "execution_id": existing_revision.execution_id,
                        "correction_id": existing_revision.correction_id,
                        "revision": existing_revision.revision,
                        "revised_quantity": existing_revision.revised_quantity,
                        "revised_price": existing_revision.revised_price,
                        "revised_commission": existing_revision.revised_commission,
                        "occurred_at": existing_revision.occurred_at.replace(
                            tzinfo=UTC
                        ).isoformat(),
                    }
                    if existing_payload == correction.payload():
                        return await self._snapshot(session, row)
                raise OMSConflict("FILL_CORRECTION_CONFLICT")
            if correction.revision != (prior.revision + 1 if prior is not None else 1):
                raise OMSConflict("FILL_CORRECTION_GAP")
            existing_id = await session.scalar(
                select(OmsFillCorrectionRow.id).where(
                    OmsFillCorrectionRow.venue == correction.venue,
                    OmsFillCorrectionRow.account_id == correction.account_id,
                    OmsFillCorrectionRow.correction_id == correction.correction_id,
                )
            )
            if existing_id is not None:
                raise OMSConflict("FILL_CORRECTION_CONFLICT")
            before = await self._snapshot(session, row)
            previous_quantity = (
                parse_oms_decimal(prior.revised_quantity, code="INVALID_STORED_CORRECTION")
                if prior is not None
                else parse_oms_decimal(original.quantity, positive=True, code="INVALID_STORED_FILL")
            )
            try:
                with localcontext() as context:
                    context.prec = 34
                    context.rounding = ROUND_HALF_EVEN
                    context.traps[Inexact] = True
                    total = before.filled_quantity - previous_quantity + correction.revised_quantity
            except Inexact:
                raise OMSValidationError("PRECISION_EXCEEDED") from None
            discrepancies = list(row.discrepancies)
            if "FILL_CORRECTION" not in discrepancies:
                discrepancies.append("FILL_CORRECTION")
            if total > before.request.quantity and "OVERFILL" not in discrepancies:
                discrepancies.append("OVERFILL")
            with localcontext() as context:
                context.prec = 160
                context.traps[Inexact] = True
                overfill_excess = (
                    str(total - before.request.quantity)
                    if total > before.request.quantity
                    else None
                )
            session.add(
                OmsFillCorrectionRow(
                    order_id=order_id,
                    venue=correction.venue,
                    account_id=correction.account_id,
                    execution_id=correction.execution_id,
                    correction_id=correction.correction_id,
                    revision=correction.revision,
                    revised_quantity=str(correction.revised_quantity),
                    revised_price=(
                        str(correction.revised_price)
                        if correction.revised_price is not None
                        else None
                    ),
                    revised_commission=str(correction.revised_commission),
                    occurred_at=correction.occurred_at,
                )
            )
            try:
                await self._advance(
                    session,
                    row,
                    [
                        (
                            OrderState(row.state)
                            if row.state
                            in {
                                OrderState.REJECTED.value,
                                OrderState.CANCELED.value,
                                OrderState.EXPIRED.value,
                                OrderState.FILLED.value,
                            }
                            else OrderState.RECONCILE_REQUIRED,
                            "BROKER_FILL_CORRECTION",
                            {
                                "execution_id": correction.execution_id,
                                "correction_id": correction.correction_id,
                                "revision": correction.revision,
                                "discrepancies": discrepancies,
                                "overfill_excess": overfill_excess,
                            },
                        )
                    ],
                    values={"discrepancies": discrepancies},
                )
            except IntegrityError:
                raise OMSConflict("FILL_CORRECTION_CONFLICT") from None
            return await self._snapshot(session, row)

    async def record_observation(
        self, order_id: str, observation: BrokerObservation
    ) -> OrderSnapshot:
        self._require_actor_when_bound()
        if not isinstance(observation, BrokerObservation):
            raise OMSValidationError("INVALID_OBSERVATION")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            if (
                observation.environment != row.environment
                or observation.account_id != row.account_id
                or observation.venue != row.venue
                or observation.client_order_id != row.client_order_id
                or (
                    row.venue_order_id is not None
                    and observation.venue_order_id is not None
                    and observation.venue_order_id != row.venue_order_id
                )
            ):
                if row.submit_attempted:
                    discrepancies = list(row.discrepancies)
                    if "BROKER_SCOPE_MISMATCH" not in discrepancies:
                        discrepancies.append("BROKER_SCOPE_MISMATCH")
                    await self._advance(
                        session,
                        row,
                        [
                            (
                                OrderState(row.state),
                                "BROKER_SCOPE_MISMATCH",
                                {"discrepancies": discrepancies},
                            )
                        ],
                        values={"discrepancies": discrepancies},
                    )
                raise OMSValidationError("OBSERVATION_SCOPE_MISMATCH")
            if not row.submit_attempted:
                raise OMSConflict("SUBMIT_MARKER_REQUIRED")
            prior = await session.scalar(
                select(OmsObservationRow).where(
                    OmsObservationRow.venue == observation.venue,
                    OmsObservationRow.account_id == observation.account_id,
                    OmsObservationRow.observation_id == observation.observation_id,
                )
            )
            if prior is not None:
                if prior.order_id != order_id or prior.evidence != observation.payload():
                    raise OMSConflict("OBSERVATION_ID_CONFLICT")
                return await self._snapshot(session, row)
            current = await self._snapshot(session, row)
            observation_rows = (
                await session.scalars(
                    select(OmsObservationRow).where(OmsObservationRow.order_id == order_id)
                )
            ).all()
            latest = max(
                (self._observation_key(existing) for existing in observation_rows),
                default=None,
            )
            target, event_code, discrepancies, venue_order_id = self._reduce_observation(
                observation,
                current.state,
                current.filled_quantity,
                current.request.quantity,
                current.discrepancies,
                latest,
                row.venue_order_id,
            )
            discrepancy_code = (
                event_code
                if event_code
                in {"REJECT_AFTER_FILL", "MISSING_EXECUTIONS", "BROKER_STATE_DIVERGENCE"}
                else None
            )
            session.add(
                OmsObservationRow(
                    order_id=order_id,
                    venue=observation.venue,
                    account_id=observation.account_id,
                    observation_id=observation.observation_id,
                    evidence=observation.payload(),
                    recorded_at=datetime.now(UTC),
                )
            )
            try:
                await self._advance(
                    session,
                    row,
                    [
                        (
                            target,
                            event_code,
                            {
                                "observation_id": observation.observation_id,
                                "discrepancies": discrepancies,
                            },
                        )
                    ],
                    values={
                        "venue_order_id": venue_order_id,
                        "discrepancies": discrepancies,
                    },
                )
            except IntegrityError:
                raise OMSConflict("OBSERVATION_ID_CONFLICT") from None
            snapshot = await self._snapshot(session, row)
            if discrepancy_code is not None:
                raise OMSDiscrepancy(discrepancy_code)
            return snapshot

    async def record_reconcile_pending(self, order_id: str, code: str) -> OrderSnapshot:
        """Audit a failed/empty broker read without inventing broker state."""
        self._require_actor_when_bound()
        if not isinstance(code, str) or code not in {
            "BROKER_READ_UNAVAILABLE",
            "BROKER_EVIDENCE_ABSENT",
            "BROKER_EXECUTION_CONFLICT",
        }:
            raise OMSValidationError("INVALID_RECONCILE_CODE")
        async with self._sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            if row is None:
                raise OMSConflict("ORDER_NOT_FOUND")
            if not row.submit_attempted:
                raise OMSConflict("SUBMIT_MARKER_REQUIRED")
            if code == "BROKER_EXECUTION_CONFLICT":
                discrepancies = list(row.discrepancies)
                if code in discrepancies:
                    return await self._snapshot(session, row)
                discrepancies.append(code)
                current_state = OrderState(row.state)
                target = (
                    current_state
                    if current_state in _TERMINAL_STATES
                    else OrderState.RECONCILE_REQUIRED
                )
                await self._advance(
                    session,
                    row,
                    [(target, code, {"discrepancies": discrepancies})],
                    values={"discrepancies": discrepancies},
                )
            else:
                await self._advance(session, row, [(OrderState(row.state), code, {})])
            return await self._snapshot(session, row)

    async def recover_uncertain(self) -> list[OrderSnapshot]:
        """On restart, in-flight markers become visible UNKNOWN; never re-dispatch."""
        self._require_actor_when_bound()
        recovered: list[OrderSnapshot] = []
        async with self._sessions() as session:
            rows = (
                await session.scalars(
                    select(OmsOrderRow).where(
                        OmsOrderRow.state.in_(
                            [
                                OrderState.SUBMITTING.value,
                                OrderState.CANCEL_PENDING.value,
                                OrderState.DISPATCH_IN_FLIGHT.value,
                            ]
                        )
                    )
                )
            ).all()
            for row in rows:
                self._armed_here.pop(row.order_id, None)
                state = (
                    OrderState.UNKNOWN_SUBMIT
                    if row.state == OrderState.SUBMITTING.value
                    else (
                        OrderState.UNKNOWN_CANCEL
                        if row.state == OrderState.CANCEL_PENDING.value
                        else OrderState.RECONCILE_REQUIRED
                    )
                )
                await self._advance(session, row, [(state, "RECOVERED_UNCERTAIN", {})])
                recovered.append(await self._snapshot(session, row))
        return recovered

    async def events(self, order_id: str) -> list[dict[str, Any]]:
        """Read redacted, ordered audit events for review and tests."""
        async with self._sessions() as session:
            rows = (
                await session.scalars(
                    select(OmsEventRow)
                    .where(OmsEventRow.order_id == order_id)
                    .order_by(OmsEventRow.sequence)
                )
            ).all()
            return [
                {
                    "sequence": row.sequence,
                    "state": row.state,
                    "code": row.code,
                    "evidence": row.evidence,
                }
                for row in rows
            ]


def open_order_gateway_actor(
    sessions: async_sessionmaker[AsyncSession],
    broker: BrokerPortV1,
    reconciliation: BrokerReconciliationPort,
    client_id_key: ClientIdKey,
    *,
    ledger_key: LedgerIntegrityKey,
    operator_key: OperatorAuthorizationKey | None = None,
    dispatch_gate: DispatchGate | None = None,
    allow_in_memory: bool = False,
) -> OrderGatewayActor:
    """Claim the one ledger owner and issue its serialized fake-only actor."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        raise OMSValidationError("OMS_ACTOR_LOOP_REQUIRED") from None
    if type(allow_in_memory) is not bool:
        raise OMSValidationError("OMS_FILE_LEDGER_REQUIRED")
    if type(ledger_key) is not LedgerIntegrityKey:
        raise OMSValidationError("LEDGER_INTEGRITY_KEY_REQUIRED")
    if operator_key is not None and type(operator_key) is not OperatorAuthorizationKey:
        raise OMSValidationError("OPERATOR_AUTHORIZATION_KEY_REQUIRED")
    if not isinstance(sessions, async_sessionmaker):
        raise OMSValidationError("OMS_FILE_LEDGER_REQUIRED")
    engine = sessions.kw.get("bind")
    if not isinstance(engine, AsyncEngine) or engine.url.get_backend_name() != "sqlite":
        raise OMSValidationError("OMS_FILE_LEDGER_REQUIRED")
    database = engine.url.database
    query = engine.url.query
    memory = (
        database in (None, "", ":memory:")
        or (
            isinstance(database, str)
            and (database.lower().startswith("file::memory:") or "mode=memory" in database.lower())
        )
        or query.get("mode") == "memory"
    )
    if memory and not allow_in_memory:
        raise OMSValidationError("OMS_FILE_LEDGER_REQUIRED")
    with _OWNER_CLAIM_LOCK:
        ledger = OrderLedger(sessions, key=ledger_key, operator_key=operator_key)

        def release_owner() -> None:
            with _OWNER_CLAIM_LOCK:
                if ledger.active_dispatch:
                    raise OMSConflict("OMS_LEDGER_BUSY")
                owner = _ACTOR_TASKS.pop(ledger, None)
                try:
                    ledger.close()
                except Exception:
                    if owner is not None:
                        _ACTOR_TASKS[ledger] = owner
                    raise

        try:
            gate = dispatch_gate or _DefaultDispatchGate(test_factory=allow_in_memory)
            actor = _issue_order_gateway_actor(
                ledger,
                broker,
                reconciliation,
                client_id_key,
                operator_key,
                gate,
                release_owner,
            )
        except Exception:
            ledger.close()
            raise
        _ACTOR_TASKS[ledger] = actor._worker  # noqa: SLF001 - sealed factory owns task
    return actor
