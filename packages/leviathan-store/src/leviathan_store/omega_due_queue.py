"""Durable, peer-isolated OMEGA task storage for the synchronous task port."""

from __future__ import annotations

import re
from typing import Any, cast

from sqlalchemy import and_, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.numeric import NumericError, canonical_json
from leviathan_core.omega_link.state_models import HandoffTaskV1
from leviathan_core.omega_link.task_bridge import (
    IDEMPOTENCY_RETENTION_NS,
    MAX_CONTEXT_BYTES,
    MAX_UTC_NS,
    Priority,
    TaskBridgeError,
    TaskCreateDisposition,
    TaskCreateResultV1,
    TaskRecordV1,
    issue_task_create_result,
    require_task_record,
    restore_task_record,
)
from leviathan_store.tables import OmegaTaskRow

_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PRIORITIES = frozenset({"low", "normal", "high", "urgent"})
_PAYLOAD_FIELDS = frozenset(
    {
        "peer_system",
        "task",
        "priority",
        "requires_risk_guard",
        "context_payload_hex",
        "model_route_json",
        "revision",
    }
)
_MAX_DUE_LIMIT = 500
_MAX_PEER_DUE_LIMIT = 501  # API asks for one look-ahead row above its 500 item cap.
_ROW_DOMAIN = b"leviathan.omega.due.store.row.v1\x00"


class OmegaDueQueueStore:
    """Synchronous TaskStorePort + DueQueueStorePort backed by SQLAlchemy.

    The HMAC key must be supplied by the trusted runtime configuration. It is
    held only in memory and is never written to the database or error surface.
    """

    __slots__ = ("_key", "_sessions")

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        key: LedgerIntegrityKey,
    ) -> None:
        if not callable(session_factory) or type(key) is not LedgerIntegrityKey:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        self._sessions = session_factory
        self._key = key
        self._reject_legacy_untagged_rows()

    def _reject_legacy_untagged_rows(self) -> None:
        """Reject persisted rows whose legacy, untagged MAC still verifies."""
        try:
            with self._sessions() as session:
                rows = tuple(session.scalars(select(OmegaTaskRow)))
            for row in rows:
                if type(row.payload) is not dict or type(row.row_hmac) is not str:
                    continue
                tagged_payload = self._signed_row(
                    peer_system=row.peer_system,
                    task_id=row.task_id,
                    state=row.state,
                    expires_at_ns=row.expires_at_ns,
                    sla_due_at_ns=row.sla_due_at_ns,
                    revision=row.revision,
                    payload=row.payload,
                    idempotency_key=row.idempotency_key,
                    request_digest=row.request_digest,
                    idempotency_expires_at_ns=row.idempotency_expires_at_ns,
                )
                if self._key.verify(tagged_payload[len(_ROW_DOMAIN) :], row.row_hmac):
                    raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        except TaskBridgeError:
            raise
        except Exception:
            # Wrong-key and malformed rows fail on the first current-format
            # operation, while a valid legacy row is rejected on reopen.
            return

    def _verify_existing_rows(self) -> None:
        """Reject legacy or corrupted rows before serving an operation."""
        try:
            with self._sessions() as session:
                rows = tuple(
                    session.scalars(
                        select(OmegaTaskRow).order_by(
                            OmegaTaskRow.peer_system, OmegaTaskRow.task_id
                        )
                    )
                )
            for row in rows:
                self._decode_row(row)
        except TaskBridgeError:
            raise
        except Exception:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None

    def create(
        self,
        *,
        peer_system: str,
        record: TaskRecordV1,
        idempotency_key: str,
        request_digest: str,
        idempotency_expires_at_ns: int,
    ) -> TaskCreateResultV1:
        self._verify_existing_rows()
        checked = self._validate_create(
            peer_system,
            record,
            idempotency_key,
            request_digest,
            idempotency_expires_at_ns,
        )
        expires_now = idempotency_expires_at_ns - IDEMPOTENCY_RETENTION_NS
        try:
            with self._sessions.begin() as session:
                prior = session.scalar(
                    select(OmegaTaskRow).where(
                        OmegaTaskRow.peer_system == peer_system,
                        OmegaTaskRow.idempotency_key == idempotency_key,
                    )
                )
                if prior is not None:
                    self._decode_row(prior)
                    if prior.idempotency_expires_at_ns is None:
                        raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
                    if prior.idempotency_expires_at_ns > expires_now:
                        disposition: TaskCreateDisposition = (
                            "duplicate" if prior.request_digest == request_digest else "conflict"
                        )
                        return issue_task_create_result(
                            disposition=disposition,
                            record=self._decode_row(prior),
                        )
                    self._clear_idempotency(prior)

                values = self._row_values(
                    checked,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    idempotency_expires_at_ns=idempotency_expires_at_ns,
                )
                session.add(OmegaTaskRow(**values))
                session.flush()
            return issue_task_create_result(disposition="created", record=checked)
        except TaskBridgeError:
            raise
        except IntegrityError:
            # A concurrent writer may have won the unique idempotency key.
            return self._resolve_create_race(
                peer_system=peer_system,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                expires_now=expires_now,
            )
        except Exception:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None

    def get_task(self, peer_system: str, task_id: str) -> TaskRecordV1 | None:
        self._verify_existing_rows()
        self._validate_identity(peer_system, task_id)
        try:
            with self._sessions() as session:
                row = session.get(OmegaTaskRow, (peer_system, task_id))
                return None if row is None else self._decode_row(row)
        except TaskBridgeError:
            raise
        except Exception:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None

    def replace_task(
        self,
        *,
        peer_system: str,
        task_id: str,
        expected_revision: int,
        record: TaskRecordV1,
    ) -> bool:
        self._verify_existing_rows()
        self._validate_identity(peer_system, task_id)
        if type(expected_revision) is not int or not 1 <= expected_revision < MAX_UTC_NS:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        checked = self._validate_record(peer_system, record)
        if checked.task.task_id != task_id or checked.revision != expected_revision + 1:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        try:
            with self._sessions.begin() as session:
                prior = session.get(OmegaTaskRow, (peer_system, task_id))
                if prior is None:
                    return False
                self._decode_row(prior)
                row_values = self._row_values(
                    checked,
                    idempotency_key=prior.idempotency_key,
                    request_digest=prior.request_digest,
                    idempotency_expires_at_ns=prior.idempotency_expires_at_ns,
                )
                result = cast(
                    CursorResult[Any],
                    session.execute(
                        update(OmegaTaskRow)
                        .where(
                            OmegaTaskRow.peer_system == peer_system,
                            OmegaTaskRow.task_id == task_id,
                            OmegaTaskRow.revision == expected_revision,
                        )
                        .values(**row_values)
                    ),
                )
                return result.rowcount == 1
        except TaskBridgeError:
            raise
        except Exception:
            # A concurrent SQLite writer can win after this transaction read
            # the old row but before its compare-and-swap UPDATE. If the
            # durable revision advanced, treat that as the ordinary stale-CAS
            # result; otherwise preserve the fixed unavailable error.
            try:
                current = self.get_task(peer_system, task_id)
            except TaskBridgeError:
                raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None
            if current is None or current.revision != expected_revision:
                return False
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None

    def list_due(self, *, now_ns: int, limit: int) -> tuple[TaskRecordV1, ...]:
        self._validate_query(now_ns, limit, maximum=_MAX_DUE_LIMIT)
        return self._list_due(now_ns=now_ns, limit=limit, peer_system=None)

    def list_due_for_peer(
        self, *, peer_system: str, now_ns: int, limit: int
    ) -> tuple[TaskRecordV1, ...]:
        if type(peer_system) is not str or _ID.fullmatch(peer_system) is None:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        self._validate_query(now_ns, limit, maximum=_MAX_PEER_DUE_LIMIT)
        return self._list_due(now_ns=now_ns, limit=limit, peer_system=peer_system)

    def _list_due(
        self, *, now_ns: int, limit: int, peer_system: str | None
    ) -> tuple[TaskRecordV1, ...]:
        self._verify_existing_rows()
        pending = and_(OmegaTaskRow.state == "pending", OmegaTaskRow.expires_at_ns <= now_ns)
        active = and_(
            OmegaTaskRow.state == "in_progress",
            or_(
                OmegaTaskRow.expires_at_ns <= now_ns,
                OmegaTaskRow.sla_due_at_ns <= now_ns,
            ),
        )
        statement = select(OmegaTaskRow).where(or_(pending, active))
        if peer_system is not None:
            # Apply peer isolation in SQL before ordering and LIMIT.
            statement = statement.where(OmegaTaskRow.peer_system == peer_system)
        statement = statement.order_by(
            OmegaTaskRow.expires_at_ns,
            OmegaTaskRow.task_id,
            OmegaTaskRow.peer_system,
        ).limit(limit)
        try:
            with self._sessions() as session:
                rows = tuple(session.scalars(statement).all())
            if len(rows) > limit:
                raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
            # Verify the complete bounded page before returning any records.
            records = tuple(self._decode_row(row) for row in rows)
            return records
        except TaskBridgeError:
            raise
        except Exception:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None

    def _resolve_create_race(
        self,
        *,
        peer_system: str,
        idempotency_key: str,
        request_digest: str,
        expires_now: int,
    ) -> TaskCreateResultV1:
        try:
            with self._sessions() as session:
                prior = session.scalar(
                    select(OmegaTaskRow).where(
                        OmegaTaskRow.peer_system == peer_system,
                        OmegaTaskRow.idempotency_key == idempotency_key,
                    )
                )
                if prior is None or prior.idempotency_expires_at_ns is None:
                    raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
                if prior.idempotency_expires_at_ns <= expires_now:
                    raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
                record = self._decode_row(prior)
                disposition: TaskCreateDisposition = (
                    "duplicate" if prior.request_digest == request_digest else "conflict"
                )
                return issue_task_create_result(disposition=disposition, record=record)
        except TaskBridgeError:
            raise
        except Exception:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None

    def _clear_idempotency(self, row: OmegaTaskRow) -> None:
        values = self._row_values(
            self._decode_row(row),
            idempotency_key=None,
            request_digest=None,
            idempotency_expires_at_ns=None,
        )
        # Re-sign the expired row after releasing its idempotency key. Its task
        # remains durable and visible to reads/sweepers.
        for name, value in values.items():
            setattr(row, name, value)

    def _validate_create(
        self,
        peer_system: str,
        record: TaskRecordV1,
        idempotency_key: str,
        request_digest: str,
        idempotency_expires_at_ns: int,
    ) -> TaskRecordV1:
        checked = self._validate_record(peer_system, record)
        if (
            type(idempotency_key) is not str
            or _KEY.fullmatch(idempotency_key) is None
            or type(request_digest) is not str
            or _DIGEST.fullmatch(request_digest) is None
            or type(idempotency_expires_at_ns) is not int
            or not IDEMPOTENCY_RETENTION_NS <= idempotency_expires_at_ns <= MAX_UTC_NS
        ):
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        return checked

    @staticmethod
    def _validate_identity(peer_system: str, task_id: str) -> None:
        if (
            type(peer_system) is not str
            or _ID.fullmatch(peer_system) is None
            or type(task_id) is not str
            or _ID.fullmatch(task_id) is None
        ):
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)

    @staticmethod
    def _validate_query(now_ns: int, limit: int, *, maximum: int) -> None:
        if (
            type(now_ns) is not int
            or not 0 <= now_ns <= MAX_UTC_NS
            or type(limit) is not int
            or not 1 <= limit <= maximum
        ):
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)

    @staticmethod
    def _validate_record(peer_system: str, record: TaskRecordV1) -> TaskRecordV1:
        checked = require_task_record(record)
        if checked.peer_system != peer_system:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        return checked

    def _row_values(
        self,
        record: TaskRecordV1,
        *,
        idempotency_key: str | None,
        request_digest: str | None,
        idempotency_expires_at_ns: int | None,
    ) -> dict[str, Any]:
        task = record.task
        sla_due_at_ns = task.created_at_ns + task.sla_ms * 1_000_000
        payload = {
            "peer_system": record.peer_system,
            "task": task.model_dump(mode="json"),
            "priority": record.priority,
            "requires_risk_guard": record.requires_risk_guard,
            "context_payload_hex": record.context_payload_hex,
            "model_route_json": record.model_route_json,
            "revision": record.revision,
        }
        signed = self._signed_row(
            peer_system=record.peer_system,
            task_id=task.task_id,
            state=task.state,
            expires_at_ns=task.expires_at_ns,
            sla_due_at_ns=sla_due_at_ns,
            revision=record.revision,
            payload=payload,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            idempotency_expires_at_ns=idempotency_expires_at_ns,
        )
        return {
            "peer_system": record.peer_system,
            "task_id": task.task_id,
            "state": task.state,
            "expires_at_ns": task.expires_at_ns,
            "sla_due_at_ns": sla_due_at_ns,
            "revision": record.revision,
            "payload": payload,
            "row_hmac": self._key.sign(signed),
            "idempotency_key": idempotency_key,
            "request_digest": request_digest,
            "idempotency_expires_at_ns": idempotency_expires_at_ns,
        }

    def _decode_row(self, row: OmegaTaskRow) -> TaskRecordV1:
        try:
            payload = row.payload
            if type(payload) is not dict or set(payload) != _PAYLOAD_FIELDS:
                raise ValueError
            if (
                type(row.peer_system) is not str
                or type(row.task_id) is not str
                or type(row.state) is not str
                or type(row.expires_at_ns) is not int
                or type(row.sla_due_at_ns) is not int
                or type(row.revision) is not int
                or type(row.row_hmac) is not str
                or type(row.idempotency_key) not in (str, type(None))
                or type(row.request_digest) not in (str, type(None))
                or type(row.idempotency_expires_at_ns) not in (int, type(None))
            ):
                raise ValueError
            if (
                type(payload["peer_system"]) is not str
                or type(payload["task"]) is not dict
                or type(payload["priority"]) is not str
                or type(payload["requires_risk_guard"]) is not bool
                or type(payload["context_payload_hex"]) not in (str, type(None))
                or type(payload["model_route_json"]) is not str
                or type(payload["revision"]) is not int
                or len(payload["model_route_json"]) > MAX_CONTEXT_BYTES
                or (
                    payload["context_payload_hex"] is not None
                    and len(payload["context_payload_hex"]) > MAX_CONTEXT_BYTES * 2
                )
                or len(canonical_json(payload)) > MAX_CONTEXT_BYTES * 4
            ):
                raise ValueError
            if row.idempotency_key is None:
                if row.request_digest is not None or row.idempotency_expires_at_ns is not None:
                    raise ValueError
            elif (
                _KEY.fullmatch(row.idempotency_key) is None
                or row.request_digest is None
                or _DIGEST.fullmatch(row.request_digest) is None
                or row.idempotency_expires_at_ns is None
                or not IDEMPOTENCY_RETENTION_NS <= row.idempotency_expires_at_ns <= MAX_UTC_NS
            ):
                raise ValueError
            if type(row.row_hmac) is not str or _DIGEST.fullmatch(row.row_hmac) is None:
                raise ValueError
            if not self._key.verify(
                self._signed_row(
                    peer_system=row.peer_system,
                    task_id=row.task_id,
                    state=row.state,
                    expires_at_ns=row.expires_at_ns,
                    sla_due_at_ns=row.sla_due_at_ns,
                    revision=row.revision,
                    payload=payload,
                    idempotency_key=row.idempotency_key,
                    request_digest=row.request_digest,
                    idempotency_expires_at_ns=row.idempotency_expires_at_ns,
                ),
                row.row_hmac,
            ):
                raise ValueError

            if payload["peer_system"] != row.peer_system or payload["revision"] != row.revision:
                raise ValueError
            task_data = payload["task"]
            if task_data.get("task_id") != row.task_id:
                raise ValueError
            task = HandoffTaskV1.model_validate(task_data)
            if (
                task.state != row.state
                or task.expires_at_ns != row.expires_at_ns
                or task.created_at_ns + task.sla_ms * 1_000_000 != row.sla_due_at_ns
            ):
                raise ValueError
            record = restore_task_record(
                peer_system=row.peer_system,
                task=task,
                priority=cast(Priority, payload["priority"]),
                requires_risk_guard=payload["requires_risk_guard"],
                context_payload_hex=payload["context_payload_hex"],
                model_route_json=payload["model_route_json"],
                revision=row.revision,
            )
            if record.task.task_id != row.task_id:
                raise ValueError
            return record
        except Exception:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None

    def _signed_row(
        self,
        *,
        peer_system: str,
        task_id: str,
        state: str,
        expires_at_ns: int,
        sla_due_at_ns: int,
        revision: int,
        payload: dict[str, Any],
        idempotency_key: str | None,
        request_digest: str | None,
        idempotency_expires_at_ns: int | None,
    ) -> bytes:
        try:
            return _ROW_DOMAIN + canonical_json(
                {
                    "peer_system": peer_system,
                    "task_id": task_id,
                    "state": state,
                    "expires_at_ns": expires_at_ns,
                    "sla_due_at_ns": sla_due_at_ns,
                    "revision": revision,
                    "record": payload,
                    "idempotency_key": idempotency_key,
                    "request_digest": request_digest,
                    "idempotency_expires_at_ns": idempotency_expires_at_ns,
                }
            )
        except (NumericError, TypeError, ValueError):
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None


__all__ = ["OmegaDueQueueStore"]
