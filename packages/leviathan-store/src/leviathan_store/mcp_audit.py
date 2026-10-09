"""Durable, scope-bound HMAC chain for MCP control audit events.

The caller supplies the integrity key and deployment scope. This module never
creates, loads, or logs key material. Initialize the registered schema before
constructing the store; construction then verifies the complete persisted
chain before accepting appends. Appends authenticate the head and tail, while
``verify_chain`` performs the full walk. SQLite durability requires
journal_mode=DELETE (or MEMORY for an in-memory database), synchronous=FULL,
and SQLAlchemy engine logging at WARNING or above in production (the store
rejects DEBUG and INFO unless parameters are hidden). The SQLite driver must
allow explicit BEGIN and BEGIN IMMEDIATE statements;
construction rejects incompatible begin hooks. An HMAC head stored in the
same database cannot detect rollback to an earlier authentic copy or deletion
of both rows and head; that requires a future mount-supplied authenticated
external anchor.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.mcp_control.audit_chain import (
    GENESIS_HASH,
    _event_bytes,
    _event_hash,
    verify_audit_chain,
)
from leviathan_core.mcp_control.state_models import AuditEventV1
from leviathan_core.numeric import NumericError, canonical_json
from leviathan_store.tables import McpAuditHeadRow, McpAuditRow

_PROJECT_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z", re.ASCII)
_STORE_ID = "mcp-audit-v1"
_GENESIS_DOMAIN = b"leviathan.mcp.audit.store.genesis.v1\x00"
_ROW_DOMAIN = b"leviathan.mcp.audit.store.row.v1\x00"
_HEAD_DOMAIN = b"leviathan.mcp.audit.store.head.v1\x00"


class McpAuditStoreError(RuntimeError):
    """Fixed, content-free failure raised by the durable MCP audit store."""

    code: Literal["AUDIT_STORE_UNAVAILABLE"] = "AUDIT_STORE_UNAVAILABLE"

    def __init__(self) -> None:
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class McpAuditScopeV1:
    """Trusted deployment identity bound into every durable chain row."""

    project_id: str
    environment: Literal["PAPER", "DEMO", "LIVE"]

    def __post_init__(self) -> None:
        if (
            type(self.project_id) is not str
            or _PROJECT_ID.fullmatch(self.project_id) is None
            or type(self.environment) is not str
            or self.environment not in {"PAPER", "DEMO", "LIVE"}
        ):
            raise McpAuditStoreError()


class McpAuditStore:
    """Synchronous ``McpAuditPort`` backed by an append-only SQLite chain."""

    __slots__ = ("_key", "_scope", "_sessions")

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        key: LedgerIntegrityKey,
        scope: McpAuditScopeV1,
    ) -> None:
        if (
            not callable(session_factory)
            or type(key) is not LedgerIntegrityKey
            or type(scope) is not McpAuditScopeV1
        ):
            raise McpAuditStoreError()
        bind = getattr(session_factory, "kw", {}).get("bind")
        if getattr(getattr(bind, "dialect", None), "name", None) != "sqlite":
            raise McpAuditStoreError()
        self._validate_logging(bind)
        self._sessions = session_factory
        self._key = key
        self._scope = scope
        self._probe_begin_immediate(bind)
        self._validate_durability_pragmas(bind)
        self._verify_or_initialize()

    def append(self, event: AuditEventV1) -> None:
        """Persist one event and acknowledge only after its transaction commits.

        Replaying the same already-committed event is idempotent. A changed
        event, sequence gap, corrupt tail, or storage failure fails closed.
        """

        self.append_batch((event,))

    def append_batch(self, events: tuple[AuditEventV1, ...]) -> None:
        """Atomically append an event tuple, accepting identical persisted prefixes.

        Every row and the authenticated checkpoint update share one database
        transaction. A failed batch therefore leaves both chain data and head
        unchanged, and may be retried with the same event identifiers.
        """

        if type(events) is not tuple or any(type(event) is not AuditEventV1 for event in events):
            raise McpAuditStoreError()
        if not events:
            return
        try:
            with self._sessions.begin() as session:
                # Acquire the SQLite write reservation before reading the
                # checkpoint so concurrent writers serialize without a
                # deferred-transaction upgrade race.
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
                self._validate_session_runtime(session)
                head = session.get(McpAuditHeadRow, _STORE_ID)
                if head is None or not self._valid_head(head):
                    raise McpAuditStoreError()
                previous_event_hash = GENESIS_HASH
                if head.sequence_count:
                    tail = session.get(McpAuditRow, head.sequence_count - 1)
                    if (
                        tail is None
                        or not self._valid_row(tail)
                        or tail.sequence != head.sequence_count - 1
                        or tail.row_mac != head.chain_tip
                    ):
                        raise McpAuditStoreError()
                    tail_event = _decode_event(tail.event_json)
                    if (
                        tail.event_id != tail_event.event_id
                        or tail_event.sequence != tail.sequence
                        or not self._valid_event(tail_event, tail_event.predecessor_hash)
                    ):
                        raise McpAuditStoreError()
                    previous_event_hash = tail_event.event_hash
                elif head.chain_tip != self._genesis_mac():
                    raise McpAuditStoreError()
                next_sequence = head.sequence_count
                previous_mac = head.chain_tip
                pending_rows: list[McpAuditRow] = []
                seen_ids: dict[str, str] = {}
                last_input_sequence: int | None = None
                last_input_hash: str | None = None

                for event in events:
                    if last_input_sequence is not None and (
                        event.sequence != last_input_sequence + 1
                        or event.predecessor_hash != last_input_hash
                    ):
                        raise McpAuditStoreError()
                    event_json = _event_json(event)
                    prior_json = seen_ids.get(event.event_id)
                    if prior_json is not None:
                        if prior_json != event_json:
                            raise McpAuditStoreError()
                    else:
                        seen_ids[event.event_id] = event_json

                    existing = session.scalar(
                        select(McpAuditRow).where(McpAuditRow.event_id == event.event_id)
                    )
                    if existing is not None:
                        if (
                            not self._valid_row(existing)
                            or existing.sequence != event.sequence
                            or existing.event_json != event_json
                            or existing.event_id != event.event_id
                            or not self._valid_event(event, event.predecessor_hash)
                        ):
                            raise McpAuditStoreError()
                        # Already-persisted identical prefix is a no-op.
                        if event.sequence >= next_sequence:
                            raise McpAuditStoreError()
                        existing_at_sequence = session.get(McpAuditRow, event.sequence)
                        if (
                            existing_at_sequence is None
                            or existing_at_sequence.event_id != event.event_id
                        ):
                            raise McpAuditStoreError()
                        last_input_sequence = event.sequence
                        last_input_hash = event.event_hash
                        continue

                    if (
                        event.sequence != next_sequence
                        or event.event_id != event.event_hash
                        or not self._valid_event(event, previous_event_hash)
                    ):
                        raise McpAuditStoreError()

                    row_mac = self._row_mac(
                        sequence=event.sequence,
                        event_id=event.event_id,
                        event_json=event_json,
                        previous_mac=previous_mac,
                    )
                    pending_rows.append(
                        McpAuditRow(
                            sequence=event.sequence,
                            event_id=event.event_id,
                            event_json=event_json,
                            scope_project_id=self._scope.project_id,
                            scope_environment=self._scope.environment,
                            previous_mac=previous_mac,
                            row_mac=row_mac,
                        )
                    )
                    previous_mac = row_mac
                    previous_event_hash = event.event_hash
                    next_sequence += 1
                    last_input_sequence = event.sequence
                    last_input_hash = event.event_hash

                if pending_rows:
                    session.add_all(pending_rows)
                    head.sequence_count = next_sequence
                    head.chain_tip = previous_mac
                    head.checkpoint_mac = self._head_mac(next_sequence, previous_mac)
                    session.flush()
        except McpAuditStoreError:
            raise
        except Exception:
            raise McpAuditStoreError() from None

    def verify_chain(self) -> None:
        """Perform a full authenticated chain walk for explicit audit checks."""

        try:
            with self._sessions() as session:
                # SQLite's pysqlite legacy mode does not implicitly start a
                # database transaction for SELECT. Begin explicitly so the
                # head and row scan share one read snapshot.
                session.connection().exec_driver_sql("BEGIN")
                self._validate_session_runtime(session)
                head = session.get(McpAuditHeadRow, _STORE_ID)
                if head is None or not self._valid_head(head):
                    raise McpAuditStoreError()
                rows = tuple(session.scalars(select(McpAuditRow).order_by(McpAuditRow.sequence)))
                self._verify_rows(rows, head)
        except McpAuditStoreError:
            raise
        except Exception:
            raise McpAuditStoreError() from None

    def _validate_durability_pragmas(self, bind: object) -> None:
        try:
            with bind.connect() as connection:  # type: ignore[attr-defined]
                journal_mode = str(connection.exec_driver_sql("PRAGMA journal_mode").scalar())
                synchronous = connection.exec_driver_sql("PRAGMA synchronous").scalar()
                database_path = connection.exec_driver_sql("PRAGMA database_list").all()[0][2]
            expected_mode = "delete" if database_path else "memory"
            if journal_mode.lower() != expected_mode or synchronous != 2:
                raise McpAuditStoreError()
        except McpAuditStoreError:
            raise
        except Exception:
            raise McpAuditStoreError() from None

    @staticmethod
    def _validate_logging(bind: object) -> None:
        logger = getattr(bind, "logger", None)
        if (
            getattr(bind, "echo", False)
            or logger is None
            or logger.isEnabledFor(logging.DEBUG)
            or (logger.isEnabledFor(logging.INFO) and not getattr(bind, "hide_parameters", False))
        ):
            raise McpAuditStoreError()

    def _validate_session_runtime(self, session: Session) -> None:
        bind = session.get_bind()
        self._validate_logging(bind)
        try:
            synchronous = session.connection().exec_driver_sql("PRAGMA synchronous").scalar()
            if synchronous != 2:
                raise McpAuditStoreError()
        except McpAuditStoreError:
            raise
        except Exception:
            raise McpAuditStoreError() from None

    @staticmethod
    def _probe_begin_immediate(bind: object) -> None:
        """Reject SQLite engines whose begin hooks conflict with writer locking."""

        try:
            with bind.connect() as connection:  # type: ignore[attr-defined]
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                connection.rollback()
        except Exception:
            raise McpAuditStoreError() from None

    @staticmethod
    def _valid_event(event: AuditEventV1, predecessor_hash: str) -> bool:
        try:
            body = _event_bytes(
                version=event.version,
                sequence=event.sequence,
                org_id=event.org_id,
                agent_id=event.agent_id,
                session_id=event.session_id,
                action_id=event.action_id,
                kind=event.kind,
                reason_codes=event.reason_codes,
                recorded_at_ns=event.recorded_at_ns,
                actor_principal_id=event.actor_principal_id,
                subject_id=event.subject_id,
                dry_run=event.dry_run,
            )
            expected_hash = _event_hash(predecessor_hash, body)
            return (
                event.predecessor_hash == predecessor_hash
                and event.event_hash == expected_hash
                and event.event_id == expected_hash
            )
        except Exception:
            return False

    def _verify_or_initialize(self) -> None:
        try:
            with self._sessions.begin() as session:
                # Keep the head and row walk in one SQLite read snapshot. In
                # pysqlite legacy mode SELECT alone does not begin a database
                # transaction, even though SQLAlchemy has autobegun one.
                session.connection().exec_driver_sql("BEGIN")
                self._validate_session_runtime(session)
                heads = tuple(session.scalars(select(McpAuditHeadRow)))
                if not heads:
                    if session.scalar(select(McpAuditRow.sequence).limit(1)) is not None:
                        raise McpAuditStoreError()
                    genesis = self._genesis_mac()
                    session.add(
                        McpAuditHeadRow(
                            store_id=_STORE_ID,
                            scope_project_id=self._scope.project_id,
                            scope_environment=self._scope.environment,
                            sequence_count=0,
                            chain_tip=genesis,
                            checkpoint_mac=self._head_mac(0, genesis),
                        )
                    )
                    session.flush()
                    return
                if len(heads) != 1 or not self._valid_head(heads[0]):
                    raise McpAuditStoreError()
                head = heads[0]
                rows = tuple(session.scalars(select(McpAuditRow).order_by(McpAuditRow.sequence)))
                self._verify_rows(rows, head)
        except McpAuditStoreError:
            raise
        except Exception:
            raise McpAuditStoreError() from None

    def _verify_rows(
        self, rows: tuple[McpAuditRow, ...], head: McpAuditHeadRow
    ) -> tuple[AuditEventV1, ...]:
        previous_mac = self._genesis_mac()
        events: list[AuditEventV1] = []
        for expected_sequence, row in enumerate(rows):
            if (
                row.sequence != expected_sequence
                or row.previous_mac != previous_mac
                or not self._valid_row(row)
            ):
                raise McpAuditStoreError()
            event = _decode_event(row.event_json)
            if event.sequence != expected_sequence or event.event_id != row.event_id:
                raise McpAuditStoreError()
            events.append(event)
            previous_mac = row.row_mac
        if (
            head.sequence_count != len(rows)
            or head.chain_tip != previous_mac
            or not verify_audit_chain(tuple(events))
        ):
            raise McpAuditStoreError()
        return tuple(events)

    def _valid_head(self, head: McpAuditHeadRow) -> bool:
        return (
            head.store_id == _STORE_ID
            and head.scope_project_id == self._scope.project_id
            and head.scope_environment == self._scope.environment
            and type(head.sequence_count) is int
            and head.sequence_count >= 0
            and type(head.chain_tip) is str
            and self._key.verify(
                self._head_payload(head.sequence_count, head.chain_tip),
                head.checkpoint_mac,
            )
        )

    def _valid_row(self, row: McpAuditRow) -> bool:
        return (
            row.scope_project_id == self._scope.project_id
            and row.scope_environment == self._scope.environment
            and type(row.sequence) is int
            and row.sequence >= 0
            and type(row.event_id) is str
            and type(row.event_json) is str
            and type(row.previous_mac) is str
            and type(row.row_mac) is str
            and self._key.verify(
                self._row_payload(
                    sequence=row.sequence,
                    event_id=row.event_id,
                    event_json=row.event_json,
                    previous_mac=row.previous_mac,
                ),
                row.row_mac,
            )
        )

    def _genesis_mac(self) -> str:
        return self._key.sign(_GENESIS_DOMAIN + self._scope_bytes())

    def _head_mac(self, sequence_count: int, chain_tip: str) -> str:
        return self._key.sign(self._head_payload(sequence_count, chain_tip))

    def _head_payload(self, sequence_count: int, chain_tip: str) -> bytes:
        return _HEAD_DOMAIN + canonical_json(
            {
                "scope": {
                    "project_id": self._scope.project_id,
                    "environment": self._scope.environment,
                },
                "sequence_count": sequence_count,
                "chain_tip": chain_tip,
            }
        )

    def _row_mac(self, *, sequence: int, event_id: str, event_json: str, previous_mac: str) -> str:
        return self._key.sign(
            self._row_payload(
                sequence=sequence,
                event_id=event_id,
                event_json=event_json,
                previous_mac=previous_mac,
            )
        )

    def _row_payload(
        self, *, sequence: int, event_id: str, event_json: str, previous_mac: str
    ) -> bytes:
        return _ROW_DOMAIN + canonical_json(
            {
                "scope": {
                    "project_id": self._scope.project_id,
                    "environment": self._scope.environment,
                },
                "sequence": sequence,
                "event_id": event_id,
                "event_json": event_json,
                "previous_mac": previous_mac,
            }
        )

    def _scope_bytes(self) -> bytes:
        return canonical_json(
            {"project_id": self._scope.project_id, "environment": self._scope.environment}
        )


def _event_json(event: AuditEventV1) -> str:
    try:
        return canonical_json(event.model_dump(mode="json", warnings=False)).decode("ascii")
    except (NumericError, UnicodeError, TypeError, ValueError):
        raise McpAuditStoreError() from None


def _decode_event(value: str) -> AuditEventV1:
    try:
        decoded = json.loads(value)
        if type(decoded) is not dict:
            raise McpAuditStoreError()
        reason_codes = decoded.get("reason_codes")
        if type(reason_codes) is not list:
            raise McpAuditStoreError()
        decoded["reason_codes"] = tuple(reason_codes)
        event = AuditEventV1(**decoded)
        if type(event) is not AuditEventV1 or _event_json(event) != value:
            raise McpAuditStoreError()
        return event
    except McpAuditStoreError:
        raise
    except Exception:
        raise McpAuditStoreError() from None
