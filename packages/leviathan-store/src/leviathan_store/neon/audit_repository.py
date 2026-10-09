"""Append-only fake-Neon audit journal with a checked hash chain."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, require
from leviathan_core.security import (
    ActionV1,
    AuthorizationContextV1,
    AuthorizationPolicyV1,
    ResourceV1,
    TrustedPrincipalV1,
    authorize,
)

from .audit_models import (
    AuditActionV1,
    AuditChainVerificationV1,
    AuditDecisionV1,
    AuditDiffFieldV1,
    AuditDiffV1,
    AuditEntryV1,
    AuditEventV1,
    AuditPageV1,
    AuditReasonCodeV1,
)

_ENTRY_ISSUER = Issuer("sec005.audit_entry.v1")
_ENTRY_TAG = _ENTRY_ISSUER.tag
_VERIFICATION_ISSUER = Issuer("sec005.audit_verification.v1")
_VERIFICATION_TAG = _VERIFICATION_ISSUER.tag
_SCOPE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_ZERO_HASH = "0" * 64
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
MAX_AUDIT_PAYLOAD_BYTES = 16_384
MAX_PAGE_ENTRIES = 500
_ERROR_CODES = frozenset(
    {
        "ORG_NOT_FOUND",
        "ORG_CONFLICT",
        "INVALID_IDENTITY",
        "INVALID_PRINCIPAL",
        "PRINCIPAL_SCOPE_MISMATCH",
        "INVALID_EVENT",
        "INVALID_FAILPOINT",
        "INVALID_CLOCK",
        "INVALID_CURSOR",
        "INVALID_LIMIT",
        "INVALID_POLICY",
        "AUDIT_APPEND_DENIED",
        "PAYLOAD_TOO_LARGE",
        "CLOCK_REGRESSION",
        "READ_NOT_AUTHORIZED",
        "FAKE_TRANSACTION_ABORTED",
        "CHAIN_INVALID",
    }
)


class AuditPersistenceError(ValueError):
    """Content-free and allowlisted audit repository failure."""

    def __init__(self, code: str) -> None:
        if code not in _ERROR_CODES:
            code = "CHAIN_INVALID"
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _AuditRow:
    payload: bytes


@dataclass(frozen=True, slots=True)
class _Checkpoint:
    sequence: int
    chain_tip: str


class _FakeNeonAuditState:
    """Private shared fake state; passing it to another repository simulates reopen."""

    __slots__ = ("checkpoints", "entry_hash_indices", "entry_ids", "lock", "org_projects", "rows")

    def __init__(self) -> None:
        self.lock = RLock()
        self.org_projects: dict[str, str] = {}
        self.rows: dict[str, list[_AuditRow]] = {}
        self.checkpoints: dict[str, _Checkpoint] = {}
        self.entry_ids: dict[str, set[str]] = {}
        self.entry_hash_indices: dict[str, dict[str, int]] = {}


def _scope(value: object) -> str | None:
    return value if type(value) is str and _SCOPE_ID.fullmatch(value) else None


def _utc_ns(value: object) -> int | None:
    if type(value) is not datetime or value.tzinfo is not UTC:
        return None
    delta = value - _EPOCH
    if delta.days < 0:
        return None
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def _event_payload(entry: AuditEntryV1) -> dict[str, Any]:
    return {
        "schema_version": entry.schema_version,
        "entry_id": entry.entry_id,
        "org_id": entry.org_id,
        "env": entry.env,
        "sequence": entry.sequence,
        "recorded_at": entry.recorded_at.isoformat(),
        "recorded_at_ns": entry.recorded_at_ns,
        "actor_ref": entry.actor_ref,
        "actor_project_id": entry.actor_project_id,
        "actor_roles": entry.actor_roles,
        "action": entry.action.value,
        "decision": entry.decision.value,
        "reason_code": entry.reason_code.value,
        "target_ref": entry.target_ref,
        "diff": tuple(
            {
                "field": item.field.value,
                "before_sha256": item.before_sha256,
                "after_sha256": item.after_sha256,
            }
            for item in entry.diff
        ),
        "correlation_id": entry.correlation_id,
        "trace_id": entry.trace_id,
        "previous_hash": entry.previous_hash,
    }


def _entry_hash(entry: AuditEntryV1) -> str:
    return hashlib.sha256(canonical_json(_event_payload(entry))).hexdigest()


def _event_input(value: object) -> AuditEventV1 | None:
    checked: AuditEventV1 | None = None
    invalid = False
    try:
        if type(value) is not AuditEventV1:
            invalid = True
        else:
            checked = AuditEventV1.model_validate(value.model_dump(mode="python", warnings=False))
    except Exception:
        invalid = True
    return None if invalid else checked


class NeonAuditRepositoryV1:
    """Pure fake-Neon repository; no SQL, network, credentials, or durability claim."""

    backend = "FAKE_NEON"

    def __init__(
        self,
        *,
        clock: Callable[[], datetime],
        policy: AuthorizationPolicyV1 | None = None,
        _state: _FakeNeonAuditState | None = None,
    ) -> None:
        if (
            not callable(clock)
            or (policy is not None and type(policy) is not AuthorizationPolicyV1)
            or (_state is not None and type(_state) is not _FakeNeonAuditState)
        ):
            raise AuditPersistenceError(
                "INVALID_CLOCK" if not callable(clock) else "INVALID_POLICY"
            )
        self._clock = clock
        self._policy = policy
        self._state = _state if _state is not None else _FakeNeonAuditState()
        self._lock = self._state.lock

    def register_org(self, org_id: str, project_id: str) -> None:
        org, project = _scope(org_id), _scope(project_id)
        if org is None or project is None:
            raise AuditPersistenceError("INVALID_IDENTITY")
        with self._lock:
            previous = self._state.org_projects.get(org)
            if previous is not None and previous != project:
                raise AuditPersistenceError("ORG_CONFLICT")
            self._state.org_projects[org] = project
            self._state.rows.setdefault(org, [])
            self._state.checkpoints.setdefault(org, _Checkpoint(0, _ZERO_HASH))
            self._state.entry_ids.setdefault(org, set())
            self._state.entry_hash_indices.setdefault(org, {})

    def append(
        self,
        org_id: str,
        principal: TrustedPrincipalV1,
        event: AuditEventV1,
        *,
        fail_before_commit: bool = False,
    ) -> AuditEntryV1:
        org = _scope(org_id)
        if org is None:
            raise AuditPersistenceError("AUDIT_APPEND_DENIED")

        with self._lock:
            now = self._read_clock()
            if now is None or not self._authorization_allowed(
                org, principal, "audit:append", now
            ):
                raise AuditPersistenceError("AUDIT_APPEND_DENIED")
            project = self._state.org_projects.get(org)
            if project is None:
                raise AuditPersistenceError("AUDIT_APPEND_DENIED")
            if type(principal) is not TrustedPrincipalV1:
                raise AuditPersistenceError("INVALID_PRINCIPAL")
            principal_project = _scope(principal.project_id)
            env = _scope(principal.env)
            principal_id = _scope(principal.principal_id)
            roles = principal.roles
            if (
                principal_project is None
                or env is None
                or principal_id is None
                or type(roles) is not tuple
            ):
                raise AuditPersistenceError("INVALID_PRINCIPAL")
            if project != principal_project:
                raise AuditPersistenceError("AUDIT_APPEND_DENIED")
            if type(fail_before_commit) is not bool:
                raise AuditPersistenceError("INVALID_FAILPOINT")
            checked_event = _event_input(event)
            if checked_event is None:
                raise AuditPersistenceError("INVALID_EVENT")
            timestamp_ns = _utc_ns(now)
            if timestamp_ns is None:
                raise AuditPersistenceError("INVALID_CLOCK")
            rows = self._state.rows[org]
            checkpoint = self._state.checkpoints[org]
            entry_ids = self._state.entry_ids[org]
            hash_indices = self._state.entry_hash_indices[org]
            tail_valid, tail = self._valid_tail(
                org, rows, checkpoint, entry_ids, hash_indices
            )
            if not tail_valid:
                raise AuditPersistenceError("CHAIN_INVALID")
            if tail is not None and timestamp_ns < tail.recorded_at_ns:
                raise AuditPersistenceError("CLOCK_REGRESSION")
            entry_id = uuid.uuid4().hex
            if entry_id in entry_ids:
                raise AuditPersistenceError("CHAIN_INVALID")
            sequence = checkpoint.sequence + 1
            entry = AuditEntryV1(
                entry_id=entry_id,
                org_id=org,
                env=env,
                sequence=sequence,
                recorded_at=now,
                recorded_at_ns=timestamp_ns,
                actor_ref="sha256:" + hashlib.sha256(principal_id.encode("utf-8")).hexdigest(),
                actor_project_id=principal_project,
                actor_roles=roles,
                action=checked_event.action,
                decision=checked_event.decision,
                reason_code=checked_event.reason_code,
                target_ref=checked_event.target_ref,
                diff=checked_event.diff,
                correlation_id=checked_event.correlation_id,
                trace_id=checked_event.trace_id,
                previous_hash=checkpoint.chain_tip,
                entry_hash=_ZERO_HASH,
            )
            entry_values = _event_payload(entry)
            entry_values.update(
                recorded_at=now,
                action=entry.action,
                decision=entry.decision,
                reason_code=entry.reason_code,
                diff=entry.diff,
                entry_hash=_entry_hash(entry),
            )
            entry = AuditEntryV1(**entry_values)
            issued = _ENTRY_ISSUER.issue(entry)
            payload = canonical_json({**_event_payload(issued), "entry_hash": issued.entry_hash})
            if len(payload) > MAX_AUDIT_PAYLOAD_BYTES:
                raise AuditPersistenceError("PAYLOAD_TOO_LARGE")
            if fail_before_commit:
                raise AuditPersistenceError("FAKE_TRANSACTION_ABORTED")
            rows.append(_AuditRow(payload=payload))
            self._state.checkpoints[org] = _Checkpoint(sequence, issued.entry_hash)
            entry_ids.add(issued.entry_id)
            hash_indices[issued.entry_hash] = sequence - 1
            return issued

    def verify_chain(
        self,
        org_id: str,
        principal: TrustedPrincipalV1,
    ) -> AuditChainVerificationV1:
        org = _scope(org_id)
        if org is None:
            raise AuditPersistenceError("INVALID_IDENTITY")
        if type(principal) is not TrustedPrincipalV1:
            raise AuditPersistenceError("READ_NOT_AUTHORIZED")
        with self._lock:
            project = self._state.org_projects.get(org)
            if project is None or project != principal.project_id:
                raise AuditPersistenceError("READ_NOT_AUTHORIZED")
            if not self._can_read(org, principal):
                raise AuditPersistenceError("READ_NOT_AUTHORIZED")
            rows = self._state.rows.get(org)
            checkpoint = self._state.checkpoints.get(org)
            if org not in self._state.org_projects or rows is None or checkpoint is None:
                raise AuditPersistenceError("READ_NOT_AUTHORIZED")
            valid, checked, tip = self._valid_chain(
                org,
                rows,
                checkpoint,
                self._state.entry_ids.get(org, set()),
                self._state.entry_hash_indices.get(org, {}),
            )
            return _VERIFICATION_ISSUER.issue(
                AuditChainVerificationV1(
                    org_id=org,
                    valid=valid,
                    entries_checked=checked,
                    chain_tip=tip,
                    failure_code=None if valid else "CHAIN_INVALID",
                )
            )

    def read_page(
        self,
        org_id: str,
        principal: TrustedPrincipalV1,
        *,
        cursor: str | None = None,
        limit: int = 100,
    ) -> AuditPageV1:
        org = _scope(org_id)
        if org is None:
            raise AuditPersistenceError("INVALID_IDENTITY")
        if not self._can_read(org, principal):
            raise AuditPersistenceError("READ_NOT_AUTHORIZED")
        if type(limit) is not int or not 1 <= limit <= MAX_PAGE_ENTRIES:
            raise AuditPersistenceError("INVALID_LIMIT")
        if cursor is not None and (
            type(cursor) is not str or re.fullmatch(r"[0-9a-f]{64}", cursor) is None
        ):
            raise AuditPersistenceError("INVALID_CURSOR")
        with self._lock:
            rows = self._state.rows.get(org)
            checkpoint = self._state.checkpoints.get(org)
            if (
                self._state.org_projects.get(org) != principal.project_id
                or rows is None
                or checkpoint is None
            ):
                raise AuditPersistenceError("READ_NOT_AUTHORIZED")
            entry_ids = self._state.entry_ids.get(org, set())
            hash_indices = self._state.entry_hash_indices.get(org, {})
            if not self._indexed_tip_valid(rows, checkpoint, entry_ids, hash_indices):
                raise AuditPersistenceError("CHAIN_INVALID")
            start = 0
            if cursor is not None:
                cursor_index = hash_indices.get(cursor)
                if cursor_index is None:
                    raise AuditPersistenceError("INVALID_CURSOR")
                start = cursor_index + 1
            stop = min(start + limit, len(rows))
            previous_hash = cursor if cursor is not None else _ZERO_HASH
            page_entries: list[AuditEntryV1] = []
            try:
                for index in range(start, stop):
                    entry = self._decode_row(rows[index])
                    if (
                        entry.org_id != org
                        or entry.sequence != index + 1
                        or entry.previous_hash != previous_hash
                        or _utc_ns(entry.recorded_at) != entry.recorded_at_ns
                        or _entry_hash(entry) != entry.entry_hash
                        or hash_indices.get(entry.entry_hash) != index
                        or entry.entry_id not in entry_ids
                    ):
                        raise AuditPersistenceError("CHAIN_INVALID")
                    page_entries.append(entry)
                    previous_hash = entry.entry_hash
            except AuditPersistenceError:
                raise
            except Exception:
                raise AuditPersistenceError("CHAIN_INVALID") from None
            issued_entries = tuple(_ENTRY_ISSUER.issue(entry) for entry in page_entries)
            more = stop < len(rows)
            next_cursor = issued_entries[-1].entry_hash if more and issued_entries else None
            page = AuditPageV1(
                org_id=org,
                entries=issued_entries,
                next_cursor=next_cursor,
                chain_tip=checkpoint.chain_tip,
            )
            return page

    def _read_clock(self) -> datetime | None:
        try:
            value = self._clock()
            return value if _utc_ns(value) is not None else None
        except Exception:
            return None

    def _can_read(self, org: str, principal: TrustedPrincipalV1) -> bool:
        if type(principal) is not TrustedPrincipalV1:
            return False
        at = self._read_clock()
        if at is None:
            return False
        return self._authorization_allowed(org, principal, "audit:read", at)

    def _authorization_allowed(
        self,
        org: str,
        principal: TrustedPrincipalV1,
        action: str,
        at: datetime,
    ) -> bool:
        if type(principal) is not TrustedPrincipalV1:
            return False
        policy = self._policy
        if policy is None or type(policy) is not AuthorizationPolicyV1:
            return False
        authorized = False
        try:
            context = AuthorizationContextV1(
                project_id=principal.project_id,
                env=principal.env,
                at=at,
                venue=principal.venue,
                portfolio=principal.portfolio,
                strategy=principal.strategy,
            )
            resource = ResourceV1(
                resource_id=f"audit-journal:{org}",
                project_id=principal.project_id,
                env=principal.env,
                venue=principal.venue,
                portfolio=principal.portfolio,
                strategy=principal.strategy,
            )
            authorized = authorize(
                principal,
                ActionV1(action),
                resource,
                context,
                policy,
            ).allowed
        except Exception:
            authorized = False
        return authorized

    def _valid_tail(
        self,
        org: str,
        rows: list[_AuditRow],
        checkpoint: _Checkpoint,
        entry_ids: set[str],
        hash_indices: dict[str, int],
    ) -> tuple[bool, AuditEntryV1 | None]:
        """Validate only the chain tip and its immediate predecessor in O(1)."""
        if (
            checkpoint.sequence != len(rows)
            or checkpoint.sequence != len(entry_ids)
            or checkpoint.sequence != len(hash_indices)
        ):
            return False, None
        if checkpoint.sequence == 0:
            valid_empty = (
                checkpoint.chain_tip == _ZERO_HASH
                and not rows
                and not entry_ids
                and not hash_indices
            )
            return valid_empty, None
        try:
            tail = self._decode_row(rows[-1])
            if (
                tail.org_id != org
                or tail.sequence != checkpoint.sequence
                or tail.entry_hash != checkpoint.chain_tip
                or _utc_ns(tail.recorded_at) != tail.recorded_at_ns
                or _entry_hash(tail) != tail.entry_hash
                or tail.entry_id not in entry_ids
                or hash_indices.get(tail.entry_hash) != checkpoint.sequence - 1
            ):
                return False, None
            if checkpoint.sequence == 1:
                return tail.previous_hash == _ZERO_HASH, tail
            previous = self._decode_row(rows[-2])
            valid = (
                previous.org_id == org
                and previous.sequence == checkpoint.sequence - 1
                and previous.entry_hash == tail.previous_hash
                and _utc_ns(previous.recorded_at) == previous.recorded_at_ns
                and _entry_hash(previous) == previous.entry_hash
                and previous.entry_id in entry_ids
                and hash_indices.get(previous.entry_hash) == checkpoint.sequence - 2
                and tail.recorded_at_ns >= previous.recorded_at_ns
            )
            return valid, tail
        except Exception:
            return False, None

    @staticmethod
    def _indexed_tip_valid(
        rows: list[_AuditRow],
        checkpoint: _Checkpoint,
        entry_ids: set[str],
        hash_indices: dict[str, int],
    ) -> bool:
        """Check the fake store's O(1) indexes and checkpoint without decoding rows."""
        if (
            checkpoint.sequence != len(rows)
            or checkpoint.sequence != len(entry_ids)
            or checkpoint.sequence != len(hash_indices)
        ):
            return False
        if checkpoint.sequence == 0:
            return checkpoint.chain_tip == _ZERO_HASH and not rows
        return hash_indices.get(checkpoint.chain_tip) == checkpoint.sequence - 1

    def _decode_row(self, row: _AuditRow) -> AuditEntryV1:
        raw = json.loads(row.payload)
        if type(raw) is not dict:
            raise ValueError("invalid stored audit row")
        raw["recorded_at"] = datetime.fromisoformat(raw["recorded_at"])
        raw["action"] = AuditActionV1(raw["action"])
        raw["decision"] = AuditDecisionV1(raw["decision"])
        raw["reason_code"] = AuditReasonCodeV1(raw["reason_code"])
        raw["actor_roles"] = tuple(raw["actor_roles"])
        raw["diff"] = tuple(
            AuditDiffV1(
                field=AuditDiffFieldV1(item["field"]),
                before_sha256=item["before_sha256"],
                after_sha256=item["after_sha256"],
            )
            for item in raw["diff"]
        )
        entry = AuditEntryV1(**raw)
        if canonical_json({**_event_payload(entry), "entry_hash": entry.entry_hash}) != row.payload:
            raise ValueError("noncanonical audit row")
        return entry

    def _valid_chain(
        self,
        org: str,
        rows: list[_AuditRow],
        checkpoint: _Checkpoint,
        expected_ids: set[str],
        expected_hash_indices: dict[str, int],
    ) -> tuple[bool, int, str]:
        previous = _ZERO_HASH
        checked = 0
        entry_ids: set[str] = set()
        hash_indices: dict[str, int] = {}
        previous_timestamp_ns = 0
        try:
            for expected_sequence, row in enumerate(rows, start=1):
                entry = self._decode_row(row)
                if (
                    entry.org_id != org
                    or entry.sequence != expected_sequence
                    or entry.previous_hash != previous
                    or entry.entry_id in entry_ids
                    or _utc_ns(entry.recorded_at) != entry.recorded_at_ns
                    or entry.recorded_at_ns < previous_timestamp_ns
                    or _entry_hash(entry) != entry.entry_hash
                ):
                    return False, checked, previous
                entry_ids.add(entry.entry_id)
                hash_indices[entry.entry_hash] = expected_sequence - 1
                previous = entry.entry_hash
                previous_timestamp_ns = entry.recorded_at_ns
                checked += 1
        except Exception:
            return False, checked, previous
        if checkpoint.sequence != checked or checkpoint.chain_tip != previous:
            return False, checked, previous
        if entry_ids != expected_ids or hash_indices != expected_hash_indices:
            return False, checked, previous
        return True, checked, previous


def require_audit_entry(entry: AuditEntryV1) -> AuditEntryV1:
    """Require the exact immutable entry issued by this repository boundary."""
    return require(entry, _ENTRY_TAG)


__all__ = [
    "MAX_AUDIT_PAYLOAD_BYTES",
    "MAX_PAGE_ENTRIES",
    "AuditPersistenceError",
    "NeonAuditRepositoryV1",
    "require_audit_entry",
]
