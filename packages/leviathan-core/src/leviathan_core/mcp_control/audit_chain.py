"""Canonical append-only hash chain for pure MCP-002 control transitions."""

from __future__ import annotations

from hashlib import sha256
from typing import Literal

from leviathan_core.numeric import NumericError, canonical_json
from leviathan_core.seal import SealError

from .state_models import MAX_UTC_NS, AuditEventV1, ControlError, _id

GENESIS_HASH = sha256(b"leviathan.mcp002.audit.genesis.v1").hexdigest()


def _event_bytes(
    *,
    version: Literal["1", "2"],
    sequence: int,
    org_id: str,
    agent_id: str,
    session_id: str | None,
    action_id: str | None,
    kind: str,
    reason_codes: tuple[str, ...],
    recorded_at_ns: int,
    actor_principal_id: str | None = None,
    subject_id: str | None = None,
    dry_run: bool | None = None,
) -> bytes:
    try:
        fields: dict[str, object] = {
            "version": version,
            "sequence": sequence,
            "org_id": org_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "action_id": action_id,
            "kind": kind,
            "reason_codes": reason_codes,
            "recorded_at_ns": recorded_at_ns,
        }
        if version == "2":
            fields["actor_principal_id"] = actor_principal_id
            fields["subject_id"] = subject_id
            if dry_run is True:
                fields["dry_run"] = True
        elif (
            version != "1"
            or actor_principal_id is not None
            or subject_id is not None
            or dry_run is not None
        ):
            raise ControlError("AUDIT_INPUT_INVALID")
        return canonical_json(fields)
    except NumericError:
        raise ControlError("AUDIT_INPUT_INVALID") from None


def _event_hash(predecessor_hash: str, canonical_event_bytes: bytes) -> str:
    return sha256(bytes.fromhex(predecessor_hash) + b"\x00" + canonical_event_bytes).hexdigest()


def append_audit_event(
    events: tuple[AuditEventV1, ...],
    *,
    org_id: str,
    agent_id: str,
    session_id: str | None,
    action_id: str | None,
    kind: str,
    reason_codes: tuple[str, ...],
    recorded_at_ns: int,
    actor_principal_id: str | None = None,
    subject_id: str | None = None,
    dry_run: bool | None = None,
) -> tuple[AuditEventV1, ...]:
    """Return the old prefix plus one event; never mutate an existing entry."""

    if type(events) is not tuple or not verify_audit_chain(events):
        raise ControlError("AUDIT_CHAIN_INVALID")
    return _append_to_verified_prefix(
        events,
        org_id=org_id,
        agent_id=agent_id,
        session_id=session_id,
        action_id=action_id,
        kind=kind,
        reason_codes=reason_codes,
        recorded_at_ns=recorded_at_ns,
        actor_principal_id=actor_principal_id,
        subject_id=subject_id,
        dry_run=dry_run,
    )


def _append_to_verified_prefix(
    events: tuple[AuditEventV1, ...],
    *,
    org_id: str,
    agent_id: str,
    session_id: str | None,
    action_id: str | None,
    kind: str,
    reason_codes: tuple[str, ...],
    recorded_at_ns: int,
    actor_principal_id: str | None = None,
    subject_id: str | None = None,
    dry_run: bool | None = None,
) -> tuple[AuditEventV1, ...]:
    """Private fast path: the issued snapshot has already bound the prefix head."""

    if type(recorded_at_ns) is not int or not 0 <= recorded_at_ns <= MAX_UTC_NS:
        raise ControlError("TIME_INVALID")
    if type(reason_codes) is not tuple or any(type(code) is not str for code in reason_codes):
        raise ControlError("AUDIT_INPUT_INVALID")
    if dry_run is not None and type(dry_run) is not bool:
        raise ControlError("AUDIT_INPUT_INVALID")
    for identifier in (
        org_id,
        agent_id,
        kind,
        session_id,
        action_id,
        actor_principal_id,
        subject_id,
        *reason_codes,
    ):
        if identifier is not None:
            _id(identifier)
    sequence = len(events)
    predecessor = events[-1].event_hash if events else GENESIS_HASH
    version: Literal["1", "2"] = (
        "2"
        if actor_principal_id is not None or subject_id is not None or dry_run is not None
        else "1"
    )
    if version == "2" and (actor_principal_id is None or subject_id is None):
        raise ControlError("AUDIT_INPUT_INVALID")
    body = _event_bytes(
        version=version,
        sequence=sequence,
        org_id=org_id,
        agent_id=agent_id,
        session_id=session_id,
        action_id=action_id,
        kind=kind,
        reason_codes=reason_codes,
        recorded_at_ns=recorded_at_ns,
        actor_principal_id=actor_principal_id,
        subject_id=subject_id,
        dry_run=dry_run,
    )
    event_hash = _event_hash(predecessor, body)
    try:
        event = AuditEventV1(
            version=version,
            event_id=event_hash,
            sequence=sequence,
            org_id=org_id,
            agent_id=agent_id,
            session_id=session_id,
            action_id=action_id,
            kind=kind,
            reason_codes=reason_codes,
            recorded_at_ns=recorded_at_ns,
            predecessor_hash=predecessor,
            event_hash=event_hash,
            actor_principal_id=actor_principal_id,
            subject_id=subject_id,
            dry_run=dry_run,
        )
    except SealError:
        raise ControlError("AUDIT_INPUT_INVALID") from None
    return (*events, event)


def verify_audit_chain(events: tuple[AuditEventV1, ...]) -> bool:
    """Check genesis, canonical event content, order, links and event IDs."""

    if type(events) is not tuple:
        return False
    predecessor = GENESIS_HASH
    try:
        for sequence, event in enumerate(events):
            if type(event) is not AuditEventV1:
                return False
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
            expected = _event_hash(predecessor, body)
            if (
                event.sequence != sequence
                or event.predecessor_hash != predecessor
                or event.event_hash != expected
                or event.event_id != expected
            ):
                return False
            predecessor = expected
    except (ControlError, ValueError, TypeError):
        return False
    return True
