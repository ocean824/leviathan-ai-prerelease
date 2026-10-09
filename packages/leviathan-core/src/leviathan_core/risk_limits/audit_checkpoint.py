"""Signed checkpoints and typed verification for the global risk-audit chain.

Checkpoints are caller-held signed values. They do not replace append-time
integrity checks or a scheduled genesis-anchored full-chain replay.
"""

from __future__ import annotations

import hashlib
import re
from typing import NoReturn, cast

from pydantic import BaseModel, ConfigDict, Field

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.numeric import NumericError, canonical_json
from leviathan_core.risk_limits.audit_port import (
    RISK_AUDIT_GENESIS_HASH,
    RiskAuditEventV1,
    require_risk_audit_event,
    risk_audit_event_hash,
)
from leviathan_core.seal import SealedModel

MAX_CHECKPOINT_SUFFIX_ROWS = 256
_KEY_ID_DOMAIN = b"leviathan/risk-audit-checkpoint/key-id/v1"
_CHECKPOINT_PURPOSE = "leviathan.risk-audit-checkpoint.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z", re.ASCII)
_CHECKPOINT_SCHEMA = 1


class RiskAuditCheckpointError(ValueError):
    """Content-free failure for invalid checkpoint input or verification."""

    __slots__ = ("code",)

    def __init__(self) -> None:
        self.code = "CHECKPOINT_INVALID"
        super().__init__(self.code)

    def __str__(self) -> str:
        return self.code


class RiskAuditScopeV1(SealedModel):
    """Requested projection scope; it is not itself evidence of a chain."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, revalidate_instances="always"
    )

    environment: str = Field(min_length=1, max_length=128)
    account_id: str = Field(min_length=1, max_length=128)


class RiskAuditHeadV1(SealedModel):
    """A caller-supplied exact global chain head."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, revalidate_instances="always"
    )

    sequence: int = Field(ge=0)
    head_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class RiskAuditCheckpointV1(SealedModel):
    """Untrusted, serializable checkpoint authenticated by its signature."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, revalidate_instances="always"
    )

    schema_version: int = Field(ge=1)
    environment: str = Field(min_length=1, max_length=128)
    account_id: str = Field(min_length=1, max_length=128)
    sequence: int = Field(ge=0)
    head_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    key_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


class _RiskAuditSuffixCandidate(BaseModel):
    """Unissued cryptographic result; persistence validation is still required."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    scope: RiskAuditScopeV1
    checkpoint_sequence: int = Field(ge=0)
    supplied_head: RiskAuditHeadV1
    events: tuple[RiskAuditEventV1, ...]


def _fail() -> NoReturn:
    raise RiskAuditCheckpointError


def _require_scope(scope: object) -> RiskAuditScopeV1:
    if type(scope) is not RiskAuditScopeV1:
        _fail()
    try:
        RiskAuditScopeV1.model_validate(scope.model_dump(mode="python"))
    except (TypeError, ValueError):
        _fail()
    if (
        _IDENTIFIER.fullmatch(scope.environment) is None
        or _IDENTIFIER.fullmatch(scope.account_id) is None
    ):
        _fail()
    return scope


def _require_head(head: object) -> RiskAuditHeadV1:
    if type(head) is not RiskAuditHeadV1:
        _fail()
    try:
        RiskAuditHeadV1.model_validate(head.model_dump(mode="python"))
    except (TypeError, ValueError):
        _fail()
    if type(head.sequence) is not int or not 0 <= head.sequence <= 2**53 - 1:
        _fail()
    if _SHA256.fullmatch(head.head_hash) is None:
        _fail()
    if head.sequence == 0 and head.head_hash != RISK_AUDIT_GENESIS_HASH:
        _fail()
    return head


def _key_id(key: object) -> str:
    if type(key) is not LedgerIntegrityKey:
        _fail()
    try:
        proof = key.sign(_KEY_ID_DOMAIN)
        if type(proof) is not str or re.fullmatch(r"[0-9a-f]{64}", proof, re.ASCII) is None:
            _fail()
        return hashlib.sha256(proof.encode("ascii")).hexdigest()
    except RiskAuditCheckpointError:
        raise
    except Exception:
        _fail()


def _checkpoint_payload(
    *,
    schema_version: int,
    environment: str,
    account_id: str,
    sequence: int,
    head_hash: str,
    key_id: str,
) -> bytes:
    try:
        return canonical_json(
            {
                "purpose": _CHECKPOINT_PURPOSE,
                "schema_version": schema_version,
                "environment": environment,
                "account_id": account_id,
                "sequence": sequence,
                "head_hash": head_hash,
                "key_id": key_id,
            }
        )
    except (NumericError, TypeError, ValueError):
        _fail()


def _verify_prefix(rows: object) -> tuple[int, str]:
    if type(rows) is not tuple:
        _fail()
    rows = cast(tuple[RiskAuditEventV1, ...], rows)
    previous = RISK_AUDIT_GENESIS_HASH
    expected_sequence = 1
    for row in rows:
        if type(row) is not RiskAuditEventV1:
            _fail()
        try:
            require_risk_audit_event(row)
            if row.sequence != expected_sequence or row.predecessor_hash != previous:
                _fail()
            digest = risk_audit_event_hash(row, previous)
            if row.event_hash != digest or row.event_id != digest:
                _fail()
        except RiskAuditCheckpointError:
            raise
        except Exception:
            _fail()
        previous = digest
        expected_sequence += 1
    return expected_sequence - 1, previous


def create_risk_audit_checkpoint(
    rows_through_seq: tuple[RiskAuditEventV1, ...],
    *,
    key: LedgerIntegrityKey,
    scope: RiskAuditScopeV1,
) -> RiskAuditCheckpointV1:
    """Sign a checkpoint at the final row of a verified global genesis prefix.

    An empty tuple creates a checkpoint at the canonical genesis head.
    """
    if type(key) is not LedgerIntegrityKey:
        _fail()
    checked_scope = _require_scope(scope)
    sequence, head_hash = _verify_prefix(rows_through_seq)
    key_id = _key_id(key)
    payload = _checkpoint_payload(
        schema_version=_CHECKPOINT_SCHEMA,
        environment=checked_scope.environment,
        account_id=checked_scope.account_id,
        sequence=sequence,
        head_hash=head_hash,
        key_id=key_id,
    )
    try:
        signature = key.sign(payload)
        return RiskAuditCheckpointV1(
            schema_version=_CHECKPOINT_SCHEMA,
            environment=checked_scope.environment,
            account_id=checked_scope.account_id,
            sequence=sequence,
            head_hash=head_hash,
            key_id=key_id,
            signature=signature,
        )
    except Exception:
        _fail()


def authenticate_risk_audit_checkpoint(
    checkpoint: RiskAuditCheckpointV1,
    *,
    key: LedgerIntegrityKey,
    scope: RiskAuditScopeV1,
) -> None:
    """Authenticate signed claims without reading persisted chain state."""
    if type(checkpoint) is not RiskAuditCheckpointV1:
        _fail()
    checked_scope = _require_scope(scope)
    key_id = _key_id(key)
    try:
        RiskAuditCheckpointV1.model_validate(checkpoint.model_dump(mode="python"))
    except (TypeError, ValueError):
        _fail()
    if (
        checkpoint.schema_version != _CHECKPOINT_SCHEMA
        or checkpoint.environment != checked_scope.environment
        or checkpoint.account_id != checked_scope.account_id
        or checkpoint.key_id != key_id
    ):
        _fail()
    payload = _checkpoint_payload(
        schema_version=checkpoint.schema_version,
        environment=checkpoint.environment,
        account_id=checkpoint.account_id,
        sequence=checkpoint.sequence,
        head_hash=checkpoint.head_hash,
        key_id=checkpoint.key_id,
    )
    try:
        if not key.verify(payload, checkpoint.signature):
            _fail()
    except RiskAuditCheckpointError:
        raise
    except Exception:
        _fail()
    if checkpoint.sequence > 2**53 - 1:
        _fail()


def verify_suffix_from_checkpoint(
    checkpoint: RiskAuditCheckpointV1,
    suffix_rows: tuple[RiskAuditEventV1, ...],
    *,
    supplied_head: RiskAuditHeadV1,
    key: LedgerIntegrityKey,
    scope: RiskAuditScopeV1,
) -> _RiskAuditSuffixCandidate:
    """Verify a caller-supplied suffix, but do not issue persisted evidence.

    Only the store can turn this candidate into a verified result after it has
    checked the checkpoint anchor and requested head against persisted rows.
    """
    authenticate_risk_audit_checkpoint(checkpoint, key=key, scope=scope)
    checked_scope = _require_scope(scope)
    checked_head = _require_head(supplied_head)
    if checkpoint.sequence > checked_head.sequence:
        _fail()
    if type(suffix_rows) is not tuple:
        _fail()
    if len(suffix_rows) > MAX_CHECKPOINT_SUFFIX_ROWS:
        _fail()
    previous = checkpoint.head_hash
    next_sequence = checkpoint.sequence + 1
    verified: list[RiskAuditEventV1] = []
    for event in suffix_rows:
        if type(event) is not RiskAuditEventV1:
            _fail()
        try:
            require_risk_audit_event(event)
            if event.sequence != next_sequence or event.predecessor_hash != previous:
                _fail()
            digest = risk_audit_event_hash(event, previous)
            if event.event_hash != digest or event.event_id != digest:
                _fail()
        except RiskAuditCheckpointError:
            raise
        except Exception:
            _fail()
        verified.append(event)
        previous = digest
        next_sequence += 1
    final_sequence = next_sequence - 1
    if final_sequence != checked_head.sequence or previous != checked_head.head_hash:
        _fail()
    scoped = tuple(
        event
        for event in verified
        if event.environment == checked_scope.environment
        and event.account_id == checked_scope.account_id
    )
    try:
        return _RiskAuditSuffixCandidate(
            scope=checked_scope,
            checkpoint_sequence=checkpoint.sequence,
            supplied_head=checked_head,
            events=scoped,
        )
    except Exception:
        _fail()


__all__ = [
    "MAX_CHECKPOINT_SUFFIX_ROWS",
    "RiskAuditCheckpointError",
    "RiskAuditCheckpointV1",
    "RiskAuditHeadV1",
    "RiskAuditScopeV1",
    "authenticate_risk_audit_checkpoint",
    "create_risk_audit_checkpoint",
    "verify_suffix_from_checkpoint",
]
