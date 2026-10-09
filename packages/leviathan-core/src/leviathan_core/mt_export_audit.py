"""Offline, append-only audit records for MT export proposals.

The kernel stores only canonical digests of parameter maps. It has no storage,
terminal, bridge, network, or secret-resolution behavior.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import InitVar, dataclass, field
from enum import StrEnum
from typing import NoReturn, SupportsIndex

from leviathan_core.mt_export_bridge_artifacts import MtPlatformV1
from leviathan_core.mt_export_bridge_build_view import BuildStatusV1
from leviathan_core.numeric import NumericError, canonical_json
from leviathan_core.seal import Issuer, SealError, require
from leviathan_core.text.safe_label import is_safe_identifier

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z", re.ASCII)
_PARAMETER_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z", re.ASCII)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_GENESIS_HASH = "0" * 64
_MAX_UTC_NS = 253_402_300_799_999_999_999
_MAX_TARGETS = 64
_FACTORY_KEY = object()
_RECORD_ISSUER = Issuer("mtbr.audit.record.v1")
_CHAIN_ISSUER = Issuer("mtbr.audit.chain.v1")


class AuditActionV1(StrEnum):
    """Closed set of proposal actions covered by this audit slice."""

    CODEGEN = "CODEGEN"
    BUILD = "BUILD"
    DEPLOY = "DEPLOY"
    ROLLBACK = "ROLLBACK"


_PARAMETER_SCHEMAS: dict[AuditActionV1, dict[str, str]] = {
    AuditActionV1.CODEGEN: {
        "template_id": "id",
        "template_version": "id",
        "platform": "platform",
        "parameter_mapping_digest": "digest",
    },
    AuditActionV1.BUILD: {
        "export_job_id": "id",
        "platform": "platform",
        "artifact_sha256": "digest",
        "build_status": "build_status",
    },
    AuditActionV1.DEPLOY: {
        "target_id": "id",
        "artifact_id": "id",
        "mode": "deployment_mode",
        "plan_digest": "digest",
    },
    AuditActionV1.ROLLBACK: {
        "target_id": "id",
        "current_artifact_id": "id",
        "prior_artifact_id": "id",
        "forward_deployment_id": "id",
        "plan_digest": "digest",
    },
}


_AUDIT_ERROR_CODES = frozenset(
    {
        "INVALID_AUDIT_FIELD",
        "INVALID_ACTION",
        "INVALID_TIME",
        "INVALID_PARAMS_MAP",
        "SECRET_FIELD",
        "CHAIN_ORDER",
        "CHAIN_INVALID",
        "UNISSUED_RECORD",
        "UNISSUED_CHAIN",
    }
)


class AuditError(ValueError):
    """Content-free audit validation failure with a stable code."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in _AUDIT_ERROR_CODES else "CHAIN_INVALID"
        super().__init__(self.code)

    def __str__(self) -> str:
        return self.code


class _NoCopyOrPickle:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __deepcopy__(self, _memo: object) -> NoReturn:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __reduce__(self) -> NoReturn:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise SealError("SEAL_FORBIDDEN_OPERATION")


def _identifier(value: object) -> bool:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        return False
    # These closed audit namespaces identify MT platform versions and wave releases.
    # Normalize only those trusted tokens so the shared helper still rejects arbitrary
    # letter-then-digit identifiers such as `hunter2`.
    normalized = re.sub(r"(?<![A-Za-z0-9])(?:mt[45]|wave[0-9]+)(?![A-Za-z0-9])", "wave", value)
    return is_safe_identifier(normalized)


def _digest(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _valid_parameter_value(kind: str, value: object) -> bool:
    if type(value) is not str:
        return False
    if kind == "id":
        return _PARAMETER_ID_RE.fullmatch(value) is not None
    if kind == "digest":
        return _SHA256_RE.fullmatch(value) is not None
    if kind == "platform":
        return value in {item.value for item in MtPlatformV1}
    if kind == "build_status":
        return value in {item.value for item in BuildStatusV1}
    if kind == "deployment_mode":
        return value in {"PAPER", "DEMO", "LIVE"}
    return False


def _params_digest(action: AuditActionV1, value: object) -> str:
    schema = _PARAMETER_SCHEMAS[action]
    if type(value) is not dict or len(value) != len(schema):
        raise AuditError("INVALID_PARAMS_MAP")
    if any(type(key) is not str or key not in schema for key in value):
        raise AuditError("INVALID_PARAMS_MAP")
    if any(not _valid_parameter_value(schema[key], item) for key, item in value.items()):
        raise AuditError("INVALID_PARAMS_MAP")
    if any(key not in value for key in schema):
        raise AuditError("INVALID_PARAMS_MAP")
    normalized = dict(value)
    try:
        encoded = canonical_json(
            {"domain": "mtbr.audit.params-map.v1", "action": action.value, "params": normalized}
        )
    except (NumericError, TypeError, ValueError):
        raise AuditError("INVALID_PARAMS_MAP") from None
    return hashlib.sha256(encoded).hexdigest()


def _validate_fields(
    *,
    sequence: object,
    actor_ref: object,
    action: object,
    occurred_ns: object,
    target_ids: object,
    correlation_id: object,
    artifact_id: object,
    before_params_digest: object,
    after_params_digest: object,
    previous_hash: object,
    record_hash: object,
) -> None:
    if type(sequence) is not int or sequence < 0:
        raise AuditError("INVALID_AUDIT_FIELD")
    if (
        not _identifier(actor_ref)
        or not _identifier(correlation_id)
        or not _identifier(artifact_id)
    ):
        raise AuditError("INVALID_AUDIT_FIELD")
    if type(action) is not AuditActionV1:
        raise AuditError("INVALID_ACTION")
    if type(occurred_ns) is not int or not 0 <= occurred_ns <= _MAX_UTC_NS:
        raise AuditError("INVALID_TIME")
    if (
        type(target_ids) is not tuple
        or not 1 <= len(target_ids) <= _MAX_TARGETS
        or any(not _identifier(item) for item in target_ids)
        or target_ids != tuple(sorted(set(target_ids)))
    ):
        raise AuditError("INVALID_AUDIT_FIELD")
    if not all(_digest(item) for item in (before_params_digest, after_params_digest)):
        raise AuditError("INVALID_PARAMS_MAP")
    if not _digest(previous_hash) or not _digest(record_hash):
        raise AuditError("CHAIN_INVALID")


def _record_payload(
    *,
    sequence: int,
    actor_ref: str,
    action: AuditActionV1,
    occurred_ns: int,
    target_ids: tuple[str, ...],
    correlation_id: str,
    artifact_id: str,
    before_params_digest: str,
    after_params_digest: str,
    previous_hash: str,
) -> dict[str, object]:
    return {
        "schema": "mtbr.audit.record.v1",
        "sequence": sequence,
        "actor_ref": actor_ref,
        "action": action.value,
        "occurred_ns": occurred_ns,
        "target_ids": target_ids,
        "correlation_id": correlation_id,
        "artifact_id": artifact_id,
        "before_params_digest": before_params_digest,
        "after_params_digest": after_params_digest,
        "previous_hash": previous_hash,
    }


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class AuditRecordV1(_NoCopyOrPickle):
    """One sealed audit event containing identifiers and digests only."""

    sequence: int
    actor_ref: str
    action: AuditActionV1
    occurred_ns: int
    target_ids: tuple[str, ...]
    correlation_id: str
    artifact_id: str
    before_params_digest: str
    after_params_digest: str
    previous_hash: str
    record_hash: str
    _factory_key: InitVar[object] = field(default=None, kw_only=True, repr=False, compare=False)

    def __init__(
        self,
        *,
        sequence: int,
        actor_ref: str,
        action: AuditActionV1,
        occurred_ns: int,
        target_ids: tuple[str, ...],
        correlation_id: str,
        artifact_id: str,
        before_params_digest: str,
        after_params_digest: str,
        previous_hash: str,
        record_hash: str,
        _factory_key: object = None,
    ) -> None:
        try:
            require(self, _RECORD_ISSUER.tag)
        except SealError as exc:
            if exc.code != "SEAL_NOT_ISSUED":
                raise
        else:
            raise SealError("SEAL_FORBIDDEN_OPERATION")
        if _factory_key is not _FACTORY_KEY:
            raise AuditError("UNISSUED_RECORD")
        for name, value in (
            ("sequence", sequence),
            ("actor_ref", actor_ref),
            ("action", action),
            ("occurred_ns", occurred_ns),
            ("target_ids", target_ids),
            ("correlation_id", correlation_id),
            ("artifact_id", artifact_id),
            ("before_params_digest", before_params_digest),
            ("after_params_digest", after_params_digest),
            ("previous_hash", previous_hash),
            ("record_hash", record_hash),
        ):
            object.__setattr__(self, name, value)
        self.__post_init__(_factory_key)

    def __post_init__(self, _factory_key: object) -> None:
        if _factory_key is not _FACTORY_KEY:
            raise AuditError("UNISSUED_RECORD")
        _validate_fields(
            sequence=self.sequence,
            actor_ref=self.actor_ref,
            action=self.action,
            occurred_ns=self.occurred_ns,
            target_ids=self.target_ids,
            correlation_id=self.correlation_id,
            artifact_id=self.artifact_id,
            before_params_digest=self.before_params_digest,
            after_params_digest=self.after_params_digest,
            previous_hash=self.previous_hash,
            record_hash=self.record_hash,
        )

    def canonical_bytes(self) -> bytes:
        require_audit_record(self)
        payload = _record_payload(
            sequence=self.sequence,
            actor_ref=self.actor_ref,
            action=self.action,
            occurred_ns=self.occurred_ns,
            target_ids=self.target_ids,
            correlation_id=self.correlation_id,
            artifact_id=self.artifact_id,
            before_params_digest=self.before_params_digest,
            after_params_digest=self.after_params_digest,
            previous_hash=self.previous_hash,
        )
        payload["record_hash"] = self.record_hash
        return canonical_json(payload)


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class AuditChainV1(_NoCopyOrPickle):
    """Sealed immutable view of the append-only audit sequence."""

    records: tuple[AuditRecordV1, ...]
    head_hash: str
    last_occurred_ns: int | None
    _factory_key: InitVar[object] = field(default=None, kw_only=True, repr=False, compare=False)

    def __init__(
        self,
        *,
        records: tuple[AuditRecordV1, ...],
        head_hash: str,
        last_occurred_ns: int | None,
        _factory_key: object = None,
    ) -> None:
        try:
            require(self, _CHAIN_ISSUER.tag)
        except SealError as exc:
            if exc.code != "SEAL_NOT_ISSUED":
                raise
        else:
            raise SealError("SEAL_FORBIDDEN_OPERATION")
        if _factory_key is not _FACTORY_KEY:
            raise AuditError("UNISSUED_CHAIN")
        object.__setattr__(self, "records", records)
        object.__setattr__(self, "head_hash", head_hash)
        object.__setattr__(self, "last_occurred_ns", last_occurred_ns)
        self.__post_init__(_factory_key)

    def __post_init__(self, _factory_key: object) -> None:
        if _factory_key is not _FACTORY_KEY:
            raise AuditError("UNISSUED_CHAIN")
        if type(self.records) is not tuple or any(
            type(item) is not AuditRecordV1 for item in self.records
        ):
            raise AuditError("CHAIN_INVALID")
        if not _digest(self.head_hash):
            raise AuditError("CHAIN_INVALID")
        if self.last_occurred_ns is not None and (
            type(self.last_occurred_ns) is not int or not 0 <= self.last_occurred_ns <= _MAX_UTC_NS
        ):
            raise AuditError("CHAIN_INVALID")
        expected_head = self.records[-1].record_hash if self.records else _GENESIS_HASH
        expected_time = self.records[-1].occurred_ns if self.records else None
        if self.head_hash != expected_head or self.last_occurred_ns != expected_time:
            raise AuditError("CHAIN_INVALID")

    def canonical_bytes(self) -> bytes:
        require_audit_chain(self)
        return canonical_json(
            {
                "schema": "mtbr.audit.chain.v1",
                "head_hash": self.head_hash,
                "last_occurred_ns": self.last_occurred_ns,
                "records": [record.canonical_bytes().decode("ascii") for record in self.records],
            }
        )


def require_audit_record(value: object) -> AuditRecordV1:
    """Require a current module-issued audit record."""
    if type(value) is not AuditRecordV1:
        raise SealError("SEAL_UNSUPPORTED_TYPE")
    return require(value, _RECORD_ISSUER.tag)


def require_audit_chain(value: object) -> AuditChainV1:
    """Require a current module-issued chain and every record it contains."""
    if type(value) is not AuditChainV1:
        raise SealError("SEAL_UNSUPPORTED_TYPE")
    chain = require(value, _CHAIN_ISSUER.tag)
    _validate_chain(chain)
    return chain


def _record_digest(record: AuditRecordV1) -> str:
    payload = _record_payload(
        sequence=record.sequence,
        actor_ref=record.actor_ref,
        action=record.action,
        occurred_ns=record.occurred_ns,
        target_ids=record.target_ids,
        correlation_id=record.correlation_id,
        artifact_id=record.artifact_id,
        before_params_digest=record.before_params_digest,
        after_params_digest=record.after_params_digest,
        previous_hash=record.previous_hash,
    )
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _validate_chain(chain: AuditChainV1) -> None:
    prior_hash = _GENESIS_HASH
    prior_time: int | None = None
    for index, record in enumerate(chain.records):
        require_audit_record(record)
        if (
            record.sequence != index
            or record.previous_hash != prior_hash
            or record.record_hash != _record_digest(record)
        ):
            raise AuditError("CHAIN_INVALID")
        if prior_time is not None and record.occurred_ns < prior_time:
            raise AuditError("CHAIN_ORDER")
        prior_hash = record.record_hash
        prior_time = record.occurred_ns
    expected_head = prior_hash
    if chain.head_hash != expected_head or chain.last_occurred_ns != prior_time:
        raise AuditError("CHAIN_INVALID")


def new_audit_chain() -> AuditChainV1:
    """Create a sealed empty chain with the fixed genesis hash."""
    chain = AuditChainV1(
        records=(),
        head_hash=_GENESIS_HASH,
        last_occurred_ns=None,
        _factory_key=_FACTORY_KEY,
    )
    return _CHAIN_ISSUER.issue(chain)


def append_audit_record(
    chain: AuditChainV1,
    *,
    actor_ref: str,
    action: AuditActionV1,
    occurred_ns: int,
    target_ids: tuple[str, ...],
    correlation_id: str,
    artifact_id: str,
    before_params_map: dict[str, object],
    after_params_map: dict[str, object],
) -> AuditChainV1:
    """Append one sealed record and return a new chain view.

    The incoming chain and all its records are checked before any new object is
    built. Parameter maps are converted to digests and are never retained.
    """
    current = require_audit_chain(chain)
    if type(action) is not AuditActionV1:
        raise AuditError("INVALID_ACTION")
    if type(occurred_ns) is not int or not 0 <= occurred_ns <= _MAX_UTC_NS:
        raise AuditError("INVALID_TIME")
    if current.last_occurred_ns is not None and (occurred_ns < current.last_occurred_ns):
        raise AuditError("CHAIN_ORDER")
    before_digest = _params_digest(action, before_params_map)
    after_digest = _params_digest(action, after_params_map)
    if (
        type(target_ids) is not tuple
        or not 1 <= len(target_ids) <= _MAX_TARGETS
        or any(not _identifier(item) for item in target_ids)
    ):
        raise AuditError("INVALID_AUDIT_FIELD")
    canonical_targets = tuple(sorted(set(target_ids)))
    sequence = len(current.records)
    previous_hash = current.head_hash
    _validate_fields(
        sequence=sequence,
        actor_ref=actor_ref,
        action=action,
        occurred_ns=occurred_ns,
        target_ids=canonical_targets,
        correlation_id=correlation_id,
        artifact_id=artifact_id,
        before_params_digest=before_digest,
        after_params_digest=after_digest,
        previous_hash=previous_hash,
        record_hash=_GENESIS_HASH,
    )
    payload = _record_payload(
        sequence=sequence,
        actor_ref=actor_ref,
        action=action,
        occurred_ns=occurred_ns,
        target_ids=canonical_targets,
        correlation_id=correlation_id,
        artifact_id=artifact_id,
        before_params_digest=before_digest,
        after_params_digest=after_digest,
        previous_hash=previous_hash,
    )
    record_hash = hashlib.sha256(canonical_json(payload)).hexdigest()
    record = AuditRecordV1(
        sequence=sequence,
        actor_ref=actor_ref,
        action=action,
        occurred_ns=occurred_ns,
        target_ids=canonical_targets,
        correlation_id=correlation_id,
        artifact_id=artifact_id,
        before_params_digest=before_digest,
        after_params_digest=after_digest,
        previous_hash=previous_hash,
        record_hash=record_hash,
        _factory_key=_FACTORY_KEY,
    )
    _RECORD_ISSUER.issue(record)
    updated = AuditChainV1(
        records=(*current.records, record),
        head_hash=record_hash,
        last_occurred_ns=occurred_ns,
        _factory_key=_FACTORY_KEY,
    )
    return _CHAIN_ISSUER.issue(updated)


__all__ = [
    "AuditActionV1",
    "AuditChainV1",
    "AuditError",
    "AuditRecordV1",
    "append_audit_record",
    "new_audit_chain",
    "require_audit_chain",
    "require_audit_record",
]
