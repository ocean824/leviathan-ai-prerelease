"""Pure version-lineage decisions for untrusted knowledge sources.

No function here writes storage, emits events, removes vectors, reads a clock,
or generates identifiers. Consumers must call ``require`` on issued outputs
before trusting fields. Source text and parser output are data, never authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal, TypeVar

from leviathan_core.knowledge_sync.lineage_models import (
    DedupDecisionV1,
    DocumentVersionV1,
    LineageEdgeV1,
    LineageEventV1,
    LineageModelV1,
    TombstoneV1,
    TrustedRenameV1,
    VaultSourceV1,
    is_vault_relative_path,
    is_wire_id,
    path_sha256,
)
from leviathan_core.knowledge_sync.parser_models import ParseResultV1
from leviathan_core.seal import Issuer, SealError, require

PARSER_ISSUER_TAG = "knowledge.parser.v1"
LINEAGE_ISSUER_TAG = "knowledge.lineage.v1"
RENAME_ISSUER_TAG = "knowledge.rename.v1"

_LINEAGE_ISSUER = Issuer(LINEAGE_ISSUER_TAG)
_RENAME_ISSUER = Issuer(RENAME_ISSUER_TAG)
_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}\Z", re.ASCII)
_LineageRecord = TypeVar("_LineageRecord", bound=LineageModelV1)


class LineagePolicyError(Exception):
    """Content-free validation failure at the lineage policy boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _decision(
    decision: Literal["existing", "new_version", "rename", "conflict", "tombstone"],
    reason_code: str,
    *,
    source: VaultSourceV1 | None = None,
    version: DocumentVersionV1 | None = None,
    edge: LineageEdgeV1 | None = None,
    tombstone: TombstoneV1 | None = None,
    event: LineageEventV1 | None = None,
    existing_version_id: str | None = None,
    vector_removal_intent: bool = False,
) -> DedupDecisionV1:
    return _LINEAGE_ISSUER.issue(
        DedupDecisionV1(
            decision=decision,
            reason_code=reason_code,
            source=source,
            version=version,
            edge=edge,
            tombstone=tombstone,
            event=event,
            existing_version_id=existing_version_id,
            vector_removal_intent=vector_removal_intent,
        )
    )


def _state_snapshot(value: _LineageRecord, expected_type: type[_LineageRecord]) -> _LineageRecord:
    """Verify issued state or validate a detached persisted snapshot as data."""

    if type(value) is not expected_type:
        raise LineagePolicyError("INVALID_STATE")
    try:
        return require(value, _LINEAGE_ISSUER.tag)
    except SealError as error:
        if error.code != "SEAL_NOT_ISSUED":
            raise
    # Persisted records may be reconstructed by an adapter as fresh, unissued
    # immutable models. Revalidation creates a detached copy and cannot launder
    # an issued-but-invalid record because require() above would raise instead.
    data = value.model_dump(mode="python")
    return expected_type.model_validate(data)


def _validate_trusted_scope(org_id: str, vault_id: str) -> None:
    if not is_wire_id(org_id) or not is_wire_id(vault_id):
        raise LineagePolicyError("INVALID_TRUSTED_SCOPE")


def _validate_actor(actor_id: str) -> None:
    if type(actor_id) is not str or _ACTOR.fullmatch(actor_id) is None:
        raise LineagePolicyError("INVALID_ACTOR")


def _conflict(reason_code: str, existing_version_id: str | None = None) -> DedupDecisionV1:
    return _decision("conflict", reason_code, existing_version_id=existing_version_id)


def _make_version(
    parsed: ParseResultV1,
    *,
    parent: DocumentVersionV1 | None,
    actor_id: str,
    reason_code: str,
) -> DocumentVersionV1:
    if parent is not None and parsed.version_id == parent.version_id:
        raise LineagePolicyError("VERSION_ID_REUSED")
    return DocumentVersionV1(
        org_id=parsed.org_id,
        vault_id=parsed.vault_id,
        doc_id=parsed.doc_id,
        version_id=parsed.version_id,
        version_no=1 if parent is None else parent.version_no + 1,
        parent_version_id=None if parent is None else parent.version_id,
        path=parsed.path,
        content_hash=parsed.source_hash,
        parser_version=parsed.parser_version,
        chunker_version=parsed.chunker_version,
        created_at_ns=parsed.created_at_ns,
        actor_id=actor_id,
        reason_code=reason_code,
    )


def _make_event(
    parsed: ParseResultV1,
    *,
    event_id: str,
    actor_id: str,
    event_kind: Literal["create", "update", "rename", "reindex", "delete"],
    parent_version_id: str | None,
    version_id: str | None = None,
    old_path: str | None = None,
) -> LineageEventV1:
    return LineageEventV1(
        event_id=event_id,
        event_kind=event_kind,
        org_id=parsed.org_id,
        vault_id=parsed.vault_id,
        doc_id=parsed.doc_id,
        version_id=parsed.version_id if version_id is None else version_id,
        parent_version_id=parent_version_id,
        path=parsed.path,
        old_path=old_path,
        content_hash=parsed.source_hash,
        parser_version=parsed.parser_version,
        chunker_version=parsed.chunker_version,
        created_at_ns=parsed.created_at_ns,
        actor_id=actor_id,
        deletion_tombstone=False,
    )


def _make_edge(
    *,
    org_id: str,
    vault_id: str,
    doc_id: str,
    parent_id: str,
    parent_kind: Literal["source", "version", "source_path"],
    child_id: str,
    child_kind: Literal["source", "version", "tombstone", "source_path"],
    relation: Literal["contains", "revision", "rename", "tombstone", "reindex"],
    created_at_ns: int,
    actor_id: str,
) -> LineageEdgeV1:
    return LineageEdgeV1(
        org_id=org_id,
        vault_id=vault_id,
        doc_id=doc_id,
        parent_id=parent_id,
        parent_kind=parent_kind,
        child_id=child_id,
        child_kind=child_kind,
        relation=relation,
        created_at_ns=created_at_ns,
        actor_id=actor_id,
    )


def _check_previous(
    source: VaultSourceV1 | None,
    version: DocumentVersionV1 | None,
    *,
    org_id: str,
    vault_id: str,
    doc_id: str,
) -> tuple[VaultSourceV1 | None, DocumentVersionV1 | None, str | None]:
    if source is None:
        if version is not None:
            return None, None, "VERSION_WITHOUT_SOURCE"
        return None, None, None
    checked_source = _state_snapshot(source, VaultSourceV1)
    if (
        checked_source.org_id != org_id
        or checked_source.vault_id != vault_id
        or checked_source.doc_id != doc_id
    ):
        return None, None, "TENANT_OR_DOCUMENT_MISMATCH"
    if not checked_source.active:
        return None, None, "SOURCE_DELETED"
    if version is None:
        if checked_source.current_version_id is not None:
            return None, None, "CURRENT_VERSION_MISSING"
        return checked_source, None, None
    checked_version = _state_snapshot(version, DocumentVersionV1)
    if (
        checked_version.org_id != org_id
        or checked_version.vault_id != vault_id
        or checked_version.doc_id != doc_id
        or checked_source.current_version_id != checked_version.version_id
    ):
        return None, None, "TENANT_OR_VERSION_MISMATCH"
    if checked_source.path != checked_version.path:
        return None, None, "SOURCE_VERSION_PATH_MISMATCH"
    return checked_source, checked_version, None


def decide_lineage(
    parsed: ParseResultV1,
    *,
    trusted_org_id: str,
    trusted_vault_id: str,
    event_id: str,
    actor_id: str,
    current_source: VaultSourceV1 | None = None,
    current_version: DocumentVersionV1 | None = None,
    force_reindex: bool = False,
    rename_evidence: TrustedRenameV1 | None = None,
) -> DedupDecisionV1:
    """Return immutable source/version/event intents for one parser result.

    ``trusted_org_id`` and ``trusted_vault_id`` come from the authenticated
    caller. A same-path/hash result deduplicates unless explicitly force
    reindexed. A path change can retain the stable document identity only with
    a SEAL-issued, exact-scope rename assertion. Unissued or tampered assertions
    are treated as absent evidence and produce a code-only conflict.
    """

    try:
        require(parsed, PARSER_ISSUER_TAG)
    except SealError:
        raise LineagePolicyError("PARSE_RESULT_UNTRUSTED") from None
    if type(parsed) is not ParseResultV1:
        raise LineagePolicyError("PARSE_RESULT_UNTRUSTED")
    _validate_trusted_scope(trusted_org_id, trusted_vault_id)
    _validate_actor(actor_id)
    if type(force_reindex) is not bool:
        raise LineagePolicyError("INVALID_FORCE_REINDEX")
    if not is_wire_id(event_id):
        raise LineagePolicyError("INVALID_EVENT_ID")
    if (
        parsed.org_id != trusted_org_id
        or parsed.vault_id != trusted_vault_id
        or not all(is_wire_id(value) for value in (parsed.doc_id, parsed.version_id))
        or not is_vault_relative_path(parsed.path)
    ):
        return _conflict("TRUSTED_SCOPE_OR_SOURCE_MISMATCH")

    previous_source, previous_version, error = _check_previous(
        current_source,
        current_version,
        org_id=trusted_org_id,
        vault_id=trusted_vault_id,
        doc_id=parsed.doc_id,
    )
    if error is not None:
        return _conflict(error)

    old_path: str | None = None
    is_rename = False
    if previous_source is not None and previous_source.path != parsed.path:
        old_path = previous_source.path
        if rename_evidence is None:
            return _conflict("TRUSTED_RENAME_REQUIRED")
        try:
            require(rename_evidence, _RENAME_ISSUER.tag)
        except SealError:
            return _conflict("INVALID_RENAME_EVIDENCE")
        if (
            rename_evidence.org_id != trusted_org_id
            or rename_evidence.vault_id != trusted_vault_id
            or rename_evidence.doc_id != parsed.doc_id
            or rename_evidence.old_path != previous_source.path
            or rename_evidence.new_path != parsed.path
        ):
            return _conflict("RENAME_EVIDENCE_MISMATCH")
        is_rename = True
    elif rename_evidence is not None:
        # Evidence for another operation must not be silently carried forward.
        try:
            require(rename_evidence, _RENAME_ISSUER.tag)
        except SealError:
            return _conflict("INVALID_RENAME_EVIDENCE")
        return _conflict("RENAME_EVIDENCE_MISMATCH")

    same_content = (
        previous_version is not None and previous_version.content_hash == parsed.source_hash
    )
    if same_content and not force_reindex:
        if not is_rename:
            assert previous_version is not None
            return _decision(
                "existing",
                "UNCHANGED_CONTENT",
                source=previous_source,
                version=previous_version,
                existing_version_id=previous_version.version_id,
            )
        assert previous_source is not None and previous_version is not None and old_path is not None
        source = VaultSourceV1(
            org_id=previous_source.org_id,
            vault_id=previous_source.vault_id,
            doc_id=previous_source.doc_id,
            path=parsed.path,
            path_hash=path_sha256(parsed.path),
            current_version_id=previous_version.version_id,
            active=True,
            deleted_at_ns=None,
        )
        event = _make_event(
            parsed,
            event_id=event_id,
            actor_id=actor_id,
            event_kind="rename",
            version_id=previous_version.version_id,
            parent_version_id=None,
            old_path=old_path,
        )
        edge = _make_edge(
            org_id=trusted_org_id,
            vault_id=trusted_vault_id,
            doc_id=parsed.doc_id,
            parent_id=path_sha256(old_path),
            parent_kind="source_path",
            child_id=path_sha256(parsed.path),
            child_kind="source_path",
            relation="rename",
            created_at_ns=parsed.created_at_ns,
            actor_id=actor_id,
        )
        return _decision(
            "rename",
            "TRUSTED_RENAME",
            source=source,
            version=previous_version,
            edge=edge,
            event=event,
            existing_version_id=previous_version.version_id,
        )

    reason_code = (
        "FORCE_REINDEX"
        if force_reindex
        else "CONTENT_CHANGED"
        if previous_version is not None
        else "FIRST_VERSION"
    )
    version = _make_version(
        parsed,
        parent=previous_version,
        actor_id=actor_id,
        reason_code=reason_code,
    )
    source = VaultSourceV1(
        org_id=parsed.org_id,
        vault_id=parsed.vault_id,
        doc_id=parsed.doc_id,
        path=parsed.path,
        path_hash=path_sha256(parsed.path),
        current_version_id=version.version_id,
        active=True,
        deleted_at_ns=None,
    )
    event_kind: Literal["create", "update", "rename", "reindex", "delete"]
    if is_rename:
        event_kind = "rename"
    elif force_reindex:
        event_kind = "reindex"
    else:
        event_kind = "update" if previous_version is not None else "create"
    event = _make_event(
        parsed,
        event_id=event_id,
        actor_id=actor_id,
        event_kind=event_kind,
        parent_version_id=None if previous_version is None else previous_version.version_id,
        old_path=old_path,
    )
    relation: Literal["contains", "revision", "rename", "tombstone", "reindex"] = (
        "reindex" if force_reindex else "revision" if previous_version is not None else "contains"
    )
    edge = _make_edge(
        org_id=trusted_org_id,
        vault_id=trusted_vault_id,
        doc_id=parsed.doc_id,
        parent_id=parsed.doc_id if previous_version is None else previous_version.version_id,
        parent_kind="source" if previous_version is None else "version",
        child_id=version.version_id,
        child_kind="version",
        relation=relation,
        created_at_ns=parsed.created_at_ns,
        actor_id=actor_id,
    )
    return _decision(
        "rename" if is_rename else "new_version",
        "TRUSTED_RENAME_WITH_VERSION" if is_rename else reason_code,
        source=source,
        version=version,
        edge=edge,
        event=event,
    )


def decide_tombstone(
    source: VaultSourceV1,
    current_version: DocumentVersionV1,
    *,
    trusted_org_id: str,
    trusted_vault_id: str,
    tombstone_id: str,
    event_id: str,
    actor_id: str,
    deleted_at_ns: int,
) -> DedupDecisionV1:
    """Return a tombstone and vector-removal intent while retaining history."""

    _validate_trusted_scope(trusted_org_id, trusted_vault_id)
    _validate_actor(actor_id)
    if not is_wire_id(tombstone_id) or not is_wire_id(event_id):
        raise LineagePolicyError("INVALID_EVENT_ID")
    if type(deleted_at_ns) is not int or deleted_at_ns < 0:
        raise LineagePolicyError("INVALID_TIMESTAMP")
    checked_source = _state_snapshot(source, VaultSourceV1)
    checked_version = _state_snapshot(current_version, DocumentVersionV1)
    if (
        checked_source.org_id != trusted_org_id
        or checked_source.vault_id != trusted_vault_id
        or checked_version.org_id != trusted_org_id
        or checked_version.vault_id != trusted_vault_id
        or checked_source.doc_id != checked_version.doc_id
        or checked_source.current_version_id != checked_version.version_id
        or checked_source.path != checked_version.path
    ):
        return _conflict("TENANT_OR_VERSION_MISMATCH", checked_version.version_id)
    if not checked_source.active:
        return _conflict("SOURCE_ALREADY_DELETED", checked_version.version_id)

    next_source = VaultSourceV1(
        org_id=checked_source.org_id,
        vault_id=checked_source.vault_id,
        doc_id=checked_source.doc_id,
        path=checked_source.path,
        path_hash=checked_source.path_hash,
        current_version_id=checked_source.current_version_id,
        active=False,
        deleted_at_ns=deleted_at_ns,
    )
    tombstone = TombstoneV1(
        org_id=checked_source.org_id,
        vault_id=checked_source.vault_id,
        doc_id=checked_source.doc_id,
        tombstone_id=tombstone_id,
        version_id=checked_version.version_id,
        path=checked_source.path,
        content_hash=checked_version.content_hash,
        deleted_at_ns=deleted_at_ns,
        actor_id=actor_id,
        history_retained=True,
        vector_removal_intent=True,
    )
    event = LineageEventV1(
        event_id=event_id,
        event_kind="delete",
        org_id=checked_source.org_id,
        vault_id=checked_source.vault_id,
        doc_id=checked_source.doc_id,
        version_id=checked_version.version_id,
        parent_version_id=checked_version.version_id,
        path=checked_source.path,
        content_hash=checked_version.content_hash,
        parser_version=checked_version.parser_version,
        chunker_version=checked_version.chunker_version,
        created_at_ns=deleted_at_ns,
        actor_id=actor_id,
        deletion_tombstone=True,
    )
    edge = _make_edge(
        org_id=checked_source.org_id,
        vault_id=checked_source.vault_id,
        doc_id=checked_source.doc_id,
        parent_id=checked_version.version_id,
        parent_kind="version",
        child_id=tombstone_id,
        child_kind="tombstone",
        relation="tombstone",
        created_at_ns=deleted_at_ns,
        actor_id=actor_id,
    )
    return _decision(
        "tombstone",
        "SOURCE_DELETED",
        source=next_source,
        edge=edge,
        tombstone=tombstone,
        event=event,
        vector_removal_intent=True,
    )


def deterministic_chunk_id(version_id: str, sequence: int) -> str:
    """Derive a version-scoped chunk identity from canonical JSON input."""

    if not is_wire_id(version_id):
        raise LineagePolicyError("INVALID_VERSION_ID")
    if type(sequence) is not int or sequence < 0:
        raise LineagePolicyError("INVALID_CHUNK_SEQUENCE")
    canonical = json.dumps(
        {"domain": "knowledge.chunk.v1", "sequence": sequence, "version_id": version_id},
        ensure_ascii=True,
        sort_keys=True,
        allow_nan=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


__all__ = [
    "LINEAGE_ISSUER_TAG",
    "PARSER_ISSUER_TAG",
    "RENAME_ISSUER_TAG",
    "LineagePolicyError",
    "decide_lineage",
    "decide_tombstone",
    "deterministic_chunk_id",
]
