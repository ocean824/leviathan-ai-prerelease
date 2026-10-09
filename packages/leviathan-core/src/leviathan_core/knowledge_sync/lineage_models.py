"""Immutable V1 records for knowledge-source version lineage.

These records carry source and version data, never instructions. Values returned
by the policy kernel are issued through SEAL-001; consumers must require an
issued root before trusting any of its fields.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Literal
from uuid import UUID

from pydantic import Field, StrictBool, StrictInt, model_validator

from leviathan_core.seal import SealedModel

_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ULID = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z", re.ASCII)
_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z", re.ASCII)
_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}\Z", re.ASCII)
_DEVICE = re.compile(
    r"(?:con|prn|aux|nul|conin\$|conout\$|clock\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?\Z",
    re.IGNORECASE | re.ASCII,
)
_SHORT_NAME = re.compile(r"~[1-9](?:\.|$)", re.IGNORECASE | re.ASCII)


def is_wire_id(value: object) -> bool:
    """Return whether value is a canonical UUID or Crockford ULID string."""

    if type(value) is not str or len(value) > 36:
        return False
    if _ULID.fullmatch(value) is not None:
        return True
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        return False
    return str(parsed) == value.lower()


def path_sha256(path: str) -> str:
    """Hash the exact NFC UTF-8 vault-relative path, independently of content."""

    return hashlib.sha256(path.encode("utf-8")).hexdigest()


def is_vault_relative_path(path: object) -> bool:
    """Validate the parser's strict vault-relative path grammar locally."""

    if type(path) is not str or not path or len(path) > 1024:
        return False
    if path != unicodedata.normalize("NFC", path):
        return False
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if (
        "\\" in path
        or path.startswith("/")
        or path.endswith("/")
        or "//" in path
        or ":" in path
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
    ):
        return False
    parts = path.split("/")
    if len(parts) > 32:
        return False
    return all(
        part not in ("", ".", "..")
        and part.rstrip(" .") == part
        and _DEVICE.fullmatch(part) is None
        and _SHORT_NAME.search(part) is None
        for part in parts
    )


class LineageModelV1(SealedModel):
    """Shared immutable, strict and extra-forbid boundary for lineage records."""


class VaultSourceV1(LineageModelV1):
    """Current source identity; updates are represented by fresh snapshots."""

    org_id: str = Field(min_length=1, max_length=36)
    vault_id: str = Field(min_length=1, max_length=36)
    doc_id: str = Field(min_length=1, max_length=36)
    path: str = Field(min_length=1, max_length=1024)
    path_hash: str = Field(min_length=64, max_length=64)
    current_version_id: str | None = Field(default=None, min_length=1, max_length=36)
    active: StrictBool = True
    deleted_at_ns: StrictInt | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_source(self) -> VaultSourceV1:
        if not all(is_wire_id(value) for value in (self.org_id, self.vault_id, self.doc_id)):
            raise ValueError("invalid source identity")
        if self.current_version_id is not None and not is_wire_id(self.current_version_id):
            raise ValueError("invalid current version identity")
        if not is_vault_relative_path(self.path):
            raise ValueError("invalid vault path")
        if _HEX_SHA256.fullmatch(self.path_hash) is None or self.path_hash != path_sha256(
            self.path
        ):
            raise ValueError("invalid path hash")
        if self.active == (self.deleted_at_ns is not None):
            raise ValueError("invalid source activity state")
        return self


class DocumentVersionV1(LineageModelV1):
    """Append-only parsed source version; callers supply every ID and timestamp."""

    org_id: str = Field(min_length=1, max_length=36)
    vault_id: str = Field(min_length=1, max_length=36)
    doc_id: str = Field(min_length=1, max_length=36)
    version_id: str = Field(min_length=1, max_length=36)
    version_no: StrictInt = Field(ge=1)
    parent_version_id: str | None = Field(default=None, min_length=1, max_length=36)
    path: str = Field(min_length=1, max_length=1024)
    content_hash: str = Field(min_length=64, max_length=64)
    parser_version: str = Field(min_length=1, max_length=64)
    chunker_version: str = Field(min_length=1, max_length=64)
    created_at_ns: StrictInt = Field(ge=0)
    actor_id: str = Field(min_length=1, max_length=128)
    reason_code: str = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_version(self) -> DocumentVersionV1:
        ids = (self.org_id, self.vault_id, self.doc_id, self.version_id)
        if not all(is_wire_id(value) for value in ids):
            raise ValueError("invalid version identity")
        if self.parent_version_id is not None and not is_wire_id(self.parent_version_id):
            raise ValueError("invalid parent version identity")
        if not is_vault_relative_path(self.path):
            raise ValueError("invalid vault path")
        if _HEX_SHA256.fullmatch(self.content_hash) is None:
            raise ValueError("invalid content hash")
        if not _ACTOR.fullmatch(self.actor_id):
            raise ValueError("invalid actor identity")
        if _REASON.fullmatch(self.reason_code) is None:
            raise ValueError("invalid reason code")
        if (self.version_no == 1) != (self.parent_version_id is None):
            raise ValueError("invalid version parent")
        return self


class LineageEdgeV1(LineageModelV1):
    """Typed parent-child relation between immutable source lineage nodes."""

    org_id: str = Field(min_length=1, max_length=36)
    vault_id: str = Field(min_length=1, max_length=36)
    doc_id: str = Field(min_length=1, max_length=36)
    parent_id: str = Field(min_length=1, max_length=128)
    parent_kind: Literal["source", "version", "source_path"]
    child_id: str = Field(min_length=1, max_length=128)
    child_kind: Literal["source", "version", "tombstone", "source_path"]
    relation: Literal["contains", "revision", "rename", "tombstone", "reindex"]
    created_at_ns: StrictInt = Field(ge=0)
    actor_id: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_edge(self) -> LineageEdgeV1:
        if not all(is_wire_id(value) for value in (self.org_id, self.vault_id, self.doc_id)):
            raise ValueError("invalid edge identity")
        parent_valid = (
            _HEX_SHA256.fullmatch(self.parent_id) is not None
            if self.parent_kind == "source_path"
            else is_wire_id(self.parent_id)
        )
        child_valid = (
            _HEX_SHA256.fullmatch(self.child_id) is not None
            if self.child_kind == "source_path"
            else is_wire_id(self.child_id)
        )
        if not parent_valid or not child_valid:
            raise ValueError("invalid edge endpoint")
        if not _ACTOR.fullmatch(self.actor_id):
            raise ValueError("invalid actor identity")
        if self.parent_kind == self.child_kind == "version" and self.parent_id == self.child_id:
            raise ValueError("lineage edge must advance")
        return self


class TrustedRenameV1(LineageModelV1):
    """Rename assertion accepted only when issued by KNOW's private rename issuer."""

    org_id: str = Field(min_length=1, max_length=36)
    vault_id: str = Field(min_length=1, max_length=36)
    doc_id: str = Field(min_length=1, max_length=36)
    old_path: str = Field(min_length=1, max_length=1024)
    new_path: str = Field(min_length=1, max_length=1024)
    evidence_id: str = Field(min_length=1, max_length=36)

    @model_validator(mode="after")
    def validate_rename(self) -> TrustedRenameV1:
        if not all(
            is_wire_id(value)
            for value in (self.org_id, self.vault_id, self.doc_id, self.evidence_id)
        ):
            raise ValueError("invalid rename identity")
        if (
            not is_vault_relative_path(self.old_path)
            or not is_vault_relative_path(self.new_path)
            or self.old_path == self.new_path
        ):
            raise ValueError("invalid rename path")
        return self


class TombstoneV1(LineageModelV1):
    """Deletion intent that preserves source and revision history."""

    org_id: str = Field(min_length=1, max_length=36)
    vault_id: str = Field(min_length=1, max_length=36)
    doc_id: str = Field(min_length=1, max_length=36)
    tombstone_id: str = Field(min_length=1, max_length=36)
    version_id: str = Field(min_length=1, max_length=36)
    path: str = Field(min_length=1, max_length=1024)
    content_hash: str = Field(min_length=64, max_length=64)
    deleted_at_ns: StrictInt = Field(ge=0)
    actor_id: str = Field(min_length=1, max_length=128)
    history_retained: Literal[True] = True
    vector_removal_intent: Literal[True] = True

    @model_validator(mode="after")
    def validate_tombstone(self) -> TombstoneV1:
        ids = (self.org_id, self.vault_id, self.doc_id, self.tombstone_id, self.version_id)
        if not all(is_wire_id(value) for value in ids):
            raise ValueError("invalid tombstone identity")
        if (
            not is_vault_relative_path(self.path)
            or _HEX_SHA256.fullmatch(self.content_hash) is None
        ):
            raise ValueError("invalid tombstone source")
        if not _ACTOR.fullmatch(self.actor_id):
            raise ValueError("invalid actor identity")
        return self


class LineageEventV1(LineageModelV1):
    """Immutable TRITON event payload; publication is a later adapter action."""

    event_id: str = Field(min_length=1, max_length=36)
    event_kind: Literal["create", "update", "rename", "reindex", "delete"]
    org_id: str = Field(min_length=1, max_length=36)
    vault_id: str = Field(min_length=1, max_length=36)
    doc_id: str = Field(min_length=1, max_length=36)
    version_id: str = Field(min_length=1, max_length=36)
    parent_version_id: str | None = Field(default=None, min_length=1, max_length=36)
    path: str = Field(min_length=1, max_length=1024)
    old_path: str | None = Field(default=None, min_length=1, max_length=1024)
    content_hash: str = Field(min_length=64, max_length=64)
    parser_version: str = Field(min_length=1, max_length=64)
    chunker_version: str = Field(min_length=1, max_length=64)
    created_at_ns: StrictInt = Field(ge=0)
    actor_id: str = Field(min_length=1, max_length=128)
    deletion_tombstone: StrictBool = False

    @model_validator(mode="after")
    def validate_event(self) -> LineageEventV1:
        ids = (self.event_id, self.org_id, self.vault_id, self.doc_id, self.version_id)
        if not all(is_wire_id(value) for value in ids):
            raise ValueError("invalid event identity")
        if self.parent_version_id is not None and not is_wire_id(self.parent_version_id):
            raise ValueError("invalid parent version identity")
        if not is_vault_relative_path(self.path):
            raise ValueError("invalid vault path")
        if self.old_path is not None and not is_vault_relative_path(self.old_path):
            raise ValueError("invalid previous path")
        if _HEX_SHA256.fullmatch(self.content_hash) is None or not _ACTOR.fullmatch(self.actor_id):
            raise ValueError("invalid event metadata")
        if self.deletion_tombstone != (self.event_kind == "delete"):
            raise ValueError("invalid deletion marker")
        return self


class DedupDecisionV1(LineageModelV1):
    """Pure outcome and immutable intents for one source/version evaluation."""

    decision: Literal["existing", "new_version", "rename", "conflict", "tombstone"]
    reason_code: str = Field(min_length=1, max_length=64)
    source: VaultSourceV1 | None = None
    version: DocumentVersionV1 | None = None
    edge: LineageEdgeV1 | None = None
    tombstone: TombstoneV1 | None = None
    event: LineageEventV1 | None = None
    existing_version_id: str | None = Field(default=None, min_length=1, max_length=36)
    vector_removal_intent: StrictBool = False

    @model_validator(mode="after")
    def validate_decision(self) -> DedupDecisionV1:
        if _REASON.fullmatch(self.reason_code) is None:
            raise ValueError("invalid reason code")
        if self.existing_version_id is not None and not is_wire_id(self.existing_version_id):
            raise ValueError("invalid existing version identity")
        records = (self.source, self.version, self.edge, self.tombstone, self.event)
        present = tuple(value for value in records if value is not None)
        scopes = {(value.org_id, value.vault_id, value.doc_id) for value in present}
        if len(scopes) > 1:
            raise ValueError("decision intents cross tenant or document scope")
        if (
            self.source is not None
            and self.version is not None
            and self.source.current_version_id != self.version.version_id
        ):
            raise ValueError("decision source and version disagree")
        if (
            self.event is not None
            and self.version is not None
            and (
                self.event.version_id != self.version.version_id
                or self.event.content_hash != self.version.content_hash
            )
        ):
            raise ValueError("decision event and version disagree")
        if (
            self.event is not None
            and self.source is not None
            and self.event.path != self.source.path
        ):
            raise ValueError("decision event and source disagree")
        if (
            self.tombstone is not None
            and self.source is not None
            and (
                self.source.active
                or self.tombstone.path != self.source.path
                or self.tombstone.version_id != self.source.current_version_id
            )
        ):
            raise ValueError("decision tombstone and source disagree")
        if self.decision == "conflict":
            if any(
                (
                    self.source,
                    self.version,
                    self.edge,
                    self.tombstone,
                    self.event,
                    self.vector_removal_intent,
                )
            ):
                raise ValueError("conflict cannot carry mutation intents")
        elif self.decision == "existing":
            if (
                self.source is None
                or self.version is None
                or self.existing_version_id != self.version.version_id
            ):
                raise ValueError("existing decision requires its current version")
            if any((self.edge, self.tombstone, self.event, self.vector_removal_intent)):
                raise ValueError("existing decision cannot carry mutation intents")
        elif self.decision == "new_version":
            if any(value is None for value in (self.source, self.version, self.edge, self.event)):
                raise ValueError("new version decision requires complete intents")
            if (
                self.tombstone is not None
                or self.existing_version_id is not None
                or self.vector_removal_intent
            ):
                raise ValueError("new version decision has conflicting intents")
        elif self.decision == "rename":
            if any(value is None for value in (self.source, self.edge, self.event)):
                raise ValueError("rename decision requires complete intents")
            if self.tombstone is not None or self.vector_removal_intent:
                raise ValueError("rename decision has conflicting intents")
        else:
            if any(value is None for value in (self.source, self.tombstone, self.edge, self.event)):
                raise ValueError("tombstone decision requires complete intents")
            if not self.vector_removal_intent or self.version is not None:
                raise ValueError("invalid tombstone intents")
        return self


__all__ = [
    "DedupDecisionV1",
    "DocumentVersionV1",
    "LineageEdgeV1",
    "LineageEventV1",
    "LineageModelV1",
    "TombstoneV1",
    "TrustedRenameV1",
    "VaultSourceV1",
    "is_vault_relative_path",
    "is_wire_id",
    "path_sha256",
]
