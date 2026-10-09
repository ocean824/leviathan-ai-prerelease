"""Strict, immutable records for source-to-claim strategy review.

These records carry evidence only. None grants permission to generate code or route orders.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Literal, NoReturn, Self, SupportsIndex, cast
from urllib.parse import urlsplit
from weakref import ReferenceType, finalize, ref

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)

from leviathan_core.numeric import NumericError, canonical_json, canonical_str, parse_decimal
from leviathan_core.seal import SealedModel, SealError

HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_MAX_CLAIM_TEXT_CHARS = 512
_MAX_CONTENT_IDENTITY_CLAIM_TEXT_CHARS = 1200


class StrategyIngestError(ValueError):
    """A safe failure that never includes source content or a supplied value."""

    def __init__(
        self, code: str, *, location: tuple[str | int, ...] = (), error_type: str = ""
    ) -> None:
        self.code = code
        self.location = location
        self.error_type = error_type
        super().__init__(code)

    def errors(self) -> list[dict[str, object]]:
        return [{"code": self.code, "loc": self.location, "type": self.error_type}]


def canonical_decimal(value: Decimal) -> str:
    """One exact, context-independent JSON form for finite decimals."""
    return canonical_str(value)


def digest(payload: object) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _safe_validation_error(
    exc: ValidationError, record_type: type[BaseModel]
) -> StrategyIngestError:
    first_with_context = exc.errors(include_input=False)[0]
    nested = (first_with_context.get("ctx") or {}).get("error")
    if isinstance(nested, StrategyIngestError):
        return nested
    first = exc.errors(include_input=False, include_context=False)[0]
    first_location = first["loc"][0] if first["loc"] else None
    location = (
        (first_location,)
        if isinstance(first_location, str) and first_location in record_type.model_fields
        else ("record",)
    )
    return StrategyIngestError("INVALID_RECORD", location=location, error_type=str(first["type"]))


class _StrategySealedModel(SealedModel):
    """Translate SEAL failures to the stable STRAT-001 error surface once."""

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except SealError:
            raise StrategyIngestError("SEALED_RECORD_REINIT_DENIED") from None

    def __getattribute__(self, name: str) -> Any:
        if name == "__pydantic_validator__":
            try:
                from .review import _reviewed_spec_issuer

                if _reviewed_spec_issuer.issued_here(self):
                    raise StrategyIngestError("SEALED_RECORD_REINIT_DENIED")
            except SealError:
                raise StrategyIngestError("SEALED_RECORD_REINIT_DENIED") from None
        return super().__getattribute__(name)

    def __setattr__(self, name: str, value: Any) -> None:
        raise StrategyIngestError("SEALED_RECORD_MUTATION_DENIED")

    def __delattr__(self, name: str) -> None:
        raise StrategyIngestError("SEALED_RECORD_MUTATION_DENIED")

    def __setstate__(self, state: object) -> None:
        raise StrategyIngestError("SEALED_RECORD_REINIT_DENIED")

    @classmethod  # type: ignore[no-redef]
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_CONSTRUCTION_DENIED")

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_COPY_DENIED")

    def copy(
        self, *, include: Any = None, exclude: Any = None, update: Any = None, deep: bool = False
    ) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_COPY_DENIED")

    def __copy__(self) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_COPY_DENIED")

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_COPY_DENIED")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_SERIALIZATION_DENIED")


class _Record(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    @property
    def __dict__(self) -> dict[str, Any]:
        return cast(dict[str, Any], BaseModel.__dict__["__dict__"].__get__(self, type(self)))

    @__dict__.setter
    def __dict__(self, values: dict[str, Any]) -> None:
        try:
            object.__getattribute__(self, "__pydantic_fields_set__")
        except AttributeError:
            pass
        else:
            raise StrategyIngestError("SEALED_RECORD_REINIT_DENIED")
        BaseModel.__dict__["__dict__"].__set__(self, values)

    def __getattribute__(self, name: str) -> Any:
        if name == "__pydantic_validator__":
            try:
                object.__getattribute__(self, "__pydantic_fields_set__")
            except AttributeError:
                pass
            else:
                raise StrategyIngestError("SEALED_RECORD_REINIT_DENIED")
        return super().__getattribute__(name)

    def __init__(self, **data: Any) -> None:
        try:
            object.__getattribute__(self, "__pydantic_fields_set__")
        except AttributeError:
            pass
        else:
            raise StrategyIngestError("SEALED_RECORD_REINIT_DENIED")
        try:
            super().__init__(**data)
        except ValidationError as exc:
            raise _safe_validation_error(exc, type(self)) from None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError as exc:
            raise _safe_validation_error(exc, cls) from None

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Self:
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError as exc:
            raise _safe_validation_error(exc, cls) from None

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate_strings(obj, **kwargs)
        except ValidationError as exc:
            raise _safe_validation_error(exc, cls) from None

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_MUTATION_DENIED")

    def __delattr__(self, name: str) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_MUTATION_DENIED")

    @classmethod  # type: ignore[no-redef]
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_CONSTRUCTION_DENIED")

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_COPY_DENIED")

    def copy(
        self, *, include: Any = None, exclude: Any = None, update: Any = None, deep: bool = False
    ) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_COPY_DENIED")

    def __copy__(self) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_COPY_DENIED")

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_COPY_DENIED")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_SERIALIZATION_DENIED")

    def __setstate__(self, state: dict[str, Any]) -> NoReturn:
        raise StrategyIngestError("SEALED_RECORD_REINIT_DENIED")


class _SealedRecord(_Record):
    """Prevent copy helpers from bypassing an append-only record's content hash."""


class SafeScanReceiptV1(_Record):
    schema_version: Literal["1"]
    provenance_status: Literal["CALLER_DECLARED"]
    scanned_sha256: str
    verdict: Literal["clean", "infected", "not_scanned"]
    scanner_name: str
    scanner_version: str
    scanned_at_ns: int

    @field_validator("scanned_sha256")
    @classmethod
    def _digest(cls, value: str) -> str:
        if not HEX64.fullmatch(value):
            raise ValueError("invalid scan digest")
        return value

    @field_validator("scanner_name", "scanner_version")
    @classmethod
    def _version(cls, value: str) -> str:
        if not VERSION.fullmatch(value):
            raise ValueError("invalid scanner identity")
        return value

    @field_validator("scanned_at_ns")
    @classmethod
    def _clock(cls, value: int) -> int:
        if value < 0:
            raise ValueError("invalid scan clock")
        return value


class SourceManifestV1(_Record):
    schema_version: Literal["1"]
    source_id: str
    source_uri: str
    source_locator: str
    source_bytes: bytes = Field(repr=False, exclude=True)
    byte_sha256: str
    media_type: str
    license_status: Literal["unreviewed", "reference_only", "reuse_permitted", "prohibited"]
    license_reference_id: str
    collection_method: Literal["provided_upload", "approved_export", "licensed_archive"]
    entitlement_status: Literal["authorized", "unknown", "denied"]
    entitlement_provenance_status: Literal["CALLER_DECLARED"]
    drm_status: Literal["clear", "protected", "unknown"]
    safe_scan: SafeScanReceiptV1
    parser_version: str
    transcriber_version: str | None
    acquired_ns: int
    available_ns: int
    review_asof_ns: int

    @field_validator("source_id")
    @classmethod
    def _source_id(cls, value: str) -> str:
        if not IDENT.fullmatch(value):
            raise ValueError("invalid source id")
        return value

    @field_validator("source_uri")
    @classmethod
    def _uri(cls, value: str) -> str:
        if (
            len(value) > 1024
            or not value.isascii()
            or any(ord(c) < 33 or ord(c) == 127 for c in value)
        ):
            raise ValueError("invalid source uri")
        try:
            parts = urlsplit(value)
            host = parts.hostname
            port = parts.port
        except ValueError:
            raise ValueError("invalid source uri") from None
        if parts.scheme not in {"file", "https", "ipfs"} or parts.username or parts.password:
            raise ValueError("unsupported source uri")
        if parts.query or parts.fragment:
            raise ValueError("invalid source uri")
        if parts.scheme == "https" and (
            not value.startswith("https://") or not parts.netloc or not host
        ):
            raise ValueError("invalid source uri")
        if parts.scheme == "file" and (
            not value.startswith("file://") or not parts.path or port is not None
        ):
            raise ValueError("invalid source uri")
        if parts.scheme == "ipfs" and (
            not value.startswith("ipfs://") or not parts.netloc or not host
        ):
            raise ValueError("invalid source uri")
        return value

    @field_validator("source_locator", "parser_version")
    @classmethod
    def _safe_reference(cls, value: str) -> str:
        if not value or len(value) > 256 or not value.isascii():
            raise ValueError("invalid source reference")
        if any(ord(c) < 33 or c in "?#@\\" for c in value):
            raise ValueError("invalid source reference")
        return value

    @field_validator("license_reference_id")
    @classmethod
    def _license_reference_id(cls, value: str) -> str:
        if not IDENT.fullmatch(value):
            raise ValueError("invalid license reference id")
        return value

    @field_validator("transcriber_version")
    @classmethod
    def _transcriber(cls, value: str | None) -> str | None:
        if value is not None and not VERSION.fullmatch(value):
            raise ValueError("invalid transcriber version")
        return value

    @field_validator("byte_sha256")
    @classmethod
    def _byte_digest(cls, value: str) -> str:
        if not HEX64.fullmatch(value):
            raise ValueError("invalid source digest")
        return value

    @model_validator(mode="after")
    def _clocks(self) -> Self:
        if (
            self.acquired_ns < 0
            or self.available_ns < self.acquired_ns
            or self.review_asof_ns < self.available_ns
        ):
            raise ValueError("invalid source clocks")
        return self


class SourceRecordV1(_Record):
    schema_version: Literal["1"]
    source_id: str
    source_uri: str
    source_locator: str
    byte_sha256: str
    byte_length: int
    media_type: str
    license_status: Literal["unreviewed", "reference_only", "reuse_permitted", "prohibited"]
    license_reference_id: str
    collection_method: Literal["provided_upload", "approved_export", "licensed_archive"]
    entitlement_status: Literal["authorized", "unknown", "denied"]
    entitlement_provenance_status: Literal["CALLER_DECLARED"]
    drm_status: Literal["clear", "protected", "unknown"]
    safe_scan: SafeScanReceiptV1
    parser_version: str
    transcriber_version: str | None
    acquired_ns: int
    available_ns: int
    review_asof_ns: int


class SourceSpanV1(_Record):
    schema_version: Literal["1"]
    byte_start: int
    byte_end: int
    span_sha256: str
    page_start: int | None
    page_end: int | None
    time_start_ms: int | None
    time_end_ms: int | None

    @field_validator("span_sha256")
    @classmethod
    def _span_digest(cls, value: str) -> str:
        if not HEX64.fullmatch(value):
            raise ValueError("invalid span digest")
        return value

    @model_validator(mode="after")
    def _bounds(self) -> Self:
        if self.byte_start < 0 or self.byte_end <= self.byte_start:
            raise ValueError("invalid byte span")
        if (self.page_start is None) != (self.page_end is None):
            raise ValueError("incomplete page span")
        if self.page_start is not None and (
            self.page_start < 1 or self.page_end is None or self.page_end < self.page_start
        ):
            raise ValueError("invalid page span")
        if (self.time_start_ms is None) != (self.time_end_ms is None):
            raise ValueError("incomplete time span")
        if self.time_start_ms is not None and (
            self.time_start_ms < 0
            or self.time_end_ms is None
            or self.time_end_ms <= self.time_start_ms
        ):
            raise ValueError("invalid time span")
        return self


ClaimKind = Literal[
    "risk_rule",
    "entry_condition",
    "exit_condition",
    "parameter",
    "market_assumption",
    "proxy_method",
    "unknown_logic",
    "research_failure",
    "latency_loss",
    "unsafe_execution",
    "naive_local_time",
    "strategy_content_identity_v1",
]


class ExtractedEvidenceV1(_Record):
    schema_version: Literal["1"]
    evidence_id: str
    claim_key: str
    claim_kind: ClaimKind
    claim_text: str
    confidence: Decimal
    source_sha256: str
    span: SourceSpanV1
    derived_from: tuple[str, ...]
    text_ref: str | None
    chunk_ref: str | None
    embedding_ref: str | None
    tags: tuple[str, ...]

    @field_validator("evidence_id", "claim_key")
    @classmethod
    def _identity(cls, value: str) -> str:
        if not IDENT.fullmatch(value):
            raise ValueError("invalid evidence identity")
        return value

    @field_validator("source_sha256")
    @classmethod
    def _sha(cls, value: str) -> str:
        if not HEX64.fullmatch(value):
            raise ValueError("invalid evidence source digest")
        return value

    @field_validator("claim_text")
    @classmethod
    def _text(cls, value: str, info: ValidationInfo) -> str:
        max_chars = (
            _MAX_CONTENT_IDENTITY_CLAIM_TEXT_CHARS
            if info.data.get("claim_kind") == "strategy_content_identity_v1"
            else _MAX_CLAIM_TEXT_CHARS
        )
        if not value or value != value.strip() or len(value) > max_chars:
            raise ValueError("invalid claim text")
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid claim text")
        return value

    @field_validator("confidence", mode="before")
    @classmethod
    def _decimal(cls, value: object) -> Decimal:
        try:
            return parse_decimal(value, field="confidence", min_value=0, max_value=1)
        except NumericError:
            raise ValueError("invalid confidence") from None

    @field_serializer("confidence", when_used="json")
    def _json_decimal(self, value: Decimal) -> str:
        return canonical_decimal(value)

    @field_validator("derived_from", "tags")
    @classmethod
    def _identities(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(not IDENT.fullmatch(v) for v in values):
            raise ValueError("invalid evidence references")
        return values

    @field_validator("text_ref", "chunk_ref", "embedding_ref")
    @classmethod
    def _ref(cls, value: str | None) -> str | None:
        if value is not None and not IDENT.fullmatch(value):
            raise ValueError("invalid content reference")
        return value


class LineageEdgeV1(_Record):
    schema_version: Literal["1"]
    parent_id: str
    child_id: str
    relation: Literal["extracted_from", "derived_from"]


class ClaimConflictV1(_Record):
    schema_version: Literal["1"]
    claim_key: str
    candidate_ids: tuple[str, ...]
    candidate_hashes: tuple[str, ...]
    status: Literal["unresolved"]


class ReviewPacketV1(_SealedRecord):
    schema_version: Literal["1"]
    status: Literal["QUARANTINED", "REVIEWED"]
    source: SourceRecordV1
    evidence: tuple[ExtractedEvidenceV1, ...]
    lineage_edges: tuple[LineageEdgeV1, ...]
    conflicts: tuple[ClaimConflictV1, ...]
    reviewer_actions: tuple[ReviewerActionV1, ...]
    packet_sha256: str


_ISSUED_PACKETS: dict[int, tuple[ReferenceType[ReviewPacketV1], str]] = {}


def _forget_packet(identity: int, packet_ref: ReferenceType[ReviewPacketV1]) -> None:
    entry = _ISSUED_PACKETS.get(identity)
    if entry is not None and entry[0] is packet_ref:
        del _ISSUED_PACKETS[identity]


def _issue_packet(packet: ReviewPacketV1) -> ReviewPacketV1:
    identity = id(packet)
    packet_ref = ref(packet)
    _ISSUED_PACKETS[identity] = (packet_ref, packet.packet_sha256)
    finalize(packet, _forget_packet, identity, packet_ref)
    return packet


def _packet_is_issued(packet: ReviewPacketV1) -> bool:
    entry = _ISSUED_PACKETS.get(id(packet))
    return entry is not None and entry[0]() is packet and entry[1] == packet.packet_sha256


class ClaimDecisionV1(_Record):
    schema_version: Literal["1"]
    evidence_id: str
    decision: Literal["accept", "reject"]
    reason_code: Literal["supported", "unsupported", "conflict", "out_of_scope"]


class ReviewerActionV1(_Record):
    schema_version: Literal["1"]
    action_id: str
    packet_sha256: str
    reviewer_id: str
    reviewed_at_ns: int
    decisions: tuple[ClaimDecisionV1, ...]

    @field_validator("action_id", "reviewer_id")
    @classmethod
    def _identity(cls, value: str) -> str:
        if not IDENT.fullmatch(value):
            raise ValueError("invalid reviewer identity")
        return value


class ReviewedStrategySpecV1(_StrategySealedModel):
    schema_version: Literal["1"]
    spec_kind: Literal["review_only"]
    promotion_status: Literal["BLOCKED_UNVERIFIED_SOURCE"]
    source: SourceRecordV1
    packet_sha256: str
    accepted_claims: tuple[ExtractedEvidenceV1, ...]
    rejected_claims: tuple[ExtractedEvidenceV1, ...]
    lineage_edges: tuple[LineageEdgeV1, ...]
    conflicts: tuple[ClaimConflictV1, ...]
    reviewer_actions: tuple[ReviewerActionV1, ...]
    spec_sha256: str


class ReviewResultV1(_SealedRecord):
    schema_version: Literal["1"]
    packet: ReviewPacketV1
    spec: ReviewedStrategySpecV1 | None
