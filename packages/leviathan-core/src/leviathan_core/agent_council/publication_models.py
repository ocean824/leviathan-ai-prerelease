"""Closed publication inputs and sealed receipts for the council scribe."""

from __future__ import annotations

import re
from typing import Any, ClassVar, Literal, NoReturn, Self, SupportsIndex

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    field_validator,
    model_validator,
)

from leviathan_core.seal import Issuer, SealedModel, SealError, require
from leviathan_core.text.safe_label import is_safe_display_label as is_safe_display_label

MAX_PUBLICATION_FILE_BYTES = 25 * 1024 * 1024
MAX_PUBLICATION_TOTAL_BYTES = 200 * 1024 * 1024
MAX_PUBLICATION_FILES = 66
MAX_CONFLICT_SUFFIX = 32
MAX_PUBLICATION_RETRIES = 3
MAX_PUBLICATION_ATTEMPTS = MAX_PUBLICATION_RETRIES + 1
_IDENTIFIER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,126}[A-Za-z0-9])?\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_WINDOWS_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\Z", re.ASCII | re.IGNORECASE)
DisplayLabelSource = Literal["strategy_name", "market_symbol", "target_metric", "signal_id"]


def _windows_component(value: str) -> bool:
    return (
        _IDENTIFIER.fullmatch(value) is not None
        and _WINDOWS_RESERVED.fullmatch(value.split(".", 1)[0]) is None
    )


class ScribeError(ValueError):
    """Content-free scribe failure."""

    def __init__(self, code: str, *, http_status: int | None = None) -> None:
        allowed = {
            "PUBLICATION_MODEL_INVALID",
            "PUBLICATION_INPUT_INVALID",
            "AUTHORIZATION_DENIED",
            "STATE_UNTRUSTED",
            "LEAK_RESULT_UNTRUSTED",
            "CRITIQUE_RESULT_UNTRUSTED",
            "PUBLICATION_EXCEPTION_UNTRUSTED",
            "PUBLICATION_GATE_DENIED",
            "PUBLICATION_TOO_LARGE",
            "VAULT_SCOPE_INVALID",
            "VAULT_UNAVAILABLE",
            "VAULT_POSTCONDITION_FAILED",
            "PUBLICATION_CONFLICT_LIMIT",
        }
        safe = code if type(code) is str and code in allowed else "PUBLICATION_MODEL_INVALID"
        self.code = safe
        self.http_status = 413 if safe == "PUBLICATION_TOO_LARGE" else http_status
        super().__init__(safe)


class _InputModel(BaseModel):
    """Frozen boundary input with sanitized validation and mutation errors."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always"
    )
    error_code: ClassVar[str] = "PUBLICATION_MODEL_INVALID"

    def __init__(self, **data: Any) -> None:
        invalid = False
        try:
            super().__init__(**data)
        except Exception:
            invalid = True
        if invalid:
            raise ScribeError(self.error_code)

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        invalid = False
        try:
            value = super().model_validate(obj, **kwargs)
        except Exception:
            invalid = True
        if invalid:
            raise ScribeError(cls.error_code)
        return value

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> Self:
        invalid = False
        try:
            value = super().model_validate_json(json_data, **kwargs)
        except Exception:
            invalid = True
        if invalid:
            raise ScribeError(cls.error_code)
        return value

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        invalid = False
        try:
            value = super().model_validate_strings(obj, **kwargs)
        except Exception:
            invalid = True
        if invalid:
            raise ScribeError(cls.error_code)
        return value

    @classmethod
    def model_construct(cls, *_: object, **__: object) -> NoReturn:  # type: ignore[override]
        raise ScribeError(cls.error_code) from None

    def model_copy(self, **_: object) -> NoReturn:
        raise ScribeError(type(self).error_code) from None

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise ScribeError(type(self).error_code) from None

    def __delattr__(self, _name: str) -> NoReturn:
        raise ScribeError(type(self).error_code) from None

    def __setstate__(self, _state: object) -> NoReturn:
        raise ScribeError(type(self).error_code) from None


class _ScribeIssuedModel(SealedModel):
    """Issued values with content-free validation and mutation errors."""

    kernel_error_code: ClassVar[str] = "PUBLICATION_MODEL_INVALID"

    def __init__(self, **data: Any) -> None:
        invalid = False
        try:
            super().__init__(**data)
        except Exception:
            invalid = True
        if invalid:
            raise ScribeError(self.kernel_error_code)

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        invalid = False
        try:
            value = super().model_validate(obj, **kwargs)
        except Exception:
            invalid = True
        if invalid:
            raise ScribeError(cls.kernel_error_code)
        return value

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> Self:
        invalid = False
        try:
            value = super().model_validate_json(json_data, **kwargs)
        except Exception:
            invalid = True
        if invalid:
            raise ScribeError(cls.kernel_error_code)
        return value

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        invalid = False
        try:
            value = super().model_validate_strings(obj, **kwargs)
        except Exception:
            invalid = True
        if invalid:
            raise ScribeError(cls.kernel_error_code)
        return value

    @classmethod
    def model_construct(cls, *_: object, **__: object) -> NoReturn:  # type: ignore[override]
        raise ScribeError(cls.kernel_error_code) from None

    def model_copy(self, **_: object) -> NoReturn:
        raise ScribeError(type(self).kernel_error_code) from None

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise ScribeError(type(self).kernel_error_code) from None

    def __delattr__(self, _name: str) -> NoReturn:
        raise ScribeError(type(self).kernel_error_code) from None

    def __setstate__(self, _state: object) -> NoReturn:
        raise ScribeError(type(self).kernel_error_code) from None

    def __copy__(self) -> NoReturn:
        raise ScribeError(type(self).kernel_error_code) from None

    def __deepcopy__(self, _memo: object = None) -> NoReturn:
        raise ScribeError(type(self).kernel_error_code) from None

    def __reduce__(self) -> NoReturn:
        raise ScribeError(type(self).kernel_error_code) from None

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise ScribeError(type(self).kernel_error_code) from None


class PublicationPlotV1(_InputModel):
    """Bounded PNG bytes; path names are generated by the service."""

    error_code = "PUBLICATION_MODEL_INVALID"

    name: str = Field(min_length=1, max_length=128)
    media_type: Literal["image/png"]
    # Permit a bounded over-file-size value through to publish(), which reports
    # the contractual 413 before any vault operation.
    content: bytes = Field(min_length=1, max_length=MAX_PUBLICATION_TOTAL_BYTES + 1)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not _windows_component(value):
            raise ValueError("invalid name")
        return value


class PublishedFileV1(_ScribeIssuedModel):
    """Verified relative path, digest and byte count for one published file."""

    path: str = Field(min_length=1, max_length=256)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: StrictInt = Field(ge=0, le=MAX_PUBLICATION_FILE_BYTES)
    schema_version: Literal["1.0.0"] = "1.0.0"


class PublicationConflictV1(_ScribeIssuedModel):
    """Explicit record when occupied content forces a numeric path suffix."""

    requested_path: str = Field(min_length=1, max_length=512)
    published_path: str = Field(min_length=1, max_length=512)
    existing_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    schema_version: Literal["1.0.0"] = "1.0.0"


class PublicationManifestV1(_ScribeIssuedModel):
    """Sealed evidence binding reviewed inputs to verified vault postconditions."""

    session_id: str = Field(min_length=1, max_length=128)
    hypothesis_id: str = Field(min_length=1, max_length=128)
    experiment_id: str = Field(min_length=1, max_length=128)
    state_semantic_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    hypothesis_revision_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    critique_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    leak_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    vault_id: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=1, max_length=512)
    display_label: str = Field(min_length=1, max_length=64)
    display_label_source: DisplayLabelSource
    files: tuple[PublishedFileV1, ...] = Field(min_length=6, max_length=MAX_PUBLICATION_FILES)
    conflicts: tuple[PublicationConflictV1, ...] = Field(max_length=MAX_PUBLICATION_FILES)
    reviewer_id: str | None = Field(default=None, min_length=1, max_length=128)
    review_basis: Literal["CRITIC_PASS", "METRIC_EXCEPTION"]
    publisher_id: str = Field(min_length=1, max_length=128)
    published_at_ns: StrictInt = Field(gt=0, le=2**63 - 1)
    schema_version: Literal["1.0.0"] = "1.0.0"

    @field_validator("display_label")
    @classmethod
    def valid_display_label(cls, value: str) -> str:
        if not is_safe_display_label(value):
            raise ValueError("invalid display label")
        return value

    @model_validator(mode="after")
    def files_are_closed(self) -> PublicationManifestV1:
        paths = tuple(item.path for item in self.files)
        if (
            not _windows_component(self.session_id)
            or len(set(paths)) != len(paths)
            or any(path.startswith("/") or ".." in path.split("/") for path in paths)
            or not {"TLDR.md", "hypothesis.md", "critique.md", "metrics.json", "checksums.json"}
            <= set(paths)
            or (self.review_basis == "CRITIC_PASS" and self.reviewer_id is not None)
            or (self.review_basis == "METRIC_EXCEPTION" and self.reviewer_id is None)
        ):
            raise ValueError("manifest invalid")
        return self


class SummaryIntentV1(_ScribeIssuedModel):
    """Deduplicated downstream intent; this is not a bridge delivery."""

    event_type: Literal["council.scribe.published"] = "council.scribe.published"
    session_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=160)
    publication_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    vault_id: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=1, max_length=512)
    schema_version: Literal["1.0.0"] = "1.0.0"


class PublicationResultV1(_ScribeIssuedModel):
    """Terminal synchronous result; only a synced result carries an intent."""

    status: Literal["synced", "error"]
    manifest: PublicationManifestV1 | None
    summary_intent: SummaryIntentV1 | None
    error_code: Literal["VAULT_UNAVAILABLE", "VAULT_POSTCONDITION_FAILED"] | None
    attempts: StrictInt = Field(ge=0, le=MAX_PUBLICATION_ATTEMPTS)
    schema_version: Literal["1.0.0"] = "1.0.0"

    @model_validator(mode="after")
    def consistent(self) -> PublicationResultV1:
        if self.status == "synced":
            if self.manifest is None or self.summary_intent is None or self.error_code is not None:
                raise ValueError("result invalid")
        elif (
            self.manifest is not None or self.summary_intent is not None or self.error_code is None
        ):
            raise ValueError("result invalid")
        return self


MANIFEST_TAG = "agent005.publication_manifest.v1"
RESULT_TAG = "agent005.publication_result.v1"
SUMMARY_INTENT_TAG = "agent005.summary_intent.v1"
_MANIFEST_ISSUER = Issuer(MANIFEST_TAG)
_RESULT_ISSUER = Issuer(RESULT_TAG)
_SUMMARY_ISSUER = Issuer(SUMMARY_INTENT_TAG)
_FILE_ISSUER = Issuer("agent005.published_file.v1")
_CONFLICT_ISSUER = Issuer("agent005.publication_conflict.v1")


def _issue_manifest(value: PublicationManifestV1) -> PublicationManifestV1:
    return _MANIFEST_ISSUER.issue(value)


def _issue_published_file(value: PublishedFileV1) -> PublishedFileV1:
    return _FILE_ISSUER.issue(value)


def _issue_conflict(value: PublicationConflictV1) -> PublicationConflictV1:
    return _CONFLICT_ISSUER.issue(value)


def _issue_summary_intent(value: SummaryIntentV1) -> SummaryIntentV1:
    return _SUMMARY_ISSUER.issue(value)


def _issue_publication_result(value: PublicationResultV1) -> PublicationResultV1:
    return _RESULT_ISSUER.issue(value)


def require_manifest(value: object) -> PublicationManifestV1:
    if type(value) is not PublicationManifestV1:
        raise ScribeError("PUBLICATION_INPUT_INVALID")
    invalid = False
    try:
        result = require(value, MANIFEST_TAG)
    except SealError:
        invalid = True
    if invalid:
        raise ScribeError("PUBLICATION_INPUT_INVALID")
    return result


def require_summary_intent(value: object) -> SummaryIntentV1:
    if type(value) is not SummaryIntentV1:
        raise ScribeError("PUBLICATION_INPUT_INVALID")
    invalid = False
    try:
        result = require(value, SUMMARY_INTENT_TAG)
    except SealError:
        invalid = True
    if invalid:
        raise ScribeError("PUBLICATION_INPUT_INVALID")
    return result


def require_publication_result(value: object) -> PublicationResultV1:
    if type(value) is not PublicationResultV1:
        raise ScribeError("PUBLICATION_INPUT_INVALID")
    invalid = False
    try:
        result = require(value, RESULT_TAG)
    except SealError:
        invalid = True
    if invalid:
        raise ScribeError("PUBLICATION_INPUT_INVALID")
    return result


__all__ = [
    "MAX_CONFLICT_SUFFIX",
    "MAX_PUBLICATION_ATTEMPTS",
    "MAX_PUBLICATION_FILES",
    "MAX_PUBLICATION_FILE_BYTES",
    "MAX_PUBLICATION_RETRIES",
    "MAX_PUBLICATION_TOTAL_BYTES",
    "PublicationConflictV1",
    "PublicationManifestV1",
    "PublicationPlotV1",
    "PublicationResultV1",
    "PublishedFileV1",
    "ScribeError",
    "SummaryIntentV1",
    "require_manifest",
    "require_publication_result",
    "require_summary_intent",
]
