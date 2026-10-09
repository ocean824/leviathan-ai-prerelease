"""Issued, content-bound evidence from a fake Cloudflare R2 bucket-lock read."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Final, cast

from pydantic import ConfigDict, field_validator, model_validator

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel, require
from leviathan_core.seal.errors import SealError

_LOCK_TAG: Final = "stor002.r2_lock.v1"
_LOCK_ISSUER: Final = Issuer(_LOCK_TAG)
_FAKE_LOCK_TAG: Final = "stor002.fake_r2_lock_response.v1"
_FAKE_LOCK_ISSUER: Final = Issuer(_FAKE_LOCK_TAG)
_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}\Z", re.ASCII)
_PREFIX = re.compile(r"[A-Za-z0-9._/-]{1,256}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class R2LockError(ValueError):
    """Content-free lock-evidence validation error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class FakeR2LockResponseV1(SealedModel):
    """Synthetic R2 lock configuration returned by the in-memory transport."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    bucket: str
    prefix: str
    policy_id: str
    manifest_digest: str
    retention_start_utc_ns: int
    retention_end_utc_ns: int
    lifecycle_expiration_utc_ns: int | None = None
    legal_hold: bool = False
    provider_response_digest: str

    @field_validator("bucket")
    @classmethod
    def _bucket(cls, value: str) -> str:
        if not isinstance(value, str) or _NAME.fullmatch(value) is None:
            raise ValueError("INVALID_BUCKET")
        return value

    @field_validator("prefix")
    @classmethod
    def _prefix_value(cls, value: str) -> str:
        if (
            not isinstance(value, str)
            or _PREFIX.fullmatch(value) is None
            or value.startswith("/")
            or ".." in value.split("/")
        ):
            raise ValueError("INVALID_PREFIX")
        return value

    @field_validator("policy_id")
    @classmethod
    def _policy_id(cls, value: str) -> str:
        if not isinstance(value, str) or _PREFIX.fullmatch(value) is None:
            raise ValueError("INVALID_POLICY_ID")
        return value

    @field_validator("manifest_digest")
    @classmethod
    def _manifest_digest(cls, value: str) -> str:
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise ValueError("INVALID_MANIFEST_DIGEST")
        return value

    @field_validator(
        "retention_start_utc_ns", "retention_end_utc_ns", "lifecycle_expiration_utc_ns"
    )
    @classmethod
    def _utc_ns(cls, value: int | None) -> int | None:
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError("INVALID_UTC_NS")
        return value

    @field_validator("legal_hold")
    @classmethod
    def _legal_hold(cls, value: bool) -> bool:
        if type(value) is not bool:
            raise ValueError("INVALID_LEGAL_HOLD")
        return value

    @field_validator("provider_response_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise ValueError("INVALID_PROVIDER_DIGEST")
        return value

    @model_validator(mode="after")
    def _retention(self) -> FakeR2LockResponseV1:
        if self.retention_end_utc_ns <= self.retention_start_utc_ns:
            raise ValueError("INVALID_RETENTION_RANGE")
        return self


class R2LockEvidenceV1(SealedModel):
    """A sealed readback of bucket/prefix retention and legal-hold facts."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    bucket: str
    prefix: str
    policy_id: str
    manifest_digest: str
    retention_start_utc_ns: int
    retention_end_utc_ns: int
    captured_at: datetime
    provider_response_digest: str
    lifecycle_expiration_utc_ns: int | None = None
    legal_hold: bool = False

    @field_validator("bucket")
    @classmethod
    def _bucket(cls, value: str) -> str:
        if not isinstance(value, str) or _NAME.fullmatch(value) is None:
            raise ValueError("INVALID_BUCKET")
        return value

    @field_validator("prefix")
    @classmethod
    def _prefix_value(cls, value: str) -> str:
        if (
            not isinstance(value, str)
            or _PREFIX.fullmatch(value) is None
            or value.startswith("/")
            or ".." in value.split("/")
        ):
            raise ValueError("INVALID_PREFIX")
        return value

    @field_validator("policy_id")
    @classmethod
    def _policy_id(cls, value: str) -> str:
        if not isinstance(value, str) or _PREFIX.fullmatch(value) is None:
            raise ValueError("INVALID_POLICY_ID")
        return value

    @field_validator("manifest_digest")
    @classmethod
    def _manifest_digest(cls, value: str) -> str:
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise ValueError("INVALID_MANIFEST_DIGEST")
        return value

    @field_validator(
        "retention_start_utc_ns", "retention_end_utc_ns", "lifecycle_expiration_utc_ns"
    )
    @classmethod
    def _utc_ns(cls, value: int | None) -> int | None:
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError("INVALID_UTC_NS")
        return value

    @field_validator("legal_hold")
    @classmethod
    def _legal_hold(cls, value: bool) -> bool:
        if type(value) is not bool:
            raise ValueError("INVALID_LEGAL_HOLD")
        return value

    @field_validator("provider_response_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise ValueError("INVALID_PROVIDER_DIGEST")
        return value

    @field_validator("captured_at")
    @classmethod
    def _utc_datetime(cls, value: datetime) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is not UTC:
            raise ValueError("INVALID_CAPTURE_TIME")
        return value

    @model_validator(mode="after")
    def _retention(self) -> R2LockEvidenceV1:
        if self.retention_end_utc_ns <= self.retention_start_utc_ns:
            raise ValueError("INVALID_RETENTION_RANGE")
        return self


def lock_response_digest(
    *,
    bucket: str,
    prefix: str,
    policy_id: str,
    manifest_digest: str,
    retention_start_utc_ns: int,
    retention_end_utc_ns: int,
    lifecycle_expiration_utc_ns: int | None,
    legal_hold: bool,
) -> str:
    """Canonical digest for the synthetic provider response fields."""
    from hashlib import sha256

    try:
        payload = canonical_json(
            {
                "bucket": bucket,
                "prefix": prefix,
                "policy_id": policy_id,
                "manifest_digest": manifest_digest,
                "retention_start_utc_ns": retention_start_utc_ns,
                "retention_end_utc_ns": retention_end_utc_ns,
                "lifecycle_expiration_utc_ns": lifecycle_expiration_utc_ns,
                "legal_hold": legal_hold,
                "provider": "cloudflare-r2-bucket-lock",
            }
        )
    except Exception:
        raise R2LockError("INVALID_LOCK_RESPONSE") from None
    return sha256(payload).hexdigest()


def make_fake_lock_response(
    *,
    bucket: str,
    prefix: str,
    policy_id: str,
    manifest_digest: str,
    retention_start_utc_ns: int,
    retention_end_utc_ns: int,
    lifecycle_expiration_utc_ns: int | None = None,
    legal_hold: bool = False,
) -> FakeR2LockResponseV1:
    """Build validated synthetic lock facts for the fake R2 transport."""
    response_digest = lock_response_digest(
        bucket=bucket,
        prefix=prefix,
        policy_id=policy_id,
        manifest_digest=manifest_digest,
        retention_start_utc_ns=retention_start_utc_ns,
        retention_end_utc_ns=retention_end_utc_ns,
        lifecycle_expiration_utc_ns=lifecycle_expiration_utc_ns,
        legal_hold=legal_hold,
    )
    try:
        response = FakeR2LockResponseV1.model_validate(
            {
                "bucket": bucket,
                "prefix": prefix,
                "policy_id": policy_id,
                "manifest_digest": manifest_digest,
                "retention_start_utc_ns": retention_start_utc_ns,
                "retention_end_utc_ns": retention_end_utc_ns,
                "lifecycle_expiration_utc_ns": lifecycle_expiration_utc_ns,
                "legal_hold": legal_hold,
                "provider_response_digest": response_digest,
            }
        )
        return _FAKE_LOCK_ISSUER.issue(response)
    except SealError:
        raise R2LockError("INVALID_LOCK_RESPONSE") from None


def issue_lock_evidence(
    response: FakeR2LockResponseV1, *, captured_at: datetime
) -> R2LockEvidenceV1:
    """Issue evidence from a validated fake-provider response."""
    try:
        response = require_fake_lock_response(response)
        expected_digest = lock_response_digest(
            bucket=response.bucket,
            prefix=response.prefix,
            policy_id=response.policy_id,
            manifest_digest=response.manifest_digest,
            retention_start_utc_ns=response.retention_start_utc_ns,
            retention_end_utc_ns=response.retention_end_utc_ns,
            lifecycle_expiration_utc_ns=response.lifecycle_expiration_utc_ns,
            legal_hold=response.legal_hold,
        )
        if response.provider_response_digest != expected_digest:
            raise R2LockError("INVALID_LOCK_RESPONSE")
        evidence = R2LockEvidenceV1.model_validate(
            {
                "bucket": response.bucket,
                "prefix": response.prefix,
                "policy_id": response.policy_id,
                "manifest_digest": response.manifest_digest,
                "retention_start_utc_ns": response.retention_start_utc_ns,
                "retention_end_utc_ns": response.retention_end_utc_ns,
                "captured_at": captured_at,
                "provider_response_digest": response.provider_response_digest,
                "lifecycle_expiration_utc_ns": response.lifecycle_expiration_utc_ns,
                "legal_hold": response.legal_hold,
            }
        )
        return _LOCK_ISSUER.issue(evidence)
    except (SealError, R2LockError):
        raise R2LockError("INVALID_LOCK_EVIDENCE") from None


def require_lock_evidence(value: object) -> R2LockEvidenceV1:
    """Require a live, untampered lock-evidence issue from this module."""
    try:
        return cast(R2LockEvidenceV1, require(value, _LOCK_TAG))
    except SealError:
        raise R2LockError("INVALID_LOCK_EVIDENCE") from None


def require_fake_lock_response(value: object) -> FakeR2LockResponseV1:
    """Require an untampered fake lock response issued by this module."""
    try:
        return cast(FakeR2LockResponseV1, require(value, _FAKE_LOCK_TAG))
    except SealError:
        raise R2LockError("INVALID_LOCK_RESPONSE") from None


__all__ = [
    "FakeR2LockResponseV1",
    "R2LockError",
    "R2LockEvidenceV1",
    "issue_lock_evidence",
    "lock_response_digest",
    "make_fake_lock_response",
    "require_fake_lock_response",
    "require_lock_evidence",
]
