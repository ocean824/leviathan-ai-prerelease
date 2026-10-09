"""Pure, secret-free rotation audit records and restart-required intent."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from collections.abc import Callable
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import ConfigDict, Field

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel, SealError, require

_EVENT_TAG = "dep_rotation_audit.event.v1"
_INTENT_TAG = "dep_rotation_audit.restart_intent.v1"
_EVENT_ISSUER = Issuer(_EVENT_TAG)
_INTENT_ISSUER = Issuer(_INTENT_TAG)
_EVENT_FACTORY_TOKEN = object()
_INTENT_FACTORY_TOKEN = object()
_MAX_NS = (1 << 63) - 1
_BINDING_REF = re.compile(
    r"vault://leviathan-ai/(?:development|live)/"
    r"[a-z][a-z0-9-]{0,63}/[A-Z][A-Z0-9_]{0,63}\Z",
    re.ASCII,
)
_VERSION_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}\Z", re.ASCII)
_TOKEN_PREFIXES = ("sk_", "ghp_", "xox", "akia")
_BASE64URL_SEGMENT = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_SEMVER = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+\Z", re.ASCII)
_SECRET_MARKERS = re.compile(
    r"(?:secret|token|password|credential|api[-_]?key|private[-_]?key|bearer|"
    r"sk[-_](?:live|test)[-_]|gh[pousr]_[A-Za-z0-9]{20,})",
    re.IGNORECASE | re.ASCII,
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class RotationAuditCode(StrEnum):
    INVALID_BINDING_REFERENCE = "INVALID_BINDING_REFERENCE"
    INVALID_VERSION_ID = "INVALID_VERSION_ID"
    VERSION_UNCHANGED = "VERSION_UNCHANGED"
    INVALID_RESTART_FLAG = "INVALID_RESTART_FLAG"
    CLOCK_INVALID = "CLOCK_INVALID"
    EVENT_UNISSUED = "EVENT_UNISSUED"
    EVENT_TAMPERED = "EVENT_TAMPERED"
    INTENT_UNISSUED = "INTENT_UNISSUED"
    INTENT_TAMPERED = "INTENT_TAMPERED"
    INVALID_EVENT = "INVALID_EVENT"


class RotationAuditError(ValueError):
    """Content-free failure; caller values are never included."""

    def __init__(self, code: RotationAuditCode) -> None:
        if type(code) is not RotationAuditCode:
            code = RotationAuditCode.INVALID_EVENT
        self.code = code.value
        super().__init__(code.value)


class RotationAuditEventV1(SealedModel):
    """Immutable issued event; binding reference is reduced to an opaque ID."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, revalidate_instances="always"
    )

    binding_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    prior_version_id_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    new_version_id_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    rotated_at_ns: int = Field(ge=0, le=_MAX_NS)
    requires_restart: bool

    def __init__(self, /, *, _factory_token: object | None = None, **data: Any) -> None:
        if _factory_token is not _EVENT_FACTORY_TOKEN:
            raise RotationAuditError(RotationAuditCode.EVENT_UNISSUED)
        try:
            super().__init__(**data)
        except Exception:
            raise RotationAuditError(RotationAuditCode.INVALID_EVENT) from None

    @classmethod
    def model_validate(
        cls, obj: Any, *, _factory_token: object | None = None, **kwargs: Any
    ) -> Self:
        if _factory_token is not _EVENT_FACTORY_TOKEN:
            raise RotationAuditError(RotationAuditCode.EVENT_UNISSUED)
        try:
            return super().model_validate(obj, **kwargs)
        except RotationAuditError:
            raise
        except Exception:
            raise RotationAuditError(RotationAuditCode.INVALID_EVENT) from None

    @classmethod
    def model_validate_json(
        cls, json_data: Any, *, _factory_token: object | None = None, **kwargs: Any
    ) -> Self:
        if _factory_token is not _EVENT_FACTORY_TOKEN:
            raise RotationAuditError(RotationAuditCode.EVENT_UNISSUED)
        try:
            return super().model_validate_json(json_data, **kwargs)
        except RotationAuditError:
            raise
        except Exception:
            raise RotationAuditError(RotationAuditCode.INVALID_EVENT) from None

    @classmethod
    def model_validate_strings(
        cls, obj: Any, *, _factory_token: object | None = None, **kwargs: Any
    ) -> Self:
        if _factory_token is not _EVENT_FACTORY_TOKEN:
            raise RotationAuditError(RotationAuditCode.EVENT_UNISSUED)
        try:
            return super().model_validate_strings(obj, **kwargs)
        except RotationAuditError:
            raise
        except Exception:
            raise RotationAuditError(RotationAuditCode.INVALID_EVENT) from None


class RestartRequiredDeploymentAuditIntentV1(SealedModel):
    """Non-executable deployment audit intent derived from an issued event."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, revalidate_instances="always"
    )

    binding_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    prior_version_id_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    new_version_id_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    rotated_at_ns: int = Field(ge=0, le=_MAX_NS)
    rotation_event_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    requires_restart: Literal[True]

    def __init__(self, /, *, _factory_token: object | None = None, **data: Any) -> None:
        if _factory_token is not _INTENT_FACTORY_TOKEN:
            raise RotationAuditError(RotationAuditCode.INTENT_UNISSUED)
        try:
            super().__init__(**data)
        except Exception:
            raise RotationAuditError(RotationAuditCode.INVALID_EVENT) from None

    @classmethod
    def model_validate(
        cls, obj: Any, *, _factory_token: object | None = None, **kwargs: Any
    ) -> Self:
        if _factory_token is not _INTENT_FACTORY_TOKEN:
            raise RotationAuditError(RotationAuditCode.INTENT_UNISSUED)
        try:
            return super().model_validate(obj, **kwargs)
        except RotationAuditError:
            raise
        except Exception:
            raise RotationAuditError(RotationAuditCode.INVALID_EVENT) from None

    @classmethod
    def model_validate_json(
        cls, json_data: Any, *, _factory_token: object | None = None, **kwargs: Any
    ) -> Self:
        if _factory_token is not _INTENT_FACTORY_TOKEN:
            raise RotationAuditError(RotationAuditCode.INTENT_UNISSUED)
        try:
            return super().model_validate_json(json_data, **kwargs)
        except RotationAuditError:
            raise
        except Exception:
            raise RotationAuditError(RotationAuditCode.INVALID_EVENT) from None

    @classmethod
    def model_validate_strings(
        cls, obj: Any, *, _factory_token: object | None = None, **kwargs: Any
    ) -> Self:
        if _factory_token is not _INTENT_FACTORY_TOKEN:
            raise RotationAuditError(RotationAuditCode.INTENT_UNISSUED)
        try:
            return super().model_validate_strings(obj, **kwargs)
        except RotationAuditError:
            raise
        except Exception:
            raise RotationAuditError(RotationAuditCode.INVALID_EVENT) from None


def _validate_binding_reference(binding_ref: str) -> str:
    if type(binding_ref) is not str or _BINDING_REF.fullmatch(binding_ref) is None:
        raise RotationAuditError(RotationAuditCode.INVALID_BINDING_REFERENCE)
    return binding_ref


def _binding_identity(binding_ref: str) -> str:
    try:
        payload = canonical_json(
            {"domain": "leviathan.dep.rotation.binding.v1", "binding_ref": binding_ref}
        )
    except Exception:
        raise RotationAuditError(RotationAuditCode.INVALID_BINDING_REFERENCE) from None
    return hashlib.sha256(payload).hexdigest()


def _validate_version_id(value: str) -> bool:
    if type(value) is not str or _VERSION_ID.fullmatch(value) is None:
        return False
    lowered = value.lower()
    if lowered.startswith(_TOKEN_PREFIXES) or _SECRET_MARKERS.search(value) is not None:
        return False
    segments = value.split(".")
    if (
        len(segments) == 3
        and not _SEMVER.fullmatch(value)
        and all(_BASE64URL_SEGMENT.fullmatch(segment) for segment in segments)
    ):
        return False
    normalized = re.sub(r"[._-]", "", value)
    if len(normalized) >= 24:
        entropy = -sum(
            (count / len(normalized)) * math.log2(count / len(normalized))
            for count in Counter(normalized).values()
        )
        if entropy >= 3.5:
            return False
    return True


def _version_id_digest(value: str) -> str:
    try:
        payload = canonical_json(
            {"domain": "leviathan.dep.rotation.version.v1", "version_id": value}
        )
    except Exception:
        raise RotationAuditError(RotationAuditCode.INVALID_VERSION_ID) from None
    return hashlib.sha256(payload).hexdigest()


def create_rotation_audit_event(
    *,
    binding_ref: str,
    prior_version_id: str,
    new_version_id: str,
    requires_restart: bool,
    clock_ns: Callable[[], int],
) -> RotationAuditEventV1:
    """Validate a logical binding reference and issue one timestamped event.

    The caller provides a trusted UTC-nanosecond clock; it is called exactly once.
    The raw logical reference is never retained in the model or an error.
    """
    canonical_binding_ref = _validate_binding_reference(binding_ref)
    if not _validate_version_id(prior_version_id) or not _validate_version_id(new_version_id):
        raise RotationAuditError(RotationAuditCode.INVALID_VERSION_ID)
    if prior_version_id == new_version_id:
        raise RotationAuditError(RotationAuditCode.VERSION_UNCHANGED)
    if type(requires_restart) is not bool:
        raise RotationAuditError(RotationAuditCode.INVALID_RESTART_FLAG)
    binding_id = _binding_identity(canonical_binding_ref)
    prior_version_id_digest = _version_id_digest(prior_version_id)
    new_version_id_digest = _version_id_digest(new_version_id)
    if not callable(clock_ns):
        raise RotationAuditError(RotationAuditCode.CLOCK_INVALID)
    try:
        rotated_at_ns = clock_ns()
    except Exception:
        raise RotationAuditError(RotationAuditCode.CLOCK_INVALID) from None
    if type(rotated_at_ns) is not int or not 0 <= rotated_at_ns <= _MAX_NS:
        raise RotationAuditError(RotationAuditCode.CLOCK_INVALID)
    try:
        event = RotationAuditEventV1(
            _factory_token=_EVENT_FACTORY_TOKEN,
            binding_id=binding_id,
            prior_version_id_digest=prior_version_id_digest,
            new_version_id_digest=new_version_id_digest,
            rotated_at_ns=rotated_at_ns,
            requires_restart=requires_restart,
        )
        return _EVENT_ISSUER.issue(event)
    except RotationAuditError:
        raise
    except Exception:
        raise RotationAuditError(RotationAuditCode.INVALID_EVENT) from None


def require_rotation_audit_event(value: object) -> RotationAuditEventV1:
    if type(value) is not RotationAuditEventV1:
        raise RotationAuditError(RotationAuditCode.EVENT_UNISSUED)
    try:
        require(value, _EVENT_TAG)
    except SealError as exc:
        code = (
            RotationAuditCode.EVENT_UNISSUED
            if exc.code == "SEAL_NOT_ISSUED"
            else RotationAuditCode.EVENT_TAMPERED
        )
        raise RotationAuditError(code) from None
    except Exception:
        raise RotationAuditError(RotationAuditCode.EVENT_TAMPERED) from None
    return value


def _rotation_event_digest(event: RotationAuditEventV1) -> str:
    try:
        payload = canonical_json(
            {
                "domain": "leviathan.dep.rotation.event.v1",
                "event": event.model_dump(mode="python"),
            }
        )
    except Exception:
        raise RotationAuditError(RotationAuditCode.EVENT_TAMPERED) from None
    return hashlib.sha256(payload).hexdigest()


def derive_restart_required_intent(
    event: RotationAuditEventV1,
) -> RestartRequiredDeploymentAuditIntentV1 | None:
    """Issue only a proposal record; never restarts a service or deploys."""
    issued_event = require_rotation_audit_event(event)
    if not issued_event.requires_restart:
        return None
    event_digest = _rotation_event_digest(issued_event)
    try:
        intent = RestartRequiredDeploymentAuditIntentV1(
            _factory_token=_INTENT_FACTORY_TOKEN,
            binding_id=issued_event.binding_id,
            prior_version_id_digest=issued_event.prior_version_id_digest,
            new_version_id_digest=issued_event.new_version_id_digest,
            rotated_at_ns=issued_event.rotated_at_ns,
            rotation_event_digest=event_digest,
            requires_restart=True,
        )
        return _INTENT_ISSUER.issue(intent)
    except RotationAuditError:
        raise
    except Exception:
        raise RotationAuditError(RotationAuditCode.INVALID_EVENT) from None


def require_restart_required_intent(
    value: object,
) -> RestartRequiredDeploymentAuditIntentV1:
    if type(value) is not RestartRequiredDeploymentAuditIntentV1:
        raise RotationAuditError(RotationAuditCode.INTENT_UNISSUED)
    try:
        require(value, _INTENT_TAG)
    except SealError as exc:
        code = (
            RotationAuditCode.INTENT_UNISSUED
            if exc.code == "SEAL_NOT_ISSUED"
            else RotationAuditCode.INTENT_TAMPERED
        )
        raise RotationAuditError(code) from None
    except Exception:
        raise RotationAuditError(RotationAuditCode.INTENT_TAMPERED) from None
    return value


__all__ = [
    "RestartRequiredDeploymentAuditIntentV1",
    "RotationAuditCode",
    "RotationAuditError",
    "RotationAuditEventV1",
    "create_rotation_audit_event",
    "derive_restart_required_intent",
    "require_restart_required_intent",
    "require_rotation_audit_event",
]
