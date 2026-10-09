"""Pure lifecycle checks for MT4/MT5 build artifacts, deployments and events."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel, SealError, require

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_INT64_MAX = (1 << 63) - 1
_EVENT_TAG = "mtbr.artifact_bridge_event.v1"
_EVENT_ISSUER = Issuer(_EVENT_TAG)
_EVENT_CONSTRUCTION_MARKER = object()


class ArtifactLifecycleError(ValueError):
    """Content-free lifecycle failure with a closed code set."""

    _CODES = frozenset(
        {
            "INVALID_INPUT",
            "ARTIFACT_JOB_MISMATCH",
            "EXPORT_NOT_SUCCEEDED",
            "SIGNATURE_ALGORITHM_REQUIRED",
            "ARTIFACT_ID_MISMATCH",
            "TARGET_ID_MISMATCH",
            "PLATFORM_MISMATCH",
            "MAGIC_NUMBER_CONFLICT",
            "CHANNEL_LIFECYCLE_INVALID",
            "EVENT_INVALID",
            "EVENT_CHAIN_INVALID",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_INPUT"
        super().__init__(self.code)


class MtPlatformV1(StrEnum):
    MT4 = "MT4"
    MT5 = "MT5"


class ExportJobStatusV1(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class DeploymentModeV1(StrEnum):
    LIVE = "LIVE"
    PAPER = "PAPER"
    BACKTEST = "BACKTEST"


class DeploymentStatusV1(StrEnum):
    QUEUED = "QUEUED"
    DEPLOYED = "DEPLOYED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class BridgeChannelStateV1(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    ERROR = "ERROR"


class BridgeEventTypeV1(StrEnum):
    EVENT = "EVENT"
    HEARTBEAT = "HEARTBEAT"
    LOG = "LOG"
    ORDER = "ORDER"


@dataclass(frozen=True, slots=True)
class ExportJobEvidenceV1:
    """Minimal synthetic job evidence needed for artifact binding."""

    export_job_id: str
    status: ExportJobStatusV1


@dataclass(frozen=True, slots=True)
class BuildArtifactV1:
    """Minimal artifact metadata; no file, URI, signature, or secret is held."""

    artifact_id: str
    export_job_id: str
    platform: MtPlatformV1
    signed: bool
    signature_algo: str | None


@dataclass(frozen=True, slots=True)
class DeploymentTargetV1:
    """Minimal target identity for the platform equality check."""

    target_id: str
    platform: MtPlatformV1


@dataclass(frozen=True, slots=True)
class DeploymentCandidateV1:
    """Synthetic candidate and existing-row shape for partial-index checks."""

    deployment_id: str
    artifact_id: str
    target_id: str
    account_id: str
    mode: DeploymentModeV1
    magic_number: int
    status: DeploymentStatusV1


@dataclass(frozen=True, slots=True)
class BridgeChannelV1:
    """Minimal channel lifecycle state; no endpoint or bridge config is stored."""

    channel_id: str
    state: BridgeChannelStateV1
    closed_at: datetime | None


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _platform(value: object) -> bool:
    return type(value) is MtPlatformV1


def _validate_artifact(artifact: object) -> BuildArtifactV1:
    if type(artifact) is not BuildArtifactV1:
        raise ArtifactLifecycleError("INVALID_INPUT")
    if (
        not _identifier(artifact.artifact_id)
        or not _identifier(artifact.export_job_id)
        or not _platform(artifact.platform)
        or type(artifact.signed) is not bool
        or (
            artifact.signature_algo is not None
            and (
                type(artifact.signature_algo) is not str
                or not artifact.signature_algo
                or len(artifact.signature_algo) > 64
                or not artifact.signature_algo.isascii()
            )
        )
    ):
        raise ArtifactLifecycleError("INVALID_INPUT")
    if artifact.signed and artifact.signature_algo is None:
        raise ArtifactLifecycleError("SIGNATURE_ALGORITHM_REQUIRED")
    return artifact


def validate_build_artifact_binding(artifact: BuildArtifactV1, job: ExportJobEvidenceV1) -> None:
    """Require an artifact's exact export-job reference to be successful."""
    artifact = _validate_artifact(artifact)
    if type(job) is not ExportJobEvidenceV1 or not _identifier(job.export_job_id):
        raise ArtifactLifecycleError("INVALID_INPUT")
    if type(job.status) is not ExportJobStatusV1:
        raise ArtifactLifecycleError("INVALID_INPUT")
    if artifact.export_job_id != job.export_job_id:
        raise ArtifactLifecycleError("ARTIFACT_JOB_MISMATCH")
    if job.status is not ExportJobStatusV1.SUCCEEDED:
        raise ArtifactLifecycleError("EXPORT_NOT_SUCCEEDED")


def _validate_target(target: object) -> DeploymentTargetV1:
    if (
        type(target) is not DeploymentTargetV1
        or not _identifier(target.target_id)
        or not _platform(target.platform)
    ):
        raise ArtifactLifecycleError("INVALID_INPUT")
    return target


def _validate_deployment(deployment: object) -> DeploymentCandidateV1:
    if type(deployment) is not DeploymentCandidateV1:
        raise ArtifactLifecycleError("INVALID_INPUT")
    if (
        not _identifier(deployment.deployment_id)
        or not _identifier(deployment.artifact_id)
        or not _identifier(deployment.target_id)
        or not _identifier(deployment.account_id)
        or type(deployment.mode) is not DeploymentModeV1
        or type(deployment.status) is not DeploymentStatusV1
        or type(deployment.magic_number) is not int
        or not 0 <= deployment.magic_number <= _INT64_MAX
    ):
        raise ArtifactLifecycleError("INVALID_INPUT")
    return deployment


def validate_deployment(
    deployment: DeploymentCandidateV1,
    *,
    artifact: BuildArtifactV1,
    target: DeploymentTargetV1,
    existing_deployments: tuple[DeploymentCandidateV1, ...] = (),
) -> None:
    """Validate exact artifact/target links, platform and active magic uniqueness.

    The uniqueness key follows the PRD partial index:
    ``(target_id, account_id, mode, magic_number)`` for QUEUED/DEPLOYED rows.
    """
    deployment = _validate_deployment(deployment)
    artifact = _validate_artifact(artifact)
    target = _validate_target(target)
    if deployment.artifact_id != artifact.artifact_id:
        raise ArtifactLifecycleError("ARTIFACT_ID_MISMATCH")
    if deployment.target_id != target.target_id:
        raise ArtifactLifecycleError("TARGET_ID_MISMATCH")
    if artifact.platform is not target.platform:
        raise ArtifactLifecycleError("PLATFORM_MISMATCH")
    if type(existing_deployments) is not tuple:
        raise ArtifactLifecycleError("INVALID_INPUT")
    if deployment.status not in {DeploymentStatusV1.QUEUED, DeploymentStatusV1.DEPLOYED}:
        return
    key = (
        deployment.target_id,
        deployment.account_id,
        deployment.mode,
        deployment.magic_number,
    )
    for prior_value in existing_deployments:
        prior = _validate_deployment(prior_value)
        if (
            prior.status in {DeploymentStatusV1.QUEUED, DeploymentStatusV1.DEPLOYED}
            and (
                prior.target_id,
                prior.account_id,
                prior.mode,
                prior.magic_number,
            )
            == key
        ):
            raise ArtifactLifecycleError("MAGIC_NUMBER_CONFLICT")


def _is_utc(value: object) -> bool:
    return type(value) is datetime and value.tzinfo is UTC


def validate_bridge_channel(channel: BridgeChannelV1) -> None:
    """Require a valid state and a UTC close timestamp for CLOSED channels."""
    if (
        type(channel) is not BridgeChannelV1
        or not _identifier(channel.channel_id)
        or type(channel.state) is not BridgeChannelStateV1
        or (channel.closed_at is not None and not _is_utc(channel.closed_at))
    ):
        raise ArtifactLifecycleError("INVALID_INPUT")
    if channel.state is BridgeChannelStateV1.CLOSED and channel.closed_at is None:
        raise ArtifactLifecycleError("CHANNEL_LIFECYCLE_INVALID")


class BridgeEventV1(SealedModel):
    """SEAL-issued, content-free bridge event linked to its prior event."""

    schema_version: Literal["mtbr.bridge-event/1"] = "mtbr.bridge-event/1"
    event_id: str
    channel_id: str
    sequence: int
    event_type: BridgeEventTypeV1
    event_time: datetime
    payload_sha256: str
    previous_event_sha256: str | None

    def __init__(self, *, _marker: object | None = None, **data: object) -> None:
        if _marker is not _EVENT_CONSTRUCTION_MARKER:
            raise ArtifactLifecycleError("EVENT_INVALID")
        super().__init__(**data)


def _validate_event_fields(event: BridgeEventV1) -> None:
    if (
        not _identifier(event.event_id)
        or not _identifier(event.channel_id)
        or type(event.sequence) is not int
        or not 1 <= event.sequence <= _INT64_MAX
        or type(event.event_type) is not BridgeEventTypeV1
        or not _is_utc(event.event_time)
        or type(event.payload_sha256) is not str
        or _SHA256.fullmatch(event.payload_sha256) is None
        or (
            event.previous_event_sha256 is not None
            and (
                type(event.previous_event_sha256) is not str
                or _SHA256.fullmatch(event.previous_event_sha256) is None
            )
        )
    ):
        raise ArtifactLifecycleError("EVENT_INVALID")


def require_bridge_event(value: object) -> BridgeEventV1:
    """Verify the event's issuer and content digest before returning it."""
    if type(value) is not BridgeEventV1:
        raise ArtifactLifecycleError("EVENT_INVALID")
    try:
        event = require(value, _EVENT_TAG)
        _validate_event_fields(event)
    except (SealError, TypeError, ValueError):
        raise ArtifactLifecycleError("EVENT_INVALID") from None
    return event


def append_bridge_event(
    previous_event: BridgeEventV1 | None,
    *,
    event_id: str,
    channel_id: str,
    event_type: BridgeEventTypeV1,
    event_time: datetime,
    payload_sha256: str,
) -> BridgeEventV1:
    """Append one new event to an issued, per-channel hash-linked sequence."""
    if previous_event is None:
        sequence = 1
        previous_digest = None
    else:
        previous = require_bridge_event(previous_event)
        if previous.channel_id != channel_id:
            raise ArtifactLifecycleError("EVENT_CHAIN_INVALID")
        sequence = previous.sequence + 1
        try:
            previous_digest = hashlib.sha256(
                canonical_json(previous.model_dump(mode="json"))
            ).hexdigest()
        except Exception:
            raise ArtifactLifecycleError("EVENT_CHAIN_INVALID") from None
    try:
        candidate = BridgeEventV1(
            _marker=_EVENT_CONSTRUCTION_MARKER,
            event_id=event_id,
            channel_id=channel_id,
            sequence=sequence,
            event_type=event_type,
            event_time=event_time,
            payload_sha256=payload_sha256,
            previous_event_sha256=previous_digest,
        )
        _validate_event_fields(candidate)
        return _EVENT_ISSUER.issue(candidate)
    except ArtifactLifecycleError:
        raise
    except (SealError, TypeError, ValueError):
        raise ArtifactLifecycleError("EVENT_INVALID") from None


__all__ = [
    "ArtifactLifecycleError",
    "BridgeChannelStateV1",
    "BridgeChannelV1",
    "BridgeEventTypeV1",
    "BridgeEventV1",
    "BuildArtifactV1",
    "DeploymentCandidateV1",
    "DeploymentModeV1",
    "DeploymentStatusV1",
    "DeploymentTargetV1",
    "ExportJobEvidenceV1",
    "ExportJobStatusV1",
    "MtPlatformV1",
    "append_bridge_event",
    "require_bridge_event",
    "validate_bridge_channel",
    "validate_build_artifact_binding",
    "validate_deployment",
]
