"""Unit tests for the offline MT4/MT5 artifact lifecycle boundary."""

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone

import pytest

from leviathan_core.mt_export_bridge_artifacts import (
    ArtifactLifecycleError,
    BridgeChannelStateV1,
    BridgeChannelV1,
    BridgeEventTypeV1,
    BridgeEventV1,
    BuildArtifactV1,
    DeploymentCandidateV1,
    DeploymentModeV1,
    DeploymentStatusV1,
    DeploymentTargetV1,
    ExportJobEvidenceV1,
    ExportJobStatusV1,
    MtPlatformV1,
    append_bridge_event,
    require_bridge_event,
    validate_bridge_channel,
    validate_build_artifact_binding,
    validate_deployment,
)
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import SealError

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


def _artifact(
    *,
    artifact_id: str = "artifact-1",
    export_job_id: str = "job-1",
    platform: MtPlatformV1 = MtPlatformV1.MT5,
    signed: bool = False,
    signature_algo: str | None = None,
) -> BuildArtifactV1:
    return BuildArtifactV1(
        artifact_id=artifact_id,
        export_job_id=export_job_id,
        platform=platform,
        signed=signed,
        signature_algo=signature_algo,
    )


def _deployment(
    deployment_id: str = "deployment-1",
    *,
    artifact_id: str = "artifact-1",
    target_id: str = "target-1",
    account_id: str = "account-1",
    mode: DeploymentModeV1 = DeploymentModeV1.PAPER,
    magic_number: int = 101,
    status: DeploymentStatusV1 = DeploymentStatusV1.QUEUED,
) -> DeploymentCandidateV1:
    return DeploymentCandidateV1(
        deployment_id=deployment_id,
        artifact_id=artifact_id,
        target_id=target_id,
        account_id=account_id,
        mode=mode,
        magic_number=magic_number,
        status=status,
    )


def _assert_code(call: Callable[[], object], code: str) -> None:
    with pytest.raises(ArtifactLifecycleError) as caught:
        call()
    assert caught.value.code == code
    assert caught.value.args == (code,)


def test_artifact_binding_requires_exact_successful_job_and_signing_metadata() -> None:
    successful = ExportJobEvidenceV1("job-1", ExportJobStatusV1.SUCCEEDED)
    validate_build_artifact_binding(_artifact(), successful)
    validate_build_artifact_binding(_artifact(signed=True, signature_algo="ed25519"), successful)

    _assert_code(
        lambda: validate_build_artifact_binding(_artifact(export_job_id="job-2"), successful),
        "ARTIFACT_JOB_MISMATCH",
    )
    _assert_code(
        lambda: validate_build_artifact_binding(
            _artifact(), ExportJobEvidenceV1("job-1", ExportJobStatusV1.RUNNING)
        ),
        "EXPORT_NOT_SUCCEEDED",
    )
    _assert_code(
        lambda: validate_build_artifact_binding(_artifact(signed=True), successful),
        "SIGNATURE_ALGORITHM_REQUIRED",
    )


def test_deployment_checks_artifact_target_platform_and_active_magic_key() -> None:
    candidate = _deployment()
    artifact = _artifact()
    target = DeploymentTargetV1("target-1", MtPlatformV1.MT5)
    validate_deployment(candidate, artifact=artifact, target=target)

    peer = _deployment("peer", status=DeploymentStatusV1.DEPLOYED)
    _assert_code(
        lambda: validate_deployment(
            candidate, artifact=artifact, target=target, existing_deployments=(peer,)
        ),
        "MAGIC_NUMBER_CONFLICT",
    )

    # Every component of the partial-index key scopes uniqueness.
    for disjoint in (
        _deployment("other-target", target_id="target-2"),
        _deployment("other-account", account_id="account-2"),
        _deployment("other-mode", mode=DeploymentModeV1.LIVE),
        _deployment("other-magic", magic_number=102),
        _deployment("inactive", status=DeploymentStatusV1.FAILED),
    ):
        validate_deployment(
            candidate,
            artifact=artifact,
            target=target,
            existing_deployments=(disjoint,),
        )

    _assert_code(
        lambda: validate_deployment(
            _deployment(artifact_id="unrelated"), artifact=artifact, target=target
        ),
        "ARTIFACT_ID_MISMATCH",
    )
    _assert_code(
        lambda: validate_deployment(
            candidate,
            artifact=artifact,
            target=DeploymentTargetV1("target-1", MtPlatformV1.MT4),
        ),
        "PLATFORM_MISMATCH",
    )


@pytest.mark.parametrize(
    ("state", "closed_at", "expected"),
    [
        (BridgeChannelStateV1.OPEN, None, None),
        (BridgeChannelStateV1.ERROR, None, None),
        (BridgeChannelStateV1.CLOSED, NOW, None),
        (BridgeChannelStateV1.CLOSED, None, "CHANNEL_LIFECYCLE_INVALID"),
        (
            BridgeChannelStateV1.CLOSED,
            NOW.astimezone(timezone(timedelta(hours=1))),
            "INVALID_INPUT",
        ),
    ],
)
def test_channel_close_time_requirement_and_exact_utc(
    state: BridgeChannelStateV1, closed_at: datetime | None, expected: str | None
) -> None:
    channel = BridgeChannelV1("channel-1", state, closed_at)
    if expected is None:
        validate_bridge_channel(channel)
    else:
        _assert_code(lambda: validate_bridge_channel(channel), expected)


def test_event_append_is_sealed_hash_linked_and_append_only() -> None:
    first = append_bridge_event(
        None,
        event_id="event-1",
        channel_id="channel-1",
        event_type=BridgeEventTypeV1.HEARTBEAT,
        event_time=NOW,
        payload_sha256="a" * 64,
    )
    second = append_bridge_event(
        first,
        event_id="event-2",
        channel_id="channel-1",
        event_type=BridgeEventTypeV1.EVENT,
        event_time=NOW + timedelta(seconds=1),
        payload_sha256="b" * 64,
    )

    assert require_bridge_event(first) is first
    assert require_bridge_event(second) is second
    assert second.sequence == first.sequence + 1
    assert (
        second.previous_event_sha256
        == hashlib.sha256(canonical_json(first.model_dump(mode="json"))).hexdigest()
    )
    with pytest.raises(SealError):
        first.event_id = "rewritten"  # type: ignore[misc]
    with pytest.raises(SealError):
        del first.event_id

    original_id = first.event_id
    _assert_code(lambda: BridgeEventV1.__init__(first), "EVENT_INVALID")
    assert first.event_id == original_id
    _assert_code(
        lambda: append_bridge_event(
            first,
            event_id="event-3",
            channel_id="other-channel",
            event_type=BridgeEventTypeV1.LOG,
            event_time=NOW + timedelta(seconds=2),
            payload_sha256="c" * 64,
        ),
        "EVENT_CHAIN_INVALID",
    )
    _assert_code(lambda: BridgeEventV1(), "EVENT_INVALID")


def test_event_rejects_invalid_fields_and_tampering_with_content_free_errors() -> None:
    _assert_code(
        lambda: append_bridge_event(
            None,
            event_id="secret-canary",
            channel_id="channel-1",
            event_type=BridgeEventTypeV1.LOG,
            event_time=NOW.astimezone(timezone(timedelta(hours=1))),
            payload_sha256="not-a-digest",
        ),
        "EVENT_INVALID",
    )

    event = append_bridge_event(
        None,
        event_id="event-tamper",
        channel_id="channel-1",
        event_type=BridgeEventTypeV1.LOG,
        event_time=NOW,
        payload_sha256="d" * 64,
    )
    object.__setattr__(event, "event_id", "SECRET_CANARY")
    with pytest.raises(ArtifactLifecycleError) as caught:
        require_bridge_event(event)
    assert caught.value.code == "EVENT_INVALID"
    assert "SECRET_CANARY" not in str(caught.value)
